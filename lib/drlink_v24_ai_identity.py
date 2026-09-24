#!/usr/bin/env python3
"""AI Identity OAuth verification for the v2.4 CLI/AI Master.

Uses the control plane's existing OAuth Authorization Code and Client Credentials
primitives. Display-name creation alone never yields VERIFIED.

Critical security boundaries:
- verify_authorization_code() never calls approve_oauth_pending().
- verify_client_credentials() never issues a secret and treats that same secret
  as proof of external possession.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane

DEFAULT_REDIRECT = "http://127.0.0.1:8765/callback"
DEFAULT_RESOURCE = "drlink://ai"


class WizardAuthCancelled(Exception):
    pass


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).rstrip(b"=").decode(
        "ascii"
    )
    return verifier, challenge


def _new_state() -> str:
    return secrets.token_urlsafe(24)


def _mark_verified(plane: ControlPlane, name: str, *, subject: str, grant: str) -> dict:
    principal = plane.get_principal(name)
    if principal is None:
        raise ControlPlaneError("AI Identity '%s' was not found." % name)

    def write():
        plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified', auth_mode = 'oauth', "
            "oauth_subject = ?, enabled = 1, row_version = row_version + 1, updated_at = datetime('now') "
            "WHERE id = ?",
            (subject, principal["id"]),
        )
        return {
            "entity": {"type": "ai-identity", "id": principal["id"], "name": name},
            "operation": "verify",
            "after": "VERIFIED via %s" % grant,
        }

    return plane._mutate("set ai-identity %s verify" % name, "verify ai identity", write)


def _verification_failed() -> ControlPlaneError:
    return ControlPlaneError(
        "ERROR:\nOAuth Authorization Code verification failed.\n\n"
        "No trusted AI Identity binding was created.\n\n"
        "No changes were applied."
    )


def _client_credentials_failed() -> ControlPlaneError:
    return ControlPlaneError(
        "ERROR:\nOAuth Client Credentials verification failed.\n\n"
        "No trusted AI Identity binding was created.\n\n"
        "No changes were applied."
    )


def stage_ai_identity_oauth(
    plane: ControlPlane,
    name: str,
    *,
    redirect_uri: str = DEFAULT_REDIRECT,
) -> dict:
    """Create or refresh OAuth client binding without a configuration revision.

    Used by guided wizards so Cancel can discard staged rows without advancing
    config_revisions. Not a substitute for final VERIFIED commit.
    """
    now = __import__("drlink_control_db", fromlist=["utc_now_iso"]).utc_now_iso()
    existing = plane.get_principal(name)
    if existing is None:
        pid = "aipr_" + secrets.token_hex(8)
        plane.conn.execute(
            "INSERT INTO ai_principals(id, name, description, enabled, credential_status, auth_mode, "
            "row_version, created_at, updated_at) VALUES (?, ?, '', 1, 'pending', 'oauth', 1, ?, ?)",
            (pid, name, now, now),
        )
        principal_id = pid
        created = True
    else:
        principal_id = existing["id"]
        plane.conn.execute(
            "UPDATE ai_principals SET auth_mode = 'oauth', credential_status = CASE "
            "WHEN lower(COALESCE(credential_status,'')) IN ('verified','active','revoked') THEN credential_status "
            "ELSE 'pending' END, updated_at = ? WHERE id = ?",
            (now, principal_id),
        )
        created = False
    row = plane.conn.execute(
        "SELECT redirect_uris FROM ai_oauth_clients WHERE client_id = ?", (name,)
    ).fetchone()
    existing_uris = [p for p in str(row["redirect_uris"] if row else "").split("\n") if p]
    if redirect_uri not in existing_uris:
        existing_uris.append(redirect_uri)
    plane.conn.execute(
        "INSERT OR REPLACE INTO ai_oauth_clients(client_id, principal_id, redirect_uris, created_at) "
        "VALUES (?, ?, ?, ?)",
        (name, principal_id, "\n".join(existing_uris), now),
    )
    plane.conn.commit()
    return {"name": name, "principal_id": principal_id, "created": created, "staged": True}


def discard_staged_ai_identity(plane: ControlPlane, name: str, *, only_if_unverified: bool = True) -> None:
    """Remove staged AI Identity / OAuth rows without creating a configuration revision."""
    row = plane.get_principal(name)
    if row is None:
        return
    status = str(row["credential_status"] or "").lower()
    if only_if_unverified and status in ("verified", "active"):
        return
    pid = row["id"]
    plane.conn.execute("DELETE FROM ai_oauth_pending WHERE principal_id = ?", (pid,))
    plane.conn.execute("DELETE FROM ai_oauth_codes WHERE principal_id = ?", (pid,))
    plane.conn.execute("DELETE FROM ai_oauth_tokens WHERE principal_id = ?", (pid,))
    plane.conn.execute("DELETE FROM ai_oauth_clients WHERE principal_id = ?", (pid,))
    plane.conn.execute("DELETE FROM ai_sessions WHERE principal_id = ?", (pid,))
    plane.conn.execute("DELETE FROM ai_principals WHERE id = ?", (pid,))
    plane.conn.commit()


def begin_authorization_code(
    plane: ControlPlane,
    name: str,
    *,
    redirect_uri: str = DEFAULT_REDIRECT,
    resource: str = DEFAULT_RESOURCE,
    stage: bool = True,
) -> dict:
    """Start an Authorization Code request. Does not approve or verify."""
    principal = plane.get_principal(name)
    if principal is None:
        if not stage:
            raise ControlPlaneError(
                "ERROR:\nAI Identity '%s' does not exist.\n\nNo changes were applied." % name
            )
        stage_ai_identity_oauth(plane, name, redirect_uri=redirect_uri)
    else:
        stage_ai_identity_oauth(plane, name, redirect_uri=redirect_uri)

    verifier, challenge = _pkce_pair()
    state = _new_state()
    pending = plane.create_oauth_pending(
        client_id=name,
        redirect_uri=redirect_uri,
        code_challenge=challenge,
        resource=resource,
        state=state,
    )
    plane.conn.commit()
    return {
        "pending_id": pending["id"],
        "client_id": name,
        "redirect_uri": redirect_uri,
        "resource": resource,
        "state": state,
        "verifier": verifier,
        "code_challenge": challenge,
    }


def _wait_local_callback(redirect_uri: str, expected_state: str, timeout: float = 120.0) -> Optional[str]:
    """Optional local loopback capture of ?code=&state=. Returns code or None."""
    parsed = urlparse(redirect_uri)
    if parsed.hostname not in ("127.0.0.1", "localhost"):
        return None
    port = parsed.port or 80
    path = parsed.path or "/callback"
    box: dict[str, Any] = {"code": None, "error": None}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            req = urlparse(self.path)
            if req.path != path:
                self.send_response(404)
                self.end_headers()
                return
            qs = parse_qs(req.query)
            if expected_state and (qs.get("state") or [None])[0] != expected_state:
                box["error"] = "state"
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"invalid state")
                return
            box["code"] = (qs.get("code") or [None])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authorization received. You may close this window.")

        def log_message(self, fmt, *args):  # noqa: A003
            return

    try:
        server = HTTPServer(("127.0.0.1", int(port)), Handler)
    except OSError:
        return None
    server.timeout = 1.0
    deadline = __import__("time").time() + timeout
    try:
        while __import__("time").time() < deadline and box["code"] is None and box["error"] is None:
            server.handle_request()
    finally:
        server.server_close()
    return box.get("code")


def verify_authorization_code(
    plane: ControlPlane,
    name: str,
    *,
    io=None,
    redirect_uri: str = DEFAULT_REDIRECT,
    resource: str = DEFAULT_RESOURCE,
    authorization_code: Optional[str] = None,
    code_verifier: Optional[str] = None,
    state: Optional[str] = None,
    pending_id: Optional[str] = None,
    force_fail: Optional[bool] = None,
    stage: bool = False,
) -> dict:
    """Authorization Code path → VERIFIED binding.

    Requires an externally completed authorization (callback / supplied code).
    Production verification never self-approves the pending OAuth request.
    """
    session = None
    verifier = code_verifier
    expected_state = state
    code = authorization_code or (os.environ.get("DRLINK_OAUTH_AUTHORIZATION_CODE") or "").strip() or None

    if not code or not verifier:
        session = begin_authorization_code(
            plane, name, redirect_uri=redirect_uri, resource=resource, stage=stage or True
        )
        pending_id = session["pending_id"]
        verifier = session["verifier"]
        expected_state = session["state"]
        if io is not None:
            io.write("\nOAuth Authorization Code\n")
            io.write("------------------------\n")
            io.write("Authorize this AI Identity in an external browser / approval actor.\n")
            io.write("Pending request: %s\n" % pending_id)
            io.write("This CLI will not approve the request itself.\n")
            ans = io.ask("Continue after external authorization? [Y/n/cancel]: ").strip().lower()
            if ans in ("cancel", "c", "n", "no"):
                plane.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (pending_id,))
                plane.conn.commit()
                raise WizardAuthCancelled()
            # Prefer loopback callback, then pasted code / env.
            code = _wait_local_callback(redirect_uri, expected_state, timeout=0.5)
            if not code:
                pasted = io.ask("Authorization code (from external approval/callback): ").strip()
                code = pasted or (os.environ.get("DRLINK_OAUTH_AUTHORIZATION_CODE") or "").strip() or None
        else:
            # Non-interactive: only succeed when caller supplied code+verifier, or env code
            # after an already-started session with matching verifier.
            if authorization_code and code_verifier:
                code = authorization_code
                verifier = code_verifier
            else:
                code = (os.environ.get("DRLINK_OAUTH_AUTHORIZATION_CODE") or "").strip() or None

    fail = force_fail
    if fail is None:
        fail = str(os.environ.get("DRLINK_OAUTH_FORCE_FAIL") or "").strip().lower() in (
            "1",
            "yes",
            "true",
        )

    if fail or not code or not verifier:
        if pending_id:
            plane.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (pending_id,))
            plane.conn.commit()
        raise _verification_failed()

    # Ensure principal/client exist for exchange binding checks.
    if plane.get_principal(name) is None:
        raise _verification_failed()

    try:
        token = plane.exchange_authorization_code(
            code=code,
            verifier=verifier,
            redirect_uri=redirect_uri,
            resource=resource,
            client_id=name,
        )
    except Exception as exc:
        raise _verification_failed() from exc
    if not token or not token.get("access_token"):
        raise _verification_failed()

    subject = name
    result = _mark_verified(plane, name, subject=subject, grant="authorization_code")
    result["grant"] = "authorization_code"
    result["auth"] = "VERIFIED"
    for k in ("access_token", "refresh_token", "code", "client_secret", "verifier"):
        result.pop(k, None)
    return result


def verify_client_credentials(
    plane: ControlPlane,
    name: str,
    *,
    io=None,
    client_secret: Optional[str] = None,
    resource: str = DEFAULT_RESOURCE,
    force_fail: Optional[bool] = None,
) -> dict:
    """Automation / Client Credentials path → VERIFIED binding.

    Proof-of-possession only: a pre-provisioned secret must be supplied by the
    external automation client (argument, prompt, or env). Issuing a credential
    is a separate operation and is never performed here as self-proof.
    """
    principal = plane.get_principal(name)
    if principal is None:
        raise ControlPlaneError(
            "ERROR:\nAI Identity '%s' does not exist.\n\nNo changes were applied." % name
        )

    secret = client_secret
    if secret is None and io is not None:
        secret = io.ask("Client secret: ").strip()
    if not secret:
        secret = os.environ.get("DRLINK_OAUTH_CLIENT_SECRET") or ""

    fail = force_fail
    if fail is None:
        fail = str(os.environ.get("DRLINK_OAUTH_FORCE_FAIL") or "").strip().lower() in (
            "1",
            "yes",
            "true",
        )
    if fail or not secret:
        raise _client_credentials_failed()

    token = plane.client_credentials_token(name, secret, resource)
    if not token or not token.get("access_token"):
        raise _client_credentials_failed()

    result = _mark_verified(plane, name, subject=name, grant="client_credentials")
    result["grant"] = "client_credentials"
    result["auth"] = "VERIFIED"
    for k in ("access_token", "refresh_token", "code", "client_secret", "token"):
        result.pop(k, None)
    return result


def identity_is_verified(plane: ControlPlane, name: str) -> bool:
    row = plane.get_principal(name)
    if row is None:
        return False
    return str(row["credential_status"] or "").lower() in ("verified", "active")


def require_verified_identity(plane: ControlPlane, name: str) -> None:
    if not identity_is_verified(plane, name):
        raise ControlPlaneError(
            "ERROR:\nAI Identity '%s' is not VERIFIED.\n\n"
            "Authentication is required before AI Access authorization.\n\n"
            "No changes were applied.\n\n"
            "Use:\n  set ai-identity %s" % (name, name)
        )
