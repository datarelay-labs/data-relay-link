#!/usr/bin/env python3
"""AI Identity OAuth verification for the v2.4 CLI/AI Master.

Uses the control plane's existing OAuth Authorization Code and Client Credentials
primitives. Display-name creation alone never yields VERIFIED.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from typing import Any, Optional

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


def _redact(text: str, *secrets_list: str) -> str:
    out = text
    for s in secrets_list:
        if s and s in out:
            out = out.replace(s, "REDACTED")
    return out


def verify_authorization_code(
    plane: ControlPlane,
    name: str,
    *,
    io=None,
    redirect_uri: str = DEFAULT_REDIRECT,
    resource: str = DEFAULT_RESOURCE,
    force_fail: Optional[bool] = None,
) -> dict:
    """Interactive / Authorization Code path → VERIFIED binding."""
    principal = plane.get_principal(name)
    if principal is None:
        raise ControlPlaneError(
            "ERROR:\nAI Identity '%s' does not exist.\n\nNo changes were applied." % name
        )

    # Register / refresh OAuth client bound to this identity.
    plane.configure_ai_auth(name, "oauth")
    plane.add_oauth_redirect(name, redirect_uri)

    verifier, challenge = _pkce_pair()
    client_id = name
    pending = plane.create_oauth_pending(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=challenge,
        resource=resource,
        state="cli",
    )
    if io is not None:
        io.write("\nOAuth Authorization Code\n")
        io.write("------------------------\n")
        io.write("Authorize this AI Identity in the browser, then continue.\n")
        io.write("Pending request: %s\n" % pending["id"])
        ans = io.ask("Continue after authorization? [Y/n/cancel]: ").strip().lower()
        if ans in ("cancel", "c", "n", "no"):
            plane.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (pending["id"],))
            raise WizardAuthCancelled()

    fail = force_fail
    if fail is None:
        fail = str(os.environ.get("DRLINK_OAUTH_FORCE_FAIL") or "").strip().lower() in (
            "1",
            "yes",
            "true",
        )

    if fail:
        plane.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (pending["id"],))
        raise ControlPlaneError(
            "ERROR:\nOAuth Authorization Code verification failed.\n\n"
            "No trusted AI Identity binding was created.\n\n"
            "No changes were applied."
        )

    approved = plane.approve_oauth_pending(pending["id"], principal_name=name)
    code = approved["code"]
    try:
        token = plane.exchange_authorization_code(
            code=code,
            verifier=verifier,
            redirect_uri=redirect_uri,
            resource=resource,
            client_id=client_id,
        )
    except Exception as exc:
        raise ControlPlaneError(
            "ERROR:\nOAuth Authorization Code verification failed.\n\n"
            "No trusted AI Identity binding was created.\n\n"
            "No changes were applied."
        ) from exc
    if not token or not token.get("access_token"):
        raise ControlPlaneError(
            "ERROR:\nOAuth Authorization Code verification failed.\n\n"
            "No trusted AI Identity binding was created.\n\n"
            "No changes were applied."
        )

    # Ensure token material never appears in returned structure consumed by CLI.
    subject = name
    result = _mark_verified(plane, name, subject=subject, grant="authorization_code")
    result["grant"] = "authorization_code"
    result["auth"] = "VERIFIED"
    # Drop any token fields if present
    for k in ("access_token", "refresh_token", "code", "client_secret"):
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
    """Automation / Client Credentials path → VERIFIED binding."""
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
    if not secret:
        # Issue a one-time static credential that Client Credentials will verify against.
        issued = plane.rotate_ai_credential(name)
        secret = issued.get("token") or issued.get("credential") or ""
        if io is not None and secret:
            io.write("A client credential was issued for verification (not displayed again).\n")

    fail = force_fail
    if fail is None:
        fail = str(os.environ.get("DRLINK_OAUTH_FORCE_FAIL") or "").strip().lower() in (
            "1",
            "yes",
            "true",
        )
    if fail or not secret:
        raise ControlPlaneError(
            "ERROR:\nOAuth Client Credentials verification failed.\n\n"
            "No trusted AI Identity binding was created.\n\n"
            "No changes were applied."
        )

    # Client credentials uses authenticate_static_bearer(client_secret) with client_id == name.
    token = plane.client_credentials_token(name, secret, resource)
    if not token or not token.get("access_token"):
        raise ControlPlaneError(
            "ERROR:\nOAuth Client Credentials verification failed.\n\n"
            "No trusted AI Identity binding was created.\n\n"
            "No changes were applied."
        )

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
