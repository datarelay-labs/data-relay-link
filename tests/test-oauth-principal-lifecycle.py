#!/usr/bin/env python3
"""OAuth approval must not revive a revoked or unverified AI Identity."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import ControlPlaneError  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_mcp_bridge import MCPBridge, MCP_PROTOCOL_VERSION, ThreadingHTTPServer, make_handler  # noqa: E402
import drlink_v24_ai_identity as ai_id  # noqa: E402

REDIRECT = "http://127.0.0.1/callback"


def _pkce():
    verifier = "P" * 43
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return verifier, challenge


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class OAuthPrincipalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-oauth-lifecycle-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_OAUTH_AUTO_APPROVE", None)
        self.plane = ControlPlane(self.tmp)
        self.plane.set_ai_principal("verified-ai", enabled=True)
        self.plane.set_ai_principal("revoked-ai", enabled=True)
        self.plane.set_ai_principal("plain-ai", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified', auth_mode = 'oauth' WHERE name = 'verified-ai'"
        )
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'revoked', auth_mode = 'oauth' WHERE name = 'revoked-ai'"
        )
        self.plane.conn.commit()
        self.port = _free_port()
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), make_handler(self.bridge))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.bridge.listen_host = "127.0.0.1"
        self.bridge.listen_port = self.port
        self.base = "http://127.0.0.1:%s" % self.port
        self.resource = self.bridge.canonical_resource()

    def tearDown(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
        self.bridge.close()
        self.plane.close()
        os.environ.pop("DRLINK_TEST_ROOT", None)
        os.environ.pop("DRLINK_CONFIRM", None)

    def _dcr_pending(self, state: str):
        reg = self.plane.register_oauth_client(
            {
                "redirect_uris": [REDIRECT],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "client_name": state,
            }
        )
        verifier, challenge = _pkce()
        pending = self.plane.create_oauth_pending(
            client_id=reg["client_id"],
            redirect_uri=REDIRECT,
            code_challenge=challenge,
            resource=self.resource,
            state=state,
        )
        self.assertTrue(pending.get("unbound"))
        return reg["client_id"], verifier, pending["id"]

    def _codes_for(self, principal_name: str) -> int:
        row = self.plane.conn.execute(
            "SELECT COUNT(*) AS c FROM ai_oauth_codes c "
            "JOIN ai_principals p ON p.id = c.principal_id WHERE p.name = ?",
            (principal_name,),
        ).fetchone()
        return int(row["c"])

    def _mcp(self, token):
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        }
        req = urllib.request.Request(
            self.base + "/mcp",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Authorization": "Bearer %s" % token,
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                "Mcp-Method": "tools/list",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"raw": raw}
            return exc.code, parsed

    def test_unbound_approval_rejects_revoked_and_unverified(self):
        for name, state in (("revoked-ai", "rej-revoked"), ("plain-ai", "rej-plain")):
            before = str(self.plane.get_principal(name)["credential_status"]).lower()
            _client, _verifier, pending_id = self._dcr_pending(state)
            with self.assertRaises(ControlPlaneError) as ctx:
                self.plane.approve_oauth_pending(pending_id, name, retain_for_browser=False)
            self.assertIn("revoked or not VERIFIED", str(ctx.exception))
            self.assertIn("No changes were applied", str(ctx.exception))
            self.assertEqual(str(self.plane.get_principal(name)["credential_status"]).lower(), before)
            self.assertEqual(self._codes_for(name), 0)
            self.assertIsNone(self.plane.authenticate_oauth_token("drauth_not-issued"))

    def test_verified_approve_pkce_mcp_then_revoke_refresh_and_static_bearer(self):
        client_id, verifier, pending_id = self._dcr_pending("ok-verified")
        approved = self.plane.approve_oauth_pending(
            pending_id, "verified-ai", retain_for_browser=True
        )
        self.assertEqual(approved["status"], "approved")
        self.assertNotIn("code", approved)
        self.assertEqual(
            str(self.plane.get_principal("verified-ai")["credential_status"]).lower(),
            "verified",
        )
        completed = self.plane.complete_oauth_pending_browser(approved["completion_token"])
        self.assertTrue(str(completed.get("code") or "").startswith("drc_"))
        issued = self.plane.exchange_authorization_code(
            code=completed["code"],
            verifier=verifier,
            redirect_uri=REDIRECT,
            resource=self.resource,
            client_id=client_id,
        )
        self.assertTrue(str(issued.get("access_token") or "").startswith("drauth_"))
        self.assertTrue(str(issued.get("refresh_token") or "").startswith("drref_"))
        authed = self.plane.authenticate_oauth_token(issued["access_token"], resource=self.resource)
        self.assertIsNotNone(authed)
        self.assertEqual(authed["id"], self.plane.get_principal("verified-ai")["id"])
        self.assertEqual(authed["name"], "verified-ai")
        status, payload = self._mcp(issued["access_token"])
        self.assertEqual(status, 200, payload)
        self.assertIn("tools", json.dumps(payload))

        refreshed = self.plane.exchange_refresh_token(
            refresh_token=issued["refresh_token"],
            client_id=client_id,
            resource=self.resource,
        )
        self.assertIsNotNone(refreshed)
        self.assertTrue(str(refreshed.get("access_token") or "").startswith("drauth_"))
        status, payload = self._mcp(refreshed["access_token"])
        self.assertEqual(status, 200, payload)
        self.assertIsNone(self.plane.authenticate_oauth_token(issued["access_token"], resource=self.resource))

        self.plane.revoke_ai_credential("verified-ai")
        self.assertEqual(
            str(self.plane.get_principal("verified-ai")["credential_status"]).lower(),
            "revoked",
        )
        self.assertIsNone(
            self.plane.authenticate_oauth_token(refreshed["access_token"], resource=self.resource)
        )
        self.assertIsNone(
            self.plane.exchange_refresh_token(
                refresh_token=refreshed["refresh_token"],
                client_id=client_id,
                resource=self.resource,
            )
        )
        status, payload = self._mcp(refreshed["access_token"])
        self.assertEqual(status, 401, payload)

        rotated = self.plane.rotate_ai_credential("plain-ai")
        bearer = rotated["token"]
        self.assertEqual(
            str(self.plane.get_principal("plain-ai")["credential_status"]).lower(),
            "active",
        )
        self.assertIsNotNone(self.plane.authenticate_static_bearer(bearer))
        self.plane.revoke_ai_credential("plain-ai")
        self.assertEqual(
            str(self.plane.get_principal("plain-ai")["credential_status"]).lower(),
            "revoked",
        )
        self.assertIsNone(self.plane.authenticate_static_bearer(bearer))
        self.assertIsNone(self.plane.get_principal("plain-ai")["credential_hash"])

    def test_bound_none_configure_cannot_approve_pending_ceremony_can(self):
        self.plane.set_ai_principal("bound-plain", enabled=True)
        self.assertEqual(str(self.plane.get_principal("bound-plain")["credential_status"]).lower(), "none")
        self.plane.configure_ai_auth("bound-plain", "oauth")
        self.plane.add_oauth_redirect("bound-plain", REDIRECT)
        client = self.plane.conn.execute(
            "SELECT principal_id FROM ai_oauth_clients WHERE client_id = ?",
            ("bound-plain",),
        ).fetchone()
        self.assertEqual(client["principal_id"], self.plane.get_principal("bound-plain")["id"])
        verifier, challenge = _pkce()
        qs = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": "bound-plain",
                "redirect_uri": REDIRECT,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": self.resource,
                "state": "bound-none",
            }
        )
        page = urllib.request.urlopen(self.base + "/oauth/authorize?" + qs, timeout=10).read().decode("utf-8")
        self.assertIn("approve-oauth", page)
        pending = self.plane.conn.execute(
            "SELECT id, principal_id FROM ai_oauth_pending WHERE state = ?",
            ("bound-none",),
        ).fetchone()
        self.assertEqual(pending["principal_id"], self.plane.get_principal("bound-plain")["id"])
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.approve_oauth_pending(pending["id"], retain_for_browser=False)
        self.assertIn("revoked or not VERIFIED", str(ctx.exception))
        self.assertEqual(str(self.plane.get_principal("bound-plain")["credential_status"]).lower(), "none")
        self.assertEqual(self._codes_for("bound-plain"), 0)
        self.assertIsNone(self.plane.authenticate_oauth_token("drauth_not-issued", resource=self.resource))

        session = ai_id.begin_authorization_code(
            self.plane, "ceremony-ai", redirect_uri=REDIRECT, resource=self.resource
        )
        self.assertEqual(str(self.plane.get_principal("ceremony-ai")["credential_status"]).lower(), "pending")
        approved = self.plane.approve_oauth_pending(session["pending_id"], retain_for_browser=False)
        issued = self.plane.exchange_authorization_code(
            code=approved["code"],
            verifier=session["verifier"],
            redirect_uri=session["redirect_uri"],
            resource=session["resource"],
            client_id="ceremony-ai",
        )
        self.assertTrue(str(issued.get("access_token") or "").startswith("drauth_"))
        self.assertEqual(str(self.plane.get_principal("ceremony-ai")["credential_status"]).lower(), "pending")
        self.assertIsNone(
            self.plane.authenticate_oauth_token(issued["access_token"], resource=session["resource"])
        )
        self.assertIsNone(
            self.plane.exchange_refresh_token(
                refresh_token=issued["refresh_token"],
                client_id="ceremony-ai",
                resource=session["resource"],
            )
        )
        pending_status, pending_payload = self._mcp(issued["access_token"])
        self.assertEqual(pending_status, 401, pending_payload)
        marked = ai_id._mark_verified(self.plane, "ceremony-ai", subject="ceremony-ai", grant="authorization_code")
        self.assertIn("VERIFIED", marked["after"])
        self.assertEqual(str(self.plane.get_principal("ceremony-ai")["credential_status"]).lower(), "verified")
        authed = self.plane.authenticate_oauth_token(issued["access_token"], resource=session["resource"])
        self.assertIsNotNone(authed)
        self.assertEqual(authed["name"], "ceremony-ai")
        status, payload = self._mcp(issued["access_token"])
        self.assertEqual(status, 200, payload)
        refreshed = self.plane.exchange_refresh_token(
            refresh_token=issued["refresh_token"],
            client_id="ceremony-ai",
            resource=session["resource"],
        )
        self.assertIsNotNone(refreshed)
        self.assertIsNotNone(
            self.plane.authenticate_oauth_token(refreshed["access_token"], resource=session["resource"])
        )

    def test_none_tokens_cannot_authenticate_or_refresh(self):
        """Legacy rows with credential_status none must not use or rotate OAuth tokens."""
        client_id, verifier, pending_id = self._dcr_pending("legacy-none")
        approved = self.plane.approve_oauth_pending(
            pending_id, "verified-ai", retain_for_browser=False
        )
        issued = self.plane.exchange_authorization_code(
            code=approved["code"],
            verifier=verifier,
            redirect_uri=REDIRECT,
            resource=self.resource,
            client_id=client_id,
        )
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'none' WHERE name = 'verified-ai'"
        )
        self.plane.conn.commit()
        self.assertIsNone(self.plane.authenticate_oauth_token(issued["access_token"], resource=self.resource))
        self.assertIsNone(
            self.plane.exchange_refresh_token(
                refresh_token=issued["refresh_token"],
                client_id=client_id,
                resource=self.resource,
            )
        )
        status, payload = self._mcp(issued["access_token"])
        self.assertEqual(status, 401, payload)
        self.assertIsNone(self.plane.authenticate_oauth_token(issued["access_token"], resource=self.resource))

    def test_client_credentials_active_token_authenticates(self):
        rotated = self.plane.rotate_ai_credential("plain-ai")
        self.assertEqual(str(self.plane.get_principal("plain-ai")["credential_status"]).lower(), "active")
        issued = self.plane.client_credentials_token("plain-ai", rotated["token"], self.resource)
        self.assertTrue(str(issued.get("access_token") or "").startswith("drauth_"))
        authed = self.plane.authenticate_oauth_token(issued["access_token"], resource=self.resource)
        self.assertIsNotNone(authed)
        self.assertEqual(authed["name"], "plain-ai")
        self.assertEqual(str(authed["credential_status"]).lower(), "active")

    def test_bound_revoked_identity_is_not_resurrected_by_staging_or_approval(self):
        session = ai_id.begin_authorization_code(self.plane, "revoked-ai", redirect_uri=REDIRECT, resource=self.resource)
        self.assertEqual(
            str(self.plane.get_principal("revoked-ai")["credential_status"]).lower(),
            "revoked",
        )
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.approve_oauth_pending(session["pending_id"], retain_for_browser=False)
        self.assertIn("revoked or not VERIFIED", str(ctx.exception))
        self.assertEqual(
            str(self.plane.get_principal("revoked-ai")["credential_status"]).lower(),
            "revoked",
        )
        self.assertEqual(self._codes_for("revoked-ai"), 0)


if __name__ == "__main__":
    unittest.main()
