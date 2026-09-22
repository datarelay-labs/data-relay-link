#!/usr/bin/env python3
"""Production manual OAuth consent: browser redirect completion without AUTO_APPROVE."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_mcp_bridge import MCPBridge, ThreadingHTTPServer, make_handler  # noqa: E402


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def open_no_redirect(url):
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(url, timeout=10)
        raise AssertionError("expected HTTPError")
    except urllib.error.HTTPError as exc:
        return exc


class ManualConsentBrowserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-oauth-manual-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_OAUTH_AUTO_APPROVE", None)
        self.plane = ControlPlane(self.tmp)
        dispatch(["set", "ai-principal", "agent-a"], root=self.tmp)
        dispatch(["set", "ai-principal", "agent-a", "enabled"], root=self.tmp)
        dispatch(
            ["system", "credential", "configure", "ai-principal", "agent-a", "authentication", "oauth"],
            root=self.tmp,
        )
        dispatch(
            [
                "system",
                "credential",
                "configure",
                "ai-principal",
                "agent-a",
                "oauth-redirect",
                "http://127.0.0.1/callback",
            ],
            root=self.tmp,
        )
        self.port = free_port()
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), make_handler(self.bridge))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.bridge.listen_host = "127.0.0.1"
        self.bridge.listen_port = self.port
        self.base = "http://127.0.0.1:%s" % self.port
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text(
            json.dumps(
                {
                    "public_host": "127.0.0.1",
                    "deployment_mode": "single443",
                    "frp_control_public_port": 443,
                }
            ),
            encoding="utf-8",
        )

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
        os.environ.pop("DRLINK_OAUTH_AUTO_APPROVE", None)

    def _pkce(self):
        verifier = "V" * 43
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .decode("ascii")
            .rstrip("=")
        )
        return verifier, challenge

    def _authorize(self, *, challenge, state="st-manual", client_id="agent-a", redirect="http://127.0.0.1/callback"):
        resource = self.bridge.canonical_resource()
        qs = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
                "state": state,
            }
        )
        resp = urllib.request.urlopen(self.base + "/oauth/authorize?" + qs, timeout=10)
        self.assertEqual(resp.status, 200)
        page = resp.read().decode("utf-8")
        self.assertIn("approve-oauth", page)
        self.assertIn("/oauth/continue?", page)
        pending_m = re.search(r"approve-oauth\s+(oap_[A-Za-z0-9_-]+)", page)
        self.assertIsNotNone(pending_m, page)
        cont_m = re.search(r"/oauth/continue\?([^\"'\s>]+)", page)
        self.assertIsNotNone(cont_m, page)
        return {
            "page": page,
            "pending_id": pending_m.group(1),
            "continue_path": "/oauth/continue?" + cont_m.group(1),
            "resource": resource,
            "state": state,
            "redirect": redirect,
            "client_id": client_id,
        }

    def _exchange(self, *, code, verifier, resource, client_id="agent-a", redirect="http://127.0.0.1/callback"):
        body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": resource,
            }
        ).encode("utf-8")
        return json.loads(
            urllib.request.urlopen(
                urllib.request.Request(
                    self.base + "/oauth/token",
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                ),
                timeout=10,
            )
            .read()
            .decode("utf-8")
        )

    def test_browser_flow_cli_approve_continue_pkce(self):
        verifier, challenge = self._pkce()
        auth = self._authorize(challenge=challenge, state="browser-ok")
        # Wait page while still pending.
        wait = urllib.request.urlopen(self.base + auth["continue_path"], timeout=10)
        self.assertEqual(wait.status, 200)
        self.assertIn("Waiting for operator approval", wait.read().decode("utf-8"))
        # Public CLI approval path only (no DB / plane helper).
        buf = io.StringIO()
        with redirect_stdout(buf):
            dispatch(
                ["system", "credential", "approve-oauth", auth["pending_id"]],
                root=self.tmp,
            )
        cli_out = buf.getvalue()
        self.assertNotIn("drc_", cli_out)
        self.assertNotRegex(cli_out, r"(?i)\bcode=")
        exc = open_no_redirect(self.base + auth["continue_path"])
        self.assertEqual(exc.code, 302)
        loc = exc.headers.get("Location") or ""
        parsed = urllib.parse.urlparse(loc)
        self.assertEqual("%s://%s%s" % (parsed.scheme, parsed.netloc, parsed.path), auth["redirect"])
        params = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(params.get("state", [None])[0], "browser-ok")
        self.assertEqual(params.get("iss", [None])[0], self.bridge.canonical_public_base())
        code = params["code"][0]
        self.assertTrue(code.startswith("drc_"))
        issued = self._exchange(code=code, verifier=verifier, resource=auth["resource"])
        self.assertTrue(issued.get("access_token", "").startswith("drauth_"))
        print("MANUAL_CONSENT_BROWSER_FLOW=PASS")

    def test_deny_redirects_access_denied(self):
        _, challenge = self._pkce()
        auth = self._authorize(challenge=challenge, state="deny-me")
        dispatch(["system", "credential", "deny-oauth", auth["pending_id"]], root=self.tmp)
        exc = open_no_redirect(self.base + auth["continue_path"])
        self.assertEqual(exc.code, 302)
        loc = exc.headers.get("Location") or ""
        params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        self.assertEqual(params.get("error", [None])[0], "access_denied")
        self.assertEqual(params.get("state", [None])[0], "deny-me")
        self.assertEqual(params.get("iss", [None])[0], self.bridge.canonical_public_base())
        self.assertNotIn("code", params)
        print("MANUAL_CONSENT_DENY=PASS")

    def test_expired_pending_cannot_complete(self):
        _, challenge = self._pkce()
        auth = self._authorize(challenge=challenge)
        past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
        self.plane.conn.execute(
            "UPDATE ai_oauth_pending SET expires_at = ? WHERE id = ?",
            (past, auth["pending_id"]),
        )
        exc = open_no_redirect(self.base + auth["continue_path"])
        # Fail closed: 400 JSON, not a success redirect with code.
        self.assertEqual(exc.code, 400)
        body = json.loads(exc.read().decode("utf-8"))
        self.assertIn("expired", (body.get("error_description") or "").lower())
        print("MANUAL_CONSENT_EXPIRED=PASS")

    def test_approve_then_expire_continue_fail_closed(self):
        """Finding A: expiry must bound post-approval browser continuation."""
        _, challenge = self._pkce()
        auth = self._authorize(challenge=challenge, state="ttl-after-approve")
        dispatch(
            ["system", "credential", "approve-oauth", auth["pending_id"]],
            root=self.tmp,
        )
        row = self.plane.conn.execute(
            "SELECT status, code_plain FROM ai_oauth_pending WHERE id = ?",
            (auth["pending_id"],),
        ).fetchone()
        self.assertEqual(row["status"], "approved")
        self.assertTrue(str(row["code_plain"] or "").startswith("drc_"))
        code_digest = hashlib.sha256(row["code_plain"].encode("utf-8")).hexdigest()
        past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
        self.plane.conn.execute(
            "UPDATE ai_oauth_pending SET expires_at = ? WHERE id = ?",
            (past, auth["pending_id"]),
        )
        exc = open_no_redirect(self.base + auth["continue_path"])
        self.assertEqual(exc.code, 400)
        body = json.loads(exc.read().decode("utf-8"))
        self.assertIn("expired", (body.get("error_description") or "").lower())
        gone = self.plane.conn.execute(
            "SELECT id FROM ai_oauth_pending WHERE id = ?", (auth["pending_id"],)
        ).fetchone()
        self.assertIsNone(gone)
        leftover = self.plane.conn.execute(
            "SELECT code_hash FROM ai_oauth_codes WHERE code_hash = ? AND used_at IS NULL",
            (code_digest,),
        ).fetchone()
        self.assertIsNone(leftover)
        print("MANUAL_CONSENT_APPROVED_EXPIRED=PASS")

    def test_replay_and_wrong_token_fail_closed(self):
        verifier, challenge = self._pkce()
        auth = self._authorize(challenge=challenge, state="once")
        dispatch(
            ["system", "credential", "approve-oauth", auth["pending_id"]],
            root=self.tmp,
        )
        first = open_no_redirect(self.base + auth["continue_path"])
        self.assertEqual(first.code, 302)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(first.headers.get("Location") or "").query)
        code = params["code"][0]
        issued = self._exchange(code=code, verifier=verifier, resource=auth["resource"])
        self.assertTrue(issued.get("access_token"))
        # Same continue URL again must fail closed.
        replay = open_no_redirect(self.base + auth["continue_path"])
        self.assertEqual(replay.code, 400)
        # Unrelated authorize cannot steal prior completion token.
        auth2 = self._authorize(challenge=challenge, state="other")
        stolen = open_no_redirect(self.base + auth["continue_path"])
        self.assertEqual(stolen.code, 400)
        # Wrong token on second transaction.
        bad = open_no_redirect(self.base + "/oauth/continue?t=not-a-real-token")
        self.assertEqual(bad.code, 400)
        wait2 = urllib.request.urlopen(self.base + auth2["continue_path"], timeout=10)
        self.assertEqual(wait2.status, 200)
        print("MANUAL_CONSENT_REPLAY_ISOLATION=PASS")

    def test_approve_after_deny_rejected(self):
        _, challenge = self._pkce()
        auth = self._authorize(challenge=challenge)
        dispatch(["system", "credential", "deny-oauth", auth["pending_id"]], root=self.tmp)
        rc = dispatch(
            ["system", "credential", "approve-oauth", auth["pending_id"]],
            root=self.tmp,
        )
        self.assertEqual(rc, 1)
        print("MANUAL_CONSENT_DENY_THEN_APPROVE=PASS")


if __name__ == "__main__":
    unittest.main()
