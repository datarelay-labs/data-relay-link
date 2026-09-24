#!/usr/bin/env python3
"""Production manual OAuth consent: browser redirect completion without AUTO_APPROVE."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_cli import dispatch  # noqa: E402
from frp_ctl_grammar import match  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_mcp_bridge import MCPBridge, MCP_PROTOCOL_VERSION, ThreadingHTTPServer, make_handler  # noqa: E402
import frp_frontend  # noqa: E402
import frp_pki  # noqa: E402


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def nginx_bin():
    for cand in (os.environ.get("FRP_NGINX_BIN"), "/usr/sbin/nginx", shutil.which("nginx")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def open_no_redirect(url, *, context=None):
    handlers = [_NoRedirect]
    if context is not None:
        handlers.insert(0, urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
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
        # Browser success is a trusted runtime identity. pending is only the
        # in-progress verification ceremony and must not authenticate after token exchange.
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'agent-a'"
        )
        self.plane.conn.commit()
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
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer %s" % token,
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            "Mcp-Method": "tools/list",
        }
        req = urllib.request.Request(
            self.base + "/mcp",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
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
        grammar = self._public_grammar(
            ["system", "credential", "approve-oauth", auth["pending_id"]]
        )
        self.assertEqual(grammar.get("status"), "ok")
        self.assertEqual(grammar.get("action"), "control_plane")
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
        status, payload = self._mcp(issued["access_token"])
        self.assertEqual(status, 200, payload)
        self.assertIn("tools", json.dumps(payload))
        print("MANUAL_CONSENT_BROWSER_FLOW=PASS")
        print("MANUAL_CONSENT_MCP_AUTH_AFTER_EXCHANGE=PASS")

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

    def test_concurrent_continue_exactly_one_success(self):
        """Finding D: threaded concurrent /oauth/continue must be single-use."""
        verifier, challenge = self._pkce()
        auth = self._authorize(challenge=challenge, state="race")
        dispatch(
            ["system", "credential", "approve-oauth", auth["pending_id"]],
            root=self.tmp,
        )
        url = self.base + auth["continue_path"]
        barrier = threading.Barrier(8)

        def one_continue(_idx):
            barrier.wait(timeout=10)
            return open_no_redirect(url)

        results = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(one_continue, i) for i in range(8)]
            for fut in as_completed(futs):
                results.append(fut.result())

        successes = [r for r in results if r.code == 302]
        failures = [r for r in results if r.code != 302]
        self.assertEqual(len(successes), 1, "expected exactly one success, got %s" % [r.code for r in results])
        self.assertEqual(len(failures), 7)
        for fail in failures:
            self.assertEqual(fail.code, 400)
            body = json.loads(fail.read().decode("utf-8"))
            self.assertNotIn("code", body)
        loc = successes[0].headers.get("Location") or ""
        params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        code = params["code"][0]
        self.assertTrue(code.startswith("drc_"))
        # Losers must not have disclosed the same code via Location.
        for fail in failures:
            self.assertNotIn(code, fail.headers.get("Location") or "")
        issued = self._exchange(code=code, verifier=verifier, resource=auth["resource"])
        self.assertTrue(issued.get("access_token", "").startswith("drauth_"))
        print("MANUAL_CONSENT_CONCURRENT_CONTINUE=PASS")

    def test_production_frontend_continue_redirect(self):
        """Finding C: public nginx frontend must proxy exact /oauth/continue."""
        bin_path = nginx_bin()
        if bin_path is None:
            self.skipTest("nginx not available")
        frontend_port = free_port()
        pki = frp_pki.ensure_pki(str(Path(self.tmp) / "pki-fe"), "127.0.0.1")
        temp_root = Path(self.tmp) / "nginx-temp"
        for name in ("body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (temp_root / name).mkdir(parents=True, exist_ok=True)
        dest = Path(self.tmp) / "frontend-oauth.conf"
        frp_frontend.write_nginx_conf(
            str(dest),
            public_host="127.0.0.1",
            frontend_port=frontend_port,
            allocator_listen_port=free_port(),
            control_listen_port=free_port(),
            ca_cert=pki["ca_crt"],
            server_cert=pki["server_crt"],
            server_key=pki["server_key"],
            pid_path=str(Path(self.tmp) / "nginx-oauth.pid"),
            error_log=str(Path(self.tmp) / "frontend-oauth.error.log"),
            temp_root=str(temp_root),
            mcp_bridge_port=self.port,
        )
        conf_text = dest.read_text(encoding="utf-8")
        self.assertIn("location = /oauth/continue {", conf_text)
        self.assertNotIn("location ^~ /oauth/", conf_text)
        nginx = subprocess.Popen(
            [bin_path, "-c", str(dest)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ctx = ssl.create_default_context(cafile=pki["ca_crt"])
        public = "https://127.0.0.1:%s" % frontend_port
        try:
            deadline = time.time() + 5
            last = None
            while time.time() < deadline:
                try:
                    bad = open_no_redirect(public + "/oauth/continue?t=not-a-real-token", context=ctx)
                    # Reaching MCP Bridge yields OAuth JSON 400, not nginx HTML 404.
                    self.assertEqual(bad.code, 400)
                    body = json.loads(bad.read().decode("utf-8"))
                    self.assertEqual(body.get("error"), "invalid_request")
                    break
                except Exception as exc:
                    last = exc
                    time.sleep(0.05)
            else:
                self.fail("frontend /oauth/continue not ready: %s" % last)

            verifier, challenge = self._pkce()
            # Authorize via public frontend (same exact route set).
            resource = self.bridge.canonical_resource()
            qs = urllib.parse.urlencode(
                {
                    "response_type": "code",
                    "client_id": "agent-a",
                    "redirect_uri": "http://127.0.0.1/callback",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "resource": resource,
                    "state": "fe-continue",
                }
            )
            page = (
                urllib.request.urlopen(public + "/oauth/authorize?" + qs, context=ctx, timeout=10)
                .read()
                .decode("utf-8")
            )
            pending_m = re.search(r"approve-oauth\s+(oap_[A-Za-z0-9_-]+)", page)
            cont_m = re.search(r"/oauth/continue\?([^\"'\s>]+)", page)
            self.assertIsNotNone(pending_m, page)
            self.assertIsNotNone(cont_m, page)
            pending_id = pending_m.group(1)
            continue_path = "/oauth/continue?" + cont_m.group(1)
            dispatch(["system", "credential", "approve-oauth", pending_id], root=self.tmp)
            exc = open_no_redirect(public + continue_path, context=ctx)
            self.assertEqual(exc.code, 302)
            loc = exc.headers.get("Location") or ""
            parsed = urllib.parse.urlparse(loc)
            self.assertEqual("%s://%s%s" % (parsed.scheme, parsed.netloc, parsed.path), "http://127.0.0.1/callback")
            params = urllib.parse.parse_qs(parsed.query)
            self.assertEqual(params.get("state", [None])[0], "fe-continue")
            self.assertEqual(params.get("iss", [None])[0], self.bridge.canonical_public_base())
            code = params["code"][0]
            self.assertTrue(code.startswith("drc_"))
            issued = self._exchange(code=code, verifier=verifier, resource=resource)
            self.assertTrue(issued.get("access_token", "").startswith("drauth_"))
            print("MANUAL_CONSENT_FRONTEND_CONTINUE=PASS")
        finally:
            if nginx.poll() is None:
                nginx.terminate()
                try:
                    nginx.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    nginx.kill()
                    nginx.wait(timeout=2)


    def _public_grammar(self, tokens):
        return match(tokens, "server")

    def test_dcr_unbound_public_cli_identity_approval(self):
        dispatch(["set", "ai-principal", "agent-dcr"], root=self.tmp)
        dispatch(["set", "ai-principal", "agent-dcr", "enabled"], root=self.tmp)
        dispatch(["set", "ai-principal", "agent-off"], root=self.tmp)
        reg = json.loads(
            urllib.request.urlopen(
                urllib.request.Request(
                    self.base + "/oauth/register",
                    data=json.dumps(
                        {
                            "redirect_uris": ["http://127.0.0.1/cb-dcr"],
                            "token_endpoint_auth_method": "none",
                            "grant_types": ["authorization_code", "refresh_token"],
                            "client_name": "manual-dcr",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=10,
            )
            .read()
            .decode("utf-8")
        )
        verifier, challenge = self._pkce()
        auth = self._authorize(
            challenge=challenge,
            state="dcr-bind",
            client_id=reg["client_id"],
            redirect="http://127.0.0.1/cb-dcr",
        )
        self.assertIn("AI-IDENTITY", auth["page"])
        pending = auth["pending_id"]
        one = ["system", "credential", "approve-oauth", pending]
        two = one + ["agent-dcr"]
        three = two + ["extra"]
        self.assertEqual(self._public_grammar(one).get("status"), "ok")
        self.assertEqual(self._public_grammar(two).get("action"), "control_plane")
        rejected = self._public_grammar(three)
        self.assertEqual(rejected.get("status"), "error")
        self.assertIn("unexpected argument: extra", rejected.get("message", ""))
        err = io.StringIO()
        with redirect_stderr(err):
            rc = dispatch(one, root=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("AI Principal", err.getvalue())
        err = io.StringIO()
        with redirect_stderr(err):
            rc = dispatch(one + ["missing-principal"], root=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("not found or disabled", err.getvalue())
        err = io.StringIO()
        with redirect_stderr(err):
            rc = dispatch(one + ["agent-off"], root=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("not found or disabled", err.getvalue())
        try:
            dispatch(three, root=self.tmp)
        except SystemExit as exc:
            self.assertIn("unexpected argument: extra", str(exc))
        else:
            self.fail("third approve-oauth argument reached the handler")
        err = io.StringIO()
        with redirect_stderr(err):
            rc = dispatch(two, root=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("not VERIFIED", err.getvalue())
        self.assertEqual(
            str(self.plane.get_principal("agent-dcr")["credential_status"]).lower(),
            "none",
        )
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'revoked' WHERE name = 'agent-dcr'"
        )
        err = io.StringIO()
        with redirect_stderr(err):
            rc = dispatch(two, root=self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("revoked", err.getvalue())
        self.assertEqual(
            str(self.plane.get_principal("agent-dcr")["credential_status"]).lower(),
            "revoked",
        )
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'agent-dcr'"
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = dispatch(two, root=self.tmp)
        self.assertEqual(rc, 0)
        self.assertNotIn("drc_", buf.getvalue())
        self.assertEqual(
            str(self.plane.get_principal("agent-dcr")["credential_status"]).lower(),
            "verified",
        )
        exc = open_no_redirect(self.base + auth["continue_path"])
        self.assertEqual(exc.code, 302)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(exc.headers.get("Location") or "").query)
        self.assertEqual(params.get("state", [None])[0], "dcr-bind")
        code = params["code"][0]
        issued = self._exchange(
            code=code,
            verifier=verifier,
            resource=auth["resource"],
            client_id=reg["client_id"],
            redirect="http://127.0.0.1/cb-dcr",
        )
        self.assertTrue(issued.get("access_token", "").startswith("drauth_"))
        status, payload = self._mcp(issued["access_token"])
        self.assertEqual(status, 200, payload)
        self.assertIn("tools", json.dumps(payload))
        print("DCR_PUBLIC_CLI_IDENTITY_APPROVAL=PASS")
        print("DCR_APPROVE_PKCE_MCP_AUTH=PASS")


if __name__ == "__main__":
    unittest.main()
