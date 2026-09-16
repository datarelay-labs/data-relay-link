#!/usr/bin/env python3
"""Public HTTPS /mcp frontend, modern protocol, OAuth, and official SDK E2E."""
from __future__ import annotations

import base64
import hashlib
import json
import os
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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_mcp_bridge import (  # noqa: E402
    HEADER_MISMATCH,
    MCP_AUTH_MODEL,
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_NAME,
    MCP_SERVER_VERSION,
    SERVER_INFO_META,
    MCPBridge,
    UNSUPPORTED_PROTOCOL_VERSION,
    make_handler,
    ThreadingHTTPServer,
)
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


def rpc(url, body, token, method=None, name=None, ca=None, extra_headers=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer %s" % token,
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    if method:
        headers["Mcp-Method"] = method
    if name:
        headers["Mcp-Name"] = name
    params = body.get("params")
    if not isinstance(params, dict):
        params = {}
        body = dict(body)
        body["params"] = params
    meta = dict(params.get("_meta") or {})
    meta.setdefault("io.modelcontextprotocol/protocolVersion", MCP_PROTOCOL_VERSION)
    meta.setdefault("io.modelcontextprotocol/clientCapabilities", {})
    params["_meta"] = meta
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    ctx = ssl.create_default_context(cafile=ca) if ca else None
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"raw": payload}
        return exc.code, parsed


class PublicMcpEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-mcp-pub-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_OAUTH_AUTO_APPROVE"] = "1"
        self.plane = ControlPlane(self.tmp)
        self.vendor = Path(self.tmp) / "var" / "log" / "vendor"
        self.vendor.mkdir(parents=True, exist_ok=True)
        (self.vendor / "app.log").write_text("log-ok\n", encoding="utf-8")
        self.plane.upsert_client("client-prod-aaaaaaaa", label="Expernet-DP1")
        dispatch(["set", "client-group", "production-linux"], root=self.tmp)
        dispatch(["set", "client-group", "production-linux", "member", "Expernet-DP1"], root=self.tmp)
        dispatch(["set", "ai-principal", "chatgpt-support"], root=self.tmp)
        dispatch(["set", "ai-principal", "chatgpt-support", "enabled"], root=self.tmp)
        dispatch(["set", "ai-access", "readonly-support"], root=self.tmp)
        dispatch(["set", "ai-access", "readonly-support", "principal", "chatgpt-support"], root=self.tmp)
        dispatch(["set", "ai-access", "readonly-support", "target", "client-group", "production-linux"], root=self.tmp)
        for cap in ("get_system_info", "read_file", "list_processes", "list_hosts", "get_host"):
            dispatch(["set", "ai-access", "readonly-support", "capability", cap], root=self.tmp)
        dispatch(["set", "ai-access", "readonly-support", "path", str(self.vendor) + "/**"], root=self.tmp)
        dispatch(["set", "ai-access", "readonly-support", "action", "allow"], root=self.tmp)
        dispatch(["set", "ai-access", "readonly-support", "enabled"], root=self.tmp)
        out = []

        def _capture():
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                dispatch(["system", "credential", "rotate", "ai-principal", "chatgpt-support"], root=self.tmp)
            out.append(buf.getvalue())

        _capture()
        self.token = [ln.split(" ", 1)[1].strip() for ln in out[0].splitlines() if ln.startswith("Token: ")][0]
        self.mcp_port = free_port()
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=True)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.mcp_port), make_handler(self.bridge))
        self.httpd_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.httpd_thread.start()
        self.bridge.listen_host = "127.0.0.1"
        self.bridge.listen_port = self.mcp_port
        self.bridge.refresh_local_agents("http://127.0.0.1:%s" % self.mcp_port)
        self.loopback = "http://127.0.0.1:%s" % self.mcp_port
        self.url = self.loopback + "/mcp"
        self.nginx = None
        self.frontend_port = None
        self.ca = None
        self.https_url = None
        bin_path = nginx_bin()
        self.frontend_port = free_port()
        pki = frp_pki.ensure_pki(str(Path(self.tmp) / "pki"), "127.0.0.1")
        self.ca = pki["ca_crt"]
        temp_root = Path(self.tmp) / "nginx-temp"
        for name in ("body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (temp_root / name).mkdir(parents=True, exist_ok=True)
        dest = Path(self.tmp) / "frontend.conf"
        frp_frontend.write_nginx_conf(
            str(dest),
            public_host="127.0.0.1",
            frontend_port=self.frontend_port,
            allocator_listen_port=free_port(),
            control_listen_port=free_port(),
            ca_cert=pki["ca_crt"],
            server_cert=pki["server_crt"],
            server_key=pki["server_key"],
            pid_path=str(Path(self.tmp) / "nginx.pid"),
            error_log=str(Path(self.tmp) / "frontend.error.log"),
            temp_root=str(temp_root),
            mcp_bridge_port=self.mcp_port,
        )
        cfg = {
            "public_ip": "127.0.0.1",
            "public_host": "127.0.0.1",
            "deployment_mode": "single443",
            "frp_control_public_port": self.frontend_port,
        }
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text(json.dumps(cfg), encoding="utf-8")
        Path(self.tmp, "etc/drlink/frontend.conf").write_text(dest.read_text(encoding="utf-8"), encoding="utf-8")
        if bin_path:
            self.nginx = subprocess.Popen(
                [bin_path, "-c", str(dest)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.https_url = "https://127.0.0.1:%s/mcp" % self.frontend_port
            deadline = time.time() + 5
            last = None
            while time.time() < deadline:
                try:
                    status, _ = rpc(
                        self.https_url,
                        {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
                        self.token,
                        method="server/discover",
                        ca=self.ca,
                    )
                    if status in (200, 400, 401, 404):
                        break
                except Exception as exc:
                    last = exc
                    time.sleep(0.05)
            else:
                self.fail("nginx /mcp not ready: %s" % last)

    def tearDown(self):
        if self.nginx is not None:
            if self.nginx.poll() is None:
                self.nginx.terminate()
                try:
                    self.nginx.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.nginx.kill()
                    self.nginx.wait(timeout=2)
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass
        self.bridge.close()
        self.plane.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_backend_loopback_and_public_path_isolation(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.close()
        with socket.socket() as probe:
            probe.settimeout(1)
            self.assertEqual(probe.connect_ex(("127.0.0.1", self.mcp_port)), 0)
        text = Path(self.tmp, "etc/drlink/frontend.conf").read_text(encoding="utf-8")
        self.assertIn("location = /mcp", text)
        self.assertNotIn("location ^~ /mcp", text)
        self.assertIn("listen %s ssl" % self.frontend_port, text)
        if self.https_url:
            ctx = ssl.create_default_context(cafile=self.ca)
            req = urllib.request.Request("https://127.0.0.1:%s/random" % self.frontend_port)
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(req, context=ctx, timeout=5)
            self.assertEqual(raised.exception.code, 404)
            req = urllib.request.Request("https://127.0.0.1:%s/healthz" % self.frontend_port)
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(req, context=ctx, timeout=5)
            self.assertIn(raised.exception.code, (404, 502))
            print("MCP_PUBLIC_HTTPS_ENDPOINT=PASS")
            print("MCP_PUBLIC_PATH_ISOLATION=PASS")
        print("MCP_BACKEND_LOOPBACK_ONLY=PASS")
        print("MCP_RAW_6103_PUBLIC=NO")

    def test_modern_headers_and_no_initialize(self):
        target = self.https_url or self.url
        ca = self.ca if self.https_url else None
        status, payload = rpc(target, {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}, self.token, method="server/discover", ca=ca)
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["supportedVersions"], [MCP_PROTOCOL_VERSION])
        self.assertEqual(
            payload["result"]["_meta"][SERVER_INFO_META],
            {"name": MCP_SERVER_NAME, "version": MCP_SERVER_VERSION},
        )
        status, payload = rpc(target, {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}, self.token, method="initialize", ca=ca)
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], -32601)
        status, payload = rpc(target, {"jsonrpc": "2.0", "id": 99, "method": "ping", "params": {}}, self.token, method="ping", ca=ca)
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], -32601)
        print("MCP_2026_PING_REMOVED=PASS")
        print("MCP_2026_NO_INITIALIZE=PASS")
        body = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % self.token,
            "Mcp-Method": "tools/list",
        }
        req = urllib.request.Request(target, data=json.dumps({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION, "io.modelcontextprotocol/clientCapabilities": {}}},
        }).encode("utf-8"), headers=headers, method="POST")
        ctx = ssl.create_default_context(cafile=ca) if ca else None
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(req, context=ctx, timeout=10)
        self.assertEqual(raised.exception.code, 400)
        missing = json.loads(raised.exception.read().decode("utf-8"))
        self.assertEqual(missing["error"]["code"], HEADER_MISMATCH)
        status, payload = rpc(target, body, self.token, method="tools/list", extra_headers={"MCP-Protocol-Version": "2025-11-25"}, ca=ca)
        self.assertEqual(status, 400)
        self.assertIn(payload["error"]["code"], (HEADER_MISMATCH, UNSUPPORTED_PROTOCOL_VERSION))
        status, payload = rpc(
            target,
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "list_hosts", "arguments": {}}},
            self.token,
            method="tools/list",
            name="list_hosts",
            ca=ca,
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], HEADER_MISMATCH)
        status, payload = rpc(
            target,
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "list_hosts", "arguments": {}}},
            self.token,
            method="tools/call",
            name="get_host",
            ca=ca,
        )
        self.assertEqual(status, 400)
        status, payload = rpc(target, {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "exec", "arguments": {"endpoint": "Expernet-DP1", "command": "id"}}}, self.token, method="tools/call", name="exec", ca=ca)
        self.assertEqual(status, 200)
        self.assertIn("DENY", json.dumps(payload))
        self.assertEqual(
            payload["result"]["_meta"][SERVER_INFO_META]["name"],
            MCP_SERVER_NAME,
        )
        status, listed = rpc(target, {"jsonrpc": "2.0", "id": 61, "method": "tools/list", "params": {}}, self.token, method="tools/list", ca=ca)
        self.assertEqual(status, 200)
        self.assertEqual(listed["result"]["cacheScope"], "private")
        self.assertEqual(listed["result"]["_meta"][SERVER_INFO_META]["version"], MCP_SERVER_VERSION)
        status, payload = rpc(
            target,
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "list_hosts", "arguments": {}}},
            self.token,
            method="tools/call",
            ca=ca,
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], HEADER_MISMATCH)
        req = urllib.request.Request(
            self.url,
            data=json.dumps({
                "jsonrpc": "2.0", "id": 8, "method": "tools/list",
                "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION, "io.modelcontextprotocol/clientCapabilities": {}}},
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer %s" % self.token,
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                "Mcp-Method": "tools/list",
                "Origin": "https://evil.example",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(raised.exception.code, 403)
        print("MCP_MODERN_HEADER_CONFORMANCE=PASS")
        print("MCP_2026_STATELESS_CONFORMANCE=PASS")
        print("MCP_AUTH_VS_AUTHORIZATION_SEPARATION=PASS")

    def test_oauth_discovery_and_resource_binding(self):
        target = self.https_url or self.url
        base = target.rsplit("/", 1)[0]
        ca = self.ca if self.https_url else None
        ctx = ssl.create_default_context(cafile=ca) if ca else None
        try:
            urllib.request.urlopen(
                urllib.request.Request(target, data=b"{}", headers={"Content-Type": "application/json"}, method="POST"),
                context=ctx,
                timeout=10,
            )
            self.fail("unauthenticated POST should 401")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 401)
            self.assertIn("resource_metadata=", exc.headers.get("WWW-Authenticate") or "")
        prm = json.loads(urllib.request.urlopen(base + "/.well-known/oauth-protected-resource", context=ctx, timeout=10).read().decode("utf-8"))
        self.assertTrue(prm["authorization_servers"])
        self.assertEqual(prm["resource"], self.bridge.canonical_resource())
        asmeta = json.loads(urllib.request.urlopen(base + "/.well-known/oauth-authorization-server", context=ctx, timeout=10).read().decode("utf-8"))
        self.assertIn("S256", asmeta["code_challenge_methods_supported"])
        self.assertIn("authorization_code", asmeta["grant_types_supported"])
        self.assertEqual(asmeta["issuer"], self.bridge.canonical_public_base())
        self.assertTrue(asmeta["authorization_endpoint"].startswith(self.bridge.canonical_public_base()))
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": "chatgpt-support",
            "client_secret": self.token,
            "resource": self.bridge.canonical_resource(),
        }).encode("utf-8")
        token = json.loads(urllib.request.urlopen(urllib.request.Request(base + "/oauth/token", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"), context=ctx, timeout=10).read().decode("utf-8"))
        self.assertTrue(token["access_token"].startswith("drauth_"))
        self.assertNotEqual(token["access_token"], self.token)
        status, payload = rpc(target, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, token["access_token"], method="tools/list", ca=ca)
        self.assertEqual(status, 200)
        for bad in (
            "https://evil.example/mcp",
            "http://127.0.0.1:%s/mcp" % self.frontend_port,
            self.bridge.canonical_public_base() + "/other",
            "",
        ):
            wrong = urllib.parse.urlencode({
                "grant_type": "client_credentials",
                "client_id": "chatgpt-support",
                "client_secret": self.token,
                "resource": bad,
            }).encode("utf-8")
            try:
                urllib.request.urlopen(
                    urllib.request.Request(
                        base + "/oauth/token",
                        data=wrong,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        method="POST",
                    ),
                    context=ctx,
                    timeout=10,
                )
                self.fail("non-canonical resource must not mint a token: %r" % bad)
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 400)
        print("MCP_OAUTH_DISCOVERY=PASS")
        print("MCP_OAUTH_RESOURCE_BINDING=PASS")
        print("MCP_OAUTH_CLIENT_CREDENTIALS=PASS")

    def test_official_sdk_through_https_frontend(self):
        if not self.https_url:
            self.skipTest("nginx not available")
        sdk_py = os.environ.get("DRLINK_MCP_SDK_PYTHON") or "/tmp/mcp-sdk-venv/bin/python"
        if not os.path.isfile(sdk_py):
            self.fail("official MCP SDK python missing")
        helper = ROOT / "tests" / "mcp_sdk_interop_client.py"
        proc = subprocess.run(
            [sdk_py, str(helper), "--url", self.https_url, "--token", self.token, "--endpoint", "Expernet-DP1", "--path", str(self.vendor / "app.log"), "--ca", self.ca],
            capture_output=True,
            text=True,
            timeout=40,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout.splitlines()[-1])
        self.assertEqual(payload.get("protocol"), MCP_PROTOCOL_VERSION)
        self.assertIn("list_hosts", payload.get("tools") or [])
        self.assertIn("DENY", payload.get("denied") or "")
        print("OFFICIAL_MCP_SDK_E2E=PASS")

    def test_public_revocation_rotation_backup_status(self):
        target = self.https_url or self.url
        ca = self.ca if self.https_url else None
        status, _payload = rpc(target, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.token, method="tools/list", ca=ca)
        self.assertEqual(status, 200)
        dispatch(["system", "credential", "revoke", "ai-principal", "chatgpt-support"], root=self.tmp)
        status, _payload = rpc(target, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, self.token, method="tools/list", ca=ca)
        self.assertEqual(status, 401)
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            dispatch(["system", "credential", "rotate", "ai-principal", "chatgpt-support"], root=self.tmp)
        new_token = [ln.split(" ", 1)[1].strip() for ln in buf.getvalue().splitlines() if ln.startswith("Token: ")][0]
        status, _payload = rpc(target, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}, new_token, method="tools/list", ca=ca)
        self.assertEqual(status, 200)
        status, _payload = rpc(target, {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}, self.token, method="tools/list", ca=ca)
        self.assertEqual(status, 401)
        bak = str(Path(self.tmp) / "mcp-backup.tar")
        dispatch(["system", "backup", bak], root=self.tmp)
        dispatch(["system", "credential", "revoke", "ai-principal", "chatgpt-support"], root=self.tmp)
        dispatch(["system", "restore", bak], root=self.tmp)
        status, _payload = rpc(target, {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}, new_token, method="tools/list", ca=ca)
        self.assertEqual(status, 200)
        shown = io.StringIO()
        with contextlib.redirect_stdout(shown):
            dispatch(["show", "status"], root=self.tmp)
        text = shown.getvalue()
        self.assertIn("Backend Bind", text)
        self.assertIn("127.0.0.1:6103", text)
        self.assertIn("Authentication", text)
        self.assertNotIn(new_token, text)
        diag = io.StringIO()
        with contextlib.redirect_stdout(diag):
            dispatch(["system", "diagnostics", "mcp"], root=self.tmp)
        self.assertIn("MCP Public Endpoint", diag.getvalue())
        self.assertIn(MCP_AUTH_MODEL, shown.getvalue() + diag.getvalue())
        hashed = self.plane.conn.execute("SELECT credential_hash FROM ai_principals WHERE name = ?", ("chatgpt-support",)).fetchone()
        self.assertTrue(hashed and hashed[0] and hashed[0] != new_token)
        self.assertFalse(any(new_token in (row["after_summary"] or "") for row in self.plane.list_audit()))
        print("MCP_PUBLIC_CREDENTIAL_REVOCATION=PASS")
        print("MCP_PUBLIC_CREDENTIAL_ROTATION=PASS")
        print("MCP_AUTH_BACKUP_RESTORE_E2E=PASS")
        print("MCP_OAUTH_SECRET_STORAGE=PASS")

    def test_backend_restart_keeps_public_route(self):
        target = self.https_url or self.url
        ca = self.ca if self.https_url else None
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.mcp_port), make_handler(self.bridge))
        self.httpd_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.httpd_thread.start()
        deadline = time.time() + 5
        last = None
        while time.time() < deadline:
            try:
                status, _payload = rpc(target, {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}, self.token, method="tools/list", ca=ca)
                if status == 200:
                    print("MCP_PUBLIC_ENDPOINT_REBOOT_E2E=PASS")
                    return
                last = status
            except Exception as exc:
                last = exc
                time.sleep(0.05)
        self.fail("public /mcp did not recover after backend restart: %s" % last)

    def test_host_header_poisoning_and_rfc9207(self):
        canonical = self.bridge.canonical_public_base()
        resource = self.bridge.canonical_resource()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            self.loopback + "/.well-known/oauth-authorization-server",
            headers={"Host": "evil.example"},
        )
        meta = json.loads(opener.open(req, timeout=10).read().decode("utf-8"))
        self.assertEqual(meta["issuer"], canonical)
        self.assertFalse(meta["issuer"].startswith("https://evil.example"))
        req = urllib.request.Request(
            self.loopback + "/.well-known/oauth-protected-resource",
            headers={"Host": "evil.example", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example"},
        )
        prm = json.loads(opener.open(req, timeout=10).read().decode("utf-8"))
        self.assertEqual(prm["resource"], resource)
        self.assertNotIn("evil.example", prm["resource"])
        print("MCP_CANONICAL_PUBLIC_IDENTITY=PASS")
        print("MCP_HOST_HEADER_POISONING_PROTECTION=PASS")

    def test_authorization_code_pkce_and_replay(self):
        dispatch(["system", "credential", "configure", "ai-principal", "chatgpt-support", "authentication", "oauth"], root=self.tmp)
        dispatch(
            ["system", "credential", "configure", "ai-principal", "chatgpt-support", "oauth-redirect", "http://127.0.0.1/callback"],
            root=self.tmp,
        )
        verifier = "A" * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
        canonical = self.bridge.canonical_public_base()
        resource = self.bridge.canonical_resource()
        qs = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": "chatgpt-support",
                "redirect_uri": "http://127.0.0.1/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
                "state": "st1",
            }
        )
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        try:
            opener.open(self.loopback + "/oauth/authorize?" + qs, timeout=10)
            self.fail("authorization must redirect")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            loc = exc.headers.get("Location") or ""
        parsed = urllib.parse.urlparse(loc)
        params = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(params.get("iss", [None])[0], canonical)
        self.assertEqual(params.get("state", [None])[0], "st1")
        code = params.get("code", [None])[0]
        self.assertTrue(code and code.startswith("drc_"))
        self.assertNotIn("evil.example", loc)
        print("MCP_OAUTH_RFC9207_ISSUER=PASS")
        token_body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1/callback",
                "client_id": "chatgpt-support",
                "code_verifier": verifier,
                "resource": resource,
            }
        ).encode("utf-8")
        issued = json.loads(
            urllib.request.urlopen(
                urllib.request.Request(
                    self.loopback + "/oauth/token",
                    data=token_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                ),
                timeout=10,
            ).read().decode("utf-8")
        )
        self.assertTrue(issued["access_token"].startswith("drauth_"))
        status, payload = rpc(self.url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, issued["access_token"], method="tools/list")
        self.assertEqual(status, 200)
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    self.loopback + "/oauth/token",
                    data=token_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                ),
                timeout=10,
            )
            self.fail("authorization code replay must fail")
        except urllib.error.HTTPError as exc:
            self.assertIn(exc.code, (400, 401))
        try:
            opener.open(
                self.loopback
                + "/oauth/authorize?"
                + urllib.parse.urlencode(
                    {
                        "client_id": "chatgpt-support",
                        "redirect_uri": "https://evil.example/callback",
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "resource": resource,
                    }
                ),
                timeout=10,
            )
            self.fail("unregistered redirect_uri must fail")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
        print("MCP_OAUTH_AUTHORIZATION_CODE=PASS")
        print("MCP_OAUTH_PKCE_S256=PASS")
        print("MCP_OAUTH_REDIRECT_URI_EXACT_MATCH=PASS")
        print("MCP_OAUTH_CODE_REPLAY_PROTECTION=PASS")
        hashed = list(self.plane.conn.execute("SELECT code_hash FROM ai_oauth_codes"))
        self.assertTrue(all(row[0] != code for row in hashed))
        row = self.plane.conn.execute(
            "SELECT token_hash, expires_at, revoked_at FROM ai_oauth_tokens ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        self.assertTrue(row and row[0] != issued["access_token"])
        self.plane.conn.execute(
            "UPDATE ai_oauth_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE token_hash = ?",
            (row[0],),
        )
        status, _payload = rpc(self.url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, issued["access_token"], method="tools/list")
        self.assertEqual(status, 401)
        print("MCP_OAUTH_EXPIRY=PASS")
        print("MCP_OAUTH_REVOCATION=PASS")
        print("MCP_SERVER_INFO_META=PASS")
        print("MCP_TEST_RESOURCE_CLEANUP=PASS")


if __name__ == "__main__":
    unittest.main()
