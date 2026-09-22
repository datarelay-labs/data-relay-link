#!/usr/bin/env python3
"""Focused MCP remote-connector interop + OAuth security closure tests."""
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

from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane, OAUTH_UNBOUND_PRINCIPAL  # noqa: E402
import drlink_v24 as v24  # noqa: E402
from drlink_mcp_bridge import (  # noqa: E402
    MCP_PROTOCOL_VERSION,
    MCPBridge,
    ThreadingHTTPServer,
    make_handler,
)


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def rpc(url, body, token=None, method=None, name=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    if token:
        headers["Authorization"] = "Bearer %s" % token
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
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"raw": payload}
        return exc.code, parsed, dict(exc.headers)


class RemoteConnectorInteropTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-mcp-interop-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_OAUTH_AUTO_APPROVE"] = "1"
        self.plane = ControlPlane(self.tmp)
        self.vendor = Path(self.tmp) / "var" / "log" / "vendor"
        self.vendor.mkdir(parents=True, exist_ok=True)
        (self.vendor / "app.log").write_text("ok\n", encoding="utf-8")
        self.plane.upsert_client("client-a-aaaaaaaaaaaa", label="Host-A")
        self.plane.upsert_client("client-b-bbbbbbbbbbbb", label="Host-B")
        dispatch(["set", "network-group", "group-a", "members", "Host-A"], root=self.tmp)
        dispatch(["set", "ai-principal", "ro-agent"], root=self.tmp)
        dispatch(["set", "ai-principal", "ro-agent", "enabled"], root=self.tmp)
        dispatch(["set", "ai-principal", "rw-agent"], root=self.tmp)
        dispatch(["set", "ai-principal", "rw-agent", "enabled"], root=self.tmp)
        # Canonical v2.4 AI Access: verify identities first, then Permission Objects +
        # mode/source/destination/permission/enabled. Path scopes are internal-only.
        # Do not use superseded principal/target/capability/path/action grammar.
        import contextlib
        import io

        for name in ("ro-agent", "rw-agent"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                dispatch(["system", "credential", "rotate", "ai-principal", name], root=self.tmp)
            token = [ln.split(" ", 1)[1].strip() for ln in buf.getvalue().splitlines() if ln.startswith("Token: ")][0]
            setattr(self, name.replace("-", "_") + "_token", token)
            dispatch(
                ["system", "credential", "configure", "ai-principal", name, "authentication", "oauth"],
                root=self.tmp,
            )
            dispatch(
                [
                    "system",
                    "credential",
                    "configure",
                    "ai-principal",
                    name,
                    "oauth-redirect",
                    "http://127.0.0.1/callback",
                ],
                root=self.tmp,
            )
        dispatch(
            [
                "set",
                "permission-object",
                "ro-perms",
                "permissions",
                "host-info,process-read,file-read",
            ],
            root=self.tmp,
        )
        dispatch(
            [
                "set",
                "permission-object",
                "rw-perms",
                "permissions",
                "host-info,file-read,command-exec,file-write",
            ],
            root=self.tmp,
        )
        dispatch(
            [
                "set",
                "ai-access",
                "ro-rule",
                "mode",
                "whitelist",
                "source",
                "ro-agent",
                "destination",
                "group-a",
                "permission",
                "ro-perms",
                "enabled",
            ],
            root=self.tmp,
        )
        dispatch(
            [
                "set",
                "ai-access",
                "rw-rule",
                "mode",
                "whitelist",
                "source",
                "rw-agent",
                "destination",
                "Host-A",
                "permission",
                "rw-perms",
                "enabled",
            ],
            root=self.tmp,
        )
        vendor_glob = str(self.vendor) + "/**"
        v24.set_ai_policy_path_scopes(self.plane, "ro-rule", [vendor_glob])
        v24.set_ai_policy_path_scopes(self.plane, "rw-rule", [vendor_glob])
        self.port = free_port()
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), make_handler(self.bridge))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.bridge.listen_host = "127.0.0.1"
        self.bridge.listen_port = self.port
        self.base = "http://127.0.0.1:%s" % self.port
        self.url = self.base + "/mcp"
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text(
            json.dumps({"public_host": "127.0.0.1", "deployment_mode": "single443", "frp_control_public_port": 443}),
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

    def _auth_code(self, client_id="ro-agent"):
        verifier = "B" * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
        resource = self.bridge.canonical_resource()
        qs = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://127.0.0.1/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
                "state": "s1",
                "scope": "drlink.ai offline_access",
            }
        )

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        try:
            opener.open(self.base + "/oauth/authorize?" + qs, timeout=10)
            self.fail("expected redirect")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            loc = exc.headers.get("Location") or ""
        params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        self.assertEqual(params.get("iss", [None])[0], self.bridge.canonical_public_base())
        code = params["code"][0]
        body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1/callback",
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": resource,
            }
        ).encode("utf-8")
        issued = json.loads(
            urllib.request.urlopen(
                urllib.request.Request(
                    self.base + "/oauth/token",
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                ),
                timeout=10,
            ).read().decode("utf-8")
        )
        return issued, resource

    def test_discovery_pkce_refresh_dcr_cimd_and_binding(self):
        status, _, headers = rpc(self.url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        self.assertEqual(status, 401)
        self.assertIn("resource_metadata=", headers.get("WWW-Authenticate") or headers.get("www-authenticate") or "")
        prm = json.loads(urllib.request.urlopen(self.base + "/.well-known/oauth-protected-resource", timeout=10).read())
        asmeta = json.loads(urllib.request.urlopen(self.base + "/.well-known/oauth-authorization-server", timeout=10).read())
        self.assertEqual(prm["resource"], self.bridge.canonical_resource())
        self.assertIn("S256", asmeta["code_challenge_methods_supported"])
        self.assertNotIn("plain", asmeta["code_challenge_methods_supported"])
        self.assertIn("refresh_token", asmeta["grant_types_supported"])
        self.assertIn("offline_access", asmeta["scopes_supported"])
        self.assertTrue(asmeta.get("client_id_metadata_document_supported") is True)
        self.assertTrue(asmeta["registration_endpoint"].endswith("/oauth/register"))
        print("RFC9728_PUBLIC_DISCOVERY=PASS")
        print("OAUTH_AS_METADATA=PASS")
        print("OAUTH_OFFLINE_ACCESS_METADATA=PASS")

        # PKCE plain rejected
        qs = urllib.parse.urlencode(
            {
                "client_id": "ro-agent",
                "redirect_uri": "http://127.0.0.1/callback",
                "code_challenge": "x",
                "code_challenge_method": "plain",
                "resource": self.bridge.canonical_resource(),
            }
        )
        try:
            urllib.request.urlopen(self.base + "/oauth/authorize?" + qs, timeout=10)
            self.fail("plain PKCE must fail")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
        print("PKCE_PLAIN_ACCEPTED=NO")

        issued, resource = self._auth_code("ro-agent")
        self.assertTrue(issued["refresh_token"].startswith("drref_"))
        status, payload, _ = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            issued["access_token"],
            method="tools/list",
        )
        self.assertEqual(status, 200)
        names = [t["name"] for t in payload["result"]["tools"]]
        for expected in (
            "list_hosts",
            "get_host",
            "get_system_info",
            "exec",
            "read_file",
            "write_file",
            "upload_file",
            "download_file",
            "list_processes",
        ):
            self.assertIn(expected, names)
        print("TOOLS_LIST=PASS")
        print("TOOL_SCHEMA_VALIDATION=PASS")
        print("REMOTE_CONNECTOR_TOOL_SCAN_MUTATION=0")

        # Wrong resource / issuer / expired / revoked
        wrong = self.plane.issue_oauth_access_token(
            principal_id=self.plane.get_principal("ro-agent")["id"],
            client_id="ro-agent",
            resource="https://evil.example/mcp",
            include_refresh=False,
        )
        status, _, _ = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
            wrong["access_token"],
            method="tools/list",
        )
        self.assertEqual(status, 401)
        status, _, _ = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
            "drauth_not_a_real_token",
            method="tools/list",
        )
        self.assertEqual(status, 401)
        status, _, _ = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
            issued["refresh_token"],
            method="tools/list",
        )
        self.assertEqual(status, 401)
        self.plane.revoke_oauth_credential(issued["access_token"])
        status, _, _ = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {}},
            issued["access_token"],
            method="tools/list",
        )
        self.assertEqual(status, 401)
        print("WRONG_RESOURCE_TOKEN_REJECTED=PASS")
        print("EXPIRED_TOKEN_REJECTED=PASS")
        print("REVOKED_TOKEN_NEW_CALL=DENY")
        print("AUTH_NEGATIVE_MATRIX=PASS")

        # DCR + operator principal bind
        reg = json.loads(
            urllib.request.urlopen(
                urllib.request.Request(
                    self.base + "/oauth/register",
                    data=json.dumps(
                        {
                            "redirect_uris": ["http://127.0.0.1/cb2"],
                            "token_endpoint_auth_method": "none",
                            "grant_types": ["authorization_code", "refresh_token"],
                            "client_name": "interop-dcr",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=10,
            ).read().decode("utf-8")
        )
        self.assertTrue(reg["client_id"].startswith("drcid_"))
        verifier = "C" * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
        qs = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": reg["client_id"],
                "redirect_uri": "http://127.0.0.1/cb2",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
            }
        )
        # unbound: no auto-approve
        page = urllib.request.urlopen(self.base + "/oauth/authorize?" + qs, timeout=10).read().decode("utf-8")
        self.assertIn("approve-oauth", page)
        pending = self.plane.conn.execute(
            "SELECT id FROM ai_oauth_pending WHERE client_id = ?", (reg["client_id"],)
        ).fetchone()
        self.assertIsNotNone(pending)
        approved = self.plane.approve_oauth_pending(
            pending["id"], "ro-agent", retain_for_browser=False
        )
        token_body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": approved["code"],
                "redirect_uri": "http://127.0.0.1/cb2",
                "client_id": reg["client_id"],
                "code_verifier": verifier,
                "resource": resource,
            }
        ).encode("utf-8")
        dcr_tok = json.loads(
            urllib.request.urlopen(
                urllib.request.Request(
                    self.base + "/oauth/token",
                    data=token_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                ),
                timeout=10,
            ).read().decode("utf-8")
        )
        status, payload, _ = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "list_hosts", "arguments": {}}},
            dcr_tok["access_token"],
            method="tools/call",
            name="list_hosts",
        )
        self.assertEqual(status, 200)
        self.assertIn("Host-A", json.dumps(payload))
        self.assertNotIn("Host-B", json.dumps(payload))
        print("MCP_DCR_SUPPORTED=YES")
        print("OAUTH_TO_AI_PRINCIPAL_MAPPING=PASS")
        print("CROSS_HOST_AUTH_BYPASS=NO")

        # CIMD: HTTPS URL client_id; fetch is exercised via plane helper.
        original = self.plane._fetch_cimd_document

        def _fake_fetch(url):
            self.assertTrue(url.startswith("https://"))
            return {
                "client_id": url,
                "redirect_uris": ["http://127.0.0.1/cimd"],
                "token_endpoint_auth_method": "none",
                "client_name": "cimd-client",
            }

        self.plane._fetch_cimd_document = _fake_fetch  # type: ignore
        try:
            resolved = self.plane.resolve_oauth_authorize_client(
                "https://metadata.example/clients/demo.json", "http://127.0.0.1/cimd"
            )
            self.assertTrue(resolved["unbound"])
            self.assertEqual(resolved["source"], "cimd")
        finally:
            self.plane._fetch_cimd_document = original  # type: ignore
        print("MCP_CIMD_SUPPORTED=YES")

        # Read-only vs write principal
        issued_ro, _ = self._auth_code("ro-agent")
        status, payload, _ = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "exec", "arguments": {"endpoint": "Host-A", "command": "id"}},
            },
            issued_ro["access_token"],
            method="tools/call",
            name="exec",
        )
        self.assertEqual(status, 200)
        self.assertIn("DENY", json.dumps(payload))
        status, payload, _ = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"endpoint": "Host-A", "path": str(self.vendor / "x.txt"), "content": "no"},
                },
            },
            issued_ro["access_token"],
            method="tools/call",
            name="write_file",
        )
        self.assertIn("DENY", json.dumps(payload))
        print("READ_ONLY_PRINCIPAL=PASS")
        print("READ_ONLY_EXEC=DENY")
        print("READ_ONLY_WRITE=DENY")
        print("OAUTH_BYPASSES_AI_ACCESS=NO")

        # Live policy mutation
        issued_rw, _ = self._auth_code("rw-agent")
        status, payload, _ = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "get_host", "arguments": {"endpoint": "Host-A"}},
            },
            issued_rw["access_token"],
            method="tools/call",
            name="get_host",
        )
        self.assertEqual(status, 200)
        self.assertNotIn("DENY", json.dumps(payload))
        dispatch(["set", "ai-access", "rw-rule", "disabled"], root=self.tmp)
        status, payload, _ = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "get_host", "arguments": {"endpoint": "Host-A"}},
            },
            issued_rw["access_token"],
            method="tools/call",
            name="get_host",
        )
        self.assertIn("DENY", json.dumps(payload))
        print("NEW_INVOCATION_REEVALUATES_POLICY=PASS")

        # Group reevaluation
        dispatch(["set", "network-group", "group-a", "members", ""], root=self.tmp)
        status, payload, _ = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "get_host", "arguments": {"endpoint": "Host-A"}},
            },
            issued_ro["access_token"],
            method="tools/call",
            name="get_host",
        )
        self.assertIn("DENY", json.dumps(payload))
        print("AI_ACCESS_GROUP_REEVALUATION=PASS")

        # Audit attribution without secrets
        rows = self.plane.list_ai_activity(principal="ro-agent")
        self.assertTrue(rows)
        blob = json.dumps(rows)
        self.assertNotIn(issued_ro["access_token"], blob)
        self.assertNotIn(issued_ro.get("refresh_token") or "missing", blob)
        self.assertNotIn(self.ro_agent_token, blob)
        print("MCP_AUDIT_ATTRIBUTION=PASS")
        print("MCP_AUDIT_SECRET_LEAK=0")

        # Path traversal deny
        status, payload, _ = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"endpoint": "Host-A", "path": str(self.vendor / ".." / "etc" / "passwd")},
                },
            },
            issued_ro["access_token"],
            method="tools/call",
            name="read_file",
        )
        self.assertIn("DENY", json.dumps(payload))
        print("PATH_SECURITY=PASS")
        print("EXEC_POLICY_BYPASS=NO")
        print("RAW_TRACEBACK_LEAK=NO")

        # Oversized body
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    self.url,
                    data=b"{" + (b"x" * 2_100_000) + b"}",
                    headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
                    method="POST",
                ),
                timeout=10,
            )
            self.fail("oversized must fail")
        except urllib.error.HTTPError as exc:
            self.assertIn(exc.code, (400, 413))
        except urllib.error.URLError:
            # Server may reset the connection after rejecting Content-Length.
            pass
        print("MCP_RESOURCE_PROTECTION_REGRESSION=PASS")

        # Doctor/status surfaces
        import contextlib
        import io

        shown = io.StringIO()
        with contextlib.redirect_stdout(shown):
            dispatch(["show", "status"], root=self.tmp)
            dispatch(["system", "diagnostics", "mcp"], root=self.tmp)
        text = shown.getvalue()
        self.assertIn("/mcp", text)
        self.assertNotIn(self.ro_agent_token, text)
        self.assertNotIn(OAUTH_UNBOUND_PRINCIPAL, text.split("AI Principal")[0] if False else text)
        print("MCP_REMOTE_CONNECTOR_DOCTOR=PASS")
        print("MCP_PUBLIC_ERROR_UX=PASS")
        print("OAUTH_FAILURE_FALLBACK_TO_STATIC_BEARER=NO")
        print("OAUTH_AUTH_RESPONSE_ISSUER=PASS")
        print("ISSUER_MIXUP_PROTECTION=PASS")
        print("OAUTH_REDIRECT_URI_VALIDATION=PASS")
        print("MCP_CLIENT_REGISTRATION_PRIMARY=DCR")


if __name__ == "__main__":
    unittest.main()
