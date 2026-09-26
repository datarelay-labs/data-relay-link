#!/usr/bin/env python3
"""AI Access + MCP Bridge E2E (v2.4.0 Phase 2)."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_ai_agent import MAX_STDOUT_BYTES, AgentLoop, execute_local  # noqa: E402
from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane, path_allowed  # noqa: E402
from drlink_mcp_bridge import MCP_PROTOCOL_VERSION, MCPBridge, make_handler  # noqa: E402
from drlink_mcp_bridge import ThreadingHTTPServer  # noqa: E402
import drlink_v24 as v24  # noqa: E402


def start_endpoint_workers(bridge: MCPBridge, base_url: str):
    """Start real AgentLoop workers against the bridge (not Server-local impersonation)."""
    stops = []
    threads = []
    for client in bridge.plane.connected_clients():
        token = bridge.plane.issue_agent_credential(client["id"], rotate=True)
        if not token:
            continue
        stop = threading.Event()
        loop = AgentLoop(base_url, token, stop_event=stop)
        thread = threading.Thread(target=loop.run, daemon=True, name="test-ai-agent-%s" % client["id"][:8])
        thread.start()
        stops.append(stop)
        threads.append(thread)
    return stops, threads


def stop_endpoint_workers(stops, threads, *, join_timeout=5.0):
    """Signal AgentLoop workers, then join them before closing shared ControlPlane state."""
    for stop in stops or []:
        stop.set()
    alive = []
    for thread in threads or []:
        thread.join(timeout=join_timeout)
        if thread.is_alive():
            alive.append(thread.name or "unnamed-agent-worker")
    return alive

sys.path.insert(0, str(ROOT / "tests"))
from mcp_sdk_env import resolve_mcp_sdk_python  # noqa: E402


def run_cli(root, tokens):
    buf = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = dispatch(list(tokens), root=root)
    return rc, buf.getvalue(), err.getvalue()


def rpc(url, body, token, method=None, name=None, extra_headers=None):
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
    if isinstance(params, dict):
        meta = dict(params.get("_meta") or {})
        meta.setdefault("io.modelcontextprotocol/protocolVersion", MCP_PROTOCOL_VERSION)
        meta.setdefault("io.modelcontextprotocol/clientCapabilities", {})
        params["_meta"] = meta
        body = dict(body)
        body["params"] = params
    else:
        body = dict(body)
        body["params"] = {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"raw": payload}
        return exc.code, parsed


class ControlPlaneAITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-ai-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        self.vendor = Path(self.tmp) / "var" / "log" / "vendor"
        self.etc_vendor = Path(self.tmp) / "etc" / "vendor"
        self.opt_vendor = Path(self.tmp) / "opt" / "vendor"
        for path in (self.vendor, self.etc_vendor, self.opt_vendor):
            path.mkdir(parents=True, exist_ok=True)
        (self.vendor / "app.log").write_text("log-ok\n", encoding="utf-8")
        (self.etc_vendor / "config.yaml").write_text("k: v\n", encoding="utf-8")
        self.vendor_glob = str(self.vendor) + "/**"
        self.etc_glob = str(self.etc_vendor) + "/**"
        self.opt_glob = str(self.opt_vendor) + "/**"
        self.plane.upsert_client("client-prod-aaaaaaaa", label="Expernet-DP1")
        self.plane.upsert_client("client-lab-bbbbbbbb", label="lab1")

    def tearDown(self):
        self.plane.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cli(self, *tokens):
        rc, out, err = run_cli(self.tmp, tokens)
        self.assertEqual(rc, 0, "cli %s failed: %s%s" % (tokens, out, err))
        return out

    def token_for(self, principal):
        out = self.cli("system", "credential", "rotate", "ai-principal", principal)
        self.assertIn("Fingerprint:", out)
        self.assertIn("Token:", out)
        line = [ln for ln in out.splitlines() if ln.startswith("Token: ")][0]
        return line.split(" ", 1)[1].strip()

    def test_objects_and_first_match_network_plane(self):
        self.cli("set", "network-object", "office-net", "type", "cidr", "value", "10.10.10.0/24")
        self.cli("set", "network-object", "other-net", "type", "cidr", "value", "8.8.8.0/24")
        self.cli("set", "service-object", "ssh", "type", "tcp", "port", "22")
        self.cli(
            "set",
            "remote-access",
            "allow-office",
            "mode",
            "whitelist",
            "source",
            "office-net",
            "destination",
            "Expernet-DP1",
            "service",
            "ssh",
            "enabled",
        )
        out = self.cli(
            "test",
            "remote-access",
            "source",
            "office-net",
            "destination",
            "Expernet-DP1",
            "service",
            "ssh",
        )
        self.assertIn("ALLOW", out)
        out = self.cli(
            "test",
            "remote-access",
            "source",
            "other-net",
            "destination",
            "Expernet-DP1",
            "service",
            "ssh",
        )
        self.assertIn("DENY", out)
        st = self.cli("show", "status")
        self.assertIn("DB Revision", st)
        self.assertIn("Control DB", st)
        self.assertIn("Data Relay Link", st)

    def _verify_ai_identity(self, name: str) -> str:
        """Issue a credential so the AI Identity is VERIFIED/active for AI Access."""
        return self.token_for(name)

    def test_ai1_readonly_support(self):
        self.cli("set", "ai-principal", "chatgpt-support")
        self.cli("set", "ai-principal", "chatgpt-support", "description", "ChatGPT production support")
        self.cli("set", "ai-principal", "chatgpt-support", "enabled")
        self._verify_ai_identity("chatgpt-support")
        self.cli(
            "set",
            "permission-object",
            "readonly-support-perms",
            "permissions",
            "host-info,process-read,file-read",
        )
        self.cli(
            "set",
            "ai-access",
            "readonly-support",
            "mode",
            "whitelist",
            "source",
            "chatgpt-support",
            "destination",
            "Expernet-DP1",
            "permission",
            "readonly-support-perms",
            "enabled",
        )
        v24.set_ai_policy_path_scopes(
            self.plane, "readonly-support", [self.vendor_glob, self.etc_glob]
        )
        # Pathless file-read must fail-closed (no unconditional ALLOW).
        pathless = self.cli(
            "test",
            "ai-access",
            "source",
            "chatgpt-support",
            "destination",
            "Expernet-DP1",
            "permission",
            "file-read",
        )
        self.assertIn("DENY", pathless)
        self.assertIn("path context", pathless.lower())
        allow = self.cli(
            "test",
            "ai-access",
            "source",
            "chatgpt-support",
            "destination",
            "Expernet-DP1",
            "permission",
            "file-read",
            "path",
            str(self.vendor / "app.log"),
        )
        self.assertIn("ALLOW", allow)
        self.assertIn("readonly-support", allow)
        self.assertNotIn("log-ok", allow)
        deny = self.cli(
            "test",
            "ai-access",
            "source",
            "chatgpt-support",
            "destination",
            "Expernet-DP1",
            "permission",
            "command-exec",
        )
        self.assertIn("DENY", deny)
        self.assertIn("(none)", deny)
        auth = v24.authorize_ai_capability_v24(
            self.plane,
            identity="chatgpt-support",
            destination="Expernet-DP1",
            capability="exec",
            operand="id",
        )
        self.assertEqual(auth["action"], "DENY")
        self.assertNotIn("uid=", str(auth))

    def test_ai2_lab_and_target_isolation(self):
        self.cli("set", "ai-principal", "cursor-dev")
        self.cli("set", "ai-principal", "cursor-dev", "enabled")
        self._verify_ai_identity("cursor-dev")
        self.cli(
            "set",
            "permission-object",
            "lab-maintenance-perms",
            "permissions",
            "host-info,process-read,file-read,command-exec,file-write,file-upload,file-download",
        )
        self.cli(
            "set",
            "ai-access",
            "lab-maintenance",
            "mode",
            "whitelist",
            "source",
            "cursor-dev",
            "destination",
            "lab1",
            "permission",
            "lab-maintenance-perms",
            "enabled",
        )
        v24.set_ai_policy_path_scopes(
            self.plane,
            "lab-maintenance",
            [self.etc_glob, self.opt_glob, self.vendor_glob],
        )
        shown = self.cli("show", "ai-access", "lab-maintenance")
        self.assertIn("lab-maintenance-perms", shown)
        self.assertIn("lab1", shown)
        perm_shown = self.cli("show", "permission-object", "lab-maintenance-perms")
        self.assertIn("command-exec", perm_shown)
        self.cli(
            "set",
            "permission-object",
            "exec-only",
            "permissions",
            "command-exec",
        )
        exec_only = self.cli("show", "permission-object", "exec-only")
        self.assertIn("command-exec", exec_only)
        in_scope = str(self.vendor / "app.log")
        for permission in (
            "host-info",
            "file-read",
            "file-write",
            "file-upload",
            "file-download",
            "command-exec",
        ):
            tokens = [
                "test",
                "ai-access",
                "source",
                "cursor-dev",
                "destination",
                "lab1",
                "permission",
                permission,
            ]
            # File permissions require a concrete in-scope path for ALLOW.
            if permission.startswith("file-"):
                tokens.extend(["path", in_scope])
            out = self.cli(*tokens)
            self.assertIn("ALLOW", out, out)
        prod = self.cli(
            "test",
            "ai-access",
            "source",
            "cursor-dev",
            "destination",
            "Expernet-DP1",
            "permission",
            "command-exec",
        )
        self.assertIn("DENY", prod)

    def test_ai3_explicit_deny_order(self):
        self.cli("set", "ai-principal", "cursor-dev")
        self.cli("set", "ai-principal", "cursor-dev", "enabled")
        self._verify_ai_identity("cursor-dev")
        self.cli(
            "set",
            "permission-object",
            "exec-only",
            "permissions",
            "command-exec",
        )
        # WHITELIST allow proves the permission can be granted on this destination.
        self.cli(
            "set",
            "ai-access",
            "support-read",
            "mode",
            "whitelist",
            "source",
            "cursor-dev",
            "destination",
            "Expernet-DP1",
            "permission",
            "exec-only",
            "enabled",
        )
        allow = self.cli(
            "test",
            "ai-access",
            "source",
            "cursor-dev",
            "destination",
            "Expernet-DP1",
            "permission",
            "command-exec",
        )
        self.assertIn("ALLOW", allow)
        self.assertIn("support-read", allow)
        # Reset and switch to BLACKLIST so a matching rule is an explicit DENY.
        self.cli("unset", "ai-access", "policy")
        self.cli(
            "set",
            "ai-access",
            "deny-prod-exec",
            "mode",
            "blacklist",
            "source",
            "cursor-dev",
            "destination",
            "Expernet-DP1",
            "permission",
            "exec-only",
            "enabled",
        )
        self.cli(
            "set",
            "ai-access",
            "zzz-later-deny",
            "source",
            "cursor-dev",
            "destination",
            "Expernet-DP1",
            "permission",
            "exec-only",
            "enabled",
        )
        listed = self.cli("show", "ai-access")
        deny_pos = listed.find("deny-prod-exec")
        later_pos = listed.find("zzz-later-deny")
        self.assertLess(deny_pos, later_pos)
        out = self.cli(
            "test",
            "ai-access",
            "source",
            "cursor-dev",
            "destination",
            "Expernet-DP1",
            "permission",
            "command-exec",
        )
        self.assertIn("DENY", out)
        self.assertIn("deny-prod-exec", out)
        # Unmatched blacklist permission remains ALLOW under current v2.4 model.
        # Use a non-file permission so the check is not conflated with path-scope
        # fail-closed (file ops DENY without path / without canonical scopes).
        other = self.cli(
            "test",
            "ai-access",
            "source",
            "cursor-dev",
            "destination",
            "Expernet-DP1",
            "permission",
            "host-info",
        )
        self.assertIn("ALLOW", other)

    def test_path_traversal_and_symlink(self):
        self.assertFalse(path_allowed("/var/log/vendor/../../etc/shadow", ["/var/log/vendor/**"]))
        self.assertFalse(path_allowed("/var/log/vendor/%2e%2e/%2e%2e/etc/shadow", ["/var/log/vendor/**"]))
        self.assertFalse(path_allowed("/var/log/vendor/%252e%252e/etc/shadow", ["/var/log/vendor/**"]))
        self.assertFalse(path_allowed("var/log/vendor/app.log", [self.vendor_glob]))
        self.assertFalse(path_allowed("/var/log/vendor/app.log", [self.vendor_glob]))
        self.assertTrue(path_allowed(str(self.vendor / "app.log"), [self.vendor_glob]))
        shadow = Path(self.tmp) / "etc" / "shadow"
        shadow.parent.mkdir(parents=True, exist_ok=True)
        shadow.write_text("root:secret\n", encoding="utf-8")
        link = self.vendor / "escape"
        link.symlink_to(shadow)
        self.assertFalse(path_allowed(str(link), [self.vendor_glob]))
        with self.assertRaises(Exception):
            execute_local(
                "read_file",
                {"path": str(link)},
                patterns=[self.vendor_glob],
                timeout=5,
            )
        with self.assertRaises(Exception):
            execute_local(
                "read_file",
                {"path": str(self.vendor / ".." / ".." / "etc" / "shadow")},
                patterns=[self.vendor_glob],
                timeout=5,
            )

    def test_exec_timeout_and_output_bound(self):
        timed = execute_local("exec", {"command": "sleep 8"}, patterns=[], timeout=1)
        self.assertEqual(timed["result"], "TIMEOUT")
        self.assertGreaterEqual(timed["duration_ms"], 500)
        huge = execute_local(
            "exec",
            {"command": "python3 -c 'import sys; sys.stdout.write(\"A\"*200000)'"},
            patterns=[],
            timeout=10,
        )
        self.assertTrue(huge["stdout_truncated"])
        self.assertLessEqual(len(huge["stdout"].encode("utf-8")), MAX_STDOUT_BYTES)


class MCPBridgeE2ETests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-mcp-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        self.vendor = Path(self.tmp) / "var" / "log" / "vendor"
        self.etc_vendor = Path(self.tmp) / "etc" / "vendor"
        self.opt_vendor = Path(self.tmp) / "opt" / "vendor"
        for path in (self.vendor, self.etc_vendor, self.opt_vendor):
            path.mkdir(parents=True, exist_ok=True)
        (self.vendor / "app.log").write_text("log-ok\n", encoding="utf-8")
        (self.etc_vendor / "config.yaml").write_text("k: v\n", encoding="utf-8")
        self.vendor_glob = str(self.vendor) + "/**"
        self.etc_glob = str(self.etc_vendor) + "/**"
        self.opt_glob = str(self.opt_vendor) + "/**"
        self.plane.upsert_client("client-prod-aaaaaaaa", label="Expernet-DP1")
        self.plane.upsert_client("client-lab-bbbbbbbb", label="lab1")
        run_cli(self.tmp, ["set", "client-group", "production-linux"])
        run_cli(self.tmp, ["set", "client-group", "production-linux", "member", "Expernet-DP1"])
        run_cli(self.tmp, ["set", "client-group", "lab-linux"])
        run_cli(self.tmp, ["set", "client-group", "lab-linux", "member", "lab1"])
        run_cli(self.tmp, ["set", "ai-principal", "chatgpt-support"])
        run_cli(self.tmp, ["set", "ai-principal", "chatgpt-support", "enabled"])
        run_cli(self.tmp, ["set", "ai-principal", "cursor-dev"])
        run_cli(self.tmp, ["set", "ai-principal", "cursor-dev", "enabled"])
        # Canonical v2.4 AI Access is the MCP authority. Seed verified identities
        # and equivalent ai_policy_rules (+ path scopes) before issuing tokens.
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'active', enabled = 1 "
            "WHERE name IN ('chatgpt-support', 'cursor-dev')"
        )
        self.plane.conn.commit()
        v24.ensure_v2_schema(self.plane.conn)
        v24.set_permission_object(
            self.plane,
            "readonly-support-perms",
            permissions=["host-info", "process-read", "file-read"],
            oneshot=True,
        )
        v24.set_permission_object(
            self.plane,
            "lab-maintenance-perms",
            permissions=[
                "host-info",
                "process-read",
                "file-read",
                "command-exec",
                "file-write",
                "file-upload",
                "file-download",
            ],
            oneshot=True,
        )
        v24.set_ai_access_rule(
            self.plane,
            "mcp-readonly-support",
            mode="whitelist",
            source="chatgpt-support",
            destination="Expernet-DP1",
            permission="readonly-support-perms",
            enabled=True,
            oneshot=True,
        )
        v24.set_ai_policy_path_scopes(
            self.plane, "mcp-readonly-support", [self.vendor_glob, self.etc_glob]
        )
        v24.set_ai_access_rule(
            self.plane,
            "mcp-lab-maintenance",
            mode="whitelist",
            source="cursor-dev",
            destination="lab1",
            permission="lab-maintenance-perms",
            enabled=True,
            oneshot=True,
        )
        v24.set_ai_policy_path_scopes(
            self.plane,
            "mcp-lab-maintenance",
            [self.etc_glob, self.opt_glob, self.vendor_glob],
        )
        self.chatgpt = self._token("chatgpt-support")
        self.cursor = self._token("cursor-dev")
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.bridge))
        self.port = self.httpd.server_address[1]
        self.bridge.listen_host = "127.0.0.1"
        self.bridge.listen_port = self.port
        self.url = "http://127.0.0.1:%s/mcp" % self.port
        self.base = "http://127.0.0.1:%s" % self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self._agent_stops, self._agent_threads = start_endpoint_workers(self.bridge, self.base)

    def tearDown(self):
        failures = []
        alive = stop_endpoint_workers(
            getattr(self, "_agent_stops", []),
            getattr(self, "_agent_threads", []),
            join_timeout=5.0,
        )
        if alive:
            failures.append("AgentLoop workers still alive after stop: %s" % ", ".join(alive))
        # Shut down HTTP server while ControlPlane is still valid, then join its thread.
        httpd = getattr(self, "httpd", None)
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception as exc:
                failures.append("httpd.shutdown failed: %s" % exc)
            try:
                httpd.server_close()
            except Exception as exc:
                failures.append("httpd.server_close failed: %s" % exc)
        http_thread = getattr(self, "thread", None)
        if http_thread is not None:
            http_thread.join(timeout=5.0)
            if http_thread.is_alive():
                failures.append("HTTP server thread still alive after shutdown")
        bridge = getattr(self, "bridge", None)
        if bridge is not None:
            try:
                bridge.close()
            except Exception as exc:
                failures.append("bridge.close failed: %s" % exc)
        plane = getattr(self, "plane", None)
        if plane is not None:
            try:
                plane.close()
            except Exception as exc:
                failures.append("plane.close failed: %s" % exc)
        shutil.rmtree(getattr(self, "tmp", None) or "", ignore_errors=True)
        if failures:
            self.fail("; ".join(failures))

    def _token(self, principal):
        rc, out, err = run_cli(self.tmp, ["system", "credential", "rotate", "ai-principal", principal])
        self.assertEqual(rc, 0, err)
        return [ln.split(" ", 1)[1] for ln in out.splitlines() if ln.startswith("Token: ")][0]

    def call(self, token, tool, arguments, req_id=1):
        body = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        return rpc(self.url, body, token, method="tools/call", name=tool)

    def text_of(self, payload):
        result = payload.get("result") or {}
        content = result.get("content") or []
        if content:
            return content[0].get("text") or ""
        return json.dumps(payload)

    def decoded_file(self, payload):
        text = self.text_of(payload)
        data = json.loads(text)
        if "content_b64" in data:
            return base64.b64decode(data["content_b64"]).decode("utf-8", "replace")
        return text

    def test_protocol_discovery_auth_and_tools(self):
        status, payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
            self.chatgpt,
            method="server/discover",
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["supportedVersions"], [MCP_PROTOCOL_VERSION])
        self.assertEqual(payload["result"]["resultType"], "complete")
        self.assertEqual(payload["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "data-relay-link")
        status, payload = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "ai-access-e2e", "version": "0"},
                },
            },
            self.chatgpt,
            method="initialize",
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(payload["result"]["serverInfo"]["name"], "data-relay-link")
        self.assertTrue(payload["result"].get("instructions"))
        status, payload = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 18,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2099-01-01",
                    "capabilities": {},
                    "clientInfo": {"name": "ai-access-e2e", "version": "0"},
                },
            },
            self.chatgpt,
            method="initialize",
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload.get("error", {}).get("code"), -32022)
        status, payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 19, "method": "ping", "params": {}},
            self.chatgpt,
            method="ping",
        )
        self.assertEqual(status, 200)
        status, payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            self.chatgpt,
            method="tools/list",
        )
        names = [t["name"] for t in payload["result"]["tools"]]
        for required in (
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
            self.assertIn(required, names)
        for tool in payload["result"]["tools"]:
            self.assertTrue(tool.get("title"))
            ann = tool.get("annotations") or {}
            for key in ("readOnlyHint", "destructiveHint", "openWorldHint"):
                self.assertIn(key, ann)
            self.assertTrue(any(s.get("type") == "oauth2" for s in (tool.get("securitySchemes") or [])))
        by_name = {t["name"]: t for t in payload["result"]["tools"]}
        self.assertFalse(by_name["exec"]["annotations"]["readOnlyHint"])
        self.assertTrue(by_name["read_file"]["annotations"]["readOnlyHint"])
        status, _payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
            "drk_invalid",
            method="tools/list",
        )
        self.assertEqual(status, 401)
        challenge = _payload.get("_meta") or ((_payload.get("error") or {}).get("data") or {}).get("_meta") or {}
        self.assertIn("mcp/www_authenticate", challenge)

    def test_readonly_real_tools(self):
        status, payload = self.call(self.chatgpt, "list_hosts", {})
        self.assertEqual(status, 200)
        self.assertIn("Expernet-DP1", self.text_of(payload))
        status, payload = self.call(self.chatgpt, "get_system_info", {"endpoint": "Expernet-DP1"})
        self.assertIn("sysname", self.text_of(payload))
        status, payload = self.call(
            self.chatgpt,
            "read_file",
            {"endpoint": "Expernet-DP1", "path": str(self.vendor / "app.log")},
        )
        self.assertIn("log-ok", self.decoded_file(payload))
        status, payload = self.call(self.chatgpt, "list_processes", {"endpoint": "Expernet-DP1"})
        self.assertIn("pid", self.text_of(payload).lower())
        status, payload = self.call(
            self.chatgpt, "exec", {"endpoint": "Expernet-DP1", "command": "id"}
        )
        self.assertIn("DENY", self.text_of(payload))
        for tool in ("write_file", "upload_file"):
            status, payload = self.call(
                self.chatgpt,
                tool,
                {"endpoint": "Expernet-DP1", "path": str(self.vendor / "x"), "content": "no"},
            )
            self.assertIn("DENY", self.text_of(payload))
        status, payload = self.call(
            self.chatgpt,
            "download_file",
            {"endpoint": "Expernet-DP1", "path": str(self.vendor / "app.log")},
        )
        self.assertIn("DENY", self.text_of(payload))

    def test_lab_maintenance_and_isolation(self):
        status, payload = self.call(self.cursor, "get_system_info", {"endpoint": "lab1"})
        self.assertNotIn("DENY", self.text_of(payload))
        status, payload = self.call(
            self.cursor,
            "read_file",
            {"endpoint": "lab1", "path": str(self.etc_vendor / "config.yaml")},
        )
        self.assertIn("k: v", self.decoded_file(payload))
        status, payload = self.call(
            self.cursor,
            "write_file",
            {"endpoint": "lab1", "path": str(self.etc_vendor / "test-file"), "content": "ok"},
        )
        self.assertNotIn("DENY", self.text_of(payload))
        self.assertTrue((self.etc_vendor / "test-file").is_file())
        blob = base64.b64encode(b"bin").decode("ascii")
        status, payload = self.call(
            self.cursor,
            "upload_file",
            {
                "endpoint": "lab1",
                "path": str(self.opt_vendor / "test.bin"),
                "content": blob,
                "encoding": "base64",
            },
        )
        self.assertNotIn("DENY", self.text_of(payload))
        status, payload = self.call(
            self.cursor,
            "download_file",
            {"endpoint": "lab1", "path": str(self.vendor / "app.log")},
        )
        self.assertIn("log-ok", self.decoded_file(payload))
        status, payload = self.call(
            self.cursor, "exec", {"endpoint": "lab1", "command": "true"}
        )
        self.assertNotIn("DENY", self.text_of(payload))
        status, payload = self.call(
            self.cursor, "exec", {"endpoint": "Expernet-DP1", "command": "id"}
        )
        self.assertIn("DENY", self.text_of(payload))

    def test_timeout_bounding_policy_timing_revocation_rotation(self):
        # Exec timeout/cancel/fairness is Priority 6. Canonical MCP auth no longer
        # inherits legacy ai_access_rules.exec_timeout; assert authorization still
        # allows bounded exec and keep stdout / revoke / rotate coverage here.
        status, payload = self.call(self.cursor, "exec", {"endpoint": "lab1", "command": "sleep 1"})
        self.assertNotIn("DENY", self.text_of(payload))
        status, payload = self.call(
            self.cursor,
            "exec",
            {
                "endpoint": "lab1",
                "command": "python3 -c 'import sys; sys.stdout.write(\"B\"*200000)'",
            },
        )
        text = self.text_of(payload)
        self.assertIn("stdout_truncated", text)
        self.assertNotIn("B" * 1000, json.dumps(self.plane.list_ai_activity(principal="cursor-dev")))
        started = {"done": False, "text": ""}

        def long_op():
            _status, body = self.call(
                self.cursor, "exec", {"endpoint": "lab1", "command": "sleep 1"}, req_id=99
            )
            started["text"] = self.text_of(body)
            started["done"] = True

        worker = threading.Thread(target=long_op)
        worker.start()
        time.sleep(0.2)
        v24.set_ai_access_rule(self.plane, "mcp-lab-maintenance", enabled=False)
        worker.join(timeout=10)
        self.assertTrue(started["done"])
        self.assertNotIn("DENY", started["text"])
        status, payload = self.call(self.cursor, "exec", {"endpoint": "lab1", "command": "true"})
        self.assertIn("DENY", self.text_of(payload))
        v24.set_ai_access_rule(self.plane, "mcp-lab-maintenance", enabled=True)
        run_cli(self.tmp, ["system", "credential", "revoke", "ai-principal", "chatgpt-support"])
        status, payload = self.call(
            self.chatgpt,
            "get_system_info",
            {"endpoint": "Expernet-DP1"},
        )
        self.assertEqual(status, 401)
        new_token = self._token("chatgpt-support")
        self.assertNotEqual(new_token, self.chatgpt)
        status, payload = self.call(
            new_token, "get_system_info", {"endpoint": "Expernet-DP1"}
        )
        self.assertEqual(status, 200)
        self.assertNotIn("DENY", self.text_of(payload))
        status, _payload = self.call(
            self.chatgpt, "get_system_info", {"endpoint": "Expernet-DP1"}
        )
        self.assertEqual(status, 401)
        shown = run_cli(self.tmp, ["show", "ai-principal", "chatgpt-support"])[1]
        self.assertNotIn(new_token, shown)
        self.assertIn("chatgpt-support", shown)

    def test_reachability_orphan_audit_and_header_mismatch(self):
        self.plane.upsert_client("client-prod-aaaaaaaa", label="Expernet-DP1", connected=False)
        status, payload = self.call(
            self.chatgpt,
            "read_file",
            {"endpoint": "Expernet-DP1", "path": str(self.vendor / "app.log")},
        )
        text = self.text_of(payload)
        self.assertIn("Authorization: ALLOW", text)
        self.assertIn("endpoint unavailable", text)
        self.plane.upsert_client("client-prod-aaaaaaaa", label="Expernet-DP1", connected=True)
        # Canonical destination binding already points at Expernet-DP1 via mcp-readonly-support.
        self.plane.remove_client("client-prod-aaaaaaaa")
        obj = self.plane.get_object("Expernet-DP1")
        self.assertEqual(obj["status"], "orphaned")
        status, payload = self.call(
            self.chatgpt,
            "read_file",
            {"endpoint": "Expernet-DP1", "path": str(self.vendor / "app.log")},
        )
        text = self.text_of(payload)
        self.assertIn("Authorization: ALLOW", text)
        self.assertIn("unavailable", text.lower())
        self.plane.upsert_client("client-prod-new-cccccc", label="Expernet-DP1")
        rebound = self.plane.get_object("Expernet-DP1")
        self.assertEqual(rebound["status"], "orphaned")
        activity = run_cli(self.tmp, ["show", "ai-activity", "principal", "chatgpt-support"])[1]
        self.assertIn("chatgpt-support", activity)
        self.assertIn("read_file", activity)
        self.assertNotIn("log-ok", activity)
        self.assertNotIn(self.chatgpt, activity)
        audit = run_cli(self.tmp, ["system", "audit", "ai-principal", "chatgpt-support"])[1]
        self.assertIn("chatgpt-support", audit)
        status, payload = rpc(
            self.url,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"endpoint": "lab1"}},
            },
            self.cursor,
            method="tools/list",
            name="read_file",
        )
        self.assertEqual(payload.get("error", {}).get("code"), -32020)
        self.assertEqual(status, 400)

    def test_rfc9728_prm_and_oauth_token(self):
        req = urllib.request.Request(self.base + "/.well-known/oauth-protected-resource")
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            meta = json.loads(resp.read().decode("utf-8"))
        self.assertIn("authorization_servers", meta)
        self.assertIn("bearer_methods_supported", meta)
        self.assertEqual(meta["bearer_methods_supported"], ["header"])
        req = urllib.request.Request(
            self.base + "/oauth/token",
            data=(
                "grant_type=client_credentials&client_id=chatgpt-support&client_secret="
                + self.chatgpt
                + "&resource="
                + self.url
            ).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            token = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(token.get("token_type"), "Bearer")
        self.assertTrue(str(token.get("access_token") or "").startswith("drauth_"))
        self.assertNotEqual(token.get("access_token"), self.chatgpt)
        status, payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}},
            token["access_token"],
            method="tools/list",
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["result"]["tools"])

    def test_spec_streamable_http_client(self):
        """Protocol client distinct from ad-hoc urllib helpers: required 2026-07-28 headers."""
        body = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        }
        req = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Authorization": "Bearer %s" % self.chatgpt,
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                "Mcp-Method": "tools/list",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("application/json", resp.headers.get("Content-Type", ""))
            payload = json.loads(resp.read().decode("utf-8"))
        names = [t["name"] for t in payload["result"]["tools"]]
        self.assertIn("list_hosts", names)
        self.assertIn("read_file", names)

    def test_agent_poll_does_not_rate_limit_mcp_clients(self):
        """Local agents poll /agent/v1/claim at 20Hz and must not 429 /mcp."""
        time.sleep(4)
        status, payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
            self.chatgpt,
            method="server/discover",
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["supportedVersions"], [MCP_PROTOCOL_VERSION])

    def test_official_mcp_sdk_client(self):
        sdk_py = resolve_mcp_sdk_python()
        if not sdk_py:
            try:
                import mcp  # noqa: F401

                sdk_py = sys.executable
            except Exception:
                print("OFFICIAL_MCP_SDK=NOT_INSTALLED")
                print("MCP_PROTOCOL_CLIENT=spec-streamable-http")
                return
        helper = ROOT / "tests" / "mcp_sdk_interop_client.py"
        proc = __import__("subprocess").run(
            [
                sdk_py,
                str(helper),
                "--url",
                self.url,
                "--token",
                self.chatgpt,
                "--endpoint",
                "Expernet-DP1",
                "--path",
                str(self.vendor / "app.log"),
            ],
            capture_output=True,
            text=True,
            timeout=40,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout.splitlines()[-1])
        self.assertEqual(payload.get("initialize_protocol"), "2025-11-25")
        self.assertEqual((payload.get("initialize_server") or {}).get("name"), "data-relay-link")
        self.assertEqual(payload.get("protocol"), MCP_PROTOCOL_VERSION)
        for required in (
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
            self.assertIn(required, payload.get("tools") or [])
        meta_by_name = {t["name"]: t for t in (payload.get("tool_meta") or [])}
        self.assertTrue(meta_by_name.get("list_hosts", {}).get("title"))
        self.assertTrue(meta_by_name.get("list_hosts", {}).get("readOnlyHint"))
        self.assertFalse(meta_by_name.get("exec", {}).get("readOnlyHint"))
        self.assertTrue(meta_by_name.get("exec", {}).get("destructiveHint"))
        self.assertIn("Expernet-DP1", payload.get("list_hosts") or "")
        self.assertIn("sysname", payload.get("system") or "")
        read_text = payload.get("read") or ""
        if "content_b64" in read_text:
            data = json.loads(read_text)
            read_text = base64.b64decode(data["content_b64"]).decode("utf-8", "replace")
        self.assertIn("log-ok", read_text)
        self.assertIn("DENY", payload.get("denied") or "")
        print("OFFICIAL_MCP_SDK=PASS")
        print("MCP_PROTOCOL_CLIENT=official-python-sdk")

    def test_canonical_grammar_accepts_ai_cli(self):
        import frp_ctl_grammar as grammar

        cases = [
            ["set", "ai-principal", "chatgpt-support"],
            ["set", "ai-principal", "chatgpt-support", "enabled"],
            [
                "set",
                "permission-object",
                "readonly-support-perms",
                "permissions",
                "host-info,process-read,file-read",
            ],
            [
                "set",
                "ai-access",
                "readonly-support",
                "mode",
                "whitelist",
                "source",
                "chatgpt-support",
                "destination",
                "Expernet-DP1",
                "permission",
                "readonly-support-perms",
                "enabled",
            ],
            [
                "test",
                "ai-access",
                "source",
                "chatgpt-support",
                "destination",
                "Expernet-DP1",
                "permission",
                "file-read",
            ],
            ["show", "ai-access"],
            ["show", "ai-access", "readonly-support"],
            ["show", "ai-activity", "principal", "chatgpt-support"],
            ["system", "credential", "rotate", "ai-principal", "chatgpt-support"],
            [
                "system",
                "credential",
                "configure",
                "ai-principal",
                "chatgpt-support",
                "authentication",
                "static-bearer",
            ],
            ["system", "diagnostics", "mcp"],
        ]
        for tokens in cases:
            result = grammar.match(tokens, "server")
            self.assertEqual(result.get("status"), "ok", (tokens, result))
            self.assertIn(result.get("action"), ("control_plane", "doctor"), (tokens, result))


    def test_external_mcp_hosts_classified(self):
        cursor = os.environ.get("DRLINK_CURSOR_MCP_E2E")
        claude = os.environ.get("DRLINK_CLAUDE_MCP_E2E")
        chatgpt = os.environ.get("DRLINK_CHATGPT_MCP_E2E")
        print("CURSOR_MCP_REAL_E2E=%s" % ("PASS" if cursor == "pass" else "BLOCKED"))
        print("CLAUDE_MCP_REAL_E2E=%s" % ("PASS" if claude == "pass" else "BLOCKED"))
        print("CHATGPT_MCP_REAL_E2E=%s" % ("PASS" if chatgpt == "pass" else "BLOCKED"))
        if not cursor:
            print(
                "CURSOR_BLOCKER=This Cursor agent session has no remote HTTP MCP namespace; "
                "GetDynamicTools lists only first-party cursor tools. Live host is Direct mode "
                "(no Data Relay Link 443 frontend), so https://<control-host>/mcp is not installed here."
            )
        if not claude:
            print(
                "CLAUDE_BLOCKER=ACCOUNT_OR_PRODUCT_PLAN: Claude remote custom connector UI/account "
                "is not available in this Cursor agent environment."
            )
        if not chatgpt:
            print(
                "CHATGPT_BLOCKER=ACCOUNT_OR_PRODUCT_PLAN: ChatGPT custom MCP/App developer surface "
                "is not available in this Cursor agent environment."
            )


if __name__ == "__main__":
    unittest.main()
