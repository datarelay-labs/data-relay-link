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

from drlink_ai_agent import MAX_STDOUT_BYTES, execute_local  # noqa: E402
from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane, path_allowed  # noqa: E402
from drlink_mcp_bridge import MCP_PROTOCOL_VERSION, MCPBridge, make_handler  # noqa: E402
from drlink_mcp_bridge import ThreadingHTTPServer  # noqa: E402


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

    def test_ai1_readonly_support(self):
        self.cli("set", "client-group", "production-linux")
        self.cli("set", "client-group", "production-linux", "member", "Expernet-DP1")
        self.cli("set", "ai-principal", "chatgpt-support")
        self.cli("set", "ai-principal", "chatgpt-support", "description", "ChatGPT production support")
        self.cli("set", "ai-principal", "chatgpt-support", "enabled")
        self.cli("set", "ai-access", "readonly-support")
        self.cli("set", "ai-access", "readonly-support", "principal", "chatgpt-support")
        self.cli("set", "ai-access", "readonly-support", "target", "client-group", "production-linux")
        for cap in ("get_system_info", "read_file", "list_processes"):
            self.cli("set", "ai-access", "readonly-support", "capability", cap)
        self.cli("set", "ai-access", "readonly-support", "path", self.vendor_glob)
        self.cli("set", "ai-access", "readonly-support", "path", self.etc_glob)
        self.cli("set", "ai-access", "readonly-support", "action", "allow")
        self.cli("set", "ai-access", "readonly-support", "enabled")
        allow = self.cli(
            "test",
            "ai-access",
            "chatgpt-support",
            "Expernet-DP1",
            "read_file",
            str(self.vendor / "app.log"),
        )
        self.assertIn("ALLOW", allow)
        self.assertNotIn("log-ok", allow)
        deny = self.cli("test", "ai-access", "chatgpt-support", "Expernet-DP1", "exec", "id")
        self.assertIn("implicit DENY", deny)
        self.assertNotIn("uid=", deny)

    def test_ai2_lab_and_target_isolation(self):
        self.cli("set", "client-group", "lab-linux")
        self.cli("set", "client-group", "lab-linux", "member", "lab1")
        self.cli("set", "ai-principal", "cursor-dev")
        self.cli("set", "ai-principal", "cursor-dev", "enabled")
        self.cli("set", "ai-access", "lab-maintenance")
        self.cli("set", "ai-access", "lab-maintenance", "principal", "cursor-dev")
        self.cli("set", "ai-access", "lab-maintenance", "target", "client-group", "lab-linux")
        for cap in (
            "exec",
            "read_file",
            "write_file",
            "upload_file",
            "download_file",
            "get_system_info",
        ):
            self.cli("set", "ai-access", "lab-maintenance", "capability", cap)
        for pattern in (self.etc_glob, self.opt_glob, self.vendor_glob):
            self.cli("set", "ai-access", "lab-maintenance", "path", pattern)
        self.cli("set", "ai-access", "lab-maintenance", "exec-timeout", "300")
        self.cli("set", "ai-access", "lab-maintenance", "action", "allow")
        self.cli("set", "ai-access", "lab-maintenance", "enabled")
        shown = self.cli("show", "ai-access", "lab-maintenance")
        self.assertIn("exec", shown)
        self.cli("set", "ai-access", "exec-only")
        self.cli("set", "ai-access", "exec-only", "principal", "cursor-dev")
        self.cli("set", "ai-access", "exec-only", "target", "client-group", "lab-linux")
        self.cli("set", "ai-access", "exec-only", "capability", "exec")
        warning = self.cli("show", "ai-access", "exec-only")
        self.assertIn("exec can modify the target", warning)
        self.assertIn("true read-only AI role requires exec disabled", warning)
        for cap, operand in (
            ("get_system_info", None),
            ("read_file", str(self.etc_vendor / "config.yaml")),
            ("write_file", str(self.etc_vendor / "test-file")),
            ("upload_file", str(self.opt_vendor / "test.bin")),
            ("download_file", str(self.vendor / "app.log")),
            ("exec", "true"),
        ):
            tokens = ["test", "ai-access", "cursor-dev", "lab1", cap]
            if operand:
                tokens.append(operand)
            out = self.cli(*tokens)
            self.assertIn("ALLOW", out, out)
        prod = self.cli("test", "ai-access", "cursor-dev", "Expernet-DP1", "exec", "id")
        self.assertIn("DENY", prod)

    def test_ai3_explicit_deny_order(self):
        self.cli("set", "client-group", "production-linux")
        self.cli("set", "client-group", "production-linux", "member", "Expernet-DP1")
        self.cli("set", "ai-principal", "cursor-dev")
        self.cli("set", "ai-principal", "cursor-dev", "enabled")
        self.cli("set", "ai-access", "support-read")
        self.cli("set", "ai-access", "support-read", "principal", "cursor-dev")
        self.cli("set", "ai-access", "support-read", "target", "client-group", "production-linux")
        self.cli("set", "ai-access", "support-read", "capability", "exec")
        self.cli("set", "ai-access", "support-read", "action", "allow")
        self.cli("set", "ai-access", "support-read", "enabled")
        self.cli("set", "ai-access", "deny-prod-exec")
        self.cli("set", "ai-access", "deny-prod-exec", "principal", "cursor-dev")
        self.cli("set", "ai-access", "deny-prod-exec", "target", "client-group", "production-linux")
        self.cli("set", "ai-access", "deny-prod-exec", "capability", "exec")
        self.cli("set", "ai-access", "deny-prod-exec", "action", "deny")
        self.cli("set", "ai-access", "deny-prod-exec", "enabled")
        self.cli("set", "ai-access", "deny-prod-exec", "before", "support-read")
        listed = self.cli("show", "ai-access")
        deny_pos = listed.find("deny-prod-exec")
        allow_pos = listed.find("support-read")
        self.assertLess(deny_pos, allow_pos)
        out = self.cli("test", "ai-access", "cursor-dev", "Expernet-DP1", "exec", "id")
        self.assertIn("DENY", out)
        self.assertIn("deny-prod-exec", out)
        self.assertIn("FIRST COMPLETE MATCH", out)

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
        run_cli(self.tmp, ["set", "ai-access", "readonly-support"])
        run_cli(self.tmp, ["set", "ai-access", "readonly-support", "principal", "chatgpt-support"])
        run_cli(self.tmp, ["set", "ai-access", "readonly-support", "target", "client-group", "production-linux"])
        for cap in ("get_system_info", "read_file", "list_processes", "get_host"):
            run_cli(self.tmp, ["set", "ai-access", "readonly-support", "capability", cap])
        run_cli(self.tmp, ["set", "ai-access", "readonly-support", "path", self.vendor_glob])
        run_cli(self.tmp, ["set", "ai-access", "readonly-support", "path", self.etc_glob])
        run_cli(self.tmp, ["set", "ai-access", "readonly-support", "action", "allow"])
        run_cli(self.tmp, ["set", "ai-access", "readonly-support", "enabled"])
        run_cli(self.tmp, ["set", "ai-access", "lab-maintenance"])
        run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "principal", "cursor-dev"])
        run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "target", "client-group", "lab-linux"])
        for cap in (
            "exec",
            "read_file",
            "write_file",
            "upload_file",
            "download_file",
            "get_system_info",
            "get_host",
            "list_hosts",
            "list_processes",
        ):
            run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "capability", cap])
        for pattern in (self.etc_glob, self.opt_glob, self.vendor_glob):
            run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "path", pattern])
        run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "exec-timeout", "2"])
        run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "action", "allow"])
        run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "enabled"])
        self.chatgpt = self._token("chatgpt-support")
        self.cursor = self._token("cursor-dev")
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=True)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.bridge))
        self.port = self.httpd.server_address[1]
        self.bridge.listen_host = "127.0.0.1"
        self.bridge.listen_port = self.port
        self.url = "http://127.0.0.1:%s/mcp" % self.port
        self.base = "http://127.0.0.1:%s" % self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.bridge.refresh_local_agents(self.base)

    def tearDown(self):
        self.bridge.close()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.plane.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

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
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            self.chatgpt,
            method="initialize",
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload.get("error", {}).get("code"), -32601)
        status, payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 19, "method": "ping", "params": {}},
            self.chatgpt,
            method="ping",
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload.get("error", {}).get("code"), -32601)
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
        status, _payload = rpc(
            self.url,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
            "drk_invalid",
            method="tools/list",
        )
        self.assertEqual(status, 401)

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
        status, payload = self.call(self.cursor, "exec", {"endpoint": "lab1", "command": "sleep 8"})
        self.assertIn("TIMEOUT", self.text_of(payload))
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
        run_cli(self.tmp, ["unset", "ai-access", "lab-maintenance", "enabled"])
        worker.join(timeout=10)
        self.assertTrue(started["done"])
        self.assertNotIn("DENY", started["text"])
        status, payload = self.call(self.cursor, "exec", {"endpoint": "lab1", "command": "true"})
        self.assertIn("DENY", self.text_of(payload))
        run_cli(self.tmp, ["set", "ai-access", "lab-maintenance", "enabled"])
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
        run_cli(
            self.tmp,
            ["set", "ai-access", "readonly-support", "target", "endpoint", "Expernet-DP1"],
        )
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

    def test_official_mcp_sdk_client(self):
        sdk_py = os.environ.get("DRLINK_MCP_SDK_PYTHON") or "/tmp/mcp-sdk-venv/bin/python"
        if not os.path.isfile(sdk_py):
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
            ["set", "ai-access", "readonly-support", "capability", "read_file"],
            ["set", "ai-access", "readonly-support", "path", "/var/log/vendor/**"],
            ["test", "ai-access", "chatgpt-support", "Expernet-DP1", "read_file", "/var/log/vendor/app.log"],
            ["show", "ai-access", "readonly-support", "impact"],
            ["show", "ai-activity", "principal", "chatgpt-support"],
            ["system", "credential", "rotate", "ai-principal", "chatgpt-support"],
            ["system", "credential", "configure", "ai-principal", "chatgpt-support", "authentication", "static-bearer"],
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
