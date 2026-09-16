#!/usr/bin/env python3
"""Data Relay Link MCP Bridge (MCP 2026-07-28 Streamable HTTP).

Stateless JSON-RPC over POST /mcp. Authentication (Bearer token bound to an
AI Principal) is separate from authorization (ordered AI Access rules).
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Optional
from urllib.parse import urlparse

from drlink_ai_agent import execute_local
from drlink_control_db import ControlPlaneError, open_control_db, resolve_root
from drlink_control_plane import AI_CAPABILITIES, ControlPlane, path_allowed

MCP_PROTOCOL_VERSION = "2026-07-28"
MCP_TRANSPORT = "streamable-http"
DEFAULT_LISTEN = "127.0.0.1"
DEFAULT_PORT = 6103

TOOL_DEFS = (
    ("list_hosts", "List Managed Endpoints this principal may target", {}),
    ("get_host", "Get one Managed Endpoint", {"endpoint": "string"}),
    ("get_system_info", "Read uname/system identity from a Managed Endpoint", {"endpoint": "string"}),
    ("exec", "Run a shell command on a Managed Endpoint", {"endpoint": "string", "command": "string"}),
    ("read_file", "Read a file within allowed path scopes", {"endpoint": "string", "path": "string"}),
    ("write_file", "Write a file within allowed path scopes", {"endpoint": "string", "path": "string", "content": "string"}),
    ("upload_file", "Upload bytes to an allowed path", {"endpoint": "string", "path": "string", "content": "string"}),
    ("download_file", "Download a file from an allowed path", {"endpoint": "string", "path": "string"}),
    ("list_processes", "List processes on a Managed Endpoint", {"endpoint": "string"}),
)


def _jsonrpc_error(req_id, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _jsonrpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


class MCPBridge:
    def __init__(self, root: Optional[str] = None, plane: Optional[ControlPlane] = None):
        self.root = root or resolve_root()
        self.plane = plane or ControlPlane(self.root)
        self.running_ops = {}
        self._lock = threading.Lock()

    def authenticate(self, headers) -> Optional[Any]:
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if not auth.lower().startswith("bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        if not token:
            return None
        with self._lock:
            return self.plane.authenticate_principal(token)

    def handle_rpc(self, body: dict, headers, principal) -> dict:
        with self._lock:
            return self._handle_rpc_locked(body, headers, principal)

    def _handle_rpc_locked(self, body: dict, headers, principal) -> dict:
        req_id = body.get("id")
        method = str(body.get("method") or "")
        params = body.get("params") or {}
        meta = (params.get("_meta") if isinstance(params, dict) else None) or body.get("_meta") or {}
        proto = headers.get("MCP-Protocol-Version") or headers.get("mcp-protocol-version") or ""
        meta_ver = meta.get("io.modelcontextprotocol/protocolVersion") or proto
        if proto and meta_ver and proto != meta_ver:
            return _jsonrpc_error(req_id, -32020, "HeaderMismatch")
        if proto and proto != MCP_PROTOCOL_VERSION:
            return _jsonrpc_error(req_id, -32602, "Unsupported protocol version")
        mcp_method = headers.get("Mcp-Method") or headers.get("mcp-method") or ""
        if mcp_method and mcp_method != method:
            return _jsonrpc_error(req_id, -32020, "HeaderMismatch")
        if method == "server/discover":
            return _jsonrpc_result(
                req_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "data-relay-link", "version": "2.4.0"},
                },
            )
        if method in ("initialize", "notifications/initialized"):
            # Compatibility with older hosts; 2026-07-28 is stateless.
            return _jsonrpc_result(
                req_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "data-relay-link", "version": "2.4.0"},
                },
            )
        if method == "tools/list":
            tools = []
            for name, desc, props in TOOL_DEFS:
                tools.append(
                    {
                        "name": name,
                        "description": desc,
                        "inputSchema": {
                            "type": "object",
                            "properties": {k: {"type": v} for k, v in props.items()},
                        },
                    }
                )
            return _jsonrpc_result(
                req_id,
                {
                    "tools": tools,
                    "ttlMs": 5000,
                    "cacheScope": "private",
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "data-relay-link",
                            "version": "2.4.0",
                        }
                    },
                },
            )
        if method == "tools/call":
            name = (params.get("name") if isinstance(params, dict) else None) or ""
            hdr_name = headers.get("Mcp-Name") or headers.get("mcp-name") or ""
            if hdr_name and hdr_name != name:
                return _jsonrpc_error(req_id, -32020, "HeaderMismatch")
            args = params.get("arguments") if isinstance(params, dict) else {}
            try:
                result = self.call_tool(principal, name, args or {})
                return _jsonrpc_result(req_id, result)
            except ControlPlaneError as exc:
                return _jsonrpc_result(req_id, _text_result("DENY: %s" % exc))
            except Exception as exc:
                return _jsonrpc_error(req_id, -32603, "internal error", str(exc))
        return _jsonrpc_error(req_id, -32601, "Method not found")

    def call_tool(self, principal, name: str, arguments: dict) -> dict:
        if name not in AI_CAPABILITIES:
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=str(arguments.get("endpoint") or "-"),
                capability=name,
                result="DENY",
                operand="unknown capability",
            )
            return _text_result("DENY: unknown capability")
        if name == "list_hosts":
            hosts = []
            decision = None
            for obj in self.plane.list_objects():
                if obj["type"] != "managed_endpoint":
                    continue
                allowed = False
                for cap in ("list_hosts", "get_host", "get_system_info"):
                    decision = self.plane.evaluate_ai_access(principal["name"], obj["name"], cap)
                    if decision["action"] == "ALLOW":
                        allowed = True
                        break
                if allowed:
                    hosts.append(
                        {
                            "name": obj["name"],
                            "status": obj.get("status"),
                            "client_id": obj.get("client_id"),
                        }
                    )
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint="*",
                capability="list_hosts",
                result="ALLOW" if hosts else "DENY",
                rule=(decision["winner"]["name"] if decision and decision.get("winner") else None),
            )
            return _text_result(json.dumps(hosts, indent=2))
        endpoint = str(arguments.get("endpoint") or arguments.get("host") or "")
        if not endpoint:
            raise ControlPlaneError("endpoint is required")
        operand = arguments.get("path") or arguments.get("command") or arguments.get("operand")
        start = time.monotonic()
        decision = self.plane.evaluate_ai_access(principal["name"], endpoint, name, operand)
        if decision["action"] != "ALLOW":
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="DENY",
                rule=decision["winner"]["name"] if decision.get("winner") else None,
                operand=operand,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            return _text_result("DENY\nReason: %s" % decision["reason"])
        ep = decision.get("endpoint_row")
        if ep is None:
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="UNAVAILABLE",
                rule=decision["winner"]["name"] if decision.get("winner") else None,
                operand=operand,
            )
            return _text_result("Authorization: ALLOW\nDelivery: endpoint unavailable")
        if ep["status"] == "orphaned":
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="UNAVAILABLE",
                rule=decision["winner"]["name"] if decision.get("winner") else None,
                operand=operand,
            )
            return _text_result("Authorization: ALLOW\nDelivery: endpoint unavailable (orphaned)")
        link = self.plane.conn.execute(
            "SELECT c.connected, c.status FROM managed_endpoints e JOIN clients c ON c.id = e.client_id WHERE e.object_id = ?",
            (ep["id"],),
        ).fetchone()
        if link is None or not int(link["connected"] or 0):
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="UNAVAILABLE",
                rule=decision["winner"]["name"] if decision.get("winner") else None,
                operand=operand,
            )
            return _text_result("Authorization: ALLOW\nDelivery: endpoint unavailable")
        if name == "get_host":
            view = {
                "name": ep["name"],
                "status": ep["status"],
                "type": ep["type"],
                "origin": ep["origin"],
            }
            self.plane.record_ai_activity(
                principal=principal["name"],
                endpoint=endpoint,
                capability=name,
                result="ALLOW",
                rule=decision["winner"]["name"],
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            return _text_result(json.dumps(view, indent=2))
        patterns = decision["winner"].get("paths") or []
        timeout = decision.get("exec_timeout")
        op_id = "%s:%s:%s" % (principal["name"], endpoint, name)
        self.running_ops[op_id] = True
        try:
            payload = execute_local(name, arguments, patterns=patterns, timeout=timeout)
        finally:
            self.running_ops.pop(op_id, None)
        duration_ms = int((time.monotonic() - start) * 1000)
        op_result = payload.get("result") or "ALLOW"
        self.plane.record_ai_activity(
            principal=principal["name"],
            endpoint=endpoint,
            capability=name,
            result=op_result,
            rule=decision["winner"]["name"],
            operand=operand,
            duration_ms=duration_ms,
        )
        safe = dict(payload)
        if name not in ("read_file", "download_file"):
            safe.pop("content_b64", None)
        return _text_result(json.dumps(safe, indent=2))


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def make_handler(bridge: MCPBridge):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _send(self, code, payload, extra_headers=None):
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path in ("/healthz", "/health"):
                st = bridge.plane.status()
                mcp = "Healthy" if st.get("mcp_configured") else "Not configured"
                self._send(200, {"status": mcp, "revision": st["revision"]})
                return
            self._send(404, {"error": "not found"})

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path not in ("/mcp", "/"):
                self._send(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 2_000_000:
                self._send(413, _jsonrpc_error(None, -32700, "payload too large"))
                return
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                self._send(400, _jsonrpc_error(None, -32700, "parse error"))
                return
            principal = bridge.authenticate(self.headers)
            if principal is None:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="drlink-mcp"')
                self.send_header("Content-Type", "application/json")
                payload = json.dumps(_jsonrpc_error(body.get("id"), -32001, "unauthorized")).encode("utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            result = bridge.handle_rpc(body, self.headers, principal)
            self._send(200, result)

    return Handler


def serve(host=DEFAULT_LISTEN, port=DEFAULT_PORT, root=None):
    bridge = MCPBridge(root=root)
    httpd = ThreadingHTTPServer((host, int(port)), make_handler(bridge))
    httpd.serve_forever()


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Data Relay Link MCP Bridge")
    parser.add_argument("--listen", default=os.environ.get("DRLINK_MCP_LISTEN", DEFAULT_LISTEN))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DRLINK_MCP_PORT", DEFAULT_PORT)))
    args = parser.parse_args(argv)
    serve(args.listen, args.port)


if __name__ == "__main__":
    main()
