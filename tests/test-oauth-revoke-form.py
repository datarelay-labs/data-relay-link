#!/usr/bin/env python3
"""RFC 7009 revocation through the real MCP HTTP handler.

form-urlencoded /oauth/revoke must not crash when do_POST also parses
form-urlencoded /oauth/token. Unknown tokens still return HTTP 200, and a
revoked access token stops authorizing /mcp.
"""
from __future__ import annotations

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

from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_mcp_bridge import MCP_PROTOCOL_VERSION, MCPBridge, ThreadingHTTPServer, make_handler  # noqa: E402


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class OAuthRevokeFormTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-oauth-revoke-form-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        self.plane.set_ai_principal("revoke-agent", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'revoke-agent'"
        )
        self.plane.conn.commit()
        self.port = free_port()
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        self.bridge.listen_host = "127.0.0.1"
        self.bridge.listen_port = self.port
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), make_handler(self.bridge))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:%s" % self.port

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.plane.close()
        os.environ.pop("DRLINK_TEST_ROOT", None)
        os.environ.pop("DRLINK_CONFIRM", None)

    def _post(self, path: str, body: bytes, content_type: str) -> tuple[int, bytes]:
        req = urllib.request.Request(
            self.base + path,
            data=body,
            headers={"Content-Type": content_type},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def _mcp(self, token: str) -> int:
        payload = {
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
            data=json.dumps(payload).encode("utf-8"),
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
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_form_urlencoded_unknown_token_returns_200(self):
        status, raw = self._post(
            "/oauth/revoke",
            urllib.parse.urlencode(
                {"token": "drauth_unknown", "token_type_hint": "access_token"}
            ).encode("utf-8"),
            "application/x-www-form-urlencoded",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw.decode("utf-8")), {})

    def test_json_unknown_token_still_returns_200(self):
        status, raw = self._post(
            "/oauth/revoke",
            json.dumps({"token": "drauth_unknown_json"}).encode("utf-8"),
            "application/json",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw.decode("utf-8")), {})

    def test_form_urlencoded_revoke_makes_access_token_unusable(self):
        issued = self.plane.issue_oauth_access_token(
            principal_id=self.plane.get_principal("revoke-agent")["id"],
            client_id="revoke-agent",
            resource=self.bridge.canonical_resource(),
            include_refresh=False,
        )
        token = issued["access_token"]
        self.assertEqual(self._mcp(token), 200)
        status, raw = self._post(
            "/oauth/revoke",
            urllib.parse.urlencode({"token": token}).encode("utf-8"),
            "application/x-www-form-urlencoded",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw.decode("utf-8")), {})
        self.assertEqual(self._mcp(token), 401)
        self.assertIsNone(
            self.plane.authenticate_oauth_token(token, resource=self.bridge.canonical_resource())
        )


if __name__ == "__main__":
    unittest.main()
