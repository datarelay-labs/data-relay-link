#!/usr/bin/env python3
"""P1-OAUTH-4: trusted reverse-proxy source identity for public rate limits."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_mcp_bridge import (  # noqa: E402
    OAUTH_AUTHORIZE_RATE_LIMIT,
    MCPBridge,
    make_handler,
    public_rate_source,
)
import frp_frontend  # noqa: E402

REDIRECT = "http://127.0.0.1/callback"
CHALLENGE = "trusted-proxy-challenge"
SOURCE_A = "198.51.100.9"
SOURCE_B = "198.51.100.10"
RATED_LOCATIONS = (
    "location = /mcp {",
    "location = /.well-known/oauth-protected-resource {",
    "location = /.well-known/oauth-protected-resource/mcp {",
    "location = /.well-known/oauth-authorization-server {",
    "location = /oauth/token {",
    "location = /oauth/authorize {",
    "location = /oauth/continue {",
    "location = /oauth/register {",
    "location = /register {",
    "location = /oauth/revoke {",
)


def free_port() -> int:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TrustedProxyRateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-oauth-proxy-rate-")
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
            ["system", "credential", "configure", "ai-principal", "agent-a", "oauth-redirect", REDIRECT],
            root=self.tmp,
        )
        self.port = free_port()
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), make_handler(self.bridge))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.plane.close()
        os.environ.pop("DRLINK_TEST_ROOT", None)
        os.environ.pop("DRLINK_CONFIRM", None)

    def test_frontend_overwrites_source_on_rated_exact_routes(self):
        conf = frp_frontend._mcp_location_block(6103)
        self.assertNotIn("$proxy_add_x_forwarded_for", conf)
        self.assertNotIn("location ^~ /oauth/", conf)
        self.assertNotIn("location /oauth/", conf)
        for marker in RATED_LOCATIONS:
            start = conf.find(marker)
            self.assertGreaterEqual(start, 0, marker)
            block = conf[start : conf.find("\n        }", start)]
            self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", block, marker)
            self.assertIn("proxy_set_header X-Real-IP $remote_addr;", block, marker)

    def test_public_rate_source_ignores_spoofed_forwarded_headers(self):
        spoofed = {"X-Forwarded-For": SOURCE_A, "X-Real-IP": "198.51.100.8"}
        self.assertEqual(public_rate_source("203.0.113.10", spoofed), "203.0.113.10")
        self.assertEqual(public_rate_source("127.0.0.1", spoofed), SOURCE_A)
        self.assertEqual(public_rate_source("127.0.0.1", {}), "127.0.0.1")
        self.assertEqual(public_rate_source("127.0.0.1", {"X-Forwarded-For": "not-an-ip"}), "127.0.0.1")
        self.assertEqual(public_rate_source("", None), "unknown")

    def _seed(self, bucket: str, source: str, limit: int) -> None:
        hits = getattr(self.bridge, "_rate_hits", None)
        if hits is None:
            self.bridge._rate_hits = {}
            hits = self.bridge._rate_hits
        hits["%s:%s" % (bucket, source)] = [time.time(), limit]

    def _request(self, method: str, path: str, forwarded: str | None = None, body: bytes | None = None) -> int:
        headers = {}
        data = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            data = b"{}" if body is None else body
        if forwarded:
            headers["X-Forwarded-For"] = forwarded
        req = urllib.request.Request(
            "http://127.0.0.1:%s%s" % (self.port, path),
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_distinct_proxy_sources_do_not_share_post_buckets(self):
        cases = (
            ("post", 120, "POST", "/oauth/revoke", 200),
            ("register", 20, "POST", "/oauth/register", None),
            ("register", 20, "POST", "/register", None),
            ("token", 60, "POST", "/oauth/token", None),
            ("authfail", 30, "POST", "/mcp", 401),
        )
        for bucket, limit, method, path, other_status in cases:
            self.bridge._rate_hits = {}
            self._seed(bucket, SOURCE_A, limit)
            self.assertEqual(self._request(method, path, SOURCE_A), 429, bucket + " " + path)
            other = self._request(method, path, SOURCE_B)
            self.assertNotEqual(other, 429, bucket + " " + path)
            if other_status is not None:
                self.assertEqual(other, other_status, bucket + " " + path)

    def test_direct_loopback_without_forwarded_header_stays_bounded(self):
        self._seed("post", "127.0.0.1", 120)
        self.assertEqual(self._request("POST", "/oauth/revoke"), 429)
        self.assertEqual(self._request("POST", "/oauth/revoke", SOURCE_B), 200)
        self.assertIn("post:127.0.0.1", self.bridge._rate_hits)
        self.assertNotIn("post:%s" % SOURCE_A, self.bridge._rate_hits)

    def test_authorize_sources_behind_loopback_are_independent(self):
        self._seed("authorize", SOURCE_A, OAUTH_AUTHORIZE_RATE_LIMIT)
        query = urllib.parse.urlencode(
            {
                "client_id": "agent-a",
                "redirect_uri": REDIRECT,
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "resource": self.bridge.canonical_resource(),
                "state": "proxy-a",
            }
        )
        blocked = self._request("GET", "/oauth/authorize?%s" % query, SOURCE_A)
        self.assertEqual(blocked, 429)
        other = urllib.parse.urlencode(
            {
                "client_id": "agent-a",
                "redirect_uri": REDIRECT,
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "resource": self.bridge.canonical_resource(),
                "state": "proxy-b",
            }
        )
        self.assertEqual(self._request("GET", "/oauth/authorize?%s" % other, SOURCE_B), 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
