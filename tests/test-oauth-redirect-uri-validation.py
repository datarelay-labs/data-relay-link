#!/usr/bin/env python3
"""Finding E: OAuth redirect URI loopback validation (no deceptive prefixes)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane, ControlPlaneError  # noqa: E402
from drlink_mcp_bridge import MCPBridge, make_handler  # noqa: E402


def free_port() -> int:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class OAuthRedirectUriValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-oauth-redir-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        os.environ.pop("DRLINK_TEST_ROOT", None)
        os.environ.pop("DRLINK_CONFIRM", None)

    def test_accepts_loopback_http_and_https(self):
        accepted = [
            "https://chatgpt.com/aip/g/callback",
            "https://example.com/cb",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:8080/callback",
            "http://localhost/callback",
            "http://localhost:9876/path",
            "http://[::1]/callback",
            "http://[::1]:4242/callback",
            "http://127.0.0.8/cb",
        ]
        for uri in accepted:
            self.assertEqual(self.plane._validate_oauth_redirect_uri(uri), uri, uri)

    def test_rejects_deceptive_and_non_loopback_http(self):
        rejected = [
            "http://localhost.evil.example/callback",
            "http://127.0.0.1.evil.example/callback",
            "http://[::1].evil.example/callback",
            "http://evil.example/callback",
            "http://192.168.1.1/callback",
            "http://0.0.0.0/callback",
            "http://127.0.0.1@evil.example/callback",
            "http://user:pass@127.0.0.1/callback",
            "http://localhost@evil.example/callback",
            "http://",
            "http:///callback",
            "ftp://127.0.0.1/callback",
            "javascript:alert(1)",
        ]
        for uri in rejected:
            with self.assertRaises(ControlPlaneError, msg=uri):
                self.plane._validate_oauth_redirect_uri(uri)

    def test_rejects_fragment_component(self):
        rejected = [
            "https://example.com/cb#frag",
            "http://127.0.0.1/cb#frag",
            "http://localhost:8080/cb#x",
            "https://chatgpt.com/aip/g/callback#token",
            "https://example.com/cb#",
        ]
        for uri in rejected:
            with self.assertRaises(ControlPlaneError, msg=uri) as ctx:
                self.plane._validate_oauth_redirect_uri(uri)
            self.assertIn("fragment", str(ctx.exception).lower(), uri)

    def test_rejects_malformed_and_out_of_range_ports(self):
        rejected = [
            "https://example.com:abc/cb",
            "http://127.0.0.1:abc/cb",
            "https://example.com:65536/cb",
            "http://127.0.0.1:65536/cb",
            "https://example.com:0/cb",
            "http://localhost:0/cb",
            "http://[::1]:99999/cb",
        ]
        for uri in rejected:
            with self.assertRaises(ControlPlaneError, msg=uri):
                self.plane._validate_oauth_redirect_uri(uri)

    def test_accepts_valid_explicit_ports(self):
        accepted = [
            "https://example.com:443/cb",
            "https://example.com:8443/path",
            "http://127.0.0.1:1/cb",
            "http://127.0.0.1:65535/cb",
            "http://localhost:8080/callback",
            "http://[::1]:4242/callback",
        ]
        for uri in accepted:
            self.assertEqual(self.plane._validate_oauth_redirect_uri(uri), uri, uri)

    def test_dcr_rejects_deceptive_loopback_lookalikes(self):
        for uri in (
            "http://localhost.evil.example/callback",
            "http://127.0.0.1.evil.example/callback",
        ):
            with self.assertRaises(ControlPlaneError):
                self.plane.register_oauth_client(
                    {
                        "redirect_uris": [uri],
                        "token_endpoint_auth_method": "none",
                        "client_name": "evil",
                    }
                )

    def test_dcr_rejects_fragment_and_bad_port(self):
        for uri in (
            "https://example.com/cb#frag",
            "http://127.0.0.1/cb#frag",
            "https://example.com:abc/cb",
            "http://127.0.0.1:65536/cb",
        ):
            with self.assertRaises(ControlPlaneError, msg=uri):
                self.plane.register_oauth_client(
                    {
                        "redirect_uris": [uri],
                        "token_endpoint_auth_method": "none",
                        "client_name": "bad-grammar",
                    }
                )

    def test_dcr_accepts_true_loopback(self):
        for uri in (
            "http://127.0.0.1:5555/callback",
            "http://localhost:5555/callback",
            "http://[::1]:5555/callback",
        ):
            issued = self.plane.register_oauth_client(
                {
                    "redirect_uris": [uri],
                    "token_endpoint_auth_method": "none",
                    "client_name": "ok",
                }
            )
            self.assertIn(uri, issued["redirect_uris"])

    def test_authorize_rejects_deceptive_redirect_via_http(self):
        port = free_port()
        bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(bridge))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        bridge.listen_host = "127.0.0.1"
        bridge.listen_port = port
        base = "http://127.0.0.1:%s" % port
        try:
            # Valid client registered with true loopback; authorize with lookalike must fail closed.
            issued = self.plane.register_oauth_client(
                {
                    "redirect_uris": ["http://127.0.0.1/callback"],
                    "token_endpoint_auth_method": "none",
                    "client_name": "good",
                }
            )
            for bad in (
                "http://localhost.evil.example/callback",
                "http://127.0.0.1.evil.example/callback",
                "http://127.0.0.1/callback#frag",
                "https://example.com/cb#frag",
                "http://127.0.0.1:abc/callback",
            ):
                qs = urllib.parse.urlencode(
                    {
                        "response_type": "code",
                        "client_id": issued["client_id"],
                        "redirect_uri": bad,
                        "code_challenge": "A" * 43,
                        "code_challenge_method": "S256",
                        "resource": "http://127.0.0.1:%s/mcp" % port,
                    }
                )
                try:
                    urllib.request.urlopen(base + "/oauth/authorize?" + qs, timeout=10)
                    self.fail("invalid redirect_uri must not authorize: %s" % bad)
                except urllib.error.HTTPError as exc:
                    self.assertEqual(exc.code, 400, bad)

            # DCR of deceptive URI itself must fail at registration endpoint.
            for bad in (
                "http://localhost.evil.example/callback",
                "http://127.0.0.1.evil.example/callback",
            ):
                try:
                    urllib.request.urlopen(
                        urllib.request.Request(
                            base + "/oauth/register",
                            data=json.dumps(
                                {
                                    "redirect_uris": [bad],
                                    "token_endpoint_auth_method": "none",
                                    "client_name": "evil-dcr",
                                }
                            ).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        ),
                        timeout=10,
                    )
                    self.fail("DCR must reject deceptive redirect_uri: %s" % bad)
                except urllib.error.HTTPError as exc:
                    self.assertIn(exc.code, (400, 422), bad)

            # Happy path still works for true loopback.
            qs_ok = urllib.parse.urlencode(
                {
                    "response_type": "code",
                    "client_id": issued["client_id"],
                    "redirect_uri": "http://127.0.0.1/callback",
                    "code_challenge": "A" * 43,
                    "code_challenge_method": "S256",
                    "resource": "http://127.0.0.1:%s/mcp" % port,
                }
            )
            page = urllib.request.urlopen(base + "/oauth/authorize?" + qs_ok, timeout=10).read().decode("utf-8")
            self.assertIn("approve-oauth", page)
            print("OAUTH_REDIRECT_LOOPBACK_VALIDATION=PASS")
            print("OAUTH_REDIRECT_DECEPTIVE_PREFIX_REJECTED=PASS")
            print("OAUTH_DCR_DECEPTIVE_REDIRECT_REJECTED=PASS")
        finally:
            httpd.shutdown()
            httpd.server_close()
            bridge.close()


if __name__ == "__main__":
    unittest.main()
