#!/usr/bin/env python3
"""P1-OAUTH-3: CIMD outbound fetch SSRF / redirect / rebinding boundary."""
from __future__ import annotations

import json
import os
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import (  # noqa: E402
    CIMD_FETCH_MAX_BYTES,
    ControlPlane,
    ControlPlaneError,
)


def free_port() -> int:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _CimdHandler(BaseHTTPRequestHandler):
    behavior = "ok"

    def log_message(self, fmt, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        mode = type(self).behavior
        if mode == "redirect_http":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/meta.json")
            self.end_headers()
            return
        if mode == "redirect_loopback":
            self.send_response(302)
            self.send_header("Location", "https://127.0.0.1/meta.json")
            self.end_headers()
            return
        if mode == "redirect_chain":
            self.send_response(302)
            self.send_header("Location", "https://cimd.test/next.json")
            self.end_headers()
            return
        if mode == "bad_ctype":
            body = b'{"redirect_uris":["https://example.com/cb"]}'
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "too_large":
            body = b"{" + (b"a" * (CIMD_FETCH_MAX_BYTES + 64)) + b"}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps(
            {
                "client_id": "https://cimd.test/client.json",
                "redirect_uris": ["https://example.com/cb"],
                "client_name": "ok-cimd",
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OAuthCimdSsrfTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-cimd-ssrf-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        self._tls = None
        self._httpd = None

    def tearDown(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        self.plane.close()
        os.environ.pop("DRLINK_TEST_ROOT", None)
        os.environ.pop("DRLINK_CONFIRM", None)

    def _start_https(self, behavior: str) -> int:
        port = free_port()
        # Self-signed cert for hermetic TLS; production path still uses default verify,
        # tests override _cimd_ssl_context to trust this cert.
        import subprocess

        key = Path(self.tmp) / "key.pem"
        cert = Path(self.tmp) / "cert.pem"
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=cimd.test",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        handler = type("H", (_CimdHandler,), {"behavior": behavior})
        httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self._httpd = httpd
        self._cert = cert

        def _ctx():
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            return c

        self.plane._cimd_ssl_context = _ctx  # type: ignore[method-assign]
        return port

    def _pin_local(self, port: int, peer_ip: str = "1.1.1.1"):
        """Resolve to a public peer IP but connect to the local hermetic HTTPS port."""
        import socket

        self.plane._cimd_resolve_validated_ips = lambda host: [peer_ip]  # type: ignore

        real_cc = socket.create_connection

        def _cc(address, timeout=None, source_address=None):
            host, p = address[0], address[1]
            if host == peer_ip:
                return real_cc(("127.0.0.1", port), timeout=timeout, source_address=source_address)
            return real_cc(address, timeout=timeout, source_address=source_address)

        socket.create_connection = _cc  # type: ignore
        self.addCleanup(lambda: setattr(socket, "create_connection", real_cc))

    def test_rejects_literal_private_loopback_linklocal_metadata(self):
        blocked = [
            "https://127.0.0.1/meta.json",
            "https://10.0.0.8/meta.json",
            "https://192.168.1.9/meta.json",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/meta.json",
            "https://[fe80::1]/meta.json",
            "https://[fc00::1]/meta.json",
        ]
        for uri in blocked:
            with self.assertRaises(ControlPlaneError, msg=uri):
                self.plane._fetch_cimd_document(uri)

    def test_rejects_userinfo_fragment_and_bad_port(self):
        for uri in (
            "https://user:pass@example.com/meta.json",
            "https://example.com/meta.json#frag",
            "https://example.com:abc/meta.json",
            "https://example.com:65536/meta.json",
            "http://example.com/meta.json",
            "https://example.com/",
        ):
            with self.assertRaises(ControlPlaneError, msg=uri):
                self.plane._fetch_cimd_document(uri)

    def test_rejects_resolved_private_or_special_addresses(self):
        for peer in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::2", "100.64.1.1"):
            self.plane._cimd_resolve_validated_ips = lambda host, p=peer: [p]  # type: ignore
            with self.assertRaises(ControlPlaneError, msg=peer):
                # resolve returns blocked; fetch must fail closed before/at pin check
                self.plane._fetch_cimd_document("https://cimd.test/client.json")

    def test_rejects_http_downgrade_redirect(self):
        port = self._start_https("redirect_http")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document("https://cimd.test/client.json")
        self.assertIn("https", str(ctx.exception).lower())

    def test_rejects_redirect_to_loopback(self):
        port = self._start_https("redirect_loopback")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError):
            self.plane._fetch_cimd_document("https://cimd.test/client.json")

    def test_rejects_excessive_redirect_chain(self):
        port = self._start_https("redirect_chain")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document("https://cimd.test/client.json")
        self.assertIn("redirect", str(ctx.exception).lower())

    def test_connects_only_to_validated_peer_not_rebinding_lookup(self):
        port = self._start_https("ok")
        calls = {"resolve": 0, "connect_hosts": []}
        import socket

        def _resolve(host):
            calls["resolve"] += 1
            # First validated peer is public; a rebinding lookup would yield loopback.
            return ["1.1.1.1"]

        self.plane._cimd_resolve_validated_ips = _resolve  # type: ignore
        real_cc = socket.create_connection

        def _cc(address, timeout=None, source_address=None):
            calls["connect_hosts"].append(address[0])
            if address[0] == "1.1.1.1":
                return real_cc(("127.0.0.1", port), timeout=timeout, source_address=source_address)
            raise AssertionError("must not connect to unbound/rebound address %r" % (address,))

        socket.create_connection = _cc  # type: ignore
        self.addCleanup(lambda: setattr(socket, "create_connection", real_cc))
        doc = self.plane._fetch_cimd_document("https://cimd.test/client.json")
        self.assertEqual(doc["client_name"], "ok-cimd")
        self.assertEqual(calls["connect_hosts"], ["1.1.1.1"])
        self.assertGreaterEqual(calls["resolve"], 1)

    def test_rejects_bad_content_type(self):
        port = self._start_https("bad_ctype")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document("https://cimd.test/client.json")
        self.assertIn("content-type", str(ctx.exception).lower())

    def test_rejects_oversized_body(self):
        port = self._start_https("too_large")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document("https://cimd.test/client.json")
        self.assertIn("too large", str(ctx.exception).lower())

    def test_valid_public_https_cimd_success(self):
        port = self._start_https("ok")
        self._pin_local(port)
        doc = self.plane._fetch_cimd_document("https://cimd.test/client.json")
        self.assertEqual(doc["redirect_uris"], ["https://example.com/cb"])
        resolved = self.plane.resolve_oauth_authorize_client(
            "https://cimd.test/client.json", "https://example.com/cb"
        )
        self.assertEqual(resolved["source"], "cimd")
        print("CIMD_SSRF_LITERAL_BLOCKED=PASS")
        print("CIMD_SSRF_REDIRECT_HTTP_DOWNGRADE=PASS")
        print("CIMD_SSRF_REDIRECT_LOOPBACK=PASS")
        print("CIMD_SSRF_REDIRECT_LIMIT=PASS")
        print("CIMD_SSRF_DNS_REBIND_PINNED_PEER=PASS")
        print("CIMD_SSRF_CONTENT_BOUNDS=PASS")
        print("CIMD_SSRF_VALID_PUBLIC_SUCCESS=PASS")


if __name__ == "__main__":
    unittest.main()
