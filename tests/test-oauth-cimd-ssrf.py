#!/usr/bin/env python3
"""P1-OAUTH-3: CIMD outbound fetch SSRF / draft alignment / rebinding boundary."""
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

REQUESTED_CIMD_URL = "https://cimd.test/client.json"


def free_port() -> int:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _CimdHandler(BaseHTTPRequestHandler):
    behavior = "ok"
    request_count = 0

    def log_message(self, fmt, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        type(self).request_count += 1
        mode = type(self).behavior
        if mode.startswith("redirect"):
            self.send_response(302)
            self.send_header("Location", "https://cimd.test/other.json")
            self.end_headers()
            return
        if mode == "bad_ctype":
            body = json.dumps(
                {"client_id": REQUESTED_CIMD_URL, "redirect_uris": ["https://example.com/cb"]}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "plus_json":
            body = json.dumps(
                {
                    "client_id": REQUESTED_CIMD_URL,
                    "redirect_uris": ["https://example.com/cb"],
                    "client_name": "plus-json",
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.oai.openapi+json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "too_large":
            # Keep valid JSON object shape while exceeding the 5 KiB cap.
            pad = "x" * (CIMD_FETCH_MAX_BYTES)
            body = json.dumps(
                {
                    "client_id": REQUESTED_CIMD_URL,
                    "redirect_uris": ["https://example.com/cb"],
                    "pad": pad,
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "missing_client_id":
            body = json.dumps({"redirect_uris": ["https://example.com/cb"]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "mismatched_client_id":
            body = json.dumps(
                {
                    "client_id": "https://cimd.test/other.json",
                    "redirect_uris": ["https://example.com/cb"],
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps(
            {
                "client_id": REQUESTED_CIMD_URL,
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
        self._httpd = None
        self._handler_cls = None

    def tearDown(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        self.plane.close()
        os.environ.pop("DRLINK_TEST_ROOT", None)
        os.environ.pop("DRLINK_CONFIRM", None)

    def _start_https(self, behavior: str) -> int:
        port = free_port()
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
        handler = type("H", (_CimdHandler,), {"behavior": behavior, "request_count": 0})
        httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self._httpd = httpd
        self._handler_cls = handler

        def _ctx():
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            return c

        self.plane._cimd_ssl_context = _ctx  # type: ignore[method-assign]
        return port

    def _pin_local(self, port: int, peer_ip: str = "1.1.1.1"):
        import socket

        self.plane._cimd_resolve_validated_ips = lambda host: [peer_ip]  # type: ignore
        real_cc = socket.create_connection

        def _cc(address, timeout=None, source_address=None):
            if address[0] == peer_ip:
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

    def test_rejects_identifier_edge_whitespace_and_controls_without_normalizing(self):
        base = REQUESTED_CIMD_URL
        padded = [
            " " + base,
            base + " ",
            "\t" + base,
            base + "\t",
            "\r" + base,
            base + "\r",
            "\n" + base,
            base + "\n",
            "\r\n" + base,
            base + "\r\n",
            "\x00" + base,
            base + "\x7f",
        ]
        for uri in padded:
            with self.assertRaises(ControlPlaneError, msg=repr(uri)) as ctx:
                self.plane._fetch_cimd_document(uri)
            self.assertIn("whitespace", str(ctx.exception).lower(), msg=repr(uri))
        # Trailing whitespace still looks like an https client_id; it must not
        # be stripped into a stored CIMD cache key.
        with self.assertRaises(ControlPlaneError):
            self.plane.resolve_oauth_authorize_client(base + " ", "https://example.com/cb")
        with self.assertRaises(ControlPlaneError):
            self.plane.resolve_oauth_authorize_client(base + "\t", "https://example.com/cb")
        with self.assertRaises(ControlPlaneError):
            self.plane.resolve_oauth_authorize_client(base + "\r\n", "https://example.com/cb")
        row = self.plane.conn.execute(
            "SELECT client_id FROM ai_oauth_dcr_clients WHERE client_id = ? OR client_id = ? OR metadata_url = ?",
            (base, base + " ", base),
        ).fetchone()
        self.assertIsNone(row)

    def test_rejects_userinfo_fragment_bad_port_and_dot_segments(self):
        for uri in (
            "https://user:pass@example.com/meta.json",
            "https://example.com/meta.json#frag",
            "https://example.com:abc/meta.json",
            "https://example.com:65536/meta.json",
            "http://example.com/meta.json",
            "https://example.com/",
            "https://example.com/./meta.json",
            "https://example.com/foo/../meta.json",
            "https://example.com/../meta.json",
        ):
            with self.assertRaises(ControlPlaneError, msg=uri):
                self.plane._fetch_cimd_document(uri)

    def test_rejects_mixed_public_and_private_dns_answers(self):
        import socket

        real_gai = socket.getaddrinfo

        def _mixed(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
            ]

        socket.getaddrinfo = _mixed  # type: ignore
        self.addCleanup(lambda: setattr(socket, "getaddrinfo", real_gai))
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._cimd_resolve_validated_ips("cimd.test")
        self.assertIn("not allowed", str(ctx.exception).lower())
        # Must not return the filtered public-only subset.
        with self.assertRaises(ControlPlaneError):
            self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)

    def test_rejects_resolved_private_or_special_addresses(self):
        for peer in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::2", "100.64.1.1"):
            self.plane._cimd_resolve_validated_ips = lambda host, p=peer: [p]  # type: ignore
            with self.assertRaises(ControlPlaneError, msg=peer):
                self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)

    def test_rejects_3xx_without_following_redirect(self):
        port = self._start_https("redirect")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertIn("redirect", str(ctx.exception).lower())
        self.assertEqual(self._handler_cls.request_count, 1)

    def test_connects_only_to_validated_peer_not_rebinding_lookup(self):
        port = self._start_https("ok")
        calls = {"resolve": 0, "connect_hosts": []}
        import socket

        def _resolve(host):
            calls["resolve"] += 1
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
        doc = self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertEqual(doc["client_name"], "ok-cimd")
        self.assertEqual(calls["connect_hosts"], ["1.1.1.1"])
        self.assertEqual(calls["resolve"], 1)

    def test_rejects_bad_content_type(self):
        port = self._start_https("bad_ctype")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertIn("content-type", str(ctx.exception).lower())

    def test_accepts_application_plus_json(self):
        port = self._start_https("plus_json")
        self._pin_local(port)
        doc = self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertEqual(doc["client_name"], "plus-json")

    def test_rejects_oversized_body(self):
        self.assertEqual(CIMD_FETCH_MAX_BYTES, 5 * 1024)
        port = self._start_https("too_large")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertIn("too large", str(ctx.exception).lower())

    def test_rejects_missing_metadata_client_id(self):
        port = self._start_https("missing_client_id")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertIn("client_id", str(ctx.exception).lower())

    def test_rejects_mismatched_metadata_client_id(self):
        port = self._start_https("mismatched_client_id")
        self._pin_local(port)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertIn("client_id", str(ctx.exception).lower())

    def test_valid_public_https_cimd_success(self):
        port = self._start_https("ok")
        self._pin_local(port)
        doc = self.plane._fetch_cimd_document(REQUESTED_CIMD_URL)
        self.assertEqual(doc["client_id"], REQUESTED_CIMD_URL)
        self.assertEqual(doc["redirect_uris"], ["https://example.com/cb"])
        resolved = self.plane.resolve_oauth_authorize_client(
            REQUESTED_CIMD_URL, "https://example.com/cb"
        )
        self.assertEqual(resolved["source"], "cimd")
        self.assertEqual(resolved["client_id"], REQUESTED_CIMD_URL)
        cached = self.plane.conn.execute(
            "SELECT client_id, metadata_url FROM ai_oauth_dcr_clients WHERE client_id = ?",
            (REQUESTED_CIMD_URL,),
        ).fetchone()
        self.assertIsNotNone(cached)
        self.assertEqual(cached["client_id"], REQUESTED_CIMD_URL)
        self.assertEqual(cached["metadata_url"], REQUESTED_CIMD_URL)
        print("CIMD_SSRF_LITERAL_BLOCKED=PASS")
        print("CIMD_SSRF_MIXED_DNS_REJECTED=PASS")
        print("CIMD_SSRF_REDIRECT_NO_FOLLOW=PASS")
        print("CIMD_SSRF_DOT_SEGMENTS_REJECTED=PASS")
        print("CIMD_SSRF_DNS_REBIND_PINNED_PEER=PASS")
        print("CIMD_SSRF_CONTENT_BOUNDS_5KIB=PASS")
        print("CIMD_SSRF_PLUS_JSON_ACCEPTED=PASS")
        print("CIMD_SSRF_CLIENT_ID_BINDING=PASS")
        print("CIMD_SSRF_VALID_PUBLIC_SUCCESS=PASS")


if __name__ == "__main__":
    unittest.main()
