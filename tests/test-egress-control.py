#!/usr/bin/env python3
"""Controlled Egress policy and security regression tests."""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import importlib.util
import sys

sys.path.insert(0, str(ROOT / "lib"))
spec = importlib.util.spec_from_file_location(
    "frp_egress_control", ROOT / "lib" / "frp_egress_control.py"
)
EG = importlib.util.module_from_spec(spec)
spec.loader.exec_module(EG)

gw_spec = importlib.util.spec_from_file_location(
    "frp_egress_gateway", ROOT / "server" / "frp-egress-gateway.py"
)
# Gateway loads EG via path search; set env so it finds lib.
os.environ.setdefault("FRP_DEPLOY_TEST_ROOT", "")


class EgressPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.state_path = self.root / "var/lib/frp-auto-deploy/egress-control.json"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=self.state_path)
        self.cfg = {"egress_control_file": "/var/lib/frp-auto-deploy/egress-control.json"}

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _profile(self, name="ubuntu-update", enabled=True):
        def mut(state):
            return EG.create_profile(state, name, enabled=enabled)

        return EG.mutate_egress_state(mut, cfg=self.cfg)

    def test_exact_fqdn_allow_deny(self):
        pid, _ = self._profile()
        EG.mutate_egress_state(
            lambda s: EG.add_source(s, pid, "203.0.113.10/32"), cfg=self.cfg
        )
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, pid, "security.ubuntu.com", 443), cfg=self.cfg
        )
        state = EG.load_egress_state(cfg=self.cfg)
        allow = EG.authorize_request(
            state, source_ip="203.0.113.10", hostname="security.ubuntu.com", port=443
        )
        self.assertEqual(allow["decision"], EG.DECISION_ALLOW)
        deny_host = EG.authorize_request(
            state, source_ip="203.0.113.10", hostname="evil.example.com", port=443
        )
        self.assertEqual(deny_host["decision"], EG.DECISION_DENY)
        deny_port = EG.authorize_request(
            state, source_ip="203.0.113.10", hostname="security.ubuntu.com", port=80
        )
        self.assertEqual(deny_port["decision"], EG.DECISION_DENY)
        deny_src = EG.authorize_request(
            state, source_ip="198.51.100.1", hostname="security.ubuntu.com", port=443
        )
        self.assertEqual(deny_src["decision"], EG.DECISION_DENY)

    def test_disabled_profile_deny(self):
        pid, _ = self._profile(enabled=True)
        EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "10.0.0.0/8"), cfg=self.cfg)
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, pid, "example.com", 443), cfg=self.cfg
        )
        EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, False), cfg=self.cfg)
        state = EG.load_egress_state(cfg=self.cfg)
        d = EG.authorize_request(state, source_ip="10.1.2.3", hostname="example.com", port=443)
        self.assertEqual(d["decision"], EG.DECISION_DENY)
        self.assertEqual(d["reason"], EG.REASON_PROFILE_DISABLED)

    def test_wildcard_semantics(self):
        self.assertTrue(EG.hostname_matches("api.example.com", "*.example.com", "wildcard"))
        self.assertTrue(EG.hostname_matches("a.b.example.com", "*.example.com", "wildcard"))
        self.assertFalse(EG.hostname_matches("example.com", "*.example.com", "wildcard"))
        self.assertFalse(EG.hostname_matches("evil-example.com", "*.example.com", "wildcard"))
        self.assertFalse(EG.hostname_matches("example.com.evil.org", "*.example.com", "wildcard"))
        # case / trailing dot
        host, mode = EG.canonicalize_hostname("API.Example.COM.")
        self.assertEqual(host, "api.example.com")
        self.assertEqual(mode, "exact")

    def test_invalid_cidr_reject(self):
        pid, _ = self._profile()
        with self.assertRaises(EG.EgressError):
            EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "not-a-cidr"), cfg=self.cfg)

    def test_corrupt_and_missing_fail_closed(self):
        self.state_path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(EG.EgressError):
            EG.load_egress_state(cfg=self.cfg)
        self.state_path.unlink()
        with self.assertRaises(EG.EgressError):
            EG.load_egress_state(cfg=self.cfg)
        d = EG.authorize_request(None, source_ip="1.2.3.4", hostname="example.com", port=443)
        self.assertEqual(d["decision"], EG.DECISION_DENY)
        d2 = EG.authorize_request(
            EG.empty_egress_state(),
            source_ip="1.2.3.4",
            hostname="example.com",
            port=443,
            load_error="boom",
        )
        self.assertEqual(d2["decision"], EG.DECISION_DENY)

    def test_ip_literal_denied(self):
        pid, _ = self._profile()
        EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "0.0.0.0/0"), cfg=self.cfg)
        with self.assertRaises(EG.EgressError):
            EG.mutate_egress_state(lambda s: EG.add_destination(s, pid, "1.2.3.4", 443), cfg=self.cfg)
        with self.assertRaises(EG.EgressError):
            EG.parse_authority_host_port("1.2.3.4:443")

    def test_ssrf_ranges(self):
        blocked = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "fc00::1",
            "224.0.0.1",
        ]
        for ip in blocked:
            self.assertTrue(
                EG.is_unsafe_destination_ip(ipaddress.ip_address(ip)),
                msg=ip,
            )
        self.assertFalse(EG.is_unsafe_destination_ip(ipaddress.ip_address("1.1.1.1")))
        with self.assertRaises(EG.EgressError):
            EG.validate_resolved_addresses(["8.8.8.8", "10.0.0.1"])

    def test_connect_parser_hardening(self):
        host, port = EG.parse_authority_host_port("security.ubuntu.com:443")
        self.assertEqual((host, port), ("security.ubuntu.com", 443))
        for bad in (
            "host",
            "host:0",
            "host:65536",
            "host:08",
            "user@host:443",
            "host:443 ",
            "host\r\n:443",
            "[::1]:443",  # IP literal
            "1.2.3.4:443",
            "host:abc",
        ):
            with self.assertRaises(EG.EgressError, msg=bad):
                EG.parse_authority_host_port(bad)

    def test_duplicate_create(self):
        self._profile("dup")
        with self.assertRaises(EG.EgressError):
            self._profile("dup")


class EgressProxyFunctionalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        # Import gateway after setting test root so module search works.
        if "frp_egress_gateway" in sys.modules:
            del sys.modules["frp_egress_gateway"]
        # Force reload of EG path in gateway by ensuring FRP_DEPLOY_TEST_ROOT libs exist
        libdir = self.root / "usr/local/lib/frp-auto-deploy"
        libdir.mkdir(parents=True, exist_ok=True)
        (libdir / "frp_egress_control.py").write_text(
            (ROOT / "lib" / "frp_egress_control.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        cfg_path = self.root / "etc/frp-auto-deploy/config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        state_path = self.root / "var/lib/frp-auto-deploy/egress-control.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=state_path)

        def mut(state):
            pid, _ = EG.create_profile(state, "test")
            EG.add_source(state, pid, "127.0.0.1/32")
            EG.add_destination(state, pid, "allowed.test", 80)
            EG.add_destination(state, pid, "allowed.test", 443)
            return pid

        EG.mutate_egress_state(mut, path=state_path)
        cfg = {
            "egress_control_file": "/var/lib/frp-auto-deploy/egress-control.json",
            "egress_conn_log_file": "/var/log/frp-auto-deploy/egress-conn.jsonl",
            "egress_listen_addr": "127.0.0.1",
            "egress_listen_port": 0,
        }
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        self.cfg_path = cfg_path

        # Local origin server
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"hello-egress"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or "0")
                data = self.rfile.read(n)
                body = b"echo:" + data
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        self.origin = HTTPServer(("127.0.0.1", 0), H)
        self.origin_port = self.origin.server_address[1]
        self.origin_thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        self.origin_thread.start()

        gw_path = ROOT / "server" / "frp-egress-gateway.py"
        spec = importlib.util.spec_from_file_location("frp_egress_gateway_test", gw_path)
        self.GW = importlib.util.module_from_spec(spec)
        # Pretend ROOT env for gateway module loader
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        spec.loader.exec_module(self.GW)

        def resolve(hostname: str):
            if hostname == "allowed.test":
                return ["203.0.113.50"]  # documentation range? wait - blocked!
            if hostname == "denied.test":
                return ["203.0.113.50"]
            raise OSError("nxdomain")

        # Use a public-looking test IP that is NOT in blocked list.
        # 1.2.3.4 is public enough for validate_resolved_addresses.
        def resolve2(hostname: str):
            if hostname in ("allowed.test", "denied.test"):
                return ["1.2.3.4"]
            if hostname == "private.test":
                return ["10.0.0.1"]
            if hostname == "mixed.test":
                return ["1.2.3.4", "10.0.0.1"]
            raise OSError("nxdomain")

        origin_port = self.origin_port

        def connect(ip: str, port: int, hostname: str, timeout: float):
            # Rebinding-safe: connect to exact IP argument, but for harness map
            # validated public IP to local origin without re-resolving hostname.
            self.assertEqual(ip, "1.2.3.4")
            sock = socket.create_connection(("127.0.0.1", origin_port), timeout=timeout)
            return sock

        cache = self.GW.PolicyCache(cfg_path)
        self.gw_state = self.GW.GatewayState(
            cache, resolve_fn=resolve2, connect_fn=connect, max_concurrent=32
        )
        self.server = self.GW.ThreadedTCPServer(("127.0.0.1", 0), self.gw_state)
        self.proxy_port = self.server.server_address[1]
        self.proxy_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.proxy_thread.start()

    def tearDown(self):
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.origin.shutdown()
        except Exception:
            pass
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _raw(self, payload: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)

    def test_http_get_allow(self):
        req = (
            b"GET http://allowed.test/path HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertIn(b"200", resp.split(b"\r\n", 1)[0])
        self.assertIn(b"hello-egress", resp)

    def test_http_post_allow(self):
        body = b"abc123"
        req = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"%s"
        ) % (len(body), body)
        resp = self._raw(req)
        self.assertIn(b"echo:abc123", resp)

    def test_http_deny_host(self):
        req = (
            b"GET http://denied.test/ HTTP/1.1\r\n"
            b"Host: denied.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403"), resp[:80])

    def test_connect_allow(self):
        req = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            # Read status line
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                self.assertTrue(chunk)
                buf += chunk
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"), buf[:80])
            # After CONNECT, send a raw HTTP request to origin mapped by harness
            sock.sendall(b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            self.assertIn(b"hello-egress", data)

    def test_connect_deny_port(self):
        req = b"CONNECT allowed.test:8443 HTTP/1.1\r\nHost: allowed.test:8443\r\n\r\n"
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403"), resp[:80])

    def test_private_dns_denied(self):
        # Authorize would need destination policy — add temporarily via mutate
        state_path = self.root / "var/lib/frp-auto-deploy/egress-control.json"
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, "test", "private.test", 80),
            path=state_path,
        )
        req = (
            b"GET http://private.test/ HTTP/1.1\r\n"
            b"Host: private.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403") or resp.startswith(b"HTTP/1.1 502"), resp[:80])

    def test_mixed_dns_denied(self):
        state_path = self.root / "var/lib/frp-auto-deploy/egress-control.json"
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, "test", "mixed.test", 80),
            path=state_path,
        )
        req = (
            b"GET http://mixed.test/ HTTP/1.1\r\n"
            b"Host: mixed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403") or resp.startswith(b"HTTP/1.1 502"), resp[:80])

    def test_host_header_mismatch_denied(self):
        req = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: other.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])


if __name__ == "__main__":
    unittest.main()
