#!/usr/bin/env python3
"""Controlled Egress policy and security regression tests."""
from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import tempfile
import threading
import time
import unittest
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

os.environ.setdefault("FRP_DEPLOY_TEST_ROOT", "")


def build_client_hello(sni: str) -> bytes:
    """Minimal TLS 1.2 ClientHello with server_name extension (no crypto)."""
    host = sni.encode("ascii")
    name_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_list = len(name_entry).to_bytes(2, "big") + name_entry
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    body = bytearray()
    body += b"\x03\x03"
    body += b"\x00" * 32
    body += b"\x00"
    body += b"\x00\x02\x00\x2f"
    body += b"\x01\x00"
    body += len(sni_ext).to_bytes(2, "big") + sni_ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class EgressPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.state_path = self.root / "var/lib/drlink/egress-control.json"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=self.state_path)
        self.cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json"}

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
            lambda s: EG.add_destination(s, pid, "security.ubuntu.com", 443, protocol="https"), cfg=self.cfg
        )
        state = EG.load_egress_state(cfg=self.cfg)
        allow = EG.authorize_request(
            state,
            source_ip="203.0.113.10",
            hostname="security.ubuntu.com",
            port=443,
            protocol="https",
        )
        self.assertEqual(allow["decision"], EG.DECISION_ALLOW)
        deny_host = EG.authorize_request(
            state,
            source_ip="203.0.113.10",
            hostname="evil.example.com",
            port=443,
            protocol="https",
        )
        self.assertEqual(deny_host["decision"], EG.DECISION_DENY)
        deny_port = EG.authorize_request(
            state,
            source_ip="203.0.113.10",
            hostname="security.ubuntu.com",
            port=80,
            protocol="http",
        )
        self.assertEqual(deny_port["decision"], EG.DECISION_DENY)
        deny_src = EG.authorize_request(
            state,
            source_ip="198.51.100.1",
            hostname="security.ubuntu.com",
            port=443,
            protocol="https",
        )
        self.assertEqual(deny_src["decision"], EG.DECISION_DENY)

    def test_disabled_profile_deny(self):
        pid, _ = self._profile(enabled=True)
        EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "10.0.0.0/8"), cfg=self.cfg)
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, pid, "example.com", 443, protocol="https"), cfg=self.cfg
        )
        EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, False), cfg=self.cfg)
        state = EG.load_egress_state(cfg=self.cfg)
        d = EG.authorize_request(
            state, source_ip="10.1.2.3", hostname="example.com", port=443, protocol="https"
        )
        self.assertEqual(d["decision"], EG.DECISION_DENY)
        self.assertEqual(d["reason"], EG.REASON_PROFILE_DISABLED)

    def test_wildcard_semantics(self):
        self.assertTrue(EG.hostname_matches("api.example.com", "*.example.com", "wildcard"))
        self.assertTrue(EG.hostname_matches("a.b.example.com", "*.example.com", "wildcard"))
        self.assertFalse(EG.hostname_matches("example.com", "*.example.com", "wildcard"))
        self.assertFalse(EG.hostname_matches("evil-example.com", "*.example.com", "wildcard"))
        self.assertFalse(EG.hostname_matches("example.com.evil.org", "*.example.com", "wildcard"))
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
        d = EG.authorize_request(
            None, source_ip="1.2.3.4", hostname="example.com", port=443, protocol="https"
        )
        self.assertEqual(d["decision"], EG.DECISION_DENY)
        d2 = EG.authorize_request(
            EG.empty_egress_state(),
            source_ip="1.2.3.4",
            hostname="example.com",
            port=443,
            protocol="https",
            load_error="boom",
        )
        self.assertEqual(d2["decision"], EG.DECISION_DENY)

    def test_ip_literal_denied(self):
        pid, _ = self._profile()
        EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "0.0.0.0/0"), cfg=self.cfg)
        with self.assertRaises(EG.EgressError):
            EG.mutate_egress_state(lambda s: EG.add_destination(s, pid, "1.2.3.4", 443, protocol="https"), cfg=self.cfg)
        with self.assertRaises(EG.EgressError):
            EG.parse_authority_host_port("1.2.3.4:443")

    def test_ssrf_ranges(self):
        blocked = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
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

    def test_cgnat_100_64_block(self):
        """CGNAT_100_64_BLOCK: RFC6598 Shared Address Space is fail-closed."""
        self.assertTrue(EG.is_unsafe_destination_ip(ipaddress.ip_address("100.64.0.1")))
        with self.assertRaises(EG.EgressError):
            EG.validate_resolved_addresses(["100.64.1.2"])

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
            "[::1]:443",
            "1.2.3.4:443",
            "host:abc",
        ):
            with self.assertRaises(EG.EgressError, msg=bad):
                EG.parse_authority_host_port(bad)

    def test_duplicate_create(self):
        self._profile("dup")
        with self.assertRaises(EG.EgressError):
            self._profile("dup")


class _RecordingOrigin:
    """Raw TCP origin that records exact bytes received (proves upstream leakage)."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.sessions: list[bytes] = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop.set()
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def total_bytes(self) -> bytes:
        with self.lock:
            return b"".join(self.sessions)

    def session_count(self) -> int:
        with self.lock:
            return len(self.sessions)

    def _serve(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        conn.settimeout(2.0)
        buf = bytearray()
        try:
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                # Minimal HTTP response if request looks complete.
                is_http = (
                    buf.startswith(b"GET")
                    or buf.startswith(b"POST")
                    or buf.startswith(b"HEAD")
                    or buf.startswith(b"PUT")
                    or buf.startswith(b"PATCH")
                    or buf.startswith(b"DELETE")
                    or buf.startswith(b"OPTIONS")
                )
                if is_http and b"\r\n\r\n" in buf:
                    head, rest = bytes(buf).split(b"\r\n\r\n", 1)
                    body = b"hello-egress"
                    cl = None
                    for line in head.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"content-length:"):
                            try:
                                cl = int(line.split(b":", 1)[1].strip())
                            except ValueError:
                                cl = None
                    if cl is not None and len(rest) < cl:
                        continue
                    if buf.startswith(b"POST") and cl is not None:
                        body = b"echo:" + rest[:cl]
                    resp = (
                        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                        % len(body)
                    ) + body
                    conn.sendall(resp)
                    break
                # Opaque / TLS ClientHello: keep reading until peer closes or timeout.
                if buf and not is_http:
                    continue
        finally:
            with self.lock:
                self.sessions.append(bytes(buf))
            try:
                conn.close()
            except OSError:
                pass


class EgressProxyFunctionalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        if "frp_egress_gateway" in sys.modules:
            del sys.modules["frp_egress_gateway"]
        libdir = self.root / "usr/local/lib/drlink"
        libdir.mkdir(parents=True, exist_ok=True)
        (libdir / "frp_egress_control.py").write_text(
            (ROOT / "lib" / "frp_egress_control.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (libdir / "frp_public_suffix.py").write_text(
            (ROOT / "lib" / "frp_public_suffix.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (libdir / "frp_bounded_server.py").write_text(
            (ROOT / "lib" / "frp_bounded_server.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        data_dst = libdir / "data"
        data_dst.mkdir(parents=True, exist_ok=True)
        (data_dst / "public_suffix_list.dat").write_bytes(
            (ROOT / "lib" / "data" / "public_suffix_list.dat").read_bytes()
        )
        cfg_path = self.root / "etc/drlink/config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        state_path = self.root / "var/lib/drlink/egress-control.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=state_path)

        def mut(state):
            pid, _ = EG.create_profile(state, "test", enabled=True)
            EG.add_source(state, pid, "127.0.0.1/32")
            EG.add_destination(state, pid, "allowed.test", 80, protocol="http")
            EG.add_destination(state, pid, "allowed.test", 443, protocol="https")
            return pid

        EG.mutate_egress_state(mut, path=state_path)
        cfg = {
            "egress_control_file": "/var/lib/drlink/egress-control.json",
            "egress_conn_log_file": "/var/log/drlink/egress-conn.jsonl",
            "egress_listen_addr": "127.0.0.1",
            "egress_listen_port": 0,
        }
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        self.cfg_path = cfg_path
        self.state_path = state_path
        (self.root / "var/log/drlink").mkdir(parents=True, exist_ok=True)

        self.origin = _RecordingOrigin()
        self.origin.start()
        self.origin_port = self.origin.port

        gw_path = ROOT / "server" / "frp-egress-gateway.py"
        spec = importlib.util.spec_from_file_location("frp_egress_gateway_test", gw_path)
        self.GW = importlib.util.module_from_spec(spec)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        spec.loader.exec_module(self.GW)

        def resolve2(hostname: str):
            if hostname in ("allowed.test", "denied.test"):
                return ["1.2.3.4"]
            if hostname == "private.test":
                return ["10.0.0.1"]
            if hostname == "mixed.test":
                return ["1.2.3.4", "10.0.0.1"]
            if hostname == "cgnat.test":
                return ["100.64.0.10"]
            raise OSError("nxdomain")

        origin_port = self.origin_port
        self.connect_calls = []

        def connect(ip: str, port: int, hostname: str, timeout: float):
            self.assertEqual(ip, "1.2.3.4")
            self.connect_calls.append((ip, port, hostname))
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
            self.origin.stop()
        except Exception:
            pass
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _raw(self, payload: bytes, timeout: float = 5.0) -> bytes:
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=timeout) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            chunks = []
            sock.settimeout(timeout)
            while True:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)

    def _upstream_saw(self, needle: bytes) -> bool:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if needle in self.origin.total_bytes():
                return True
            time.sleep(0.05)
        return needle in self.origin.total_bytes()

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
        self.assertFalse(self._upstream_saw(b"denied.test"))

    def test_connect_allow(self):
        """CONNECT allow with matching SNI; ClientHello forwarded byte-for-byte."""
        req = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        hello = build_client_hello("allowed.test")
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                self.assertTrue(chunk)
                buf += chunk
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"), buf[:80])
            sock.sendall(hello)
            # Give relay time to forward
            time.sleep(0.2)
        self.assertTrue(self._upstream_saw(hello), msg=self.origin.total_bytes()[:200])

    def test_connect_deny_port(self):
        req = b"CONNECT allowed.test:8443 HTTP/1.1\r\nHost: allowed.test:8443\r\n\r\n"
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403"), resp[:80])
        self.assertEqual(self.origin.session_count(), 0)

    def test_private_dns_denied(self):
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, "test", "private.test", 80, protocol="http"),
            path=self.state_path,
        )
        req = (
            b"GET http://private.test/ HTTP/1.1\r\n"
            b"Host: private.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403") or resp.startswith(b"HTTP/1.1 502"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_mixed_dns_denied(self):
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, "test", "mixed.test", 80, protocol="http"),
            path=self.state_path,
        )
        req = (
            b"GET http://mixed.test/ HTTP/1.1\r\n"
            b"Host: mixed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403") or resp.startswith(b"HTTP/1.1 502"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_host_header_mismatch_denied(self):
        req = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: other.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)


class EgressAdversarialTests(EgressProxyFunctionalTests):
    """Attack-oriented Controlled Egress cases. Upstream must not receive abuse bytes."""

    def test_http_excess_body_reject(self):
        """HTTP_EXCESS_BODY_REJECT / EXCESS_BODY_REJECT: body_prefix > Content-Length."""
        # Content-Length: 1 but body is "XGET /second..."
        payload = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: 1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"XGET /second HTTP/1.1\r\nHost: allowed.test\r\n\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)
        self.assertFalse(self._upstream_saw(b"GET /second"))
        self.assertFalse(self._upstream_saw(b"XGET"))

    def test_http_pipelined_second_request_reject(self):
        """HTTP_PIPELINED_SECOND_REQUEST_REJECT / HTTP_SINGLE_REQUEST_BOUNDARY."""
        payload = (
            b"GET http://allowed.test/a HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"GET http://allowed.test/leaked HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        # First request may succeed (no body) — excess after headers with CL absent is reject.
        # With no CL, body_prefix non-empty => 400 before connect.
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)
        self.assertFalse(self._upstream_saw(b"/leaked"))

    def test_cl_te_conflict(self):
        """CL_TE_CONFLICT=PASS — Transfer-Encoding + Content-Length rejected (400)."""
        payload = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: 3\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"3\r\nabc\r\n0\r\n\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)
        self.assertFalse(self._upstream_saw(b"chunked"))
        self.assertFalse(self._upstream_saw(b"abc"))

    def test_negative_cl_reject(self):
        payload = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: -1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"x"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_invalid_cl_reject(self):
        for bad in (b"abc", b"1.5", b"+3", b"08", b""):
            headers = b"Content-Length: " + bad + b"\r\n" if bad else b"Content-Length:\r\n"
            payload = (
                b"POST http://allowed.test/x HTTP/1.1\r\n"
                b"Host: allowed.test\r\n" + headers + b"Connection: close\r\n\r\n"
            )
            resp = self._raw(payload)
            self.assertTrue(resp.startswith(b"HTTP/1.1 400"), msg=(bad, resp[:80]))
            self.assertEqual(len(self.connect_calls), 0)

    def test_incomplete_body_reject(self):
        payload = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: 10\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"short"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_chunked_request_reject(self):
        """CHUNKED_REQUEST_REJECT — TE present => 400 (not stripped)."""
        payload = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"4\r\nleak\r\n0\r\n\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)
        self.assertFalse(self._upstream_saw(b"leak"))

    def test_header_cr_reject(self):
        # Inject CR into header value via raw bytes (parser sees it in value).
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"X-Test: good\rvalue\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_header_lf_reject(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"X-Test: good\nInjected: evil\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)
        self.assertFalse(self._upstream_saw(b"Injected"))

    def test_header_nul_reject(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"X-Test: good\x00evil\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_header_ctl_reject(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"X-Test: good\x01evil\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_header_name_space_reject(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"X Bad Name: value\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_header_name_colon_reject(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Bad@Name: value\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_header_name_control_reject(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"X\x01Bad: value\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_header_name_valid_token_passes(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"X-Valid_Name.1: ok\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertIn(b"200", resp.split(b"\r\n", 1)[0])

    def test_connection_named_header_stripped(self):
        """CONNECTION_NAMED_HEADER_STRIPPED — Connection: X-Internal strips that header."""
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: X-Internal\r\n"
            b"X-Internal: secret-token\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertIn(b"200", resp.split(b"\r\n", 1)[0])
        up = self.origin.total_bytes()
        self.assertIn(b"GET / HTTP/1.1", up)
        self.assertNotIn(b"secret-token", up)
        self.assertNotIn(b"X-Internal: secret-token", up)

    def test_absolute_http_uri(self):
        """ABSOLUTE_HTTP_URI=PASS"""
        payload = (
            b"GET http://allowed.test/ok HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertIn(b"200", resp.split(b"\r\n", 1)[0])

    def test_absolute_https_uri_reject(self):
        """ABSOLUTE_HTTPS_URI_REJECT — deterministic 400 (not 405). Use CONNECT instead."""
        payload = (
            b"GET https://allowed.test/path HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)
        self.assertFalse(self._upstream_saw(b"/path"))

    def test_expect_100_continue_reject(self):
        payload = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: 4\r\n"
            b"Expect: 100-continue\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"data"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_connect_sni_match_allow(self):
        hello = build_client_hello("allowed.test")
        req = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"))
            sock.sendall(hello)
            time.sleep(0.25)
        self.assertTrue(self._upstream_saw(hello))

    def test_connect_sni_mismatch_deny(self):
        hello = build_client_hello("blocked.example.com")
        req = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"))
            sock.sendall(hello)
            time.sleep(0.3)
            try:
                sock.recv(64)
            except OSError:
                pass
        # Upstream TCP may connect, but mismatched ClientHello must NOT be forwarded.
        self.assertFalse(self._upstream_saw(hello))
        self.assertFalse(self._upstream_saw(b"blocked.example.com"))

    def test_connect_fragmented_clienthello(self):
        hello = build_client_hello("allowed.test")
        req = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"))
            for i in range(0, len(hello), 3):
                sock.sendall(hello[i : i + 3])
                time.sleep(0.01)
            time.sleep(0.3)
        self.assertTrue(self._upstream_saw(hello))

    def test_connect_malformed_tls_deny(self):
        junk = b"\x16\x03\x01\x00\x05NOTLS"
        req = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"))
            sock.sendall(junk)
            time.sleep(0.3)
        self.assertFalse(self._upstream_saw(junk))
        self.assertFalse(self._upstream_saw(b"NOTLS"))

    def test_connect_no_sni_behavior(self):
        """CONNECT_NO_SNI_POLICY: missing SNI on port 443 fail-closed."""
        # ClientHello with no extensions / no SNI.
        body = bytearray()
        body += b"\x03\x03" + (b"\x00" * 32) + b"\x00"
        body += b"\x00\x02\x00\x2f" + b"\x01\x00"
        # no extensions field at all
        handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
        hello = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
        req = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"))
            sock.sendall(hello)
            time.sleep(0.3)
        self.assertFalse(self._upstream_saw(hello))

    def test_cgnat_dns_blocked(self):
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, "test", "cgnat.test", 80, protocol="http"),
            path=self.state_path,
        )
        req = (
            b"GET http://cgnat.test/ HTTP/1.1\r\n"
            b"Host: cgnat.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = self._raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1.1 403") or resp.startswith(b"HTTP/1.1 502"), resp[:80])
        self.assertEqual(len(self.connect_calls), 0)

    def test_malformed_uri_port(self):
        for target in (
            b"http://allowed.test:abc/",
            b"http://allowed.test:99999/",
        ):
            payload = (
                b"GET " + target + b" HTTP/1.1\r\n"
                b"Host: allowed.test\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            resp = self._raw(payload)
            self.assertTrue(resp.startswith(b"HTTP/1.1 400"), msg=(target, resp[:80]))
            self.assertEqual(len(self.connect_calls), 0)

    def test_malformed_authority(self):
        for target in (
            b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n",
            b"CONNECT host:abc HTTP/1.1\r\nHost: host:abc\r\n\r\n",
            b"GET http://[bad/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
        ):
            resp = self._raw(target)
            self.assertTrue(
                resp.startswith(b"HTTP/1.1 400") or resp.startswith(b"HTTP/1.1 403"),
                msg=resp[:80],
            )

    def test_worker_exception_escape(self):
        """WORKER_EXCEPTION_ESCAPE=0 — garbage must yield 400, not kill worker."""
        resp = self._raw(b"\xff\xfe\x00not-http\r\n\r\n")
        self.assertTrue(resp.startswith(b"HTTP/1.1 400") or resp == b"", resp[:80])
        # Proxy still serves a normal request afterward (proves worker did not die).
        deadline = time.time() + 5.0
        ok = b""
        while time.time() < deadline:
            ok = self._raw(
                b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n"
            )
            if b"200" in ok.split(b"\r\n", 1)[0]:
                break
            time.sleep(0.05)
        self.assertIn(b"200", ok.split(b"\r\n", 1)[0])
        # Wait for in-flight workers to release (avoid flaky active-count races).
        deadline = time.time() + 5.0
        while time.time() < deadline and self.gw_state._active != 0:
            time.sleep(0.05)
        self.assertEqual(self.gw_state._active, 0)


class EgressRelayTests(unittest.TestCase):
    """RELAY_SLOW_RECEIVER / RELAY_LARGE_PAYLOAD / RELAY_HALF_CLOSE."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        libdir = self.root / "usr/local/lib/drlink"
        libdir.mkdir(parents=True, exist_ok=True)
        (libdir / "frp_egress_control.py").write_text(
            (ROOT / "lib" / "frp_egress_control.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (libdir / "frp_public_suffix.py").write_text(
            (ROOT / "lib" / "frp_public_suffix.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (libdir / "frp_bounded_server.py").write_text(
            (ROOT / "lib" / "frp_bounded_server.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        data_dst = libdir / "data"
        data_dst.mkdir(parents=True, exist_ok=True)
        (data_dst / "public_suffix_list.dat").write_bytes(
            (ROOT / "lib" / "data" / "public_suffix_list.dat").read_bytes()
        )
        cfg_path = self.root / "etc/drlink/config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        state_path = self.root / "var/lib/drlink/egress-control.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=state_path)

        def mut(state):
            pid, _ = EG.create_profile(state, "test", enabled=True)
            EG.add_source(state, pid, "127.0.0.1/32")
            EG.add_destination(state, pid, "allowed.test", 80, protocol="http")
            EG.add_destination(state, pid, "allowed.test", 443, protocol="https")
            return pid

        EG.mutate_egress_state(mut, path=state_path)
        cfg = {
            "egress_control_file": "/var/lib/drlink/egress-control.json",
            "egress_conn_log_file": "/var/log/drlink/egress-conn.jsonl",
            "egress_listen_addr": "127.0.0.1",
            "egress_listen_port": 0,
        }
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        (self.root / "var/log/drlink").mkdir(parents=True, exist_ok=True)

        self.payload = os.urandom(256 * 1024)
        self.slow_delay = 0.002

        origin_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        origin_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        origin_sock.bind(("127.0.0.1", 0))
        origin_sock.listen(5)
        self.origin_port = origin_sock.getsockname()[1]
        self._origin_stop = threading.Event()

        def origin_serve():
            origin_sock.settimeout(0.5)
            while not self._origin_stop.is_set():
                try:
                    conn, _ = origin_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._origin_handle, args=(conn,), daemon=True).start()
            try:
                origin_sock.close()
            except OSError:
                pass

        self._origin_sock = origin_sock
        self.origin_thread = threading.Thread(target=origin_serve, daemon=True)
        self.origin_thread.start()

        gw_path = ROOT / "server" / "frp-egress-gateway.py"
        spec = importlib.util.spec_from_file_location("frp_egress_gateway_relay", gw_path)
        self.GW = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.GW)

        def resolve(hostname: str):
            if hostname == "allowed.test":
                return ["1.2.3.4"]
            raise OSError("nxdomain")

        origin_port = self.origin_port

        def connect(ip: str, port: int, hostname: str, timeout: float):
            self.assertEqual(ip, "1.2.3.4")
            return socket.create_connection(("127.0.0.1", origin_port), timeout=timeout)

        cache = self.GW.PolicyCache(cfg_path)
        self.gw_state = self.GW.GatewayState(
            cache, resolve_fn=resolve, connect_fn=connect, max_concurrent=32
        )
        self.server = self.GW.ThreadedTCPServer(("127.0.0.1", 0), self.gw_state)
        self.proxy_port = self.server.server_address[1]
        self.proxy_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.proxy_thread.start()

    def _origin_handle(self, conn: socket.socket):
        conn.settimeout(5.0)
        buf = bytearray()
        try:
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf.extend(chunk)
            # Large response for relay tests.
            body = self.payload
            headers = (
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                % len(body)
            )
            conn.sendall(headers)
            # Send in paced chunks to exercise backpressure with slow client.
            view = memoryview(body)
            step = 8192
            for i in range(0, len(body), step):
                conn.sendall(view[i : i + step])
                time.sleep(0.0005)
        except OSError:
            pass
        finally:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def tearDown(self):
        self._origin_stop.set()
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self._origin_sock.close()
        except Exception:
            pass
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def test_relay_large_payload(self):
        req = (
            b"GET http://allowed.test/big HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=10) as sock:
            sock.sendall(req)
            sock.shutdown(socket.SHUT_WR)
            data = b""
            sock.settimeout(30)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 200"))
        self.assertIn(self.payload, data)

    def test_relay_slow_receiver(self):
        req = (
            b"GET http://allowed.test/slow HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=10) as sock:
            sock.sendall(req)
            sock.shutdown(socket.SHUT_WR)
            data = b""
            sock.settimeout(60)
            while True:
                r, _, _ = select.select([sock], [], [], 5.0)
                if not r:
                    break
                chunk = sock.recv(1024)  # intentionally small reads
                if not chunk:
                    break
                data += chunk
                time.sleep(self.slow_delay)
        self.assertTrue(data.startswith(b"HTTP/1.1 200"), data[:80])
        self.assertIn(self.payload, data)

    def test_relay_half_close(self):
        """Client half-close after request; response still completes."""
        req = (
            b"GET http://allowed.test/half HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=10) as sock:
            sock.sendall(req)
            sock.shutdown(socket.SHUT_WR)
            data = b""
            sock.settimeout(30)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 200"))
        self.assertIn(self.payload, data)


class EgressHardeningFeatureTests(unittest.TestCase):
    """Option B, DNS, HE, streaming, ECH, limits, import/export."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        libdir = self.root / "usr/local/lib/drlink"
        libdir.mkdir(parents=True, exist_ok=True)
        for name in ("frp_egress_control.py", "frp_public_suffix.py", "frp_bounded_server.py"):
            (libdir / name).write_text((ROOT / "lib" / name).read_text(encoding="utf-8"), encoding="utf-8")
        data_dst = libdir / "data"
        data_dst.mkdir(parents=True, exist_ok=True)
        (data_dst / "public_suffix_list.dat").write_bytes(
            (ROOT / "lib" / "data" / "public_suffix_list.dat").read_bytes()
        )
        self.state_path = self.root / "var/lib/drlink/egress-control.json"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=self.state_path)
        self.cfg = {
            "egress_control_file": "/var/lib/drlink/egress-control.json",
            "egress_conn_log_file": "/var/log/drlink/egress-conn.jsonl",
            "egress_listen_addr": "127.0.0.1",
            "egress_listen_port": 0,
        }
        cfg_path = self.root / "etc/drlink/config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(self.cfg, indent=2) + "\n", encoding="utf-8")
        (self.root / "var/log/drlink").mkdir(parents=True, exist_ok=True)
        self.cfg_path = cfg_path

        def mut(state):
            pid, _ = EG.create_profile(state, "test", enabled=True)
            EG.add_source(state, pid, "127.0.0.1/32")
            EG.add_destination(state, pid, "allowed.test", 80, protocol="http")
            EG.add_destination(state, pid, "allowed.test", 443, protocol="https")
            EG.add_destination(state, pid, "allowed.test", 8443, protocol="https")
            return pid

        EG.mutate_egress_state(mut, path=self.state_path)

        self.origin = _RecordingOrigin()
        self.origin.start()
        origin_port = self.origin.port

        gw_path = ROOT / "server" / "frp-egress-gateway.py"
        if "frp_egress_gateway_hard" in sys.modules:
            del sys.modules["frp_egress_gateway_hard"]
        spec = importlib.util.spec_from_file_location("frp_egress_gateway_hard", gw_path)
        self.GW = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.GW)
        # Fast revalidation for Option B tests.
        self.GW.SESSION_REVALIDATE_INTERVAL = 0.2
        self.GW.DNS_TIMEOUT = 2.0

        self.resolve_counts = {}

        def resolve2(hostname: str):
            self.resolve_counts[hostname] = self.resolve_counts.get(hostname, 0) + 1
            if hostname == "allowed.test":
                return ["1.2.3.4"]
            if hostname == "dual.test":
                return ["2606:4700::1", "1.2.3.4"]
            if hostname == "mixed.test":
                return ["1.2.3.4", "10.0.0.1"]
            if hostname == "slow.test":
                time.sleep(3.0)
                return ["1.2.3.4"]
            raise OSError("nxdomain")

        def connect(ip: str, port: int, hostname: str, timeout: float):
            if ip in ("10.0.0.1",):
                raise OSError("should not connect unsafe")
            if ip == "2606:4700::1":
                # Simulate unreachable v6.
                raise OSError("network unreachable")
            sock = socket.create_connection(("127.0.0.1", origin_port), timeout=timeout)
            return sock

        cache = self.GW.PolicyCache(cfg_path)
        self.gw_state = self.GW.GatewayState(
            cache,
            resolve_fn=resolve2,
            connect_fn=connect,
            max_concurrent=8,
            per_source_limit=2,
            dns_pending_limit=2,
        )
        self.server = self.GW.ThreadedTCPServer(("127.0.0.1", 0), self.gw_state)
        self.proxy_port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.origin.stop()
        except Exception:
            pass
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _conn_log(self) -> str:
        path = self.root / "var/log/drlink/egress-conn.jsonl"
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8")

    def test_protocol_http_connect_denied(self):
        """CONNECT must not use an http-only destination even if host:port match."""
        # Remove https:80 if any; only http:80 exists for port 80.
        req = b"CONNECT allowed.test:80 HTTP/1.1\r\nHost: allowed.test:80\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(req)
            data = sock.recv(4096)
        self.assertTrue(data.startswith(b"HTTP/1.1 403") or data.startswith(b"HTTP/1.1 400"), data[:80])

    def test_ech_clienthello_denied(self):
        host = b"allowed.test"
        name_entry = b"\x00" + len(host).to_bytes(2, "big") + host
        sni_list = len(name_entry).to_bytes(2, "big") + name_entry
        sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
        ech_ext = b"\xfe\x0d" + b"\x00\x04" + b"\x00\x00\x00\x00"
        exts = sni_ext + ech_ext
        body = bytearray()
        body += b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
        body += len(exts).to_bytes(2, "big") + exts
        handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
        hello = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
        # Send headers first, then ClientHello, so body_prefix is empty and the
        # gateway must read/parse the ECH ClientHello on the tunnel.
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
            sock.settimeout(3)
            first = sock.recv(4096)
            self.assertTrue(first.startswith(b"HTTP/1.1 200"), first[:80])
            sock.sendall(hello)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
        deadline = time.time() + 2.0
        while time.time() < deadline and "TLS_CLIENT_HELLO_INVALID" not in self._conn_log():
            time.sleep(0.05)
        self.assertIn("TLS_CLIENT_HELLO_INVALID", self._conn_log())

    def test_https_non443_sni_required(self):
        hello = build_client_hello("allowed.test")
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(b"CONNECT allowed.test:8443 HTTP/1.1\r\nHost: allowed.test:8443\r\n\r\n")
            sock.settimeout(3)
            first = sock.recv(4096)
            self.assertTrue(first.startswith(b"HTTP/1.1 200"), first[:80])
            sock.sendall(hello)
            time.sleep(0.3)
        deadline = time.time() + 2.0
        saw = False
        while time.time() < deadline:
            if self.origin.total_bytes():
                saw = True
                break
            time.sleep(0.05)
        self.assertTrue(saw)

    def test_dns_coalesce_and_positive_cache(self):
        barrier = threading.Barrier(4)
        errors = []

        def one():
            try:
                barrier.wait(timeout=5)
                ips = self.gw_state.dns.resolve_validated("allowed.test")
                self.assertEqual(ips, ["1.2.3.4"])
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=one) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(errors, [])
        # Coalesce + cache: resolve_fn should run once (or very few), not 4.
        self.assertLessEqual(self.resolve_counts.get("allowed.test", 0), 2)
        # Warm cache hit — no additional resolve.
        before = self.resolve_counts.get("allowed.test", 0)
        self.assertEqual(self.gw_state.dns.resolve_validated("allowed.test"), ["1.2.3.4"])
        self.assertEqual(self.resolve_counts.get("allowed.test", 0), before)

    def test_dns_mixed_unsafe_deny_all(self):
        with self.assertRaises(Exception) as ctx:
            self.gw_state.dns.resolve_validated("mixed.test")
        self.assertIn("unsafe", str(ctx.exception).lower())

    def test_dns_pending_limit(self):
        started = threading.Event()
        release = threading.Event()

        def slow_resolve(hostname: str):
            started.set()
            release.wait(timeout=5)
            return ["1.2.3.4"]

        dns = self.GW.DnsResolver(resolve_fn=slow_resolve, pending_limit=1, timeout=2.0)
        errors = []

        def leader():
            try:
                dns.resolve_validated("slow.pending")
            except Exception as exc:
                errors.append(("leader", exc))

        def waiter():
            started.wait(timeout=2)
            try:
                dns.resolve_validated("other.pending")
            except Exception as exc:
                errors.append(("waiter", exc))

        t1 = threading.Thread(target=leader)
        t2 = threading.Thread(target=waiter)
        t1.start()
        t2.start()
        started.wait(timeout=2)
        time.sleep(0.05)
        release.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
        self.assertTrue(any("pending limit" in str(e) for _who, e in errors))

    def test_happy_eyeballs_falls_back_to_v4(self):
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, "test", "dual.test", 443, protocol="https"),
            path=self.state_path,
        )
        self.gw_state.cache.reload(force=True)
        sock, decision = self.GW._authorize_and_connect(
            self.gw_state,
            source_ip="127.0.0.1",
            hostname="dual.test",
            port=443,
            method="CONNECT",
            protocol="https",
        )
        self.assertIsNotNone(sock)
        self.assertEqual(decision.get("decision"), EG.DECISION_ALLOW)
        sock.close()

    def test_http_body_streaming_large(self):
        # Above BODY_MEMORY_THRESHOLD → disk spool; RSS must not hold full body.
        size = 2 * 1024 * 1024
        body = b"A" * size
        req = (
            b"POST http://allowed.test/upload HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        ) % size + body
        self.assertGreater(size, self.GW.BODY_MEMORY_THRESHOLD)
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=30) as sock:
            sock.sendall(req)
            sock.settimeout(30)
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 200"), data[:80])
        upstream = self.origin.total_bytes()
        self.assertIn(b"POST /upload HTTP/1.1", upstream)
        self.assertIn(b"A" * 1024, upstream)
        self.assertGreaterEqual(len(upstream), size)

    def test_session_terminal_outcome_logged(self):
        hello = build_client_hello("allowed.test")
        s = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        try:
            s.sendall(
                b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n" + hello
            )
            s.settimeout(3)
            first = s.recv(4096)
            self.assertTrue(first.startswith(b"HTTP/1.1 200"), first[:80])
            s.close()
            deadline = time.time() + 3.0
            log = ""
            while time.time() < deadline:
                log = self._conn_log()
                if "CLIENT_CLOSED" in log or "UPSTREAM_CLOSED" in log or "IDLE_TIMEOUT" in log:
                    break
                time.sleep(0.05)
            self.assertTrue(
                any(tok in log for tok in ("CLIENT_CLOSED", "UPSTREAM_CLOSED", "IDLE_TIMEOUT")),
                log[-500:],
            )
            self.assertIn("session_id", log)
        finally:
            try:
                s.close()
            except OSError:
                pass

    def test_per_source_limit_resource_limit(self):
        # Hold two CONNECT tunnels open (limit=2), third must 503.
        hello = build_client_hello("allowed.test")
        socks = []
        try:
            for _ in range(2):
                s = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
                s.sendall(
                    b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n" + hello
                )
                s.settimeout(3)
                first = s.recv(4096)
                self.assertTrue(first.startswith(b"HTTP/1.1 200"), first[:80])
                socks.append(s)
            s3 = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
            s3.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n" + hello)
            s3.settimeout(3)
            resp = s3.recv(4096)
            s3.close()
            self.assertTrue(resp.startswith(b"HTTP/1.1 503"), resp[:80])
            self.assertIn("RESOURCE_LIMIT", self._conn_log())
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

    def test_option_b_policy_revoked_closes_session(self):
        hello = build_client_hello("allowed.test")
        s = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        try:
            s.sendall(
                b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n" + hello
            )
            s.settimeout(3)
            first = s.recv(4096)
            self.assertTrue(first.startswith(b"HTTP/1.1 200"), first[:80])
            # Revoke destination while tunnel is live.
            EG.mutate_egress_state(
                lambda st: EG.remove_destination(st, "test", "allowed.test:443"),
                path=self.state_path,
            )
            self.gw_state.cache.reload(force=True)
            # Wait for revalidation interval and expect peer close.
            s.settimeout(3)
            deadline = time.time() + 3.0
            closed = False
            while time.time() < deadline:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        closed = True
                        break
                except socket.timeout:
                    continue
            self.assertTrue(closed)
            self.assertIn("POLICY_REVOKED", self._conn_log())
        finally:
            try:
                s.close()
            except OSError:
                pass

    def test_option_b_unrelated_change_keeps_session(self):
        hello = build_client_hello("allowed.test")
        s = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        try:
            s.sendall(
                b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n" + hello
            )
            first = s.recv(4096)
            self.assertTrue(first.startswith(b"HTTP/1.1 200"), first[:80])
            # Unrelated: add another destination (generation bumps but still authorized).
            EG.mutate_egress_state(
                lambda st: EG.add_destination(st, "test", "other.test", 443, protocol="https"),
                path=self.state_path,
            )
            self.gw_state.cache.reload(force=True)
            time.sleep(0.6)
            # Connection should still be open (send should succeed or not get immediate close).
            try:
                s.sendall(b"\x00")
                alive = True
            except OSError:
                alive = False
            self.assertTrue(alive)
            self.assertNotIn("POLICY_REVOKED", self._conn_log())
        finally:
            try:
                s.close()
            except OSError:
                pass

    def test_export_import_diff_no_auto_enable(self):
        state = EG.load_egress_state(path=self.state_path)
        doc = EG.export_profile(state, "test")
        self.assertEqual(doc["schema_version"], EG.EGRESS_SCHEMA_VERSION)
        candidate = EG.parse_import_document(doc)
        self.assertFalse(candidate.get("enabled"))
        # Mutate candidate destination set
        candidate["destinations"] = list(candidate.get("destinations") or [])[:-1]
        diff = EG.diff_profiles(state["egress_profiles"][doc["profile"]["id"]], candidate)
        self.assertTrue(diff["destinations_removed"] or diff["destinations_added"] is not None)

        def mut(st):
            return EG.import_profile_into_state(st, candidate, target_selector="test")

        pid, profile, _diff = EG.mutate_egress_state(mut, path=self.state_path)
        self.assertFalse(profile.get("enabled"))
        self.assertEqual(pid, doc["profile"]["id"])


class EgressPublicSuffixTests(unittest.TestCase):
    def test_reject_public_suffix_wildcards(self):
        for bad in ("*.com", "*.net", "*.org", "*.co.kr", "*.co.uk"):
            with self.assertRaises(EG.EgressError):
                EG.canonicalize_hostname(bad, allow_wildcard=True)

    def test_allow_narrow_wildcard(self):
        host, mode = EG.canonicalize_hostname("*.ubuntu.com", allow_wildcard=True)
        self.assertEqual(host, "*.ubuntu.com")
        self.assertEqual(mode, "wildcard")


class EgressSchemaMigrationTests(unittest.TestCase):
    def test_migrate_80_443_and_fail_closed_custom(self):
        raw = {
            "schema_version": 1,
            "egress_profiles": {
                "egp_aaaaaaaaaaaa": {
                    "id": "egp_aaaaaaaaaaaa",
                    "name": "legacy",
                    "enabled": False,
                    "description": "",
                    "sources": [],
                    "destinations": [
                        {"id": "egd_1", "host": "a.example", "port": 80, "match": "exact"},
                        {"id": "egd_2", "host": "b.example", "port": 443, "match": "exact"},
                    ],
                    "created_at": "t",
                    "updated_at": "t",
                }
            },
        }
        migrated = EG.migrate_egress_state_v1_to_v2(raw)
        dests = migrated["egress_profiles"]["egp_aaaaaaaaaaaa"]["destinations"]
        self.assertEqual(dests[0]["protocol"], "http")
        self.assertEqual(dests[1]["protocol"], "https")
        raw["egress_profiles"]["egp_aaaaaaaaaaaa"]["destinations"].append(
            {"id": "egd_3", "host": "c.example", "port": 8443, "match": "exact"}
        )
        with self.assertRaises(EG.EgressError):
            EG.migrate_egress_state_v1_to_v2(raw)


if __name__ == "__main__":
    unittest.main()
