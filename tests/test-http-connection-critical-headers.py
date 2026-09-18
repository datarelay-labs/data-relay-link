#!/usr/bin/env python3
"""F04: Connection must not strip Host/Content-Length/Transfer-Encoding."""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import frp_egress_control as EG  # noqa: E402


class _WireOrigin:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.requests: list[bytes] = []
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
        self.sock.close()

    def last(self) -> bytes:
        with self.lock:
            return self.requests[-1] if self.requests else b""

    def _serve(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        conn.settimeout(2.0)
        buf = bytearray()
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
                if b"\r\n\r\n" in buf:
                    head, rest = bytes(buf).split(b"\r\n\r\n", 1)
                    cl = 0
                    for line in head.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"content-length:"):
                            cl = int(line.split(b":", 1)[1].strip())
                    while len(rest) < cl:
                        more = conn.recv(65536)
                        if not more:
                            break
                        rest += more
                        buf.extend(more)
                    break
        except OSError:
            pass
        with self.lock:
            self.requests.append(bytes(buf))
        try:
            body = b"ok"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(body), body)
            )
        except OSError:
            pass
        finally:
            conn.close()


class ConnectionCriticalHeaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        libdir = self.root / "usr/local/lib/drlink"
        libdir.mkdir(parents=True, exist_ok=True)
        for name in (
            "frp_egress_control.py",
            "frp_public_suffix.py",
            "frp_bounded_server.py",
            "frp_policy_fingerprint.py",
        ):
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
            "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
            "egress_listen_addr": "127.0.0.1",
            "egress_listen_port": 0,
        }
        cfg_path = self.root / "etc/drlink/config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(self.cfg, indent=2) + "\n", encoding="utf-8")
        (self.root / "var/log/drlink/egress").mkdir(parents=True, exist_ok=True)

        def mut(state):
            pid, _ = EG.create_profile(state, "t", enabled=False)
            EG.add_source(state, pid, "127.0.0.1/32")
            EG.add_destination(state, pid, "allowed.test", 80, protocol="http")
            EG.set_profile_enabled(state, pid, True)
            return pid

        EG.mutate_egress_state(mut, path=self.state_path)
        from drlink_control_plane import ControlPlane
        import drlink_v24 as v24

        plane = ControlPlane(str(self.root))
        try:
            v24.set_network_object(plane, "proxy-src", type="ip", value="127.0.0.1", oneshot=True)
            v24.set_network_object(plane, "allowed-host", type="fqdn", value="allowed.test", oneshot=True)
            v24.set_service_object(plane, "http", type="tcp", port=80, oneshot=True)
            v24.set_access_rule(
                plane,
                "internet",
                "allow-http",
                mode="whitelist",
                source="proxy-src",
                destination="allowed-host",
                service="http",
                enabled=True,
                oneshot=True,
            )
            plane.compile_runtime()
        finally:
            plane.close()

        self.origin = _WireOrigin()
        self.origin.start()
        gw_path = ROOT / "server" / "frp-egress-gateway.py"
        spec = importlib.util.spec_from_file_location("gw_f04", gw_path)
        self.GW = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.GW)

        def resolve2(hostname: str):
            if hostname == "allowed.test":
                return ["1.2.3.4"]
            raise OSError("nxdomain")

        origin_port = self.origin.port

        def connect(ip: str, port: int, hostname: str, timeout: float):
            return socket.create_connection(("127.0.0.1", origin_port), timeout=timeout or 5)

        cache = self.GW.PolicyCache(cfg_path)
        self.gw_state = self.GW.GatewayState(
            cache, resolve_fn=resolve2, connect_fn=connect, max_concurrent=32
        )
        self.server = self.GW.ThreadedTCPServer(("127.0.0.1", 0), self.gw_state)
        self.proxy_port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def tearDown(self):
        try:
            self.server.shutdown()
        except Exception:
            pass
        self.origin.stop()
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _raw(self, payload: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5) as sock:
            sock.sendall(payload)
            sock.settimeout(5)
            data = b""
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data

    def test_connection_content_length_rejected(self):
        payload = (
            b"POST http://allowed.test/x HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: 4\r\n"
            b"Connection: Content-Length\r\n"
            b"\r\n"
            b"abcd"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:120])
        self.assertEqual(self.origin.last(), b"")

    def test_connection_host_rejected(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: Host\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:120])
        self.assertEqual(self.origin.last(), b"")

    def test_connection_transfer_encoding_rejected(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: Transfer-Encoding\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:120])

    def test_connection_host_case_insensitive(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"host: allowed.test\r\n"
            b"Connection: host\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:120])

    def test_normal_connection_close_forwards_host_and_cl(self):
        payload = (
            b"POST http://allowed.test/body HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Content-Length: 3\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"xyz"
        )
        resp = self._raw(payload)
        self.assertIn(b"200", resp.split(b"\r\n", 1)[0])
        up = self.origin.last()
        self.assertTrue(
            b"Host: allowed.test" in up or b"host: allowed.test" in up,
            up[:200],
        )
        self.assertTrue(
            b"Content-Length: 3" in up or b"content-length: 3" in up,
            up[:200],
        )
        self.assertIn(b"xyz", up)

    def test_connection_multi_token_critical_rejected(self):
        payload = (
            b"GET http://allowed.test/ HTTP/1.1\r\n"
            b"Host: allowed.test\r\n"
            b"Connection: keep-alive, Content-Length\r\n"
            b"\r\n"
        )
        resp = self._raw(payload)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:120])


if __name__ == "__main__":
    unittest.main()
