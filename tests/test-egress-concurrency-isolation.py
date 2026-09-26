#!/usr/bin/env python3
"""Internet Access concurrency: isolated SQLite auth and bounded resources.

A shared ControlPlane connection raises sqlite3.InterfaceError under concurrent
CONNECT. Those faults must not become HTTP 400, and a 20-way burst must release
slots, threads, and sockets so the next request succeeds immediately.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))


def build_client_hello(sni: str) -> bytes:
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


def _seed_internet_allow(root: Path) -> None:
    from drlink_control_plane import ControlPlane
    import drlink_v24 as v24

    plane = ControlPlane(str(root))
    try:
        v24.set_network_object(plane, "proxy-src", type="ip", value="127.0.0.1", oneshot=True)
        v24.set_network_object(plane, "allowed-host", type="fqdn", value="allowed.test", oneshot=True)
        v24.set_service_object(plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            plane,
            "internet",
            "allow-https",
            mode="whitelist",
            source="proxy-src",
            destination="allowed-host",
            service="https",
            enabled=True,
            oneshot=True,
        )
        plane.compile_runtime()
    finally:
        plane.close()


class _Origin(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(64)
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()

    def run(self):
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        conn.settimeout(2.0)
        try:
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass


def _fd_count() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return 0


def _free_slots(sem, limit: int) -> int:
    held = 0
    for _ in range(limit):
        if not sem.acquire(blocking=False):
            break
        held += 1
    for _ in range(held):
        sem.release()
    return held


class InternetAccessConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        cfg_path = self.root / "etc/drlink/config.json"
        cfg_path.parent.mkdir(parents=True)
        (self.root / "var/log/drlink/egress").mkdir(parents=True)
        (self.root / "var/lib/drlink").mkdir(parents=True)
        cfg = {
            "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
            "egress_listen_addr": "127.0.0.1",
            "egress_listen_port": 0,
        }
        cfg_path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
        _seed_internet_allow(self.root)
        self.origin = _Origin()
        self.origin.start()
        gw_path = ROOT / "server" / "frp-egress-gateway.py"
        spec = importlib.util.spec_from_file_location("frp_egress_gateway_conc", gw_path)
        self.GW = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.GW)
        origin_port = self.origin.port

        def resolve(hostname: str):
            if hostname in ("allowed.test", "denied.test"):
                return ["1.2.3.4"]
            raise OSError("nxdomain")

        def connect(ip, port, hostname, timeout):
            return socket.create_connection(("127.0.0.1", origin_port), timeout=timeout)

        cache = self.GW.PolicyCache(cfg_path)
        self.state = self.GW.GatewayState(
            cache,
            resolve_fn=resolve,
            connect_fn=connect,
            max_concurrent=64,
            per_source_limit=256,
        )
        self.server = self.GW.ThreadedTCPServer(("127.0.0.1", 0), self.state)
        self.proxy_port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.hello = build_client_hello("allowed.test")

    def tearDown(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass
        try:
            self.origin.stop()
        except Exception:
            pass
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _connect(self, host: str, timeout: float = 5.0) -> bytes:
        payload = (
            "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)
        ).encode()
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if buf.startswith(b"HTTP/1.1 200"):
                sock.sendall(self.hello)
            return buf

    def test_concurrent_connect_isolated_and_resources_released(self):
        workers = 20
        total = 100
        hosts = ["allowed.test" if i % 5 else "denied.test" for i in range(total)]
        stderr = io.StringIO()
        threads_before = threading.active_count()
        fds_before = _fd_count()
        started = time.monotonic()
        with redirect_stderr(stderr):
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(self._connect, hosts))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 30.0, "concurrent CONNECT burst did not finish")
        log = stderr.getvalue()
        self.assertNotIn("InterfaceError", log)
        self.assertNotIn("bad parameter", log.lower())
        allow = [buf for host, buf in zip(hosts, results) if host == "allowed.test"]
        deny = [buf for host, buf in zip(hosts, results) if host == "denied.test"]
        self.assertEqual(len(allow), 80)
        self.assertEqual(len(deny), 20)
        for buf in allow:
            self.assertTrue(buf.startswith(b"HTTP/1.1 200"), buf[:120])
            self.assertNotIn(b"bad request", buf.lower())
        for buf in deny:
            self.assertTrue(buf.startswith(b"HTTP/1.1 403"), buf[:120])
            self.assertNotIn(b"bad request", buf.lower())

        seq_started = time.monotonic()
        sequential = self._connect("allowed.test", timeout=2.0)
        seq_elapsed = time.monotonic() - seq_started
        self.assertTrue(sequential.startswith(b"HTTP/1.1 200"), sequential[:120])
        self.assertLess(seq_elapsed, 2.0, "sequential CONNECT did not recover after the burst")

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if self.state._active == 0 and not self.state._per_source:
                break
            time.sleep(0.02)
        self.assertEqual(self.state._active, 0)
        self.assertEqual(self.state._per_source, {})
        self.assertEqual(_free_slots(self.server._slot_sem, self.server.max_concurrent), self.server.max_concurrent)
        outbound = self.GW._OUTBOUND_CONNECT_SEM
        self.assertEqual(
            _free_slots(outbound, self.GW.OUTBOUND_CONNECT_ATTEMPTS),
            self.GW.OUTBOUND_CONNECT_ATTEMPTS,
        )
        self.assertLessEqual(threading.active_count(), threads_before + 4)
        if fds_before:
            self.assertLessEqual(_fd_count(), fds_before + 16)

    def test_internal_authorize_fault_is_not_http_400(self):
        def boom(**_kwargs):
            raise RuntimeError("control DB wedged")

        self.state.cache.authorize = boom
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            buf = self._connect("allowed.test", timeout=3.0)
        self.assertTrue(buf.startswith(b"HTTP/1.1 403"), buf[:160])
        self.assertIn(b"authorization unavailable", buf)
        self.assertNotIn(b"bad request", buf.lower())
        text = stderr.getvalue()
        self.assertIn("internal failure", text)
        self.assertIn("control DB wedged", text)


if __name__ == "__main__":
    unittest.main()
