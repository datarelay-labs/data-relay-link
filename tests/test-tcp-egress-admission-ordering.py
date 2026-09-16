#!/usr/bin/env python3
"""Fixed TCP Egress admission must precede worker-thread creation.

ThreadingMixIn spawns a thread in process_request and only then runs the
handler, so a resource reservation taken inside the handler bounds concurrent
*sessions* while thread creation stays unbounded: N unadmitted connections
still cost N threads. These regressions flood a relay listener past capacity
and require that no worker runs for a connection that was never admitted.

The per-connection handler runs exactly once per worker thread, so counting
handler entries counts worker threads regardless of who spawns them.
"""
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


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


EG = _load("frp_egress_control", ROOT / "lib" / "frp_egress_control.py")
RT = _load("frp_egress_runtime", ROOT / "lib" / "frp_egress_runtime.py")
TCP = _load("drlink_tcp_egress", ROOT / "server" / "drlink-tcp-egress.py")

CONN_LOG = "/var/log/drlink/egress/connections.jsonl"


class _FailingThreads:
    """Stand-in for the module's ``threading`` global whose Thread cannot start."""

    def __init__(self):
        self.attempts = 0

    def Thread(self, *args, **kwargs):
        outer = self

        class _Thread:
            daemon = True

            def start(self):
                outer.attempts += 1
                raise RuntimeError("can't start new thread")

        return _Thread()

    def __getattr__(self, name):
        return getattr(threading, name)


class TcpEgressAdmissionOrdering(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-admission-")
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        # Resolve the audit log through the env hook so both the accept loop and
        # any handler-side deny land in the same temp file.
        os.environ["FRP_EGRESS_CONN_LOG"] = CONN_LOG
        self.log_path = self.root / CONN_LOG.lstrip("/")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        control = self.root / "var/lib/drlink/egress-control.json"
        control.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=control)
        self.cfg_path = self.root / "etc/drlink/config.json"
        self.cfg_path.parent.mkdir(parents=True, exist_ok=True)
        self.cfg_path.write_text(
            json.dumps({"egress_control_file": "/var/lib/drlink/egress-control.json"})
            + "\n",
            encoding="utf-8",
        )
        self.cache = RT.PolicyCache(self.cfg_path)
        self.servers: list = []
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.entered: list = []
        self.admitted: list = []
        self.in_flight = 0
        self.peak_in_flight = 0
        self._orig_handler = TCP.handle_tcp_client
        self._orig_threading = TCP.threading

    def tearDown(self):
        self.release.set()
        TCP.handle_tcp_client = self._orig_handler
        TCP.threading = self._orig_threading
        for server in self.servers:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
        os.environ.pop("FRP_EGRESS_CONN_LOG", None)

    def _install_blocking_handler(self):
        """Replace the relay body with one that holds its slots until released.

        Mirrors the real release contract: reservations made by the caller are
        released here, and a handler reached without a reservation takes its own
        and audits the denial (which is what the pre-fix ordering relied on), so
        the RESOURCE_LIMIT count is comparable either way.
        """

        def handler(state, request, client_address, relay_id, admitted=False):
            source_ip = str(client_address[0])
            acquired = bool(admitted)
            source_acquired = bool(admitted)
            with self.lock:
                self.entered.append(source_ip)
            try:
                if not admitted:
                    if not state.try_acquire():
                        self._audit_reject(source_ip, relay_id)
                        return
                    acquired = True
                    if not state.try_acquire_source(source_ip):
                        self._audit_reject(source_ip, relay_id)
                        return
                    source_acquired = True
                with self.lock:
                    self.admitted.append(source_ip)
                    self.in_flight += 1
                    self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
                self.release.wait(10.0)
            finally:
                with self.lock:
                    if acquired or source_acquired:
                        self.in_flight -= 1
                try:
                    request.close()
                except OSError:
                    pass
                if source_acquired:
                    state.release_source(source_ip)
                if acquired:
                    state.release()

        TCP.handle_tcp_client = handler

    def _audit_reject(self, source_ip: str, relay_id: str) -> None:
        EG.emit_conn_log(
            {
                "source_ip": source_ip,
                "protocol": EG.PROTOCOL_TCP,
                "relay_id": relay_id,
                "decision": EG.DECISION_DENY,
                "reason": EG.REASON_RESOURCE_LIMIT,
                "outcome": EG.AUDIT_RESOURCE_LIMIT,
            }
        )

    def _serve(self, state) -> int:
        server = TCP.RelayServer(("127.0.0.1", 0), state, "egr_" + ("a" * 12))
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return int(server.server_address[1])

    def _rejections(self) -> int:
        if not self.log_path.is_file():
            return 0
        count = 0
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("reason") == EG.REASON_RESOURCE_LIMIT:
                count += 1
        return count

    def _wait(self, predicate, timeout: float = 15.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def _flood(self, port: int, count: int) -> list:
        socks = []
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", port))
            socks.append(sock)
        return socks

    def test_global_limit_bounds_worker_threads(self):
        limit = 4
        total = 24
        state = TCP.TcpEgressState(
            self.cache, max_concurrent=limit, per_source_limit=total
        )
        self._install_blocking_handler()
        port = self._serve(state)
        socks = self._flood(port, total)
        try:
            self.assertTrue(
                self._wait(lambda: self._rejections() >= total - limit),
                "every connection past capacity must be denied RESOURCE_LIMIT "
                "(saw %d of %d)" % (self._rejections(), total - limit),
            )
            time.sleep(0.2)  # settle: catch workers started just after the flood
            with self.lock:
                entered = len(self.entered)
                admitted = len(self.admitted)
                peak = self.peak_in_flight
            self.assertLessEqual(
                entered,
                limit,
                "a worker ran for a connection that was never admitted: %d "
                "workers for %d slots (admission must precede Thread.start)"
                % (entered, limit),
            )
            self.assertEqual(admitted, limit)
            self.assertEqual(peak, limit)
        finally:
            self.release.set()
            for sock in socks:
                try:
                    sock.close()
                except OSError:
                    pass

    def test_per_source_limit_bounds_worker_threads(self):
        limit = 3
        total = 18
        state = TCP.TcpEgressState(
            self.cache, max_concurrent=total * 4, per_source_limit=limit
        )
        self._install_blocking_handler()
        port = self._serve(state)
        socks = self._flood(port, total)
        try:
            self.assertTrue(
                self._wait(lambda: self._rejections() >= total - limit),
                "per-source overflow must be denied RESOURCE_LIMIT (saw %d of %d)"
                % (self._rejections(), total - limit),
            )
            time.sleep(0.2)
            with self.lock:
                entered = len(self.entered)
            self.assertLessEqual(
                entered,
                limit,
                "per-source reservation must also precede Thread.start: %d "
                "workers for %d slots" % (entered, limit),
            )
        finally:
            self.release.set()
            for sock in socks:
                try:
                    sock.close()
                except OSError:
                    pass

    def test_failed_thread_start_restores_capacity(self):
        limit = 2
        state = TCP.TcpEgressState(self.cache, max_concurrent=limit, per_source_limit=limit)
        self._install_blocking_handler()
        port = self._serve(state)
        failing = _FailingThreads()
        TCP.threading = failing
        try:
            socks = self._flood(port, limit)
            self.assertTrue(
                self._wait(lambda: failing.attempts >= limit, timeout=5.0),
                "accept loop must create the worker thread itself, after admission",
            )
            time.sleep(0.2)
            for sock in socks:
                try:
                    sock.close()
                except OSError:
                    pass
        finally:
            TCP.threading = self._orig_threading
        with self.lock:
            self.assertEqual(self.entered, [], "no worker body may run")
        # Every slot the failed workers reserved must be back.
        for _ in range(limit):
            self.assertTrue(state.try_acquire(), "global capacity leaked")
            self.assertTrue(state.try_acquire_source("127.0.0.1"), "source capacity leaked")


if __name__ == "__main__":
    unittest.main()
