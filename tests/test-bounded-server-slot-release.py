#!/usr/bin/env python3
"""A concurrency slot must survive a failed worker-thread start.

The bounded servers acquire a slot in process_request and release it in the
worker's finally block. When Thread.start() fails (thread limit reached, memory
pressure) the worker never runs, so that release never happens and the slot is
gone for the process lifetime: repeated failures starve the server down to zero
capacity and it rejects every later connection even when completely idle.
"""
from __future__ import annotations

import importlib.util
import socket
import sys
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


BOUNDED = _load("frp_bounded_server", ROOT / "lib" / "frp_bounded_server.py")
GW = _load("frp_egress_gateway", ROOT / "server" / "frp-egress-gateway.py")

MAX_CONCURRENT = 3


def _process(server, request, client_address) -> None:
    """Feed one request in, absorbing what socketserver's accept loop absorbs.

    socketserver calls handle_error() and drops the request when
    process_request raises, so a propagating start failure keeps the listener
    alive — and keeps the leak silent.
    """
    try:
        server.process_request(request, client_address)
    except RuntimeError:
        try:
            request.close()
        except OSError:
            pass


class _FailingThreads:
    """Stand-in for a module's ``threading`` global whose Thread cannot start."""

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


class _Server(BOUNDED.BoundedThreadingMixIn):
    """Minimal BoundedThreadingMixIn host: no listening socket needed."""

    max_concurrent = MAX_CONCURRENT
    request_timeout = 5.0

    def __init__(self):
        self.served: list = []
        self.rejected: list = []
        self.release = threading.Event()
        self.lock = threading.Lock()
        super().__init__()

    def reject_callback(self, request, client_address):
        with self.lock:
            self.rejected.append(client_address)

    def finish_request(self, request, client_address):
        with self.lock:
            self.served.append(client_address)
        self.release.wait(10.0)

    def shutdown_request(self, request):
        try:
            request.close()
        except OSError:
            pass

    def handle_error(self, request, client_address):
        pass


class BoundedServerSlotRelease(unittest.TestCase):
    def setUp(self):
        self.pairs: list = []

    def tearDown(self):
        for left, right in self.pairs:
            for sock in (left, right):
                try:
                    sock.close()
                except OSError:
                    pass

    def _request(self):
        left, right = socket.socketpair()
        self.pairs.append((left, right))
        return left

    def _wait(self, predicate, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def test_capacity_restored_after_failed_thread_start(self):
        server = _Server()
        failing = _FailingThreads()
        orig = BOUNDED.threading
        BOUNDED.threading = failing
        try:
            # Exhaust every slot on requests whose worker can never start.
            for i in range(MAX_CONCURRENT):
                _process(server, self._request(), ("127.0.0.1", 1000 + i))
            self.assertEqual(failing.attempts, MAX_CONCURRENT)
        finally:
            BOUNDED.threading = orig
        self.assertEqual(server.served, [], "no worker body may run")
        self.assertEqual(
            server.rejected, [], "these requests were admitted, not rejected"
        )

        # Threads work again: the server must still be at full capacity.
        for i in range(MAX_CONCURRENT):
            server.process_request(self._request(), ("127.0.0.1", 2000 + i))
        try:
            self.assertTrue(
                self._wait(lambda: len(server.served) >= MAX_CONCURRENT),
                "capacity leaked on failed Thread.start: only %d of %d slots "
                "usable after %d failures"
                % (len(server.served), MAX_CONCURRENT, MAX_CONCURRENT),
            )
            # Still bounded: the next one over the limit is rejected, not queued.
            server.process_request(self._request(), ("127.0.0.1", 3000))
            self.assertEqual(len(server.rejected), 1)
        finally:
            server.release.set()

    def test_failed_start_closes_the_socket(self):
        server = _Server()
        failing = _FailingThreads()
        orig = BOUNDED.threading
        BOUNDED.threading = failing
        try:
            request = self._request()
            try:
                # Deliberately no cleanup here: process_request owns the socket.
                server.process_request(request, ("127.0.0.1", 4000))
            except RuntimeError:
                pass
        finally:
            BOUNDED.threading = orig
        with self.assertRaises(OSError):
            request.send(b"x")

    def test_slots_are_reusable_after_normal_completion(self):
        server = _Server()
        for i in range(MAX_CONCURRENT):
            server.process_request(self._request(), ("127.0.0.1", 5000 + i))
        self.assertTrue(self._wait(lambda: len(server.served) >= MAX_CONCURRENT))
        server.release.set()
        self.assertTrue(self._wait(lambda: True))
        for i in range(MAX_CONCURRENT):
            self.assertTrue(
                self._wait(lambda: server._slot_sem.acquire(blocking=False)),
                "slot %d never came back" % i,
            )


class _StubCache:
    cfg: dict = {}

    def snapshot(self):
        return None, "not loaded", {}, None


class GatewaySlotRelease(unittest.TestCase):
    """The Controlled Egress HTTP gateway carries the same accept-time gate."""

    def setUp(self):
        gw = type("_Gw", (), {})()
        gw.max_concurrent = MAX_CONCURRENT
        gw.cache = _StubCache()
        self.server = GW.ThreadedTCPServer(("127.0.0.1", 0), gw)
        self.pairs: list = []

    def tearDown(self):
        try:
            self.server.server_close()
        except Exception:
            pass
        for left, right in self.pairs:
            for sock in (left, right):
                try:
                    sock.close()
                except OSError:
                    pass

    def _request(self):
        left, right = socket.socketpair()
        self.pairs.append((left, right))
        return left

    def test_capacity_restored_after_failed_thread_start(self):
        failing = _FailingThreads()
        orig = GW.threading
        GW.threading = failing
        try:
            for i in range(MAX_CONCURRENT):
                _process(self.server, self._request(), ("127.0.0.1", 6000 + i))
            self.assertEqual(failing.attempts, MAX_CONCURRENT)
        finally:
            GW.threading = orig
        for i in range(MAX_CONCURRENT):
            self.assertTrue(
                self.server._slot_sem.acquire(blocking=False),
                "capacity leaked on failed Thread.start: slot %d never came back" % i,
            )


if __name__ == "__main__":
    unittest.main()
