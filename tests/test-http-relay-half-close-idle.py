#!/usr/bin/env python3
"""F01: HTTP relay must idle-timeout after client EOF without busy-spinning."""
from __future__ import annotations

import importlib.util
import select
import socket
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_gw():
    path = ROOT / "server" / "frp-egress-gateway.py"
    spec = importlib.util.spec_from_file_location("frp_egress_gateway_f01", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class HalfCloseIdleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.GW = load_gw()

    def _pair(self):
        a, b = socket.socketpair()
        return a, b

    def test_half_close_silent_upstream_idle_timeout_bounded(self):
        """Client SHUT_WR + silent upstream → idle timeout, no busy select loop."""
        gw = self.GW
        client_c, client_s = self._pair()
        up_c, up_s = self._pair()
        # Upstream stays open and silent; client half-closes after "request done".
        client_c.shutdown(socket.SHUT_WR)
        up_c.setblocking(False)

        select_calls = {"n": 0}
        real_select = select.select

        def counting_select(rlist, wlist, xlist, timeout=None):
            select_calls["n"] += 1
            return real_select(rlist, wlist, xlist, timeout)

        idle = 0.35
        started = time.monotonic()
        with mock.patch.object(gw, "IDLE_TIMEOUT", idle), mock.patch(
            "select.select", side_effect=counting_select
        ):
            gw._relay_upstream_response(client_s, up_s)
        elapsed = time.monotonic() - started

        self.assertGreaterEqual(elapsed, idle * 0.8)
        self.assertLess(elapsed, idle + 3.0)
        # ~1 select/sec with 1.0 timeout → dozens, not hundreds of thousands.
        self.assertLess(select_calls["n"], 20, msg="busy-spin detected: %d selects" % select_calls["n"])
        client_c.close()
        up_c.close()

    def test_half_close_delayed_upstream_response_delivered(self):
        """Client write EOF must not kill reception of a delayed upstream response."""
        gw = self.GW
        client_c, client_s = self._pair()
        up_c, up_s = self._pair()
        client_c.shutdown(socket.SHUT_WR)

        body = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

        def delayed_send():
            time.sleep(0.25)
            try:
                up_c.sendall(body)
                up_c.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        threading.Thread(target=delayed_send, daemon=True).start()
        with mock.patch.object(gw, "IDLE_TIMEOUT", 5.0):
            t = threading.Thread(
                target=gw._relay_upstream_response, args=(client_s, up_s), daemon=True
            )
            t.start()
            client_c.settimeout(5.0)
            data = b""
            while True:
                try:
                    chunk = client_c.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            t.join(timeout=5.0)
        self.assertIn(b"hello", data)
        self.assertTrue(data.startswith(b"HTTP/1.1 200"))
        client_c.close()
        up_c.close()

    def test_full_disconnect_reclaims(self):
        gw = self.GW
        client_c, client_s = self._pair()
        up_c, up_s = self._pair()
        client_c.close()
        up_c.close()
        with mock.patch.object(gw, "IDLE_TIMEOUT", 1.0):
            started = time.monotonic()
            gw._relay_upstream_response(client_s, up_s)
            self.assertLess(time.monotonic() - started, 2.0)


if __name__ == "__main__":
    unittest.main()
