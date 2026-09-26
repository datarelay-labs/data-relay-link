#!/usr/bin/env python3
"""Bounded Zero-Touch issuance and redemption tests (server-enforced)."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_allocator():
    path = ROOT / "server" / "frp-port-allocator.py"
    spec = importlib.util.spec_from_file_location("frp_port_allocator", path)
    mod = importlib.util.module_from_spec(spec)
    # Minimal stubs for optional imports used at module load.
    sys.path.insert(0, str(ROOT / "lib"))
    spec.loader.exec_module(mod)
    return mod


class BoundedZeroTouchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="drlink-zt-bound-"))
        self.enroll = self.tmp / "enrollments"
        self.boot = self.tmp / "bootstrap"
        self.enroll.mkdir()
        self.boot.mkdir()
        (self.tmp / "registry.json").write_text(
            json.dumps({"schema_version": 2, "reserved": [], "clients": {}}, indent=2) + "\n"
        )
        self.cfg = {
            "enrollments_dir": str(self.enroll),
            "bootstrap_dir": str(self.boot),
            "registry_file": str(self.tmp / "registry.json"),
            "enrollment_retention_days": 30,
        }
        self.alloc = load_allocator()

    def _issue(self, n=1, ttl=3600, label_prefix="n"):
        rows = [{"services": [], "note": "", "label": "%s%s" % (label_prefix, i)} for i in range(n)]
        if n == 1:
            return [
                self.alloc.issue_bootstrap_ticket(
                    self.enroll, self.boot, [], ttl, "", label=rows[0]["label"], cfg=self.cfg
                )
            ]
        _batch, issued = self.alloc.issue_bootstrap_ticket_batch(
            self.enroll, self.boot, rows, ttl, cfg=self.cfg
        )
        return issued

    def test_defaults_and_max_ttl(self):
        self.assertEqual(self.alloc.ZERO_TOUCH_DEFAULT_TTL_SEC, 3600)
        self.assertEqual(self.alloc.ZERO_TOUCH_MAX_TTL_SEC, 86400)
        self.assertEqual(self.alloc.normalize_zero_touch_ttl(None), 3600)
        with self.assertRaises(ValueError):
            self.alloc.normalize_zero_touch_ttl(0)
        with self.assertRaises(ValueError):
            self.alloc.normalize_zero_touch_ttl(86400 + 1)

    def test_issue_10_unique_and_ceiling(self):
        issued = self._issue(10)
        self.assertEqual(len(issued), 10)
        tickets = [t[0] for t in issued]
        self.assertEqual(len(set(tickets)), 10)
        ids = [t[2]["id"] for t in issued]
        self.assertEqual(len(set(ids)), 10)
        # raw secret not persisted
        for path in self.boot.glob("*.json"):
            data = json.loads(path.read_text())
            self.assertIn("secret_hash", data)
            text = path.read_text()
            self.assertNotIn(tickets[0].split(".")[-1], text)
            self.assertNotIn("bt1.", text)
        active = self.alloc.count_active_unused_bootstrap_tickets(self.boot)
        self.assertEqual(active, 10)
        with self.assertRaises(self.alloc.ZeroTouchCapacityError) as ctx:
            self._issue(1, label_prefix="over")
        self.assertEqual(ctx.exception.max_issuable, 0)
        self.assertEqual(ctx.exception.requested, 1)

    def test_capacity_remainder_reject_all(self):
        self._issue(3, label_prefix="a")
        with self.assertRaises(self.alloc.ZeroTouchCapacityError) as ctx:
            self._issue(8, label_prefix="b")
        self.assertEqual(ctx.exception.max_issuable, 7)
        self.assertEqual(self.alloc.count_active_unused_bootstrap_tickets(self.boot), 3)

    def test_expired_and_revoked_release_capacity(self):
        issued = self._issue(2, ttl=3600, label_prefix="e")
        # expire one by rewriting expires_at
        tid = issued[0][2]["id"]
        path = self.boot / (tid + ".json")
        rec = json.loads(path.read_text())
        rec["expires_at"] = int(time.time()) - 10
        path.write_text(json.dumps(rec))
        self.assertEqual(self.alloc.count_active_unused_bootstrap_tickets(self.boot), 1)
        # revoke other
        tid2 = issued[1][2]["id"]
        path2 = self.boot / (tid2 + ".json")
        rec2 = json.loads(path2.read_text())
        rec2["revoked_at"] = "2020-01-01T00:00:00Z"
        path2.write_text(json.dumps(rec2))
        self.assertEqual(self.alloc.count_active_unused_bootstrap_tickets(self.boot), 0)
        self._issue(10, label_prefix="r")
        self.assertEqual(self.alloc.count_active_unused_bootstrap_tickets(self.boot), 10)

    def test_batch_revoke(self):
        batch_id, issued = self.alloc.issue_bootstrap_ticket_batch(
            self.enroll,
            self.boot,
            [{"services": [], "note": "", "label": "b%s" % i} for i in range(3)],
            3600,
            cfg=self.cfg,
            batch_id="batchdeadbeef00",
        )
        self.assertEqual(batch_id, "batchdeadbeef00")
        revoked = self.alloc.revoke_bootstrap_tickets_by_batch(self.boot, batch_id)
        self.assertEqual(len(revoked), 3)
        self.assertEqual(self.alloc.count_active_unused_bootstrap_tickets(self.boot), 0)

    def test_concurrent_capacity_race(self):
        errors = []
        issued_counts = []

        def worker(prefix):
            try:
                rows = [
                    {"services": [], "note": "", "label": "%s%s" % (prefix, i)}
                    for i in range(6)
                ]
                _b, issued = self.alloc.issue_bootstrap_ticket_batch(
                    self.enroll, self.boot, rows, 3600, cfg=self.cfg
                )
                issued_counts.append(len(issued))
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=worker, args=("x",))
        t2 = threading.Thread(target=worker, args=("y",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        active = self.alloc.count_active_unused_bootstrap_tickets(self.boot)
        self.assertLessEqual(active, 10)
        self.assertTrue(errors or sum(issued_counts) <= 10)
        # At least one capacity error expected when both try for 6.
        if sum(issued_counts) > 10:
            self.fail("capacity race issued more than 10: %s" % issued_counts)

    def test_max_per_issue(self):
        with self.assertRaises(self.alloc.ZeroTouchCapacityError):
            self.alloc.assert_zero_touch_issuance_capacity(self.boot, 11)


if __name__ == "__main__":
    unittest.main()
