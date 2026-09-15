#!/usr/bin/env python3
"""Concurrent writers must not lose connection records to log rotation.

Rotating outside the append lock races: a writer can resolve the active log,
have it renamed away underneath, and then fail or write into an inode that is
about to be replaced or truncated. Two writers can also rotate the same log
back to back. Either way audit records silently disappear, so rotation and
append have to share one exclusive lock on the inode the log currently names.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

WRITERS = 12
PER_WRITER = 40
# Small enough to rotate many times over the run, with enough generations kept
# that nothing is legitimately evicted.
MAX_BYTES = 2000
KEEP = 400


def _load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EG = _load("frp_egress_control_rot_conc", "lib/frp_egress_control.py")


class ConnLogRotationConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-rot-conc-")
        self.root = Path(self.tmp.name)
        self.parent = self.root / "var/log/drlink"
        self.egress_dir = self.parent / "egress"
        self.egress_dir.mkdir(parents=True)
        self.log_path = self.egress_dir / "connections.jsonl"
        os.chmod(self.parent, 0o711)
        os.chmod(self.egress_dir, 0o700)
        self._orig_max = EG.CONN_LOG_MAX_BYTES
        self._orig_keep = EG.CONN_LOG_KEEP
        EG.CONN_LOG_MAX_BYTES = MAX_BYTES
        EG.CONN_LOG_KEEP = KEEP

    def tearDown(self):
        EG.CONN_LOG_MAX_BYTES = self._orig_max
        EG.CONN_LOG_KEEP = self._orig_keep
        self.tmp.cleanup()

    def _emit(self, connection_id: str) -> None:
        EG.emit_conn_log(
            {
                "connection_id": connection_id,
                "source_ip": "203.0.113.9",
                "hostname": "rot.test",
                "port": 443,
                "protocol": "https",
                "decision": "ALLOW",
                "reason": "concurrency",
                "outcome": "ok",
                "policy_generation": 1,
                "method": "x" * 60,
            },
            path=self.log_path,
        )

    def _generations(self) -> list:
        files = [self.log_path]
        idx = 1
        while True:
            rotated = Path("%s.%d" % (self.log_path, idx))
            if not rotated.is_file():
                break
            files.append(rotated)
            idx += 1
        return files

    def _recorded_ids(self) -> list:
        ids = []
        for path in self._generations():
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                # A torn line means an append landed on a rotated inode.
                record = json.loads(line)
                cid = record.get("connection_id")
                if cid is not None:
                    ids.append(cid)
        return ids

    def test_no_records_lost_across_concurrent_rotation(self):
        expected = {
            "w%02d-%03d" % (writer, seq)
            for writer in range(WRITERS)
            for seq in range(PER_WRITER)
        }
        start = threading.Barrier(WRITERS)

        def run(writer: int) -> None:
            start.wait(30.0)
            for seq in range(PER_WRITER):
                self._emit("w%02d-%03d" % (writer, seq))

        threads = [
            threading.Thread(target=run, args=(writer,), daemon=True)
            for writer in range(WRITERS)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120.0)
            self.assertFalse(thread.is_alive(), "writer deadlocked on the log lock")

        rotations = len(self._generations()) - 1
        self.assertGreater(
            rotations, 2, "test did not exercise rotation (only %d)" % rotations
        )
        self.assertLessEqual(rotations, KEEP, "no generation may be evicted here")

        ids = self._recorded_ids()
        missing = expected - set(ids)
        self.assertEqual(
            missing,
            set(),
            "rotation raced with append and dropped %d of %d records (e.g. %s)"
            % (len(missing), len(expected), sorted(missing)[:5]),
        )
        duplicates = len(ids) - len(set(ids))
        self.assertEqual(duplicates, 0, "records duplicated across generations")

    def test_active_log_stays_locked_mode_and_bounded(self):
        for seq in range(60):
            self._emit("seq-%03d" % seq)
        self.assertTrue(self.log_path.is_file())
        self.assertEqual(self.log_path.stat().st_mode & 0o777, 0o600)
        for path in self._generations():
            self.assertEqual(
                path.stat().st_mode & 0o777, 0o600, "%s must stay 0600" % path.name
            )


if __name__ == "__main__":
    unittest.main()
