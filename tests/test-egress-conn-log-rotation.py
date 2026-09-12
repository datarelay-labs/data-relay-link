#!/usr/bin/env python3
"""Egress connection-log rotation: append, threshold rotate, recreate, continue.

Proves rotation works when the service-specific ``egress/`` directory is
writable (rename/unlink/create), not merely append to a pre-existing inode.
"""
from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EG = _load("frp_egress_control_rot", "lib/frp_egress_control.py")


class EgressConnLogRotation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-egress-rot-")
        self.root = Path(self.tmp.name)
        self.parent = self.root / "var/log/drlink"
        self.egress_dir = self.parent / "egress"
        self.egress_dir.mkdir(parents=True)
        self.log_path = self.egress_dir / "connections.jsonl"
        # Shared parent traverse-oriented; service dir writable for rotation.
        os.chmod(self.parent, 0o711)
        os.chmod(self.egress_dir, 0o700)
        self._orig_max = EG.CONN_LOG_MAX_BYTES
        self._orig_keep = EG.CONN_LOG_KEEP
        EG.CONN_LOG_MAX_BYTES = 200
        EG.CONN_LOG_KEEP = 3

    def tearDown(self):
        EG.CONN_LOG_MAX_BYTES = self._orig_max
        EG.CONN_LOG_KEEP = self._orig_keep
        self.tmp.cleanup()

    def _emit(self, marker: str, pad: int = 80) -> None:
        EG.emit_conn_log(
            {
                "connection_id": marker,
                "source_ip": "203.0.113.9",
                "hostname": "rot.test",
                "port": 443,
                "protocol": "https",
                "decision": "ALLOW",
                "reason": marker,
                "outcome": "ok",
                "policy_generation": 1,
                "method": "x" * pad,
            },
            path=self.log_path,
        )

    def test_append_rotate_recreate_continue(self):
        # Start with no file — create via append (dir must be writable).
        self.assertFalse(self.log_path.exists())
        self._emit("first", pad=20)
        self.assertTrue(self.log_path.is_file())
        mode_before = stat.S_IMODE(self.log_path.stat().st_mode)
        self.assertEqual(mode_before, 0o600)

        # Seed an over-threshold file, then emit once to force rename+recreate.
        # Directory write is required for os.replace → connections.jsonl.1.
        seed = "SEED-BEFORE-ROTATE\n" + ("z" * (EG.CONN_LOG_MAX_BYTES + 50))
        self.log_path.write_text(seed, encoding="utf-8")
        os.chmod(self.log_path, 0o600)
        self._emit("post-rotate", pad=10)

        rotated = Path(str(self.log_path) + ".1")
        self.assertTrue(rotated.is_file(), "threshold rotation must rename into .1")
        self.assertIn("SEED-BEFORE-ROTATE", rotated.read_text(encoding="utf-8"))
        # Active log was recreated empty then appended — not left as the seed blob.
        active = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn("SEED-BEFORE-ROTATE", active)
        self.assertIn("post-rotate", active)
        self.assertLess(
            self.log_path.stat().st_size,
            len(seed),
            "active log must be recreated, not left as the over-threshold seed",
        )
        self.assertEqual(stat.S_IMODE(self.log_path.stat().st_mode), 0o600)

        # Continued append after rotation.
        before = self.log_path.stat().st_size
        self._emit("after-rotate", pad=10)
        self.assertGreater(self.log_path.stat().st_size, before)
        self.assertIn("after-rotate", self.log_path.read_text(encoding="utf-8"))

    def test_rotation_keeps_bound(self):
        for i in range(40):
            self._emit("k-%d" % i, pad=50)
        self.assertTrue(self.log_path.is_file())
        self.assertTrue(Path(str(self.log_path) + ".1").is_file())
        self.assertFalse(Path(str(self.log_path) + ".4").exists())


if __name__ == "__main__":
    unittest.main()
