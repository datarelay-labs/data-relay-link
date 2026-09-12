#!/usr/bin/env python3
"""Regression: egress conn log with traverse-only parent + writable egress/.

Production: ``/var/log/drlink`` is traverse-only for drlink-egress; the
service subdirectory ``egress/`` is writable so append + rotation work.
Sidecar ``*.lock`` must not be required.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
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


EG = _load("frp_egress_control", "lib/frp_egress_control.py")
ACL = _load("frp_access_control", "lib/frp_access_control.py")


def _make_traverse_only(path: Path) -> None:
    os.chmod(path, 0o711)
    try:
        os.chmod(path, stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


class ConnLogTraverseOnly(unittest.TestCase):
    def test_egress_emit_with_traverse_only_parent_writable_subdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "var/log/drlink"
            egress_dir = log_dir / "egress"
            egress_dir.mkdir(parents=True)
            log_path = egress_dir / "connections.jsonl"
            log_path.write_text("", encoding="utf-8")
            os.chmod(log_path, 0o600)
            os.chmod(egress_dir, 0o700)
            _make_traverse_only(log_dir)
            before = log_path.stat().st_size
            EG.emit_conn_log(
                {
                    "connection_id": "c1",
                    "source_ip": "203.0.113.9",
                    "hostname": "allowed.test",
                    "port": 443,
                    "protocol": "https",
                    "decision": "ALLOW",
                    "reason": "test",
                    "outcome": "ok",
                    "policy_generation": 1,
                },
                path=log_path,
            )
            after = log_path.stat().st_size
            self.assertGreater(after, before, "conn log must grow without sidecar lock")
            lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec.get("hostname"), "allowed.test")
            self.assertFalse((egress_dir / "connections.jsonl.lock").exists())
            self.assertFalse((log_dir / "connections.jsonl.lock").exists())

    def test_access_emit_with_traverse_only_parent_writable_subdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "var/log/drlink"
            access_dir = log_dir / "access"
            access_dir.mkdir(parents=True)
            log_path = access_dir / "connections.jsonl"
            log_path.write_text("", encoding="utf-8")
            os.chmod(log_path, 0o600)
            os.chmod(access_dir, 0o700)
            _make_traverse_only(log_dir)
            ACL.emit_conn_log(
                {
                    "client_id": "abcd1234",
                    "service_id": "ssh",
                    "source_ip": "198.51.100.10",
                    "decision": "ALLOW",
                    "reason": "ALLOWLIST",
                },
                path=log_path,
            )
            self.assertGreater(log_path.stat().st_size, 0)
            self.assertFalse((access_dir / "connections.jsonl.lock").exists())


if __name__ == "__main__":
    unittest.main()
