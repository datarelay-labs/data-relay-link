#!/usr/bin/env python3
"""Regression: egress conn log must work when /var/log/drlink is traverse-only.

Production install makes the log directory 0710 / --x for drlink-egress and
grants write only on the pre-created egress-conn.jsonl inode. Sidecar
``*.lock`` creation previously failed with EACCES and silently dropped logs.
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


class ConnLogTraverseOnly(unittest.TestCase):
    def test_egress_emit_with_traverse_only_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "var/log/drlink"
            log_dir.mkdir(parents=True)
            log_path = log_dir / "egress-conn.jsonl"
            log_path.write_text("", encoding="utf-8")
            os.chmod(log_path, 0o600)
            # Simulate production: directory not writable (no create sidecar lock).
            os.chmod(log_dir, 0o711)  # traverse+execute for owner; no write
            # Drop write for owner too when possible (best effort on this FS).
            try:
                os.chmod(log_dir, stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                pass
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
            # Sidecar lock must not be required / created.
            self.assertFalse((log_dir / "egress-conn.jsonl.lock").exists())

    def test_access_emit_with_traverse_only_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "var/log/drlink"
            log_dir.mkdir(parents=True)
            log_path = log_dir / "access-conn.jsonl"
            log_path.write_text("", encoding="utf-8")
            os.chmod(log_path, 0o600)
            try:
                os.chmod(log_dir, stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                pass
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
            self.assertFalse((log_dir / "access-conn.jsonl.lock").exists())


if __name__ == "__main__":
    unittest.main()
