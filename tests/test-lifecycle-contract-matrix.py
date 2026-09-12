#!/usr/bin/env python3
"""Lifecycle semantic matrix (AUDIT-005) against registry tools."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _seed(root: Path) -> Path:
    etc = root / "etc/drlink"
    etc.mkdir(parents=True, exist_ok=True)
    var = root / "var/lib/drlink"
    var.mkdir(parents=True, exist_ok=True)
    reg = var / "registry.json"
    client = {
        "label": "edge",
        "hostname": "edge-host",
        "mgmt_status": "enrolled",
        "mgmt_pubkey": "pub",
        "mgmt_fingerprint": "abcd" * 8,
        "mgmt_mac_key": "mac",
        "services": {
            "ssh": {
                "remote_port": 60001,
                "enabled": True,
                "local_ip": "127.0.0.1",
                "local_port": 22,
            },
            "http": {
                "remote_port": 60002,
                "enabled": True,
                "local_ip": "127.0.0.1",
                "local_port": 80,
            },
        },
    }
    reg.write_text(
        json.dumps({"schema_version": 2, "clients": {"cccccccccccccccc": client}}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (etc / "config.json").write_text(
        json.dumps({"registry_file": "/var/lib/drlink/registry.json"}) + "\n",
        encoding="utf-8",
    )
    lib = root / "usr/local/lib/drlink"
    lib.mkdir(parents=True, exist_ok=True)
    for name in (
        "frp_client_registry.py",
        "frp_control_locks.py",
        "frp_access_control.py",
        "frp_audit.py",
    ):
        shutil.copy2(ROOT / "lib" / name, lib / name)
    return reg


class LifecycleContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.reg = _seed(self.root)
        self.env = os.environ.copy()
        self.env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.env["PYTHONUNBUFFERED"] = "1"

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _state(self):
        return json.loads(self.reg.read_text(encoding="utf-8"))

    def test_release_service_keeps_identity(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-u",
                str(ROOT / "tools/frp-release-service"),
                "cccccccccccccccc",
                "http",
                "--force",
            ],
            input="RELEASE\n",
            text=True,
            capture_output=True,
            env=self.env,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        client = self._state()["clients"]["cccccccccccccccc"]
        self.assertNotIn("http", client["services"])
        self.assertIn("ssh", client["services"])
        self.assertEqual(client["mgmt_status"], "enrolled")

    def test_revoke_keeps_reservations(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-u",
                str(ROOT / "tools/frp-revoke-client"),
                "cccccccccccccccc",
            ],
            input="REVOKE\n",
            text=True,
            capture_output=True,
            env=self.env,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        client = self._state()["clients"]["cccccccccccccccc"]
        self.assertEqual(client["mgmt_status"], "revoked")
        self.assertIn("ssh", client["services"])
        self.assertIn("http", client["services"])

    def test_release_client_removes_record(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-u",
                str(ROOT / "tools/frp-release-client"),
                "cccccccccccccccc",
                "--force",
            ],
            input="RELEASE\n",
            text=True,
            capture_output=True,
            env=self.env,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        self.assertIn("WHAT WILL BE REMOVED", proc.stdout)
        self.assertIn("management identity", proc.stdout)
        self.assertNotIn("cccccccccccccccc", self._state()["clients"])


if __name__ == "__main__":
    unittest.main()
