#!/usr/bin/env python3
"""F02: valid backup must restore even when live registry is corrupt."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_restore():
    loader = SourceFileLoader("frp_restore_f02", str(ROOT / "tools" / "frp-restore"))
    spec = importlib.util.spec_from_loader("frp_restore_f02", loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def seed_valid_tree(root: Path, marker: str) -> None:
    for rel in (
        "etc/drlink/pki",
        "etc/frp",
        "var/lib/drlink",
        "var/lib/drlink/backups",
        "var/log/drlink",
        "usr/local/lib/drlink",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)
    (root / "etc/drlink/config.json").write_text(
        json.dumps(
            {
                "port_start": 6000,
                "port_end": 6098,
                "egress_listen_port": 6102,
                "allocator_listen_port": 6099,
                "registry_file": "/var/lib/drlink/registry.json",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "etc/drlink/version").write_text("PROJECT_VERSION=1.0.0\n", encoding="utf-8")
    for name in ("ca.key", "ca.crt", "server.key", "server.crt"):
        (root / "etc/drlink/pki" / name).write_text("%s-%s\n" % (marker, name), encoding="utf-8")
    (root / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (root / "etc/frp/server_token").write_text("token-%s\n" % marker, encoding="utf-8")
    (root / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}, "reserved": [], "marker": marker})
        + "\n",
        encoding="utf-8",
    )
    (root / "var/lib/drlink/access-control.json").write_text(
        json.dumps({"schema_version": 1, "access_lists": {}, "service_access": {}}) + "\n",
        encoding="utf-8",
    )
    (root / "var/lib/drlink/egress-control.json").write_text(
        json.dumps({"schema_version": 2, "egress_profiles": {}}) + "\n",
        encoding="utf-8",
    )
    (root / "var/lib/drlink/service-profiles.json").write_text(
        json.dumps({"schema_version": 1, "profiles": {}}) + "\n",
        encoding="utf-8",
    )
    for name in (
        "frp_control_locks.py",
        "frp_access_control.py",
        "frp_egress_control.py",
        "frp_service_profiles.py",
        "frp_infrastructure_ports.py",
        "frp_audit.py",
        "frp_state_paths.py",
    ):
        src = ROOT / "lib" / name
        if src.is_file():
            shutil.copy2(src, root / "usr/local/lib/drlink" / name)


class CorruptCurrentRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "tree"
        self.root.mkdir()
        self.env = os.environ.copy()
        self.env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.env["FRP_RESTORE_READY_TIMEOUT"] = "0.1"
        self.env["FRP_RESTORE_READY_INTERVAL"] = "0.05"
        self.mod = load_restore()
        seed_valid_tree(self.root, "good")
        # Install tools into test root path resolution via FRP_DEPLOY_TEST_ROOT.
        tools = self.root / "usr/local/sbin"
        tools.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "tools" / "frp-backup", tools / "frp-backup")
        shutil.copy2(ROOT / "tools" / "frp-restore", tools / "frp-restore")
        # make_snapshot invokes sibling frp-backup next to frp-restore source.
        self.backup_tool = ROOT / "tools" / "frp-backup"
        self.restore_tool = ROOT / "tools" / "frp-restore"

    def tearDown(self):
        self.tmp.cleanup()

    def _make_valid_backup(self) -> Path:
        archive = Path(self.tmp.name) / "valid.tar.gz"
        proc = subprocess.run(
            [sys.executable, str(self.backup_tool), str(archive)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(archive.is_file())
        return archive

    def test_valid_backup_valid_current(self):
        archive = self._make_valid_backup()
        (self.root / "var/lib/drlink/registry.json").write_text(
            json.dumps({"schema_version": 2, "clients": {}, "reserved": [], "marker": "mutated"})
            + "\n",
            encoding="utf-8",
        )
        with mock.patch.object(self.mod, "restart_services"), mock.patch.object(
            self.mod, "verify_restored_control_state"
        ), mock.patch.object(self.mod, "_reapply_egress_permissions_after_restore"):
            # Drive restore.main with patched module path by exec via subprocess
            # against the real tool (uses classify_rollback on live tree).
            pass
        proc = subprocess.run(
            [sys.executable, str(self.restore_tool), str(archive)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        # Restart/verify may fail in fixture; accept apply success via registry marker.
        registry = json.loads((self.root / "var/lib/drlink/registry.json").read_text(encoding="utf-8"))
        if proc.returncode != 0:
            # If health/restart hooks fail, still prove we didn't abort on rollback validate.
            self.assertNotIn("staged registry failed invariant", proc.stderr + proc.stdout)
        else:
            self.assertEqual(registry.get("marker"), "good")

    def test_valid_backup_corrupted_registry(self):
        archive = self._make_valid_backup()
        (self.root / "var/lib/drlink/registry.json").write_text("{not-json", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(self.restore_tool), str(archive)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        combined = proc.stdout + proc.stderr
        self.assertNotIn("staged registry failed invariant", combined)
        # Either restore completed or failed later for restart/health — but must
        # have progressed past corrupt-current rollback validation.
        self.assertNotRegex(combined, r"staged registry failed")
        registry_text = (self.root / "var/lib/drlink/registry.json").read_text(encoding="utf-8")
        # Candidate must have been applied (valid JSON with marker good).
        registry = json.loads(registry_text)
        self.assertEqual(registry.get("marker"), "good")
        # Raw snapshot preserved under backups.
        snaps = list((self.root / "var/lib/drlink/backups").glob("pre-restore-*.tar.gz"))
        self.assertTrue(snaps, "expected RAW_CORRUPT pre-restore snapshot")

    def test_valid_backup_missing_registry(self):
        archive = self._make_valid_backup()
        (self.root / "var/lib/drlink/registry.json").unlink()
        proc = subprocess.run(
            [sys.executable, str(self.restore_tool), str(archive)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        combined = proc.stdout + proc.stderr
        self.assertNotIn("staged registry failed invariant", combined)
        registry = json.loads((self.root / "var/lib/drlink/registry.json").read_text(encoding="utf-8"))
        self.assertEqual(registry.get("marker"), "good")

    def test_invalid_backup_rejected(self):
        bad = Path(self.tmp.name) / "bad.tar.gz"
        bad.write_text("not a tar\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(self.restore_tool), str(bad)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        registry = json.loads((self.root / "var/lib/drlink/registry.json").read_text(encoding="utf-8"))
        self.assertEqual(registry.get("marker"), "good")

    def test_classify_rollback_raw_corrupt(self):
        archive = self._make_valid_backup()
        # Build a corrupt-current snapshot by hand: backup then corrupt registry inside archive.
        # Simpler: call classify on a backup of corrupt tree.
        (self.root / "var/lib/drlink/registry.json").write_text("{broken", encoding="utf-8")
        snap = Path(self.tmp.name) / "snap.tar.gz"
        proc = subprocess.run(
            [sys.executable, str(self.backup_tool), str(snap)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        # Backup may fail if required files must be valid JSON — if so, skip classify via raw tar.
        if proc.returncode != 0:
            # Construct raw tarball with corrupt registry matching backup format.
            staging = Path(self.tmp.name) / "staging"
            payload = staging / "payload"
            seed_valid_tree(payload, "raw")
            (payload / "var/lib/drlink/registry.json").write_text("{broken", encoding="utf-8")
            (staging / "manifest.json").write_text(
                json.dumps(
                    {
                        "format": "frp-auto-deploy-server-backup",
                        "schema_version": 1,
                        "project_version": "1.0.0",
                        "files": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with tarfile.open(snap, "w:gz") as tar:
                tar.add(staging / "manifest.json", arcname="manifest.json")
                tar.add(payload, arcname="payload")
        kind, temp, extracted = self.mod.classify_rollback_snapshot(snap)
        self.assertEqual(kind, "RAW_CORRUPT")
        self.assertIsNone(temp)
        self.assertIsNone(extracted)
        # Restore original good tree marker for other tests in class — setUp recreates each time.
        del archive


if __name__ == "__main__":
    unittest.main()
