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
        "drlink_control_db.py",
        "drlink_control_plane.py",
        "drlink_v24.py",
    ):
        src = ROOT / "lib" / name
        if src.is_file():
            shutil.copy2(src, root / "usr/local/lib/drlink" / name)
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
    os.environ.setdefault("DRLINK_SKIP_ACTIVATION", "1")
    sys.path.insert(0, str(ROOT / "lib"))
    from drlink_control_plane import ControlPlane
    import drlink_v24 as v24

    plane = ControlPlane(str(root))
    try:
        v24.ensure_v2_schema(plane.conn)
        plane.conn.execute(
            "INSERT OR REPLACE INTO clients(id, label, hostname, created_at, updated_at) "
            "VALUES (?, ?, 'host', datetime('now'), datetime('now'))",
            ("client-" + marker, marker),
        )
        plane.conn.commit()
    finally:
        plane.close()


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

    def _client_label(self) -> str:
        sys.path.insert(0, str(ROOT / "lib"))
        from drlink_control_plane import ControlPlane

        plane = ControlPlane(str(self.root))
        try:
            row = plane.conn.execute(
                "SELECT label FROM clients WHERE id LIKE 'client-%' ORDER BY id LIMIT 1"
            ).fetchone()
            return str(row[0]) if row else ""
        finally:
            plane.close()

    def test_valid_backup_valid_current(self):
        archive = self._make_valid_backup()
        # Mutate live DB after backup.
        sys.path.insert(0, str(ROOT / "lib"))
        from drlink_control_plane import ControlPlane

        plane = ControlPlane(str(self.root))
        try:
            plane.conn.execute("UPDATE clients SET label='mutated'")
            plane.conn.commit()
        finally:
            plane.close()
        (self.root / "var/lib/drlink/registry.json").write_text(
            json.dumps({"schema_version": 2, "clients": {}, "reserved": [], "marker": "mutated"})
            + "\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [sys.executable, str(self.restore_tool), str(archive)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        combined = proc.stdout + proc.stderr
        self.assertNotIn("staged registry failed invariant", combined)
        if proc.returncode == 0:
            self.assertEqual(self._client_label(), "good")
            self.assertFalse((self.root / "var/lib/drlink/registry.json").exists())

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
        self.assertNotRegex(combined, r"staged registry failed")
        # Candidate DB applied; legacy registry purged.
        self.assertEqual(self._client_label(), "good")
        self.assertFalse((self.root / "var/lib/drlink/registry.json").exists())
        snaps = list((self.root / "var/lib/drlink/backups").glob("pre-restore-*.tar.gz"))
        self.assertTrue(snaps, "expected pre-restore snapshot")

    def test_valid_backup_missing_registry(self):
        archive = self._make_valid_backup()
        (self.root / "var/lib/drlink/registry.json").unlink(missing_ok=True)
        proc = subprocess.run(
            [sys.executable, str(self.restore_tool), str(archive)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        combined = proc.stdout + proc.stderr
        self.assertNotIn("staged registry failed invariant", combined)
        self.assertEqual(self._client_label(), "good")

    def test_invalid_backup_rejected(self):
        bad = Path(self.tmp.name) / "bad.tar.gz"
        bad.write_text("not a tar\n", encoding="utf-8")
        before = self._client_label()
        proc = subprocess.run(
            [sys.executable, str(self.restore_tool), str(bad)],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self._client_label(), before)

    def test_classify_rollback_raw_corrupt(self):
        archive = self._make_valid_backup()
        # Corrupt live DB so raw pre-restore snapshot cannot pass semantic validation.
        (self.root / "var/lib/drlink/drlink.db").write_bytes(b"not-a-sqlite-db")
        snap = Path(self.tmp.name) / "snap.tar.gz"
        env = dict(self.env)
        env["FRP_BACKUP_RAW_SNAPSHOT"] = "1"
        env["FRP_BACKUP_ALREADY_LOCKED"] = "1"
        proc = subprocess.run(
            [sys.executable, str(self.backup_tool), str(snap)],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        kind, temp, extracted = self.mod.classify_rollback_snapshot(snap)
        self.assertEqual(kind, "RAW_CORRUPT")
        self.assertIsNone(temp)
        self.assertIsNone(extracted)
        del archive


if __name__ == "__main__":
    unittest.main()
