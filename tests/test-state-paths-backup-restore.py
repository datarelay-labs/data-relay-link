#!/usr/bin/env python3
"""F06/S03: state/log path contract drives backup and restore."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, rel_path):
    path = ROOT / rel_path
    spec = importlib.util.spec_from_loader(name, loader=importlib.machinery.SourceFileLoader(name, str(path)))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


STATE = load_module("frp_state_paths", "lib/frp_state_paths.py")
BACKUP = load_module("frp_backup", "tools/frp-backup")
RESTORE = load_module("frp_restore", "tools/frp-restore")


def seed_required(tree: Path, marker: str = "test") -> None:
    dirs = (
        "etc/drlink/pki",
        "etc/frp",
        "var/lib/drlink/enrollments",
        "var/lib/drlink/bootstrap",
        "var/log/drlink/access",
        "var/log/drlink/egress",
    )
    for rel in dirs:
        (tree / rel).mkdir(parents=True, exist_ok=True)
    (tree / "etc/drlink/config.json").write_text(
        json.dumps({"marker": marker, "public_hostname": "example.test"}) + "\n",
        encoding="utf-8",
    )
    (tree / "etc/drlink/version").write_text("PROJECT_VERSION=2.4.0\n", encoding="utf-8")
    for name in ("ca.key", "ca.crt", "server.key", "server.crt"):
        (tree / "etc/drlink/pki" / name).write_text("%s-%s\n" % (name, marker), encoding="utf-8")
    (tree / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (tree / "etc/frp/server_token").write_text("token-%s\n" % marker, encoding="utf-8")
    for rel in (
        "var/lib/drlink/registry.json",
        "var/lib/drlink/access-control.json",
        "var/lib/drlink/egress-control.json",
        "var/lib/drlink/service-profiles.json",
    ):
        (tree / rel).write_text("{}\n", encoding="utf-8")
    # Canonical control DB is required for supported v2.4 DR archives.
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(tree)
    os.environ.setdefault("DRLINK_SKIP_ACTIVATION", "1")
    sys.path.insert(0, str(ROOT / "lib"))
    from drlink_control_plane import ControlPlane
    import drlink_v24 as v24

    plane = ControlPlane(str(tree))
    try:
        v24.ensure_v2_schema(plane.conn)
        plane.conn.commit()
    finally:
        plane.close()


class StatePathContractTests(unittest.TestCase):
    def test_contract_covers_current_and_legacy_egress_logs(self):
        optional = set(STATE.backup_optional_files())
        self.assertIn("var/log/drlink/egress/connections.jsonl", optional)
        self.assertIn("var/log/drlink/egress-conn.jsonl", optional)
        restore_optional = STATE.restore_optional_exact()
        self.assertIn("var/log/drlink/egress/connections.jsonl", restore_optional)
        self.assertIn("var/log/drlink/egress-conn.jsonl", restore_optional)

    def test_rotated_prefixes_accept_numeric_suffix(self):
        for rel in (
            "var/log/drlink/egress/connections.jsonl.1",
            "var/log/drlink/egress-conn.jsonl.2",
            "var/log/drlink/access/connections.jsonl.3",
            "var/log/drlink/access-conn.jsonl.4",
            "var/log/drlink/audit.jsonl.5",
        ):
            self.assertTrue(STATE.allowed_rotated_rel(rel), rel)
        self.assertFalse(STATE.allowed_rotated_rel("var/log/drlink/audit.jsonl.lock"))


class BackupRestoreEgressLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = Path(self.tmp.name) / "root"
        self.tree.mkdir()
        seed_required(self.tree)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.tree)
        os.environ["FRP_BACKUP_ALREADY_LOCKED"] = "1"

    def tearDown(self):
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
        os.environ.pop("FRP_BACKUP_ALREADY_LOCKED", None)
        self.tmp.cleanup()

    def _write_log(self, rel: str, body: str) -> None:
        path = self.tree / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    def _backup_and_collect(self):
        out = self.tree / "backup.tar.gz"
        BACKUP.create_backup(self.tree, out, secure_parent=False)
        return BACKUP.collect_files(self.tree)

    def test_new_path_only_in_backup(self):
        self._write_log("var/log/drlink/egress/connections.jsonl", '{"event":"new"}\n')
        rels = {rel for rel, _src in self._backup_and_collect()}
        self.assertIn("var/log/drlink/egress/connections.jsonl", rels)
        self.assertNotIn("var/log/drlink/egress-conn.jsonl", rels)

    def test_legacy_path_only_in_backup(self):
        self._write_log("var/log/drlink/egress-conn.jsonl", '{"event":"legacy"}\n')
        rels = {rel for rel, _src in self._backup_and_collect()}
        self.assertIn("var/log/drlink/egress-conn.jsonl", rels)
        self.assertNotIn("var/log/drlink/egress/connections.jsonl", rels)

    def test_both_paths_and_rotation_in_backup(self):
        self._write_log("var/log/drlink/egress/connections.jsonl", '{"event":"new"}\n')
        self._write_log("var/log/drlink/egress/connections.jsonl.1", '{"event":"rot-new"}\n')
        self._write_log("var/log/drlink/egress-conn.jsonl", '{"event":"legacy"}\n')
        self._write_log("var/log/drlink/egress-conn.jsonl.1", '{"event":"rot-legacy"}\n')
        rels = {rel for rel, _src in self._backup_and_collect()}
        self.assertTrue(
            {
                "var/log/drlink/egress/connections.jsonl",
                "var/log/drlink/egress/connections.jsonl.1",
                "var/log/drlink/egress-conn.jsonl",
                "var/log/drlink/egress-conn.jsonl.1",
            }.issubset(rels)
        )

    def test_missing_logs_do_not_fail_backup(self):
        rels = {rel for rel, _src in self._backup_and_collect()}
        self.assertNotIn("var/log/drlink/egress/connections.jsonl", rels)
        self.assertNotIn("var/log/drlink/egress-conn.jsonl", rels)

    def test_restore_default_egress_log_path(self):
        self.assertEqual(
            RESTORE._STATE_PATHS.default_egress_conn_log_rel(),
            "var/log/drlink/egress/connections.jsonl",
        )

    def test_nested_archive_directories_restore(self):
        handle = "var/lib/drlink/bootstrap/handles"
        active = "var/lib/drlink/tls/mcp/active"
        self.assertTrue(RESTORE.allowed_directory(handle))
        self.assertTrue(RESTORE.allowed_directory(active))
        self.assertTrue(RESTORE.allowed_path(handle + "/ab.json"))
        self.assertTrue(RESTORE.allowed_path(active + "/fullchain.pem"))
        for unsafe in (
            "var/lib/drlink/bootstrap/../etc/frp/server_token",
            "/etc/passwd",
            "var/lib/drlink/bootstrap/handles/../../tls",
        ):
            with self.assertRaises(RESTORE.RestoreError):
                RESTORE.validate_rel(unsafe)
        self._write_log(handle + "/ab.json", '{"ticket_id":"ab"}\n')
        self._write_log(active + "/fullchain.pem", "pem-marker\n")
        archive = self.tree / "nested.tar.gz"
        BACKUP.create_backup(self.tree, archive, secure_parent=False)
        (self.tree / handle / "ab.json").unlink()
        (self.tree / active / "fullchain.pem").unlink()
        extracted = Path(self.tmp.name) / "extracted"
        RESTORE.extract_and_validate(archive, extracted)
        RESTORE.apply_payload(self.tree, extracted, allow_hook=False)
        self.assertEqual(
            (self.tree / handle / "ab.json").read_text(encoding="utf-8"),
            '{"ticket_id":"ab"}\n',
        )
        self.assertEqual(
            (self.tree / active / "fullchain.pem").read_text(encoding="utf-8"),
            "pem-marker\n",
        )


if __name__ == "__main__":
    unittest.main()
