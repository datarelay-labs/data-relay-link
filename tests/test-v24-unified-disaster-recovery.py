#!/usr/bin/env python3
"""Priority 7: unified v2.4 Server disaster-recovery contract."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import SCHEMA_VERSION, ensure_ai_jobs_safety_schema
from drlink_control_plane import ControlPlane
import drlink_v24 as v24
from frp_ctl_grammar import match

BACKUP = ROOT / "tools" / "frp-backup"
RESTORE = ROOT / "tools" / "frp-restore"


def seed_server(tree: Path, marker: str = "orig") -> ControlPlane:
    for rel in (
        "etc/drlink/pki",
        "etc/frp",
        "var/lib/drlink/enrollments",
        "var/lib/drlink/bootstrap",
        "var/lib/drlink/backups",
        "var/log/drlink",
    ):
        (tree / rel).mkdir(parents=True, exist_ok=True)
    (tree / "etc/drlink/config.json").write_text(
        json.dumps(
            {
                "role": "server",
                "marker": marker,
                "public_hostname": "dr.example.test",
                "public_host": "dr.example.test",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tree / "etc/drlink/version").write_text(
        "PROJECT_VERSION=2.4.0\nRELEASE_CHANNEL=dev\nSOURCE_REF=test\n",
        encoding="utf-8",
    )
    for name in ("ca.key", "ca.crt", "server.key", "server.crt"):
        (tree / "etc/drlink/pki" / name).write_text("%s-%s\n" % (name, marker), encoding="utf-8")
    (tree / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (tree / "etc/frp/server_token").write_text("token-%s\n" % marker, encoding="utf-8")
    # Contradictory legacy JSON — must never become authority after restore.
    (tree / "var/lib/drlink/access-control.json").write_text(
        json.dumps({"schema_version": 1, "access_lists": {"legacy-%s" % marker: {}}}) + "\n",
        encoding="utf-8",
    )
    (tree / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {"legacy": {"label": "legacy-%s" % marker}}, "reserved": []})
        + "\n",
        encoding="utf-8",
    )
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(tree)
    os.environ["FRP_BACKUP_ALREADY_LOCKED"] = "1"
    os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
    plane = ControlPlane(str(tree))
    v24.ensure_v2_schema(plane.conn)
    plane.conn.execute(
        "INSERT OR REPLACE INTO clients(id, label, hostname, created_at, updated_at) "
        "VALUES ('cccccccccccccccccccccccccccccccc', ?, 'host-a', datetime('now'), datetime('now'))",
        (marker,),
    )
    plane.conn.commit()
    plane.compile_runtime()
    return plane


def run_tool(tool: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(tool), *args],
        capture_output=True,
        text=True,
        env=merged,
    )


def archive_paths(archive: Path) -> set[str]:
    with tarfile.open(archive, "r:gz") as tar:
        return {m.name for m in tar.getmembers() if m.isfile()}


def rewrite_archive(source: Path, dest: Path, mutate) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with tarfile.open(source, "r:gz") as tar:
            tar.extractall(root)
        mutate(root)
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        files = []
        lines = []
        for path in sorted((root / "payload").rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root / "payload").as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            mode = path.stat().st_mode & 0o777
            files.append({"path": rel, "sha256": digest, "mode": mode})
            lines.append("%s  payload/%s" % (digest, rel))
        manifest["files"] = files
        db_path = root / "payload/var/lib/drlink/drlink.db"
        if "control_db" in manifest and db_path.is_file():
            try:
                conn = sqlite3.connect(str(db_path))
                try:
                    schema = int(
                        conn.execute(
                            "SELECT COALESCE(MAX(version),0) FROM schema_migrations"
                        ).fetchone()[0]
                        or 0
                    )
                    rev = int(
                        conn.execute(
                            "SELECT COALESCE(MAX(revision),0) FROM config_revisions"
                        ).fetchone()[0]
                        or 0
                    )
                finally:
                    conn.close()
                manifest["control_db"] = {
                    "path": "var/lib/drlink/drlink.db",
                    "schema_version": schema,
                    "revision": rev,
                }
            except sqlite3.Error:
                # Leave prior control_db metadata; validation should fail on DB itself.
                pass
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (root / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(root / "manifest.json", arcname="manifest.json")
            tar.add(root / "checksums.sha256", arcname="checksums.sha256")
            tar.add(root / "payload", arcname="payload")


class UnifiedDisasterRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-p7-dr-")
        self.tree = Path(self.tmp.name) / "root"
        self.tree.mkdir()
        self.outdir = Path(self.tmp.name) / "out"
        self.outdir.mkdir()
        self.plane = seed_server(self.tree, "orig")

    def tearDown(self):
        try:
            self.plane.close()
        except Exception:
            pass
        for key in (
            "FRP_DEPLOY_TEST_ROOT",
            "FRP_BACKUP_ALREADY_LOCKED",
            "DRLINK_SKIP_ACTIVATION",
            "FRP_RESTORE_HOOK_FAIL_AFTER",
            "FRP_RESTORE_HOOK_HEALTH_FAIL",
            "FRP_RESTORE_HOOK_ROLLBACK_HEALTH_FAIL",
        ):
            os.environ.pop(key, None)
        self.tmp.cleanup()

    def _backup(self) -> Path:
        archive = self.outdir / "server.tar.gz"
        proc = run_tool(BACKUP, str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return archive

    def test_01_full_round_trip_and_trust(self):
        archive = self._backup()
        names = archive_paths(archive)
        self.assertIn("payload/var/lib/drlink/drlink.db", names)
        self.assertIn("payload/etc/drlink/pki/ca.key", names)
        # Mutate live authoritative + trust state.
        self.plane.conn.execute("UPDATE clients SET label='mutated'")
        self.plane.conn.commit()
        (self.tree / "etc/drlink/pki/ca.key").write_text("mutated-ca\n", encoding="utf-8")
        (self.tree / "var/lib/drlink/access-control.json").write_text(
            json.dumps({"schema_version": 1, "access_lists": {"evil": {}}}) + "\n",
            encoding="utf-8",
        )
        proc = run_tool(RESTORE, str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        label = self.plane.conn.execute(
            "SELECT label FROM clients WHERE id='cccccccccccccccccccccccccccccccc'"
        ).fetchone()[0]
        self.assertEqual(label, "orig")
        self.assertEqual((self.tree / "etc/drlink/pki/ca.key").read_text(encoding="utf-8"), "ca.key-orig\n")
        self.assertFalse((self.tree / "var/lib/drlink/access-control.json").exists())
        runtime = self.tree / "var/lib/drlink/runtime"
        self.assertTrue((runtime / "generation.json").is_file())
        self.assertTrue((runtime / "remote-access.json").is_file())

    def test_02_db_required_and_tamper_rejected(self):
        archive = self._backup()
        missing = self.outdir / "missing-db.tar.gz"

        def drop_db(root: Path) -> None:
            (root / "payload/var/lib/drlink/drlink.db").unlink()

        rewrite_archive(archive, missing, drop_db)
        before = (self.tree / "etc/frp/server_token").read_text(encoding="utf-8")
        proc = run_tool(RESTORE, str(missing))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("drlink.db", proc.stderr.lower())
        self.assertEqual((self.tree / "etc/frp/server_token").read_text(encoding="utf-8"), before)

        corrupt = self.outdir / "corrupt-db.tar.gz"

        def corrupt_db(root: Path) -> None:
            (root / "payload/var/lib/drlink/drlink.db").write_bytes(b"not-a-db")

        rewrite_archive(archive, corrupt, corrupt_db)
        proc = run_tool(RESTORE, str(corrupt))
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((self.tree / "etc/frp/server_token").read_text(encoding="utf-8"), before)

    def test_03_manifest_checksum_mismatch_rejected(self):
        archive = self._backup()
        bad = self.outdir / "checksum.tar.gz"

        def tamper(root: Path) -> None:
            path = root / "payload/etc/frp/server_token"
            path.write_text("tampered\n", encoding="utf-8")

        rewrite_archive(archive, bad, tamper)
        # Break checksum intentionally after rewrite by flipping one digest.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with tarfile.open(bad, "r:gz") as tar:
                tar.extractall(root)
            lines = (root / "checksums.sha256").read_text(encoding="utf-8").splitlines()
            lines[0] = ("0" * 64) + lines[0][64:]
            (root / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
            with tarfile.open(bad, "w:gz") as tar:
                tar.add(root / "manifest.json", arcname="manifest.json")
                tar.add(root / "checksums.sha256", arcname="checksums.sha256")
                tar.add(root / "payload", arcname="payload")
        before = (self.tree / "etc/frp/server_token").read_text(encoding="utf-8")
        proc = run_tool(RESTORE, str(bad))
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((self.tree / "etc/frp/server_token").read_text(encoding="utf-8"), before)

    def test_04_legacy_json_and_stale_runtime_cannot_override_db(self):
        archive = self._backup()
        # Stale runtime projection + contradictory legacy JSON on live tree.
        runtime = self.tree / "var/lib/drlink/runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        (runtime / "remote-access.json").write_text(
            json.dumps({"plane": "remote", "rules": [{"name": "stale-evil"}]}) + "\n",
            encoding="utf-8",
        )
        (self.tree / "var/lib/drlink/access-control.json").write_text(
            json.dumps({"schema_version": 1, "access_lists": {"evil": {}}}) + "\n",
            encoding="utf-8",
        )
        self.plane.conn.execute("UPDATE clients SET label='mutated'")
        self.plane.conn.commit()
        proc = run_tool(RESTORE, str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        label = self.plane.conn.execute(
            "SELECT label FROM clients WHERE id='cccccccccccccccccccccccccccccccc'"
        ).fetchone()[0]
        self.assertEqual(label, "orig")
        self.assertFalse((self.tree / "var/lib/drlink/access-control.json").exists())
        rules = json.loads((runtime / "remote-access.json").read_text(encoding="utf-8"))
        self.assertNotEqual(rules.get("rules"), [{"name": "stale-evil"}])

    def test_05_activation_failure_rolls_back(self):
        archive = self._backup()
        before_token = (self.tree / "etc/frp/server_token").read_text(encoding="utf-8")
        before_label = self.plane.conn.execute(
            "SELECT label FROM clients WHERE id='cccccccccccccccccccccccccccccccc'"
        ).fetchone()[0]
        proc = run_tool(
            RESTORE,
            str(archive),
            env={"FRP_RESTORE_HOOK_FAIL_AFTER": "2"},
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("previous state was restored", proc.stderr)
        self.assertEqual((self.tree / "etc/frp/server_token").read_text(encoding="utf-8"), before_token)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        label = self.plane.conn.execute(
            "SELECT label FROM clients WHERE id='cccccccccccccccccccccccccccccccc'"
        ).fetchone()[0]
        self.assertEqual(label, before_label)

    def test_06_rollback_failure_recovery_required(self):
        archive = self._backup()
        proc = run_tool(
            RESTORE,
            str(archive),
            env={
                "FRP_RESTORE_HOOK_FAIL_AFTER": "2",
                "FRP_RESTORE_HOOK_ROLLBACK_HEALTH_FAIL": "1",
            },
        )
        self.assertNotEqual(proc.returncode, 0)
        combined = proc.stdout + proc.stderr
        self.assertIn("RECOVERY_REQUIRED", combined)
        self.assertNotIn("previous state was restored", combined)

    def test_07_ai_nonterminal_reconciled(self):
        ensure_ai_jobs_safety_schema(self.plane.conn)
        self.plane.conn.execute(
            "INSERT INTO ai_jobs(id, principal_id, endpoint_object_id, capability, payload_json, "
            "status, created_at, updated_at, client_id) VALUES "
            "('job-q', 'p', 'e', 'exec', '{}', 'queued', datetime('now'), datetime('now'), 'host'),"
            "('job-r', 'p', 'e', 'write_file', '{}', 'running', datetime('now'), datetime('now'), 'host'),"
            "('job-ro', 'p', 'e', 'read_file', '{}', 'running', datetime('now'), datetime('now'), 'host')"
        )
        self.plane.conn.commit()
        archive = self._backup()
        proc = run_tool(RESTORE, str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        rows = {
            str(r["id"]): str(r["status"])
            for r in self.plane.conn.execute("SELECT id, status FROM ai_jobs")
        }
        self.assertEqual(rows["job-q"], "expired")
        self.assertEqual(rows["job-r"], "recovery_required")
        self.assertEqual(rows["job-ro"], "expired")

    def test_08_public_cli_parity_and_validate(self):
        archive = self._backup()
        self.assertEqual(
            match(["system", "backup"], role="server")["action"],
            "create_backup",
        )
        self.assertEqual(
            match(["system", "restore", str(archive)], role="server")["action"],
            "restore_backup",
        )
        result = match(["system", "backup", "validate", str(archive)], role="server")
        self.assertEqual(result["action"], "control_plane")
        self.assertEqual(result["tokens"][:3], ["system", "backup", "validate"])
        proc = run_tool(RESTORE, "--validate", str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Backup valid", proc.stdout)

    def test_09_version_incompatibility_rejected(self):
        archive = self._backup()
        (self.tree / "etc/drlink/version").write_text(
            "PROJECT_VERSION=9.9.9\nRELEASE_CHANNEL=dev\n",
            encoding="utf-8",
        )
        proc = run_tool(RESTORE, str(archive))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("cross-version", proc.stderr.lower())

    def test_10_priority2_controlplane_db_restore_still_pass(self):
        # Internal DB-only checkpoint helper remains for activation/tests.
        dest = self.outdir / "db-only.tar"
        self.plane.backup(str(dest))
        info = self.plane.backup_validate(str(dest))
        self.assertTrue(info["ok"])
        self.assertEqual(info["schema_version"], SCHEMA_VERSION)
        self.plane.conn.execute("UPDATE clients SET label='mutated'")
        self.plane.conn.commit()
        restored = self.plane.restore(str(dest))
        self.assertTrue(restored["ok"])
        label = self.plane.conn.execute(
            "SELECT label FROM clients WHERE id='cccccccccccccccccccccccccccccccc'"
        ).fetchone()[0]
        self.assertEqual(label, "orig")


if __name__ == "__main__":
    unittest.main()
