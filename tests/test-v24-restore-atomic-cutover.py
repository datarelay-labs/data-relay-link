#!/usr/bin/env python3
"""P0: ControlPlane backup candidate validation + atomic restore cutover."""
from __future__ import annotations

import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import SCHEMA_VERSION, SchemaTooNewError
from drlink_control_plane import BACKUP_FORMAT, ControlPlane, ControlPlaneError
import drlink_v24 as v24

MID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MID2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _pack_backup(dest: Path, db_bytes: bytes, meta: dict) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "drlink.db").write_bytes(db_bytes)
        (root / "backup-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        with tarfile.open(dest, "w") as tar:
            tar.add(root / "drlink.db", arcname="drlink.db")
            tar.add(root / "backup-meta.json", arcname="backup-meta.json")
    return dest


def _extract_db_and_meta(archive: Path) -> tuple[bytes, dict]:
    with tarfile.open(archive, "r") as tar:
        db = tar.extractfile("drlink.db").read()
        meta = json.loads(tar.extractfile("backup-meta.json").read().decode("utf-8"))
    return db, meta


class RestoreAtomicCutover(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-restore-atom-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ.pop("DRLINK_FAULT_RESTORE", None)
        os.environ.pop("DRLINK_FAULT_ROLLBACK", None)
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        self.outdir = Path(tempfile.mkdtemp(prefix="drlink-restore-out-"))

    def tearDown(self):
        self.plane.close()
        for key in (
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_FAULT_RESTORE",
            "DRLINK_FAULT_ROLLBACK",
        ):
            os.environ.pop(key, None)

    def _logical_state(self) -> dict:
        clients = [
            {
                "id": str(row["id"]),
                "label": str(row["label"] or ""),
                "hostname": str(row["hostname"] or ""),
            }
            for row in self.plane.conn.execute(
                "SELECT id, label, hostname FROM clients ORDER BY id"
            )
        ]
        return {
            "revision": self.plane.current_revision(),
            "clients": clients,
            "schema": int(
                self.plane.conn.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
                ).fetchone()[0]
                or 0
            ),
        }

    def test_canonical_backup_round_trip(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        rev_a = self.plane.current_revision()
        backup = self.outdir / "good.tar"
        self.plane.backup(str(backup))
        info = self.plane.backup_validate(str(backup))
        self.assertTrue(info["ok"])
        self.assertEqual(info["revision"], rev_a)
        self.assertEqual(info["schema_version"], SCHEMA_VERSION)
        self.assertEqual(info["format"], BACKUP_FORMAT)

        self.plane.upsert_client(MID2, label="host-b", hostname="host-b")
        self.assertNotEqual(self.plane.current_revision(), rev_a)
        result = self.plane.restore(str(backup))
        self.assertTrue(result["ok"])
        self.assertEqual(result["revision"], rev_a)
        self.assertEqual(self.plane.current_revision(), rev_a)
        row = self.plane.conn.execute(
            "SELECT label FROM clients WHERE id = ?", (MID,)
        ).fetchone()
        self.assertIsNotNone(row)
        missing = self.plane.conn.execute(
            "SELECT 1 FROM clients WHERE id = ?", (MID2,)
        ).fetchone()
        self.assertIsNone(missing)
        st = self.plane.status()
        self.assertEqual(st["revision"], rev_a)
        self.assertTrue(st["db_healthy"])

    def test_arbitrary_sqlite_rejected_before_live_mutation(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        before = self._logical_state()
        foreign = self.outdir / "foreign.db"
        conn = sqlite3.connect(str(foreign))
        conn.execute("CREATE TABLE unrelated(x INTEGER)")
        conn.execute("INSERT INTO unrelated(x) VALUES (1)")
        conn.commit()
        conn.close()
        archive = _pack_backup(
            self.outdir / "foreign.tar",
            foreign.read_bytes(),
            {
                "format": BACKUP_FORMAT,
                "schema_version": SCHEMA_VERSION,
                "revision": 0,
                "created_at": "2026-01-01T00:00:00Z",
            },
        )
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.backup_validate(str(archive))
        self.assertIn("not a DRLink control-plane database", str(ctx.exception))
        with self.assertRaises(ControlPlaneError):
            self.plane.restore(str(archive))
        self.assertEqual(self._logical_state(), before)

    def test_future_schema_rejected_before_live_mutation(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        before = self._logical_state()
        good = self.outdir / "base.tar"
        self.plane.backup(str(good))
        db_bytes, meta = _extract_db_and_meta(good)
        mutated = self.outdir / "future.db"
        mutated.write_bytes(db_bytes)
        conn = sqlite3.connect(str(mutated))
        conn.execute(
            "INSERT INTO schema_migrations(version, name, applied_at) VALUES (99, 'future', 't')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO system_meta(key, value) VALUES ('schema_version', '99')"
        )
        conn.commit()
        conn.close()
        meta["schema_version"] = 99
        archive = _pack_backup(self.outdir / "future.tar", mutated.read_bytes(), meta)
        with self.assertRaises(SchemaTooNewError):
            self.plane.backup_validate(str(archive))
        with self.assertRaises(ControlPlaneError):
            self.plane.restore(str(archive))
        self.assertEqual(self._logical_state(), before)

    def test_metadata_mismatch_rejected(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        good = self.outdir / "base.tar"
        self.plane.backup(str(good))
        db_bytes, meta = _extract_db_and_meta(good)

        bad_fmt = dict(meta)
        bad_fmt["format"] = "not-drlink"
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.backup_validate(
                str(_pack_backup(self.outdir / "bad-fmt.tar", db_bytes, bad_fmt))
            )
        self.assertIn("format", str(ctx.exception).lower())

        bad_schema = dict(meta)
        bad_schema["schema_version"] = SCHEMA_VERSION + 5
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.backup_validate(
                str(_pack_backup(self.outdir / "bad-schema.tar", db_bytes, bad_schema))
            )
        self.assertIn("schema_version", str(ctx.exception))

        bad_rev = dict(meta)
        bad_rev["revision"] = int(meta["revision"]) + 99
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.backup_validate(
                str(_pack_backup(self.outdir / "bad-rev.tar", db_bytes, bad_rev))
            )
        self.assertIn("revision", str(ctx.exception))

    def test_missing_required_structures_rejected(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        good = self.outdir / "base.tar"
        self.plane.backup(str(good))
        db_bytes, meta = _extract_db_and_meta(good)
        stripped = self.outdir / "stripped.db"
        stripped.write_bytes(db_bytes)
        conn = sqlite3.connect(str(stripped))
        conn.execute("DROP TABLE published_services")
        conn.commit()
        conn.close()
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.backup_validate(
                str(_pack_backup(self.outdir / "stripped.tar", stripped.read_bytes(), meta))
            )
        self.assertIn("missing tables", str(ctx.exception))

        # Missing metadata member.
        bare = self.outdir / "bare.tar"
        with tarfile.open(bare, "w") as tar:
            with tempfile.NamedTemporaryFile(suffix=".db") as fh:
                fh.write(db_bytes)
                fh.flush()
                tar.add(fh.name, arcname="drlink.db")
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.backup_validate(str(bare))
        self.assertIn("backup-meta.json", str(ctx.exception))

    def test_fk_violation_rejected(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        good = self.outdir / "base.tar"
        self.plane.backup(str(good))
        db_bytes, meta = _extract_db_and_meta(good)
        broken = self.outdir / "fk.db"
        broken.write_bytes(db_bytes)
        conn = sqlite3.connect(str(broken))
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute(
            "INSERT INTO revision_snapshots(revision, snapshot_json) VALUES (999999, '{}')"
        )
        conn.commit()
        conn.close()
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.backup_validate(
                str(_pack_backup(self.outdir / "fk.tar", broken.read_bytes(), meta))
            )
        msg = str(ctx.exception).lower()
        self.assertTrue("integrity" in msg or "foreign" in msg)

    def test_cutover_failure_rolls_back_previous_state(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        backup = self.outdir / "prev.tar"
        self.plane.backup(str(backup))
        rev_a = self.plane.current_revision()

        self.plane.upsert_client(MID2, label="host-b", hostname="host-b")
        rev_b = self.plane.current_revision()
        self.assertNotEqual(rev_a, rev_b)
        before = self._logical_state()
        self.plane.compile_runtime()

        os.environ["DRLINK_FAULT_RESTORE"] = "1"
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.restore(str(backup))
        self.assertIn("previous control-plane state was restored", str(ctx.exception))
        os.environ.pop("DRLINK_FAULT_RESTORE", None)

        self.assertEqual(self._logical_state(), before)
        # Candidate revision must not remain authoritative.
        self.assertNotEqual(self.plane.current_revision(), rev_a)
        self.plane.compile_runtime()
        st = self.plane.status()
        self.assertEqual(st["revision"], rev_b)
        self.assertTrue(st["db_healthy"])
        gens = st["generations"]
        for plane in ("remote", "internet", "ai"):
            self.assertEqual(int(gens[plane]["db_revision"]), rev_b)

    def test_successful_restore_status_and_evaluation(self):
        self.plane.upsert_client(MID, label="host-a", hostname="host-a")
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        backup = self.outdir / "eval.tar"
        self.plane.backup(str(backup))
        rev = self.plane.current_revision()
        self.plane.upsert_client(MID2, label="host-b", hostname="host-b")
        result = self.plane.restore(str(backup))
        self.assertEqual(result["revision"], rev)
        st = self.plane.status()
        self.assertEqual(st["revision"], rev)
        self.assertTrue(st["db_healthy"])
        self.assertEqual(st["clients"], 1)
        # Runtime compile after restore must succeed for evaluation surfaces.
        self.plane.compile_runtime()
        rules = self.plane.list_rules("remote")
        self.assertIsInstance(rules, list)


if __name__ == "__main__":
    unittest.main()
