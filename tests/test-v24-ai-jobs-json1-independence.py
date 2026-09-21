#!/usr/bin/env python3
"""Priority 8F: AI-job safety schema must not require SQLite JSON1."""
from __future__ import annotations

import inspect
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import (  # noqa: E402
    _ai_job_client_id_from_payload,
    ensure_ai_jobs_safety_schema,
)


LEGACY_AI_JOBS_DDL = """
CREATE TABLE ai_jobs (
  id TEXT PRIMARY KEY,
  principal_id TEXT,
  endpoint_object_id TEXT,
  capability TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  timeout_seconds INTEGER
);
"""


class _NoJson1Connection:
    """Connection proxy that fails closed if SQL uses SQLite JSON1."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def execute(self, sql, parameters=()):
        text = str(sql).lower()
        if "json_extract" in text or "json_each" in text or "json_type" in text:
            raise sqlite3.OperationalError("no such function: json_extract")
        return self._conn.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self._conn, name)


class AiJobsJson1IndependenceTests(unittest.TestCase):
    def test_helper_rejects_non_bindable_client_ids(self):
        self.assertEqual(
            _ai_job_client_id_from_payload('{"client_id":"host-a"}'), "host-a"
        )
        self.assertEqual(
            _ai_job_client_id_from_payload('{"client_id":"  host-a  "}'), "host-a"
        )
        self.assertIsNone(_ai_job_client_id_from_payload("{}"))
        self.assertIsNone(_ai_job_client_id_from_payload('{"client_id":""}'))
        self.assertIsNone(_ai_job_client_id_from_payload('{"client_id":"   "}'))
        self.assertIsNone(_ai_job_client_id_from_payload('{"client_id":123}'))
        self.assertIsNone(_ai_job_client_id_from_payload('{"client_id":null}'))
        self.assertIsNone(_ai_job_client_id_from_payload('{"client_id":["x"]}'))
        self.assertIsNone(_ai_job_client_id_from_payload("not-json"))
        self.assertIsNone(_ai_job_client_id_from_payload(None))

    def test_source_has_no_sqlite_json1_dependency(self):
        source = inspect.getsource(ensure_ai_jobs_safety_schema)
        self.assertNotIn("json_extract", source)
        helper = inspect.getsource(_ai_job_client_id_from_payload)
        self.assertIn("json.loads", helper)

    def test_migration_backfills_without_json_extract(self):
        with tempfile.TemporaryDirectory(prefix="drlink-p8f-") as tmp:
            db_path = Path(tmp) / "legacy.db"
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            conn.executescript(LEGACY_AI_JOBS_DDL)
            conn.executemany(
                "INSERT INTO ai_jobs(id, principal_id, endpoint_object_id, capability, "
                "payload_json, status, created_at, updated_at) VALUES "
                "(?,?,?,?,?,?,?,?)",
                [
                    (
                        "job-ok",
                        "p",
                        "e",
                        "host-info",
                        '{"client_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","arguments":{}}',
                        "queued",
                        "2026-01-01T00:00:00Z",
                        "2026-01-01T00:00:00Z",
                    ),
                    (
                        "job-keep",
                        "p",
                        "e",
                        "host-info",
                        '{"client_id":"should-not-overwrite"}',
                        "queued",
                        "2026-01-01T00:00:01Z",
                        "2026-01-01T00:00:01Z",
                    ),
                    (
                        "job-bad-json",
                        "p",
                        "e",
                        "host-info",
                        "{not-json",
                        "queued",
                        "2026-01-01T00:00:02Z",
                        "2026-01-01T00:00:02Z",
                    ),
                    (
                        "job-num",
                        "p",
                        "e",
                        "host-info",
                        '{"client_id":42}',
                        "queued",
                        "2026-01-01T00:00:03Z",
                        "2026-01-01T00:00:03Z",
                    ),
                    (
                        "job-missing",
                        "p",
                        "e",
                        "host-info",
                        '{"arguments":{}}',
                        "queued",
                        "2026-01-01T00:00:04Z",
                        "2026-01-01T00:00:04Z",
                    ),
                ],
            )
            # Pre-set an existing client_id on job-keep after adding the column
            # via migration; first prove additive columns + backfill under no-JSON1.
            proxy = _NoJson1Connection(conn)
            ensure_ai_jobs_safety_schema(proxy)

            by_id = {
                str(r["id"]): r
                for r in conn.execute(
                    "SELECT id, client_id FROM ai_jobs ORDER BY id"
                )
            }
            self.assertEqual(
                by_id["job-ok"]["client_id"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            self.assertIsNone(by_id["job-bad-json"]["client_id"])
            self.assertIsNone(by_id["job-num"]["client_id"])
            self.assertIsNone(by_id["job-missing"]["client_id"])
            # job-keep had empty client_id and a payload client_id; backfilled.
            self.assertEqual(by_id["job-keep"]["client_id"], "should-not-overwrite")

            # Existing non-empty client_id must not be overwritten on re-run.
            conn.execute(
                "UPDATE ai_jobs SET client_id = ? WHERE id = ?",
                ("existing-host", "job-ok"),
            )
            conn.execute(
                "UPDATE ai_jobs SET payload_json = ? WHERE id = ?",
                ('{"client_id":"other-host"}', "job-ok"),
            )
            ensure_ai_jobs_safety_schema(proxy)
            kept = conn.execute(
                "SELECT client_id FROM ai_jobs WHERE id = ?", ("job-ok",)
            ).fetchone()[0]
            self.assertEqual(kept, "existing-host")

            # Index exists for claim filtering.
            idx = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_ai_jobs_claim'"
            ).fetchone()
            self.assertIsNotNone(idx)
            conn.close()

    def test_fresh_schema_init_survives_json_extract_absence(self):
        """Fresh Server DB init path must not require JSON1 (AL2 regression)."""
        with tempfile.TemporaryDirectory(prefix="drlink-p8f-fresh-") as tmp:
            db_path = Path(tmp) / "fresh.db"
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            # Minimal tables used by ensure_ai_jobs_safety_schema.
            conn.executescript(
                """
                CREATE TABLE ai_jobs (
                  id TEXT PRIMARY KEY,
                  principal_id TEXT,
                  endpoint_object_id TEXT,
                  capability TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  status TEXT NOT NULL,
                  result_json TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  timeout_seconds INTEGER,
                  client_id TEXT,
                  deadline_at TEXT,
                  claim_token TEXT,
                  attempt_id TEXT,
                  claimed_at TEXT
                );
                """
            )
            proxy = _NoJson1Connection(conn)
            # Must not raise OperationalError for missing json_extract.
            ensure_ai_jobs_safety_schema(proxy)
            # Guard: if implementation regresses to SQL JSON1, this fails.
            with self.assertRaises(sqlite3.OperationalError):
                proxy.execute(
                    "SELECT json_extract(payload_json, '$.client_id') FROM ai_jobs"
                )
            conn.close()

    def test_current_sqlite_json1_builds_still_backfill(self):
        """Preserve behavior on builds that do provide JSON1."""
        try:
            probe = sqlite3.connect(":memory:")
            probe.execute("SELECT json_extract(?, '$.a')", ('{"a":1}',)).fetchone()
            probe.close()
        except sqlite3.OperationalError:
            self.skipTest("host SQLite lacks JSON1; AL2 path covered elsewhere")

        with tempfile.TemporaryDirectory(prefix="drlink-p8f-json1-") as tmp:
            db_path = Path(tmp) / "ok.db"
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            conn.executescript(LEGACY_AI_JOBS_DDL)
            conn.execute(
                "INSERT INTO ai_jobs(id, principal_id, endpoint_object_id, capability, "
                "payload_json, status, created_at, updated_at) VALUES "
                "(?,?,?,?,?,?,?,?)",
                (
                    "job-1",
                    "p",
                    "e",
                    "host-info",
                    '{"client_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}',
                    "queued",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )
            ensure_ai_jobs_safety_schema(conn)
            got = conn.execute(
                "SELECT client_id FROM ai_jobs WHERE id = ?", ("job-1",)
            ).fetchone()[0]
            self.assertEqual(got, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            conn.close()


if __name__ == "__main__":
    unittest.main()
