#!/usr/bin/env python3
"""SQLite control-plane connection, schema, and migration ledger.

Authoritative path: /var/lib/drlink/drlink.db
Runtime JSON is derived state only.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 2
APPLICATION_ID = 0x44524C4B  # 'DRLK'
DEFAULT_DB_REL = "var/lib/drlink/drlink.db"
BUSY_TIMEOUT_MS = 5000

SUPPORTED_PRAGMAS = (
    ("foreign_keys", "ON"),
    ("journal_mode", "WAL"),
    ("synchronous", "FULL"),
    ("busy_timeout", str(BUSY_TIMEOUT_MS)),
    ("trusted_schema", "OFF"),
)


class ControlPlaneError(Exception):
    """User-facing control-plane failure."""


class SchemaTooNewError(ControlPlaneError):
    def __init__(self, found: int, supported: int):
        super().__init__(
            "Control DB schema %s is newer than this binary (supports %s). "
            "No changes were applied."
            % (found, supported)
        )
        self.found = found
        self.supported = supported


class DatabaseCorruptError(ControlPlaneError):
    def __init__(self, detail: str = ""):
        msg = "Control DB is corrupt or unreadable. Enforcement is fail-closed."
        if detail:
            msg = "%s %s" % (msg, detail)
        super().__init__(msg)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_root(root: Optional[str] = None) -> str:
    if root:
        return str(root)
    for key in (
        "FRP_DEPLOY_TEST_ROOT",
        "FRP_CTL_TEST_ROOT",
        "FRP_SERVER_TEST_ROOT",
        "DRLINK_TEST_ROOT",
    ):
        value = os.environ.get(key) or ""
        if value:
            return value
    return ""


def db_path(root: Optional[str] = None) -> Path:
    base = resolve_root(root)
    if base:
        return Path(base) / DEFAULT_DB_REL
    return Path("/") / DEFAULT_DB_REL


def deploy_root_from_db_path(db_file) -> str:
    """Return <ROOT> for <ROOT>/var/lib/drlink/drlink.db.

    Real filesystem: ``/var/lib/drlink/drlink.db`` → ``/``.
    Staging/test: ``/tmp/test-root/var/lib/drlink/drlink.db`` → ``/tmp/test-root``.

    Do not walk a fixed number of parents: ``Path.parent`` × 3 on the real DB
    path stops at ``/var`` and would create ``/var/var/lib/drlink``.
    """
    path = Path(db_file)
    rel_parts = Path(DEFAULT_DB_REL).parts
    parts = path.parts
    if len(parts) >= len(rel_parts) and parts[-len(rel_parts) :] == rel_parts:
        prefix = parts[: -len(rel_parts)]
        if not prefix or prefix == ("/",):
            return "/"
        return str(Path(*prefix))
    parts_list = list(parts)
    for idx, part in enumerate(parts_list):
        if part != "var":
            continue
        if parts_list[idx : idx + len(rel_parts)] != list(rel_parts):
            continue
        prefix = parts_list[:idx]
        if not prefix or prefix == ["/"]:
            return "/"
        return str(Path(*prefix))
    raise ControlPlaneError(
        "cannot derive deploy root from control db path %s" % path
    )


def runtime_dir(root: Optional[str] = None) -> Path:
    return db_path(root).parent / "runtime"


SCHEMA_SQL = r"""
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE system_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE config_revisions (
  revision INTEGER PRIMARY KEY,
  actor TEXT NOT NULL,
  command TEXT NOT NULL,
  created_at TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT ''
);

CREATE TABLE revision_snapshots (
  revision INTEGER PRIMARY KEY,
  snapshot_json TEXT NOT NULL,
  FOREIGN KEY (revision) REFERENCES config_revisions(revision)
);

CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  revision INTEGER,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  before_summary TEXT,
  after_summary TEXT,
  impact_summary TEXT,
  result TEXT NOT NULL,
  FOREIGN KEY (revision) REFERENCES config_revisions(revision)
);

CREATE TABLE runtime_generations (
  plane TEXT PRIMARY KEY,
  db_revision INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  status TEXT NOT NULL,
  artifact_path TEXT,
  activated_at TEXT,
  error TEXT
);

CREATE TABLE objects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  type TEXT NOT NULL,
  origin TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  orphan_reason TEXT,
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE object_values (
  object_id TEXT NOT NULL,
  value TEXT NOT NULL,
  normalized TEXT NOT NULL,
  PRIMARY KEY (object_id, value),
  FOREIGN KEY (object_id) REFERENCES objects(id) ON DELETE CASCADE
);

CREATE TABLE object_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE object_group_members (
  group_id TEXT NOT NULL,
  member_kind TEXT NOT NULL,
  member_id TEXT NOT NULL,
  PRIMARY KEY (group_id, member_kind, member_id),
  FOREIGN KEY (group_id) REFERENCES object_groups(id) ON DELETE CASCADE
);

CREATE TABLE clients (
  id TEXT PRIMARY KEY,
  label TEXT,
  description TEXT,
  hostname TEXT,
  status TEXT NOT NULL DEFAULT 'connected',
  trust_status TEXT NOT NULL DEFAULT 'trusted',
  connected INTEGER NOT NULL DEFAULT 0,
  last_seen TEXT,
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE managed_endpoints (
  id TEXT PRIMARY KEY,
  object_id TEXT NOT NULL UNIQUE,
  client_id TEXT,
  FOREIGN KEY (object_id) REFERENCES objects(id),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE endpoint_addresses (
  endpoint_object_id TEXT NOT NULL,
  address TEXT NOT NULL,
  address_family TEXT NOT NULL,
  interface_name TEXT,
  scope TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  PRIMARY KEY (endpoint_object_id, address),
  FOREIGN KEY (endpoint_object_id) REFERENCES objects(id) ON DELETE CASCADE
);

CREATE TABLE client_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE client_group_members (
  group_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  PRIMARY KEY (group_id, client_id),
  FOREIGN KEY (group_id) REFERENCES client_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE client_tags (
  client_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (client_id, key),
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE published_services (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  name TEXT NOT NULL,
  service_type TEXT NOT NULL,
  target_mode TEXT NOT NULL,
  target_host TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  public_port INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  released INTEGER NOT NULL DEFAULT 0,
  preset_name TEXT,
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (client_id, name),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE service_presets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  service_type TEXT,
  target_mode TEXT,
  target_port INTEGER,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE port_reservations (
  public_port INTEGER PRIMARY KEY,
  client_id TEXT,
  service_id TEXT,
  service_name TEXT,
  released INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE policy_rules (
  id TEXT PRIMARY KEY,
  plane TEXT NOT NULL,
  name TEXT NOT NULL COLLATE NOCASE,
  position INTEGER NOT NULL,
  action TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (plane, name)
);

CREATE TABLE rule_sources (
  rule_id TEXT NOT NULL,
  ref_kind TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  PRIMARY KEY (rule_id, ref_kind, ref_id),
  FOREIGN KEY (rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE
);

CREATE TABLE rule_destinations (
  rule_id TEXT NOT NULL,
  ref_kind TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  PRIMARY KEY (rule_id, ref_kind, ref_id),
  FOREIGN KEY (rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE
);

CREATE TABLE rule_services (
  rule_id TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  PRIMARY KEY (rule_id, protocol, port),
  FOREIGN KEY (rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE
);

CREATE TABLE enrollments (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  secret_ref TEXT
);

CREATE TABLE fixed_tcp (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  listen_port INTEGER,
  dest_host TEXT,
  dest_port INTEGER,
  destination_object_id TEXT,
  enabled INTEGER NOT NULL DEFAULT 0,
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (destination_object_id) REFERENCES objects(id)
);

CREATE TABLE ai_principals (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 0,
  credential_hash TEXT,
  credential_fingerprint TEXT,
  credential_status TEXT NOT NULL DEFAULT 'none',
  last_seen TEXT,
  auth_mode TEXT NOT NULL DEFAULT 'static-bearer',
  oauth_issuer TEXT NOT NULL DEFAULT '',
  oauth_subject TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE ai_access_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  principal_id TEXT,
  position INTEGER NOT NULL,
  action TEXT NOT NULL DEFAULT 'allow',
  enabled INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  exec_timeout INTEGER,
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);

CREATE TABLE ai_rule_targets (
  rule_id TEXT NOT NULL,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  PRIMARY KEY (rule_id, target_kind, target_id),
  FOREIGN KEY (rule_id) REFERENCES ai_access_rules(id) ON DELETE CASCADE
);

CREATE TABLE ai_rule_capabilities (
  rule_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  PRIMARY KEY (rule_id, capability),
  FOREIGN KEY (rule_id) REFERENCES ai_access_rules(id) ON DELETE CASCADE
);

CREATE TABLE ai_path_scopes (
  rule_id TEXT NOT NULL,
  pattern TEXT NOT NULL,
  PRIMARY KEY (rule_id, pattern),
  FOREIGN KEY (rule_id) REFERENCES ai_access_rules(id) ON DELETE CASCADE
);

CREATE TABLE ai_exec_constraints (
  rule_id TEXT PRIMARY KEY,
  timeout_seconds INTEGER,
  FOREIGN KEY (rule_id) REFERENCES ai_access_rules(id) ON DELETE CASCADE
);

CREATE TABLE ai_sessions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  credential_fingerprint TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);

CREATE TABLE ai_oauth_clients (
  client_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  redirect_uris TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);

CREATE TABLE ai_oauth_codes (
  code_hash TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);

CREATE TABLE ai_oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  client_id TEXT,
  resource TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  fingerprint TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);

CREATE TABLE ai_oauth_pending (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  completion_token TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TEXT NOT NULL DEFAULT '',
  decision_at TEXT NOT NULL DEFAULT '',
  consumed_at TEXT NOT NULL DEFAULT '',
  code_plain TEXT NOT NULL DEFAULT '',
  source_addr TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);

CREATE TABLE ai_activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  principal_id TEXT,
  principal_name TEXT,
  endpoint_id TEXT,
  endpoint_name TEXT,
  capability TEXT NOT NULL,
  matched_rule TEXT,
  result TEXT NOT NULL,
  duration_ms INTEGER,
  revision INTEGER,
  operand_summary TEXT,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);

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

CREATE INDEX IF NOT EXISTS idx_ai_jobs_claim
  ON ai_jobs(status, client_id, created_at);

CREATE INDEX idx_objects_type ON objects(type);
CREATE INDEX idx_policy_plane_pos ON policy_rules(plane, position);
CREATE INDEX idx_ai_rules_pos ON ai_access_rules(position);
CREATE INDEX idx_ai_activity_principal ON ai_activity(principal_name, timestamp);
CREATE INDEX idx_audit_revision ON audit_events(revision);
"""


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA busy_timeout = %s" % BUSY_TIMEOUT_MS)
    try:
        conn.execute("PRAGMA trusted_schema = OFF")
    except sqlite3.Error:
        pass
    try:
        conn.execute("PRAGMA application_id = %s" % APPLICATION_ID)
    except sqlite3.Error:
        pass


def current_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if not row:
        return 0
    row = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
    return int(row[0] or 0)


def integrity_check(conn: sqlite3.Connection) -> None:
    row = conn.execute("PRAGMA integrity_check").fetchone()
    if not row or str(row[0]).lower() != "ok":
        raise DatabaseCorruptError(str(row[0]) if row else "integrity_check failed")
    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        raise DatabaseCorruptError("foreign key check failed (%s rows)" % len(fk))


def connect(path: Optional[Path] = None, root: Optional[str] = None, *, create: bool = True) -> sqlite3.Connection:
    target = Path(path) if path else db_path(root)
    if create:
        target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists() and not create:
        raise ControlPlaneError("Control DB does not exist: %s" % target)
    uri = "file:%s" % target
    conn = sqlite3.connect(
        uri, uri=True, isolation_level=None, timeout=BUSY_TIMEOUT_MS / 1000.0, check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    _apply_pragmas(conn)
    try:
        found = current_schema_version(conn) if target.exists() else 0
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise DatabaseCorruptError(str(exc)) from exc
    if found > SCHEMA_VERSION:
        conn.close()
        raise SchemaTooNewError(found, SCHEMA_VERSION)
    return conn


AI_AUTH_SQL = r"""
CREATE TABLE IF NOT EXISTS ai_oauth_clients (
  client_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  redirect_uris TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);
CREATE TABLE IF NOT EXISTS ai_oauth_codes (
  code_hash TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);
CREATE TABLE IF NOT EXISTS ai_oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  client_id TEXT,
  resource TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  fingerprint TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);
CREATE TABLE IF NOT EXISTS ai_oauth_pending (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  completion_token TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TEXT NOT NULL DEFAULT '',
  decision_at TEXT NOT NULL DEFAULT '',
  consumed_at TEXT NOT NULL DEFAULT '',
  code_plain TEXT NOT NULL DEFAULT '',
  source_addr TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (principal_id) REFERENCES ai_principals(id)
);
CREATE TABLE IF NOT EXISTS ai_oauth_dcr_clients (
  client_id TEXT PRIMARY KEY,
  redirect_uris TEXT NOT NULL DEFAULT '',
  token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
  client_secret_hash TEXT,
  client_name TEXT NOT NULL DEFAULT '',
  metadata_url TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
"""


def _ai_job_client_id_from_payload(payload_json: object) -> Optional[str]:
    """Extract a bindable client_id from legacy ai_jobs.payload_json.

    Returns a non-empty string only. Missing, malformed, or non-string values
    yield None so claim filtering cannot silently bind the wrong host.
    Does not use SQLite JSON1 (unavailable on Amazon Linux 2 Python builds).
    """
    if payload_json is None:
        return None
    try:
        raw = payload_json if isinstance(payload_json, str) else str(payload_json)
        doc = json.loads(raw)
    except (TypeError, ValueError, UnicodeError):
        return None
    if not isinstance(doc, dict):
        return None
    value = doc.get("client_id")
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def ensure_ai_jobs_safety_schema(conn: sqlite3.Connection) -> None:
    """Additive AI job fairness/attempt columns without bumping SCHEMA_VERSION."""
    cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(ai_jobs)")}
    if not cols:
        return
    for name, ddl in (
        ("client_id", "ALTER TABLE ai_jobs ADD COLUMN client_id TEXT"),
        ("deadline_at", "ALTER TABLE ai_jobs ADD COLUMN deadline_at TEXT"),
        ("claim_token", "ALTER TABLE ai_jobs ADD COLUMN claim_token TEXT"),
        ("attempt_id", "ALTER TABLE ai_jobs ADD COLUMN attempt_id TEXT"),
        ("claimed_at", "ALTER TABLE ai_jobs ADD COLUMN claimed_at TEXT"),
    ):
        if name not in cols:
            conn.execute(ddl)
    # Backfill target host from legacy payload JSON so claim can filter in SQL.
    # Use Python JSON parsing — Amazon Linux 2's Python sqlite3 build lacks the
    # SQLite JSON1 SQL functions, and Server init must not depend on them.
    rows = list(
        conn.execute(
            "SELECT id, payload_json FROM ai_jobs "
            "WHERE client_id IS NULL OR client_id = ''"
        )
    )
    for row in rows:
        job_id = row[0]
        client_id = _ai_job_client_id_from_payload(row[1])
        if client_id is None:
            continue
        conn.execute(
            "UPDATE ai_jobs SET client_id = ? WHERE id = ? "
            "AND (client_id IS NULL OR client_id = '')",
            (client_id, job_id),
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_jobs_claim "
        "ON ai_jobs(status, client_id, created_at)"
    )


def ensure_ai_auth_schema(conn: sqlite3.Connection) -> None:
    """Additive AI auth tables/columns without bumping SCHEMA_VERSION."""
    cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(ai_principals)")}
    if cols and "auth_mode" not in cols:
        conn.execute(
            "ALTER TABLE ai_principals ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'static-bearer'"
        )
    if cols and "oauth_issuer" not in cols:
        conn.execute("ALTER TABLE ai_principals ADD COLUMN oauth_issuer TEXT NOT NULL DEFAULT ''")
    if cols and "oauth_subject" not in cols:
        conn.execute("ALTER TABLE ai_principals ADD COLUMN oauth_subject TEXT NOT NULL DEFAULT ''")
    conn.executescript(AI_AUTH_SQL)
    tok_cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(ai_oauth_tokens)")}
    if tok_cols and "kind" not in tok_cols:
        conn.execute("ALTER TABLE ai_oauth_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'access'")
    if tok_cols and "rotated_from" not in tok_cols:
        conn.execute("ALTER TABLE ai_oauth_tokens ADD COLUMN rotated_from TEXT")
    ensure_oauth_pending_completion_schema(conn)
    ensure_enrollment_plans_schema(conn)
    ensure_ai_jobs_safety_schema(conn)


def ensure_oauth_pending_completion_schema(conn: sqlite3.Connection) -> None:
    """Additive OAuth pending browser-completion columns without SCHEMA_VERSION bump."""
    cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(ai_oauth_pending)")}
    if not cols:
        return
    for name, ddl in (
        ("completion_token", "ALTER TABLE ai_oauth_pending ADD COLUMN completion_token TEXT NOT NULL DEFAULT ''"),
        ("status", "ALTER TABLE ai_oauth_pending ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"),
        ("expires_at", "ALTER TABLE ai_oauth_pending ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''"),
        ("decision_at", "ALTER TABLE ai_oauth_pending ADD COLUMN decision_at TEXT NOT NULL DEFAULT ''"),
        ("consumed_at", "ALTER TABLE ai_oauth_pending ADD COLUMN consumed_at TEXT NOT NULL DEFAULT ''"),
        ("code_plain", "ALTER TABLE ai_oauth_pending ADD COLUMN code_plain TEXT NOT NULL DEFAULT ''"),
        ("source_addr", "ALTER TABLE ai_oauth_pending ADD COLUMN source_addr TEXT NOT NULL DEFAULT ''"),
    ):
        if name not in cols:
            conn.execute(ddl)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_oauth_pending_completion_token "
        "ON ai_oauth_pending(completion_token)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_oauth_pending_source_addr "
        "ON ai_oauth_pending(source_addr)"
    )


ENROLLMENT_PLANS_SQL = """
CREATE TABLE IF NOT EXISTS enrollment_plans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  platform TEXT NOT NULL DEFAULT 'linux',
  client_groups_json TEXT NOT NULL DEFAULT '[]',
  initial_services_json TEXT NOT NULL DEFAULT '[]',
  description TEXT NOT NULL DEFAULT '',
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""


def ensure_enrollment_plans_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(ENROLLMENT_PLANS_SQL)


def initialize(conn: sqlite3.Connection) -> None:
    from drlink_v24 import ensure_v2_schema

    found = current_schema_version(conn)
    if found > SCHEMA_VERSION:
        raise SchemaTooNewError(found, SCHEMA_VERSION)
    if found == SCHEMA_VERSION:
        ensure_ai_auth_schema(conn)
        ensure_v2_schema(conn)
        integrity_check(conn)
        return
    if found == 0:
        conn.executescript(SCHEMA_SQL)
        ensure_v2_schema(conn)
        now = utc_now_iso()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (1, "initial_control_plane", now),
            )
            conn.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (2, "v24_canonical_objects_policy", now),
            )
            conn.execute(
                "INSERT OR REPLACE INTO system_meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO system_meta(key, value) VALUES (?, ?)",
                ("created_at", now),
            )
            for plane, status in (
                ("remote", "active"),
                ("internet", "active"),
                ("ai", "not_configured"),
            ):
                conn.execute(
                    "INSERT OR REPLACE INTO runtime_generations"
                    "(plane, db_revision, generation, status, artifact_path, activated_at, error) "
                    "VALUES (?, 0, 0, ?, '', ?, '')",
                    (plane, status, now),
                )
            integrity_check(conn)
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        ensure_ai_auth_schema(conn)
        return
    if found == 1:
        ensure_v2_schema(conn)
        now = utc_now_iso()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (2, "v24_canonical_objects_policy", now),
            )
            conn.execute(
                "INSERT OR REPLACE INTO system_meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            integrity_check(conn)
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        ensure_ai_auth_schema(conn)
        return
    raise ControlPlaneError("Unknown control DB schema %s" % found)


def open_control_db(root: Optional[str] = None, *, create: bool = True) -> sqlite3.Connection:
    conn = connect(root=root, create=create)
    initialize(conn)
    return conn


def pragma_snapshot(conn: sqlite3.Connection) -> dict:
    out = {}
    for name, _expected in SUPPORTED_PRAGMAS:
        try:
            row = conn.execute("PRAGMA %s" % name).fetchone()
            out[name] = row[0] if row else None
        except sqlite3.Error:
            out[name] = None
    return out
