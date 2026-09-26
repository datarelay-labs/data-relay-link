#!/usr/bin/env python3
"""Data Relay Link v2.4 control plane: Objects, policy, AI Access, runtime.

SQLite is the SSOT. Runtime artifacts under /var/lib/drlink/runtime/ are derived.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from drlink_control_db import (
    SCHEMA_VERSION,
    ControlPlaneError,
    DatabaseCorruptError,
    SchemaTooNewError,
    db_path,
    ensure_ai_jobs_safety_schema,
    integrity_check,
    open_control_db,
    pragma_snapshot,
    runtime_dir,
    utc_now_iso,
)

class OAuthPendingCapacityError(ControlPlaneError):
    """Live pending OAuth transactions are at the admission cap."""

    oauth_error = "temporarily_unavailable"

    def __init__(self, scope: str):
        if scope not in ("client", "source", "global"):
            raise ValueError("invalid OAuth pending capacity scope: %s" % scope)
        self.scope = scope
        super().__init__(
            "too many pending OAuth authorizations; retry after existing requests expire or complete"
        )


NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
TAG_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BACKUP_FORMAT = "drlink-control-backup"
BACKUP_REQUIRED_TABLES = (
    "schema_migrations",
    "system_meta",
    "config_revisions",
    "runtime_generations",
    "clients",
    "objects",
    "published_services",
)
OAUTH_UNBOUND_PRINCIPAL = "__oauth_unbound__"
OAUTH_ACCESS_TTL = 3600
OAUTH_REFRESH_TTL = 30 * 24 * 3600
OAUTH_PENDING_TTL = 600
OAUTH_MAX_REDIRECTS = 16
# Live (unexpired) authorization transactions. Expired rows are reclaimed on admission.
OAUTH_PENDING_MAX_PER_CLIENT = 16
# One trusted admission source cannot consume the global pool by rotating clients.
OAUTH_PENDING_MAX_PER_SOURCE = 32
OAUTH_PENDING_MAX_GLOBAL = 128
CIMD_FETCH_TIMEOUT = 8
CIMD_FETCH_MAX_BYTES = 5 * 1024  # IETF CIMD draft recommended maximum
# Extra special-use destinations beyond ipaddress "public" flags (CGNAT, docs, etc.).
_CIMD_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
    )
)
FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
AI_CAPABILITIES = (
    "list_hosts",
    "get_host",
    "get_system_info",
    "exec",
    "read_file",
    "write_file",
    "upload_file",
    "download_file",
    "list_processes",
)
FILE_CAPABILITIES = frozenset({"read_file", "write_file", "upload_file", "download_file"})
AI_MUTATING_CAPABILITIES = frozenset({"exec", "write_file", "upload_file"})
AI_TERMINAL_JOB_STATUSES = frozenset(
    {"done", "timeout", "cancelled", "expired", "recovery_required"}
)
AI_ACTIVE_JOB_STATUSES = frozenset({"queued", "running"})
# Absolute claim/completion deadline includes MCP wait slack past the exec timeout.
AI_JOB_DISPATCH_GRACE_SECONDS = 10
# AI-executor freshness. This is not transport connectivity: a host can stay
# FRP-connected without a durable AI worker (macOS has no such worker in this
# release). Absence of AI polls must not be reported as Disconnected.
MANAGED_HOST_LIVENESS_SECONDS = 120
# Persist liveness well inside the TTL so claim polls do not rewrite the row
# on every poll. 30s is safely inside the 120s freshness bound.
MANAGED_HOST_LIVENESS_REFRESH_SECONDS = 30
MCP_AUTH_MODEL = "static-bearer+built-in-oauth2.1-as/rs+rfc9728"
OBJECT_TYPES = ("host", "network", "fqdn")
PLANES = ("remote", "internet")
POSITION_STEP = 1000

CONTEXT_MATRIX = {
    ("remote", "source"): frozenset({"host", "network", "fqdn", "managed_endpoint"}),
    ("remote", "destination"): frozenset({"host", "network", "fqdn", "managed_endpoint"}),
    ("internet", "source"): frozenset({"host", "network", "fqdn", "managed_endpoint"}),
    ("internet", "destination"): frozenset({"fqdn", "host", "network"}),
}


class ConfirmationRequired(ControlPlaneError):
    def __init__(self, message: str, impact: dict):
        super().__init__(message)
        self.impact = impact


class ConcurrencyError(ControlPlaneError):
    pass


def _new_id(prefix: str) -> str:
    return "%s_%s" % (prefix, secrets.token_hex(8))


def _parse_ai_job_ts(value: Optional[str]) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _ai_job_deadline_iso(now_iso: str, timeout_seconds: int) -> str:
    base = _parse_ai_job_ts(now_iso) or datetime.now(timezone.utc)
    delta = timedelta(seconds=max(0, int(timeout_seconds)))
    return (base + delta).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ai_job_deadline_passed(deadline_at: Optional[str], *, now_iso: Optional[str] = None) -> bool:
    deadline = _parse_ai_job_ts(deadline_at)
    if deadline is None:
        return False
    now = _parse_ai_job_ts(now_iso) if now_iso else datetime.now(timezone.utc)
    if now is None:
        now = datetime.now(timezone.utc)
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now >= deadline


def managed_host_liveness_fresh(last_seen: Optional[str], *, now_iso: Optional[str] = None) -> bool:
    """True when last_seen is within the Managed Host liveness bound."""
    seen = _parse_ai_job_ts(last_seen)
    if seen is None:
        return False
    now = _parse_ai_job_ts(now_iso) if now_iso else datetime.now(timezone.utc)
    if now is None:
        now = datetime.now(timezone.utc)
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    age = (now - seen).total_seconds()
    return 0 <= age <= MANAGED_HOST_LIVENESS_SECONDS


def _validate_name(value: str, kind: str = "name") -> str:
    text = str(value or "").strip()
    if not text:
        raise ControlPlaneError("%s is required" % kind)
    if not NAME_RE.fullmatch(text):
        raise ControlPlaneError(
            "%s must start with a letter and may contain letters, digits, '.', '_' and '-'"
            % kind
        )
    return text


def display_position(position: int) -> int:
    if position >= POSITION_STEP and position % 100 == 0:
        return position // 100
    return int(position)


def _actor() -> str:
    return os.environ.get("DRLINK_ACTOR") or os.environ.get("USER") or "root"


def _confirm_requested(confirm: Optional[bool]) -> bool:
    if confirm is True:
        return True
    env = str(os.environ.get("DRLINK_CONFIRM") or "").strip().lower()
    return env in ("yes", "y", "1", "true")


def normalize_object_value(obj_type: str, value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ControlPlaneError("Object value is required")
    kind = str(obj_type or "").strip().lower()
    if kind == "host":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise ControlPlaneError("Invalid host value: %s" % text) from exc
    if kind == "network":
        try:
            net = ipaddress.ip_network(text, strict=False)
            return str(net)
        except ValueError as exc:
            raise ControlPlaneError("Invalid network value: %s" % text) from exc
    if kind == "fqdn":
        host = text.rstrip(".").lower()
        if not FQDN_RE.fullmatch(host):
            raise ControlPlaneError("Invalid FQDN value: %s" % text)
        return host
    raise ControlPlaneError("Unknown object type: %s" % obj_type)


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_public_network(value: str) -> bool:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return False
    return is_public_ip(str(net.network_address)) and not (
        net.is_private or net.is_loopback or net.is_link_local or net.is_multicast
    )


def classify_address(address: str) -> str:
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return "special"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "special"
    if ip.is_private:
        return "private"
    return "public"


def membership_eligible(address: str) -> bool:
    return classify_address(address) in ("private", "public")


class ControlPlane:
    def __init__(self, root: Optional[str] = None, conn: Optional[sqlite3.Connection] = None):
        self.root = root
        self.db_file = db_path(root)
        self.runtime = runtime_dir(root)
        self.conn = conn or open_control_db(root)
        self._db_ident = self._db_file_ident()
        self._batch_mode = False
        self._batch_results: list = []
        # Serialize threaded MCP Bridge access to the shared SQLite connection.
        self._db_lock = threading.RLock()
        # Agent Bundle / nested Apply: Server-side Remote Service creates to
        # reverse if the local transaction rolls back. Not a distributed txn.
        self._agent_mgmt_side_effects: list = []

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _db_file_ident(self):
        try:
            st = os.stat(self.db_file)
            return (st.st_dev, st.st_ino)
        except OSError:
            return None

    def _ensure_live_conn(self) -> None:
        """Reopen SQLite when backup/restore replaced the database file.

        The long-lived MCP Bridge keeps a connection. Replacing drlink.db under
        that fd would otherwise keep serving the unlinked inode, and leftover
        WAL files from the old connection would replay onto the restored image.
        """
        ident = self._db_file_ident()
        if ident is None or ident == getattr(self, "_db_ident", None):
            return
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
        self.conn = open_control_db(self.root)
        self._db_ident = ident

    # --- revision / audit -------------------------------------------------
    def current_revision(self) -> int:
        row = self.conn.execute("SELECT COALESCE(MAX(revision), 0) FROM config_revisions").fetchone()
        return int(row[0] or 0)

    def _next_revision(self) -> int:
        return self.current_revision() + 1

    def _write_revision(self, command: str, summary: str, snapshot: Optional[dict] = None) -> int:
        rev = self._next_revision()
        now = utc_now_iso()
        self.conn.execute(
            "INSERT INTO config_revisions(revision, actor, command, created_at, summary) "
            "VALUES (?, ?, ?, ?, ?)",
            (rev, _actor(), command, now, summary),
        )
        payload = json.dumps(snapshot if snapshot is not None else {"revision": rev}, sort_keys=True)
        self.conn.execute(
            "INSERT INTO revision_snapshots(revision, snapshot_json) VALUES (?, ?)",
            (rev, payload),
        )
        return rev

    def _audit(
        self,
        *,
        revision: int,
        action: str,
        entity_type: str,
        entity_id: str,
        operation: str,
        result: str = "ok",
        before: str = "",
        after: str = "",
        impact: str = "",
    ) -> None:
        self.conn.execute(
            "INSERT INTO audit_events(timestamp, revision, actor, action, entity_type, "
            "entity_id, operation, before_summary, after_summary, impact_summary, result) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                utc_now_iso(),
                revision,
                _actor(),
                action,
                entity_type,
                entity_id,
                operation,
                before,
                after,
                impact,
                result,
            ),
        )

    def _pre_activation_checkpoint(self) -> dict:
        """Snapshot authoritative DB + runtime artifacts before a mutating Apply."""
        runtime_snap: dict[str, bytes] = {}
        if self.runtime.exists():
            for path in self.runtime.iterdir():
                if path.is_file():
                    try:
                        runtime_snap[path.name] = path.read_bytes()
                    except OSError:
                        pass
        fd, backup_path = tempfile.mkstemp(prefix="drlink-act-", suffix=".tar")
        os.close(fd)
        try:
            self.backup(backup_path)
        except Exception:
            try:
                os.unlink(backup_path)
            except OSError:
                pass
            raise
        return {
            "backup": backup_path,
            "runtime": runtime_snap,
            "revision": self.current_revision(),
        }

    def _restore_db_only(self, backup_path: str) -> None:
        """Restore DB from a control backup without re-entering activation."""
        self.backup_validate(backup_path)
        with tarfile.open(backup_path, "r") as tar:
            db_member = tar.extractfile("drlink.db")
            if db_member is None:
                raise ControlPlaneError("backup drlink.db unreadable")
            payload = db_member.read()
        # Close live connection so the on-disk DB can be replaced safely.
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
        self.conn = None
        db_file = Path(self.db_file)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        # Remove WAL/SHM companions from the previous connection.
        for suffix in ("", "-wal", "-shm"):
            companion = Path(str(db_file) + suffix) if suffix else db_file
            if suffix:
                try:
                    companion.unlink()
                except FileNotFoundError:
                    pass
        tmp = db_file.with_suffix(db_file.suffix + ".restore-tmp")
        tmp.write_bytes(payload)
        os.replace(str(tmp), str(db_file))
        self.conn = open_control_db(self.root)
        self._db_ident = self._db_file_ident()

    def _rollback_activation(self, checkpoint: dict) -> None:
        if str(os.environ.get("DRLINK_FAULT_ROLLBACK") or "").strip().lower() in (
            "1",
            "yes",
            "y",
            "true",
        ):
            raise ControlPlaneError("simulated rollback failure")
        backup_path = checkpoint.get("backup")
        if not backup_path:
            raise ControlPlaneError("activation checkpoint missing")
        self._restore_db_only(str(backup_path))
        self.runtime.mkdir(parents=True, exist_ok=True)
        wanted = set((checkpoint.get("runtime") or {}).keys())
        for path in list(self.runtime.iterdir()):
            if path.is_file() and path.name not in wanted:
                try:
                    path.unlink()
                except OSError:
                    pass
        for name, data in (checkpoint.get("runtime") or {}).items():
            target = self.runtime / name
            target.write_bytes(data)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass

    def _cleanup_activation_checkpoint(self, checkpoint: Optional[dict]) -> None:
        if not checkpoint:
            return
        path = checkpoint.get("backup")
        if path:
            try:
                os.unlink(str(path))
            except OSError:
                pass

    def _activation_should_run(self) -> bool:
        return str(os.environ.get("DRLINK_SKIP_ACTIVATION") or "").strip().lower() not in (
            "1",
            "yes",
            "y",
            "true",
        )

    def _forced_activation_failure(self) -> bool:
        return str(os.environ.get("DRLINK_FAULT_ACTIVATION") or "").strip().lower() in (
            "1",
            "yes",
            "y",
            "true",
        )

    def _forced_restore_failure(self) -> bool:
        return str(os.environ.get("DRLINK_FAULT_RESTORE") or "").strip().lower() in (
            "1",
            "yes",
            "y",
            "true",
        )

    def _commit_open_transaction(self) -> None:
        """COMMIT only when this connection still owns an open transaction."""
        try:
            if self.conn is not None and self.conn.in_transaction:
                self.conn.execute("COMMIT")
        except sqlite3.OperationalError as exc:
            if "no transaction is active" not in str(exc).lower():
                raise

    def _rollback_open_transaction(self) -> None:
        """ROLLBACK only when this connection still owns an open transaction."""
        try:
            if self.conn is not None and self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
        except sqlite3.OperationalError as exc:
            if "no transaction is active" not in str(exc).lower():
                raise

    def commit_if_autonomous(self) -> None:
        """Commit only when this plane is not participating in an outer batch."""
        if self._batch_mode:
            return
        self._commit_open_transaction()

    def _mutate(
        self,
        command: str,
        summary: str,
        writer: Callable[[], Any],
        *,
        expected: Optional[dict] = None,
        impact: Optional[dict] = None,
        confirm: Optional[bool] = None,
        compile_runtime: bool = True,
    ) -> Any:
        if impact and not _confirm_requested(confirm):
            needs_confirm = bool(
                impact.get("access_broadened")
                or impact.get("access_narrowed")
                or impact.get("requires_confirmation")
            )
            if needs_confirm and not self._batch_mode:
                raise ConfirmationRequired(self._format_impact(impact), impact)
        if self._batch_mode:
            if expected:
                for table, entity_id, version in expected.get("rows") or ():
                    row = self.conn.execute(
                        "SELECT row_version FROM %s WHERE id = ?" % table, (entity_id,)
                    ).fetchone()
                    if row is None or int(row["row_version"]) != int(version):
                        raise ConcurrencyError(
                            "Object changed while you were editing it.\n"
                            "No changes were applied.\n"
                            "Review current state and retry."
                        )
            result = writer()
            self._batch_results.append(result)
            return result
        checkpoint = None
        if compile_runtime and self._activation_should_run():
            checkpoint = self._pre_activation_checkpoint()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if expected:
                for table, entity_id, version in expected.get("rows") or ():
                    row = self.conn.execute(
                        "SELECT row_version FROM %s WHERE id = ?" % table, (entity_id,)
                    ).fetchone()
                    if row is None:
                        raise ControlPlaneError("Object changed while you were editing it.\nNo changes were applied.\nReview current state and retry.")
                    if int(row["row_version"]) != int(version):
                        raise ConcurrencyError(
                            "Object changed while you were editing it.\n"
                            "No changes were applied.\n"
                            "Review current state and retry."
                        )
            result = writer()
            rev = self._write_revision(command, summary, snapshot={"summary": summary})
            if isinstance(result, dict):
                result["revision"] = rev
                entity = result.get("entity") or {}
                self._audit(
                    revision=rev,
                    action=command,
                    entity_type=str(entity.get("type") or "control"),
                    entity_id=str(entity.get("id") or entity.get("name") or ""),
                    operation=str(result.get("operation") or command),
                    after=str(result.get("after") or summary),
                    impact=json.dumps(impact or {}, sort_keys=True)[:2000],
                )
            else:
                self._audit(
                    revision=rev,
                    action=command,
                    entity_type="control",
                    entity_id="",
                    operation=command,
                    after=summary,
                    impact=json.dumps(impact or {}, sort_keys=True)[:2000],
                )
            self._commit_open_transaction()
        except ConfirmationRequired:
            self._rollback_open_transaction()
            self._cleanup_activation_checkpoint(checkpoint)
            raise
        except ConcurrencyError:
            self._rollback_open_transaction()
            self._cleanup_activation_checkpoint(checkpoint)
            raise
        except ControlPlaneError:
            self._rollback_open_transaction()
            self._cleanup_activation_checkpoint(checkpoint)
            raise
        except Exception as exc:
            self._rollback_open_transaction()
            self._cleanup_activation_checkpoint(checkpoint)
            if isinstance(exc, sqlite3.IntegrityError) and "foreign key" in str(exc).lower():
                raise ControlPlaneError(
                    "ERROR:\nCannot apply this change because a referenced dependency still exists.\n\n"
                    "No changes were applied.\n\n"
                    "Remove dependent Rules or Groups first, or include them in the same "
                    "ConfigurationBundle with dependency-aware delete ordering."
                ) from exc
            raise ControlPlaneError("No changes were applied. %s" % exc) from exc
        if compile_runtime and self._activation_should_run():
            try:
                if self._forced_activation_failure():
                    raise ControlPlaneError("simulated activation failure")
                self.compile_runtime()
            except Exception:
                try:
                    self._rollback_activation(checkpoint or {})
                except Exception:
                    self._mark_generation_failed("activation failed; rollback incomplete")
                    self._cleanup_activation_checkpoint(checkpoint)
                    raise ControlPlaneError(
                        "ERROR:\nApply failed and automatic rollback was not fully successful.\n\n"
                        "The current runtime state may require operator attention.\n\n"
                        "Run:\n  system diagnostics"
                    ) from None
                self._cleanup_activation_checkpoint(checkpoint)
                raise ControlPlaneError(
                    "ERROR:\nRuntime activation failed.\n\n"
                    "Previous configuration was restored.\n"
                    "No configuration changes remain active."
                ) from None
            self._cleanup_activation_checkpoint(checkpoint)
        else:
            self._cleanup_activation_checkpoint(checkpoint)
        return result

    def _format_impact(self, impact: dict) -> str:
        if impact.get("kind") == "managed-host-retire":
            lines = [
                str(impact.get("warning") or "Managed Host will be removed"),
                "",
                "Host: %s" % (impact.get("host") or "-"),
            ]
            if impact.get("cleanup"):
                lines.append("")
                lines.append("Cleanup:")
                for item in impact["cleanup"]:
                    lines.append("  %s" % item)
            if impact.get("before") or impact.get("after"):
                lines.append("")
                lines.append("Before:")
                lines.append("  %s" % (impact.get("before") or "-"))
                lines.append("")
                lines.append("After:")
                lines.append("  %s" % (impact.get("after") or "Host removed"))
            lines.append("")
            lines.append("Continue? [y/N]:")
            return "\n".join(lines)
        lines = [
            "Policy behavior will change",
            "",
        ]
        if impact.get("warning"):
            lines.append(str(impact["warning"]))
            lines.append("")
        if impact.get("adding"):
            lines.append("Adding:")
            for item in impact["adding"]:
                lines.append("  %s" % item)
            lines.append("")
        lines.append("Access broadened: %s" % ("YES" if impact.get("access_broadened") else "NO"))
        lines.append("Access narrowed: %s" % ("YES" if impact.get("access_narrowed") else "NO"))
        if impact.get("affected_rules"):
            lines.append("")
            lines.append("Affected Rule:")
            for name in impact["affected_rules"]:
                lines.append("  %s" % name)
        if impact.get("before") or impact.get("after"):
            lines.append("")
            lines.append("Before:")
            lines.append("  %s" % (impact.get("before") or "DENY"))
            lines.append("")
            lines.append("After:")
            lines.append("  %s" % (impact.get("after") or "ALLOW"))
        lines.append("")
        lines.append("Continue? [y/N]:")
        return "\n".join(lines)

    # --- lookups ----------------------------------------------------------
    def get_object(self, name: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM objects WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()

    def require_object(self, name: str) -> sqlite3.Row:
        row = self.get_object(name)
        if row is None:
            raise ControlPlaneError("Object not found: %s" % name)
        return row

    def get_object_group(self, name: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM object_groups WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()

    def get_client(self, selector: str) -> Optional[sqlite3.Row]:
        text = str(selector or "").strip()
        if not text:
            return None
        row = self.conn.execute("SELECT * FROM clients WHERE id = ?", (text,)).fetchone()
        if row:
            return row
        rows = self.conn.execute(
            "SELECT * FROM clients WHERE id LIKE ?", (text + "%",)
        ).fetchall()
        if len(rows) == 1:
            return rows[0]
        if len(rows) > 1:
            raise ControlPlaneError("multiple clients matched")
        rows = self.conn.execute(
            "SELECT * FROM clients WHERE lower(label) = lower(?)", (text,)
        ).fetchall()
        if len(rows) == 1:
            return rows[0]
        row = self.get_object(text)
        if row and row["type"] == "managed_endpoint":
            ep = self.conn.execute(
                "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                (row["id"],),
            ).fetchone()
            if ep and ep["client_id"]:
                return self.conn.execute(
                    "SELECT * FROM clients WHERE id = ?", (ep["client_id"],)
                ).fetchone()
        return None

    def require_client(self, selector: str) -> sqlite3.Row:
        row = self.get_client(selector)
        if row is None:
            raise ControlPlaneError("client not found: %s" % selector)
        return row

    def resolve_ref(self, token: str) -> tuple[str, sqlite3.Row]:
        text = str(token or "").strip()
        obj = self.get_object(text)
        grp = self.get_object_group(text)
        if obj is not None and grp is not None:
            raise ControlPlaneError(
                "ERROR:\nPublic name '%s' is ambiguous because both a Network Object "
                "and a Network Group exist.\n\n"
                "Rename or remove one of them so the selector is unique.\n\n"
                "No changes were applied." % text
            )
        if obj is not None:
            return "object", obj
        if grp is not None:
            return "group", grp
        raise ControlPlaneError("Object or Object Group not found: %s" % token)

    # --- objects ----------------------------------------------------------
    def list_objects(self) -> list[dict]:
        rows = []
        for obj in self.conn.execute("SELECT * FROM objects ORDER BY name").fetchall():
            rows.append(self._object_view(obj))
        return rows

    def _object_values(self, object_id: str) -> list[str]:
        return [
            r["value"]
            for r in self.conn.execute(
                "SELECT value FROM object_values WHERE object_id = ? ORDER BY value",
                (object_id,),
            )
        ]

    def _object_view(self, obj: sqlite3.Row) -> dict:
        values = self._object_values(obj["id"])
        view = {
            "id": obj["id"],
            "name": obj["name"],
            "type": obj["type"],
            "origin": obj["origin"],
            "description": obj["description"],
            "status": obj["status"],
            "orphan_reason": obj["orphan_reason"],
            "row_version": obj["row_version"],
            "values": values,
        }
        if obj["type"] == "managed_endpoint":
            ep = self.conn.execute(
                "SELECT * FROM managed_endpoints WHERE object_id = ?", (obj["id"],)
            ).fetchone()
            view["client_id"] = ep["client_id"] if ep else None
            view["addresses"] = self.endpoint_addresses(obj["name"])
        return view

    def object_type_valid_for(self, obj: sqlite3.Row, plane: str, field: str) -> bool:
        allowed = CONTEXT_MATRIX.get((plane, field), frozenset())
        if obj["type"] not in allowed:
            return False
        if plane == "internet" and field == "destination":
            if obj["type"] == "managed_endpoint":
                return False
            if obj["type"] == "host":
                return all(is_public_ip(v) for v in self._object_values(obj["id"])) if self._object_values(obj["id"]) else True
            if obj["type"] == "network":
                return all(is_public_network(v) for v in self._object_values(obj["id"])) if self._object_values(obj["id"]) else True
        return True

    def _expand_group_members(self, group_id: str, seen: Optional[set] = None) -> list[sqlite3.Row]:
        seen = seen if seen is not None else set()
        if group_id in seen:
            raise ControlPlaneError("Object Group cycle detected.")
        seen.add(group_id)
        out = []
        for mem in self.conn.execute(
            "SELECT * FROM object_group_members WHERE group_id = ? "
            "ORDER BY member_kind, member_id",
            (group_id,),
        ):
            if mem["member_kind"] == "object":
                obj = self.conn.execute(
                    "SELECT * FROM objects WHERE id = ?", (mem["member_id"],)
                ).fetchone()
                if obj:
                    out.append(obj)
            else:
                out.extend(self._expand_group_members(mem["member_id"], seen))
        # Stable leaf order for public policy-test expansion (Finding Y).
        out.sort(key=lambda row: str(row["name"] or "").lower())
        return out

    def group_valid_for(self, group: sqlite3.Row, plane: str, field: str) -> tuple[bool, str]:
        members = self._expand_group_members(group["id"], set())
        for obj in members:
            if not self.object_type_valid_for(obj, plane, field):
                return False, obj["name"]
        return True, ""

    def set_object_type(self, name: str, obj_type: str, *, confirm: Optional[bool] = None) -> dict:
        obj_type = str(obj_type or "").strip().lower()
        if obj_type == "managed_endpoint" or obj_type in ("managed", "endpoint"):
            raise ControlPlaneError(
                "Managed Host is not a creatable Object type.\n"
                "Managed Hosts follow the Managed Host lifecycle."
            )
        if obj_type not in OBJECT_TYPES:
            raise ControlPlaneError("Object type must be host, network, or fqdn")
        name = _validate_name(name, "Object name")

        def write():
            existing = self.get_object(name)
            if existing:
                if existing["origin"] == "managed":
                    raise ControlPlaneError("Cannot change type of a Managed Host through Object CRUD.")
                values = self._object_values(existing["id"])
                refs = self.object_references(existing["name"])
                if existing["type"] != obj_type and (values or refs):
                    raise ControlPlaneError(
                        "Static Object type cannot change after values or references exist.\n"
                        "No changes were applied."
                    )
                self.conn.execute(
                    "UPDATE objects SET type = ?, row_version = row_version + 1, "
                    "updated_at = ?, updated_revision = ? WHERE id = ?",
                    (obj_type, utc_now_iso(), self._next_revision(), existing["id"]),
                )
                return {"entity": {"type": "object", "id": existing["id"], "name": name}, "operation": "set-type", "after": obj_type}
            if self.get_object_group(name):
                raise ControlPlaneError(
                    "ERROR:\nPublic name '%s' is already used by a Network Group.\n\n"
                    "Network Object and Network Group names must be unique across that "
                    "selector namespace.\n\n"
                    "No changes were applied." % name
                )
            oid = _new_id("obj")
            now = utc_now_iso()
            self.conn.execute(
                "INSERT INTO objects(id, name, type, origin, description, status, row_version, "
                "created_at, updated_at) VALUES (?, ?, ?, 'static', '', 'active', 1, ?, ?)",
                (oid, name, obj_type, now, now),
            )
            return {"entity": {"type": "object", "id": oid, "name": name}, "operation": "create", "after": obj_type}

        return self._mutate("set object %s type %s" % (name, obj_type), "create/set object type", write, confirm=confirm)

    def set_object_value(self, name: str, value: str, *, confirm: Optional[bool] = None, expected_row_version: Optional[int] = None) -> dict:
        obj = self.require_object(name)
        if obj["origin"] == "managed":
            raise ControlPlaneError("Cannot edit Managed Host values through Object CRUD.")
        normalized = normalize_object_value(obj["type"], value)
        impact = self._value_add_impact(obj, normalized)

        def write():
            cur = self.conn.execute("SELECT * FROM objects WHERE id = ?", (obj["id"],)).fetchone()
            if expected_row_version is not None and int(cur["row_version"]) != int(expected_row_version):
                raise ConcurrencyError(
                    "Object changed while you were editing it.\n"
                    "No changes were applied.\n"
                    "Review current state and retry."
                )
            exists = self.conn.execute(
                "SELECT 1 FROM object_values WHERE object_id = ? AND normalized = ?",
                (obj["id"], normalized),
            ).fetchone()
            if exists:
                return {"entity": {"type": "object", "id": obj["id"], "name": obj["name"]}, "operation": "noop", "after": normalized}
            self.conn.execute(
                "INSERT INTO object_values(object_id, value, normalized) VALUES (?, ?, ?)",
                (obj["id"], value.strip(), normalized),
            )
            self.conn.execute(
                "UPDATE objects SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), obj["id"]),
            )
            return {
                "entity": {"type": "object", "id": obj["id"], "name": obj["name"]},
                "operation": "add-value",
                "after": normalized,
            }

        expected = None
        if expected_row_version is not None:
            expected = {"rows": [("objects", obj["id"], expected_row_version)]}
        return self._mutate(
            "set object %s value %s" % (name, normalized),
            "add object value",
            write,
            expected=expected,
            impact=impact,
            confirm=confirm,
        )

    def replace_object_value(
        self,
        name: str,
        value: str,
        *,
        confirm: Optional[bool] = None,
        expected_row_version: Optional[int] = None,
        impact: Optional[dict] = None,
    ) -> dict:
        """Public v2.4 Network Object edit: one object → one canonical value.

        Replaces every stored value atomically. Managed Host objects are rejected.
        Legacy multi-value add remains on set_object_value() for compatibility.
        """
        obj = self.require_object(name)
        if obj["origin"] == "managed":
            raise ControlPlaneError("Cannot edit Managed Host values through Object CRUD.")
        normalized = normalize_object_value(obj["type"], value)
        current = [
            r["normalized"]
            for r in self.conn.execute(
                "SELECT normalized FROM object_values WHERE object_id = ? ORDER BY normalized",
                (obj["id"],),
            )
        ]
        if current == [normalized]:
            return {
                "entity": {"type": "object", "id": obj["id"], "name": obj["name"]},
                "operation": "noop",
                "after": normalized,
            }
        if impact is None:
            try:
                import drlink_v24 as v24

                impact = v24.referenced_selector_mutation_security_impact(
                    self,
                    kind="network-object",
                    name=name,
                    value=value,
                )
            except Exception:
                impact = self._value_add_impact(obj, normalized)
            if impact is None:
                impact = self._value_add_impact(obj, normalized)

        def write():
            cur = self.conn.execute("SELECT * FROM objects WHERE id = ?", (obj["id"],)).fetchone()
            if expected_row_version is not None and int(cur["row_version"]) != int(expected_row_version):
                raise ConcurrencyError(
                    "Object changed while you were editing it.\n"
                    "No changes were applied.\n"
                    "Review current state and retry."
                )
            self.conn.execute("DELETE FROM object_values WHERE object_id = ?", (obj["id"],))
            self.conn.execute(
                "INSERT INTO object_values(object_id, value, normalized) VALUES (?, ?, ?)",
                (obj["id"], value.strip(), normalized),
            )
            self.conn.execute(
                "UPDATE objects SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), obj["id"]),
            )
            try:
                from drlink_upgrade_reconcile import (
                    rematerialize_fixed_tcp_for_object,
                    rematerialize_published_targets_for_destination_name,
                )

                rematerialize_published_targets_for_destination_name(self, obj["name"])
                rematerialize_fixed_tcp_for_object(self, obj["id"])
            except Exception:
                pass
            return {
                "entity": {"type": "object", "id": obj["id"], "name": obj["name"]},
                "operation": "replace-value",
                "after": normalized,
            }

        expected = None
        if expected_row_version is not None:
            expected = {"rows": [("objects", obj["id"], expected_row_version)]}
        return self._mutate(
            "set object %s value %s" % (name, normalized),
            "replace object value",
            write,
            expected=expected,
            impact=impact,
            confirm=confirm,
        )

    def _value_add_impact(self, obj: sqlite3.Row, value: str) -> dict:
        refs = self.object_references(obj["name"])
        allow_rules = [r for r in refs if r.get("action") == "allow" and r.get("enabled")]
        broadened = bool(allow_rules)
        names = [r["name"] for r in allow_rules]
        return {
            "access_broadened": broadened,
            "access_narrowed": False,
            "adding": [value],
            "affected_rules": names,
            "before": "DENY",
            "after": ("ALLOW via %s" % names[0]) if names else "unchanged",
        }

    def unset_object_value(self, name: str, value: str, *, confirm: Optional[bool] = None) -> dict:
        obj = self.require_object(name)
        if obj["origin"] == "managed":
            raise ControlPlaneError("Cannot edit Managed Host values through Object CRUD.")
        normalized = normalize_object_value(obj["type"], value)

        def write():
            cur = self.conn.execute(
                "DELETE FROM object_values WHERE object_id = ? AND (value = ? OR normalized = ?)",
                (obj["id"], value.strip(), normalized),
            )
            if cur.rowcount < 1:
                raise ControlPlaneError("Value not found on Object %s" % name)
            self.conn.execute(
                "UPDATE objects SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), obj["id"]),
            )
            return {"entity": {"type": "object", "id": obj["id"], "name": name}, "operation": "remove-value", "after": normalized}

        return self._mutate("unset object %s value %s" % (name, normalized), "remove object value", write, confirm=confirm)

    def set_object_description(self, name: str, text: str) -> dict:
        obj = self.require_object(name)

        def write():
            self.conn.execute(
                "UPDATE objects SET description = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (str(text or ""), utc_now_iso(), obj["id"]),
            )
            return {"entity": {"type": "object", "id": obj["id"], "name": name}, "operation": "description"}

        return self._mutate("set object %s description" % name, "set description", write)

    def rename_object(self, name: str, new_name: str) -> dict:
        obj = self.require_object(name)
        new_name = _validate_name(new_name, "Object name")
        if obj["origin"] == "managed":
            raise ControlPlaneError("Rename a Managed Host with set managed-host / client label, not Object CRUD.")

        def write():
            clash = self.get_object(new_name)
            if clash and clash["id"] != obj["id"]:
                raise ControlPlaneError("Object already exists: %s" % new_name)
            self.conn.execute(
                "UPDATE objects SET name = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (new_name, utc_now_iso(), obj["id"]),
            )
            return {"entity": {"type": "object", "id": obj["id"], "name": new_name}, "operation": "rename", "after": new_name}

        return self._mutate("set object %s name %s" % (name, new_name), "rename object", write)

    def object_references(self, name: str) -> list[dict]:
        obj = self.require_object(name)
        refs = []
        for table, kind in (("rule_sources", "source"), ("rule_destinations", "destination")):
            for row in self.conn.execute(
                "SELECT r.plane, r.name, r.action, r.enabled, r.position FROM %s s "
                "JOIN policy_rules r ON r.id = s.rule_id "
                "WHERE s.ref_kind = 'object' AND s.ref_id = ?" % table,
                (obj["id"],),
            ):
                family = "Remote Access" if row["plane"] == "remote" else "Internet Access"
                refs.append(
                    {
                        "kind": "policy",
                        "plane": row["plane"],
                        "name": row["name"],
                        "field": kind,
                        "action": row["action"],
                        "enabled": bool(row["enabled"]),
                        "section": family,
                        "display": "%s: %s" % (family, row["name"]),
                    }
                )
        for row in self.conn.execute(
            "SELECT g.name FROM object_group_members m JOIN object_groups g ON g.id = m.group_id "
            "WHERE m.member_kind = 'object' AND m.member_id = ?",
            (obj["id"],),
        ):
            refs.append(
                {
                    "kind": "object-group",
                    "name": row["name"],
                    "section": "Network Groups",
                    "display": "Network Group: %s" % row["name"],
                }
            )
        for row in self.conn.execute(
            "SELECT name FROM fixed_tcp WHERE destination_object_id = ?", (obj["id"],)
        ):
            refs.append(
                {
                    "kind": "fixed-tcp",
                    "name": row["name"],
                    "section": "Fixed TCP",
                    "display": "Fixed TCP: %s" % row["name"],
                }
            )
        if obj["type"] == "managed_endpoint":
            for row in self.conn.execute(
                "SELECT r.name FROM ai_rule_targets t JOIN ai_access_rules r ON r.id = t.rule_id "
                "WHERE t.target_kind = 'endpoint' AND t.target_id = ?",
                (obj["id"],),
            ):
                refs.append(
                    {
                        "kind": "ai-access",
                        "name": row["name"],
                        "section": "AI Access",
                        "display": "AI Access: %s" % row["name"],
                    }
                )
            for row in self.conn.execute(
                "SELECT r.name FROM ai_policy_rules r "
                "WHERE r.destination_ref_kind = 'object' AND r.destination_ref_id = ?",
                (obj["id"],),
            ):
                refs.append(
                    {
                        "kind": "ai-access",
                        "name": row["name"],
                        "section": "AI Access",
                        "display": "AI Access: %s" % row["name"],
                    }
                )
            # Cross-host Remote Services bound by immutable Managed Host client_id.
            link = self.conn.execute(
                "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                (obj["id"],),
            ).fetchone()
            bound_cid = link["client_id"] if link and link["client_id"] else None
            if bound_cid:
                for row in self.conn.execute(
                    "SELECT s.name AS service_name, c.label AS owner_label, c.hostname AS owner_hostname, "
                    "c.id AS owner_id "
                    "FROM remote_service_meta m "
                    "JOIN published_services s ON s.id = m.service_id "
                    "JOIN clients c ON c.id = s.client_id "
                    "WHERE m.destination_client_id = ? AND IFNULL(s.released, 0) = 0 "
                    "ORDER BY s.name",
                    (bound_cid,),
                ):
                    owner = row["owner_label"] or row["owner_hostname"] or row["owner_id"][:8]
                    refs.append(
                        {
                            "kind": "remote-service",
                            "name": row["service_name"],
                            "owner": owner,
                            "section": "Remote Services",
                            "display": "Remote Service: %s (Agent %s)"
                            % (row["service_name"], owner),
                        }
                    )
        return refs

    def unset_object(self, name: str) -> dict:
        obj = self.require_object(name)
        if obj["origin"] == "managed":
            raise ControlPlaneError(
                "Cannot remove Managed Host %s through Object CRUD.\n"
                "Use: unset managed-host %s"
                % (name, name)
            )
        refs = self.object_references(name)
        if refs:
            listed = "\n".join("  %s" % r["display"] for r in refs)
            raise ControlPlaneError(
                "Cannot remove Object %s.\n\nReferenced by:\n%s\n\nNo changes were applied."
                % (name, listed)
            )

        def write():
            self.conn.execute("DELETE FROM object_values WHERE object_id = ?", (obj["id"],))
            self.conn.execute("DELETE FROM objects WHERE id = ?", (obj["id"],))
            return {"entity": {"type": "object", "id": obj["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset object %s" % name, "delete object", write)

    def format_object(self, name: str) -> str:
        view = self._object_view(self.require_object(name))
        type_label = {
            "host": "Host",
            "network": "Network",
            "fqdn": "FQDN",
            "managed_endpoint": "Managed Host",
        }.get(view["type"], view["type"])
        origin = "Data Relay" if view["origin"] == "managed" else "Static"
        lines = [
            "Object: %s" % view["name"],
            "Type  : %s" % type_label,
            "Origin: %s" % origin,
        ]
        if view.get("status") == "orphaned":
            lines.append("Status: Orphaned")
            if view.get("orphan_reason"):
                lines.append("Reason: %s" % view["orphan_reason"])
        if view.get("description"):
            lines.append("Description: %s" % view["description"])
        lines.extend(["", "Values", "------"])
        if view["values"]:
            lines.extend(view["values"])
        else:
            lines.append("(none)")
        return "\n".join(lines) + "\n"

    # --- object groups ----------------------------------------------------
    def set_object_group(self, name: str, description: Optional[str] = None) -> dict:
        name = _validate_name(name, "Object Group name")

        def write():
            existing = self.get_object_group(name)
            now = utc_now_iso()
            if existing:
                if description is not None:
                    self.conn.execute(
                        "UPDATE object_groups SET description = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                        (description, now, existing["id"]),
                    )
                return {"entity": {"type": "object-group", "id": existing["id"], "name": name}, "operation": "update"}
            if self.get_object(name):
                raise ControlPlaneError(
                    "ERROR:\nPublic name '%s' is already used by a Network Object.\n\n"
                    "Network Object and Network Group names must be unique across that "
                    "selector namespace.\n\n"
                    "No changes were applied." % name
                )
            gid = _new_id("ogp")
            self.conn.execute(
                "INSERT INTO object_groups(id, name, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?)",
                (gid, name, description or "", now, now),
            )
            return {"entity": {"type": "object-group", "id": gid, "name": name}, "operation": "create"}

        return self._mutate("set object-group %s" % name, "create object group", write)

    def _group_cycle_path(self, start_id: str, adding_member_id: str) -> Optional[list[str]]:
        names = {}
        for row in self.conn.execute("SELECT id, name FROM object_groups"):
            names[row["id"]] = row["name"]
        graph = {gid: [] for gid in names}
        for mem in self.conn.execute(
            "SELECT group_id, member_id FROM object_group_members WHERE member_kind = 'group'"
        ):
            graph.setdefault(mem["group_id"], []).append(mem["member_id"])
        graph.setdefault(start_id, []).append(adding_member_id)

        def dfs(node, stack):
            if node in stack:
                cycle = stack[stack.index(node) :] + [node]
                return [names.get(i, i) for i in cycle]
            stack.append(node)
            for nxt in graph.get(node, []):
                found = dfs(nxt, stack)
                if found:
                    return found
            stack.pop()
            return None

        return dfs(start_id, [])

    def set_object_group_member(self, group_name: str, member: str) -> dict:
        grp = self.get_object_group(group_name)
        if grp is None:
            self.set_object_group(group_name)
            grp = self.get_object_group(group_name)
        kind, ref = self.resolve_ref(member)
        if kind == "group" and ref["id"] == grp["id"]:
            raise ControlPlaneError(
                "Object Group cycle detected.\n\n%s → %s\n\nNo changes were applied."
                % (group_name, member)
            )
        if kind == "group":
            cycle = self._group_cycle_path(grp["id"], ref["id"])
            if cycle:
                raise ControlPlaneError(
                    "Object Group cycle detected.\n\n%s\n\nNo changes were applied."
                    % " → ".join(cycle)
                )

        def write():
            self.conn.execute(
                "INSERT OR IGNORE INTO object_group_members(group_id, member_kind, member_id) VALUES (?, ?, ?)",
                (grp["id"], kind, ref["id"]),
            )
            self.conn.execute(
                "UPDATE object_groups SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), grp["id"]),
            )
            return {"entity": {"type": "object-group", "id": grp["id"], "name": grp["name"]}, "operation": "add-member", "after": member}

        return self._mutate("set object-group %s member %s" % (group_name, member), "add group member", write)

    def unset_object_group_member(self, group_name: str, member: str) -> dict:
        grp = self.get_object_group(group_name)
        if grp is None:
            raise ControlPlaneError("Object Group not found: %s" % group_name)
        kind, ref = self.resolve_ref(member)

        def write():
            self.conn.execute(
                "DELETE FROM object_group_members WHERE group_id = ? AND member_kind = ? AND member_id = ?",
                (grp["id"], kind, ref["id"]),
            )
            self.conn.execute(
                "UPDATE object_groups SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), grp["id"]),
            )
            return {"entity": {"type": "object-group", "id": grp["id"], "name": group_name}, "operation": "remove-member"}

        return self._mutate("unset object-group %s member %s" % (group_name, member), "remove group member", write)

    def unset_object_group(self, name: str) -> dict:
        grp = self.get_object_group(name)
        if grp is None:
            raise ControlPlaneError("Object Group not found: %s" % name)
        refs = []
        for table in ("rule_sources", "rule_destinations"):
            for row in self.conn.execute(
                "SELECT r.plane, r.name FROM %s s JOIN policy_rules r ON r.id = s.rule_id "
                "WHERE s.ref_kind = 'group' AND s.ref_id = ?" % table,
                (grp["id"],),
            ):
                refs.append("%s-access %s" % (row["plane"], row["name"]))
        if refs:
            raise ControlPlaneError(
                "Cannot remove Object Group %s.\n\nReferenced by:\n%s\n\nNo changes were applied."
                % (name, "\n".join("  %s" % r for r in refs))
            )

        def write():
            self.conn.execute("DELETE FROM object_group_members WHERE group_id = ?", (grp["id"],))
            self.conn.execute("DELETE FROM object_groups WHERE id = ?", (grp["id"],))
            return {"entity": {"type": "object-group", "id": grp["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset object-group %s" % name, "delete object group", write)

    def format_object_group(self, name: str) -> str:
        grp = self.get_object_group(name)
        if grp is None:
            raise ControlPlaneError("Object Group not found: %s" % name)
        members = self.conn.execute(
            "SELECT member_kind, member_id FROM object_group_members WHERE group_id = ?",
            (grp["id"],),
        ).fetchall()
        lines = ["Object Group: %s" % grp["name"]]
        if grp["description"]:
            lines.append("Description : %s" % grp["description"])
        lines.extend(["", "Members", "-------"])
        if not members:
            lines.append("(none)")
        for mem in members:
            if mem["member_kind"] == "object":
                obj = self.conn.execute("SELECT name FROM objects WHERE id = ?", (mem["member_id"],)).fetchone()
                lines.append(obj["name"] if obj else mem["member_id"])
            else:
                g = self.conn.execute("SELECT name FROM object_groups WHERE id = ?", (mem["member_id"],)).fetchone()
                lines.append("(group) %s" % (g["name"] if g else mem["member_id"]))
        return "\n".join(lines) + "\n"

    # --- clients / endpoints ----------------------------------------------
    def upsert_client(
        self,
        client_id: str,
        *,
        label: Optional[str] = None,
        description: Optional[str] = None,
        hostname: Optional[str] = None,
        connected: bool = True,
        addresses: Optional[list[dict]] = None,
    ) -> dict:
        now = utc_now_iso()
        existing = self.conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
        endpoint_name = (label or (existing["label"] if existing else None) or client_id[:8]).strip()

        presence = "connected" if connected else "disconnected"

        def write():
            if existing:
                # Metadata reconcile must not refresh last_seen. Only authenticated
                # management activity and AI job claim/complete move liveness.
                self.conn.execute(
                    "UPDATE clients SET label = COALESCE(?, label), description = COALESCE(?, description), "
                    "hostname = COALESCE(?, hostname), status = ?, connected = ?, "
                    "row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (label, description, hostname, presence, 1 if connected else 0, now, client_id),
                )
            else:
                self.conn.execute(
                    "INSERT INTO clients(id, label, description, hostname, status, trust_status, connected, "
                    "last_seen, row_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'trusted', ?, ?, 1, ?, ?)",
                    (
                        client_id,
                        label or "",
                        description or "",
                        hostname or "",
                        presence,
                        1 if connected else 0,
                        now,
                        now,
                        now,
                    ),
                )
            obj = self.conn.execute(
                "SELECT o.* FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
                (client_id,),
            ).fetchone()
            if obj is None:
                # Never rebind an orphaned or other-client endpoint that reused a label.
                name = endpoint_name
                existing_named = self.get_object(endpoint_name)
                if existing_named and existing_named["type"] == "managed_endpoint":
                    link = self.conn.execute(
                        "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                        (existing_named["id"],),
                    ).fetchone()
                    other_client = bool(link and link["client_id"] and link["client_id"] != client_id)
                    if existing_named["status"] == "orphaned" or other_client:
                        name = client_id[:8] if client_id[:8] != endpoint_name else ("ep-" + client_id[:10])
                if self.get_object_group(name):
                    raise ControlPlaneError(
                        "ERROR:\nPublic name '%s' is already used by a Network Group.\n\n"
                        "Managed Hosts participate in the Network Object namespace and must "
                        "not collide with Network Group names.\n\n"
                        "No changes were applied." % name
                    )
                oid = _new_id("obj")
                self.conn.execute(
                    "INSERT INTO objects(id, name, type, origin, description, status, row_version, created_at, updated_at) "
                    "VALUES (?, ?, 'managed_endpoint', 'managed', '', 'active', 1, ?, ?)",
                    (oid, name, now, now),
                )
                self.conn.execute(
                    "INSERT INTO managed_endpoints(id, object_id, client_id) VALUES (?, ?, ?)",
                    (_new_id("mep"), oid, client_id),
                )
                obj_id = oid
            else:
                obj_id = obj["id"]
                self.conn.execute(
                    "UPDATE objects SET status = 'active', orphan_reason = NULL, updated_at = ? WHERE id = ?",
                    (now, obj_id),
                )
                self.conn.execute(
                    "UPDATE managed_endpoints SET client_id = ? WHERE object_id = ?",
                    (client_id, obj_id),
                )
            if addresses is not None:
                self._replace_addresses(obj_id, addresses, now)
            return {"entity": {"type": "client", "id": client_id, "name": endpoint_name}, "operation": "upsert"}

        return self._mutate("upsert client %s" % client_id[:8], "upsert client/endpoint", write)

    def _replace_addresses(self, object_id: str, addresses: list[dict], now: str) -> None:
        self.conn.execute("DELETE FROM endpoint_addresses WHERE endpoint_object_id = ?", (object_id,))
        for item in addresses or []:
            addr = str(item.get("address") or "").strip()
            if not addr:
                continue
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            family = "ipv6" if ip.version == 6 else "ipv4"
            scope = classify_address(addr)
            self.conn.execute(
                "INSERT INTO endpoint_addresses(endpoint_object_id, address, address_family, interface_name, "
                "scope, active, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    object_id,
                    str(ip),
                    family,
                    item.get("interface") or item.get("interface_name") or "",
                    scope,
                    1 if item.get("active", True) else 0,
                    now,
                    now,
                ),
            )
        link = self.conn.execute(
            "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
            (object_id,),
        ).fetchone()
        if link and link["client_id"]:
            try:
                from drlink_upgrade_reconcile import rematerialize_published_targets_for_managed_host

                rematerialize_published_targets_for_managed_host(self, link["client_id"])
            except Exception:
                pass

    def set_endpoint_addresses(self, endpoint: str, addresses: list[dict]) -> dict:
        obj = self.require_object(endpoint)
        if obj["type"] != "managed_endpoint":
            raise ControlPlaneError("Not a Managed Host: %s" % endpoint)

        def write():
            self._replace_addresses(obj["id"], addresses, utc_now_iso())
            self.conn.execute(
                "UPDATE objects SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), obj["id"]),
            )
            return {"entity": {"type": "managed-endpoint", "id": obj["id"], "name": obj["name"]}, "operation": "addresses"}

        return self._mutate("set endpoint addresses %s" % endpoint, "update address inventory", write)

    def endpoint_addresses(self, name: str) -> list[dict]:
        obj = self.require_object(name)
        rows = []
        for row in self.conn.execute(
            "SELECT * FROM endpoint_addresses WHERE endpoint_object_id = ? ORDER BY address",
            (obj["id"],),
        ):
            rows.append(
                {
                    "address": row["address"],
                    "family": row["address_family"],
                    "interface": row["interface_name"],
                    "scope": row["scope"],
                    "active": bool(row["active"]),
                }
            )
        return rows

    def format_managed_endpoint(self, name: str) -> str:
        obj = self.require_object(name)
        if obj["type"] != "managed_endpoint":
            raise ControlPlaneError("Not a Managed Host: %s" % name)
        ep = self.conn.execute(
            "SELECT * FROM managed_endpoints WHERE object_id = ?", (obj["id"],)
        ).fetchone()
        client = None
        if ep and ep["client_id"]:
            client = self.conn.execute("SELECT * FROM clients WHERE id = ?", (ep["client_id"],)).fetchone()
        if obj["status"] == "orphaned":
            status = "Orphaned"
        else:
            presence = self.managed_host_connectivity(client)
            status = {"connected": "Connected", "stale": "Stale"}.get(presence, "Disconnected")
        lines = [
            "Managed Host: %s" % obj["name"],
            "Client ID       : %s" % ((client["id"][:8] if client else (ep["client_id"][:8] if ep and ep["client_id"] else "-"))),
            "Status          : %s" % status,
            "Origin          : Data Relay",
        ]
        if obj["status"] == "orphaned":
            lines.append("Reason          : %s" % (obj["orphan_reason"] or "Client removed"))
        lines.extend(["", "Addresses", "---------"])
        addrs = [a for a in self.endpoint_addresses(name) if a["scope"] not in ("loopback", "link-local", "special")]
        if not addrs:
            lines.append("(none)")
        for addr in addrs:
            lines.append(addr["address"])
            lines.append("  Interface : %s" % (addr["interface"] or "-"))
            lines.append("  Scope     : %s" % addr["scope"])
            lines.append("  Active    : %s" % ("yes" if addr["active"] else "no"))
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def _retire_client_owned_state(self, client_id: str) -> list[str]:
        """Release reservations and delete Agent-owned published services for a client."""
        cleaned: list[str] = []
        pubs = list(
            self.conn.execute(
                "SELECT id, name, public_port FROM published_services WHERE client_id = ?",
                (client_id,),
            )
        )
        for pub in pubs:
            if pub["public_port"] is not None:
                self.conn.execute(
                    "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
                    (int(pub["public_port"]),),
                )
                cleaned.append("release port reservation %s" % pub["public_port"])
            # remote_service_meta cascades from published_services
            self.conn.execute("DELETE FROM published_services WHERE id = ?", (pub["id"],))
            cleaned.append("delete published service %s" % pub["name"])
        for res in self.conn.execute(
            "SELECT public_port FROM port_reservations WHERE client_id = ? AND released = 0",
            (client_id,),
        ):
            self.conn.execute(
                "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
                (int(res["public_port"]),),
            )
            cleaned.append("release port reservation %s" % res["public_port"])
        self.conn.execute("DELETE FROM client_group_members WHERE client_id = ?", (client_id,))
        self.conn.execute("DELETE FROM client_tags WHERE client_id = ?", (client_id,))
        return cleaned

    def remove_client(self, selector: str, *, revoke_only: bool = False) -> dict:
        client = self.require_client(selector)
        ep = self.conn.execute(
            "SELECT o.* FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
            (client["id"],),
        ).fetchone()

        def write():
            if revoke_only:
                self.conn.execute(
                    "UPDATE clients SET trust_status = 'revoked', connected = 0, updated_at = ? WHERE id = ?",
                    (utc_now_iso(), client["id"]),
                )
                self.conn.execute(
                    "DELETE FROM system_meta WHERE key = ?",
                    (self._ai_agent_credential_key(client["id"]),),
                )
                return {"entity": {"type": "client", "id": client["id"]}, "operation": "revoke"}
            refs = []
            if ep:
                refs = self.object_references(ep["name"])
            self._retire_client_owned_state(client["id"])
            self.conn.execute(
                "DELETE FROM system_meta WHERE key = ?",
                (self._ai_agent_credential_key(client["id"]),),
            )
            if ep and refs:
                self.conn.execute(
                    "UPDATE objects SET status = 'orphaned', orphan_reason = 'Client removed', updated_at = ? WHERE id = ?",
                    (utc_now_iso(), ep["id"]),
                )
                self.conn.execute(
                    "UPDATE managed_endpoints SET client_id = NULL WHERE object_id = ?",
                    (ep["id"],),
                )
            elif ep:
                self.conn.execute("DELETE FROM endpoint_addresses WHERE endpoint_object_id = ?", (ep["id"],))
                self.conn.execute("DELETE FROM managed_endpoints WHERE object_id = ?", (ep["id"],))
                self.conn.execute("DELETE FROM objects WHERE id = ?", (ep["id"],))
            self.conn.execute("DELETE FROM clients WHERE id = ?", (client["id"],))
            return {"entity": {"type": "client", "id": client["id"]}, "operation": "remove"}

        return self._mutate(
            "system revoke client" if revoke_only else "unset client %s" % selector,
            "revoke" if revoke_only else "remove client",
            write,
        )

    def unset_managed_host(
        self, selector: str, *, confirm: Optional[bool] = None
    ) -> dict:
        """Canonical server-side Managed Host retirement with impact review."""
        client = self.get_client(selector)
        if client is None:
            raise ControlPlaneError(
                "ERROR:\nManaged Host '%s' was not found.\n\nNo changes were applied." % selector
            )
        ep = self.conn.execute(
            "SELECT o.* FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
            (client["id"],),
        ).fetchone()
        host_name = (ep["name"] if ep else None) or client["label"] or client["id"][:8]
        if ep:
            refs = self.object_references(ep["name"])
            if refs:
                raise ControlPlaneError(
                    "ERROR:\nManaged Host '%s' is still referenced.\n\nReferences:\n%s\n\n"
                    "Remove or change those references first.\n\nNo changes were applied."
                    % (host_name, "\n".join("  %s" % r["display"] for r in refs))
                )

        pubs = list(
            self.conn.execute(
                "SELECT name, public_port FROM published_services WHERE client_id = ? ORDER BY name",
                (client["id"],),
            )
        )
        ports = [
            int(r["public_port"])
            for r in self.conn.execute(
                "SELECT public_port FROM port_reservations WHERE client_id = ? AND released = 0 "
                "ORDER BY public_port",
                (client["id"],),
            )
        ]
        cleanup_preview: list[str] = []
        for pub in pubs:
            cleanup_preview.append("published service %s" % pub["name"])
            if pub["public_port"] is not None:
                cleanup_preview.append("port reservation %s" % pub["public_port"])
        for port in ports:
            label = "port reservation %s" % port
            if label not in cleanup_preview:
                cleanup_preview.append(label)
        if ep:
            cleanup_preview.append("managed endpoint inventory %s" % ep["name"])
        cleanup_preview.append("client trust/inventory %s" % (client["id"][:8],))

        def write():
            self._retire_client_owned_state(client["id"])
            if ep:
                self.conn.execute(
                    "DELETE FROM endpoint_addresses WHERE endpoint_object_id = ?", (ep["id"],)
                )
                self.conn.execute("DELETE FROM managed_endpoints WHERE object_id = ?", (ep["id"],))
                self.conn.execute("DELETE FROM objects WHERE id = ?", (ep["id"],))
            self.conn.execute("DELETE FROM clients WHERE id = ?", (client["id"],))
            return {
                "entity": {"type": "managed-host", "id": client["id"], "name": host_name},
                "operation": "remove",
            }

        impact = {
            "kind": "managed-host-retire",
            "requires_confirmation": True,
            "access_broadened": False,
            "access_narrowed": False,
            "host": host_name,
            "warning": (
                "This will permanently remove Managed Host '%s' and owned server-side state."
                % host_name
            ),
            "cleanup": cleanup_preview,
            "before": "trust=%s connected=%s services=%s active_reservations=%s"
            % (
                client["trust_status"],
                "yes" if client["connected"] else "no",
                len(pubs),
                len(ports),
            ),
            "after": "Managed Host removed; published services deleted; port reservations released",
        }
        return self._mutate(
            "unset managed-host %s" % host_name,
            "retire managed host",
            write,
            impact=impact,
            confirm=confirm,
        )

    def set_client_label(self, selector: str, label: str) -> dict:
        client = self.require_client(selector)

        def write():
            self.conn.execute(
                "UPDATE clients SET label = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (label, utc_now_iso(), client["id"]),
            )
            ep = self.conn.execute(
                "SELECT o.id FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
                (client["id"],),
            ).fetchone()
            if ep and label and NAME_RE.fullmatch(label) and not self.get_object(label):
                self.conn.execute("UPDATE objects SET name = ?, updated_at = ? WHERE id = ?", (label, utc_now_iso(), ep["id"]))
            return {"entity": {"type": "client", "id": client["id"]}, "operation": "label"}

        return self._mutate("set client %s label" % selector, "set label", write)

    def set_client_description(self, selector: str, text: str) -> dict:
        client = self.require_client(selector)

        def write():
            self.conn.execute(
                "UPDATE clients SET description = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (text, utc_now_iso(), client["id"]),
            )
            return {"entity": {"type": "client", "id": client["id"]}, "operation": "description"}

        return self._mutate("set client %s description" % selector, "set description", write)

    def set_client_tag(self, selector: str, key: str, value: str) -> dict:
        client = self.require_client(selector)
        key = str(key or "").strip()
        if not TAG_KEY_RE.fullmatch(key):
            raise ControlPlaneError("invalid tag key")

        def write():
            self.conn.execute(
                "INSERT INTO client_tags(client_id, key, value) VALUES (?, ?, ?) "
                "ON CONFLICT(client_id, key) DO UPDATE SET value = excluded.value",
                (client["id"], key, value),
            )
            return {"entity": {"type": "client", "id": client["id"]}, "operation": "tag"}

        return self._mutate("set client tag", "set tag", write)

    def unset_client_tag(self, selector: str, key: str) -> dict:
        client = self.require_client(selector)

        def write():
            self.conn.execute(
                "DELETE FROM client_tags WHERE client_id = ? AND key = ?",
                (client["id"], key),
            )
            return {"entity": {"type": "client", "id": client["id"]}, "operation": "untag"}

        return self._mutate("unset client tag", "unset tag", write)

    # --- client groups ----------------------------------------------------
    def set_client_group(self, name: str, description: Optional[str] = None) -> dict:
        name = _validate_name(name, "Client Group name")

        def write():
            existing = self.conn.execute(
                "SELECT * FROM client_groups WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
            now = utc_now_iso()
            if existing:
                if description is not None:
                    self.conn.execute(
                        "UPDATE client_groups SET description = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                        (description, now, existing["id"]),
                    )
                return {"entity": {"type": "client-group", "id": existing["id"], "name": name}, "operation": "update"}
            gid = _new_id("cgrp")
            self.conn.execute(
                "INSERT INTO client_groups(id, name, description, row_version, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                (gid, name, description or "", now, now),
            )
            return {"entity": {"type": "client-group", "id": gid, "name": name}, "operation": "create"}

        return self._mutate("set client-group %s" % name, "create client group", write)

    def set_client_group_member(self, group: str, client_sel: str) -> dict:
        self.set_client_group(group)
        grp = self.conn.execute(
            "SELECT * FROM client_groups WHERE name = ? COLLATE NOCASE", (group,)
        ).fetchone()
        client = self.require_client(client_sel)

        def write():
            self.conn.execute(
                "INSERT OR IGNORE INTO client_group_members(group_id, client_id) VALUES (?, ?)",
                (grp["id"], client["id"]),
            )
            return {"entity": {"type": "client-group", "id": grp["id"], "name": group}, "operation": "add-member"}

        return self._mutate("set client-group member", "add client group member", write)

    def unset_client_group_member(self, group: str, client_sel: str) -> dict:
        grp = self.conn.execute(
            "SELECT * FROM client_groups WHERE name = ? COLLATE NOCASE", (group,)
        ).fetchone()
        if grp is None:
            raise ControlPlaneError("Client Group not found: %s" % group)
        client = self.require_client(client_sel)

        def write():
            self.conn.execute(
                "DELETE FROM client_group_members WHERE group_id = ? AND client_id = ?",
                (grp["id"], client["id"]),
            )
            return {"entity": {"type": "client-group", "id": grp["id"]}, "operation": "remove-member"}

        return self._mutate("unset client-group member", "remove client group member", write)

    def unset_client_group(self, name: str) -> dict:
        grp = self.conn.execute(
            "SELECT * FROM client_groups WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if grp is None:
            raise ControlPlaneError("Client Group not found: %s" % name)
        refs = self.conn.execute(
            "SELECT r.name FROM ai_rule_targets t JOIN ai_access_rules r ON r.id = t.rule_id "
            "WHERE t.target_kind = 'client-group' AND t.target_id = ?",
            (grp["id"],),
        ).fetchall()
        if refs:
            raise ControlPlaneError(
                "Cannot remove Client Group %s.\nReferenced by:\n%s\n\nNo changes were applied."
                % (name, "\n".join("  ai-access %s" % r["name"] for r in refs))
            )

        def write():
            self.conn.execute("DELETE FROM client_group_members WHERE group_id = ?", (grp["id"],))
            self.conn.execute("DELETE FROM client_groups WHERE id = ?", (grp["id"],))
            return {"entity": {"type": "client-group", "id": grp["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset client-group %s" % name, "delete client group", write)

    # --- published services / presets -------------------------------------
    def set_published_service(
        self,
        client_sel: str,
        name: str,
        *,
        service_type: Optional[str] = None,
        target_mode: Optional[str] = None,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        enabled: Optional[bool] = None,
        public_port: Optional[int] = None,
        from_preset: Optional[str] = None,
    ) -> dict:
        client = self.require_client(client_sel)
        name = str(name or "").strip()
        if not name:
            raise ControlPlaneError("Published Service name is required")

        def write():
            existing = self.conn.execute(
                "SELECT * FROM published_services WHERE client_id = ? AND name = ?",
                (client["id"], name),
            ).fetchone()
            now = utc_now_iso()
            stype = (service_type or (existing["service_type"] if existing else "tcp")).lower()
            if stype not in ("ssh", "http", "https", "tcp"):
                raise ControlPlaneError("type must be ssh, http, https, or tcp")
            mode = (target_mode or (existing["target_mode"] if existing else "self")).lower()
            if mode not in ("self", "routed"):
                raise ControlPlaneError("target-mode must be self or routed")
            host = target_host if target_host is not None else (existing["target_host"] if existing else ("127.0.0.1" if mode == "self" else ""))
            port = int(target_port if target_port is not None else (existing["target_port"] if existing else (22 if stype == "ssh" else 443)))
            if mode == "self" and not host:
                host = "127.0.0.1"
            if mode == "routed" and not host:
                raise ControlPlaneError("ROUTED Published Service requires target-host")
            en = existing["enabled"] if existing and enabled is None else (1 if enabled else 0 if enabled is not None else 1)
            preset = from_preset or (existing["preset_name"] if existing else None)
            rport = public_port if public_port is not None else (existing["public_port"] if existing else None)
            if rport is None:
                rport = self._allocate_port(client["id"], name)
            if existing:
                self.conn.execute(
                    "UPDATE published_services SET service_type = ?, target_mode = ?, target_host = ?, "
                    "target_port = ?, public_port = ?, enabled = ?, released = 0, row_version = row_version + 1, "
                    "updated_at = ? WHERE id = ?",
                    (stype, mode, host, port, rport, int(bool(en)), now, existing["id"]),
                )
                sid = existing["id"]
            else:
                sid = _new_id("svc")
                self.conn.execute(
                    "INSERT INTO published_services(id, client_id, name, service_type, target_mode, target_host, "
                    "target_port, public_port, enabled, released, preset_name, row_version, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 1, ?, ?)",
                    (sid, client["id"], name, stype, mode, host, port, rport, int(bool(en)), preset, now, now),
                )
            return {"entity": {"type": "published-service", "id": sid, "name": name}, "operation": "set"}

        return self._mutate("set published-service %s" % name, "set published service", write)

    def _allocate_port(self, client_id: str, service_name: str) -> int:
        used = {r[0] for r in self.conn.execute("SELECT public_port FROM port_reservations WHERE released = 0")}
        used |= {r[0] for r in self.conn.execute("SELECT public_port FROM published_services WHERE public_port IS NOT NULL AND released = 0")}
        for port in range(6000, 6099):
            if port not in used:
                self.conn.execute(
                    "INSERT OR REPLACE INTO port_reservations(public_port, client_id, service_id, service_name, released, created_at) "
                    "VALUES (?, ?, '', ?, 0, ?)",
                    (port, client_id, service_name, utc_now_iso()),
                )
                return port
        raise ControlPlaneError("no public ports remaining")

    def unset_published_service(self, client_sel: str, name: str, *, release: bool = True) -> dict:
        client = self.require_client(client_sel)

        def write():
            existing = self.conn.execute(
                "SELECT * FROM published_services WHERE client_id = ? AND name = ?",
                (client["id"], name),
            ).fetchone()
            if existing is None:
                raise ControlPlaneError("Published Service not found: %s" % name)
            if release:
                if existing["public_port"]:
                    self.conn.execute(
                        "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
                        (existing["public_port"],),
                    )
                self.conn.execute("DELETE FROM published_services WHERE id = ?", (existing["id"],))
            else:
                self.conn.execute(
                    "UPDATE published_services SET enabled = 0, updated_at = ? WHERE id = ?",
                    (utc_now_iso(), existing["id"]),
                )
            return {"entity": {"type": "published-service", "id": existing["id"], "name": name}, "operation": "unset"}

        return self._mutate("unset published-service %s" % name, "unset published service", write)

    def set_published_service_enabled(self, client_sel: str, name: str, enabled: bool) -> dict:
        return self.set_published_service(client_sel, name, enabled=enabled)

    def format_published_service(self, client_or_endpoint: str, service: str) -> str:
        client = self.get_client(client_or_endpoint)
        if client is None:
            obj = self.get_object(client_or_endpoint)
            if obj and obj["type"] == "managed_endpoint":
                ep = self.conn.execute(
                    "SELECT client_id FROM managed_endpoints WHERE object_id = ?", (obj["id"],)
                ).fetchone()
                if ep and ep["client_id"]:
                    client = self.conn.execute("SELECT * FROM clients WHERE id = ?", (ep["client_id"],)).fetchone()
        if client is None:
            raise ControlPlaneError("client not found: %s" % client_or_endpoint)
        svc = self.conn.execute(
            "SELECT * FROM published_services WHERE client_id = ? AND name = ?",
            (client["id"], service),
        ).fetchone()
        if svc is None:
            raise ControlPlaneError("Published Service not found: %s" % service)
        ep = self.conn.execute(
            "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
            (client["id"],),
        ).fetchone()
        endpoint_name = ep["name"] if ep else (client["label"] or client["id"][:8])
        mode = str(svc["target_mode"]).upper()
        lines = [
            "Published Service: %s" % svc["name"],
            "Client           : %s" % (client["label"] or endpoint_name),
            "Type             : %s" % str(svc["service_type"]).upper(),
            "Target Mode      : %s" % mode,
        ]
        if mode == "SELF":
            lines.append("Local Target     : %s:%s" % (svc["target_host"], svc["target_port"]))
            lines.append("Effective Target : %s" % endpoint_name)
        else:
            lines.append("Target           : %s:%s" % (svc["target_host"], svc["target_port"]))
            lines.append("Via              : %s" % endpoint_name)
        lines.append("Public Port      : %s" % (svc["public_port"] or "-"))
        lines.append("Status           : %s" % ("Enabled" if svc["enabled"] else "Disabled"))
        return "\n".join(lines) + "\n"

    def set_service_preset(self, name: str, **fields) -> dict:
        name = _validate_name(name, "Service Preset name")

        def write():
            existing = self.conn.execute(
                "SELECT * FROM service_presets WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
            now = utc_now_iso()
            stype = fields.get("service_type") or fields.get("type")
            mode = fields.get("target_mode")
            port = fields.get("target_port")
            desc = fields.get("description")
            if existing:
                self.conn.execute(
                    "UPDATE service_presets SET service_type = COALESCE(?, service_type), "
                    "target_mode = COALESCE(?, target_mode), target_port = COALESCE(?, target_port), "
                    "description = COALESCE(?, description), row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (stype, mode, port, desc, now, existing["id"]),
                )
                return {"entity": {"type": "service-preset", "id": existing["id"], "name": name}, "operation": "update"}
            pid = _new_id("prst")
            self.conn.execute(
                "INSERT INTO service_presets(id, name, service_type, target_mode, target_port, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (pid, name, stype, mode, port, desc or "", now, now),
            )
            return {"entity": {"type": "service-preset", "id": pid, "name": name}, "operation": "create"}

        return self._mutate("set service-preset %s" % name, "set service preset", write)

    def unset_service_preset(self, name: str) -> dict:
        existing = self.conn.execute(
            "SELECT * FROM service_presets WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if existing is None:
            raise ControlPlaneError("Service Preset not found: %s" % name)

        def write():
            self.conn.execute("DELETE FROM service_presets WHERE id = ?", (existing["id"],))
            return {"entity": {"type": "service-preset", "id": existing["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset service-preset %s" % name, "delete service preset", write)

    def apply_preset_to_new_service(self, client_sel: str, service_name: str, preset_name: str) -> dict:
        preset = self.conn.execute(
            "SELECT * FROM service_presets WHERE name = ? COLLATE NOCASE", (preset_name,)
        ).fetchone()
        if preset is None:
            raise ControlPlaneError("Service Preset not found: %s" % preset_name)
        return self.set_published_service(
            client_sel,
            service_name,
            service_type=preset["service_type"],
            target_mode=preset["target_mode"],
            target_port=preset["target_port"],
            from_preset=preset["name"],
        )

    # --- network policy ---------------------------------------------------
    def _get_rule(self, plane: str, name: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM policy_rules WHERE plane = ? AND name = ? COLLATE NOCASE",
            (plane, name),
        ).fetchone()

    def _bottom_position(self, plane: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM policy_rules WHERE plane = ?",
            (plane,),
        ).fetchone()
        current = int(row[0] or 0)
        return current + POSITION_STEP if current else POSITION_STEP

    def set_rule(self, plane: str, name: str) -> dict:
        if plane not in PLANES:
            raise ControlPlaneError("unknown plane")
        name = _validate_name(name, "Rule name")

        def write():
            existing = self._get_rule(plane, name)
            if existing:
                return {"entity": {"type": "%s-access" % plane, "id": existing["id"], "name": name}, "operation": "exists"}
            rid = _new_id("rul")
            now = utc_now_iso()
            pos = self._bottom_position(plane)
            self.conn.execute(
                "INSERT INTO policy_rules(id, plane, name, position, action, enabled, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'allow', 0, '', 1, ?, ?)",
                (rid, plane, name, pos, now, now),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rid, "name": name}, "operation": "create"}

        return self._mutate("set %s-access %s" % ("remote" if plane == "remote" else "internet", name), "create rule", write)

    def _require_rule(self, plane: str, name: str) -> sqlite3.Row:
        row = self._get_rule(plane, name)
        if row is None:
            raise ControlPlaneError("Rule not found: %s" % name)
        return row

    def _assign_rule_ref(self, plane: str, name: str, field: str, token: str) -> dict:
        rule = self._require_rule(plane, name)
        kind, ref = self.resolve_ref(token)
        if kind == "object":
            if not self.object_type_valid_for(ref, plane, field):
                raise ControlPlaneError(
                    "Object type is not valid for %s Access %s.\nNo changes were applied."
                    % ("Remote" if plane == "remote" else "Internet", field.title())
                )
        else:
            ok, bad = self.group_valid_for(ref, plane, field)
            if not ok:
                raise ControlPlaneError(
                    "Object Group is not valid for %s Access %s.\n\nInvalid member:\n  %s\n\nNo changes were applied."
                    % ("Remote" if plane == "remote" else "Internet", field.title(), bad)
                )
        table = "rule_sources" if field == "source" else "rule_destinations"

        def write():
            self.conn.execute(
                "INSERT OR IGNORE INTO %s(rule_id, ref_kind, ref_id) VALUES (?, ?, ?)" % table,
                (rule["id"], kind, ref["id"]),
            )
            self.conn.execute(
                "UPDATE policy_rules SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), rule["id"]),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "set-%s" % field}

        return self._mutate("set %s-access %s %s %s" % (plane, name, field, token), "set rule %s" % field, write)

    def set_rule_source(self, plane: str, name: str, token: str) -> dict:
        self.set_rule(plane, name)
        return self._assign_rule_ref(plane, name, "source", token)

    def set_rule_destination(self, plane: str, name: str, token: str) -> dict:
        self.set_rule(plane, name)
        return self._assign_rule_ref(plane, name, "destination", token)

    def set_rule_service(self, plane: str, name: str, protocol: str, port: int) -> dict:
        self.set_rule(plane, name)
        rule = self._require_rule(plane, name)
        proto = str(protocol or "").strip().lower()
        if proto in ("https",):
            proto = "tcp"
            port = int(port or 443)
        elif proto in ("http",):
            proto = "tcp"
            port = int(port or 80)
        elif proto not in ("tcp", "udp"):
            raise ControlPlaneError("protocol must be tcp or udp (http/https accepted)")
        port = int(port)

        def write():
            self.conn.execute(
                "INSERT OR IGNORE INTO rule_services(rule_id, protocol, port) VALUES (?, ?, ?)",
                (rule["id"], proto, port),
            )
            self.conn.execute(
                "UPDATE policy_rules SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), rule["id"]),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "set-service"}

        return self._mutate("set %s-access service" % plane, "set rule service", write)

    def set_rule_action(self, plane: str, name: str, action: str) -> dict:
        self.set_rule(plane, name)
        rule = self._require_rule(plane, name)
        action = str(action or "").strip().lower()
        if action not in ("allow", "deny"):
            raise ControlPlaneError("action must be allow or deny")

        def write():
            self.conn.execute(
                "UPDATE policy_rules SET action = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (action, utc_now_iso(), rule["id"]),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "action"}

        return self._mutate("set %s-access action" % plane, "set action", write)

    def set_rule_description(self, plane: str, name: str, text: str) -> dict:
        self.set_rule(plane, name)
        rule = self._require_rule(plane, name)

        def write():
            self.conn.execute(
                "UPDATE policy_rules SET description = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (text, utc_now_iso(), rule["id"]),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "description"}

        return self._mutate("set %s-access description" % plane, "set description", write)

    def set_rule_enabled(
        self, plane: str, name: str, enabled: bool, *, confirm: Optional[bool] = None
    ) -> dict:
        rule = self._require_rule(plane, name)

        def write():
            self.conn.execute(
                "UPDATE policy_rules SET enabled = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, utc_now_iso(), rule["id"]),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "enable" if enabled else "disable"}

        impact = None
        if not enabled and bool(rule["enabled"]):
            import drlink_v24 as v24

            impact = v24.last_enabled_rule_mutation_impact(
                self, plane, name, disabling=True
            )

        return self._mutate(
            "set %s-access enabled" % plane,
            "enable/disable rule",
            write,
            impact=impact,
            confirm=confirm,
        )

    def move_rule(self, plane: str, name: str, *, before: Optional[str] = None, after: Optional[str] = None) -> dict:
        rule = self._require_rule(plane, name)
        other_name = before or after
        other = self._require_rule(plane, other_name)

        def write():
            rules = list(
                self.conn.execute(
                    "SELECT id, position FROM policy_rules WHERE plane = ? ORDER BY position, name",
                    (plane,),
                )
            )
            ids = [r["id"] for r in rules]
            ids.remove(rule["id"])
            idx = ids.index(other["id"])
            if before:
                ids.insert(idx, rule["id"])
            else:
                ids.insert(idx + 1, rule["id"])
            for i, rid in enumerate(ids, start=1):
                self.conn.execute(
                    "UPDATE policy_rules SET position = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (i * POSITION_STEP, utc_now_iso(), rid),
                )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "move"}

        return self._mutate("set %s-access order" % plane, "move rule", write)

    def unset_rule_ref(self, plane: str, name: str, field: str, token: str) -> dict:
        rule = self._require_rule(plane, name)
        kind, ref = self.resolve_ref(token)
        table = "rule_sources" if field == "source" else "rule_destinations"

        def write():
            self.conn.execute(
                "DELETE FROM %s WHERE rule_id = ? AND ref_kind = ? AND ref_id = ?" % table,
                (rule["id"], kind, ref["id"]),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "unset-%s" % field}

        return self._mutate("unset %s-access %s" % (plane, field), "unset rule ref", write)

    def unset_rule_service(self, plane: str, name: str, protocol: str, port: int) -> dict:
        rule = self._require_rule(plane, name)
        proto = str(protocol).lower()
        if proto in ("https", "http"):
            proto = "tcp"

        def write():
            self.conn.execute(
                "DELETE FROM rule_services WHERE rule_id = ? AND protocol = ? AND port = ?",
                (rule["id"], proto, int(port)),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "unset-service"}

        return self._mutate("unset %s-access service" % plane, "unset service", write)

    def unset_rule(
        self, plane: str, name: str, *, confirm: Optional[bool] = None
    ) -> dict:
        rule = self._require_rule(plane, name)

        def write():
            self.conn.execute("DELETE FROM rule_sources WHERE rule_id = ?", (rule["id"],))
            self.conn.execute("DELETE FROM rule_destinations WHERE rule_id = ?", (rule["id"],))
            self.conn.execute("DELETE FROM rule_services WHERE rule_id = ?", (rule["id"],))
            self.conn.execute("DELETE FROM rule_service_refs WHERE rule_id = ?", (rule["id"],))
            self.conn.execute("DELETE FROM policy_rules WHERE id = ?", (rule["id"],))
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "delete"}

        impact = None
        if bool(rule["enabled"]):
            import drlink_v24 as v24

            impact = v24.last_enabled_rule_mutation_impact(
                self, plane, name, disabling=False
            )

        return self._mutate(
            "unset %s-access %s" % (plane, name),
            "delete rule",
            write,
            impact=impact,
            confirm=confirm,
        )

    def list_rules(self, plane: str) -> list[dict]:
        out = []
        for row in self.conn.execute(
            "SELECT * FROM policy_rules WHERE plane = ? ORDER BY position, name", (plane,)
        ):
            out.append(self._rule_view(row))
        return out

    def _rule_view(self, row: sqlite3.Row) -> dict:
        sources = []
        for s in self.conn.execute("SELECT ref_kind, ref_id FROM rule_sources WHERE rule_id = ?", (row["id"],)):
            sources.append(self._ref_name(s["ref_kind"], s["ref_id"]))
        dests = []
        for s in self.conn.execute("SELECT ref_kind, ref_id FROM rule_destinations WHERE rule_id = ?", (row["id"],)):
            dests.append(self._ref_name(s["ref_kind"], s["ref_id"]))
        services = [
            "%s/%s" % (s["protocol"], s["port"])
            for s in self.conn.execute("SELECT protocol, port FROM rule_services WHERE rule_id = ?", (row["id"],))
        ]
        return {
            "id": row["id"],
            "name": row["name"],
            "plane": row["plane"],
            "position": row["position"],
            "display_position": display_position(row["position"]),
            "action": row["action"],
            "enabled": bool(row["enabled"]),
            "description": row["description"],
            "sources": sources,
            "destinations": dests,
            "services": services,
            "row_version": row["row_version"],
        }

    def _ref_name(self, kind: str, ref_id: str) -> str:
        if kind == "object":
            row = self.conn.execute("SELECT name FROM objects WHERE id = ?", (ref_id,)).fetchone()
            return row["name"] if row else ref_id
        row = self.conn.execute("SELECT name FROM object_groups WHERE id = ?", (ref_id,)).fetchone()
        return row["name"] if row else ref_id

    def format_rulebase(self, plane: str) -> str:
        title = "Remote Access" if plane == "remote" else "Internet Access"
        lines = [
            title,
            "=" * len(title),
            "",
            "%-4s %-18s %-14s %-14s %-12s %-8s %s"
            % ("#", "NAME", "SOURCE", "DESTINATION", "SERVICE", "ACTION", "STATUS"),
        ]
        for rule in self.list_rules(plane):
            src = ",".join(rule["sources"]) or "-"
            dst = ",".join(rule["destinations"]) or "-"
            svc = ",".join(rule["services"]) or "-"
            lines.append(
                "%-4s %-18s %-14s %-14s %-12s %-8s %s"
                % (
                    rule["display_position"],
                    rule["name"][:18],
                    src[:14],
                    dst[:14],
                    svc[:12],
                    rule["action"].upper(),
                    "enabled" if rule["enabled"] else "disabled",
                )
            )
        lines.append("")
        lines.append("%-4s %-18s %-14s %-14s %-12s %-8s" % ("", "Implicit Default", "", "", "", "DENY"))
        return "\n".join(lines) + "\n"

    def shadow_analysis(self, plane: str) -> list[dict]:
        rules = [r for r in self.list_rules(plane) if r["enabled"]]
        findings = []
        for i, later in enumerate(rules):
            for earlier in rules[:i]:
                if self._rule_covers(earlier, later):
                    findings.append(
                        {
                            "shadowed": later["name"],
                            "by": earlier["name"],
                            "earlier_pos": earlier["display_position"],
                            "later_pos": later["display_position"],
                            "effective": earlier["action"].upper(),
                            "partial": not self._rule_equal_selectors(earlier, later),
                        }
                    )
                    break
        return findings

    def _rule_equal_selectors(self, a: dict, b: dict) -> bool:
        return set(a["sources"]) == set(b["sources"]) and set(a["destinations"]) == set(b["destinations"]) and set(a["services"]) == set(b["services"])

    def _rule_covers(self, earlier: dict, later: dict) -> bool:
        # Conservative: same-or-superset selectors in all dimensions.
        return (
            self._selector_covers(earlier["sources"], later["sources"])
            and self._selector_covers(earlier["destinations"], later["destinations"])
            and self._selector_covers(earlier["services"], later["services"])
        )

    def _selector_covers(self, earlier: list[str], later: list[str]) -> bool:
        if not later:
            return True
        if not earlier:
            return False
        return set(later).issubset(set(earlier)) or bool(set(earlier) & set(later))

    def format_shadow(self, plane: str) -> str:
        findings = self.shadow_analysis(plane)
        if not findings:
            return "No shadowed rules.\n"
        lines = []
        for item in findings:
            kind = "partially shadowed" if item["partial"] else "shadowed"
            lines.append(
                "Rule #%s %s is %s by #%s %s."
                % (item["later_pos"], item["shadowed"], kind, item["earlier_pos"], item["by"])
            )
            lines.append("Traffic matches #%s first." % item["earlier_pos"])
            lines.append("Effective action: %s" % item["effective"])
            lines.append("")
        return "\n".join(lines)

    def format_rule_impact(self, plane: str, name: str) -> str:
        rule = self._rule_view(self._require_rule(plane, name))
        shadows = [s for s in self.shadow_analysis(plane) if s["shadowed"] == name or s["by"] == name]
        lines = [
            "%s Access Rule: %s" % ("Remote" if plane == "remote" else "Internet", rule["name"]),
            "Position : #%s" % rule["display_position"],
            "Action   : %s" % rule["action"].upper(),
            "Enabled  : %s" % ("yes" if rule["enabled"] else "no"),
            "Source   : %s" % (", ".join(rule["sources"]) or "-"),
            "Dest     : %s" % (", ".join(rule["destinations"]) or "-"),
            "Service  : %s" % (", ".join(rule["services"]) or "-"),
            "",
        ]
        if shadows:
            lines.append("Shadow analysis")
            lines.append("---------------")
            lines.append(self.format_shadow(plane).rstrip())
        else:
            lines.append("Shadow analysis: none")
        return "\n".join(lines) + "\n"

    def completion_candidates(self, plane: str, field: str) -> list[str]:
        out = []
        for obj in self.conn.execute("SELECT * FROM objects ORDER BY name"):
            if self.object_type_valid_for(obj, plane, field):
                out.append(obj["name"])
        for grp in self.conn.execute("SELECT * FROM object_groups ORDER BY name"):
            ok, _bad = self.group_valid_for(grp, plane, field)
            if ok:
                out.append(grp["name"])
        return out

    # --- evaluation -------------------------------------------------------
    def _object_matches_ip(self, obj: sqlite3.Row, ip: str, *, role: str) -> bool:
        if obj["type"] == "managed_endpoint":
            # Managed Host participates as a Network Object for source and destination
            # where the context matrix allows it (Internet Access source; Remote Access both).
            for addr in self.conn.execute(
                "SELECT address, scope, active FROM endpoint_addresses WHERE endpoint_object_id = ?",
                (obj["id"],),
            ):
                if not addr["active"] or addr["scope"] in ("loopback", "link-local", "special"):
                    continue
                if addr["address"] == ip:
                    return True
            return False
        for val in self._object_values(obj["id"]):
            if obj["type"] == "host" and val == ip:
                return True
            if obj["type"] == "network":
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(val, strict=False):
                        return True
                except ValueError:
                    continue
            if obj["type"] == "fqdn" and val.lower() == str(ip).lower():
                return True
        return False

    def _object_matches_host(self, obj: sqlite3.Row, host: str) -> bool:
        host_n = str(host).rstrip(".").lower()
        if obj["type"] == "fqdn":
            return any(v.lower() == host_n for v in self._object_values(obj["id"]))
        if obj["type"] == "host":
            return any(v == host for v in self._object_values(obj["id"]))
        if obj["type"] == "network":
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False
            return any(
                ip in ipaddress.ip_network(v, strict=False) for v in self._object_values(obj["id"])
            )
        return False

    def _object_matches_internet_destination(
        self,
        obj: sqlite3.Row,
        host: str,
        *,
        is_ip_literal: bool,
        candidate_ip: Optional[str] = None,
    ) -> bool:
        """Match an Internet Access destination selector against host and/or one candidate IP.

        FQDN selectors match the requested hostname only and never authorize an IP literal.
        Host/CIDR selectors match the candidate IP (or the literal itself).
        """
        if obj["type"] == "fqdn":
            if is_ip_literal:
                return False
            host_n = str(host).rstrip(".").lower()
            return any(str(v).rstrip(".").lower() == host_n for v in self._object_values(obj["id"]))
        ip_target = candidate_ip
        if ip_target is None:
            try:
                ip_target = ipaddress.ip_address(str(host).strip()).compressed
            except ValueError:
                return False
        try:
            addr = ipaddress.ip_address(str(ip_target).strip())
        except ValueError:
            return False
        if obj["type"] == "host":
            for val in self._object_values(obj["id"]):
                try:
                    if ipaddress.ip_address(str(val).strip()) == addr:
                        return True
                except ValueError:
                    continue
            return False
        if obj["type"] == "network":
            for val in self._object_values(obj["id"]):
                try:
                    if addr in ipaddress.ip_network(str(val).strip(), strict=False):
                        return True
                except ValueError:
                    continue
            return False
        return False

    def _ref_matches_ip(self, kind: str, ref_id: str, ip: str, *, role: str) -> bool:
        if kind == "object":
            obj = self.conn.execute("SELECT * FROM objects WHERE id = ?", (ref_id,)).fetchone()
            return bool(obj) and self._object_matches_ip(obj, ip, role=role)
        grp = self.conn.execute("SELECT * FROM object_groups WHERE id = ?", (ref_id,)).fetchone()
        if not grp:
            return False
        for obj in self._expand_group_members(grp["id"], set()):
            if self._object_matches_ip(obj, ip, role=role):
                return True
        return False

    def _ref_matches_host(self, kind: str, ref_id: str, host: str) -> bool:
        if kind == "object":
            obj = self.conn.execute("SELECT * FROM objects WHERE id = ?", (ref_id,)).fetchone()
            return bool(obj) and self._object_matches_host(obj, host)
        grp = self.conn.execute("SELECT * FROM object_groups WHERE id = ?", (ref_id,)).fetchone()
        if not grp:
            return False
        for obj in self._expand_group_members(grp["id"], set()):
            if self._object_matches_host(obj, host):
                return True
        return False

    def _ref_matches_internet_destination(
        self,
        kind: str,
        ref_id: str,
        host: str,
        *,
        is_ip_literal: bool,
        candidate_ip: Optional[str] = None,
    ) -> bool:
        if kind == "object":
            obj = self.conn.execute("SELECT * FROM objects WHERE id = ?", (ref_id,)).fetchone()
            return bool(obj) and self._object_matches_internet_destination(
                obj, host, is_ip_literal=is_ip_literal, candidate_ip=candidate_ip
            )
        grp = self.conn.execute("SELECT * FROM object_groups WHERE id = ?", (ref_id,)).fetchone()
        if not grp:
            return False
        for obj in self._expand_group_members(grp["id"], set()):
            if self._object_matches_internet_destination(
                obj, host, is_ip_literal=is_ip_literal, candidate_ip=candidate_ip
            ):
                return True
        return False

    def _legacy_unmigrated(self, family: str) -> bool:
        """True when restrictive legacy policy is still unprojected (fail closed)."""
        try:
            from drlink_upgrade_reconcile import legacy_restrictive_unmigrated
        except Exception:
            return False
        try:
            return bool(legacy_restrictive_unmigrated(self, family))
        except Exception:
            return True

    def matching_objects_for_ip(self, ip: str, *, role: str) -> list[str]:
        names = []
        for obj in self.conn.execute("SELECT * FROM objects"):
            if self._object_matches_ip(obj, ip, role=role):
                names.append(obj["name"])
        return names

    def matching_objects_for_host(self, host: str) -> list[str]:
        names = []
        for obj in self.conn.execute("SELECT * FROM objects"):
            if self._object_matches_host(obj, host):
                names.append(obj["name"])
        return names

    def evaluate_remote_access(self, source_ip: str, destination: str, protocol: str, port: int) -> dict:
        from drlink_v24 import effective_policy_result, get_access_policy, rule_matches_service

        proto = str(protocol).lower()
        if proto in ("https", "http"):
            proto = "tcp"
        dest_ip = destination
        try:
            dest_ip = str(ipaddress.ip_address(destination))
        except ValueError:
            obj = self.get_object(destination)
            if obj and obj["type"] == "managed_endpoint":
                addrs = [a["address"] for a in self.endpoint_addresses(obj["name"]) if membership_eligible(a["address"]) and a["active"]]
                dest_ip = addrs[0] if addrs else destination
        src_matches = self.matching_objects_for_ip(source_ip, role="source")
        dst_matches = self.matching_objects_for_ip(dest_ip, role="destination")
        dest_obj = self.get_object(destination)
        if dest_obj and dest_obj["name"] not in dst_matches:
            dst_matches.append(dest_obj["name"])
        pol = get_access_policy(self, "remote")
        if pol["mode"] is None and self._legacy_unmigrated("remote"):
            reason = "Legacy v2.3 Remote Access policy is not migrated (fail closed)"
            return {
                "source_ip": source_ip,
                "destination": dest_ip,
                "protocol": proto,
                "port": int(port),
                "source_matches": src_matches,
                "destination_matches": dst_matches,
                "traces": [],
                "winner": None,
                "matched_rules": [],
                "mode": None,
                "enforcement": pol["enforcement"],
                "action": "DENY",
                "implicit": True,
                "published": None,
                "reason": reason,
                "effective": "DENY",
            }
        traces = []
        matched = []
        for rule_row in self.conn.execute(
            "SELECT * FROM policy_rules WHERE plane = 'remote' ORDER BY name"
        ):
            if not rule_row["enabled"]:
                continue
            view = self._rule_view(rule_row)
            src_ok = False
            for s in self.conn.execute("SELECT ref_kind, ref_id FROM rule_sources WHERE rule_id = ?", (rule_row["id"],)):
                if self._ref_matches_ip(s["ref_kind"], s["ref_id"], source_ip, role="source"):
                    src_ok = True
                    break
            dst_ok = False
            for s in self.conn.execute("SELECT ref_kind, ref_id FROM rule_destinations WHERE rule_id = ?", (rule_row["id"],)):
                if self._ref_matches_ip(s["ref_kind"], s["ref_id"], dest_ip, role="destination"):
                    dst_ok = True
                    break
                if dest_obj and s["ref_kind"] == "object" and s["ref_id"] == dest_obj["id"]:
                    dst_ok = True
                    break
            svc_ok = rule_matches_service(self, rule_row["id"], proto, port)
            hit = bool(src_ok and dst_ok and svc_ok)
            traces.append({"rule": view, "evaluated": True, "source": src_ok, "dest": dst_ok, "service": svc_ok, "match": hit})
            if hit:
                matched.append(view)
        action = effective_policy_result(pol["mode"], pol["enforcement"], bool(matched))
        winner = matched[0] if matched else None
        published = self._published_for_destination(dest_ip, proto, port, dest_obj)
        if pol["mode"] is None:
            reason = "No Policy (ALLOW)"
        elif str(pol["enforcement"]).lower() == "disabled":
            reason = "Policy enforcement DISABLED (ALLOW ALL)"
        elif matched:
            reason = "Remote Access matched rule(s): %s" % ", ".join(m["name"] for m in matched)
        else:
            reason = "No enabled Remote Access rule matched (%s)" % (
                "ALLOW" if pol["mode"] == "blacklist" else "DENY"
            )
        return {
            "source_ip": source_ip,
            "destination": dest_ip,
            "protocol": proto,
            "port": int(port),
            "source_matches": src_matches,
            "destination_matches": dst_matches,
            "traces": traces,
            "winner": winner,
            "matched_rules": [m["name"] for m in matched],
            "mode": pol["mode"],
            "enforcement": pol["enforcement"],
            "action": action,
            "implicit": winner is None,
            "published": published,
            "reason": reason,
            "effective": action,
        }

    def _published_for_destination(self, dest_ip: str, proto: str, port: int, dest_obj: Optional[sqlite3.Row]) -> Optional[dict]:
        for svc in self.conn.execute(
            "SELECT * FROM published_services WHERE enabled = 1 AND released = 0"
        ):
            if int(svc["target_port"]) != int(port):
                continue
            client = self.conn.execute("SELECT * FROM clients WHERE id = ?", (svc["client_id"],)).fetchone()
            ep = self.conn.execute(
                "SELECT o.* FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
                (svc["client_id"],),
            ).fetchone()
            endpoint_name = ep["name"] if ep else (client["label"] if client else "")
            if svc["target_mode"] == "self":
                if dest_obj and ep and dest_obj["id"] == ep["id"]:
                    return {"name": svc["name"], "mode": "SELF", "endpoint": endpoint_name, "public_port": svc["public_port"], "via": None}
                if ep and any(
                    a["address"] == dest_ip and membership_eligible(a["address"])
                    for a in self.endpoint_addresses(ep["name"])
                ):
                    return {"name": svc["name"], "mode": "SELF", "endpoint": endpoint_name, "public_port": svc["public_port"], "via": None}
            elif svc["target_mode"] == "routed" and svc["target_host"] == dest_ip:
                return {
                    "name": svc["name"],
                    "mode": "ROUTED",
                    "endpoint": endpoint_name,
                    "public_port": svc["public_port"],
                    "via": endpoint_name,
                    "target": "%s:%s" % (svc["target_host"], svc["target_port"]),
                }
        return None

    def format_remote_explain(self, result: dict) -> str:
        lines = [
            "Remote Access Policy Evaluation",
            "",
            "Source",
            "------",
            result["source_ip"],
            "Matched:",
        ]
        if result["source_matches"]:
            for name in result["source_matches"]:
                lines.append("  %s" % name)
        else:
            lines.append("  (none)")
        lines.extend(["", "Destination", "-----------", result["destination"], "Matched:"])
        if result["destination_matches"]:
            for name in result["destination_matches"]:
                lines.append("  %s" % name)
        else:
            lines.append("  (none)")
        lines.extend(["", "Service", "-------", "%s/%s" % (result["protocol"], result["port"]), "", "Rule Evaluation", "---------------"])
        decided = False
        for item in result["traces"]:
            rule = item["rule"]
            header = "#%s %s" % (rule["display_position"], rule["name"])
            if not item["evaluated"]:
                lines.append(header)
                lines.append("  Not evaluated")
                lines.append("")
                continue
            lines.append(header)
            lines.append("  Source      %s" % ("MATCH" if item["source"] else "NO MATCH"))
            lines.append("  Destination %s" % ("MATCH" if item["dest"] else "NO MATCH"))
            lines.append("  Service     %s" % ("MATCH" if item["service"] else "NO MATCH"))
            if item["source"] and item["dest"] and item["service"] and not decided:
                lines.append("")
                lines.append("FIRST COMPLETE MATCH")
                lines.append("Action: %s" % rule["action"].upper())
                decided = True
            lines.append("")
        pub = result.get("published")
        lines.extend(["Published Service", "-----------------"])
        if pub:
            lines.append(pub["name"])
            lines.append("Target Mode : %s" % pub["mode"])
            if pub["mode"] == "SELF":
                lines.append("Endpoint    : %s" % pub["endpoint"])
            else:
                lines.append("Via         : %s" % pub.get("via"))
            lines.append("Public Port : %s" % pub.get("public_port"))
        else:
            lines.append("(none)")
        lines.extend(
            [
                "",
                "Final Result",
                "------------",
                result["action"] if not result["implicit"] else "implicit DENY",
                "Reason: %s" % result["reason"],
            ]
        )
        return "\n".join(lines) + "\n"

    def evaluate_internet_access(
        self,
        source_ip: str,
        destination: str,
        port: int,
        protocol: str,
        *,
        candidate_ips: Optional[list[str]] = None,
    ) -> dict:
        from drlink_v24 import effective_policy_result, get_access_policy, rule_matches_service

        proto = str(protocol).lower()
        dest_raw = str(destination or "").strip()
        is_ip_literal = False
        try:
            dest = ipaddress.ip_address(dest_raw).compressed
            is_ip_literal = True
        except ValueError:
            dest = dest_raw.rstrip(".").lower()

        normalized_candidates: Optional[list[str]] = None
        if candidate_ips is not None:
            normalized_candidates = []
            for item in candidate_ips:
                try:
                    normalized_candidates.append(ipaddress.ip_address(str(item).strip()).compressed)
                except ValueError as exc:
                    raise ControlPlaneError("invalid candidate address: %s" % item) from exc
        elif is_ip_literal:
            normalized_candidates = [dest]

        src_matches = self.matching_objects_for_ip(source_ip, role="source")
        if is_ip_literal:
            dst_matches = self.matching_objects_for_ip(dest, role="destination")
        else:
            dst_matches = self.matching_objects_for_host(dest)
            if normalized_candidates:
                for cand in normalized_candidates:
                    for name in self.matching_objects_for_ip(cand, role="destination"):
                        if name not in dst_matches:
                            dst_matches.append(name)

        pol = get_access_policy(self, "internet")
        if pol["mode"] is None and self._legacy_unmigrated("internet"):
            reason = "Legacy v2.3 Internet Access policy is not migrated (fail closed)"
            return {
                "source_ip": source_ip,
                "destination": dest,
                "port": int(port),
                "protocol": proto,
                "is_ip_literal": is_ip_literal,
                "candidate_ips": list(normalized_candidates or []),
                "authorized_candidates": [],
                "candidate_results": [],
                "source_matches": src_matches,
                "destination_matches": dst_matches,
                "traces": [],
                "winner": None,
                "matched_rules": [],
                "mode": None,
                "enforcement": pol["enforcement"],
                "action": "DENY",
                "implicit": True,
                "reason": reason,
                "effective": "DENY",
            }

        # Build rule views once.
        rule_rows = []
        for rule_row in self.conn.execute(
            "SELECT * FROM policy_rules WHERE plane = 'internet' ORDER BY name"
        ):
            if not rule_row["enabled"]:
                continue
            rule_rows.append(rule_row)

        def _rule_src_svc(rule_row):
            view = self._rule_view(rule_row)
            src_ok = False
            for s in self.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_sources WHERE rule_id = ?", (rule_row["id"],)
            ):
                if self._ref_matches_ip(s["ref_kind"], s["ref_id"], source_ip, role="source"):
                    src_ok = True
                    break
            svc_ok = rule_matches_service(self, rule_row["id"], proto, port)
            return view, src_ok, svc_ok

        def _dest_ok(rule_row, cand_ip: Optional[str]) -> bool:
            for s in self.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_destinations WHERE rule_id = ?", (rule_row["id"],)
            ):
                if self._ref_matches_internet_destination(
                    s["ref_kind"],
                    s["ref_id"],
                    dest,
                    is_ip_literal=is_ip_literal,
                    candidate_ip=cand_ip,
                ):
                    return True
            return False

        # Aggregate traces use hostname-level destination match (any candidate).
        traces = []
        matched = []
        for rule_row in rule_rows:
            view, src_ok, svc_ok = _rule_src_svc(rule_row)
            if normalized_candidates is None:
                dst_ok = _dest_ok(rule_row, None)
            else:
                dst_ok = False
                for cand in normalized_candidates:
                    if _dest_ok(rule_row, cand):
                        dst_ok = True
                        break
                # FQDN selectors match hostname without needing a candidate IP.
                if not dst_ok and not is_ip_literal:
                    dst_ok = _dest_ok(rule_row, None)
            hit = bool(src_ok and dst_ok and svc_ok)
            traces.append(
                {
                    "rule": view,
                    "evaluated": True,
                    "source": src_ok,
                    "dest": dst_ok,
                    "service": svc_ok,
                    "match": hit,
                }
            )
            if hit:
                matched.append(view)

        candidate_results = []
        authorized_candidates: list[str] = []
        if normalized_candidates is not None:
            for cand in normalized_candidates:
                cand_matched = []
                for rule_row in rule_rows:
                    view, src_ok, svc_ok = _rule_src_svc(rule_row)
                    # Per-candidate: Host/CIDR vs cand, or FQDN vs hostname (non-literal).
                    dst_ok = _dest_ok(rule_row, cand)
                    if not dst_ok and not is_ip_literal:
                        dst_ok = _dest_ok(rule_row, None)
                    if src_ok and dst_ok and svc_ok:
                        cand_matched.append(view)
                cand_action = effective_policy_result(
                    pol["mode"], pol["enforcement"], bool(cand_matched)
                )
                candidate_results.append(
                    {
                        "ip": cand,
                        "action": cand_action,
                        "matched_rules": [m["name"] for m in cand_matched],
                    }
                )
                if cand_action == "ALLOW":
                    authorized_candidates.append(cand)
            if pol["mode"] is None or str(pol["enforcement"]).lower() == "disabled":
                action = "ALLOW"
            elif authorized_candidates:
                action = "ALLOW"
            else:
                action = "DENY"
        else:
            action = effective_policy_result(pol["mode"], pol["enforcement"], bool(matched))

        winner = matched[0] if matched else None
        if pol["mode"] is None:
            reason = "No Policy (ALLOW)"
        elif str(pol["enforcement"]).lower() == "disabled":
            reason = "Policy enforcement DISABLED (ALLOW ALL)"
        elif matched:
            reason = "Internet Access matched rule(s): %s" % ", ".join(m["name"] for m in matched)
        else:
            reason = "No enabled Internet Access rule matched (%s)" % (
                "ALLOW" if pol["mode"] == "blacklist" else "DENY"
            )
        return {
            "source_ip": source_ip,
            "destination": dest,
            "port": int(port),
            "protocol": proto,
            "is_ip_literal": is_ip_literal,
            "candidate_ips": list(normalized_candidates or []),
            "authorized_candidates": list(authorized_candidates),
            "candidate_results": candidate_results,
            "source_matches": src_matches,
            "destination_matches": dst_matches,
            "traces": traces,
            "winner": winner,
            "matched_rules": [m["name"] for m in matched],
            "mode": pol["mode"],
            "enforcement": pol["enforcement"],
            "action": action,
            "implicit": winner is None,
            "reason": reason,
            "effective": action,
        }

    def format_internet_explain(self, result: dict, *, dns: Optional[dict] = None) -> str:
        lines = [
            "Internet Access Policy Evaluation",
            "",
            "Source",
            "------",
            result["source_ip"],
            "Matched:",
        ]
        lines.extend(["  %s" % n for n in result["source_matches"]] or ["  (none)"])
        lines.extend(["", "Destination", "-----------", result["destination"], "Matched:"])
        lines.extend(["  %s" % n for n in result["destination_matches"]] or ["  (none)"])
        if dns:
            lines.extend(["", "DNS", "---", "Resolution: %s" % dns.get("status", "-")])
            if dns.get("addresses"):
                for addr in dns["addresses"]:
                    lines.append("  %s" % addr)
            if dns.get("security"):
                lines.append("Security  : %s" % dns["security"])
        lines.extend(["", "Service", "-------", "%s/%s" % (result["protocol"], result["port"]), "", "Rule Evaluation", "---------------"])
        decided = False
        for item in result["traces"]:
            rule = item["rule"]
            header = "#%s %s" % (rule["display_position"], rule["name"])
            if not item.get("evaluated"):
                lines.append(header)
                lines.append("  Not evaluated")
                lines.append("")
                continue
            lines.append(header)
            lines.append("  Source      %s" % ("MATCH" if item.get("source") else "NO MATCH"))
            lines.append("  Destination %s" % ("MATCH" if item.get("dest") else "NO MATCH"))
            lines.append("  Service     %s" % ("MATCH" if item.get("service") else "NO MATCH"))
            if item.get("source") and item.get("dest") and item.get("service") and not decided:
                lines.append("")
                lines.append("FIRST COMPLETE MATCH")
                lines.append("Action: %s" % rule["action"].upper())
                decided = True
            lines.append("")
        lines.extend(["Final Result", "------------", result["action"], "Reason: %s" % result["reason"]])
        return "\n".join(lines) + "\n"

    # --- fixed TCP --------------------------------------------------------
    def set_fixed_tcp(self, name: str, *, dest_host: Optional[str] = None, dest_port: Optional[int] = None, destination_object: Optional[str] = None, listen_port: Optional[int] = None, enabled: Optional[bool] = None) -> dict:
        name = _validate_name(name, "Fixed TCP name")
        dest_obj_id = None
        if destination_object:
            obj = self.require_object(destination_object)
            dest_obj_id = obj["id"]
            vals = self._object_values(obj["id"])
            if obj["type"] == "host" and vals:
                dest_host = vals[0]
            if obj["type"] == "fqdn" and vals:
                dest_host = vals[0]

        def write():
            existing = self.conn.execute(
                "SELECT * FROM fixed_tcp WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
            now = utc_now_iso()
            if existing:
                self.conn.execute(
                    "UPDATE fixed_tcp SET dest_host = COALESCE(?, dest_host), dest_port = COALESCE(?, dest_port), "
                    "destination_object_id = COALESCE(?, destination_object_id), listen_port = COALESCE(?, listen_port), "
                    "enabled = COALESCE(?, enabled), row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (dest_host, dest_port, dest_obj_id, listen_port, (None if enabled is None else int(bool(enabled))), now, existing["id"]),
                )
                return {"entity": {"type": "fixed-tcp", "id": existing["id"], "name": name}, "operation": "update"}
            fid = _new_id("ftcp")
            lport = listen_port
            if lport is None:
                used = {r[0] for r in self.conn.execute("SELECT listen_port FROM fixed_tcp WHERE listen_port IS NOT NULL")}
                for candidate in range(6200, 6300):
                    if candidate not in used:
                        lport = candidate
                        break
            self.conn.execute(
                "INSERT INTO fixed_tcp(id, name, listen_port, dest_host, dest_port, destination_object_id, enabled, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (fid, name, lport, dest_host, dest_port, dest_obj_id, int(bool(enabled)) if enabled is not None else 0, now, now),
            )
            return {"entity": {"type": "fixed-tcp", "id": fid, "name": name}, "operation": "create"}

        return self._mutate("set fixed-tcp %s" % name, "set fixed tcp", write)

    def unset_fixed_tcp(self, name: str) -> dict:
        existing = self.conn.execute(
            "SELECT * FROM fixed_tcp WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if existing is None:
            raise ControlPlaneError("Fixed TCP entry not found: %s" % name)

        def write():
            self.conn.execute("DELETE FROM fixed_tcp WHERE id = ?", (existing["id"],))
            return {"entity": {"type": "fixed-tcp", "id": existing["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset fixed-tcp %s" % name, "delete fixed tcp", write)

    def evaluate_fixed_tcp(self, name: str, source_ip: str) -> dict:
        entry = self.conn.execute(
            "SELECT * FROM fixed_tcp WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if entry is None:
            raise ControlPlaneError("Fixed TCP entry not found: %s" % name)
        dest = entry["dest_host"] or ""
        if entry["destination_object_id"]:
            vals = [
                str(v).strip()
                for v in self._object_values(entry["destination_object_id"])
                if str(v or "").strip()
            ]
            if vals:
                dest = vals[0]
        port = int(entry["dest_port"] or 0)
        policy = self.evaluate_internet_access(source_ip, dest, port, "tcp")
        return {"entry": name, "source_ip": source_ip, "destination": dest, "port": port, "policy": policy}

    # --- AI principals / rules --------------------------------------------
    def get_principal(self, name: str) -> Optional[sqlite3.Row]:
        row = self.conn.execute(
            "SELECT * FROM ai_principals WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if row is not None and row["name"] == OAUTH_UNBOUND_PRINCIPAL:
            return None
        return row

    def set_ai_principal(self, name: str, *, description: Optional[str] = None, enabled: Optional[bool] = None) -> dict:
        name = _validate_name(name, "AI Principal name")
        if name == OAUTH_UNBOUND_PRINCIPAL:
            raise ControlPlaneError("reserved AI Principal name")

        def write():
            existing = self.get_principal(name)
            now = utc_now_iso()
            if existing:
                self.conn.execute(
                    "UPDATE ai_principals SET description = COALESCE(?, description), "
                    "enabled = COALESCE(?, enabled), row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (description, None if enabled is None else int(bool(enabled)), now, existing["id"]),
                )
                return {"entity": {"type": "ai-principal", "id": existing["id"], "name": name}, "operation": "update"}
            pid = _new_id("aipr")
            self.conn.execute(
                "INSERT INTO ai_principals(id, name, description, enabled, credential_status, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'none', 1, ?, ?)",
                (pid, name, description or "", int(bool(enabled)) if enabled is not None else 0, now, now),
            )
            return {"entity": {"type": "ai-principal", "id": pid, "name": name}, "operation": "create"}

        return self._mutate("set ai-principal %s" % name, "set AI principal", write)

    def unset_ai_principal(self, name: str) -> dict:
        existing = self.get_principal(name)
        if existing is None:
            raise ControlPlaneError("AI Principal not found: %s" % name)
        # v2.4 AI Access stores sources on ai_policy_rules; legacy capability
        # rules remain on ai_access_rules. Both must block deletion.
        refs = []
        for row in self.conn.execute(
            "SELECT name FROM ai_policy_rules WHERE source_identity_id = ? ORDER BY name COLLATE NOCASE",
            (existing["id"],),
        ):
            refs.append("ai-access %s" % row["name"])
        for row in self.conn.execute(
            "SELECT name FROM ai_access_rules WHERE principal_id = ? ORDER BY name COLLATE NOCASE",
            (existing["id"],),
        ):
            refs.append("ai-access %s" % row["name"])
        if refs:
            raise ControlPlaneError(
                "ERROR:\nAI Identity '%s' is still referenced.\n\nReferences:\n%s\n\n"
                "No changes were applied."
                % (name, "\n".join("  %s" % r for r in refs))
            )

        def write():
            self.conn.execute("DELETE FROM ai_sessions WHERE principal_id = ?", (existing["id"],))
            self.conn.execute("DELETE FROM ai_principals WHERE id = ?", (existing["id"],))
            return {"entity": {"type": "ai-principal", "id": existing["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset ai-principal %s" % name, "delete AI principal", write)

    def rotate_ai_credential(self, name: str) -> dict:
        principal = self.get_principal(name)
        if principal is None:
            self.set_ai_principal(name)
            principal = self.get_principal(name)
        token = "drk_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        fp = digest[:12]

        def write():
            now = utc_now_iso()
            self.conn.execute(
                "UPDATE ai_sessions SET revoked_at = ? WHERE principal_id = ? AND revoked_at IS NULL",
                (now, principal["id"]),
            )
            self.conn.execute(
                "UPDATE ai_principals SET credential_hash = ?, credential_fingerprint = ?, "
                "credential_status = 'active', auth_mode = COALESCE(NULLIF(auth_mode, ''), 'static-bearer'), "
                "row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (digest, fp, now, principal["id"]),
            )
            self._revoke_oauth_tokens(principal["id"], now)
            sid = _new_id("sess")
            self.conn.execute(
                "INSERT INTO ai_sessions(id, principal_id, credential_fingerprint, created_at) VALUES (?, ?, ?, ?)",
                (sid, principal["id"], fp, now),
            )
            return {
                "entity": {"type": "ai-principal", "id": principal["id"], "name": name},
                "operation": "rotate",
                "fingerprint": fp,
                "after": "credential rotated fingerprint=%s" % fp,
            }

        result = self._mutate("system credential rotate ai-principal %s" % name, "rotate credential", write)
        if isinstance(result, dict):
            result["token"] = token
        return result

    def revoke_ai_credential(self, name: str) -> dict:
        principal = self.get_principal(name)
        if principal is None:
            raise ControlPlaneError("AI Principal not found: %s" % name)

        def write():
            now = utc_now_iso()
            self.conn.execute(
                "UPDATE ai_sessions SET revoked_at = ? WHERE principal_id = ? AND revoked_at IS NULL",
                (now, principal["id"]),
            )
            self.conn.execute(
                "UPDATE ai_principals SET credential_hash = NULL, credential_status = 'revoked', "
                "row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (now, principal["id"]),
            )
            self._revoke_oauth_tokens(principal["id"], now)
            return {"entity": {"type": "ai-principal", "id": principal["id"], "name": name}, "operation": "revoke"}

        return self._mutate("system credential revoke ai-principal %s" % name, "revoke credential", write)

    def _revoke_oauth_tokens(self, principal_id: str, now: Optional[str] = None) -> None:
        stamp = now or utc_now_iso()
        self.conn.execute(
            "UPDATE ai_oauth_tokens SET revoked_at = ? WHERE principal_id = ? AND revoked_at IS NULL",
            (stamp, principal_id),
        )
        self.conn.execute("DELETE FROM ai_oauth_codes WHERE principal_id = ?", (principal_id,))
        self.conn.execute("DELETE FROM ai_oauth_pending WHERE principal_id = ?", (principal_id,))

    def _touch_principal(self, principal_id: str) -> None:
        self.conn.execute(
            "UPDATE ai_principals SET last_seen = ? WHERE id = ?",
            (utc_now_iso(), principal_id),
        )

    def _iso_plus_seconds(self, seconds: int) -> str:
        return (
            datetime.now(timezone.utc) + timedelta(seconds=int(seconds))
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _pkce_s256(self, verifier: str) -> str:
        digest = hashlib.sha256(str(verifier).encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _ensure_oauth_unbound_principal(self) -> str:
        row = self.conn.execute(
            "SELECT id FROM ai_principals WHERE name = ?", (OAUTH_UNBOUND_PRINCIPAL,)
        ).fetchone()
        if row:
            return row["id"]
        now = utc_now_iso()
        pid = _new_id("aip")
        self.conn.execute(
            "INSERT INTO ai_principals(id, name, description, provider, enabled, credential_status, "
            "auth_mode, oauth_issuer, oauth_subject, row_version, created_at, updated_at) "
            "VALUES (?, ?, 'OAuth unbound placeholder', '', 0, 'revoked', 'oauth', '', '', 1, ?, ?)",
            (pid, OAUTH_UNBOUND_PRINCIPAL, now, now),
        )
        return pid

    def _oauth_loopback_http_host(self, host: str) -> bool:
        """True only for actual loopback hostnames/addresses (not prefix lookalikes)."""
        name = str(host or "").strip().lower().rstrip(".")
        if not name:
            return False
        if name == "localhost":
            return True
        try:
            return ipaddress.ip_address(name).is_loopback
        except ValueError:
            return False

    def _validate_oauth_redirect_uri(self, uri: str) -> str:
        text = str(uri or "").strip()
        if not text:
            raise ControlPlaneError("redirect_uri is required")
        if "*" in text:
            raise ControlPlaneError("wildcard redirect_uri is not allowed")
        # OAuth 2.0 §3.1.2: redirection endpoint URI MUST NOT include a fragment.
        if "#" in text:
            raise ControlPlaneError("redirect_uri fragment is not allowed")
        lower = text.lower()
        if lower.startswith("javascript:") or lower.startswith("data:") or lower.startswith("file:"):
            raise ControlPlaneError("redirect_uri scheme is not allowed")
        from urllib.parse import urlparse

        try:
            parsed = urlparse(text)
        except ValueError as exc:
            raise ControlPlaneError("redirect_uri is malformed") from exc
        try:
            port = parsed.port
        except ValueError as exc:
            raise ControlPlaneError("redirect_uri port is malformed") from exc
        if port is not None and not (1 <= int(port) <= 65535):
            raise ControlPlaneError("redirect_uri port is out of range")
        scheme = str(parsed.scheme or "").lower()
        if scheme == "https":
            if not parsed.hostname:
                raise ControlPlaneError("redirect_uri host is required")
            if parsed.username is not None or parsed.password is not None:
                raise ControlPlaneError("redirect_uri userinfo is not allowed")
            return text
        if scheme == "http":
            host = parsed.hostname
            if host is None:
                raise ControlPlaneError("redirect_uri host is required")
            if parsed.username is not None or parsed.password is not None:
                raise ControlPlaneError("redirect_uri userinfo is not allowed")
            if not self._oauth_loopback_http_host(host):
                raise ControlPlaneError("OAuth redirect URI must be https or loopback http")
            return text
        raise ControlPlaneError("OAuth redirect URI must be https or loopback http")

    def _redirect_uris_list(self, raw: str) -> list[str]:
        return [p for p in str(raw or "").split("\n") if p]

    def _lookup_oauth_client(self, client_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ai_oauth_clients WHERE client_id = ?", (client_id,)
        ).fetchone()

    def _lookup_dcr_client(self, client_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ai_oauth_dcr_clients WHERE client_id = ?", (client_id,)
        ).fetchone()

    def _cimd_exact_identifier(self, url: str) -> str:
        """Return the Client Identifier URL unchanged.

        Leading or trailing whitespace/control characters are rejected. The
        identifier must not be stripped or rewritten before fetch, metadata
        comparison, or cache keying (simple string comparison).
        """
        requested = "" if url is None else str(url)
        if not requested:
            return requested

        def _edge_rejected(ch: str) -> bool:
            code = ord(ch)
            return ch.isspace() or code < 32 or code == 127

        if _edge_rejected(requested[0]) or _edge_rejected(requested[-1]):
            raise ControlPlaneError(
                "CIMD client_id must not include leading or trailing whitespace or control characters"
            )
        return requested

    def _cimd_validate_request_url(self, url: str):
        """Structurally validate a CIMD metadata URL (https, path, no unsafe authority)."""
        from urllib.parse import urlparse

        text = self._cimd_exact_identifier(url)
        if not text:
            raise ControlPlaneError("CIMD client_id must be an https URL with a path")
        if "#" in text:
            raise ControlPlaneError("CIMD URL fragment is not allowed")
        try:
            parsed = urlparse(text)
        except ValueError as exc:
            raise ControlPlaneError("CIMD URL is malformed") from exc
        if str(parsed.scheme or "").lower() != "https":
            raise ControlPlaneError("CIMD client_id must be an https URL with a path")
        if parsed.username is not None or parsed.password is not None:
            raise ControlPlaneError("CIMD URL userinfo is not allowed")
        if not parsed.hostname:
            raise ControlPlaneError("CIMD URL host is required")
        if parsed.path in ("", "/"):
            raise ControlPlaneError("CIMD client_id must be an https URL with a path")
        for segment in str(parsed.path).split("/"):
            if segment in (".", ".."):
                raise ControlPlaneError("CIMD URL path must not contain dot segments")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ControlPlaneError("CIMD URL port is malformed") from exc
        if port is not None and not (1 <= int(port) <= 65535):
            raise ControlPlaneError("CIMD URL port is out of range")
        return parsed

    def _cimd_ip_blocked(self, ip: ipaddress._BaseAddress) -> bool:
        """Fail closed for loopback/private/link-local/multicast/reserved/special-use."""
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return self._cimd_ip_blocked(ip.ipv4_mapped)
        if not is_public_ip(ip.compressed):
            return True
        for net in _CIMD_BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False

    def _cimd_resolve_validated_ips(self, hostname: str) -> list[str]:
        """Resolve hostname; fail closed if any candidate is private/special."""
        import socket

        host = str(hostname or "").strip()
        if not host:
            raise ControlPlaneError("CIMD URL host is required")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if self._cimd_ip_blocked(literal):
                raise ControlPlaneError("CIMD destination is not allowed")
            return [literal.compressed]
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ControlPlaneError("CIMD metadata fetch failed") from exc
        allowed: list[str] = []
        seen: set[str] = set()
        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if self._cimd_ip_blocked(ip):
                raise ControlPlaneError("CIMD destination is not allowed")
            key = ip.compressed
            if key in seen:
                continue
            seen.add(key)
            allowed.append(key)
        if not allowed:
            raise ControlPlaneError("CIMD destination is not allowed")
        return allowed

    def _cimd_ssl_context(self):
        import ssl

        return ssl.create_default_context()

    def _cimd_content_type_allowed(self, content_type: str) -> bool:
        ctype = str(content_type or "").split(";", 1)[0].strip().lower()
        if ctype == "application/json":
            return True
        return ctype.startswith("application/") and ctype.endswith("+json")

    def _cimd_https_get_pinned(self, parsed, peer_ip: str) -> tuple[int, dict[str, str], bytes]:
        """HTTPS GET connecting only to a previously validated peer IP (anti-rebinding)."""
        import http.client
        import socket

        host = str(parsed.hostname or "")
        port = int(parsed.port or 443)
        path = parsed.path or "/"
        if parsed.query:
            path = "%s?%s" % (path, parsed.query)
        peer = str(peer_ip or "").strip()
        try:
            peer_obj = ipaddress.ip_address(peer)
        except ValueError as exc:
            raise ControlPlaneError("CIMD destination is not allowed") from exc
        if self._cimd_ip_blocked(peer_obj):
            raise ControlPlaneError("CIMD destination is not allowed")

        context = self._cimd_ssl_context()
        sock = socket.create_connection((peer, port), timeout=CIMD_FETCH_TIMEOUT)
        try:
            ssock = context.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            raise
        conn = http.client.HTTPSConnection(host, port, timeout=CIMD_FETCH_TIMEOUT, context=context)
        conn.sock = ssock
        try:
            host_header = host if port == 443 else "%s:%s" % (host, port)
            conn.request(
                "GET",
                path,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "DataRelayLink-MCP/2.4",
                    "Host": host_header,
                },
            )
            resp = conn.getresponse()
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > CIMD_FETCH_MAX_BYTES:
                    raise ControlPlaneError("CIMD metadata response too large")
                chunks.append(chunk)
            headers = {str(k).lower(): str(v) for k, v in resp.getheaders()}
            return int(resp.status), headers, b"".join(chunks)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _fetch_cimd_document(self, url: str) -> dict:
        """Fetch CIMD JSON with SSRF-safe destination pinning (no redirect follow)."""
        requested = self._cimd_exact_identifier(url)
        parsed = self._cimd_validate_request_url(requested)
        peers = self._cimd_resolve_validated_ips(parsed.hostname)
        peer = peers[0]
        try:
            status, headers, raw = self._cimd_https_get_pinned(parsed, peer)
        except ControlPlaneError:
            raise
        except Exception as exc:
            raise ControlPlaneError("CIMD metadata fetch failed") from exc
        if 300 <= status < 400:
            raise ControlPlaneError("CIMD metadata redirect is not allowed")
        if status != 200:
            raise ControlPlaneError("CIMD metadata fetch failed")
        if not self._cimd_content_type_allowed(headers.get("content-type") or ""):
            raise ControlPlaneError("CIMD metadata content-type is not allowed")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ControlPlaneError("CIMD metadata is not valid JSON") from exc
        if not isinstance(doc, dict):
            raise ControlPlaneError("CIMD metadata must be a JSON object")
        meta_client_id = doc.get("client_id")
        if not isinstance(meta_client_id, str) or meta_client_id != requested:
            raise ControlPlaneError("CIMD metadata client_id must exactly match the requested URL")
        return doc

    def register_oauth_client(self, metadata: dict) -> dict:
        """RFC 7591 Dynamic Client Registration (public clients)."""
        if not isinstance(metadata, dict):
            raise ControlPlaneError("client metadata must be a JSON object")
        redirects = metadata.get("redirect_uris") or []
        if not isinstance(redirects, list) or not redirects:
            raise ControlPlaneError("redirect_uris is required")
        if len(redirects) > OAUTH_MAX_REDIRECTS:
            raise ControlPlaneError("too many redirect_uris")
        cleaned = []
        for item in redirects:
            cleaned.append(self._validate_oauth_redirect_uri(str(item)))
        # Exact-match only; reject open-prefix patterns
        for uri in cleaned:
            if "*" in uri:
                raise ControlPlaneError("wildcard redirect_uri is not allowed")
        auth_method = str(metadata.get("token_endpoint_auth_method") or "none").strip() or "none"
        if auth_method not in ("none", "client_secret_post", "client_secret_basic"):
            raise ControlPlaneError("unsupported token_endpoint_auth_method")
        grant_types = metadata.get("grant_types") or ["authorization_code", "refresh_token"]
        if not isinstance(grant_types, list):
            raise ControlPlaneError("grant_types must be a list")
        for gt in grant_types:
            if str(gt) not in ("authorization_code", "refresh_token"):
                raise ControlPlaneError("unsupported grant_type in registration")
        client_id = "drcid_" + secrets.token_urlsafe(18)
        secret = None
        secret_hash = None
        if auth_method != "none":
            secret = "drcs_" + secrets.token_urlsafe(24)
            secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        now = utc_now_iso()
        self.conn.execute(
            "INSERT INTO ai_oauth_dcr_clients(client_id, redirect_uris, token_endpoint_auth_method, "
            "client_secret_hash, client_name, metadata_url, created_at) VALUES (?, ?, ?, ?, ?, '', ?)",
            (
                client_id,
                "\n".join(cleaned),
                auth_method,
                secret_hash,
                str(metadata.get("client_name") or "")[:128],
                now,
            ),
        )
        issued = {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": cleaned,
            "token_endpoint_auth_method": auth_method,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": str(metadata.get("client_name") or "")[:128] or None,
        }
        if secret:
            issued["client_secret"] = secret
            issued["client_secret_expires_at"] = 0
        return {k: v for k, v in issued.items() if v is not None}

    def resolve_oauth_authorize_client(self, client_id: str, redirect_uri: str, *, _cimd_doc: Optional[dict] = None) -> dict:
        """Resolve static, DCR, or CIMD client for authorization."""
        redirect_uri = self._validate_oauth_redirect_uri(redirect_uri)
        static = self._lookup_oauth_client(client_id)
        if static is not None:
            allowed = self._redirect_uris_list(static["redirect_uris"])
            if redirect_uri not in allowed:
                raise ControlPlaneError("redirect_uri is not registered")
            principal = self.conn.execute(
                "SELECT * FROM ai_principals WHERE id = ? AND enabled = 1", (static["principal_id"],)
            ).fetchone()
            if principal is None:
                raise ControlPlaneError("AI Principal disabled or missing")
            return {
                "client_id": client_id,
                "principal_id": principal["id"],
                "principal_name": principal["name"],
                "redirect_uri": redirect_uri,
                "unbound": False,
                "source": "static",
            }
        dcr = self._lookup_dcr_client(client_id)
        if dcr is not None:
            allowed = self._redirect_uris_list(dcr["redirect_uris"])
            if redirect_uri not in allowed:
                raise ControlPlaneError("redirect_uri is not registered")
            return {
                "client_id": client_id,
                "principal_id": self._ensure_oauth_unbound_principal(),
                "principal_name": OAUTH_UNBOUND_PRINCIPAL,
                "redirect_uri": redirect_uri,
                "unbound": True,
                "source": "dcr",
            }
        # CIMD: HTTPS URL client_id with path
        if str(client_id).startswith("https://"):
            doc = _cimd_doc if _cimd_doc is not None else self._fetch_cimd_document(client_id)
            redirects = doc.get("redirect_uris") or []
            if not isinstance(redirects, list):
                raise ControlPlaneError("CIMD redirect_uris must be a list")
            allowed = [self._validate_oauth_redirect_uri(str(x)) for x in redirects]
            if redirect_uri not in allowed:
                raise ControlPlaneError("redirect_uri is not registered")
            now = utc_now_iso()
            self.conn.execute(
                "INSERT OR REPLACE INTO ai_oauth_dcr_clients(client_id, redirect_uris, token_endpoint_auth_method, "
                "client_secret_hash, client_name, metadata_url, created_at) VALUES (?, ?, 'none', NULL, ?, ?, ?)",
                (
                    client_id,
                    "\n".join(allowed),
                    str(doc.get("client_name") or "cimd")[:128],
                    client_id,
                    now,
                ),
            )
            return {
                "client_id": client_id,
                "principal_id": self._ensure_oauth_unbound_principal(),
                "principal_name": OAUTH_UNBOUND_PRINCIPAL,
                "redirect_uri": redirect_uri,
                "unbound": True,
                "source": "cimd",
            }
        raise ControlPlaneError("unknown OAuth client")

    def configure_ai_auth(self, name: str, mode: str) -> dict:
        principal = self.get_principal(name)
        if principal is None:
            raise ControlPlaneError("AI Principal not found: %s" % name)
        normalized = str(mode or "").strip().lower().replace("_", "-")
        if normalized in ("static", "static-bearer", "bearer"):
            normalized = "static-bearer"
        elif normalized == "oauth":
            normalized = "oauth"
        else:
            raise ControlPlaneError("Authentication type must be static-bearer or oauth")

        def write():
            now = utc_now_iso()
            subject = principal["name"] if normalized == "oauth" else ""
            self.conn.execute(
                "UPDATE ai_principals SET auth_mode = ?, oauth_subject = ?, row_version = row_version + 1, "
                "updated_at = ? WHERE id = ?",
                (normalized, subject, now, principal["id"]),
            )
            if normalized == "oauth":
                self.conn.execute(
                    "INSERT OR REPLACE INTO ai_oauth_clients(client_id, principal_id, redirect_uris, created_at) "
                    "VALUES (?, ?, COALESCE((SELECT redirect_uris FROM ai_oauth_clients WHERE client_id = ?), ''), ?)",
                    (principal["name"], principal["id"], principal["name"], now),
                )
            return {
                "entity": {"type": "ai-principal", "id": principal["id"], "name": name},
                "operation": "configure-auth",
                "after": "authentication=%s" % normalized,
            }

        return self._mutate("system credential configure ai-principal %s" % name, "configure credential", write)

    def add_oauth_redirect(self, name: str, uri: str) -> dict:
        principal = self.get_principal(name)
        if principal is None:
            raise ControlPlaneError("AI Principal not found: %s" % name)
        text = self._validate_oauth_redirect_uri(uri)

        def write():
            now = utc_now_iso()
            row = self.conn.execute(
                "SELECT redirect_uris FROM ai_oauth_clients WHERE client_id = ?",
                (principal["name"],),
            ).fetchone()
            existing = [p for p in str(row["redirect_uris"] if row else "").split("\n") if p]
            if text not in existing:
                if len(existing) >= OAUTH_MAX_REDIRECTS:
                    raise ControlPlaneError("too many redirect_uris")
                existing.append(text)
            self.conn.execute(
                "INSERT OR REPLACE INTO ai_oauth_clients(client_id, principal_id, redirect_uris, created_at) "
                "VALUES (?, ?, ?, ?)",
                (principal["name"], principal["id"], "\n".join(existing), now),
            )
            self.conn.execute(
                "UPDATE ai_principals SET auth_mode = 'oauth', oauth_subject = ?, row_version = row_version + 1, "
                "updated_at = ? WHERE id = ?",
                (principal["name"], now, principal["id"]),
            )
            return {
                "entity": {"type": "ai-principal", "id": principal["id"], "name": name},
                "operation": "configure-oauth-redirect",
            }

        return self._mutate("system credential configure ai-principal %s oauth-redirect" % name, "configure credential", write)

    def create_oauth_pending(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        resource: str,
        state: str = "",
        source: str = "",
    ) -> dict:
        if not code_challenge:
            raise ControlPlaneError("code_challenge is required")
        # CIMD metadata is fetched before the DB lock so a slow peer cannot stall admission.
        cimd_doc = None
        with self._db_lock:
            static_known = self._lookup_oauth_client(client_id) is not None
            dcr_known = self._lookup_dcr_client(client_id) is not None
        if not static_known and not dcr_known and str(client_id).startswith("https://"):
            cimd_doc = self._fetch_cimd_document(client_id)
        pending_id = _new_id("oap")
        completion_token = secrets.token_urlsafe(32)
        now = utc_now_iso()
        expires_at = self._iso_plus_seconds(OAUTH_PENDING_TTL)
        # Public authorize passes the trusted request source. Empty means a non-HTTP
        # caller; those admissions stay under the per-client and global caps only.
        admission_source = str(source or "").strip()
        with self._db_lock:
            resolved = self.resolve_oauth_authorize_client(
                client_id, redirect_uri, _cimd_doc=cimd_doc
            )
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self._sweep_expired_oauth_pending()
                per_client = int(
                    self.conn.execute(
                        "SELECT COUNT(*) AS n FROM ai_oauth_pending WHERE client_id = ?",
                        (client_id,),
                    ).fetchone()["n"]
                )
                per_source = 0
                if admission_source:
                    per_source = int(
                        self.conn.execute(
                            "SELECT COUNT(*) AS n FROM ai_oauth_pending WHERE source_addr = ?",
                            (admission_source,),
                        ).fetchone()["n"]
                    )
                total = int(self.conn.execute("SELECT COUNT(*) AS n FROM ai_oauth_pending").fetchone()["n"])
                if (
                    per_client >= OAUTH_PENDING_MAX_PER_CLIENT
                    or (admission_source and per_source >= OAUTH_PENDING_MAX_PER_SOURCE)
                    or total >= OAUTH_PENDING_MAX_GLOBAL
                ):
                    # Persist expiry reclamation even when the new row is refused.
                    self._commit_open_transaction()
                    if per_client >= OAUTH_PENDING_MAX_PER_CLIENT:
                        scope = "client"
                    elif admission_source and per_source >= OAUTH_PENDING_MAX_PER_SOURCE:
                        scope = "source"
                    else:
                        scope = "global"
                    raise OAuthPendingCapacityError(scope)
                self.conn.execute(
                    "INSERT INTO ai_oauth_pending(id, principal_id, client_id, redirect_uri, code_challenge, resource, state, "
                    "created_at, completion_token, status, expires_at, decision_at, consumed_at, code_plain, source_addr) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, '', '', '', ?)",
                    (
                        pending_id,
                        resolved["principal_id"],
                        client_id,
                        resolved["redirect_uri"],
                        code_challenge,
                        resource or "",
                        state or "",
                        now,
                        completion_token,
                        expires_at,
                        admission_source,
                    ),
                )
                self._commit_open_transaction()
            except OAuthPendingCapacityError:
                raise
            except Exception:
                self._rollback_open_transaction()
                raise
        return {
            "id": pending_id,
            "principal": resolved["principal_name"],
            "client_id": client_id,
            "unbound": bool(resolved.get("unbound")),
            "source": resolved.get("source"),
            "completion_token": completion_token,
            "expires_at": expires_at,
        }

    def _sweep_expired_oauth_pending(self) -> None:
        """Drop expired pending transactions and any unused authorization codes they hold."""
        rows = self.conn.execute("SELECT * FROM ai_oauth_pending").fetchall()
        for row in rows:
            if self._oauth_pending_expired(row):
                self._expire_oauth_pending_row(row)

    def _oauth_pending_expired(self, row) -> bool:
        expires = str(row["expires_at"] or "").strip()
        if not expires:
            return False
        try:
            exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            return True
        return datetime.now(timezone.utc) >= exp

    def _expire_oauth_pending_row(self, row) -> None:
        """Drop an expired pending/approved/denied transaction and any unused code."""
        code_plain = str(row["code_plain"] or "").strip()
        if code_plain:
            digest = hashlib.sha256(code_plain.encode("utf-8")).hexdigest()
            self.conn.execute(
                "DELETE FROM ai_oauth_codes WHERE code_hash = ? AND used_at IS NULL",
                (digest,),
            )
        self.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (row["id"],))

    def _oauth_approval_lifecycle_error(self, name: str) -> ControlPlaneError:
        """Revoked and unverified identities stay fail-closed. Approval does not revive them."""
        return ControlPlaneError(
            "ERROR:\nAI Identity '%s' is revoked or not VERIFIED.\n\n"
            "Verify or reactivate the AI Identity explicitly before OAuth approval.\n"
            "Approval leaves a revoked identity revoked.\n\n"
            "No changes were applied." % name
        )

    def approve_oauth_pending(
        self, pending_id: str, principal_name: Optional[str] = None, *, retain_for_browser: bool = True
    ) -> dict:
        row = self.conn.execute("SELECT * FROM ai_oauth_pending WHERE id = ?", (pending_id,)).fetchone()
        if row is None:
            raise ControlPlaneError("OAuth request not found")
        status = str(row["status"] or "pending")
        if str(row["consumed_at"] or "").strip():
            raise ControlPlaneError("OAuth request already completed")
        if status == "denied":
            raise ControlPlaneError("OAuth request was denied")
        if self._oauth_pending_expired(row):
            self._expire_oauth_pending_row(row)
            raise ControlPlaneError("OAuth request expired")
        if status == "approved":
            # Idempotent confirmation while browser has not continued yet.
            # Do not re-emit the authorization code; browser /oauth/continue delivers it once.
            out = {
                "redirect_uri": row["redirect_uri"],
                "state": row["state"],
                "resource": row["resource"],
                "completion_token": row["completion_token"],
                "status": "approved",
            }
            if not retain_for_browser and str(row["code_plain"] or "").strip():
                out["code"] = row["code_plain"]
            return out
        if status != "pending":
            raise ControlPlaneError("OAuth request is not pending")
        principal = self.conn.execute(
            "SELECT * FROM ai_principals WHERE id = ?", (row["principal_id"],)
        ).fetchone()
        unbound = principal is not None and principal["name"] == OAUTH_UNBOUND_PRINCIPAL
        if unbound:
            if not principal_name:
                raise ControlPlaneError(
                    "DCR/CIMD OAuth approval requires an AI Principal: "
                    "system credential approve-oauth %s <PRINCIPAL>" % pending_id
                )
            target = self.get_principal(principal_name)
            if target is None or not int(target["enabled"] or 0):
                raise ControlPlaneError("AI Principal not found or disabled: %s" % principal_name)
            if str(target["credential_status"] or "").lower() not in ("verified", "active"):
                raise self._oauth_approval_lifecycle_error(target["name"])
            # Bind DCR/CIMD client to the approved principal for future static lookups.
            now = utc_now_iso()
            dcr = self._lookup_dcr_client(row["client_id"])
            redirects = dcr["redirect_uris"] if dcr is not None else row["redirect_uri"]
            self.conn.execute(
                "INSERT OR REPLACE INTO ai_oauth_clients(client_id, principal_id, redirect_uris, created_at) "
                "VALUES (?, ?, ?, ?)",
                (row["client_id"], target["id"], redirects, now),
            )
            self.conn.execute(
                "UPDATE ai_principals SET auth_mode = 'oauth', oauth_subject = COALESCE(NULLIF(oauth_subject, ''), ?), "
                "row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (target["name"], now, target["id"]),
            )
            principal_id = target["id"]
        else:
            if principal is None or not int(principal["enabled"] or 0):
                raise ControlPlaneError("AI Principal disabled or missing")
            # pending: in-progress verification ceremony (stage_ai_identity_oauth).
            # verified/active: already trusted. none and other untrusted states are not.
            if str(principal["credential_status"] or "").lower() not in ("pending", "verified", "active"):
                raise self._oauth_approval_lifecycle_error(principal["name"])
            if principal_name and str(principal["name"]).lower() != str(principal_name).lower():
                raise ControlPlaneError("pending OAuth request is bound to a different AI Principal")
            principal_id = principal["id"]
        code = "drc_" + secrets.token_urlsafe(24)
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        now = utc_now_iso()
        self.conn.execute(
            "INSERT INTO ai_oauth_codes(code_hash, principal_id, client_id, redirect_uri, code_challenge, resource, expires_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                digest,
                principal_id,
                row["client_id"],
                row["redirect_uri"],
                row["code_challenge"],
                row["resource"],
                self._iso_plus_seconds(300),
                now,
            ),
        )
        if retain_for_browser:
            self.conn.execute(
                "UPDATE ai_oauth_pending SET status = 'approved', decision_at = ?, code_plain = ?, principal_id = ? "
                "WHERE id = ?",
                (now, code, principal_id, pending_id),
            )
            # Browser /oauth/continue is the sole production delivery boundary for the raw code.
            return {
                "redirect_uri": row["redirect_uri"],
                "state": row["state"],
                "resource": row["resource"],
                "completion_token": row["completion_token"],
                "status": "approved",
            }
        # Auto-approve / direct redirect: code is delivered immediately; drop pending.
        self.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (pending_id,))
        return {
            "code": code,
            "redirect_uri": row["redirect_uri"],
            "state": row["state"],
            "resource": row["resource"],
            "completion_token": row["completion_token"],
            "status": "approved",
        }

    def deny_oauth_pending(self, pending_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM ai_oauth_pending WHERE id = ?", (pending_id,)).fetchone()
        if row is None:
            raise ControlPlaneError("OAuth request not found")
        if str(row["consumed_at"] or "").strip():
            raise ControlPlaneError("OAuth request already completed")
        status = str(row["status"] or "pending")
        if status == "denied":
            return {
                "status": "denied",
                "redirect_uri": row["redirect_uri"],
                "state": row["state"],
                "completion_token": row["completion_token"],
            }
        if status == "approved":
            raise ControlPlaneError("OAuth request already approved")
        if self._oauth_pending_expired(row):
            self._expire_oauth_pending_row(row)
            raise ControlPlaneError("OAuth request expired")
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE ai_oauth_pending SET status = 'denied', decision_at = ?, code_plain = '' WHERE id = ?",
            (now, pending_id),
        )
        return {
            "status": "denied",
            "redirect_uri": row["redirect_uri"],
            "state": row["state"],
            "completion_token": row["completion_token"],
        }

    def complete_oauth_pending_browser(self, completion_token: str) -> dict:
        """Browser completion for manual consent. Token is unguessable and single-use."""
        token = str(completion_token or "").strip()
        if not token:
            raise ControlPlaneError("completion token is required")
        with self._db_lock:
            return self._complete_oauth_pending_browser_locked(token)

    def _complete_oauth_pending_browser_locked(self, token: str) -> dict:
        row = self.conn.execute(
            "SELECT * FROM ai_oauth_pending WHERE completion_token = ?", (token,)
        ).fetchone()
        if row is None:
            raise ControlPlaneError("OAuth continuation not found")
        if str(row["consumed_at"] or "").strip():
            raise ControlPlaneError("OAuth continuation already used")
        # Expiry bounds the whole transaction, including post-approval continuation.
        if self._oauth_pending_expired(row):
            self._expire_oauth_pending_row(row)
            raise ControlPlaneError("OAuth request expired")
        status = str(row["status"] or "pending")
        if status == "pending":
            return {
                "status": "pending",
                "id": row["id"],
                "expires_at": row["expires_at"],
            }
        now = utc_now_iso()
        # Statement-scoped claim: RETURNING proves this request owns the row.
        # Do not use connection-global SELECT changes() under threaded handlers.
        cur = self.conn.execute(
            "UPDATE ai_oauth_pending SET consumed_at = ? "
            "WHERE id = ? AND consumed_at = '' "
            "RETURNING status, redirect_uri, state, code_plain",
            (now, row["id"]),
        )
        claimed = cur.fetchone()
        if claimed is None:
            raise ControlPlaneError("OAuth continuation already used")
        status = str(claimed["status"] or "")
        code_plain = str(claimed["code_plain"] or "").strip()
        redirect_uri = claimed["redirect_uri"]
        state = claimed["state"]
        # Drop the pending row after consumption so tokens cannot be replayed.
        self.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (row["id"],))
        if status == "denied":
            return {
                "status": "denied",
                "redirect_uri": redirect_uri,
                "state": state,
                "error": "access_denied",
                "error_description": "The resource owner denied the request",
            }
        if status != "approved" or not code_plain:
            raise ControlPlaneError("OAuth request is not completable")
        return {
            "status": "approved",
            "redirect_uri": redirect_uri,
            "state": state,
            "code": code_plain,
        }

    def issue_oauth_access_token(
        self,
        *,
        principal_id: str,
        client_id: str,
        resource: str,
        ttl: int = OAUTH_ACCESS_TTL,
        include_refresh: bool = False,
        rotated_from: Optional[str] = None,
    ) -> dict:
        token = "drauth_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        fp = digest[:12]
        now = utc_now_iso()
        self.conn.execute(
            "INSERT INTO ai_oauth_tokens(token_hash, principal_id, client_id, resource, expires_at, fingerprint, created_at, kind, rotated_from) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'access', ?)",
            (digest, principal_id, client_id, resource or "", self._iso_plus_seconds(ttl), fp, now, rotated_from),
        )
        issued = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": int(ttl),
            "scope": "drlink.ai offline_access",
        }
        if include_refresh:
            refresh = "drref_" + secrets.token_urlsafe(32)
            rdigest = hashlib.sha256(refresh.encode("utf-8")).hexdigest()
            self.conn.execute(
                "INSERT INTO ai_oauth_tokens(token_hash, principal_id, client_id, resource, expires_at, fingerprint, created_at, kind, rotated_from) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'refresh', ?)",
                (
                    rdigest,
                    principal_id,
                    client_id,
                    resource or "",
                    self._iso_plus_seconds(OAUTH_REFRESH_TTL),
                    rdigest[:12],
                    now,
                    rotated_from,
                ),
            )
            issued["refresh_token"] = refresh
        return issued

    def client_credentials_token(self, client_id: str, client_secret: str, resource: str) -> Optional[dict]:
        principal = self.authenticate_static_bearer(client_secret)
        if principal is None:
            return None
        if str(principal["name"]).lower() != str(client_id or "").lower():
            return None
        if not resource:
            raise ControlPlaneError("resource is required")
        return self.issue_oauth_access_token(
            principal_id=principal["id"], client_id=client_id, resource=resource, include_refresh=False
        )

    def exchange_authorization_code(
        self, *, code: str, verifier: str, redirect_uri: str, resource: str, client_id: str
    ) -> Optional[dict]:
        digest = hashlib.sha256(str(code or "").encode("utf-8")).hexdigest()
        row = self.conn.execute(
            "SELECT * FROM ai_oauth_codes WHERE code_hash = ? AND used_at IS NULL", (digest,)
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] <= utc_now_iso():
            return None
        if not resource:
            raise ControlPlaneError("resource is required")
        if row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
            return None
        if resource != row["resource"]:
            return None
        if self._pkce_s256(verifier) != row["code_challenge"]:
            return None
        self.conn.execute(
            "UPDATE ai_oauth_codes SET used_at = ? WHERE code_hash = ?",
            (utc_now_iso(), digest),
        )
        return self.issue_oauth_access_token(
            principal_id=row["principal_id"],
            client_id=client_id,
            resource=row["resource"] or resource,
            include_refresh=True,
        )

    def exchange_refresh_token(
        self, *, refresh_token: str, client_id: str, resource: str
    ) -> Optional[dict]:
        digest = hashlib.sha256(str(refresh_token or "").encode("utf-8")).hexdigest()
        now = utc_now_iso()
        row = self.conn.execute(
            "SELECT t.* FROM ai_oauth_tokens t "
            "JOIN ai_principals p ON p.id = t.principal_id "
            "WHERE t.token_hash = ? AND t.kind = 'refresh' AND t.revoked_at IS NULL "
            "AND t.expires_at > ? AND p.enabled = 1 "
            "AND lower(p.credential_status) IN ('verified', 'active')",
            (digest, now),
        ).fetchone()
        if row is None:
            return None
        if str(row["client_id"] or "") != str(client_id or ""):
            return None
        stored = str(row["resource"] or "")
        wanted = str(resource or stored)
        if wanted != stored:
            return None
        # Rotate: revoke presented refresh (+ sibling access tokens for same client/resource).
        self.conn.execute(
            "UPDATE ai_oauth_tokens SET revoked_at = ? WHERE client_id = ? AND resource = ? "
            "AND principal_id = ? AND revoked_at IS NULL",
            (now, row["client_id"], stored, row["principal_id"]),
        )
        return self.issue_oauth_access_token(
            principal_id=row["principal_id"],
            client_id=row["client_id"],
            resource=stored,
            include_refresh=True,
            rotated_from=digest,
        )

    def revoke_oauth_credential(self, token: str) -> bool:
        digest = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()
        now = utc_now_iso()
        row = self.conn.execute(
            "SELECT * FROM ai_oauth_tokens WHERE token_hash = ? AND revoked_at IS NULL", (digest,)
        ).fetchone()
        if row is None:
            return False
        self.conn.execute(
            "UPDATE ai_oauth_tokens SET revoked_at = ? WHERE client_id = ? AND resource = ? "
            "AND principal_id = ? AND revoked_at IS NULL",
            (now, row["client_id"], row["resource"], row["principal_id"]),
        )
        return True

    def authenticate_static_bearer(self, token: str) -> Optional[sqlite3.Row]:
        digest = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()
        return self.conn.execute(
            "SELECT * FROM ai_principals WHERE credential_hash = ? AND credential_status = 'active' AND enabled = 1",
            (digest,),
        ).fetchone()

    def authenticate_oauth_token(self, token: str, resource: Optional[str] = None) -> Optional[sqlite3.Row]:
        digest = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()
        now = utc_now_iso()
        row = self.conn.execute(
            "SELECT t.* FROM ai_oauth_tokens t "
            "JOIN ai_principals p ON p.id = t.principal_id "
            "WHERE t.token_hash = ? AND t.kind = 'access' AND t.revoked_at IS NULL AND t.expires_at > ? "
            "AND p.enabled = 1 AND lower(p.credential_status) IN ('verified', 'active') AND p.name != ?",
            (digest, now, OAUTH_UNBOUND_PRINCIPAL),
        ).fetchone()
        if row is None:
            return None
        stored = str(row["resource"] or "")
        if str(resource or "") != stored:
            return None
        return self.conn.execute("SELECT * FROM ai_principals WHERE id = ?", (row["principal_id"],)).fetchone()

    def authenticate_principal(self, token: str, resource: Optional[str] = None) -> Optional[sqlite3.Row]:
        self._ensure_live_conn()
        text = str(token or "")
        if text.startswith("drref_"):
            # Refresh tokens are not MCP access credentials.
            return None
        if text.startswith("drauth_"):
            row = self.authenticate_oauth_token(text, resource=resource)
        else:
            row = self.authenticate_static_bearer(text)
            if row is None and not text.startswith("drk_"):
                row = self.authenticate_oauth_token(text, resource=resource)
        if row is not None:
            self._touch_principal(row["id"])
        return row

    def _ai_agent_credential_key(self, client_id: str) -> str:
        return "ai_agent_hash:%s" % client_id

    def _ai_job_spool_dir(self) -> Path:
        base = Path(self.root) if self.root else Path("/")
        return base / "var" / "lib" / "drlink" / "runtime" / "ai-jobs"

    def _ai_job_spool_path(self, job_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(job_id or ""))
        return self._ai_job_spool_dir() / ("%s.json" % safe)

    def issue_agent_credential(self, client_id: str, *, rotate: bool = False) -> Optional[str]:
        """Issue a one-time plaintext AI agent bearer token (hash stored server-side).

        Production Managed Host workers should prefer enrolled management identity
        claim/complete over long-lived bearer tokens. This bearer path remains for
        hermetic tests and optional bridge-local agent loops behind an explicit
        test seam.
        """
        client = self.conn.execute(
            "SELECT id, trust_status FROM clients WHERE id = ?", (client_id,)
        ).fetchone()
        if client is None or str(client["trust_status"] or "") != "trusted":
            return None
        key = self._ai_agent_credential_key(client_id)
        existing = self.conn.execute("SELECT value FROM system_meta WHERE key = ?", (key,)).fetchone()
        if existing and not rotate:
            return None
        token = "dra_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT OR REPLACE INTO system_meta(key, value) VALUES (?, ?)",
            (key, digest),
        )
        self.commit_if_autonomous()
        return token

    def revoke_agent_credential(self, client_id: str) -> None:
        self.conn.execute(
            "DELETE FROM system_meta WHERE key = ?",
            (self._ai_agent_credential_key(client_id),),
        )
        self.commit_if_autonomous()

    def authenticate_agent(self, token: str) -> Optional[str]:
        digest = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()
        row = self.conn.execute(
            "SELECT key FROM system_meta WHERE value = ? AND key LIKE 'ai_agent_hash:%'",
            (digest,),
        ).fetchone()
        if row is None:
            return None
        client_id = str(row["key"]).split(":", 1)[1]
        client = self.conn.execute(
            "SELECT trust_status FROM clients WHERE id = ?", (client_id,)
        ).fetchone()
        if client is None or str(client["trust_status"] or "") != "trusted":
            return None
        return client_id

    def assert_ai_job_claimant(self, client_id: str) -> None:
        """Fail closed when a Managed Host is missing, revoked, or retired."""
        row = self.conn.execute(
            "SELECT id, trust_status, status FROM clients WHERE id = ?", (client_id,)
        ).fetchone()
        if row is None:
            raise ControlPlaneError("unknown Managed Host")
        if str(row["trust_status"] or "") != "trusted":
            raise ControlPlaneError("Managed Host is not trusted")
        if str(row["status"] or "").lower() in ("retired", "removed", "deleted"):
            raise ControlPlaneError("Managed Host is retired")

    def enqueue_ai_job(
        self,
        *,
        principal_id: Optional[str],
        endpoint_object_id: str,
        client_id: str,
        capability: str,
        arguments: dict,
        patterns: list[str],
        timeout: Optional[int],
    ) -> str:
        ensure_ai_jobs_safety_schema(self.conn)
        job_id = _new_id("job")
        now = utc_now_iso()
        timeout_seconds = int(timeout or 30)
        deadline_at = _ai_job_deadline_iso(
            now, timeout_seconds + AI_JOB_DISPATCH_GRACE_SECONDS
        )
        payload = {
            "client_id": client_id,
            "arguments": arguments,
            "patterns": list(patterns or []),
            "timeout": timeout_seconds,
            "deadline_at": deadline_at,
        }
        self.conn.execute(
            "INSERT INTO ai_jobs(id, principal_id, endpoint_object_id, capability, payload_json, "
            "status, result_json, created_at, updated_at, timeout_seconds, client_id, deadline_at, "
            "claim_token, attempt_id, claimed_at) "
            "VALUES (?, ?, ?, ?, ?, 'queued', NULL, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
            (
                job_id,
                principal_id,
                endpoint_object_id,
                capability,
                json.dumps(payload, sort_keys=True),
                now,
                now,
                timeout_seconds,
                client_id,
                deadline_at,
            ),
        )
        return job_id

    def _terminalize_expired_queued_ai_jobs(self, *, client_id: str, now: str) -> None:
        self.conn.execute(
            "UPDATE ai_jobs SET status = 'expired', updated_at = ? "
            "WHERE status = 'queued' AND client_id = ? "
            "AND deadline_at IS NOT NULL AND deadline_at <= ?",
            (now, client_id, now),
        )

    def _fail_closed_stale_running_ai_jobs(self, *, client_id: str, now: str) -> None:
        rows = list(
            self.conn.execute(
                "SELECT id, capability FROM ai_jobs WHERE status = 'running' AND client_id = ? "
                "AND deadline_at IS NOT NULL AND deadline_at <= ?",
                (client_id, now),
            )
        )
        for row in rows:
            capability = str(row["capability"] or "")
            terminal = (
                "recovery_required"
                if capability in AI_MUTATING_CAPABILITIES
                else "expired"
            )
            self.conn.execute(
                "UPDATE ai_jobs SET status = ?, updated_at = ? "
                "WHERE id = ? AND status = 'running'",
                (terminal, now, row["id"]),
            )

    def _managed_host_admitted(self, client) -> bool:
        """Trusted, not retired, and the persisted transport flag is up.

        This is not AI-executor freshness. A quiet AI worker does not clear it.
        """
        if client is None:
            return False
        try:
            connected = int(client["connected"] or 0)
        except (KeyError, TypeError, ValueError):
            connected = 0
        if not connected:
            return False
        trust = str(client["trust_status"] or "") if "trust_status" in client.keys() else ""
        if trust and trust != "trusted":
            return False
        status = str(client["status"] or "").lower() if "status" in client.keys() else ""
        if status in ("retired", "removed", "deleted"):
            return False
        return True

    def ai_executor_ready(self, client) -> bool:
        """True when this host can accept an AI job now.

        Requires admission plus last_seen inside MANAGED_HOST_LIVENESS_SECONDS.
        """
        if not self._managed_host_admitted(client):
            return False
        last_seen = client["last_seen"] if "last_seen" in client.keys() else None
        return managed_host_liveness_fresh(last_seen)

    def client_effectively_connected(self, client) -> bool:
        """AI-executor readiness. Dispatch uses this; public connectivity does not."""
        return self.ai_executor_ready(client)

    def managed_host_connectivity(self, client) -> str:
        """Public FRP/transport projection.

        This follows the persisted connected flag and trust. It does not
        consult AI-worker claim freshness. A macOS host with no durable AI
        worker stays connected while that flag is up.
        """
        if self._managed_host_admitted(client):
            return "connected"
        return "disconnected"

    def ai_executor_status(self, client) -> str:
        return "ready" if self.ai_executor_ready(client) else "not_ready"

    def refresh_managed_host_liveness(self, client_id: str) -> bool:
        """Record signed management activity on the AI-executor clock only.

        Does not change the transport connected flag. Revoked and retired
        hosts are not revived. Repeated calls inside
        MANAGED_HOST_LIVENESS_REFRESH_SECONDS do not rewrite the row.
        Registry nonce commit is not this clock.
        """
        row = self.conn.execute(
            "SELECT trust_status, status, last_seen FROM clients WHERE id = ?", (client_id,)
        ).fetchone()
        if row is None:
            return False
        if str(row["trust_status"] or "") != "trusted":
            return False
        if str(row["status"] or "").lower() in ("retired", "removed", "deleted"):
            return False
        seen = _parse_ai_job_ts(row["last_seen"])
        now_dt = datetime.now(timezone.utc)
        if seen is not None:
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
            age = (now_dt - seen).total_seconds()
            if 0 <= age < MANAGED_HOST_LIVENESS_REFRESH_SECONDS:
                return True
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE clients SET last_seen = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
            (now, now, client_id),
        )
        self.commit_if_autonomous()
        return True

    def claim_ai_jobs(self, client_id: str, limit: int = 4) -> list[dict]:
        ensure_ai_jobs_safety_schema(self.conn)
        self.assert_ai_job_claimant(client_id)
        self.refresh_managed_host_liveness(client_id)
        now = utc_now_iso()
        self._terminalize_expired_queued_ai_jobs(client_id=client_id, now=now)
        self._fail_closed_stale_running_ai_jobs(client_id=client_id, now=now)
        # Filter by target host before LIMIT so one busy host cannot starve another.
        take = max(1, int(limit))
        rows = list(
            self.conn.execute(
                "SELECT * FROM ai_jobs WHERE status = 'queued' AND client_id = ? "
                "AND (deadline_at IS NULL OR deadline_at > ?) "
                "ORDER BY created_at LIMIT ?",
                (client_id, now, take),
            )
        )
        claimed = []
        for row in rows:
            if len(claimed) >= take:
                break
            payload = json.loads(row["payload_json"] or "{}")
            claim_token = "atk_" + secrets.token_urlsafe(24)
            attempt_id = _new_id("att")
            self.conn.execute(
                "UPDATE ai_jobs SET status = 'running', claim_token = ?, attempt_id = ?, "
                "claimed_at = ?, updated_at = ? WHERE id = ? AND status = 'queued'",
                (claim_token, attempt_id, now, now, row["id"]),
            )
            if self.conn.execute("SELECT changes()").fetchone()[0]:
                claimed.append(
                    {
                        "id": row["id"],
                        "capability": row["capability"],
                        "arguments": payload.get("arguments") or {},
                        "patterns": payload.get("patterns") or [],
                        "timeout": payload.get("timeout") or row["timeout_seconds"],
                        "deadline_at": row["deadline_at"] or payload.get("deadline_at"),
                        "claim_token": claim_token,
                        "attempt_id": attempt_id,
                    }
                )
        self.commit_if_autonomous()
        return claimed

    def _store_ai_job_result_blob(self, job_id: str, result: dict) -> None:
        """Persist the full in-memory result so MCP Bridge can return file bytes."""
        spool_dir = self._ai_job_spool_dir()
        spool_dir.mkdir(parents=True, exist_ok=True)
        path = self._ai_job_spool_path(job_id)
        tmp = path.with_suffix(".tmp")
        raw = json.dumps(result or {}, sort_keys=True).encode("utf-8")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(path))

    def consume_ai_job_result(self, job_id: str) -> Optional[dict]:
        """Return and delete the full AI job result (spool first, then SQLite summary)."""
        path = self._ai_job_spool_path(job_id)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                data = None
            try:
                path.unlink()
            except OSError:
                pass
            if isinstance(data, dict):
                return data
        job = self.get_ai_job(job_id)
        if job and isinstance(job.get("result"), dict):
            return dict(job["result"])
        return None

    def terminalize_ai_job(self, job_id: str, status: str = "timeout") -> dict:
        """Move a non-terminal job to a fail-closed terminal status."""
        ensure_ai_jobs_safety_schema(self.conn)
        terminal = str(status or "timeout").strip().lower()
        if terminal not in ("timeout", "cancelled", "expired", "recovery_required"):
            raise ControlPlaneError("invalid AI job terminal status")
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE ai_jobs SET status = ?, updated_at = ? "
            "WHERE id = ? AND status IN ('queued', 'running')",
            (terminal, now, job_id),
        )
        self.commit_if_autonomous()
        job = self.get_ai_job(job_id) or {"id": job_id, "status": terminal}
        return job

    def complete_ai_job(
        self,
        job_id: str,
        client_id: str,
        result: dict,
        *,
        claim_token: Optional[str] = None,
        attempt_id: Optional[str] = None,
    ) -> None:
        ensure_ai_jobs_safety_schema(self.conn)
        self.assert_ai_job_claimant(client_id)
        self.refresh_managed_host_liveness(client_id)
        row = self.conn.execute("SELECT * FROM ai_jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise ControlPlaneError("AI job not found")
        status = str(row["status"] or "")
        if status in AI_TERMINAL_JOB_STATUSES:
            raise ControlPlaneError("AI job is already terminal (%s)" % status)
        if status != "running":
            raise ControlPlaneError("AI job is not open for completion")
        payload = json.loads(row["payload_json"] or "{}")
        owner = row["client_id"] or payload.get("client_id")
        if owner != client_id:
            raise ControlPlaneError("AI job does not belong to this client")
        expected_token = str(row["claim_token"] or "")
        provided_token = str(claim_token or "")
        if not expected_token or provided_token != expected_token:
            raise ControlPlaneError("AI job claim token mismatch")
        expected_attempt = str(row["attempt_id"] or "")
        if attempt_id is not None:
            provided_attempt = str(attempt_id or "")
            if expected_attempt and provided_attempt != expected_attempt:
                raise ControlPlaneError("AI job attempt mismatch")
        full = dict(result or {})
        self._store_ai_job_result_blob(job_id, full)
        safe = dict(full)
        # Never persist file contents or unbounded streams in SQLite.
        safe.pop("content_b64", None)
        stdout = str(safe.get("stdout") or "")
        stderr = str(safe.get("stderr") or "")
        if len(stdout) > 256:
            safe["stdout"] = stdout[:256]
            safe["stdout_truncated"] = True
        if len(stderr) > 256:
            safe["stderr"] = stderr[:256]
            safe["stderr_truncated"] = True
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE ai_jobs SET status = 'done', result_json = ?, updated_at = ? "
            "WHERE id = ? AND status = 'running' AND claim_token = ?",
            (json.dumps(safe, sort_keys=True)[:8000], now, job_id, expected_token),
        )
        if not self.conn.execute("SELECT changes()").fetchone()[0]:
            raise ControlPlaneError("AI job completion lost the claim race")
        self.commit_if_autonomous()

    def get_ai_job(self, job_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM ai_jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        out = dict(row)
        if out.get("result_json"):
            try:
                out["result"] = json.loads(out["result_json"])
            except Exception:
                out["result"] = {}
        return out

    def wait_ai_job(self, job_id: str, timeout: float) -> dict:
        deadline = time.monotonic() + max(0.2, float(timeout))
        while time.monotonic() < deadline:
            job = self.get_ai_job(job_id)
            if job and job.get("status") == "done":
                return job
            if job and job.get("status") in AI_TERMINAL_JOB_STATUSES:
                return job
            time.sleep(0.05)
        return self.terminalize_ai_job(job_id, "timeout")

    def connected_clients(self) -> list[dict]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM clients WHERE connected = 1 AND trust_status = 'trusted'"
            )
            if self.client_effectively_connected(r)
        ]

    def client_for_endpoint(self, endpoint_obj_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT c.* FROM clients c JOIN managed_endpoints e ON e.client_id = c.id WHERE e.object_id = ?",
            (endpoint_obj_id,),
        ).fetchone()

    def _get_ai_rule(self, name: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ai_access_rules WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()

    def set_ai_rule(self, name: str) -> dict:
        name = _validate_name(name, "AI Access rule name")

        def write():
            existing = self._get_ai_rule(name)
            if existing:
                return {"entity": {"type": "ai-access", "id": existing["id"], "name": name}, "operation": "exists"}
            rid = _new_id("airl")
            now = utc_now_iso()
            row = self.conn.execute("SELECT COALESCE(MAX(position), 0) FROM ai_access_rules").fetchone()
            pos = int(row[0] or 0) + POSITION_STEP if row[0] else POSITION_STEP
            self.conn.execute(
                "INSERT INTO ai_access_rules(id, name, position, action, enabled, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, 'allow', 0, '', 1, ?, ?)",
                (rid, name, pos, now, now),
            )
            return {"entity": {"type": "ai-access", "id": rid, "name": name}, "operation": "create"}

        return self._mutate("set ai-access %s" % name, "create AI rule", write)

    def _require_ai_rule(self, name: str) -> sqlite3.Row:
        row = self._get_ai_rule(name)
        if row is None:
            raise ControlPlaneError("AI Access rule not found: %s" % name)
        return row

    def set_ai_rule_principal(self, rule: str, principal: str) -> dict:
        self.set_ai_rule(rule)
        p = self.get_principal(principal)
        if p is None:
            raise ControlPlaneError("AI Principal not found: %s" % principal)
        r = self._require_ai_rule(rule)

        def write():
            self.conn.execute(
                "UPDATE ai_access_rules SET principal_id = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (p["id"], utc_now_iso(), r["id"]),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "principal"}

        return self._mutate("set ai-access principal", "set principal", write)

    def set_ai_rule_target(self, rule: str, kind: str, token: str) -> dict:
        self.set_ai_rule(rule)
        r = self._require_ai_rule(rule)
        kind = str(kind).lower()
        if kind in ("endpoint", "managed-endpoint"):
            obj = self.require_object(token)
            if obj["type"] != "managed_endpoint":
                raise ControlPlaneError("AI target endpoint must be a Managed Host")
            tkind, tid = "endpoint", obj["id"]
        elif kind in ("client-group", "group"):
            grp = self.conn.execute(
                "SELECT * FROM client_groups WHERE name = ? COLLATE NOCASE", (token,)
            ).fetchone()
            if grp is None:
                raise ControlPlaneError("Client Group not found: %s" % token)
            tkind, tid = "client-group", grp["id"]
        else:
            raise ControlPlaneError("AI target must be endpoint or client-group")

        def write():
            self.conn.execute(
                "INSERT OR IGNORE INTO ai_rule_targets(rule_id, target_kind, target_id) VALUES (?, ?, ?)",
                (r["id"], tkind, tid),
            )
            self.conn.execute(
                "UPDATE ai_access_rules SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), r["id"]),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "target"}

        return self._mutate("set ai-access target", "set target", write)

    def set_ai_rule_capability(self, rule: str, capability: str) -> dict:
        self.set_ai_rule(rule)
        cap = str(capability).strip()
        if cap not in AI_CAPABILITIES:
            raise ControlPlaneError("Unknown capability %s. Denied." % cap)
        r = self._require_ai_rule(rule)

        def write():
            self.conn.execute(
                "INSERT OR IGNORE INTO ai_rule_capabilities(rule_id, capability) VALUES (?, ?)",
                (r["id"], cap),
            )
            self.conn.execute(
                "UPDATE ai_access_rules SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), r["id"]),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "capability"}

        return self._mutate("set ai-access capability", "set capability", write)

    def set_ai_rule_path(self, rule: str, pattern: str) -> dict:
        self.set_ai_rule(rule)
        r = self._require_ai_rule(rule)
        pattern = str(pattern or "").strip()
        if not pattern.startswith("/"):
            raise ControlPlaneError("path pattern must be absolute")

        def write():
            self.conn.execute(
                "INSERT OR IGNORE INTO ai_path_scopes(rule_id, pattern) VALUES (?, ?)",
                (r["id"], pattern),
            )
            self.conn.execute(
                "UPDATE ai_access_rules SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (utc_now_iso(), r["id"]),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "path"}

        return self._mutate("set ai-access path", "set path", write)

    def set_ai_rule_exec_timeout(self, rule: str, seconds: int) -> dict:
        self.set_ai_rule(rule)
        r = self._require_ai_rule(rule)
        seconds = int(seconds)

        def write():
            self.conn.execute(
                "UPDATE ai_access_rules SET exec_timeout = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (seconds, utc_now_iso(), r["id"]),
            )
            self.conn.execute(
                "INSERT INTO ai_exec_constraints(rule_id, timeout_seconds) VALUES (?, ?) "
                "ON CONFLICT(rule_id) DO UPDATE SET timeout_seconds = excluded.timeout_seconds",
                (r["id"], seconds),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "exec-timeout"}

        return self._mutate("set ai-access exec-timeout", "set exec timeout", write)

    def set_ai_rule_action(self, rule: str, action: str) -> dict:
        self.set_ai_rule(rule)
        r = self._require_ai_rule(rule)
        action = str(action).lower()
        if action not in ("allow", "deny"):
            raise ControlPlaneError("action must be allow or deny")

        def write():
            self.conn.execute(
                "UPDATE ai_access_rules SET action = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (action, utc_now_iso(), r["id"]),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "action"}

        return self._mutate("set ai-access action", "set action", write)

    def set_ai_rule_description(self, rule: str, text: str) -> dict:
        self.set_ai_rule(rule)
        r = self._require_ai_rule(rule)

        def write():
            self.conn.execute(
                "UPDATE ai_access_rules SET description = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (text, utc_now_iso(), r["id"]),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "description"}

        return self._mutate("set ai-access description", "set description", write)

    def set_ai_rule_enabled(self, rule: str, enabled: bool) -> dict:
        r = self._require_ai_rule(rule)

        def write():
            self.conn.execute(
                "UPDATE ai_access_rules SET enabled = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, utc_now_iso(), r["id"]),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "enable"}

        return self._mutate("set ai-access enabled", "enable AI rule", write)

    def move_ai_rule(self, name: str, *, before: Optional[str] = None, after: Optional[str] = None) -> dict:
        rule = self._require_ai_rule(name)
        other = self._require_ai_rule(before or after)

        def write():
            rows = list(self.conn.execute("SELECT id FROM ai_access_rules ORDER BY position, name"))
            ids = [r["id"] for r in rows]
            ids.remove(rule["id"])
            idx = ids.index(other["id"])
            ids.insert(idx if before else idx + 1, rule["id"])
            for i, rid in enumerate(ids, start=1):
                self.conn.execute(
                    "UPDATE ai_access_rules SET position = ?, updated_at = ? WHERE id = ?",
                    (i * POSITION_STEP, utc_now_iso(), rid),
                )
            return {"entity": {"type": "ai-access", "id": rule["id"], "name": name}, "operation": "move"}

        return self._mutate("set ai-access order", "move AI rule", write)

    def unset_ai_rule_target(self, rule: str, kind: str, token: str) -> dict:
        r = self._require_ai_rule(rule)
        kind = "endpoint" if "endpoint" in kind else "client-group"
        if kind == "endpoint":
            obj = self.require_object(token)
            tid = obj["id"]
        else:
            grp = self.conn.execute(
                "SELECT id FROM client_groups WHERE name = ? COLLATE NOCASE", (token,)
            ).fetchone()
            if not grp:
                raise ControlPlaneError("Client Group not found")
            tid = grp["id"]

        def write():
            self.conn.execute(
                "DELETE FROM ai_rule_targets WHERE rule_id = ? AND target_kind = ? AND target_id = ?",
                (r["id"], kind, tid),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "unset-target"}

        return self._mutate("unset ai-access target", "unset target", write)

    def unset_ai_rule_capability(self, rule: str, capability: str) -> dict:
        r = self._require_ai_rule(rule)

        def write():
            self.conn.execute(
                "DELETE FROM ai_rule_capabilities WHERE rule_id = ? AND capability = ?",
                (r["id"], capability),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "unset-capability"}

        return self._mutate("unset ai-access capability", "unset capability", write)

    def unset_ai_rule_path(self, rule: str, pattern: str) -> dict:
        r = self._require_ai_rule(rule)

        def write():
            self.conn.execute(
                "DELETE FROM ai_path_scopes WHERE rule_id = ? AND pattern = ?",
                (r["id"], pattern),
            )
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "unset-path"}

        return self._mutate("unset ai-access path", "unset path", write)

    def unset_ai_rule_exec_timeout(self, rule: str) -> dict:
        r = self._require_ai_rule(rule)

        def write():
            self.conn.execute("UPDATE ai_access_rules SET exec_timeout = NULL WHERE id = ?", (r["id"],))
            self.conn.execute("DELETE FROM ai_exec_constraints WHERE rule_id = ?", (r["id"],))
            return {"entity": {"type": "ai-access", "id": r["id"], "name": rule}, "operation": "unset-timeout"}

        return self._mutate("unset ai-access exec-timeout", "unset timeout", write)

    def unset_ai_rule(self, name: str) -> dict:
        r = self._require_ai_rule(name)

        def write():
            self.conn.execute("DELETE FROM ai_rule_targets WHERE rule_id = ?", (r["id"],))
            self.conn.execute("DELETE FROM ai_rule_capabilities WHERE rule_id = ?", (r["id"],))
            self.conn.execute("DELETE FROM ai_path_scopes WHERE rule_id = ?", (r["id"],))
            self.conn.execute("DELETE FROM ai_exec_constraints WHERE rule_id = ?", (r["id"],))
            self.conn.execute("DELETE FROM ai_access_rules WHERE id = ?", (r["id"],))
            return {"entity": {"type": "ai-access", "id": r["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset ai-access %s" % name, "delete AI rule", write)

    def _endpoint_in_client_group(self, endpoint_obj: sqlite3.Row, group_id: str) -> bool:
        ep = self.conn.execute(
            "SELECT client_id FROM managed_endpoints WHERE object_id = ?", (endpoint_obj["id"],)
        ).fetchone()
        if not ep or not ep["client_id"]:
            return False
        row = self.conn.execute(
            "SELECT 1 FROM client_group_members WHERE group_id = ? AND client_id = ?",
            (group_id, ep["client_id"]),
        ).fetchone()
        return bool(row)

    def evaluate_ai_access(self, principal: str, endpoint: str, capability: str, operand: Optional[str] = None) -> dict:
        self._ensure_live_conn()
        cap = str(capability).strip()
        p = self.get_principal(principal)
        ep = self.get_object(endpoint)
        traces = []
        winner = None
        path_ok = True
        if cap not in AI_CAPABILITIES:
            return {
                "principal": principal,
                "endpoint": endpoint,
                "capability": cap,
                "operand": operand,
                "action": "DENY",
                "implicit": True,
                "reason": "unknown capability",
                "winner": None,
                "traces": [],
                "principal_row": p,
                "endpoint_row": ep,
                "exec_timeout": None,
            }
        if p is None or not p["enabled"] or p["credential_status"] == "revoked":
            return {
                "principal": principal,
                "endpoint": endpoint,
                "capability": cap,
                "operand": operand,
                "action": "DENY",
                "implicit": True,
                "reason": "unknown, disabled or revoked principal",
                "winner": None,
                "traces": [],
                "principal_row": p,
                "endpoint_row": ep,
                "exec_timeout": None,
            }
        for row in self.conn.execute("SELECT * FROM ai_access_rules ORDER BY position, name"):
            if not row["enabled"]:
                continue
            view = self._ai_rule_view(row)
            if winner is not None:
                traces.append({"rule": view, "evaluated": False})
                continue
            prin_ok = bool(p) and row["principal_id"] == p["id"]
            tgt_ok = False
            if ep:
                for t in self.conn.execute(
                    "SELECT target_kind, target_id FROM ai_rule_targets WHERE rule_id = ?", (row["id"],)
                ):
                    if t["target_kind"] == "endpoint" and t["target_id"] == ep["id"]:
                        tgt_ok = True
                    elif t["target_kind"] == "client-group" and self._endpoint_in_client_group(ep, t["target_id"]):
                        tgt_ok = True
            cap_ok = any(
                c["capability"] == cap
                for c in self.conn.execute(
                    "SELECT capability FROM ai_rule_capabilities WHERE rule_id = ?", (row["id"],)
                )
            )
            constraint_ok = True
            if cap in FILE_CAPABILITIES:
                patterns = [x["pattern"] for x in self.conn.execute("SELECT pattern FROM ai_path_scopes WHERE rule_id = ?", (row["id"],))]
                if not operand or not patterns:
                    constraint_ok = False
                else:
                    constraint_ok = path_allowed(operand, patterns)
            traces.append(
                {
                    "rule": view,
                    "evaluated": True,
                    "principal": prin_ok,
                    "target": tgt_ok,
                    "capability": cap_ok,
                    "constraint": constraint_ok,
                }
            )
            if prin_ok and tgt_ok and cap_ok and constraint_ok:
                winner = view
                winner["exec_timeout"] = row["exec_timeout"]
                path_ok = constraint_ok
        action = winner["action"].upper() if winner else "DENY"
        return {
            "principal": principal,
            "endpoint": endpoint,
            "capability": cap,
            "operand": operand,
            "action": action,
            "implicit": winner is None,
            "reason": (
                "AI Access rule #%s %s" % (winner["display_position"], winner["name"])
                if winner
                else "implicit DENY"
            ),
            "winner": winner,
            "traces": traces,
            "principal_row": p,
            "endpoint_row": ep,
            "exec_timeout": winner.get("exec_timeout") if winner else None,
            "path_ok": path_ok,
        }

    def _ai_rule_view(self, row: sqlite3.Row) -> dict:
        p = None
        if row["principal_id"]:
            p = self.conn.execute("SELECT name FROM ai_principals WHERE id = ?", (row["principal_id"],)).fetchone()
        targets = []
        for t in self.conn.execute("SELECT target_kind, target_id FROM ai_rule_targets WHERE rule_id = ?", (row["id"],)):
            if t["target_kind"] == "endpoint":
                obj = self.conn.execute("SELECT name FROM objects WHERE id = ?", (t["target_id"],)).fetchone()
                targets.append(obj["name"] if obj else t["target_id"])
            else:
                g = self.conn.execute("SELECT name FROM client_groups WHERE id = ?", (t["target_id"],)).fetchone()
                targets.append("client-group:%s" % (g["name"] if g else t["target_id"]))
        caps = [c["capability"] for c in self.conn.execute("SELECT capability FROM ai_rule_capabilities WHERE rule_id = ?", (row["id"],))]
        paths = [c["pattern"] for c in self.conn.execute("SELECT pattern FROM ai_path_scopes WHERE rule_id = ?", (row["id"],))]
        return {
            "id": row["id"],
            "name": row["name"],
            "position": row["position"],
            "display_position": display_position(row["position"]),
            "action": row["action"],
            "enabled": bool(row["enabled"]),
            "principal": p["name"] if p else None,
            "targets": targets,
            "capabilities": caps,
            "paths": paths,
            "exec_timeout": row["exec_timeout"],
            "description": row["description"],
        }

    def format_ai_explain(self, result: dict) -> str:
        lines = [
            "AI Access Policy Evaluation",
            "",
            "Principal : %s" % result["principal"],
            "Endpoint  : %s" % result["endpoint"],
            "Capability: %s" % result["capability"],
        ]
        if result.get("operand"):
            lines.append("Operand   : %s" % result["operand"])
        lines.extend(["", "Rule Evaluation", "---------------"])
        decided = False
        for item in result["traces"]:
            rule = item["rule"]
            header = "#%s %s" % (rule["display_position"], rule["name"])
            if not item.get("evaluated"):
                lines.append(header)
                lines.append("  Not evaluated")
                lines.append("")
                continue
            lines.append(header)
            lines.append("  Principal   %s" % ("MATCH" if item.get("principal") else "NO MATCH"))
            lines.append("  Target      %s" % ("MATCH" if item.get("target") else "NO MATCH"))
            lines.append("  Capability  %s" % ("MATCH" if item.get("capability") else "NO MATCH"))
            lines.append("  Constraint  %s" % ("MATCH" if item.get("constraint") else "NO MATCH"))
            if item.get("principal") and item.get("target") and item.get("capability") and item.get("constraint") and not decided:
                lines.append("")
                lines.append("FIRST COMPLETE MATCH")
                lines.append("Action: %s" % rule["action"].upper())
                decided = True
            lines.append("")
        if result["capability"] == "exec" and result["action"] == "ALLOW":
            lines.extend(
                [
                    "Note",
                    "----",
                    "exec can modify the target through shell/OS permissions.",
                    "A true read-only AI role requires exec disabled.",
                    "",
                ]
            )
        lines.extend(["Final Result", "------------", result["action"], "Reason: %s" % result["reason"]])
        return "\n".join(lines) + "\n"

    def record_ai_activity(
        self,
        *,
        principal: str,
        endpoint: str,
        capability: str,
        result: str,
        rule: Optional[str] = None,
        duration_ms: Optional[int] = None,
        operand: Optional[str] = None,
    ) -> None:
        p = self.get_principal(principal)
        summary = str(operand or "")
        if len(summary) > 200:
            summary = summary[:197] + "..."
        self.conn.execute(
            "INSERT INTO ai_activity(timestamp, principal_id, principal_name, endpoint_id, endpoint_name, "
            "capability, matched_rule, result, duration_ms, revision, operand_summary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                utc_now_iso(),
                p["id"] if p else None,
                principal,
                None,
                endpoint,
                capability,
                rule or "",
                result,
                duration_ms,
                self.current_revision(),
                summary,
            ),
        )
        self.conn.execute(
            "INSERT INTO audit_events(timestamp, revision, actor, action, entity_type, "
            "entity_id, operation, before_summary, after_summary, impact_summary, result) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                utc_now_iso(),
                self.current_revision(),
                principal,
                "ai %s" % capability,
                "ai-principal",
                principal,
                capability,
                "",
                "%s %s" % (endpoint, summary[:80]),
                rule or "",
                result,
            ),
        )

    def list_ai_activity(self, *, principal: Optional[str] = None, endpoint: Optional[str] = None) -> list[dict]:
        sql = "SELECT * FROM ai_activity WHERE 1=1"
        args: list[Any] = []
        if principal:
            sql += " AND principal_name = ?"
            args.append(principal)
        if endpoint:
            sql += " AND endpoint_name = ?"
            args.append(endpoint)
        sql += " ORDER BY id DESC LIMIT 200"
        out = []
        for row in self.conn.execute(sql, args):
            out.append(dict(row))
        return out

    def format_ai_activity(self, rows: list[dict]) -> str:
        if not rows:
            return "(no AI activity)\n"
        blocks = []
        for row in rows:
            blocks.append(
                "\n".join(
                    [
                        row["timestamp"],
                        "Principal : %s" % row["principal_name"],
                        "Endpoint  : %s" % row["endpoint_name"],
                        "Tool      : %s" % row["capability"],
                        "Path      : %s" % (row["operand_summary"] or "-"),
                        "Rule      : %s" % (row["matched_rule"] or "-"),
                        "Result    : %s" % row["result"],
                        "Revision  : %s" % (row["revision"] or "-"),
                        "Duration  : %sms" % (row["duration_ms"] if row["duration_ms"] is not None else "-"),
                    ]
                )
            )
        return "\n\n".join(blocks) + "\n"

    # --- runtime compiler -------------------------------------------------
    def compile_runtime(self, *, fail: Optional[str] = None) -> dict:
        rev = self.current_revision()
        self.runtime.mkdir(parents=True, exist_ok=True)
        now = utc_now_iso()
        artifacts = {}
        planes = {
            "remote": self.list_rules("remote"),
            "internet": self.list_rules("internet"),
            "ai": [self._ai_rule_view(r) for r in self.conn.execute("SELECT * FROM ai_access_rules ORDER BY position")],
        }
        if fail:
            self.conn.execute(
                "UPDATE runtime_generations SET status = 'failed', error = ?, db_revision = ? WHERE plane = 'internet'",
                (fail, rev),
            )
            raise ControlPlaneError(fail)
        for plane, payload in planes.items():
            path = self.runtime / ("%s-access.json" % plane)
            data = {
                "plane": plane,
                "revision": rev,
                "generated_at": now,
                "rules": payload,
                "implicit_default": "DENY",
            }
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(path)
            os.chmod(path, 0o600)
            artifacts[plane] = str(path)
            ai_configured = plane != "ai" or bool(payload) or self.conn.execute("SELECT 1 FROM ai_principals LIMIT 1").fetchone()
            status = "active" if (plane != "ai" or ai_configured) else "not_configured"
            if plane == "ai" and not ai_configured:
                status = "not_configured"
            elif plane == "ai":
                status = "active"
            self.conn.execute(
                "INSERT OR REPLACE INTO runtime_generations(plane, db_revision, generation, status, artifact_path, activated_at, error) "
                "VALUES (?, ?, ?, ?, ?, ?, '')",
                (plane, rev, rev, status, str(path), now),
            )
        gen_path = self.runtime / "generation.json"
        gen_path.write_text(
            json.dumps({"db_revision": rev, "planes": {k: rev for k in planes}, "generated_at": now}, indent=2),
            encoding="utf-8",
        )
        return {"revision": rev, "artifacts": artifacts}

    def _mark_generation_failed(self, error: str) -> None:
        rev = self.current_revision()
        self.conn.execute(
            "UPDATE runtime_generations SET status = 'mismatch', error = ?, db_revision = ? WHERE plane = 'internet'",
            (error[:500], rev),
        )

    def force_generation_mismatch(self, plane: str = "internet") -> None:
        rev = self.current_revision()
        self.conn.execute(
            "UPDATE runtime_generations SET generation = ?, status = 'mismatch', error = 'compile/activation failure' WHERE plane = ?",
            (max(rev - 1, 0), plane),
        )

    def status(self) -> dict:
        rev = self.current_revision()
        gens = {r["plane"]: dict(r) for r in self.conn.execute("SELECT * FROM runtime_generations")}
        clients = self.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        services = self.conn.execute("SELECT COUNT(*) FROM published_services WHERE released = 0").fetchone()[0]
        db_ok = True
        try:
            integrity_check(self.conn)
        except Exception:
            db_ok = False
        mismatch = any(
            g.get("status") == "mismatch" or (g.get("generation") != rev and g.get("status") == "active")
            for g in gens.values()
        )
        return {
            "db_healthy": db_ok,
            "revision": rev,
            "schema": SCHEMA_VERSION,
            "generations": gens,
            "clients": clients,
            "services": services,
            "mismatch": mismatch,
            "ai_configured": gens.get("ai", {}).get("status") == "active",
            "mcp_configured": gens.get("ai", {}).get("status") == "active",
        }

    def format_status(self) -> str:
        from drlink_v24 import detect_cli_role, format_show_status, probe_agent_runtime_unit

        role = detect_cli_role(self.root)
        base = format_show_status(role, self)
        # Append compact operational health for operators.
        st = self.status()
        db_line = "Healthy" if st["db_healthy"] and not st["mismatch"] else (
            "Critical" if not st["db_healthy"] else "Warning"
        )
        extra = [
            "",
            "Control DB       : %s" % db_line,
            "DB Revision      : %s" % st["revision"],
        ]
        if role == "server":
            extra.append("Managed Hosts    : %s" % st["clients"])
        if role == "agent":
            runtime = probe_agent_runtime_unit(root=self.root)
            level = runtime.get("level") or "Unknown"
            detail = runtime.get("detail") or "unavailable"
            if level == "Healthy":
                extra.append("Agent Runtime   : Healthy")
            else:
                extra.append("Agent Runtime   : %s — %s" % (level, detail))
            # Server connection from local identity / client-state when present.
            server_line = "Unknown"
            try:
                from drlink_v24 import load_agent_identity, detect_server_reachable

                identity = load_agent_identity(self.root) or {}
                if detect_server_reachable(self, self.root):
                    server_line = "Connected"
                elif identity:
                    server_line = "Disconnected"
            except Exception:
                server_line = "Unknown"
            extra.append("Server          : %s" % server_line)
            try:
                rs_count = self.conn.execute(
                    "SELECT COUNT(*) FROM agent_remote_services WHERE delete_pending = 0"
                ).fetchone()[0]
            except Exception:
                rs_count = 0
            extra.append("Remote Services : %s" % rs_count)
        else:
            extra.append("Remote Services  : %s" % st["services"])
        if role == "server":
            mcp = self.mcp_endpoint_status()
            extra.append("MCP Public Endpoint : %s" % (
                "Healthy" if mcp["remote_ready"] else (
                    "Not configured" if mcp["public_url"] == "Not configured" else "Warning"
                )
            ))
            extra.append("Authentication      : %s" % mcp["authentication"])
        return base.rstrip() + "\n" + "\n".join(extra) + "\n"

    def _read_server_config(self) -> dict:
        env = os.environ.get("DRLINK_SERVER_CONFIG") or ""
        candidates = []
        if env:
            candidates.append(Path(env))
        if self.root:
            candidates.append(Path(self.root) / "etc" / "drlink" / "config.json")
        candidates.append(Path("/etc/drlink/config.json"))
        for path in candidates:
            try:
                if path.is_file():
                    return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
        return {}

    def mcp_public_url(self, cfg: Optional[dict] = None) -> str:
        override = (os.environ.get("DRLINK_MCP_PUBLIC_URL") or "").strip().rstrip("/")
        if override:
            return override if override.endswith("/mcp") else override + "/mcp"
        # Prefer dedicated MCP TLS hostname when configured.
        try:
            import drlink_mcp_tls as mcp_tls

            tls_state = mcp_tls.load_state(self)
            host = str(tls_state.get("hostname") or "").strip()
            if host and tls_state.get("mode"):
                return "https://%s/mcp" % host
        except Exception:
            pass
        data = cfg if cfg is not None else self._read_server_config()
        mode = str(data.get("deployment_mode") or "direct").strip().lower().replace("-", "").replace("_", "")
        if mode not in ("single443", "enterprise", "enterprisesingle443"):
            return "Not configured"
        try:
            import frp_server_config as scfg

            host = str(scfg.public_url_host(data) or "").strip()
        except Exception:
            host = str(
                data.get("public_url_host")
                or data.get("public_hostname")
                or data.get("public_ip")
                or data.get("public_host")
                or ""
            ).strip()
        if not host:
            return "Not configured"
        port = str(data.get("frp_control_public_port") or data.get("frontend_port") or "443")
        if port in ("443", "443.0"):
            return "https://%s/mcp" % host
        return "https://%s:%s/mcp" % (host, port)

    def mcp_endpoint_status(self) -> dict:
        st = self.status()
        cfg = self._read_server_config()
        public_url = self.mcp_public_url(cfg)
        bind = "127.0.0.1:6103"
        backend = "Healthy" if st.get("mcp_configured") else "Not configured"
        frontend_conf = None
        if self.root:
            frontend_conf = Path(self.root) / "etc" / "drlink" / "frontend.conf"
        else:
            frontend_conf = Path("/etc/drlink/frontend.conf")
        routed = False
        try:
            text = frontend_conf.read_text(encoding="utf-8")
            routed = "location = /mcp" in text or 'location = "/mcp"' in text
        except Exception:
            routed = False
        modes = []
        if self.conn.execute(
            "SELECT 1 FROM ai_principals WHERE credential_status = 'active' AND name != ? LIMIT 1",
            (OAUTH_UNBOUND_PRINCIPAL,),
        ).fetchone():
            modes.append("Static Bearer")
        if self.conn.execute(
            "SELECT 1 FROM ai_principals WHERE auth_mode = 'oauth' AND name != ? LIMIT 1",
            (OAUTH_UNBOUND_PRINCIPAL,),
        ).fetchone():
            modes.append("OAuth")
        return {
            "backend": backend,
            "bind": bind,
            "public_url": public_url,
            "protocol": "2026-07-28",
            "transport": "Streamable HTTP",
            "authentication": " / ".join(modes) or "Not configured",
            "auth_model": MCP_AUTH_MODEL,
            "frontend_routed": routed,
            "remote_ready": bool(routed and public_url != "Not configured" and st.get("mcp_configured")),
        }

    def diagnostics_mcp(self) -> str:
        mcp = self.mcp_endpoint_status()
        lines = ["MCP diagnostics", "===============", ""]
        public_ok = mcp["public_url"] != "Not configured" and mcp["frontend_routed"]
        if not mcp["frontend_routed"]:
            lines.append("MCP Public Endpoint : Critical")
            lines.append("Reason              : /mcp is not routed by HTTPS frontend")
        elif mcp["public_url"] == "Not configured":
            lines.append("MCP Public Endpoint : Warning")
            lines.append("Reason              : Public URL is not configured (direct mode has no 443 MCP frontend)")
        else:
            lines.append("MCP Public Endpoint : %s" % ("Healthy" if public_ok else "Warning"))
        lines.append("Backend             : %s" % mcp["backend"])
        lines.append("Backend Bind        : %s" % mcp["bind"])
        lines.append("Public URL          : %s" % mcp["public_url"])
        lines.append("Protocol            : %s" % mcp["protocol"])
        lines.append("Transport           : %s" % mcp["transport"])
        lines.append("Authentication      : %s" % mcp["authentication"])
        lines.append("Auth Model          : %s" % mcp["auth_model"])
        try:
            import drlink_mcp_tls as mcp_tls

            view = mcp_tls.status_view(self, self.root)
            lines.append("")
            lines.append("MCP Public TLS")
            lines.append("--------------")
            lines.append("TLS mode            : %s" % view.get("mode"))
            lines.append("Certificate         : %s" % view.get("certificate"))
            lines.append("Issuer              : %s" % view.get("issuer"))
            lines.append("Expires             : %s" % view.get("expires"))
            lines.append("Auto renewal        : %s" % view.get("auto_renewal"))
            if view.get("private_ca_warning"):
                lines.append(
                    "Warning             : PRIVATE_CA is not suitable for cloud-hosted Remote MCP by default"
                )
        except Exception:
            pass
        if mcp["backend"] == "Healthy" and not mcp["remote_ready"]:
            lines.append("")
            lines.append("Backend Healthy alone does not imply MCP Remote Access = Healthy.")
        return "\n".join(lines) + "\n"

    def diagnostics_control_plane(self) -> str:
        lines = ["Control-plane diagnostics", "==========================", ""]
        try:
            integrity_check(self.conn)
            lines.append("SQLite integrity : OK")
            lines.append("Foreign keys     : OK")
        except Exception as exc:
            lines.append("SQLite integrity : FAIL (%s)" % exc)
        pragmas = pragma_snapshot(self.conn)
        lines.append("Schema version   : %s" % SCHEMA_VERSION)
        lines.append("DB path          : %s" % self.db_file)
        lines.append("journal_mode     : %s" % pragmas.get("journal_mode"))
        lines.append("synchronous      : %s" % pragmas.get("synchronous"))
        lines.append("foreign_keys     : %s" % pragmas.get("foreign_keys"))
        lines.append("Revision         : %s" % self.current_revision())
        lines.append("JSON authority   : no (derived runtime only)")
        lines.append("Implicit DENY    : active")
        return "\n".join(lines) + "\n"

    def diagnostics_runtime(self) -> str:
        st = self.status()
        lines = ["Runtime diagnostics", "===================", ""]
        lines.append("DB Revision : %s" % st["revision"])
        for plane in ("remote", "internet", "ai"):
            g = st["generations"].get(plane) or {}
            lines.append(
                "%s: generation=%s status=%s error=%s"
                % (plane, g.get("generation"), g.get("status"), g.get("error") or "-")
            )
        if st["mismatch"]:
            lines.append("")
            lines.append("Generation mismatch is visible. Affected authorization fails closed.")
        return "\n".join(lines) + "\n"

    def reconcile_ai_jobs_after_disaster_recovery(self) -> dict:
        """Fail-closed reconciliation of nonterminal AI jobs after Server DR restore.

        Restored queued/running jobs must not execute or replay after recovery.
        Mutating in-flight work becomes recovery_required; other nonterminal work
        becomes expired.
        """
        ensure_ai_jobs_safety_schema(self.conn)
        now = utc_now_iso()
        rows = list(
            self.conn.execute(
                "SELECT id, capability, status FROM ai_jobs WHERE status IN ('queued', 'running')"
            )
        )
        expired = 0
        recovery = 0
        for row in rows:
            capability = str(row["capability"] or "")
            status = str(row["status"] or "")
            if status == "running" and capability in AI_MUTATING_CAPABILITIES:
                terminal = "recovery_required"
                recovery += 1
            else:
                terminal = "expired"
                expired += 1
            self.conn.execute(
                "UPDATE ai_jobs SET status = ?, updated_at = ?, "
                "claim_token = NULL, attempt_id = NULL "
                "WHERE id = ? AND status IN ('queued', 'running')",
                (terminal, now, row["id"]),
            )
        self.conn.commit()
        return {"expired": expired, "recovery_required": recovery, "total": len(rows)}

    # --- backup / restore -------------------------------------------------
    def backup(self, dest: str) -> str:
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            snap = tmp_path / "drlink.db"
            dest_conn = sqlite3.connect(str(snap))
            self.conn.backup(dest_conn)
            dest_conn.close()
            meta = {
                "format": "drlink-control-backup",
                "schema_version": SCHEMA_VERSION,
                "revision": self.current_revision(),
                "created_at": utc_now_iso(),
            }
            (tmp_path / "backup-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
            with tarfile.open(dest_path, "w") as tar:
                tar.add(snap, arcname="drlink.db")
                tar.add(tmp_path / "backup-meta.json", arcname="backup-meta.json")
        os.chmod(dest_path, 0o600)
        return str(dest_path)

    def _read_backup_archive(self, src: str) -> tuple[bytes, dict]:
        """Extract drlink.db bytes and parsed backup-meta.json without mutating live state."""
        try:
            tar = tarfile.open(src, "r")
        except (OSError, tarfile.TarError) as exc:
            raise ControlPlaneError("backup archive unreadable: %s" % exc) from exc
        with tar:
            names = set(tar.getnames())
            if "drlink.db" not in names:
                raise ControlPlaneError("backup is missing drlink.db")
            if "backup-meta.json" not in names:
                raise ControlPlaneError("backup is missing backup-meta.json")
            db_member = tar.extractfile("drlink.db")
            if db_member is None:
                raise ControlPlaneError("backup drlink.db unreadable")
            meta_member = tar.extractfile("backup-meta.json")
            if meta_member is None:
                raise ControlPlaneError("backup backup-meta.json unreadable")
            payload = db_member.read()
            try:
                meta = json.loads(meta_member.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ControlPlaneError("backup-meta.json is not valid JSON") from exc
            if not isinstance(meta, dict):
                raise ControlPlaneError("backup-meta.json must be a JSON object")
        return payload, meta

    def _validate_backup_candidate(self, db_path_str: str, meta: dict) -> dict:
        """Validate a candidate DB file + metadata without initialize/migrate."""
        fmt = str(meta.get("format") or "").strip()
        if fmt != BACKUP_FORMAT:
            raise ControlPlaneError(
                "backup format %r is unsupported (expected %s)" % (fmt or "<missing>", BACKUP_FORMAT)
            )
        try:
            meta_schema = int(meta.get("schema_version"))
        except (TypeError, ValueError):
            raise ControlPlaneError("backup-meta.json schema_version is missing or invalid")
        try:
            meta_revision = int(meta.get("revision"))
        except (TypeError, ValueError):
            raise ControlPlaneError("backup-meta.json revision is missing or invalid")
        if meta_revision < 0:
            raise ControlPlaneError("backup-meta.json revision is invalid")

        conn = sqlite3.connect(db_path_str)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                integrity_check(conn)
            except DatabaseCorruptError as exc:
                raise ControlPlaneError("backup database failed integrity checks: %s" % exc) from exc

            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            missing = [name for name in BACKUP_REQUIRED_TABLES if name not in tables]
            if missing:
                raise ControlPlaneError(
                    "backup is not a DRLink control-plane database (missing tables: %s)"
                    % ", ".join(missing)
                )

            try:
                found_schema = int(
                    conn.execute(
                        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
                    ).fetchone()[0]
                    or 0
                )
            except sqlite3.Error as exc:
                raise ControlPlaneError(
                    "backup schema_migrations is unreadable: %s" % exc
                ) from exc
            if found_schema <= 0:
                raise ControlPlaneError(
                    "backup schema version is unknown or unsupported (found %s)" % found_schema
                )
            if found_schema > SCHEMA_VERSION:
                raise SchemaTooNewError(found_schema, SCHEMA_VERSION)
            if meta_schema != found_schema:
                raise ControlPlaneError(
                    "backup metadata schema_version %s does not match database schema %s"
                    % (meta_schema, found_schema)
                )

            meta_row = conn.execute(
                "SELECT value FROM system_meta WHERE key = 'schema_version'"
            ).fetchone()
            if meta_row is not None:
                try:
                    sys_schema = int(meta_row[0])
                except (TypeError, ValueError):
                    raise ControlPlaneError("backup system_meta schema_version is invalid")
                if sys_schema != found_schema:
                    raise ControlPlaneError(
                        "backup system_meta schema_version %s does not match schema_migrations %s"
                        % (sys_schema, found_schema)
                    )

            try:
                db_revision = int(
                    conn.execute(
                        "SELECT COALESCE(MAX(revision), 0) FROM config_revisions"
                    ).fetchone()[0]
                    or 0
                )
            except sqlite3.Error as exc:
                raise ControlPlaneError(
                    "backup config_revisions is unreadable: %s" % exc
                ) from exc
            if meta_revision != db_revision:
                raise ControlPlaneError(
                    "backup metadata revision %s does not match database revision %s"
                    % (meta_revision, db_revision)
                )
            return {
                "ok": True,
                "format": BACKUP_FORMAT,
                "schema_version": found_schema,
                "revision": db_revision,
            }
        finally:
            conn.close()

    def backup_validate(self, src: str) -> dict:
        """Prove a candidate is a supported DRLink control backup without live mutation."""
        payload, meta = self._read_backup_archive(src)
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as fh:
            fh.write(payload)
            tmp = fh.name
        try:
            info = self._validate_backup_candidate(tmp, meta)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            for suffix in ("-wal", "-shm"):
                try:
                    Path(tmp + suffix).unlink()
                except FileNotFoundError:
                    pass
        info["path"] = src
        return info

    def restore(self, src: str) -> dict:
        """Atomically restore a validated candidate; roll back live DB/runtime on failure."""
        # Full candidate validation before any live checkpoint or cutover.
        self.backup_validate(src)
        previous_revision = self.current_revision()
        checkpoint = self._pre_activation_checkpoint()
        try:
            self._restore_db_only(src)
            if self._forced_restore_failure():
                raise ControlPlaneError("simulated restore activation failure")
            self.compile_runtime()
            st = self.status()
            self._cleanup_activation_checkpoint(checkpoint)
            return {"ok": True, "revision": st["revision"]}
        except Exception as exc:
            try:
                self._rollback_activation(checkpoint)
            except Exception as rollback_exc:
                self._cleanup_activation_checkpoint(checkpoint)
                raise ControlPlaneError(
                    "restore failed and previous state could not be restored: %s "
                    "(rollback error: %s)" % (exc, rollback_exc)
                ) from exc
            self._cleanup_activation_checkpoint(checkpoint)
            raise ControlPlaneError(
                "restore failed; previous control-plane state was restored "
                "(revision %s): %s" % (previous_revision, exc)
            ) from exc

    def list_revisions(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM config_revisions ORDER BY revision DESC LIMIT 200")]

    def upsert_enrollment_plan(
        self,
        name: str,
        *,
        platform: str = "linux",
        client_groups: Optional[list] = None,
        initial_services: Optional[list] = None,
        description: str = "",
    ) -> dict:
        name = _validate_name(name, "Enrollment plan name")
        platform = str(platform or "linux").strip().lower()
        if platform not in ("linux", "windows", "macos"):
            raise ControlPlaneError("enrollment plan platform must be linux|windows|macos")
        client_groups = list(client_groups or [])
        initial_services = list(initial_services or [])

        def write():
            now = utc_now_iso()
            existing = self.conn.execute(
                "SELECT * FROM enrollment_plans WHERE lower(name)=lower(?)", (name,)
            ).fetchone()
            payload_groups = json.dumps(client_groups, sort_keys=True)
            payload_services = json.dumps(initial_services, sort_keys=True)
            if existing:
                if (
                    existing["platform"] == platform
                    and existing["client_groups_json"] == payload_groups
                    and existing["initial_services_json"] == payload_services
                    and (existing["description"] or "") == description
                ):
                    return {
                        "entity": {"type": "enrollment-plan", "id": existing["id"], "name": name},
                        "operation": "noop",
                    }
                self.conn.execute(
                    "UPDATE enrollment_plans SET platform=?, client_groups_json=?, "
                    "initial_services_json=?, description=?, updated_at=?, updated_revision=? "
                    "WHERE id=?",
                    (
                        platform,
                        payload_groups,
                        payload_services,
                        description,
                        now,
                        self._next_revision(),
                        existing["id"],
                    ),
                )
                return {
                    "entity": {"type": "enrollment-plan", "id": existing["id"], "name": name},
                    "operation": "update",
                }
            eid = _new_id("epl")
            self.conn.execute(
                "INSERT INTO enrollment_plans(id, name, platform, client_groups_json, "
                "initial_services_json, description, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (eid, name, platform, payload_groups, payload_services, description, now, now),
            )
            return {"entity": {"type": "enrollment-plan", "id": eid, "name": name}, "operation": "create"}

        return self._mutate("set enrollment-plan %s" % name, "upsert enrollment plan", write)

    def delete_enrollment_plan(self, name: str) -> dict:
        name = _validate_name(name, "Enrollment plan name")

        def write():
            row = self.conn.execute(
                "SELECT id FROM enrollment_plans WHERE lower(name)=lower(?)", (name,)
            ).fetchone()
            if not row:
                return {"entity": {"type": "enrollment-plan", "name": name}, "operation": "absent"}
            self.conn.execute("DELETE FROM enrollment_plans WHERE id = ?", (row["id"],))
            return {
                "entity": {"type": "enrollment-plan", "id": row["id"], "name": name},
                "operation": "delete",
            }

        return self._mutate("unset enrollment-plan %s" % name, "delete enrollment plan", write)

    def _audit_bundle_attempt(self, plan, *, result: str, result_revision: int) -> None:
        """Record non-secret ConfigurationBundle metadata (no raw bundle body)."""
        try:
            self._audit(
                revision=int(result_revision),
                action="system apply configuration",
                entity_type="configuration-bundle",
                entity_id=str(getattr(plan, "bundle_name", "") or ""),
                operation=str(result),
                after="bundle_hash=%s input=%s" % (
                    getattr(plan, "bundle_hash", ""),
                    getattr(plan, "input_path", ""),
                ),
                impact=json.dumps(
                    {
                        "bundle_hash": getattr(plan, "bundle_hash", ""),
                        "input_path": getattr(plan, "input_path", ""),
                        "base_revision": getattr(plan, "base_revision", None),
                        "result": result,
                    },
                    sort_keys=True,
                )[:2000],
            )
            self.conn.commit()
        except Exception:
            pass

    def list_audit(self, *, revision: Optional[int] = None, entity_type: Optional[str] = None, entity_id: Optional[str] = None, principal: Optional[str] = None) -> list[dict]:
        sql = "SELECT * FROM audit_events WHERE 1=1"
        args: list[Any] = []
        if revision is not None:
            sql += " AND revision = ?"
            args.append(revision)
        if entity_type:
            sql += " AND entity_type = ?"
            args.append(entity_type)
        if entity_id:
            sql += " AND (entity_id = ? OR after_summary LIKE ?)"
            args.extend([entity_id, "%" + entity_id + "%"])
        if principal:
            sql += " AND (entity_id LIKE ? OR after_summary LIKE ? OR action LIKE ?)"
            args.extend(["%" + principal + "%", "%" + principal + "%", "%" + principal + "%"])
        sql += " ORDER BY id DESC LIMIT 200"
        return [dict(r) for r in self.conn.execute(sql, args)]


def _decoded_absolute_path(operand: str) -> Optional[str]:
    from urllib.parse import unquote

    raw = unquote(unquote(str(operand or "")))
    if not raw or "\x00" in raw:
        return None
    if not raw.startswith("/"):
        return None
    parts = raw.split("/")
    for part in parts[1:]:
        if part == "..":
            return None
        if "%" in part:
            # Remaining encodings after double-unquote are fail-closed.
            lowered = part.lower()
            if "%2e" in lowered or "%2f" in lowered or "%5c" in lowered:
                return None
    return raw


def _walk_no_symlink(raw: str) -> Optional[Path]:
    """Resolve a path without following any symlink component.

    Returns None when a symlink is present. Missing leaf files are allowed so
    writes can create a new regular file inside an in-scope parent.
    """
    import stat as statmod

    try:
        current = Path("/")
        parts = [p for p in Path(raw).parts if p not in ("/", "")]
        for idx, part in enumerate(parts):
            current = current / part
            try:
                st = current.lstat()
            except FileNotFoundError:
                if idx == len(parts) - 1:
                    parent = Path(os.path.realpath(str(current.parent)))
                    return parent / part
                return Path(os.path.realpath(str(Path(raw))))
            if statmod.S_ISLNK(st.st_mode):
                return None
        return Path(os.path.realpath(str(Path(raw))))
    except OSError:
        return None


def _pattern_prefixes(patterns: list[str]) -> list[tuple[str, str]]:
    out = []
    for pattern in patterns:
        patt = str(pattern or "")
        if patt.endswith("/**"):
            prefix = patt[:-3].rstrip("/")
            kind = "tree"
        else:
            prefix = patt.rstrip("/")
            kind = "exact"
        prefix_res = os.path.realpath(prefix) if prefix else prefix
        out.append((kind, str(prefix_res).rstrip("/") or "/"))
    return out


def path_allowed(operand: str, patterns: list[str]) -> bool:
    """Fail-closed path match using canonicalization, not string prefix."""
    raw = _decoded_absolute_path(operand)
    if not raw or not patterns:
        return False
    walked = _walk_no_symlink(raw)
    if walked is None:
        return False
    text = str(walked)
    for kind, prefix in _pattern_prefixes(patterns):
        if kind == "tree":
            if text == prefix or text.startswith(prefix + "/"):
                return True
        elif text == prefix or fnmatch(text, prefix):
            return True
    return False


def validate_safe_path(operand: str, patterns: list[str], *, must_exist: bool = False) -> Path:
    raw = _decoded_absolute_path(operand)
    if not raw:
        raise ControlPlaneError("path must be absolute")
    walked = _walk_no_symlink(raw)
    if walked is None:
        raise ControlPlaneError("path is outside allowed scope")
    if not path_allowed(str(walked), patterns):
        raise ControlPlaneError("path is outside allowed scope")
    if must_exist and not walked.exists():
        raise ControlPlaneError("path does not exist")
    return walked
