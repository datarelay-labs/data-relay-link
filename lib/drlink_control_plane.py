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
    integrity_check,
    open_control_db,
    pragma_snapshot,
    runtime_dir,
    utc_now_iso,
)

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
TAG_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
OAUTH_UNBOUND_PRINCIPAL = "__oauth_unbound__"
OAUTH_ACCESS_TTL = 3600
OAUTH_REFRESH_TTL = 30 * 24 * 3600
OAUTH_MAX_REDIRECTS = 16
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
        if impact and impact.get("access_broadened") and not _confirm_requested(confirm):
            if not self._batch_mode:
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
            self.conn.execute("COMMIT")
        except ConfirmationRequired:
            self.conn.execute("ROLLBACK")
            self._cleanup_activation_checkpoint(checkpoint)
            raise
        except ConcurrencyError:
            self.conn.execute("ROLLBACK")
            self._cleanup_activation_checkpoint(checkpoint)
            raise
        except ControlPlaneError:
            self.conn.execute("ROLLBACK")
            self._cleanup_activation_checkpoint(checkpoint)
            raise
        except Exception as exc:
            self.conn.execute("ROLLBACK")
            self._cleanup_activation_checkpoint(checkpoint)
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
        lines = [
            "Policy behavior will change",
            "",
        ]
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
        if obj:
            return "object", obj
        grp = self.get_object_group(text)
        if grp:
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
            "SELECT * FROM object_group_members WHERE group_id = ?", (group_id,)
        ):
            if mem["member_kind"] == "object":
                obj = self.conn.execute(
                    "SELECT * FROM objects WHERE id = ?", (mem["member_id"],)
                ).fetchone()
                if obj:
                    out.append(obj)
            else:
                out.extend(self._expand_group_members(mem["member_id"], seen))
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
                "Managed Endpoint is not a creatable Object type.\n"
                "Managed Endpoints follow Client lifecycle."
            )
        if obj_type not in OBJECT_TYPES:
            raise ControlPlaneError("Object type must be host, network, or fqdn")
        name = _validate_name(name, "Object name")

        def write():
            existing = self.get_object(name)
            if existing:
                if existing["origin"] == "managed":
                    raise ControlPlaneError("Cannot change type of a Managed Endpoint through Object CRUD.")
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
            raise ControlPlaneError("Cannot edit Managed Endpoint values through Object CRUD.")
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
            raise ControlPlaneError("Cannot edit Managed Endpoint values through Object CRUD.")
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
            raise ControlPlaneError("Rename a Managed Endpoint through Client label, not Object CRUD.")

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
                refs.append(
                    {
                        "kind": "policy",
                        "plane": row["plane"],
                        "name": row["name"],
                        "field": kind,
                        "action": row["action"],
                        "enabled": bool(row["enabled"]),
                        "display": "%s-access %s" % ("remote" if row["plane"] == "remote" else "internet", row["name"]),
                    }
                )
        for row in self.conn.execute(
            "SELECT g.name FROM object_group_members m JOIN object_groups g ON g.id = m.group_id "
            "WHERE m.member_kind = 'object' AND m.member_id = ?",
            (obj["id"],),
        ):
            refs.append({"kind": "object-group", "name": row["name"], "display": "object-group %s" % row["name"]})
        for row in self.conn.execute(
            "SELECT name FROM fixed_tcp WHERE destination_object_id = ?", (obj["id"],)
        ):
            refs.append({"kind": "fixed-tcp", "name": row["name"], "display": "fixed-tcp %s" % row["name"]})
        if obj["type"] == "managed_endpoint":
            for row in self.conn.execute(
                "SELECT r.name FROM ai_rule_targets t JOIN ai_access_rules r ON r.id = t.rule_id "
                "WHERE t.target_kind = 'endpoint' AND t.target_id = ?",
                (obj["id"],),
            ):
                refs.append({"kind": "ai-access", "name": row["name"], "display": "ai-access %s" % row["name"]})
        return refs

    def unset_object(self, name: str) -> dict:
        obj = self.require_object(name)
        if obj["origin"] == "managed":
            raise ControlPlaneError(
                "Cannot remove Managed Endpoint %s through Object CRUD.\n"
                "Use Client lifecycle operations."
                % name
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
            "managed_endpoint": "Managed Endpoint",
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

        def write():
            if existing:
                self.conn.execute(
                    "UPDATE clients SET label = COALESCE(?, label), description = COALESCE(?, description), "
                    "hostname = COALESCE(?, hostname), status = 'connected', connected = ?, last_seen = ?, "
                    "row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (label, description, hostname, 1 if connected else 0, now, now, client_id),
                )
            else:
                self.conn.execute(
                    "INSERT INTO clients(id, label, description, hostname, status, trust_status, connected, "
                    "last_seen, row_version, created_at, updated_at) VALUES (?, ?, ?, ?, 'connected', 'trusted', ?, ?, 1, ?, ?)",
                    (
                        client_id,
                        label or "",
                        description or "",
                        hostname or "",
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

    def set_endpoint_addresses(self, endpoint: str, addresses: list[dict]) -> dict:
        obj = self.require_object(endpoint)
        if obj["type"] != "managed_endpoint":
            raise ControlPlaneError("Not a Managed Endpoint: %s" % endpoint)

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
            raise ControlPlaneError("Not a Managed Endpoint: %s" % name)
        ep = self.conn.execute(
            "SELECT * FROM managed_endpoints WHERE object_id = ?", (obj["id"],)
        ).fetchone()
        client = None
        if ep and ep["client_id"]:
            client = self.conn.execute("SELECT * FROM clients WHERE id = ?", (ep["client_id"],)).fetchone()
        status = "Orphaned" if obj["status"] == "orphaned" else (
            "Connected" if client and client["connected"] else "Disconnected"
        )
        lines = [
            "Managed Endpoint: %s" % obj["name"],
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
                return {"entity": {"type": "client", "id": client["id"]}, "operation": "revoke"}
            refs = []
            if ep:
                refs = self.object_references(ep["name"])
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
            self.conn.execute("DELETE FROM client_group_members WHERE client_id = ?", (client["id"],))
            self.conn.execute("DELETE FROM client_tags WHERE client_id = ?", (client["id"],))
            self.conn.execute(
                "UPDATE published_services SET enabled = 0 WHERE client_id = ?",
                (client["id"],),
            )
            self.conn.execute("DELETE FROM clients WHERE id = ?", (client["id"],))
            return {"entity": {"type": "client", "id": client["id"]}, "operation": "remove"}

        return self._mutate(
            "system revoke client" if revoke_only else "unset client %s" % selector,
            "revoke" if revoke_only else "remove client",
            write,
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

    def set_rule_enabled(self, plane: str, name: str, enabled: bool) -> dict:
        rule = self._require_rule(plane, name)

        def write():
            self.conn.execute(
                "UPDATE policy_rules SET enabled = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, utc_now_iso(), rule["id"]),
            )
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "enable" if enabled else "disable"}

        return self._mutate("set %s-access enabled" % plane, "enable/disable rule", write)

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

    def unset_rule(self, plane: str, name: str) -> dict:
        rule = self._require_rule(plane, name)

        def write():
            self.conn.execute("DELETE FROM rule_sources WHERE rule_id = ?", (rule["id"],))
            self.conn.execute("DELETE FROM rule_destinations WHERE rule_id = ?", (rule["id"],))
            self.conn.execute("DELETE FROM rule_services WHERE rule_id = ?", (rule["id"],))
            self.conn.execute("DELETE FROM policy_rules WHERE id = ?", (rule["id"],))
            return {"entity": {"type": "%s-access" % plane, "id": rule["id"], "name": name}, "operation": "delete"}

        return self._mutate("unset %s-access %s" % (plane, name), "delete rule", write)

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
        from drlink_v24 import effective_policy_result, get_access_policy

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
            svc_ok = False
            for s in self.conn.execute("SELECT protocol, port FROM rule_services WHERE rule_id = ?", (rule_row["id"],)):
                if s["protocol"] == proto and int(s["port"]) == int(port):
                    svc_ok = True
                    break
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
                result["action"] if not result["implicit"] else "DENY",
                "Reason: %s" % result["reason"],
            ]
        )
        return "\n".join(lines) + "\n"

    def evaluate_internet_access(self, source_ip: str, destination: str, port: int, protocol: str) -> dict:
        from drlink_v24 import effective_policy_result, get_access_policy

        proto = str(protocol).lower()
        if proto in ("https", "http"):
            want_tcp = True
        else:
            want_tcp = proto in ("tcp", "udp")
        src_matches = self.matching_objects_for_ip(source_ip, role="source")
        dst_matches = self.matching_objects_for_host(destination)
        pol = get_access_policy(self, "internet")
        traces = []
        matched = []
        for rule_row in self.conn.execute(
            "SELECT * FROM policy_rules WHERE plane = 'internet' ORDER BY name"
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
                if self._ref_matches_host(s["ref_kind"], s["ref_id"], destination):
                    dst_ok = True
                    break
            svc_ok = False
            for s in self.conn.execute("SELECT protocol, port FROM rule_services WHERE rule_id = ?", (rule_row["id"],)):
                if int(s["port"]) == int(port) and (
                    s["protocol"] == proto
                    or (want_tcp and s["protocol"] == "tcp")
                    or (proto in ("https",) and int(s["port"]) == 443)
                    or (proto in ("http",) and int(s["port"]) == 80)
                ):
                    svc_ok = True
                    break
            hit = bool(src_ok and dst_ok and svc_ok)
            traces.append({"rule": view, "evaluated": True, "source": src_ok, "dest": dst_ok, "service": svc_ok, "match": hit})
            if hit:
                matched.append(view)
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
            "destination": destination,
            "port": int(port),
            "protocol": proto,
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
                dest_host = dest_host or vals[0]
            if obj["type"] == "fqdn" and vals:
                dest_host = dest_host or vals[0]

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
        refs = self.conn.execute(
            "SELECT name FROM ai_access_rules WHERE principal_id = ?", (existing["id"],)
        ).fetchall()
        if refs:
            raise ControlPlaneError(
                "Cannot remove AI Principal %s.\nReferenced by:\n%s\n\nNo changes were applied."
                % (name, "\n".join("  ai-access %s" % r["name"] for r in refs))
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

    def _validate_oauth_redirect_uri(self, uri: str) -> str:
        text = str(uri or "").strip()
        if not text:
            raise ControlPlaneError("redirect_uri is required")
        if "*" in text:
            raise ControlPlaneError("wildcard redirect_uri is not allowed")
        lower = text.lower()
        if lower.startswith("javascript:") or lower.startswith("data:") or lower.startswith("file:"):
            raise ControlPlaneError("redirect_uri scheme is not allowed")
        if text.startswith("https://"):
            return text
        if text.startswith("http://127.0.0.1") or text.startswith("http://localhost") or text.startswith("http://[::1]"):
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

    def _fetch_cimd_document(self, url: str) -> dict:
        import urllib.error
        import urllib.request

        text = str(url or "").strip()
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(text)
        if parsed.scheme != "https" or parsed.path in ("", "/"):
            raise ControlPlaneError("CIMD client_id must be an https URL with a path")
        req = urllib.request.Request(
            text,
            headers={"Accept": "application/json", "User-Agent": "DataRelayLink-MCP/2.4"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                raw = resp.read(65536)
        except Exception as exc:
            raise ControlPlaneError("CIMD metadata fetch failed") from exc
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ControlPlaneError("CIMD metadata is not valid JSON") from exc
        if not isinstance(doc, dict):
            raise ControlPlaneError("CIMD metadata must be a JSON object")
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

    def resolve_oauth_authorize_client(self, client_id: str, redirect_uri: str) -> dict:
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
            doc = self._fetch_cimd_document(client_id)
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

    def create_oauth_pending(self, *, client_id: str, redirect_uri: str, code_challenge: str, resource: str, state: str = "") -> dict:
        if not code_challenge:
            raise ControlPlaneError("code_challenge is required")
        resolved = self.resolve_oauth_authorize_client(client_id, redirect_uri)
        pending_id = _new_id("oap")
        now = utc_now_iso()
        self.conn.execute(
            "INSERT INTO ai_oauth_pending(id, principal_id, client_id, redirect_uri, code_challenge, resource, state, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                pending_id,
                resolved["principal_id"],
                client_id,
                resolved["redirect_uri"],
                code_challenge,
                resource or "",
                state or "",
                now,
            ),
        )
        return {
            "id": pending_id,
            "principal": resolved["principal_name"],
            "client_id": client_id,
            "unbound": bool(resolved.get("unbound")),
            "source": resolved.get("source"),
        }

    def approve_oauth_pending(self, pending_id: str, principal_name: Optional[str] = None) -> dict:
        row = self.conn.execute("SELECT * FROM ai_oauth_pending WHERE id = ?", (pending_id,)).fetchone()
        if row is None:
            raise ControlPlaneError("OAuth request not found")
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
        self.conn.execute("DELETE FROM ai_oauth_pending WHERE id = ?", (pending_id,))
        return {
            "code": code,
            "redirect_uri": row["redirect_uri"],
            "state": row["state"],
            "resource": row["resource"],
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
            "AND t.expires_at > ? AND p.enabled = 1 AND p.credential_status != 'revoked'",
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
            "AND p.enabled = 1 AND p.credential_status != 'revoked' AND p.name != ?",
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

    def issue_agent_credential(self, client_id: str, *, rotate: bool = False) -> Optional[str]:
        key = "ai_agent_hash:%s" % client_id
        existing = self.conn.execute("SELECT value FROM system_meta WHERE key = ?", (key,)).fetchone()
        if existing and not rotate:
            return None
        token = "dra_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT OR REPLACE INTO system_meta(key, value) VALUES (?, ?)",
            (key, digest),
        )
        return token

    def authenticate_agent(self, token: str) -> Optional[str]:
        digest = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()
        row = self.conn.execute(
            "SELECT key FROM system_meta WHERE value = ? AND key LIKE 'ai_agent_hash:%'",
            (digest,),
        ).fetchone()
        if row is None:
            return None
        return str(row["key"]).split(":", 1)[1]

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
        job_id = _new_id("job")
        now = utc_now_iso()
        payload = {
            "client_id": client_id,
            "arguments": arguments,
            "patterns": list(patterns or []),
            "timeout": timeout,
        }
        self.conn.execute(
            "INSERT INTO ai_jobs(id, principal_id, endpoint_object_id, capability, payload_json, "
            "status, result_json, created_at, updated_at, timeout_seconds) "
            "VALUES (?, ?, ?, ?, ?, 'queued', NULL, ?, ?, ?)",
            (
                job_id,
                principal_id,
                endpoint_object_id,
                capability,
                json.dumps(payload, sort_keys=True),
                now,
                now,
                int(timeout or 30),
            ),
        )
        return job_id

    def claim_ai_jobs(self, client_id: str, limit: int = 4) -> list[dict]:
        rows = list(
            self.conn.execute(
                "SELECT * FROM ai_jobs WHERE status = 'queued' ORDER BY created_at LIMIT ?",
                (max(1, int(limit)),),
            )
        )
        claimed = []
        now = utc_now_iso()
        for row in rows:
            payload = json.loads(row["payload_json"] or "{}")
            if payload.get("client_id") != client_id:
                continue
            self.conn.execute(
                "UPDATE ai_jobs SET status = 'running', updated_at = ? WHERE id = ? AND status = 'queued'",
                (now, row["id"]),
            )
            if self.conn.execute("SELECT changes()").fetchone()[0]:
                claimed.append(
                    {
                        "id": row["id"],
                        "capability": row["capability"],
                        "arguments": payload.get("arguments") or {},
                        "patterns": payload.get("patterns") or [],
                        "timeout": payload.get("timeout") or row["timeout_seconds"],
                    }
                )
        return claimed

    def complete_ai_job(self, job_id: str, client_id: str, result: dict) -> None:
        row = self.conn.execute("SELECT payload_json, status FROM ai_jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise ControlPlaneError("AI job not found")
        payload = json.loads(row["payload_json"] or "{}")
        if payload.get("client_id") != client_id:
            raise ControlPlaneError("AI job does not belong to this client")
        safe = dict(result or {})
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
        self.conn.execute(
            "UPDATE ai_jobs SET status = 'done', result_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(safe, sort_keys=True)[:8000], utc_now_iso(), job_id),
        )

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
            time.sleep(0.05)
        job = self.get_ai_job(job_id) or {"id": job_id, "status": "timeout"}
        if job.get("status") != "done":
            self.conn.execute(
                "UPDATE ai_jobs SET status = 'timeout', updated_at = ? WHERE id = ? AND status != 'done'",
                (utc_now_iso(), job_id),
            )
            job["status"] = "timeout"
        return job

    def connected_clients(self) -> list[dict]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT id, label, connected, status FROM clients WHERE connected = 1 AND trust_status = 'trusted'"
            )
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
                raise ControlPlaneError("AI target endpoint must be a Managed Endpoint")
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
        from drlink_v24 import detect_cli_role, format_show_status

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
        extra.append("Remote Services  : %s" % st["services"])
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
        host = str(data.get("public_hostname") or data.get("public_ip") or data.get("public_host") or "").strip()
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

    def backup_validate(self, src: str) -> dict:
        with tarfile.open(src, "r") as tar:
            names = tar.getnames()
            if "drlink.db" not in names:
                raise ControlPlaneError("backup is missing drlink.db")
            db_member = tar.extractfile("drlink.db")
            if db_member is None:
                raise ControlPlaneError("backup drlink.db unreadable")
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as fh:
                fh.write(db_member.read())
                tmp = fh.name
        try:
            conn = sqlite3.connect(tmp)
            conn.execute("PRAGMA foreign_keys = ON")
            row = conn.execute("PRAGMA integrity_check").fetchone()
            if not row or str(row[0]).lower() != "ok":
                raise ControlPlaneError("backup SQLite integrity failed")
            fk = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk:
                raise ControlPlaneError("backup foreign keys invalid")
            conn.close()
        finally:
            os.unlink(tmp)
        return {"ok": True, "path": src}

    def restore(self, src: str) -> dict:
        self.backup_validate(src)
        with tarfile.open(src, "r") as tar:
            db_member = tar.extractfile("drlink.db")
            payload = db_member.read()
        fd, tmp = tempfile.mkstemp(prefix="drlink-restore-", suffix=".db")
        os.close(fd)
        try:
            Path(tmp).write_bytes(payload)
            src_conn = sqlite3.connect(tmp)
            try:
                if self.conn is None:
                    self.conn = open_control_db(self.root)
                src_conn.backup(self.conn)
            finally:
                src_conn.close()
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            for suffix in ("-wal", "-shm"):
                extra = Path(tmp + suffix)
                try:
                    extra.unlink()
                except FileNotFoundError:
                    pass
        self._db_ident = self._db_file_ident()
        self.compile_runtime()
        st = self.status()
        return {"ok": True, "revision": st["revision"]}

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
