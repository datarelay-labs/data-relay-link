#!/usr/bin/env python3
"""Data Relay Link v2.4 canonical CLI / Objects / Policy / Bundle helpers.

Authority: docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md
Public nouns and semantics in this module override legacy aliases.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Optional

from drlink_control_db import ControlPlaneError, utc_now_iso

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
RESERVED_TOKENS = frozenset({"enabled", "disabled", "policy"})

NETWORK_PUBLIC_TYPES = ("ip", "cidr", "fqdn")
NETWORK_STORE = {"ip": "host", "cidr": "network", "fqdn": "fqdn"}
NETWORK_DISPLAY = {
    "host": "IP",
    "network": "CIDR",
    "fqdn": "FQDN",
    "managed_endpoint": "Managed Host",
}

DESTINATION_UNREACHABLE_REASON = "Destination is currently unreachable from Relay Host."
DISABLED_OPERATOR_REASON = ""

SERVICE_TYPES = ("tcp", "udp", "fixed-tcp")
PERMISSIONS = (
    "host-info",
    "process-read",
    "file-read",
    "command-exec",
    "file-write",
    "file-upload",
    "file-download",
)
PERMISSION_TO_CAPS = {
    "host-info": ("list_hosts", "get_host", "get_system_info"),
    "process-read": ("list_processes",),
    "file-read": ("read_file",),
    "command-exec": ("exec",),
    "file-write": ("write_file",),
    "file-upload": ("upload_file",),
    "file-download": ("download_file",),
}
FILE_PERMISSIONS = frozenset(
    {"file-read", "file-write", "file-upload", "file-download"}
)
CAP_TO_PERMISSION = {}
for _perm, _caps in PERMISSION_TO_CAPS.items():
    for _cap in _caps:
        CAP_TO_PERMISSION[_cap] = _perm

POLICY_PLANES = ("remote", "internet", "ai")
POLICY_MODES = ("blacklist", "whitelist")

NORMAL_PORT_START, NORMAL_PORT_END = 6000, 6099
FIXED_PORT_START, FIXED_PORT_END = 6200, 6299

_ENDPOINT_ALLOC_LOCK = threading.Lock()

V2_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS access_policies (
  plane TEXT PRIMARY KEY,
  mode TEXT,
  enforcement TEXT NOT NULL DEFAULT 'enabled',
  row_version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS service_objects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  type TEXT NOT NULL,
  port INTEGER NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS service_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS service_group_members (
  group_id TEXT NOT NULL,
  service_object_id TEXT NOT NULL,
  PRIMARY KEY (group_id, service_object_id),
  FOREIGN KEY (group_id) REFERENCES service_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (service_object_id) REFERENCES service_objects(id)
);

CREATE TABLE IF NOT EXISTS permission_objects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permission_object_members (
  permission_object_id TEXT NOT NULL,
  permission TEXT NOT NULL,
  PRIMARY KEY (permission_object_id, permission),
  FOREIGN KEY (permission_object_id) REFERENCES permission_objects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS permission_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permission_group_members (
  group_id TEXT NOT NULL,
  permission_object_id TEXT NOT NULL,
  PRIMARY KEY (group_id, permission_object_id),
  FOREIGN KEY (group_id) REFERENCES permission_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_object_id) REFERENCES permission_objects(id)
);

CREATE TABLE IF NOT EXISTS rule_service_refs (
  rule_id TEXT NOT NULL,
  ref_kind TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  PRIMARY KEY (rule_id, ref_kind, ref_id),
  FOREIGN KEY (rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_policy_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  enabled INTEGER NOT NULL DEFAULT 1,
  source_identity_id TEXT,
  destination_ref_kind TEXT,
  destination_ref_id TEXT,
  permission_ref_kind TEXT,
  permission_ref_id TEXT,
  description TEXT NOT NULL DEFAULT '',
  row_version INTEGER NOT NULL DEFAULT 1,
  created_revision INTEGER,
  updated_revision INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Canonical path constraints for AI file capabilities.
-- Bound through public v2.4 CLI / Wizard / ConfigurationBundle (paths field)
-- and enforced by authorize_ai_capability_v24. Missing scopes fail closed for
-- file capabilities (no unrestricted filesystem default).
CREATE TABLE IF NOT EXISTS ai_policy_path_scopes (
  rule_id TEXT NOT NULL,
  pattern TEXT NOT NULL,
  PRIMARY KEY (rule_id, pattern),
  FOREIGN KEY (rule_id) REFERENCES ai_policy_rules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS remote_service_meta (
  service_id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'HEALTHY',
  pool_class TEXT NOT NULL DEFAULT 'normal',
  service_object_id TEXT,
  destination_name TEXT,
  destination_client_id TEXT,
  pending_allocation INTEGER NOT NULL DEFAULT 0,
  delete_pending INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (service_id) REFERENCES published_services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_remote_services (
  name TEXT PRIMARY KEY,
  destination TEXT NOT NULL,
  destination_client_id TEXT,
  service_object TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'DEGRADED',
  endpoint_host TEXT,
  endpoint_port INTEGER,
  pending_allocation INTEGER NOT NULL DEFAULT 1,
  delete_pending INTEGER NOT NULL DEFAULT 0,
  pool_class TEXT NOT NULL DEFAULT 'normal',
  reason TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_object_catalog (
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  payload TEXT NOT NULL,
  synced_at TEXT NOT NULL,
  PRIMARY KEY (kind, name)
);
"""


def _new_id(prefix: str) -> str:
    return "%s_%s" % (prefix, secrets.token_hex(8))


def validate_public_name(value: str, kind: str = "Name") -> str:
    text = str(value or "").strip()
    if not text:
        raise ControlPlaneError("%s is required" % kind)
    if text.lower() in RESERVED_TOKENS:
        raise ControlPlaneError(
            "%s '%s' is a reserved command token.\n\nNo changes were applied." % (kind, text)
        )
    if not NAME_RE.fullmatch(text):
        raise ControlPlaneError(
            "%s must start with a letter and may contain letters, digits, '.', '_' and '-'"
            % kind
        )
    return text


def _cross_kind_name_taken_error(name: str, creating_kind: str, conflicting_kind: str) -> str:
    return (
        "ERROR:\nPublic name '%s' is already used by a %s.\n\n"
        "%s and %s names must be unique across that selector namespace.\n\n"
        "No changes were applied."
        % (name, conflicting_kind, creating_kind, conflicting_kind)
    )


def _ambiguous_public_name_error(name: str, object_kind: str, group_kind: str) -> str:
    return (
        "ERROR:\nPublic name '%s' is ambiguous because both a %s and a %s exist.\n\n"
        "Rename or remove one of them so the selector is unique.\n\n"
        "No changes were applied."
        % (name, object_kind, group_kind)
    )


def assert_network_public_name_available(plane_db, name: str, *, creating: str) -> None:
    """Reject create when the paired Network Object/Group namespace already owns ``name``."""
    if creating == "object":
        if plane_db.get_object_group(name):
            raise ControlPlaneError(
                _cross_kind_name_taken_error(name, "Network Object", "Network Group")
            )
    elif creating == "group":
        if plane_db.get_object(name):
            raise ControlPlaneError(
                _cross_kind_name_taken_error(name, "Network Group", "Network Object")
            )
    else:
        raise ValueError("creating must be 'object' or 'group'")


def assert_service_public_name_available(plane_db, name: str, *, creating: str) -> None:
    if creating == "object":
        if get_service_group(plane_db, name):
            raise ControlPlaneError(
                _cross_kind_name_taken_error(name, "Service Object", "Service Group")
            )
    elif creating == "group":
        if get_service_object(plane_db, name):
            raise ControlPlaneError(
                _cross_kind_name_taken_error(name, "Service Group", "Service Object")
            )
    else:
        raise ValueError("creating must be 'object' or 'group'")


def assert_permission_public_name_available(plane_db, name: str, *, creating: str) -> None:
    if creating == "object":
        if get_permission_group(plane_db, name):
            raise ControlPlaneError(
                _cross_kind_name_taken_error(name, "Permission Object", "Permission Group")
            )
    elif creating == "group":
        if get_permission_object(plane_db, name):
            raise ControlPlaneError(
                _cross_kind_name_taken_error(name, "Permission Group", "Permission Object")
            )
    else:
        raise ValueError("creating must be 'object' or 'group'")


def resolve_service_ref(plane_db, token: str) -> tuple[str, sqlite3.Row]:
    """Resolve a Service public selector; fail closed on Object/Group ambiguity."""
    text = str(token or "").strip()
    sobj = get_service_object(plane_db, text)
    sgrp = get_service_group(plane_db, text)
    if sobj is not None and sgrp is not None:
        raise ControlPlaneError(
            _ambiguous_public_name_error(text, "Service Object", "Service Group")
        )
    if sobj is not None:
        return "service_object", sobj
    if sgrp is not None:
        return "service_group", sgrp
    raise ControlPlaneError(
        cli_error(
            "Service '%s' was not found." % token,
            expected="  Service Object\n  Service Group",
            next_step="Use:\n  show service-objects\n  show service-groups",
        )
    )


def resolve_permission_ref(plane_db, token: str) -> tuple[str, sqlite3.Row]:
    """Resolve a Permission public selector; fail closed on Object/Group ambiguity."""
    text = str(token or "").strip()
    pobj = get_permission_object(plane_db, text)
    pgrp = get_permission_group(plane_db, text)
    if pobj is not None and pgrp is not None:
        raise ControlPlaneError(
            _ambiguous_public_name_error(text, "Permission Object", "Permission Group")
        )
    if pobj is not None:
        return "permission_object", pobj
    if pgrp is not None:
        return "permission_group", pgrp
    raise ControlPlaneError(cli_error("Permission '%s' was not found." % token))


def ensure_v2_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(V2_SCHEMA_SQL)
    # Additive identity column for Managed Host Remote Service destinations.
    meta_cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(remote_service_meta)")}
    if "destination_client_id" not in meta_cols:
        conn.execute("ALTER TABLE remote_service_meta ADD COLUMN destination_client_id TEXT")
    agent_cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(agent_remote_services)")}
    if "destination_client_id" not in agent_cols:
        conn.execute("ALTER TABLE agent_remote_services ADD COLUMN destination_client_id TEXT")
    now = utc_now_iso()
    for plane in POLICY_PLANES:
        row = conn.execute("SELECT plane FROM access_policies WHERE plane = ?", (plane,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO access_policies(plane, mode, enforcement, row_version, updated_at) "
                "VALUES (?, NULL, 'enabled', 1, ?)",
                (plane, now),
            )
    # Seed common service objects if empty.
    count = conn.execute("SELECT COUNT(*) FROM service_objects").fetchone()[0]
    if int(count or 0) == 0:
        seeds = (
            ("ssh", "tcp", 22),
            ("http", "tcp", 80),
            ("https", "tcp", 443),
            ("rdp", "tcp", 3389),
            ("postgres", "tcp", 5432),
        )
        for name, stype, port in seeds:
            conn.execute(
                "INSERT OR IGNORE INTO service_objects"
                "(id, name, type, port, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, '', 1, ?, ?)",
                (_new_id("sobj"), name, stype, port, now, now),
            )


def _commit_if_autonomous(plane_db) -> None:
    """Never COMMIT an outer Bundle / batch transaction from a nested helper."""
    commit = getattr(plane_db, "commit_if_autonomous", None)
    if callable(commit):
        commit()
        return
    if getattr(plane_db, "_batch_mode", False):
        return
    conn = getattr(plane_db, "conn", None)
    if conn is None:
        return
    try:
        if conn.in_transaction:
            conn.commit()
    except sqlite3.OperationalError:
        pass


def _agent_mgmt_effects(plane_db) -> list:
    effects = getattr(plane_db, "_agent_mgmt_side_effects", None)
    if effects is None:
        plane_db._agent_mgmt_side_effects = []
        effects = plane_db._agent_mgmt_side_effects
    return effects


def _record_agent_mgmt_effect(plane_db, effect: dict) -> None:
    item = dict(effect or {})
    if not item.get("op") or not item.get("name"):
        return
    _agent_mgmt_effects(plane_db).append(item)


def _record_agent_mgmt_create(plane_db, name: str, *, root: Optional[str] = None) -> None:
    _record_agent_mgmt_effect(plane_db, {"op": "create-rs", "name": name, "root": root})


def _clear_agent_mgmt_side_effects(plane_db) -> None:
    plane_db._agent_mgmt_side_effects = []


def _agent_remote_service_mgmt_snapshot(
    plane_db,
    row,
    *,
    root: Optional[str] = None,
    host_name: str = "",
) -> dict:
    """Capture Server-restorable fields from a local Agent Remote Service row."""
    name = str(row["name"])
    destination = str(row["destination"] or "")
    destination_client_id = str(_row_get(row, "destination_client_id") or "").strip() or None
    service = str(row["service_object"] or "")
    enabled = bool(row["enabled"])
    pool_class = str(row["pool_class"] or "normal")
    endpoint_port = row["endpoint_port"]
    status = str(row["status"] or "").upper()
    host = str(host_name or "").strip()
    dest_l = destination.lower()
    host_l = host.lower()
    if dest_l in ("this-host", "this_host", "self") or (host_l and dest_l == host_l):
        target_mode = "self"
        target_host = "127.0.0.1"
        destination = host or destination
    else:
        target_mode = "routed"
        target_host = destination
        if destination_client_id:
            inventory = _managed_host_inventory_by_client_id(plane_db, destination_client_id)
            if inventory:
                resolved, _reason = _runtime_target_for_managed_host(inventory)
                if resolved:
                    target_host = resolved
                destination = str(inventory.get("name") or destination)
                identity = load_agent_identity(root or getattr(plane_db, "root", None))
                self_id = str(identity.get("machine_id") or "").strip()
                if self_id and self_id == destination_client_id:
                    target_mode = "self"
                    target_host = "127.0.0.1"
        else:
            obj = None
            try:
                obj = plane_db.get_object(destination) if hasattr(plane_db, "get_object") else None
            except Exception:
                obj = None
            if obj and obj.get("type") in ("host", "fqdn"):
                vals = plane_db._object_values(obj["id"]) if hasattr(plane_db, "_object_values") else []
                if vals:
                    target_host = vals[0]
            elif obj and obj.get("type") == "managed_endpoint":
                cid = obj.get("client_id") or _managed_host_client_id_from_name(plane_db, destination)
                destination_client_id = str(cid) if cid else None
                inventory = (
                    _managed_host_inventory_by_client_id(plane_db, destination_client_id)
                    if destination_client_id
                    else None
                )
                identity = load_agent_identity(root or getattr(plane_db, "root", None))
                self_id = str(identity.get("machine_id") or "").strip()
                if destination_client_id and self_id and destination_client_id == self_id:
                    target_mode = "self"
                    target_host = "127.0.0.1"
                elif inventory:
                    resolved, _reason = _runtime_target_for_managed_host(inventory)
                    target_host = resolved or destination
                else:
                    target_host = destination
            else:
                catalog = plane_db.conn.execute(
                    "SELECT payload FROM agent_object_catalog WHERE kind = 'network-object' AND name = ? COLLATE NOCASE",
                    (destination,),
                ).fetchone()
                if catalog:
                    try:
                        payload = json.loads(catalog["payload"] or "{}")
                    except (TypeError, ValueError):
                        payload = {}
                    vals = [str(v) for v in (payload.get("values") or []) if v not in (None, "")]
                    if vals:
                        target_host = vals[0]
                    if str(payload.get("type") or "").lower() == "managed_endpoint" and payload.get("client_id"):
                        destination_client_id = str(payload["client_id"])
    sobj = get_service_object(plane_db, service)
    target_port = int(sobj["port"]) if sobj else 0
    # Prefer synchronized Server catalog over local seeded Service Objects.
    catalog = plane_db.conn.execute(
        "SELECT payload FROM agent_object_catalog WHERE kind = 'service-object' AND name = ? COLLATE NOCASE",
        (service,),
    ).fetchone()
    if catalog:
        try:
            payload = json.loads(catalog["payload"] or "{}")
            target_port = int(payload.get("port") or target_port or 0)
        except (TypeError, ValueError):
            pass
    elif not sobj:
        target_port = 0
    return {
        "name": name,
        "root": root,
        "destination": destination,
        "destination_client_id": destination_client_id,
        "service": service,
        "enabled": enabled,
        "pool_class": pool_class,
        "target_host": target_host,
        "target_port": target_port,
        "target_mode": target_mode,
        "endpoint_port": endpoint_port,
        "runtime_verified": status == "HEALTHY",
    }


def _compensate_agent_mgmt_effect(mgmt, item: dict, *, root: Optional[str] = None) -> None:
    name = str(item.get("name") or "").strip()
    if not name:
        return
    op = str(item.get("op") or "")
    effect_root = item.get("root") or root
    if op == "create-rs":
        mgmt.delete_remote_service_on_server(root=effect_root, name=name)
        return
    if op in ("update-rs", "delete-rs"):
        endpoint_port = item.get("endpoint_port")
        mgmt.upsert_remote_service_on_server(
            root=effect_root,
            name=name,
            destination=str(item.get("destination") or name),
            destination_client_id=item.get("destination_client_id"),
            service=str(item.get("service") or ""),
            enabled=bool(item.get("enabled", True)),
            pool_class=str(item.get("pool_class") or "normal"),
            target_host=str(item.get("target_host") or "127.0.0.1"),
            target_port=int(item.get("target_port") or 0),
            target_mode=str(item.get("target_mode") or "self"),
            preserve_endpoint_port=int(endpoint_port) if endpoint_port is not None else None,
            runtime_verified=bool(item.get("runtime_verified", False)),
        )
        return


def reconcile_agent_mgmt_side_effects(
    plane_db, *, root: Optional[str] = None, keep_names: Optional[list] = None
) -> dict:
    """Reverse Server Remote Service side effects after local rollback.

    Returns {"ok": bool, "compensated": [names], "failures": [messages]}.
    """
    effects = list(getattr(plane_db, "_agent_mgmt_side_effects", None) or [])
    plane_db._agent_mgmt_side_effects = []
    keep = {str(n).lower() for n in (keep_names or []) if n}
    report = {"ok": True, "compensated": [], "failures": []}
    if not effects:
        return report
    try:
        import drlink_mgmt_sync as mgmt
    except Exception as exc:
        report["ok"] = False
        report["failures"].append("management sync unavailable: %s" % exc)
        return report
    # Compensate newest effects first so UPDATE then CREATE of same name is safe.
    for item in reversed(effects):
        name = str(item.get("name") or "").strip()
        if not name or name.lower() in keep:
            continue
        op = str(item.get("op") or "")
        if op not in ("create-rs", "update-rs", "delete-rs"):
            continue
        try:
            _compensate_agent_mgmt_effect(mgmt, item, root=root)
            report["compensated"].append("%s:%s" % (op, name))
        except Exception as exc:
            report["ok"] = False
            report["failures"].append("%s %s: %s" % (op, name, exc))
    return report


def raise_agent_mgmt_activation_failure(
    plane_db,
    *,
    root: Optional[str] = None,
    cause: Optional[BaseException] = None,
    local_restored: bool = True,
) -> None:
    """Raise a truthful activation failure after attempting Server compensation."""
    report = reconcile_agent_mgmt_side_effects(plane_db, root=root)
    if report.get("ok"):
        if local_restored:
            raise ControlPlaneError(
                "ERROR:\nRuntime activation failed.\n\n"
                "Previous configuration was restored.\n"
                "No configuration changes remain active."
            ) from cause
        raise ControlPlaneError(
            "ERROR:\nRuntime activation failed.\n\n"
            "Server Remote Service compensation completed, but local runtime "
            "activation did not succeed."
        ) from cause
    details = "\n".join("  %s" % f for f in (report.get("failures") or []) ) or "  unknown"
    raise ControlPlaneError(
        "ERROR:\nRuntime activation failed.\n\n"
        "PARTIAL: Server Remote Service state could not be fully restored.\n"
        "RECOVERY_REQUIRED\n\n"
        "Compensation failures:\n%s\n\n"
        "Run:\n  system diagnostics" % details
    ) from cause


def cli_error(what: str, expected: str = "", next_step: str = "", applied: bool = False) -> str:
    lines = ["ERROR:", what, ""]
    if expected:
        lines.extend(["Expected:", expected, ""])
    lines.append("No changes were applied." if not applied else "Changes may remain active.")
    if next_step:
        lines.extend(["", next_step])
    return "\n".join(lines)


def role_error_server_resource(resource: str) -> str:
    return cli_error(
        "%s is managed on the DRLink Server." % resource,
        next_step="Run this command on the DRLink Server.",
    )


def role_error_agent_resource(resource: str = "Remote Service") -> str:
    return cli_error(
        "%s is managed from the DRLink Agent Host." % resource,
        next_step="Run this command on the Agent Host that will own the Remote Service.",
    )


def _macos_agent_state_roots(root: Optional[str] = None) -> list[Path]:
    """macOS Agent state lives under Application Support, not /etc/frp."""
    roots: list[Path] = []
    env = str(os.environ.get("FRP_MACOS_STATE_ROOT") or "").strip()
    if env:
        roots.append(Path(env))
    roots.append(Path("/Library/Application Support/drlink"))
    if root and str(root) not in ("/", ""):
        base = Path(root)
        roots.append(base / "Library/Application Support/drlink")
    seen: set[str] = set()
    out: list[Path] = []
    for path in roots:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _is_agent_state_dir(state: Path) -> bool:
    if (state / "client-state.json").is_file():
        return True
    return (state / "frpc.toml").is_file() and (state / "client-identity.key").is_file()


def _agent_state_file_candidates(rel_linux: str, rel_macos: str, root: Optional[str] = None) -> list[Path]:
    """Linux nested paths plus macOS flat Application Support files."""
    base = Path(root) if root else Path("/")
    out: list[Path] = [base / rel_linux]
    for mac in _macos_agent_state_roots(root):
        out.append(mac / rel_macos)
    seen: set[str] = set()
    uniq: list[Path] = []
    for path in out:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(path)
    return uniq


def detect_cli_role(root: Optional[str] = None) -> str:
    """Return 'server', 'agent', or 'unknown'."""
    base = Path(root) if root else Path("/")
    if (base / "etc/drlink/config.json").is_file():
        return "server"
    if (base / "etc/frp/server_token").is_file() and (
        (base / "var/lib/drlink/drlink.db").is_file()
        or (base / "var/lib/drlink/registry.json").is_file()
    ):
        return "server"
    if (base / "etc/frp/client-state.json").is_file():
        return "agent"
    if (base / "etc/frp/frpc.toml").is_file() and (base / "etc/frp/client-identity.key").is_file():
        return "agent"
    for state in _macos_agent_state_roots(root):
        if _is_agent_state_dir(state):
            return "agent"
    return "unknown"


def role_label(role: str) -> str:
    if role == "server":
        return "DRLink Server"
    if role == "agent":
        return "Agent Host"
    return "Unknown"


def load_agent_identity(root: Optional[str] = None) -> dict:
    for path in _agent_state_file_candidates(
        "etc/frp/client-state.json", "client-state.json", root
    ):
        try:
            if not path.is_file():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        return {
            "machine_id": str(data.get("machine_id") or data.get("id") or "").strip(),
            "hostname": str(data.get("hostname") or data.get("label") or "").strip(),
            "label": str(data.get("label") or data.get("hostname") or "").strip(),
        }
    return {}


def agent_identity_key_path(root: Optional[str] = None) -> Optional[Path]:
    for path in _agent_state_file_candidates(
        "etc/frp/client-identity.key", "client-identity.key", root
    ):
        if path.is_file():
            return path
    return None


def agent_identity_mac_path(root: Optional[str] = None) -> Optional[Path]:
    for path in _agent_state_file_candidates(
        "etc/frp/client-identity.mac", "client-identity.mac", root
    ):
        if path.is_file():
            return path
    return None


def load_agent_server_endpoint(root: Optional[str] = None) -> Optional[tuple[str, int]]:
    """Return configured Agent→Server management endpoint (host, port) or None.

    Local SQLite availability is intentionally not treated as Server reachability.
    """
    base = Path(root) if root else Path("/")
    # Explicit connection info written by enrollment / Apply.
    endpoint_paths = [
        base / "etc/frp/server-endpoint.json",
        base / "var/lib/drlink/server-endpoint.json",
        base / "etc/drlink/server-endpoint.json",
    ]
    endpoint_paths.extend(
        _agent_state_file_candidates("etc/frp/server-endpoint.json", "server-endpoint.json", root)
    )
    for path in endpoint_paths:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = None
            if isinstance(data, dict):
                host = str(data.get("host") or data.get("server_addr") or data.get("addr") or "").strip()
                port = data.get("port") or data.get("server_port") or data.get("allocator_port")
                if host and port:
                    try:
                        return host, int(port)
                    except (TypeError, ValueError):
                        pass
    # client-state may carry allocator / server URL fragments.
    for state_path in _agent_state_file_candidates(
        "etc/frp/client-state.json", "client-state.json", root
    ):
        if not state_path.is_file():
            continue
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = None
        if isinstance(state, dict):
            host = str(
                state.get("server_addr")
                or state.get("server_host")
                or state.get("frp_server")
                or ""
            ).strip()
            port = (
                state.get("server_port")
                or state.get("allocator_port")
                or state.get("frp_server_port")
            )
            if host and port:
                try:
                    return host, int(port)
                except (TypeError, ValueError):
                    pass
            for key in (
                "allocator_url",
                "allocator_public_url",
                "mgmt_url",
                "management_url",
                "server_url",
                "enroll_url",
            ):
                url = str(state.get(key) or "").strip()
                if not url:
                    continue
                parsed = _parse_host_port_from_url(url)
                if parsed:
                    return parsed
    # frpc.toml / frpc.ini serverAddr + serverPort
    toml_paths = _agent_state_file_candidates("etc/frp/frpc.toml", "frpc.toml", root)
    toml_paths.extend(_agent_state_file_candidates("etc/frp/frpc.ini", "frpc.ini", root))
    for path in toml_paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        host = None
        port = None
        for line in text.splitlines():
            raw = line.split("#", 1)[0].strip()
            if not raw or "=" not in raw:
                continue
            key, val = raw.split("=", 1)
            key = key.strip().lower()
            val = val.strip().strip('"').strip("'")
            if key in ("serveraddr", "server_addr"):
                host = val
            elif key in ("serverport", "server_port"):
                try:
                    port = int(val)
                except ValueError:
                    port = None
        if host and port:
            return host, port
    return None


def _parse_host_port_from_url(url: str) -> Optional[tuple[str, int]]:
    text = str(url or "").strip()
    if not text:
        return None
    # Minimal parse without urllib dependency surprises for host:port forms.
    if "://" not in text:
        if ":" in text:
            host, _, port_s = text.rpartition(":")
            try:
                return host.strip("[]"), int(port_s)
            except ValueError:
                return None
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(text)
    except Exception:
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
    if port is None:
        return None
    return host, int(port)


# ---------------------------------------------------------------------------
# Access policy mode / enforcement
# ---------------------------------------------------------------------------


def get_access_policy(plane_db, family: str) -> dict:
    plane = _plane_key(family)
    row = plane_db.conn.execute(
        "SELECT * FROM access_policies WHERE plane = ?", (plane,)
    ).fetchone()
    if not row:
        return {"plane": plane, "mode": None, "enforcement": "enabled"}
    return {
        "plane": plane,
        "mode": row["mode"],
        "enforcement": row["enforcement"] or "enabled",
    }


def _plane_key(family: str) -> str:
    text = str(family or "").strip().lower().replace("_", "-")
    if text in ("remote", "remote-access"):
        return "remote"
    if text in ("internet", "internet-access"):
        return "internet"
    if text in ("ai", "ai-access"):
        return "ai"
    raise ControlPlaneError("Unknown access policy family: %s" % family)


def set_policy_enforcement(plane_db, family: str, enabled: bool, *, confirm: Optional[bool] = None) -> dict:
    plane = _plane_key(family)
    pol = get_access_policy(plane_db, plane)
    title = {
        "remote": "Remote Access",
        "internet": "Internet Access",
        "ai": "AI Access",
    }[plane]
    if pol["mode"] is None:
        raise ControlPlaneError(
            cli_error(
                "No %s policy is configured yet." % title
            )
        )

    def write():
        plane_db.conn.execute(
            "UPDATE access_policies SET enforcement = ?, row_version = row_version + 1, updated_at = ? WHERE plane = ?",
            ("enabled" if enabled else "disabled", utc_now_iso(), plane),
        )
        return {
            "entity": {"type": "%s-access" % plane, "id": plane, "name": plane},
            "operation": "enable" if enabled else "disable",
        }

    impact = None
    if not enabled and str(pol["enforcement"]).lower() == "enabled":
        blocking = _count_blocking_rules(plane_db, plane)
        impact = {
            "access_broadened": True,
            "access_narrowed": False,
            "before": "%s / Enforcement ENABLED / Effective blocking rules: %s" % (str(pol["mode"]).upper(), blocking),
            "after": "%s / Enforcement DISABLED / Effective result: ALLOW ALL" % str(pol["mode"]).upper(),
            "warning": "This change broadens %s." % title,
        }

    return plane_db._mutate(
        "set %s-access %s" % (plane if plane != "ai" else "ai", "enabled" if enabled else "disabled"),
        "policy enforcement",
        write,
        confirm=confirm,
        impact=impact,
    )


def _count_blocking_rules(plane_db, plane: str) -> int:
    if plane == "ai":
        return int(
            plane_db.conn.execute(
                "SELECT COUNT(*) FROM ai_policy_rules WHERE enabled = 1"
            ).fetchone()[0]
            or 0
        )
    return int(
        plane_db.conn.execute(
            "SELECT COUNT(*) FROM policy_rules WHERE plane = ? AND enabled = 1",
            (plane,),
        ).fetchone()[0]
        or 0
    )


def _access_family_title(plane: str) -> str:
    return {
        "remote": "Remote Access",
        "internet": "Internet Access",
        "ai": "AI Access",
    }[plane]


def _rule_is_enabled(plane_db, plane: str, name: str) -> bool:
    if plane == "ai":
        row = plane_db.conn.execute(
            "SELECT enabled FROM ai_policy_rules WHERE name = ? COLLATE NOCASE",
            (name,),
        ).fetchone()
    else:
        row = plane_db._get_rule(plane, name)
    return bool(row and row["enabled"])


def blacklist_last_rule_impact(
    plane_db,
    family: str,
    rule_name: str,
    *,
    disabling: bool = False,
) -> Optional[dict]:
    """Return access-broadening impact when this removes the last BLACKLIST block.

    Applies to delete or disable of the final enabled BLACKLIST rule while
    enforcement is enabled. Matches the policy disable/reset confirmation model.
    """
    plane = _plane_key(family)
    pol = get_access_policy(plane_db, plane)
    if str(pol.get("mode") or "").lower() != "blacklist":
        return None
    if str(pol.get("enforcement") or "enabled").lower() != "enabled":
        return None
    if not _rule_is_enabled(plane_db, plane, rule_name):
        return None
    enabled = _count_blocking_rules(plane_db, plane)
    if enabled != 1:
        return None
    title = _access_family_title(plane)
    action = "disabling" if disabling else "removing"
    return {
        "access_broadened": True,
        "access_narrowed": False,
        "warning": "This change broadens %s by %s the last BLACKLIST blocking Rule."
        % (title, action),
        "affected_rules": [rule_name],
        "before": "BLACKLIST / Enforcement ENABLED / Effective blocking rules: 1",
        "after": "BLACKLIST / last blocking Rule %s / Effective result: ALLOW"
        % ("disabled" if disabling else "removed"),
    }


def whitelist_last_rule_impact(
    plane_db,
    family: str,
    rule_name: str,
    *,
    disabling: bool = False,
) -> Optional[dict]:
    """Return outage/narrowing impact when this clears the last WHITELIST allow.

    Applies to delete or disable of the final enabled WHITELIST rule while
    enforcement is enabled. Effective result becomes DENY ALL; this is not
    access broadening and must not be labeled as such.
    """
    plane = _plane_key(family)
    pol = get_access_policy(plane_db, plane)
    if str(pol.get("mode") or "").lower() != "whitelist":
        return None
    if str(pol.get("enforcement") or "enabled").lower() != "enabled":
        return None
    if not _rule_is_enabled(plane_db, plane, rule_name):
        return None
    enabled = _count_blocking_rules(plane_db, plane)
    if enabled != 1:
        return None
    title = _access_family_title(plane)
    action = "disabling" if disabling else "removing"
    return {
        "access_broadened": False,
        "access_narrowed": True,
        "requires_confirmation": True,
        "warning": (
            "This change narrows %s by %s the last enabled WHITELIST Rule; "
            "effective result becomes DENY ALL."
        )
        % (title, action),
        "affected_rules": [rule_name],
        "before": "WHITELIST / Enforcement ENABLED / Effective enabled rules: 1",
        "after": "WHITELIST / last enabled Rule %s / Effective result: DENY ALL"
        % ("disabled" if disabling else "removed"),
    }


def last_enabled_rule_mutation_impact(
    plane_db,
    family: str,
    rule_name: str,
    *,
    disabling: bool = False,
) -> Optional[dict]:
    """BLACKLIST broadening or WHITELIST DENY ALL outage impact for rule mutation."""
    return blacklist_last_rule_impact(
        plane_db, family, rule_name, disabling=disabling
    ) or whitelist_last_rule_impact(
        plane_db, family, rule_name, disabling=disabling
    )


def _rule_service_public_name(plane_db, rule_id: str) -> Optional[str]:
    ref = plane_db.conn.execute(
        "SELECT ref_kind, ref_id FROM rule_service_refs WHERE rule_id = ?",
        (rule_id,),
    ).fetchone()
    if not ref:
        return None
    if ref["ref_kind"] == "service_object":
        row = plane_db.conn.execute(
            "SELECT name FROM service_objects WHERE id = ?", (ref["ref_id"],)
        ).fetchone()
        return row["name"] if row else None
    if ref["ref_kind"] == "service_group":
        row = plane_db.conn.execute(
            "SELECT name FROM service_groups WHERE id = ?", (ref["ref_id"],)
        ).fetchone()
        return row["name"] if row else None
    return None


def _selector_token_changed(current: Optional[str], desired: Optional[str]) -> bool:
    if desired is None:
        return False
    return str(current or "").strip().lower() != str(desired).strip().lower()


def _paths_changed(current: list[str], desired: Optional[list[str]]) -> bool:
    if desired is None:
        return False
    return {str(p).strip().lower() for p in (current or [])} != {
        str(p).strip().lower() for p in desired
    }


def access_rule_update_security_impact(
    plane_db,
    family: str,
    rule_name: str,
    *,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    service: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Optional[dict]:
    """Security impact for Remote/Internet Rule mutation (enable / selector change).

    Covers DENY→ALLOW broadening from enabling a WHITELIST Rule or changing
    selectors on an enabled BLACKLIST Rule. Disable/delete last-rule cases remain
    in last_enabled_rule_mutation_impact().
    """
    plane = _plane_key(family)
    if plane == "ai":
        return None
    existing = plane_db._get_rule(plane, rule_name)
    if existing is None:
        return None
    pol = get_access_policy(plane_db, plane)
    mode = str(pol.get("mode") or "").lower()
    if str(pol.get("enforcement") or "enabled").lower() != "enabled":
        return None
    title = _access_family_title(plane)
    was_enabled = bool(existing["enabled"])
    will_enable = (enabled is True) and not was_enabled
    will_disable = (enabled is False) and was_enabled
    if will_disable:
        return None

    view = plane_db._rule_view(existing)
    cur_src = (view.get("sources") or [None])[0]
    cur_dst = (view.get("destinations") or [None])[0]
    cur_svc = _rule_service_public_name(plane_db, existing["id"])
    selector_changed = any(
        (
            _selector_token_changed(cur_src, source),
            _selector_token_changed(cur_dst, destination),
            _selector_token_changed(cur_svc, service),
        )
    )
    effectively_enabled = was_enabled if enabled is None else bool(enabled)

    if mode == "whitelist" and will_enable:
        return {
            "access_broadened": True,
            "access_narrowed": False,
            "requires_confirmation": True,
            "warning": (
                "This change broadens %s by enabling WHITELIST Rule '%s'."
                % (title, rule_name)
            ),
            "affected_rules": [rule_name],
            "before": "WHITELIST / Rule disabled / matching flows DENY",
            "after": "WHITELIST / Rule enabled / matching flows ALLOW",
        }

    if mode == "blacklist" and effectively_enabled and selector_changed:
        return {
            "access_broadened": True,
            "access_narrowed": False,
            "requires_confirmation": True,
            "warning": (
                "This change may broaden %s by changing selectors on enabled "
                "BLACKLIST Rule '%s'." % (title, rule_name)
            ),
            "affected_rules": [rule_name],
            "before": "BLACKLIST / enabled Rule selectors block matching flows",
            "after": (
                "BLACKLIST / changed selectors / previously blocked flows may ALLOW"
            ),
        }

    if mode == "whitelist" and effectively_enabled and selector_changed:
        # Deterministic broaden when the new source/destination/service leaf set
        # is not a subset of the previous match set; otherwise stay silent.
        try:
            broaden = False
            if source is not None and _selector_token_changed(cur_src, source):
                _is_g, before_leaves = _network_test_leaves(
                    plane_db, str(cur_src), role="source"
                )
                _is_g, after_leaves = _network_test_leaves(
                    plane_db, str(source), role="source"
                )
                if not set(x.lower() for x in after_leaves).issubset(
                    set(x.lower() for x in before_leaves)
                ):
                    broaden = True
            if destination is not None and _selector_token_changed(cur_dst, destination):
                _is_g, before_leaves = _network_test_leaves(
                    plane_db, str(cur_dst), role="destination"
                )
                _is_g, after_leaves = _network_test_leaves(
                    plane_db, str(destination), role="destination"
                )
                if not set(x.lower() for x in after_leaves).issubset(
                    set(x.lower() for x in before_leaves)
                ):
                    broaden = True
            if service is not None and _selector_token_changed(cur_svc, service):
                _is_g, before_leaves = _service_test_leaves(plane_db, str(cur_svc))
                _is_g, after_leaves = _service_test_leaves(plane_db, str(service))
                if not set(x.lower() for x in after_leaves).issubset(
                    set(x.lower() for x in before_leaves)
                ):
                    broaden = True
            if broaden:
                return {
                    "access_broadened": True,
                    "access_narrowed": False,
                    "requires_confirmation": True,
                    "warning": (
                        "This change broadens %s by expanding selectors on "
                        "enabled WHITELIST Rule '%s'." % (title, rule_name)
                    ),
                    "affected_rules": [rule_name],
                    "before": "WHITELIST / enabled Rule match set",
                    "after": "WHITELIST / expanded match set / additional flows ALLOW",
                }
        except ControlPlaneError:
            # Fail closed: unknown/ambiguous selector change requires confirmation.
            return {
                "access_broadened": True,
                "access_narrowed": False,
                "requires_confirmation": True,
                "warning": (
                    "This change may broaden %s by changing selectors on "
                    "enabled WHITELIST Rule '%s'." % (title, rule_name)
                ),
                "affected_rules": [rule_name],
                "before": "WHITELIST / enabled Rule match set",
                "after": "WHITELIST / changed selectors / additional flows may ALLOW",
            }
    return None


def ai_access_rule_update_security_impact(
    plane_db,
    rule_name: str,
    *,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    permission: Optional[str] = None,
    paths: Optional[list[str]] = None,
    enabled: Optional[bool] = None,
) -> Optional[dict]:
    """Security impact for AI Access Rule mutation (enable / selector change)."""
    existing = plane_db.conn.execute(
        "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (rule_name,)
    ).fetchone()
    if existing is None:
        return None
    pol = get_access_policy(plane_db, "ai")
    mode = str(pol.get("mode") or "").lower()
    if str(pol.get("enforcement") or "enabled").lower() != "enabled":
        return None
    title = _access_family_title("ai")
    was_enabled = bool(existing["enabled"])
    will_enable = (enabled is True) and not was_enabled
    will_disable = (enabled is False) and was_enabled
    if will_disable:
        return None

    # Local import-safe view (mirrors bundle helper fields).
    principal = None
    if existing["source_identity_id"]:
        principal = plane_db.conn.execute(
            "SELECT name FROM ai_principals WHERE id = ?",
            (existing["source_identity_id"],),
        ).fetchone()
    cur_src = principal["name"] if principal else None
    cur_dst = None
    dkind = existing["destination_ref_kind"]
    if dkind == "object":
        row = plane_db.conn.execute(
            "SELECT name FROM objects WHERE id = ?", (existing["destination_ref_id"],)
        ).fetchone()
        cur_dst = row["name"] if row else None
    elif dkind == "group":
        row = plane_db.conn.execute(
            "SELECT name FROM object_groups WHERE id = ?",
            (existing["destination_ref_id"],),
        ).fetchone()
        cur_dst = row["name"] if row else None
    cur_perm = None
    pkind = existing["permission_ref_kind"]
    if pkind == "permission_object":
        row = plane_db.conn.execute(
            "SELECT name FROM permission_objects WHERE id = ?",
            (existing["permission_ref_id"],),
        ).fetchone()
        cur_perm = row["name"] if row else None
    elif pkind == "permission_group":
        row = plane_db.conn.execute(
            "SELECT name FROM permission_groups WHERE id = ?",
            (existing["permission_ref_id"],),
        ).fetchone()
        cur_perm = row["name"] if row else None
    cur_paths = list_ai_policy_path_scopes(plane_db, existing["name"])

    selector_changed = any(
        (
            _selector_token_changed(cur_src, source),
            _selector_token_changed(cur_dst, destination),
            _selector_token_changed(cur_perm, permission),
            _paths_changed(cur_paths, paths),
        )
    )
    effectively_enabled = was_enabled if enabled is None else bool(enabled)

    if mode == "whitelist" and will_enable:
        return {
            "access_broadened": True,
            "access_narrowed": False,
            "requires_confirmation": True,
            "warning": (
                "This change broadens %s by enabling WHITELIST Rule '%s'."
                % (title, rule_name)
            ),
            "affected_rules": [rule_name],
            "before": "WHITELIST / Rule disabled / matching operations DENY",
            "after": "WHITELIST / Rule enabled / matching operations ALLOW",
        }

    if mode == "blacklist" and effectively_enabled and selector_changed:
        return {
            "access_broadened": True,
            "access_narrowed": False,
            "requires_confirmation": True,
            "warning": (
                "This change may broaden %s by changing selectors on enabled "
                "BLACKLIST Rule '%s'." % (title, rule_name)
            ),
            "affected_rules": [rule_name],
            "before": "BLACKLIST / enabled Rule selectors block matching operations",
            "after": (
                "BLACKLIST / changed selectors / previously denied operations may ALLOW"
            ),
        }

    if mode == "whitelist" and effectively_enabled and selector_changed:
        return {
            "access_broadened": True,
            "access_narrowed": False,
            "requires_confirmation": True,
            "warning": (
                "This change may broaden %s by changing selectors on enabled "
                "WHITELIST Rule '%s'." % (title, rule_name)
            ),
            "affected_rules": [rule_name],
            "before": "WHITELIST / enabled Rule match set",
            "after": "WHITELIST / changed selectors / additional operations may ALLOW",
        }
    return None


def _policy_restrictiveness_rank(mode: Optional[str], enforcement: str) -> int:
    """Higher rank = more restrictive default posture for unmatched traffic."""
    if mode is None:
        return 0
    if str(enforcement or "enabled").lower() == "disabled":
        return 0
    mode_l = str(mode).lower()
    if mode_l == "blacklist":
        return 1
    if mode_l == "whitelist":
        return 2
    return 0


def _policy_effective_label(mode: Optional[str], enforcement: str, enabled_rules: int) -> str:
    if mode is None:
        return "No Policy / unmatched ALLOW"
    enf = str(enforcement or "enabled").lower()
    mode_u = str(mode).upper()
    if enf == "disabled":
        return "%s / Enforcement DISABLED / ALLOW ALL" % mode_u
    unmatched = "DENY" if mode_u == "WHITELIST" else "ALLOW"
    return "%s / Enforcement ENABLED / %s enabled Rule(s) / unmatched %s" % (
        mode_u,
        enabled_rules,
        unmatched,
    )


def _ref_public_name(conn: sqlite3.Connection, kind: str, ref_id: str) -> str:
    kind_l = str(kind or "").lower()
    table = {
        "object": "objects",
        "group": "object_groups",
        "service_object": "service_objects",
        "service_group": "service_groups",
        "permission_object": "permission_objects",
        "permission_group": "permission_groups",
    }.get(kind_l)
    if not table:
        return "%s:%s" % (kind_l or "?", ref_id)
    row = conn.execute(
        "SELECT name FROM %s WHERE id = ?" % table, (ref_id,)
    ).fetchone()
    if row is None:
        return "%s:%s" % (kind_l, ref_id)
    return str(row["name"] if isinstance(row, sqlite3.Row) else row[0])


def _unresolvable_semantic(kind: str, ref_id: str, reason: str = "missing") -> str:
    """Fail-closed marker when referenced semantics cannot be expanded."""
    return "UNRESOLVABLE:%s:%s:%s" % (kind or "?", ref_id or "?", reason)


def _object_value_semantics(conn: sqlite3.Connection, object_id: str) -> list[str]:
    """Canonical leaf semantics for one Network Object (type + normalized values)."""
    obj = conn.execute(
        "SELECT id, type FROM objects WHERE id = ?", (object_id,)
    ).fetchone()
    if obj is None:
        return [_unresolvable_semantic("object", object_id)]
    otype = str(obj["type"] or "").strip().lower() or "?"
    if otype == "managed_endpoint":
        addrs = [
            str(r["address"])
            for r in conn.execute(
                "SELECT address FROM endpoint_addresses "
                "WHERE endpoint_object_id = ? ORDER BY address COLLATE NOCASE",
                (object_id,),
            )
        ]
        if not addrs:
            ep = conn.execute(
                "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                (object_id,),
            ).fetchone()
            client = str(ep["client_id"]) if ep and ep["client_id"] else "-"
            return ["managed_endpoint:client=%s" % client]
        return ["managed_endpoint:%s" % a for a in addrs]
    vals = [
        str(r["normalized"] if r["normalized"] is not None else r["value"])
        for r in conn.execute(
            "SELECT value, normalized FROM object_values "
            "WHERE object_id = ? ORDER BY COALESCE(normalized, value) COLLATE NOCASE",
            (object_id,),
        )
    ]
    if not vals:
        return ["%s:<empty>" % otype]
    return ["%s:%s" % (otype, v) for v in vals]


def _expand_network_group_semantics(
    conn: sqlite3.Connection, group_id: str, seen: Optional[set] = None
) -> list[str]:
    seen = set() if seen is None else seen
    if group_id in seen:
        return [_unresolvable_semantic("group", group_id, "cycle")]
    seen.add(group_id)
    grp = conn.execute(
        "SELECT id FROM object_groups WHERE id = ?", (group_id,)
    ).fetchone()
    if grp is None:
        return [_unresolvable_semantic("group", group_id)]
    out: list[str] = []
    for mem in conn.execute(
        "SELECT member_kind, member_id FROM object_group_members "
        "WHERE group_id = ? ORDER BY member_kind, member_id",
        (group_id,),
    ):
        kind = str(mem["member_kind"] or "").lower()
        mid = mem["member_id"]
        if kind == "object":
            out.extend(_object_value_semantics(conn, mid))
        elif kind == "group":
            out.extend(_expand_network_group_semantics(conn, mid, seen))
        else:
            out.append(_unresolvable_semantic(kind or "member", mid, "unknown-kind"))
    return sorted(set(out), key=lambda s: s.lower())


def _semantic_network_ref(conn: sqlite3.Connection, kind: str, ref_id: str) -> str:
    kind_l = str(kind or "").lower()
    if kind_l == "object":
        leaves = _object_value_semantics(conn, ref_id)
        return "{%s}" % ",".join(leaves)
    if kind_l == "group":
        leaves = _expand_network_group_semantics(conn, ref_id, set())
        return "{%s}" % ",".join(leaves)
    return _unresolvable_semantic(kind_l, ref_id, "unknown-kind")


def _service_object_semantics(conn: sqlite3.Connection, object_id: str) -> list[str]:
    sobj = conn.execute(
        "SELECT type, port FROM service_objects WHERE id = ?", (object_id,)
    ).fetchone()
    if sobj is None:
        return [_unresolvable_semantic("service_object", object_id)]
    return ["%s:%s" % (str(sobj["type"]).lower(), int(sobj["port"]))]


def _expand_service_group_semantics(conn: sqlite3.Connection, group_id: str) -> list[str]:
    grp = conn.execute(
        "SELECT id FROM service_groups WHERE id = ?", (group_id,)
    ).fetchone()
    if grp is None:
        return [_unresolvable_semantic("service_group", group_id)]
    out: list[str] = []
    for member in conn.execute(
        "SELECT s.id AS id FROM service_group_members m "
        "JOIN service_objects s ON s.id = m.service_object_id "
        "WHERE m.group_id = ? ORDER BY s.name COLLATE NOCASE",
        (group_id,),
    ):
        out.extend(_service_object_semantics(conn, member["id"]))
    return sorted(set(out), key=lambda s: s.lower())


def _semantic_service_ref(conn: sqlite3.Connection, kind: str, ref_id: str) -> str:
    kind_l = str(kind or "").lower()
    if kind_l == "service_object":
        return "{%s}" % ",".join(_service_object_semantics(conn, ref_id))
    if kind_l == "service_group":
        return "{%s}" % ",".join(_expand_service_group_semantics(conn, ref_id))
    return _unresolvable_semantic(kind_l, ref_id, "unknown-kind")


def _permission_object_semantics(conn: sqlite3.Connection, object_id: str) -> list[str]:
    obj = conn.execute(
        "SELECT id FROM permission_objects WHERE id = ?", (object_id,)
    ).fetchone()
    if obj is None:
        return [_unresolvable_semantic("permission_object", object_id)]
    perms = [
        str(r["permission"]).lower()
        for r in conn.execute(
            "SELECT permission FROM permission_object_members "
            "WHERE permission_object_id = ? ORDER BY permission COLLATE NOCASE",
            (object_id,),
        )
    ]
    if not perms:
        return ["permission:<empty>"]
    return perms


def _expand_permission_group_semantics(conn: sqlite3.Connection, group_id: str) -> list[str]:
    grp = conn.execute(
        "SELECT id FROM permission_groups WHERE id = ?", (group_id,)
    ).fetchone()
    if grp is None:
        return [_unresolvable_semantic("permission_group", group_id)]
    out: list[str] = []
    for member in conn.execute(
        "SELECT permission_object_id FROM permission_group_members "
        "WHERE group_id = ? ORDER BY permission_object_id",
        (group_id,),
    ):
        out.extend(_permission_object_semantics(conn, member["permission_object_id"]))
    return sorted(set(out), key=lambda s: s.lower())


def _semantic_permission_ref(conn: sqlite3.Connection, kind: str, ref_id: str) -> str:
    kind_l = str(kind or "").lower()
    if kind_l == "permission_object":
        return "{%s}" % ",".join(_permission_object_semantics(conn, ref_id))
    if kind_l == "permission_group":
        return "{%s}" % ",".join(_expand_permission_group_semantics(conn, ref_id))
    return _unresolvable_semantic(kind_l, ref_id, "unknown-kind")


def _enabled_rule_fingerprints(conn: sqlite3.Connection, plane: str) -> set[str]:
    """Effective-semantics fingerprints of enabled Rules for restore comparison.

    Public reference names alone are insufficient: same-name Object/Group/Service
    mutations change effective match sets and must not evade confirmation.
    Unresolvable refs fingerprint as UNRESOLVABLE markers (fail closed).
    """
    out: set[str] = set()
    if plane == "ai":
        rows = conn.execute(
            "SELECT * FROM ai_policy_rules WHERE enabled = 1 ORDER BY name COLLATE NOCASE"
        ).fetchall()
        for row in rows:
            src = "-"
            if row["source_identity_id"]:
                principal = conn.execute(
                    "SELECT name FROM ai_principals WHERE id = ?",
                    (row["source_identity_id"],),
                ).fetchone()
                src = str(principal["name"] if principal else row["source_identity_id"])
            dst = "-"
            if row["destination_ref_kind"] and row["destination_ref_id"]:
                dst = _semantic_network_ref(
                    conn, row["destination_ref_kind"], row["destination_ref_id"]
                )
            perm = "-"
            if row["permission_ref_kind"] and row["permission_ref_id"]:
                perm = _semantic_permission_ref(
                    conn, row["permission_ref_kind"], row["permission_ref_id"]
                )
            paths = []
            try:
                for prow in conn.execute(
                    "SELECT pattern FROM ai_policy_path_scopes WHERE rule_id = ? "
                    "ORDER BY pattern COLLATE NOCASE",
                    (row["id"],),
                ):
                    paths.append(str(prow["pattern"]))
            except sqlite3.Error:
                paths = []
            out.add(
                "ai|%s|src=%s|dst=%s|perm=%s|paths=%s"
                % (row["name"], src, dst, perm, ",".join(paths) or "-")
            )
        return out

    rows = conn.execute(
        "SELECT * FROM policy_rules WHERE plane = ? AND enabled = 1 "
        "ORDER BY name COLLATE NOCASE",
        (plane,),
    ).fetchall()
    for row in rows:
        sources = []
        for s in conn.execute(
            "SELECT ref_kind, ref_id FROM rule_sources WHERE rule_id = ? "
            "ORDER BY ref_kind, ref_id",
            (row["id"],),
        ):
            sources.append(_semantic_network_ref(conn, s["ref_kind"], s["ref_id"]))
        destinations = []
        for s in conn.execute(
            "SELECT ref_kind, ref_id FROM rule_destinations WHERE rule_id = ? "
            "ORDER BY ref_kind, ref_id",
            (row["id"],),
        ):
            destinations.append(_semantic_network_ref(conn, s["ref_kind"], s["ref_id"]))
        services = []
        refs = list(
            conn.execute(
                "SELECT ref_kind, ref_id FROM rule_service_refs WHERE rule_id = ? "
                "ORDER BY ref_kind, ref_id",
                (row["id"],),
            )
        )
        for s in refs:
            services.append(_semantic_service_ref(conn, s["ref_kind"], s["ref_id"]))
        if not services:
            for s in conn.execute(
                "SELECT protocol, port FROM rule_services "
                "WHERE rule_id = ? ORDER BY protocol, port",
                (row["id"],),
            ):
                services.append("{%s:%s}" % (s["protocol"], s["port"]))
        out.add(
            "%s|%s|src=%s|dst=%s|svc=%s"
            % (
                plane,
                row["name"],
                ",".join(sources) or "-",
                ",".join(destinations) or "-",
                ",".join(services) or "-",
            )
        )
    return out


def _access_policy_snapshot(conn: sqlite3.Connection, plane: str) -> dict:
    row = conn.execute(
        "SELECT mode, enforcement FROM access_policies WHERE plane = ?", (plane,)
    ).fetchone()
    mode = None
    enforcement = "enabled"
    if row is not None:
        mode = row["mode"]
        enforcement = row["enforcement"] or "enabled"
    rules = _enabled_rule_fingerprints(conn, plane)
    return {
        "plane": plane,
        "mode": mode,
        "enforcement": enforcement,
        "rank": _policy_restrictiveness_rank(mode, enforcement),
        "rules": rules,
        "label": _policy_effective_label(mode, enforcement, len(rules)),
    }


def restore_access_security_impact(
    live_conn: sqlite3.Connection,
    candidate_conn: sqlite3.Connection,
) -> Optional[dict]:
    """Security impact for Server DR restore across Remote / Internet / AI Access.

    Requires confirmation when restore broadens access (including restrictive
    policy → No Policy / enforcement disabled) or when it causes DENY ALL
    outage-safety narrowing, matching Apply conventions.
    """
    broadened_families: list[str] = []
    narrowed_families: list[str] = []
    before_lines: list[str] = []
    after_lines: list[str] = []

    for plane in POLICY_PLANES:
        title = _access_family_title(plane)
        live = _access_policy_snapshot(live_conn, plane)
        cand = _access_policy_snapshot(candidate_conn, plane)
        before_lines.append("%s: %s" % (title, live["label"]))
        after_lines.append("%s: %s" % (title, cand["label"]))

        live_rules: set[str] = live["rules"]
        cand_rules: set[str] = cand["rules"]
        family_broaden = False
        family_narrow = False

        if cand["rank"] < live["rank"]:
            family_broaden = True
        elif cand["rank"] > live["rank"]:
            family_narrow = True
        elif live["rank"] == 0 and cand["rank"] == 0:
            # Both permissive (No Policy or enforcement disabled): no confirm.
            pass
        elif live["mode"] == "blacklist" and cand["mode"] == "blacklist":
            # Fewer / weaker blocks broaden; added blocks narrow.
            if not live_rules.issubset(cand_rules):
                family_broaden = True
            if not cand_rules.issubset(live_rules):
                family_narrow = True
        elif live["mode"] == "whitelist" and cand["mode"] == "whitelist":
            # Expanded allow set broadens; shrunk allow set narrows (DENY ALL risk).
            if not cand_rules.issubset(live_rules):
                family_broaden = True
            if not live_rules.issubset(cand_rules):
                family_narrow = True
        elif live_rules != cand_rules or live["mode"] != cand["mode"]:
            # Fail closed on ambiguous mode/rule transitions.
            family_broaden = True
            family_narrow = True

        # WHITELIST with zero enabled rules is DENY ALL outage.
        if (
            cand["mode"] == "whitelist"
            and str(cand["enforcement"]).lower() == "enabled"
            and not cand_rules
            and (
                live["mode"] != "whitelist"
                or live_rules
                or str(live["enforcement"]).lower() != "enabled"
            )
        ):
            family_narrow = True

        if family_broaden:
            broadened_families.append(title)
        if family_narrow:
            narrowed_families.append(title)

    if not broadened_families and not narrowed_families:
        return None

    warning_bits = []
    if broadened_families:
        warning_bits.append(
            "This restore broadens %s." % (", ".join(broadened_families))
        )
    if narrowed_families:
        warning_bits.append(
            "This restore narrows %s (may cause DENY ALL / outage)."
            % (", ".join(narrowed_families))
        )

    return {
        "access_broadened": bool(broadened_families),
        "access_narrowed": bool(narrowed_families),
        "requires_confirmation": True,
        "warning": " ".join(warning_bits),
        "families_broadened": broadened_families,
        "families_narrowed": narrowed_families,
        "before": "\n  ".join(before_lines),
        "after": "\n  ".join(after_lines),
        "kind": "restore-access",
    }


def format_restore_access_security_impact(impact: dict) -> str:
    """Public-safe restore security-impact confirmation text."""
    lines = [
        "WARNING:",
        str(impact.get("warning") or "This restore changes access policy posture."),
        "",
        "Access broadened: %s" % ("YES" if impact.get("access_broadened") else "NO"),
        "Access narrowed: %s" % ("YES" if impact.get("access_narrowed") else "NO"),
        "",
        "Before:",
        "  %s" % (impact.get("before") or "-"),
        "",
        "After:",
        "  %s" % (impact.get("after") or "-"),
        "",
        "Continue? [y/N]:",
    ]
    return "\n".join(lines)


def _policy_mode_if_enforced(plane_db, family: str) -> Optional[str]:
    pol = get_access_policy(plane_db, family)
    if str(pol.get("enforcement") or "enabled").lower() != "enabled":
        return None
    mode = str(pol.get("mode") or "").lower()
    return mode if mode in ("blacklist", "whitelist") else None


def _append_unique_rule_ref(
    out: list[dict], *, plane: str, name: str, mode: str
) -> None:
    key = (plane, str(name).lower())
    if any((r["plane"], str(r["name"]).lower()) == key for r in out):
        return
    out.append(
        {
            "plane": plane,
            "name": name,
            "mode": mode,
            "title": _access_family_title(plane),
        }
    )


def _enabled_rules_referencing_network_object(plane_db, name: str) -> list[dict]:
    """Enabled Remote/Internet/AI rules that resolve through this Network Object."""
    obj = plane_db.get_object(name)
    if obj is None:
        return []
    out: list[dict] = []
    for table in ("rule_sources", "rule_destinations"):
        for row in plane_db.conn.execute(
            "SELECT r.plane, r.name FROM %s s "
            "JOIN policy_rules r ON r.id = s.rule_id "
            "WHERE s.ref_kind = 'object' AND s.ref_id = ? AND r.enabled = 1" % table,
            (obj["id"],),
        ):
            mode = _policy_mode_if_enforced(plane_db, row["plane"])
            if mode:
                _append_unique_rule_ref(
                    out, plane=row["plane"], name=row["name"], mode=mode
                )
    # Via Network Groups that contain this object (direct membership).
    for grp in plane_db.conn.execute(
        "SELECT g.name FROM object_group_members m "
        "JOIN object_groups g ON g.id = m.group_id "
        "WHERE m.member_kind = 'object' AND m.member_id = ?",
        (obj["id"],),
    ):
        for ref in _enabled_rules_referencing_network_group(plane_db, grp["name"]):
            _append_unique_rule_ref(
                out, plane=ref["plane"], name=ref["name"], mode=ref["mode"]
            )
    # AI destination object refs (any origin).
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_policy_rules "
        "WHERE enabled = 1 AND destination_ref_kind = 'object' "
        "AND destination_ref_id = ?",
        (obj["id"],),
    ):
        mode = _policy_mode_if_enforced(plane_db, "ai")
        if mode:
            _append_unique_rule_ref(out, plane="ai", name=row["name"], mode=mode)
    return out


def _enabled_rules_referencing_network_group(
    plane_db, name: str, *, _seen: Optional[set] = None
) -> list[dict]:
    key = str(name).strip().lower()
    seen = _seen if _seen is not None else set()
    if key in seen:
        return []
    seen.add(key)
    grp = plane_db.get_object_group(name)
    if grp is None:
        return []
    out: list[dict] = []
    for table in ("rule_sources", "rule_destinations"):
        for row in plane_db.conn.execute(
            "SELECT r.plane, r.name FROM %s s "
            "JOIN policy_rules r ON r.id = s.rule_id "
            "WHERE s.ref_kind = 'group' AND s.ref_id = ? AND r.enabled = 1" % table,
            (grp["id"],),
        ):
            mode = _policy_mode_if_enforced(plane_db, row["plane"])
            if mode:
                _append_unique_rule_ref(
                    out, plane=row["plane"], name=row["name"], mode=mode
                )
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_policy_rules "
        "WHERE enabled = 1 AND destination_ref_kind = 'group' "
        "AND destination_ref_id = ?",
        (grp["id"],),
    ):
        mode = _policy_mode_if_enforced(plane_db, "ai")
        if mode:
            _append_unique_rule_ref(out, plane="ai", name=row["name"], mode=mode)
    # Parent groups that include this group as a member.
    for parent in plane_db.conn.execute(
        "SELECT g.name FROM object_group_members m "
        "JOIN object_groups g ON g.id = m.group_id "
        "WHERE m.member_kind = 'group' AND m.member_id = ?",
        (grp["id"],),
    ):
        for ref in _enabled_rules_referencing_network_group(
            plane_db, parent["name"], _seen=seen
        ):
            _append_unique_rule_ref(
                out, plane=ref["plane"], name=ref["name"], mode=ref["mode"]
            )
    return out


def _enabled_rules_referencing_service_object(plane_db, name: str) -> list[dict]:
    obj = get_service_object(plane_db, name)
    if obj is None:
        return []
    out: list[dict] = []
    for row in plane_db.conn.execute(
        "SELECT r.plane, r.name FROM rule_service_refs x "
        "JOIN policy_rules r ON r.id = x.rule_id "
        "WHERE x.ref_kind = 'service_object' AND x.ref_id = ? AND r.enabled = 1",
        (obj["id"],),
    ):
        mode = _policy_mode_if_enforced(plane_db, row["plane"])
        if mode:
            _append_unique_rule_ref(
                out, plane=row["plane"], name=row["name"], mode=mode
            )
    for grp in plane_db.conn.execute(
        "SELECT g.name FROM service_group_members m "
        "JOIN service_groups g ON g.id = m.group_id "
        "WHERE m.service_object_id = ?",
        (obj["id"],),
    ):
        for ref in _enabled_rules_referencing_service_group(plane_db, grp["name"]):
            _append_unique_rule_ref(
                out, plane=ref["plane"], name=ref["name"], mode=ref["mode"]
            )
    return out


def _enabled_rules_referencing_service_group(plane_db, name: str) -> list[dict]:
    grp = get_service_group(plane_db, name)
    if grp is None:
        return []
    out: list[dict] = []
    for row in plane_db.conn.execute(
        "SELECT r.plane, r.name FROM rule_service_refs x "
        "JOIN policy_rules r ON r.id = x.rule_id "
        "WHERE x.ref_kind = 'service_group' AND x.ref_id = ? AND r.enabled = 1",
        (grp["id"],),
    ):
        mode = _policy_mode_if_enforced(plane_db, row["plane"])
        if mode:
            _append_unique_rule_ref(
                out, plane=row["plane"], name=row["name"], mode=mode
            )
    return out


def _enabled_rules_referencing_permission_object(plane_db, name: str) -> list[dict]:
    obj = get_permission_object(plane_db, name)
    if obj is None:
        return []
    out: list[dict] = []
    mode = _policy_mode_if_enforced(plane_db, "ai")
    if not mode:
        return out
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_policy_rules "
        "WHERE enabled = 1 AND permission_ref_kind = 'permission_object' "
        "AND permission_ref_id = ?",
        (obj["id"],),
    ):
        _append_unique_rule_ref(out, plane="ai", name=row["name"], mode=mode)
    for grp in plane_db.conn.execute(
        "SELECT g.name FROM permission_group_members m "
        "JOIN permission_groups g ON g.id = m.group_id "
        "WHERE m.permission_object_id = ?",
        (obj["id"],),
    ):
        for ref in _enabled_rules_referencing_permission_group(plane_db, grp["name"]):
            _append_unique_rule_ref(
                out, plane=ref["plane"], name=ref["name"], mode=ref["mode"]
            )
    return out


def _enabled_rules_referencing_permission_group(plane_db, name: str) -> list[dict]:
    grp = get_permission_group(plane_db, name)
    if grp is None:
        return []
    out: list[dict] = []
    mode = _policy_mode_if_enforced(plane_db, "ai")
    if not mode:
        return out
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_policy_rules "
        "WHERE enabled = 1 AND permission_ref_kind = 'permission_group' "
        "AND permission_ref_id = ?",
        (grp["id"],),
    ):
        _append_unique_rule_ref(out, plane="ai", name=row["name"], mode=mode)
    return out


def _member_sets_equal(before: list[str], after: list[str]) -> bool:
    return {str(x).strip().lower() for x in before} == {
        str(x).strip().lower() for x in after
    }


def _member_set_expanded(before: list[str], after: list[str]) -> bool:
    b = {str(x).strip().lower() for x in before}
    a = {str(x).strip().lower() for x in after}
    return not a.issubset(b)


def _member_set_shrunk(before: list[str], after: list[str]) -> bool:
    b = {str(x).strip().lower() for x in before}
    a = {str(x).strip().lower() for x in after}
    return not b.issubset(a)


def _referenced_selector_impact_from_rules(
    refs: list[dict],
    *,
    resource_label: str,
    resource_name: str,
    blacklist_broadens: bool,
    whitelist_broadens: bool,
) -> Optional[dict]:
    if not refs:
        return None
    if not blacklist_broadens and not whitelist_broadens:
        return None
    affected = []
    families = []
    for ref in refs:
        mode = ref["mode"]
        if mode == "blacklist" and blacklist_broadens:
            affected.append("%s:%s" % (ref["plane"], ref["name"]))
            families.append(ref["title"])
        elif mode == "whitelist" and whitelist_broadens:
            affected.append("%s:%s" % (ref["plane"], ref["name"]))
            families.append(ref["title"])
    if not affected:
        return None
    family_text = ", ".join(sorted(set(families)))
    return {
        "access_broadened": True,
        "access_narrowed": False,
        "requires_confirmation": True,
        "warning": (
            "This change may broaden %s by mutating referenced %s '%s' "
            "used by enabled Access Rule(s)."
            % (family_text, resource_label, resource_name)
        ),
        "affected_rules": affected,
        "before": "enabled Rule(s) reference current selector definition",
        "after": "mutated selector definition / previously denied flows may ALLOW",
    }


def referenced_selector_mutation_security_impact(
    plane_db,
    *,
    kind: str,
    name: str,
    value: Optional[str] = None,
    members: Optional[list[str]] = None,
    type: Optional[str] = None,
    port: Optional[int] = None,
    permissions: Optional[list[str]] = None,
) -> Optional[dict]:
    """Security impact when mutating reusable selectors referenced by enabled Rules.

    BLACKLIST: any semantic shrink/replace of a referenced selector requires
    confirmation (conservative when exact subset proof is impractical).
    WHITELIST: confirmation only when the effective match set expands.
    Semantic NO CHANGE returns None.
    """
    kind = str(kind or "").strip().lower()
    name = str(name or "").strip()
    if not name:
        return None

    if kind == "network-object":
        existing = plane_db.get_object(name)
        if existing is None or value is None:
            return None
        from drlink_control_plane import normalize_object_value

        current_vals = plane_db._object_values(existing["id"])
        try:
            desired = normalize_object_value(existing["type"], value)
        except ControlPlaneError:
            return None
        if current_vals[:1] == [desired]:
            return None
        refs = _enabled_rules_referencing_network_object(plane_db, name)
        # Value replace changes the concrete match leaf for both modes.
        return _referenced_selector_impact_from_rules(
            refs,
            resource_label="Network Object",
            resource_name=name,
            blacklist_broadens=True,
            whitelist_broadens=True,
        )

    if kind == "network-group":
        existing = plane_db.get_object_group(name)
        if existing is None or members is None:
            return None
        current = [
            str(m["name"])
            for m in plane_db._expand_group_members(existing["id"], set())
        ]
        desired = [str(m) for m in members]
        if _member_sets_equal(current, desired):
            return None
        refs = _enabled_rules_referencing_network_group(plane_db, name)
        return _referenced_selector_impact_from_rules(
            refs,
            resource_label="Network Group",
            resource_name=name,
            # Conservative: any membership change on enabled BLACKLIST selectors.
            blacklist_broadens=True,
            whitelist_broadens=_member_set_expanded(current, desired),
        )

    if kind == "service-object":
        existing = get_service_object(plane_db, name)
        if existing is None or port is None:
            return None
        stype = str(type or existing["type"]).strip().lower()
        if str(existing["type"]) == stype and int(existing["port"]) == int(port):
            return None
        refs = _enabled_rules_referencing_service_object(plane_db, name)
        return _referenced_selector_impact_from_rules(
            refs,
            resource_label="Service Object",
            resource_name=name,
            blacklist_broadens=True,
            whitelist_broadens=True,
        )

    if kind == "service-group":
        existing = get_service_group(plane_db, name)
        if existing is None or members is None:
            return None
        current = [
            r["name"]
            for r in plane_db.conn.execute(
                "SELECT s.name FROM service_group_members m "
                "JOIN service_objects s ON s.id = m.service_object_id "
                "WHERE m.group_id = ?",
                (existing["id"],),
            )
        ]
        desired = [str(m) for m in members]
        if _member_sets_equal(current, desired):
            return None
        refs = _enabled_rules_referencing_service_group(plane_db, name)
        return _referenced_selector_impact_from_rules(
            refs,
            resource_label="Service Group",
            resource_name=name,
            blacklist_broadens=True,
            whitelist_broadens=_member_set_expanded(current, desired),
        )

    if kind == "permission-object":
        existing = get_permission_object(plane_db, name)
        if existing is None or permissions is None:
            return None
        current = [
            r["permission"]
            for r in plane_db.conn.execute(
                "SELECT permission FROM permission_object_members "
                "WHERE permission_object_id = ?",
                (existing["id"],),
            )
        ]
        desired = [str(p).strip().lower() for p in permissions]
        if _member_sets_equal(current, desired):
            return None
        refs = _enabled_rules_referencing_permission_object(plane_db, name)
        return _referenced_selector_impact_from_rules(
            refs,
            resource_label="Permission Object",
            resource_name=name,
            # Conservative: any permission-list change on enabled BLACKLIST selectors.
            blacklist_broadens=True,
            whitelist_broadens=_member_set_expanded(current, desired),
        )

    if kind == "permission-group":
        existing = get_permission_group(plane_db, name)
        if existing is None or members is None:
            return None
        current = [
            r["name"]
            for r in plane_db.conn.execute(
                "SELECT p.name FROM permission_group_members m "
                "JOIN permission_objects p ON p.id = m.permission_object_id "
                "WHERE m.group_id = ?",
                (existing["id"],),
            )
        ]
        desired = [str(m) for m in members]
        if _member_sets_equal(current, desired):
            return None
        refs = _enabled_rules_referencing_permission_group(plane_db, name)
        return _referenced_selector_impact_from_rules(
            refs,
            resource_label="Permission Group",
            resource_name=name,
            blacklist_broadens=True,
            whitelist_broadens=_member_set_expanded(current, desired),
        )

    return None


def reset_access_policy(plane_db, family: str, *, confirm: Optional[bool] = None) -> dict:
    plane = _plane_key(family)
    title = {
        "remote": "Remote Access",
        "internet": "Internet Access",
        "ai": "AI Access",
    }[plane]
    pol = get_access_policy(plane_db, plane)
    if plane == "ai":
        rule_count = int(plane_db.conn.execute("SELECT COUNT(*) FROM ai_policy_rules").fetchone()[0] or 0)
    else:
        rule_count = int(
            plane_db.conn.execute(
                "SELECT COUNT(*) FROM policy_rules WHERE plane = ?", (plane,)
            ).fetchone()[0]
            or 0
        )

    def write():
        if plane == "ai":
            plane_db.conn.execute("DELETE FROM ai_policy_rules")
        else:
            ids = [
                r["id"]
                for r in plane_db.conn.execute(
                    "SELECT id FROM policy_rules WHERE plane = ?", (plane,)
                )
            ]
            for rid in ids:
                plane_db.conn.execute("DELETE FROM rule_sources WHERE rule_id = ?", (rid,))
                plane_db.conn.execute("DELETE FROM rule_destinations WHERE rule_id = ?", (rid,))
                plane_db.conn.execute("DELETE FROM rule_services WHERE rule_id = ?", (rid,))
                plane_db.conn.execute("DELETE FROM rule_service_refs WHERE rule_id = ?", (rid,))
            plane_db.conn.execute("DELETE FROM policy_rules WHERE plane = ?", (plane,))
        plane_db.conn.execute(
            "UPDATE access_policies SET mode = NULL, enforcement = 'enabled', "
            "row_version = row_version + 1, updated_at = ? WHERE plane = ?",
            (utc_now_iso(), plane),
        )
        return {"entity": {"type": "%s-access" % plane, "id": plane, "name": "policy"}, "operation": "reset"}

    impact = {
        "warning": "This will remove the %s policy mode and all %s rules." % (title, title),
        "effective": "ALLOW",
        "access_broadened": True,
        "before": "mode=%s rules=%s enforcement=%s"
        % (pol.get("mode") or "none", rule_count, pol.get("enforcement")),
        "after": "mode removed / rules removed / effective result after reset: ALLOW",
    }
    return plane_db._mutate(
        "unset %s-access policy" % ("ai" if plane == "ai" else plane),
        "reset policy",
        write,
        confirm=confirm,
        impact=impact,
    )


def ensure_policy_mode(plane_db, family: str, mode: Optional[str], *, oneshot: bool) -> str:
    plane = _plane_key(family)
    pol = get_access_policy(plane_db, plane)
    wanted = str(mode or "").strip().lower() or None
    if wanted is not None and wanted not in POLICY_MODES:
        raise ControlPlaneError("mode must be blacklist or whitelist")
    if pol["mode"] is None:
        if wanted is None:
            if oneshot:
                raise ControlPlaneError(
                    cli_error(
                        "No Policy Mode exists yet.",
                        expected="mode blacklist|whitelist on the first one-shot Rule",
                    )
                )
            raise ControlPlaneError("Policy mode is required")
        plane_db.conn.execute(
            "UPDATE access_policies SET mode = ?, updated_at = ? WHERE plane = ?",
            (wanted, utc_now_iso(), plane),
        )
        return wanted
    if wanted is not None and wanted != pol["mode"]:
        title = {
            "remote": "Remote Access",
            "internet": "Internet Access",
            "ai": "AI Access",
        }[plane]
        raise ControlPlaneError(
            "ERROR:\n%s is already configured in %s mode.\n\n"
            "The requested command specifies %s.\n\n"
            "Reset the %s policy before configuring a different mode.\n\n"
            "No changes were applied."
            % (title, pol["mode"].upper(), wanted.upper(), title)
        )
    return pol["mode"]


def effective_policy_result(mode: Optional[str], enforcement: str, matched: bool) -> str:
    if mode is None:
        return "ALLOW"
    if str(enforcement or "enabled").lower() == "disabled":
        return "ALLOW"
    if mode == "blacklist":
        return "DENY" if matched else "ALLOW"
    if mode == "whitelist":
        return "ALLOW" if matched else "DENY"
    return "ALLOW"


# ---------------------------------------------------------------------------
# Network objects / groups
# ---------------------------------------------------------------------------


def display_network_type(store_type: str) -> str:
    return NETWORK_DISPLAY.get(str(store_type), str(store_type))


def set_network_object(
    plane_db,
    name: str,
    *,
    type: Optional[str] = None,
    value: Optional[str] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    from drlink_control_plane import normalize_object_value

    name = validate_public_name(name, "Network Object name")
    existing = plane_db.get_object(name)
    if existing and existing["origin"] == "managed":
        raise ControlPlaneError(
            cli_error(
                "Network Object '%s' is a Managed Host." % name,
                next_step="Use:\n  unset managed-host %s" % name,
            )
        )
    if oneshot:
        if existing:
            # Existing-resource partial edit: omitted type keeps current type;
            # value is required for a mutation; type may be restated only when
            # it matches the existing store type.
            if value is None:
                raise ControlPlaneError(
                    cli_error(
                        "Network Object is incomplete.",
                        expected="  value",
                    )
                )
            if type:
                public = str(type).strip().lower()
                if public not in NETWORK_PUBLIC_TYPES:
                    raise ControlPlaneError("Network Object type must be ip, cidr, or fqdn")
                store = NETWORK_STORE[public]
                if existing["type"] != store:
                    raise ControlPlaneError(
                        cli_error("Cannot change Network Object type after creation.")
                    )
            else:
                store = existing["type"]
            # Validate value before any authoritative mutation so failed one-shots
            # leave existence/revision/policy unchanged.
            normalize_object_value(store, value)
            impact = referenced_selector_mutation_security_impact(
                plane_db, kind="network-object", name=name, value=value
            )
            result = plane_db.replace_object_value(
                name, value, confirm=confirm, impact=impact
            )
            out = {"operation": "update", "name": name}
            if isinstance(result, dict) and "revision" in result:
                out["revision"] = result["revision"]
            return out

        if not type or value is None:
            missing = []
            if not type:
                missing.append("type")
            if value is None:
                missing.append("value")
            raise ControlPlaneError(
                cli_error(
                    "Network Object is incomplete.",
                    expected="\n".join("  %s" % m for m in missing),
                )
            )
        public = str(type).strip().lower()
        if public not in NETWORK_PUBLIC_TYPES:
            raise ControlPlaneError("Network Object type must be ip, cidr, or fqdn")
        store = NETWORK_STORE[public]
        # Validate value before any authoritative mutation so failed one-shots
        # leave existence/revision/policy unchanged.
        normalized = normalize_object_value(store, value)
        assert_network_public_name_available(plane_db, name, creating="object")

        def write_create():
            oid = _new_id("obj")
            now = utc_now_iso()
            plane_db.conn.execute(
                "INSERT INTO objects(id, name, type, origin, description, status, row_version, "
                "created_at, updated_at) VALUES (?, ?, ?, 'static', '', 'active', 1, ?, ?)",
                (oid, name, store, now, now),
            )
            plane_db.conn.execute(
                "INSERT INTO object_values(object_id, value, normalized) VALUES (?, ?, ?)",
                (oid, value.strip(), normalized),
            )
            return {
                "entity": {"type": "object", "id": oid, "name": name},
                "operation": "create",
                "after": normalized,
            }

        result = plane_db._mutate(
            "set network-object %s" % name, "create network object", write_create
        )
        out = {"operation": "create", "name": name}
        if isinstance(result, dict) and "revision" in result:
            out["revision"] = result["revision"]
        return out
    if type and value is not None:
        return set_network_object(
            plane_db, name, type=type, value=value, oneshot=True, confirm=confirm
        )
    raise ControlPlaneError("Interactive Network Object wizard requires a TTY session")


def unset_network_object(plane_db, name: str) -> dict:
    name = validate_public_name(name, "Network Object name")
    obj = plane_db.get_object(name)
    if not obj:
        raise ControlPlaneError(cli_error("Network Object '%s' was not found." % name))
    if obj["origin"] == "managed" or obj["type"] == "managed_endpoint":
        raise ControlPlaneError(
            cli_error(
                "Network Object '%s' is a Managed Host." % name,
                next_step="Use:\n  unset managed-host %s" % name,
            )
        )
    refs = plane_db.object_references(name)
    if refs:
        lines = ["References:"]
        for r in refs:
            lines.append("  %s" % (r.get("display") or r.get("kind")))
        raise ControlPlaneError(
            "ERROR:\nNetwork Object '%s' is still referenced.\n\n%s\n\nNo changes were applied."
            % (name, "\n".join(lines))
        )
    return plane_db.unset_object(name)


def list_network_objects(plane_db) -> list[dict]:
    rows = []
    for obj in plane_db.list_objects():
        if obj["type"] not in ("host", "network", "fqdn", "managed_endpoint"):
            continue
        values = obj.get("values") or []
        rows.append(
            {
                "name": obj["name"],
                "type": display_network_type(obj["type"]),
                "value": values[0] if values else "-",
                "origin": obj.get("origin"),
            }
        )
    return rows


def set_network_group(
    plane_db,
    name: str,
    *,
    members: Optional[list[str]] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    name = validate_public_name(name, "Network Group name")
    if oneshot or members is not None:
        if members is None:
            raise ControlPlaneError(
                cli_error("Network Group is incomplete.", expected="  members")
            )
        member_list = list(members)
        impact = referenced_selector_mutation_security_impact(
            plane_db, kind="network-group", name=name, members=member_list
        )
        existing_pre = plane_db.get_object_group(name)
        if existing_pre is not None:
            current_members = [
                str(m["name"])
                for m in plane_db._expand_group_members(existing_pre["id"], set())
            ]
            if _member_sets_equal(current_members, member_list):
                return {"operation": "noop", "name": name}

        def write():
            # Validate all member refs before any authoritative mutation so a
            # failed edit cannot broaden WHITELIST via partial membership.
            desired = []
            for mem in member_list:
                kind, ref = plane_db.resolve_ref(mem)
                if kind != "object":
                    raise ControlPlaneError("Network Group members must be Network Objects")
                desired.append((kind, ref["id"], mem))

            existing = plane_db.get_object_group(name)
            now = utc_now_iso()
            if existing:
                gid = existing["id"]
                plane_db.conn.execute(
                    "DELETE FROM object_group_members WHERE group_id = ?", (gid,)
                )
                plane_db.conn.execute(
                    "UPDATE object_groups SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (now, gid),
                )
                op = "update"
            else:
                assert_network_public_name_available(plane_db, name, creating="group")
                gid = _new_id("ogp")
                plane_db.conn.execute(
                    "INSERT INTO object_groups(id, name, description, row_version, created_at, updated_at) "
                    "VALUES (?, ?, '', 1, ?, ?)",
                    (gid, name, now, now),
                )
                op = "create"
            for kind, member_id, _mem in desired:
                plane_db.conn.execute(
                    "INSERT OR IGNORE INTO object_group_members(group_id, member_kind, member_id) "
                    "VALUES (?, ?, ?)",
                    (gid, kind, member_id),
                )
            return {
                "entity": {"type": "object-group", "id": gid, "name": name},
                "operation": op,
            }

        result = plane_db._mutate(
            "set network-group %s" % name,
            "set network group",
            write,
            impact=impact,
            confirm=confirm,
        )
        out = {"operation": "set", "name": name}
        if isinstance(result, dict) and "revision" in result:
            out["revision"] = result["revision"]
        return out
    raise ControlPlaneError("Interactive Network Group wizard requires a TTY session")


# ---------------------------------------------------------------------------
# Service objects / groups
# ---------------------------------------------------------------------------


def get_service_object(plane_db, name: str):
    return plane_db.conn.execute(
        "SELECT * FROM service_objects WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()


def get_service_group(plane_db, name: str):
    return plane_db.conn.execute(
        "SELECT * FROM service_groups WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()


def set_service_object(
    plane_db,
    name: str,
    *,
    type: Optional[str] = None,
    port: Optional[int] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    name = validate_public_name(name, "Service Object name")
    existing = get_service_object(plane_db, name)
    if oneshot or (type and port is not None) or (existing and port is not None):
        if existing:
            # Existing-resource partial edit: omitted type keeps current type;
            # port is required for a mutation.
            if port is None:
                raise ControlPlaneError(
                    cli_error("Service Object is incomplete.", expected="  port")
                )
            if type:
                stype = str(type).strip().lower()
                if stype not in SERVICE_TYPES:
                    raise ControlPlaneError("Service Object type must be tcp, udp, or fixed-tcp")
            else:
                stype = str(existing["type"])
        else:
            if not type or port is None:
                missing = []
                if not type:
                    missing.append("type")
                if port is None:
                    missing.append("port")
                raise ControlPlaneError(
                    cli_error(
                        "Service Object is incomplete.",
                        expected="\n".join("  %s" % m for m in missing),
                    )
                )
            stype = str(type).strip().lower()
            if stype not in SERVICE_TYPES:
                raise ControlPlaneError("Service Object type must be tcp, udp, or fixed-tcp")
        port = int(port)
        if port < 1 or port > 65535:
            raise ControlPlaneError("Invalid port: %s" % port)
        if existing:
            refs = service_object_references(plane_db, name)
            if existing["type"] != stype and refs:
                # Cross-class or UDP mutation when referenced by Remote Services
                remote_refs = [r for r in refs if r.get("kind") == "remote-service"]
                if remote_refs and (
                    {existing["type"], stype} == {"tcp", "fixed-tcp"}
                    or stype == "udp"
                    or existing["type"] == "udp"
                ):
                    lines = ["References:"]
                    for r in remote_refs:
                        lines.append("  %s" % r.get("display"))
                    raise ControlPlaneError(
                        "ERROR:\nService Object '%s' is referenced by Remote Services and cannot\n"
                        "change from %s to %s.\n\n%s\n\nNo changes were applied."
                        % (name, existing["type"].upper(), stype.upper(), "\n".join(lines))
                    )
                if refs and existing["type"] != stype:
                    raise ControlPlaneError(
                        cli_error(
                            "Service Object '%s' is still referenced and cannot change type." % name,
                            expected="\n".join("  %s" % r.get("display") for r in refs),
                        )
                    )

            impact = referenced_selector_mutation_security_impact(
                plane_db,
                kind="service-object",
                name=name,
                type=stype,
                port=port,
            )
            if impact is None and str(existing["type"]) == stype and int(existing["port"]) == int(port):
                return {"operation": "noop", "name": name}

            def write():
                plane_db.conn.execute(
                    "UPDATE service_objects SET type = ?, port = ?, row_version = row_version + 1, "
                    "updated_at = ? WHERE id = ?",
                    (stype, port, utc_now_iso(), existing["id"]),
                )
                # Keep policy enforcement aligned with the reusable Service Object:
                # rematerialize every Remote/Internet rule that references this object
                # (directly or via a Service Group).
                rematerialize_dependent_rules_for_service_object(plane_db, existing["id"])
                try:
                    from drlink_upgrade_reconcile import (
                        rematerialize_published_targets_for_service_object,
                    )

                    rematerialize_published_targets_for_service_object(plane_db, existing["id"])
                except Exception:
                    pass
                return {"entity": {"type": "service-object", "id": existing["id"], "name": name}, "operation": "update"}

            return plane_db._mutate(
                "set service-object %s" % name,
                "set service object",
                write,
                impact=impact,
                confirm=confirm,
            )

        assert_service_public_name_available(plane_db, name, creating="object")

        def write_create():
            oid = _new_id("sobj")
            now = utc_now_iso()
            plane_db.conn.execute(
                "INSERT INTO service_objects(id, name, type, port, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, '', 1, ?, ?)",
                (oid, name, stype, port, now, now),
            )
            return {"entity": {"type": "service-object", "id": oid, "name": name}, "operation": "create"}

        return plane_db._mutate("set service-object %s" % name, "create service object", write_create)
    raise ControlPlaneError("Interactive Service Object wizard requires a TTY session")


def _service_object_wire_protocol(sobj) -> str:
    return "tcp" if sobj["type"] in ("tcp", "fixed-tcp") else "udp"


def rematerialize_rule_services(plane_db, rule_id: str) -> None:
    """Rebuild materialized rule_services from current rule_service_refs + definitions."""
    plane_db.conn.execute("DELETE FROM rule_services WHERE rule_id = ?", (rule_id,))
    for ref in plane_db.conn.execute(
        "SELECT ref_kind, ref_id FROM rule_service_refs WHERE rule_id = ?", (rule_id,)
    ):
        if ref["ref_kind"] == "service_object":
            sobj = plane_db.conn.execute(
                "SELECT type, port FROM service_objects WHERE id = ?", (ref["ref_id"],)
            ).fetchone()
            if not sobj:
                continue
            plane_db.conn.execute(
                "INSERT OR IGNORE INTO rule_services(rule_id, protocol, port) VALUES (?, ?, ?)",
                (rule_id, _service_object_wire_protocol(sobj), int(sobj["port"])),
            )
        elif ref["ref_kind"] == "service_group":
            for member in plane_db.conn.execute(
                "SELECT s.type AS type, s.port AS port FROM service_group_members m "
                "JOIN service_objects s ON s.id = m.service_object_id WHERE m.group_id = ?",
                (ref["ref_id"],),
            ):
                plane_db.conn.execute(
                    "INSERT OR IGNORE INTO rule_services(rule_id, protocol, port) VALUES (?, ?, ?)",
                    (rule_id, _service_object_wire_protocol(member), int(member["port"])),
                )


def rematerialize_dependent_rules_for_service_object(plane_db, sobj_id: str) -> None:
    rule_ids = {
        row["rule_id"]
        for row in plane_db.conn.execute(
            "SELECT rule_id FROM rule_service_refs WHERE ref_kind = 'service_object' AND ref_id = ?",
            (sobj_id,),
        )
    }
    for row in plane_db.conn.execute(
        "SELECT x.rule_id AS rule_id FROM rule_service_refs x "
        "JOIN service_group_members m ON m.group_id = x.ref_id "
        "WHERE x.ref_kind = 'service_group' AND m.service_object_id = ?",
        (sobj_id,),
    ):
        rule_ids.add(row["rule_id"])
    for rid in sorted(rule_ids):
        rematerialize_rule_services(plane_db, rid)


def rematerialize_dependent_rules_for_service_group(plane_db, grp_id: str) -> None:
    for row in plane_db.conn.execute(
        "SELECT rule_id FROM rule_service_refs WHERE ref_kind = 'service_group' AND ref_id = ?",
        (grp_id,),
    ):
        rematerialize_rule_services(plane_db, row["rule_id"])


def rule_matches_service(plane_db, rule_id: str, protocol: str, port: int) -> bool:
    """Match protocol/port against live Service Object/Group defs via rule_service_refs.

    Falls back to materialized rule_services only when a rule has no semantic refs
    (legacy / incomplete rows).
    """
    proto = str(protocol).lower()
    if proto in ("http", "https"):
        proto = "tcp"
    wanted = (proto, int(port))
    refs = list(
        plane_db.conn.execute(
            "SELECT ref_kind, ref_id FROM rule_service_refs WHERE rule_id = ?", (rule_id,)
        )
    )
    if refs:
        for ref in refs:
            if ref["ref_kind"] == "service_object":
                sobj = plane_db.conn.execute(
                    "SELECT type, port FROM service_objects WHERE id = ?", (ref["ref_id"],)
                ).fetchone()
                if sobj and (_service_object_wire_protocol(sobj), int(sobj["port"])) == wanted:
                    return True
            elif ref["ref_kind"] == "service_group":
                for member in plane_db.conn.execute(
                    "SELECT s.type AS type, s.port AS port FROM service_group_members m "
                    "JOIN service_objects s ON s.id = m.service_object_id WHERE m.group_id = ?",
                    (ref["ref_id"],),
                ):
                    if (_service_object_wire_protocol(member), int(member["port"])) == wanted:
                        return True
        return False
    for s in plane_db.conn.execute(
        "SELECT protocol, port FROM rule_services WHERE rule_id = ?", (rule_id,)
    ):
        if (s["protocol"], int(s["port"])) == wanted:
            return True
    return False


def service_object_references(plane_db, name: str) -> list[dict]:
    obj = get_service_object(plane_db, name)
    if not obj:
        return []
    refs = []
    for row in plane_db.conn.execute(
        "SELECT r.plane, r.name FROM rule_service_refs x "
        "JOIN policy_rules r ON r.id = x.rule_id WHERE x.ref_kind = 'service_object' AND x.ref_id = ?",
        (obj["id"],),
    ):
        family = "Remote Access" if row["plane"] == "remote" else "Internet Access"
        refs.append(
            {
                "kind": "policy",
                "plane": row["plane"],
                "name": row["name"],
                "section": family,
                "display": "%s: %s" % (family, row["name"]),
            }
        )
    for g in plane_db.conn.execute(
        "SELECT g.name FROM service_group_members m JOIN service_groups g ON g.id = m.group_id "
        "WHERE m.service_object_id = ?",
        (obj["id"],),
    ):
        refs.append(
            {
                "kind": "service-group",
                "name": g["name"],
                "section": "Service Groups",
                "display": "Service Group: %s" % g["name"],
            }
        )
    for meta in plane_db.conn.execute(
        "SELECT s.name, c.label, c.hostname FROM remote_service_meta m "
        "JOIN published_services s ON s.id = m.service_id "
        "JOIN clients c ON c.id = s.client_id WHERE m.service_object_id = ?",
        (obj["id"],),
    ):
        host = meta["label"] or meta["hostname"] or "agent"
        refs.append(
            {
                "kind": "remote-service",
                "name": meta["name"],
                "section": "Remote Services",
                "display": "%s / %s" % (host, meta["name"]),
            }
        )
    for local in plane_db.conn.execute(
        "SELECT name FROM agent_remote_services WHERE service_object = ? COLLATE NOCASE",
        (name,),
    ):
        refs.append(
            {
                "kind": "remote-service",
                "name": local["name"],
                "section": "Remote Services",
                "display": "Remote Service: %s" % local["name"],
            }
        )
    return refs


def network_group_references(plane_db, name: str) -> list[dict]:
    grp = plane_db.get_object_group(name)
    if not grp:
        return []
    refs = []
    for table, _field in (("rule_sources", "source"), ("rule_destinations", "destination")):
        for row in plane_db.conn.execute(
            "SELECT r.plane, r.name FROM %s s JOIN policy_rules r ON r.id = s.rule_id "
            "WHERE s.ref_kind = 'group' AND s.ref_id = ?" % table,
            (grp["id"],),
        ):
            family = "Remote Access" if row["plane"] == "remote" else "Internet Access"
            refs.append(
                {
                    "kind": "policy",
                    "plane": row["plane"],
                    "name": row["name"],
                    "section": family,
                    "display": "%s: %s" % (family, row["name"]),
                }
            )
    for row in plane_db.conn.execute(
        "SELECT g.name FROM object_group_members m JOIN object_groups g ON g.id = m.group_id "
        "WHERE m.member_kind = 'group' AND m.member_id = ?",
        (grp["id"],),
    ):
        refs.append(
            {
                "kind": "network-group",
                "name": row["name"],
                "section": "Network Groups",
                "display": "Network Group: %s" % row["name"],
            }
        )
    return refs


def service_group_references(plane_db, name: str) -> list[dict]:
    grp = get_service_group(plane_db, name)
    if not grp:
        return []
    refs = []
    for row in plane_db.conn.execute(
        "SELECT r.plane, r.name FROM rule_service_refs x "
        "JOIN policy_rules r ON r.id = x.rule_id WHERE x.ref_kind = 'service_group' AND x.ref_id = ?",
        (grp["id"],),
    ):
        family = "Remote Access" if row["plane"] == "remote" else "Internet Access"
        refs.append(
            {
                "kind": "policy",
                "plane": row["plane"],
                "name": row["name"],
                "section": family,
                "display": "%s: %s" % (family, row["name"]),
            }
        )
    return refs


def format_references_view(refs: list[dict]) -> str:
    """Render dependency references for show … references subviews."""
    if not refs:
        return "References:\n  None\n"
    order = (
        "Remote Access",
        "Internet Access",
        "AI Access",
        "Network Groups",
        "Service Groups",
        "Remote Services",
        "Fixed TCP",
    )
    buckets: dict[str, list[str]] = {k: [] for k in order}
    other: list[str] = []
    seen: set[tuple[str, str]] = set()
    for ref in refs:
        section = str(ref.get("section") or "").strip()
        if not section:
            kind = str(ref.get("kind") or "")
            plane = str(ref.get("plane") or "")
            if kind == "policy" or plane in ("remote", "internet"):
                section = "Remote Access" if plane == "remote" else "Internet Access"
            elif kind in ("object-group", "network-group"):
                section = "Network Groups"
            elif kind == "service-group":
                section = "Service Groups"
            elif kind == "ai-access":
                section = "AI Access"
            elif kind == "fixed-tcp":
                section = "Fixed TCP"
            elif kind == "remote-service":
                section = "Remote Services"
            else:
                section = "Other"
        label = str(ref.get("name") or ref.get("display") or "").strip()
        if ":" in label and label.split(":", 1)[0].strip() in (
            "Remote Access",
            "Internet Access",
            "Service Group",
            "Network Group",
            "Remote Service",
        ):
            label = label.split(":", 1)[1].strip()
        if label.lower().startswith("remote-access ") or label.lower().startswith("internet-access "):
            label = label.split(" ", 1)[1].strip()
        if label.lower().startswith("object-group "):
            label = label.split(" ", 1)[1].strip()
            section = "Network Groups"
        if label.lower().startswith("ai-access "):
            label = label.split(" ", 1)[1].strip()
            section = "AI Access"
        if label.lower().startswith("fixed-tcp "):
            label = label.split(" ", 1)[1].strip()
            section = "Fixed TCP"
        key = (section, label.lower())
        if not label or key in seen:
            continue
        seen.add(key)
        if section in buckets:
            buckets[section].append(label)
        else:
            other.append(label)
    lines = ["References:"]
    for section in order:
        items = buckets.get(section) or []
        if not items:
            continue
        lines.append("%s:" % section)
        for item in items:
            lines.append("  %s" % item)
    if other:
        lines.append("Other:")
        for item in other:
            lines.append("  %s" % item)
    return "\n".join(lines) + "\n"


def unset_service_object(plane_db, name: str) -> dict:
    name = validate_public_name(name, "Service Object name")
    obj = get_service_object(plane_db, name)
    if not obj:
        raise ControlPlaneError(cli_error("Service Object '%s' was not found." % name))
    refs = service_object_references(plane_db, name)
    if refs:
        raise ControlPlaneError(
            "ERROR:\nService Object '%s' is still referenced.\n\nReferences:\n%s\n\nNo changes were applied."
            % (name, "\n".join("  %s" % r["display"] for r in refs))
        )

    def write():
        plane_db.conn.execute("DELETE FROM service_objects WHERE id = ?", (obj["id"],))
        return {"entity": {"type": "service-object", "id": obj["id"], "name": name}, "operation": "delete"}

    return plane_db._mutate("unset service-object %s" % name, "delete service object", write)


def set_service_group(
    plane_db,
    name: str,
    *,
    members: Optional[list[str]] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    name = validate_public_name(name, "Service Group name")
    if not (oneshot or members is not None):
        raise ControlPlaneError("Interactive Service Group wizard requires a TTY session")
    if members is None:
        raise ControlPlaneError(cli_error("Service Group is incomplete.", expected="  members"))

    impact = referenced_selector_mutation_security_impact(
        plane_db, kind="service-group", name=name, members=list(members)
    )
    existing_pre = get_service_group(plane_db, name)
    if existing_pre is not None:
        current_members = [
            r["name"]
            for r in plane_db.conn.execute(
                "SELECT s.name FROM service_group_members m "
                "JOIN service_objects s ON s.id = m.service_object_id "
                "WHERE m.group_id = ?",
                (existing_pre["id"],),
            )
        ]
        if _member_sets_equal(current_members, list(members)):
            return {"operation": "noop", "name": name}

    def write():
        existing = get_service_group(plane_db, name)
        now = utc_now_iso()
        if existing:
            gid = existing["id"]
            plane_db.conn.execute("DELETE FROM service_group_members WHERE group_id = ?", (gid,))
            plane_db.conn.execute(
                "UPDATE service_groups SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (now, gid),
            )
            op = "update"
        else:
            assert_service_public_name_available(plane_db, name, creating="group")
            gid = _new_id("sgrp")
            plane_db.conn.execute(
                "INSERT INTO service_groups(id, name, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, '', 1, ?, ?)",
                (gid, name, now, now),
            )
            op = "create"
        for mem in members:
            sobj = get_service_object(plane_db, mem)
            if not sobj:
                raise ControlPlaneError(
                    cli_error("Required Service Object '%s' does not exist." % mem)
                )
            plane_db.conn.execute(
                "INSERT OR IGNORE INTO service_group_members(group_id, service_object_id) VALUES (?, ?)",
                (gid, sobj["id"]),
            )
        # Membership edits must refresh materialized policy services for referencing rules.
        rematerialize_dependent_rules_for_service_group(plane_db, gid)
        return {"entity": {"type": "service-group", "id": gid, "name": name}, "operation": op}

    return plane_db._mutate(
        "set service-group %s" % name,
        "set service group",
        write,
        impact=impact,
        confirm=confirm,
    )


def unset_service_group(plane_db, name: str) -> dict:
    name = validate_public_name(name, "Service Group name")
    grp = get_service_group(plane_db, name)
    if not grp:
        raise ControlPlaneError(cli_error("Service Group '%s' was not found." % name))
    refs = service_group_references(plane_db, name)
    if refs:
        raise ControlPlaneError(
            "ERROR:\nService Group '%s' is still referenced.\n\nReferences:\n%s\n\n"
            "No changes were applied."
            % (name, "\n".join("  %s" % r["display"] for r in refs))
        )

    def write():
        plane_db.conn.execute("DELETE FROM service_group_members WHERE group_id = ?", (grp["id"],))
        plane_db.conn.execute("DELETE FROM service_groups WHERE id = ?", (grp["id"],))
        return {"entity": {"type": "service-group", "id": grp["id"], "name": name}, "operation": "delete"}

    return plane_db._mutate("unset service-group %s" % name, "delete service group", write)


def expand_service_ref(plane_db, token: str) -> list[sqlite3.Row]:
    kind, ref = resolve_service_ref(plane_db, token)
    if kind == "service_object":
        return [ref]
    return [
        r
        for r in plane_db.conn.execute(
            "SELECT s.* FROM service_group_members m JOIN service_objects s ON s.id = m.service_object_id "
            "WHERE m.group_id = ? ORDER BY s.name COLLATE NOCASE",
            (ref["id"],),
        )
    ]


def service_ref_has_udp(plane_db, token: str) -> tuple[bool, str]:
    for sobj in expand_service_ref(plane_db, token):
        if sobj["type"] == "udp":
            return True, sobj["name"]
    return False, ""


# ---------------------------------------------------------------------------
# Permission objects / groups
# ---------------------------------------------------------------------------


def get_permission_object(plane_db, name: str):
    return plane_db.conn.execute(
        "SELECT * FROM permission_objects WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()


def get_permission_group(plane_db, name: str):
    return plane_db.conn.execute(
        "SELECT * FROM permission_groups WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()


def permission_object_references(plane_db, name: str) -> list[dict]:
    """AI Access rules and Permission Groups that still reference this object."""
    obj = get_permission_object(plane_db, name)
    if not obj:
        return []
    refs: list[dict] = []
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_policy_rules WHERE permission_ref_kind = 'permission_object' "
        "AND permission_ref_id = ? ORDER BY name COLLATE NOCASE",
        (obj["id"],),
    ):
        refs.append(
            {
                "kind": "ai-access",
                "name": row["name"],
                "display": "ai-access %s" % row["name"],
            }
        )
    for row in plane_db.conn.execute(
        "SELECT g.name AS name FROM permission_groups g "
        "JOIN permission_group_members m ON m.group_id = g.id "
        "WHERE m.permission_object_id = ? ORDER BY g.name COLLATE NOCASE",
        (obj["id"],),
    ):
        refs.append(
            {
                "kind": "permission-group",
                "name": row["name"],
                "display": "permission-group %s" % row["name"],
            }
        )
    return refs


def permission_group_references(plane_db, name: str) -> list[dict]:
    """AI Access rules that still reference this Permission Group."""
    grp = get_permission_group(plane_db, name)
    if not grp:
        return []
    refs: list[dict] = []
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_policy_rules WHERE permission_ref_kind = 'permission_group' "
        "AND permission_ref_id = ? ORDER BY name COLLATE NOCASE",
        (grp["id"],),
    ):
        refs.append(
            {
                "kind": "ai-access",
                "name": row["name"],
                "display": "ai-access %s" % row["name"],
            }
        )
    return refs


def ai_identity_references(plane_db, name: str) -> list[dict]:
    """v2.4 AI Access rules and legacy AI Access rules referencing this identity."""
    principal = plane_db.get_principal(name)
    if principal is None:
        return []
    refs: list[dict] = []
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_policy_rules WHERE source_identity_id = ? ORDER BY name COLLATE NOCASE",
        (principal["id"],),
    ):
        refs.append(
            {
                "kind": "ai-access",
                "name": row["name"],
                "display": "ai-access %s" % row["name"],
            }
        )
    for row in plane_db.conn.execute(
        "SELECT name FROM ai_access_rules WHERE principal_id = ? ORDER BY name COLLATE NOCASE",
        (principal["id"],),
    ):
        refs.append(
            {
                "kind": "ai-access",
                "name": row["name"],
                "display": "ai-access %s" % row["name"],
            }
        )
    return refs


def unset_permission_object(plane_db, name: str) -> dict:
    name = validate_public_name(name, "Permission Object name")
    obj = get_permission_object(plane_db, name)
    if not obj:
        raise ControlPlaneError(cli_error("Permission Object '%s' was not found." % name))
    refs = permission_object_references(plane_db, name)
    if refs:
        raise ControlPlaneError(
            "ERROR:\nPermission Object '%s' is still referenced.\n\nReferences:\n%s\n\n"
            "No changes were applied."
            % (name, "\n".join("  %s" % r["display"] for r in refs))
        )

    def write():
        plane_db.conn.execute(
            "DELETE FROM permission_object_members WHERE permission_object_id = ?", (obj["id"],)
        )
        plane_db.conn.execute("DELETE FROM permission_objects WHERE id = ?", (obj["id"],))
        return {"entity": {"type": "permission-object", "id": obj["id"], "name": name}, "operation": "delete"}

    return plane_db._mutate("unset permission-object %s" % name, "delete permission object", write)


def unset_permission_group(plane_db, name: str) -> dict:
    name = validate_public_name(name, "Permission Group name")
    grp = get_permission_group(plane_db, name)
    if not grp:
        raise ControlPlaneError(cli_error("Permission Group '%s' was not found." % name))
    refs = permission_group_references(plane_db, name)
    if refs:
        raise ControlPlaneError(
            "ERROR:\nPermission Group '%s' is still referenced.\n\nReferences:\n%s\n\n"
            "No changes were applied."
            % (name, "\n".join("  %s" % r["display"] for r in refs))
        )

    def write():
        plane_db.conn.execute("DELETE FROM permission_group_members WHERE group_id = ?", (grp["id"],))
        plane_db.conn.execute("DELETE FROM permission_groups WHERE id = ?", (grp["id"],))
        return {"entity": {"type": "permission-group", "id": grp["id"], "name": name}, "operation": "delete"}

    return plane_db._mutate("unset permission-group %s" % name, "delete permission group", write)


def set_permission_object(
    plane_db,
    name: str,
    *,
    permissions: Optional[list[str]] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    name = validate_public_name(name, "Permission Object name")
    if not (oneshot or permissions is not None):
        raise ControlPlaneError("Interactive Permission Object wizard requires a TTY session")
    if permissions is None:
        raise ControlPlaneError(cli_error("Permission Object is incomplete.", expected="  permissions"))
    cleaned = []
    for p in permissions:
        perm = str(p).strip().lower()
        if perm not in PERMISSIONS:
            raise ControlPlaneError("Unknown permission: %s" % p)
        cleaned.append(perm)

    impact = referenced_selector_mutation_security_impact(
        plane_db, kind="permission-object", name=name, permissions=cleaned
    )
    existing_pre = get_permission_object(plane_db, name)
    if existing_pre is not None:
        current_perms = [
            r["permission"]
            for r in plane_db.conn.execute(
                "SELECT permission FROM permission_object_members "
                "WHERE permission_object_id = ?",
                (existing_pre["id"],),
            )
        ]
        if _member_sets_equal(current_perms, cleaned):
            return {"operation": "noop", "name": name}

    def write():
        existing = get_permission_object(plane_db, name)
        now = utc_now_iso()
        if existing:
            pid = existing["id"]
            plane_db.conn.execute(
                "DELETE FROM permission_object_members WHERE permission_object_id = ?", (pid,)
            )
            plane_db.conn.execute(
                "UPDATE permission_objects SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
                (now, pid),
            )
            op = "update"
        else:
            assert_permission_public_name_available(plane_db, name, creating="object")
            pid = _new_id("perm")
            plane_db.conn.execute(
                "INSERT INTO permission_objects(id, name, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, '', 1, ?, ?)",
                (pid, name, now, now),
            )
            op = "create"
        for perm in cleaned:
            plane_db.conn.execute(
                "INSERT OR IGNORE INTO permission_object_members(permission_object_id, permission) VALUES (?, ?)",
                (pid, perm),
            )
        return {"entity": {"type": "permission-object", "id": pid, "name": name}, "operation": op}

    return plane_db._mutate(
        "set permission-object %s" % name,
        "set permission object",
        write,
        impact=impact,
        confirm=confirm,
    )


def set_permission_group(
    plane_db,
    name: str,
    *,
    members: Optional[list[str]] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    name = validate_public_name(name, "Permission Group name")
    if members is None:
        raise ControlPlaneError(cli_error("Permission Group is incomplete.", expected="  members"))

    impact = referenced_selector_mutation_security_impact(
        plane_db, kind="permission-group", name=name, members=list(members)
    )
    existing_pre = get_permission_group(plane_db, name)
    if existing_pre is not None:
        current_members = [
            r["name"]
            for r in plane_db.conn.execute(
                "SELECT p.name FROM permission_group_members m "
                "JOIN permission_objects p ON p.id = m.permission_object_id "
                "WHERE m.group_id = ?",
                (existing_pre["id"],),
            )
        ]
        if _member_sets_equal(current_members, list(members)):
            return {"operation": "noop", "name": name}

    def write():
        existing = get_permission_group(plane_db, name)
        now = utc_now_iso()
        if existing:
            gid = existing["id"]
            plane_db.conn.execute("DELETE FROM permission_group_members WHERE group_id = ?", (gid,))
            op = "update"
        else:
            assert_permission_public_name_available(plane_db, name, creating="group")
            gid = _new_id("pgrp")
            plane_db.conn.execute(
                "INSERT INTO permission_groups(id, name, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, '', 1, ?, ?)",
                (gid, name, now, now),
            )
            op = "create"
        for mem in members:
            pobj = get_permission_object(plane_db, mem)
            if not pobj:
                raise ControlPlaneError(
                    cli_error("Required Permission Object '%s' does not exist." % mem)
                )
            plane_db.conn.execute(
                "INSERT OR IGNORE INTO permission_group_members(group_id, permission_object_id) VALUES (?, ?)",
                (gid, pobj["id"]),
            )
        plane_db.conn.execute(
            "UPDATE permission_groups SET row_version = row_version + 1, updated_at = ? WHERE id = ?",
            (utc_now_iso(), gid),
        ) if existing else None
        return {"entity": {"type": "permission-group", "id": gid, "name": name}, "operation": op}

    return plane_db._mutate(
        "set permission-group %s" % name,
        "set permission group",
        write,
        impact=impact,
        confirm=confirm,
    )


def expand_permissions(plane_db, token: str) -> set[str]:
    kind, ref = resolve_permission_ref(plane_db, token)
    if kind == "permission_object":
        return {
            r["permission"]
            for r in plane_db.conn.execute(
                "SELECT permission FROM permission_object_members "
                "WHERE permission_object_id = ? ORDER BY permission COLLATE NOCASE",
                (ref["id"],),
            )
        }
    out: set[str] = set()
    for mid in plane_db.conn.execute(
        "SELECT permission_object_id FROM permission_group_members "
        "WHERE group_id = ? ORDER BY permission_object_id",
        (ref["id"],),
    ):
        for r in plane_db.conn.execute(
            "SELECT permission FROM permission_object_members "
            "WHERE permission_object_id = ? ORDER BY permission COLLATE NOCASE",
            (mid["permission_object_id"],),
        ):
            out.add(r["permission"])
    return out


def expand_permissions_ordered(plane_db, token: str) -> list[str]:
    """Deterministic atomic permission list for public policy-test expansion."""
    return sorted(expand_permissions(plane_db, token), key=lambda p: str(p).lower())


# ---------------------------------------------------------------------------
# Access rules (remote / internet)
# ---------------------------------------------------------------------------


def _resolve_network_selector(plane_db, token: str, *, plane: str, field: str):
    kind, ref = plane_db.resolve_ref(token)
    if kind == "object":
        if not plane_db.object_type_valid_for(ref, plane, field):
            if plane == "internet" and field == "destination" and ref["type"] == "managed_endpoint":
                raise ControlPlaneError(
                    "ERROR:\nManaged Host '%s' cannot be used as an Internet Access destination.\n\n"
                    "Use an IP, CIDR, or FQDN Network Object as the destination.\n\n"
                    "No changes were applied." % ref["name"]
                )
            raise ControlPlaneError(
                cli_error(
                    "Object type is not valid for %s Access %s."
                    % ("Remote" if plane == "remote" else "Internet", field.title())
                )
            )
        return kind, ref
    ok, bad = plane_db.group_valid_for(ref, plane, field)
    if not ok:
        if plane == "internet" and field == "destination":
            raise ControlPlaneError(
                "ERROR:\nNetwork Group '%s' contains Managed Host '%s'.\n\n"
                "Managed Hosts are valid Internet Access sources,\n"
                "but cannot be used as Internet Access destinations.\n\n"
                "No changes were applied." % (ref["name"], bad)
            )
        raise ControlPlaneError(
            cli_error(
                "Network Group is not valid for %s Access %s (invalid member: %s)."
                % ("Remote" if plane == "remote" else "Internet", field.title(), bad)
            )
        )
    return kind, ref


def set_access_rule(
    plane_db,
    family: str,
    name: str,
    *,
    mode: Optional[str] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    service: Optional[str] = None,
    enabled: Optional[bool] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    plane = _plane_key(family)
    name = validate_public_name(name, "Rule name")
    existing = plane_db._get_rule(plane, name)
    if oneshot and existing is None:
        missing = []
        if source is None:
            missing.append("source")
        if destination is None:
            missing.append("destination")
        if service is None:
            missing.append("service")
        if enabled is None:
            missing.append("enabled|disabled")
        pol = get_access_policy(plane_db, plane)
        if pol["mode"] is None and mode is None:
            missing.append("mode blacklist|whitelist")
        if missing:
            raise ControlPlaneError(
                "ERROR:\n%s Access rule is incomplete.\n\nMissing:\n%s\n\nNo changes were applied."
                % (
                    "Remote" if plane == "remote" else "Internet",
                    "\n".join("  %s" % m for m in missing),
                )
            )
    # Validate dependencies before mutation for create
    if source is not None:
        try:
            plane_db.resolve_ref(source)
        except ControlPlaneError as exc:
            if "ambiguous" in str(exc).lower():
                raise
            raise ControlPlaneError(
                "ERROR:\nRequired Network Object '%s' does not exist.\n\n"
                "No changes were applied.\n\n"
                "Create the required Network Object first,\n"
                "or use a ConfigurationBundle to create the dependencies and Rule together."
                % source
            ) from None
    if destination is not None:
        try:
            plane_db.resolve_ref(destination)
        except ControlPlaneError as exc:
            if "ambiguous" in str(exc).lower():
                raise
            raise ControlPlaneError(
                "ERROR:\nRequired Network Object '%s' does not exist.\n\n"
                "No changes were applied.\n\n"
                "Create the required Network Object first,\n"
                "or use a ConfigurationBundle to create the dependencies and Rule together."
                % destination
            ) from None
    if service is not None:
        try:
            expand_service_ref(plane_db, service)
        except ControlPlaneError as exc:
            msg = str(exc)
            if "ambiguous" in msg.lower():
                raise
            if "was not found" in msg:
                raise ControlPlaneError(
                    "ERROR:\nRequired Service Object '%s' does not exist.\n\n"
                    "No changes were applied.\n\n"
                    "Create the required Service Object first,\n"
                    "or use a ConfigurationBundle to create the dependencies and Rule together."
                    % service
                ) from None
            raise
        if plane == "remote":
            has_udp, udp_name = service_ref_has_udp(plane_db, service)
            if has_udp:
                kind, _ref = resolve_service_ref(plane_db, service)
                if kind == "service_group":
                    raise ControlPlaneError(
                        "ERROR:\nService Group '%s' contains UDP Service Object '%s'.\n\n"
                        "Remote Access supports TCP and Fixed TCP Remote Services only.\n\n"
                        "No changes were applied." % (service, udp_name)
                    )
                raise ControlPlaneError(
                    "ERROR:\nService Object '%s' uses UDP.\n\n"
                    "Remote Access supports TCP and Fixed TCP Remote Services only.\n\n"
                    "No changes were applied." % service
                )
        if plane == "internet":
            has_udp, udp_name = service_ref_has_udp(plane_db, service)
            if has_udp:
                kind, _ref = resolve_service_ref(plane_db, service)
                if kind == "service_group":
                    raise ControlPlaneError(
                        "ERROR:\nService Group '%s' contains UDP Service Object '%s'.\n\n"
                        "Internet Access v2.4 has a TCP/HTTP/HTTPS CONNECT datapath only;\n"
                        "UDP Service Objects cannot be selected.\n\n"
                        "No changes were applied." % (service, udp_name)
                    )
                raise ControlPlaneError(
                    "ERROR:\nService Object '%s' uses UDP.\n\n"
                    "Internet Access v2.4 has a TCP/HTTP/HTTPS CONNECT datapath only;\n"
                    "UDP Service Objects cannot be selected.\n\n"
                    "No changes were applied." % service
                )

    def write():
        ensure_policy_mode(plane_db, plane, mode, oneshot=oneshot and existing is None)
        if existing is None:
            if not oneshot and (source is None or destination is None or service is None or enabled is None):
                raise ControlPlaneError("Interactive rule wizard requires a TTY session")
            rid = _new_id("rul")
            now = utc_now_iso()
            plane_db.conn.execute(
                "INSERT INTO policy_rules(id, plane, name, position, action, enabled, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'match', ?, '', 1, ?, ?)",
                (rid, plane, name, plane_db._bottom_position(plane), 1 if enabled else 0, now, now),
            )
            rule_id = rid
            op = "create"
        else:
            rule_id = existing["id"]
            if mode is not None:
                ensure_policy_mode(plane_db, plane, mode, oneshot=False)
            if enabled is not None:
                plane_db.conn.execute(
                    "UPDATE policy_rules SET enabled = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (1 if enabled else 0, utc_now_iso(), rule_id),
                )
            op = "update"
        if source is not None:
            kind, ref = _resolve_network_selector(plane_db, source, plane=plane, field="source")
            plane_db.conn.execute("DELETE FROM rule_sources WHERE rule_id = ?", (rule_id,))
            plane_db.conn.execute(
                "INSERT INTO rule_sources(rule_id, ref_kind, ref_id) VALUES (?, ?, ?)",
                (rule_id, kind, ref["id"]),
            )
        if destination is not None:
            kind, ref = _resolve_network_selector(plane_db, destination, plane=plane, field="destination")
            plane_db.conn.execute("DELETE FROM rule_destinations WHERE rule_id = ?", (rule_id,))
            plane_db.conn.execute(
                "INSERT INTO rule_destinations(rule_id, ref_kind, ref_id) VALUES (?, ?, ?)",
                (rule_id, kind, ref["id"]),
            )
        if service is not None:
            kind, ref = resolve_service_ref(plane_db, service)
            plane_db.conn.execute("DELETE FROM rule_service_refs WHERE rule_id = ?", (rule_id,))
            plane_db.conn.execute("DELETE FROM rule_services WHERE rule_id = ?", (rule_id,))
            if kind == "service_object":
                plane_db.conn.execute(
                    "INSERT INTO rule_service_refs(rule_id, ref_kind, ref_id) VALUES (?, 'service_object', ?)",
                    (rule_id, ref["id"]),
                )
                proto = "tcp" if ref["type"] in ("tcp", "fixed-tcp") else "udp"
                plane_db.conn.execute(
                    "INSERT INTO rule_services(rule_id, protocol, port) VALUES (?, ?, ?)",
                    (rule_id, proto, int(ref["port"])),
                )
            else:
                plane_db.conn.execute(
                    "INSERT INTO rule_service_refs(rule_id, ref_kind, ref_id) VALUES (?, 'service_group', ?)",
                    (rule_id, ref["id"]),
                )
                for member in expand_service_ref(plane_db, service):
                    proto = "tcp" if member["type"] in ("tcp", "fixed-tcp") else "udp"
                    plane_db.conn.execute(
                        "INSERT OR IGNORE INTO rule_services(rule_id, protocol, port) VALUES (?, ?, ?)",
                        (rule_id, proto, int(member["port"])),
                    )
        return {"entity": {"type": "%s-access" % plane, "id": rule_id, "name": name}, "operation": op}

    impact = None
    if (
        enabled is False
        and existing is not None
        and bool(existing["enabled"])
    ):
        impact = last_enabled_rule_mutation_impact(
            plane_db, plane, name, disabling=True
        )
    elif existing is not None:
        impact = access_rule_update_security_impact(
            plane_db,
            plane,
            name,
            source=source,
            destination=destination,
            service=service,
            enabled=enabled,
        )

    return plane_db._mutate(
        "set %s-access %s" % (plane, name),
        "set access rule",
        write,
        impact=impact,
        confirm=confirm,
    )


def unset_access_rule(
    plane_db, family: str, name: str, *, confirm: Optional[bool] = None
) -> dict:
    plane = _plane_key(family)
    return plane_db.unset_rule(plane, name, confirm=confirm)


# ---------------------------------------------------------------------------
# Policy evaluation (BLACKLIST / WHITELIST)
# ---------------------------------------------------------------------------


def _representative_ip_from_value(value: str) -> str:
    """Pick a concrete IP for policy test when the selector is a CIDR."""
    text = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ControlPlaneError(cli_error("Value '%s' is not a usable IP or CIDR." % text)) from exc
    hosts = list(net.hosts())
    return str(hosts[0] if hosts else net.network_address)


def _resolve_test_source_ip(plane_db, source_name: str) -> str:
    """Resolve a concrete Network Object to a runtime-equivalent source IP."""
    from drlink_control_plane import membership_eligible

    obj = plane_db.get_object(source_name)
    if obj is not None:
        if obj["type"] == "managed_endpoint":
            for addr in plane_db.endpoint_addresses(obj["name"]):
                if addr.get("active") and membership_eligible(str(addr.get("address") or "")):
                    return str(addr["address"])
            raise ControlPlaneError(
                cli_error(
                    "Managed Host '%s' has no usable address for policy test." % source_name,
                    next_step="Ensure the Agent has reported addresses, then retry.",
                )
            )
        vals = plane_db._object_values(obj["id"])
        if not vals:
            raise ControlPlaneError(cli_error("Network Object '%s' has no value." % source_name))
        if obj["type"] == "fqdn":
            # FQDN sources are unusual; still allow exact-string evaluation via host match path.
            return str(vals[0])
        return _representative_ip_from_value(vals[0])
    raise ControlPlaneError(cli_error("Network Object '%s' was not found." % source_name))


def _resolve_test_destination(plane_db, destination_name: str, *, plane: str) -> str:
    """Resolve a concrete Network Object to a runtime-equivalent destination token."""
    obj = plane_db.get_object(destination_name)
    if obj is not None:
        if obj["type"] == "managed_endpoint":
            # Remote Access runtime matches Managed Host by identity as well as address.
            if plane == "remote":
                return obj["name"]
            raise ControlPlaneError(
                cli_error("Managed Host cannot be used as an Internet Access destination.")
            )
        vals = plane_db._object_values(obj["id"])
        if not vals:
            raise ControlPlaneError(cli_error("Network Object '%s' has no value." % destination_name))
        if obj["type"] == "fqdn":
            return str(vals[0]).rstrip(".").lower()
        if obj["type"] == "network":
            return _representative_ip_from_value(vals[0])
        return str(vals[0])
    # Allow literal IP / hostname tokens for AI/operator convenience.
    try:
        return str(ipaddress.ip_address(str(destination_name).strip()))
    except ValueError:
        pass
    if plane == "internet" and "." in str(destination_name):
        return str(destination_name).rstrip(".").lower()
    raise ControlPlaneError(cli_error("Network Object '%s' was not found." % destination_name))


def _resolve_test_service(plane_db, service_name: str) -> tuple[str, int]:
    """Resolve a concrete Service Object to protocol + port used by runtime matching."""
    sobj = get_service_object(plane_db, service_name)
    if sobj is None:
        raise ControlPlaneError(
            cli_error(
                "Service Object '%s' was not found." % service_name,
                expected="  Service Object",
                next_step="Use:\n  show service-objects",
            )
        )
    stype = str(sobj["type"] or "tcp").lower()
    proto = "tcp" if stype in ("tcp", "fixed-tcp", "http", "https") else stype
    return proto, int(sobj["port"])


def _network_test_leaves(plane_db, selector: str, *, role: str) -> tuple[bool, list[str]]:
    """Expand a Network Object/Group selector to deterministic leaf Object names."""
    obj = plane_db.get_object(selector)
    grp = plane_db.get_object_group(selector)
    if obj is not None and grp is not None:
        raise ControlPlaneError(
            _ambiguous_public_name_error(selector, "Network Object", "Network Group")
        )
    if obj is not None:
        return False, [str(obj["name"])]
    if grp is not None:
        members = plane_db._expand_group_members(grp["id"], set())
        if not members:
            raise ControlPlaneError(
                cli_error("Network Group '%s' has no members." % selector)
            )
        names = []
        seen = set()
        for mem in members:
            name = str(mem["name"])
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)
        return True, names
    if role == "destination":
        # Literal tokens are treated as a single concrete leaf.
        return False, [str(selector)]
    raise ControlPlaneError(cli_error("Network Object '%s' was not found." % selector))


def _service_test_leaves(plane_db, selector: str) -> tuple[bool, list[str]]:
    """Expand a Service Object/Group selector to deterministic leaf Service Object names."""
    kind, ref = resolve_service_ref(plane_db, selector)
    if kind == "service_object":
        return False, [str(ref["name"])]
    grp = ref
    members = [
        r
        for r in plane_db.conn.execute(
            "SELECT s.name AS name FROM service_group_members m "
            "JOIN service_objects s ON s.id = m.service_object_id "
            "WHERE m.group_id = ? ORDER BY s.name COLLATE NOCASE",
            (grp["id"],),
        )
    ]
    if not members:
        raise ControlPlaneError(cli_error("Service Group '%s' has no members." % selector))
    names = []
    seen = set()
    for mem in members:
        name = str(mem["name"])
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
    return True, names


def _aggregate_group_test_result(member_results: list[dict]) -> tuple[str, bool]:
    """ALLOW only when every concrete member/combination is ALLOW; else DENY."""
    outcomes = [str(item.get("result") or "DENY").upper() for item in member_results]
    if outcomes and all(item == "ALLOW" for item in outcomes):
        return "ALLOW", False
    mixed = len(set(outcomes)) > 1
    return "DENY", mixed


def _evaluate_resolved_access(
    plane_db,
    plane: str,
    *,
    src: str,
    dest: str,
    proto: str,
    prt: int,
    resolve_fn: Optional[Callable[[str], list[str]]] = None,
) -> dict:
    """Run one concrete Remote/Internet evaluation through runtime-equivalent APIs."""
    if plane == "internet" and str(proto).lower() == "udp":
        raise ControlPlaneError(
            cli_error(
                "Internet Access v2.4 has a TCP/HTTP/HTTPS CONNECT datapath only; "
                "UDP Service Objects cannot be selected."
            )
        )
    if plane == "remote":
        evaluation = plane_db.evaluate_remote_access(str(src), str(dest), str(proto), int(prt))
    else:
        candidate_ips = None
        dest_s = str(dest)
        try:
            candidate_ips = [ipaddress.ip_address(dest_s).compressed]
        except ValueError:
            resolver = resolve_fn
            if resolver is None:
                import socket as _socket

                def _default_resolve(hostname: str) -> list[str]:
                    results = _socket.getaddrinfo(hostname, None, type=_socket.SOCK_STREAM)
                    seen = set()
                    out = []
                    for _family, _type, _proto, _canon, sockaddr in results:
                        ip = sockaddr[0]
                        if ip in seen:
                            continue
                        seen.add(ip)
                        out.append(ip)
                    return out

                resolver = _default_resolve
            try:
                import frp_egress_control as EG

                candidate_ips = EG.validate_resolved_addresses(list(resolver(dest_s)))
            except Exception as exc:
                raise ControlPlaneError(
                    cli_error(
                        "Internet Access test could not resolve destination '%s': %s"
                        % (dest_s, exc)
                    )
                ) from exc
        evaluation = plane_db.evaluate_internet_access(
            str(src), dest_s, int(prt), str(proto), candidate_ips=candidate_ips
        )
    action = str(evaluation.get("effective") or evaluation.get("action") or "DENY").upper()
    return {
        "mode": evaluation.get("mode"),
        "enforcement": evaluation.get("enforcement"),
        "matched_rules": list(evaluation.get("matched_rules") or []),
        "result": action,
        "plane": plane,
        "authorized_candidates": list(evaluation.get("authorized_candidates") or []),
        "candidate_ips": list(evaluation.get("candidate_ips") or []),
    }


def evaluate_selector_policy(
    plane_db,
    family: str,
    *,
    source_ip: Optional[str] = None,
    destination: Optional[str] = None,
    protocol: Optional[str] = None,
    port: Optional[int] = None,
    source_name: Optional[str] = None,
    destination_name: Optional[str] = None,
    service_name: Optional[str] = None,
    resolve_fn: Optional[Callable[[str], list[str]]] = None,
) -> dict:
    """Evaluate Remote/Internet Access using runtime-equivalent semantics.

    Named Object selectors are resolved to canonical values (IP/FQDN/protocol/port)
    so Object identity alone never decides the match — matching the datapath.

    When a public test selector is a Network/Service Group, every leaf member
    combination is evaluated. Top-level ALLOW requires unanimous ALLOW; mixed
    outcomes aggregate to DENY with explicit member/combination detail.

    For Internet Access hostname destinations, ``resolve_fn`` (default: getaddrinfo)
    supplies the same validated candidate set the gateway uses for IP/CIDR matching.
    """
    plane = _plane_key(family)

    # Public CLI path: named selectors → resolve → same evaluators as runtime.
    if source_name is not None or destination_name is not None or service_name is not None:
        if source_name is None or destination_name is None or service_name is None:
            raise ControlPlaneError(
                cli_error(
                    "Policy test requires source, destination, and service.",
                    expected="  source\n  destination\n  service",
                )
            )
        src_is_group, src_leaves = _network_test_leaves(
            plane_db, source_name, role="source"
        )
        dst_is_group, dst_leaves = _network_test_leaves(
            plane_db, destination_name, role="destination"
        )
        svc_is_group, svc_leaves = _service_test_leaves(plane_db, service_name)
        group_test = src_is_group or dst_is_group or svc_is_group

        if not group_test:
            src = _resolve_test_source_ip(plane_db, src_leaves[0])
            dest = _resolve_test_destination(plane_db, dst_leaves[0], plane=plane)
            proto, prt = _resolve_test_service(plane_db, svc_leaves[0])
            return _evaluate_resolved_access(
                plane_db,
                plane,
                src=src,
                dest=dest,
                proto=proto,
                prt=prt,
                resolve_fn=resolve_fn,
            )

        member_results: list[dict] = []
        matched_union: list[str] = []
        matched_seen = set()
        mode = None
        enforcement = None
        for src_leaf in src_leaves:
            for dst_leaf in dst_leaves:
                for svc_leaf in svc_leaves:
                    src = _resolve_test_source_ip(plane_db, src_leaf)
                    dest = _resolve_test_destination(plane_db, dst_leaf, plane=plane)
                    proto, prt = _resolve_test_service(plane_db, svc_leaf)
                    one = _evaluate_resolved_access(
                        plane_db,
                        plane,
                        src=src,
                        dest=dest,
                        proto=proto,
                        prt=prt,
                        resolve_fn=resolve_fn,
                    )
                    if mode is None:
                        mode = one.get("mode")
                        enforcement = one.get("enforcement")
                    rules = list(one.get("matched_rules") or [])
                    for rule in rules:
                        key = str(rule).lower()
                        if key in matched_seen:
                            continue
                        matched_seen.add(key)
                        matched_union.append(rule)
                    member_results.append(
                        {
                            "source": src_leaf,
                            "destination": dst_leaf,
                            "service": svc_leaf,
                            "result": one["result"],
                            "matched_rules": rules,
                        }
                    )
        aggregate, mixed = _aggregate_group_test_result(member_results)
        out = {
            "mode": mode,
            "enforcement": enforcement,
            "matched_rules": matched_union,
            "result": aggregate,
            "plane": plane,
            "member_results": member_results,
            "group_test": True,
            "mixed": mixed,
            "authorized_candidates": [],
            "candidate_ips": [],
        }
        if mixed:
            out["reason"] = (
                "mixed group member outcomes; aggregate DENY "
                "(ALLOW only when every member combination allows)"
            )
        return out

    # Direct IP/protocol/port path (internal / legacy callers).
    pol = get_access_policy(plane_db, plane)
    matched_rules = []
    for rule_row in plane_db.conn.execute(
        "SELECT * FROM policy_rules WHERE plane = ? ORDER BY name", (plane,)
    ):
        if not rule_row["enabled"]:
            continue
        view = plane_db._rule_view(rule_row)
        src_ok = False
        if source_ip:
            for s in plane_db.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_sources WHERE rule_id = ?", (rule_row["id"],)
            ):
                if plane_db._ref_matches_ip(s["ref_kind"], s["ref_id"], source_ip, role="source"):
                    src_ok = True
                    break
        else:
            src_ok = True
        dst_ok = False
        if destination:
            dest_obj = plane_db.get_object(destination)
            for s in plane_db.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_destinations WHERE rule_id = ?", (rule_row["id"],)
            ):
                if plane == "internet":
                    if plane_db._ref_matches_host(s["ref_kind"], s["ref_id"], destination):
                        dst_ok = True
                        break
                else:
                    try:
                        dest_ip = str(ipaddress.ip_address(destination))
                    except ValueError:
                        dest_ip = destination
                    if plane_db._ref_matches_ip(s["ref_kind"], s["ref_id"], dest_ip, role="destination"):
                        dst_ok = True
                        break
                    if dest_obj and s["ref_kind"] == "object" and s["ref_id"] == dest_obj["id"]:
                        dst_ok = True
                        break
        else:
            dst_ok = True
        svc_ok = False
        if protocol is not None and port is not None:
            svc_ok = rule_matches_service(plane_db, rule_row["id"], protocol, port)
        else:
            svc_ok = True
        if src_ok and dst_ok and svc_ok:
            matched_rules.append(view["name"])
    matched = bool(matched_rules)
    result = effective_policy_result(pol["mode"], pol["enforcement"], matched)
    return {
        "mode": pol["mode"],
        "enforcement": pol["enforcement"],
        "matched_rules": matched_rules,
        "result": result,
        "plane": plane,
    }


def _ref_name_match(plane_db, ref_kind: str, ref_id: str, name: str) -> bool:
    if ref_kind == "object":
        obj = plane_db.conn.execute("SELECT name FROM objects WHERE id = ?", (ref_id,)).fetchone()
        return bool(obj and obj["name"].lower() == name.lower())
    grp = plane_db.conn.execute("SELECT name FROM object_groups WHERE id = ?", (ref_id,)).fetchone()
    if grp and grp["name"].lower() == name.lower():
        return True
    members = plane_db._expand_group_members(ref_id, set())
    return any(m["name"].lower() == name.lower() for m in members)


def format_policy_test(family: str, evaluation: dict, selectors: dict, remote_service: Optional[dict] = None) -> str:
    titles = {
        "remote": "Remote Access Test",
        "internet": "Internet Access Test",
        "ai": "AI Access Test",
    }
    plane = evaluation["plane"]
    lines = [
        titles.get(plane, "Access Test"),
        "=" * len(titles.get(plane, "Access Test")),
        "",
        "Mode        : %s" % (evaluation["mode"].upper() if evaluation["mode"] else "No Policy"),
        "Enforcement : %s" % str(evaluation["enforcement"]).upper(),
        "",
    ]
    for key, label in (
        ("source", "Source"),
        ("destination", "Destination"),
        ("service", "Service"),
        ("permission", "Permission"),
        ("path", "Path"),
    ):
        if key in selectors and selectors[key] is not None:
            lines.append("%-12s: %s" % (label, selectors[key]))
    lines.append("")
    lines.append("Matched Rules:")
    if evaluation["matched_rules"]:
        for name in evaluation["matched_rules"]:
            lines.append("  %s" % name)
    else:
        lines.append("  (none)")
    lines.extend(["", "Effective Result:", "  %s" % evaluation["result"]])
    reason = evaluation.get("reason")
    if reason:
        lines.extend(["", "Reason:", "  %s" % reason])
    member_results = evaluation.get("member_results") or []
    if member_results:
        lines.extend(["", "Member Results:"])
        for item in member_results:
            rules = list(item.get("matched_rules") or [])
            rule_suffix = (" [%s]" % ", ".join(rules)) if rules else ""
            if "permission" in item:
                lines.append(
                    "  permission=%s => %s%s"
                    % (item.get("permission"), item.get("result"), rule_suffix)
                )
            else:
                lines.append(
                    "  source=%s destination=%s service=%s => %s%s"
                    % (
                        item.get("source"),
                        item.get("destination"),
                        item.get("service"),
                        item.get("result"),
                        rule_suffix,
                    )
                )
    if evaluation.get("path_required"):
        lines.extend(
            [
                "",
                "Note:",
                "  Provide path <PATH> to evaluate file permission against path scopes.",
            ]
        )
    if remote_service:
        lines.extend(
            [
                "",
                "Remote Service:",
                "  %s" % remote_service.get("name", "-"),
                "",
                "Status:",
                "  %s" % remote_service.get("status", "-"),
                "",
                "Policy Result:",
                "  %s" % evaluation["result"],
                "",
                "Connectivity Result:",
                "  %s"
                % (
                    "AVAILABLE"
                    if remote_service.get("status") == "HEALTHY"
                    else "UNAVAILABLE"
                ),
            ]
        )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# AI Access
# ---------------------------------------------------------------------------


def set_ai_access_rule(
    plane_db,
    name: str,
    *,
    mode: Optional[str] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    permission: Optional[str] = None,
    paths: Optional[list[str]] = None,
    enabled: Optional[bool] = None,
    oneshot: bool = False,
    confirm: Optional[bool] = None,
) -> dict:
    name = validate_public_name(name, "Rule name")
    existing = plane_db.conn.execute(
        "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()
    if oneshot and existing is None:
        missing = []
        if source is None:
            missing.append("source")
        if destination is None:
            missing.append("destination")
        if permission is None:
            missing.append("permission")
        if enabled is None:
            missing.append("enabled|disabled")
        pol = get_access_policy(plane_db, "ai")
        if pol["mode"] is None and mode is None:
            missing.append("mode blacklist|whitelist")
        if missing:
            raise ControlPlaneError(
                "ERROR:\nAI Access rule is incomplete.\n\nMissing:\n%s\n\nNo changes were applied."
                % ("\n".join("  %s" % m for m in missing))
            )
    if source is not None:
        principal = plane_db.get_principal(source)
        if not principal:
            raise ControlPlaneError(
                cli_error(
                    "Required AI Identity '%s' does not exist." % source,
                    next_step="Authenticate/bind the AI Identity first.",
                )
            )
        status = str(principal["credential_status"] or "").lower()
        if status not in ("verified", "active"):
            raise ControlPlaneError(
                "ERROR:\nAI Identity '%s' is not VERIFIED.\n\n"
                "Authentication is required before AI Access authorization.\n\n"
                "No changes were applied." % source
            )
    if destination is not None:
        try:
            plane_db.resolve_ref(destination)
        except ControlPlaneError:
            raise ControlPlaneError(
                cli_error("Required Network Object '%s' does not exist." % destination)
            ) from None
    if permission is not None:
        expand_permissions(plane_db, permission)

    def write():
        ensure_policy_mode(plane_db, "ai", mode, oneshot=oneshot and existing is None)
        now = utc_now_iso()
        if existing is None:
            rid = _new_id("air")
            plane_db.conn.execute(
                "INSERT INTO ai_policy_rules"
                "(id, name, enabled, source_identity_id, destination_ref_kind, destination_ref_id, "
                "permission_ref_kind, permission_ref_id, description, row_version, created_at, updated_at) "
                "VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL, '', 1, ?, ?)",
                (rid, name, 1 if enabled else 0, now, now),
            )
            rule_id = rid
            op = "create"
        else:
            rule_id = existing["id"]
            if enabled is not None:
                plane_db.conn.execute(
                    "UPDATE ai_policy_rules SET enabled = ?, row_version = row_version + 1, updated_at = ? WHERE id = ?",
                    (1 if enabled else 0, now, rule_id),
                )
            op = "update"
        if source is not None:
            principal = plane_db.get_principal(source)
            plane_db.conn.execute(
                "UPDATE ai_policy_rules SET source_identity_id = ?, updated_at = ? WHERE id = ?",
                (principal["id"], now, rule_id),
            )
        if destination is not None:
            kind, ref = plane_db.resolve_ref(destination)
            plane_db.conn.execute(
                "UPDATE ai_policy_rules SET destination_ref_kind = ?, destination_ref_id = ?, updated_at = ? WHERE id = ?",
                (kind, ref["id"], now, rule_id),
            )
        if permission is not None:
            kind, pref = resolve_permission_ref(plane_db, permission)
            plane_db.conn.execute(
                "UPDATE ai_policy_rules SET permission_ref_kind = ?, "
                "permission_ref_id = ?, updated_at = ? WHERE id = ?",
                (kind, pref["id"], now, rule_id),
            )
        # Omitted paths preserve existing scopes on edit; explicit list (including
        # empty) replaces. Create with omit leaves scopes empty (fail-closed).
        if paths is not None:
            _replace_ai_policy_path_scopes(plane_db, rule_id, paths)
        return {"entity": {"type": "ai-access", "id": rule_id, "name": name}, "operation": op}

    impact = None
    if (
        enabled is False
        and existing is not None
        and bool(existing["enabled"])
    ):
        impact = last_enabled_rule_mutation_impact(
            plane_db, "ai", name, disabling=True
        )
    elif existing is not None:
        impact = ai_access_rule_update_security_impact(
            plane_db,
            name,
            source=source,
            destination=destination,
            permission=permission,
            paths=paths,
            enabled=enabled,
        )

    return plane_db._mutate(
        "set ai-access %s" % name,
        "set ai access rule",
        write,
        impact=impact,
        confirm=confirm,
    )


def unset_ai_access_rule(
    plane_db, name: str, *, confirm: Optional[bool] = None
) -> dict:
    name = validate_public_name(name, "Rule name")
    row = plane_db.conn.execute(
        "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()
    if not row:
        raise ControlPlaneError(cli_error("Rule '%s' was not found." % name))

    def write():
        plane_db.conn.execute("DELETE FROM ai_policy_rules WHERE id = ?", (row["id"],))
        return {
            "entity": {"type": "ai-access", "id": row["id"], "name": name},
            "operation": "delete",
        }

    impact = last_enabled_rule_mutation_impact(
        plane_db, "ai", name, disabling=False
    )
    return plane_db._mutate(
        "unset ai-access %s" % name,
        "delete ai access rule",
        write,
        impact=impact,
        confirm=confirm,
    )


def evaluate_ai_access_v24(
    plane_db,
    *,
    identity: str,
    destination: str,
    permission: str,
) -> dict:
    pol = get_access_policy(plane_db, "ai")
    principal = plane_db.get_principal(identity)
    if not principal:
        return {
            "mode": pol["mode"],
            "enforcement": pol["enforcement"],
            "matched_rules": [],
            "result": "DENY",
            "plane": "ai",
            "auth": "UNAUTHENTICATED",
        }
    # Display name / pending shell alone is never authenticated.
    status = str(principal["credential_status"] or "").lower()
    auth_ok = status in ("verified", "active") and bool(principal["enabled"])
    if not auth_ok:
        return {
            "mode": pol["mode"],
            "enforcement": pol["enforcement"],
            "matched_rules": [],
            "result": "DENY",
            "plane": "ai",
            "auth": "UNAUTHENTICATED",
        }
    wanted_perms = expand_permissions(plane_db, permission) if get_permission_object(plane_db, permission) or get_permission_group(plane_db, permission) else {permission}
    matched = []
    for row in plane_db.conn.execute("SELECT * FROM ai_policy_rules WHERE enabled = 1 ORDER BY name"):
        if row["source_identity_id"] != principal["id"]:
            continue
        if not _ref_name_match(plane_db, row["destination_ref_kind"], row["destination_ref_id"], destination):
            continue
        if row["permission_ref_kind"] == "permission_object":
            perms = {
                r["permission"]
                for r in plane_db.conn.execute(
                    "SELECT permission FROM permission_object_members WHERE permission_object_id = ?",
                    (row["permission_ref_id"],),
                )
            }
        else:
            perms = set()
            for mid in plane_db.conn.execute(
                "SELECT permission_object_id FROM permission_group_members WHERE group_id = ?",
                (row["permission_ref_id"],),
            ):
                for r in plane_db.conn.execute(
                    "SELECT permission FROM permission_object_members WHERE permission_object_id = ?",
                    (mid["permission_object_id"],),
                ):
                    perms.add(r["permission"])
        if wanted_perms & perms or permission.lower() in {p.lower() for p in perms}:
            matched.append(row["name"])
    # Policy enforcement disabled => ALLOW only after authentication succeeds.
    result = effective_policy_result(pol["mode"], pol["enforcement"], bool(matched))
    return {
        "mode": pol["mode"],
        "enforcement": pol["enforcement"],
        "matched_rules": matched,
        "result": result,
        "plane": "ai",
        "auth": "VERIFIED",
    }


def list_ai_policy_path_scopes(plane_db, rule_name: str) -> list[str]:
    row = plane_db.conn.execute(
        "SELECT id FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (rule_name,)
    ).fetchone()
    if not row:
        return []
    return [
        r["pattern"]
        for r in plane_db.conn.execute(
            "SELECT pattern FROM ai_policy_path_scopes WHERE rule_id = ? ORDER BY pattern COLLATE NOCASE",
            (row["id"],),
        )
    ]


def _normalize_path_scope_patterns(patterns: Optional[list[str]]) -> list[str]:
    cleaned: list[str] = []
    seen = set()
    for raw in patterns or []:
        text = str(raw or "").strip()
        if not text or text in ("-", "none"):
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(text)
    return cleaned


def _replace_ai_policy_path_scopes(plane_db, rule_id: str, patterns: list[str]) -> list[str]:
    cleaned = _normalize_path_scope_patterns(patterns)
    plane_db.conn.execute("DELETE FROM ai_policy_path_scopes WHERE rule_id = ?", (rule_id,))
    for pattern in cleaned:
        plane_db.conn.execute(
            "INSERT INTO ai_policy_path_scopes(rule_id, pattern) VALUES (?, ?)",
            (rule_id, pattern),
        )
    return cleaned


def set_ai_policy_path_scopes(plane_db, rule_name: str, patterns: list[str]) -> list[str]:
    """Bind canonical path scopes to an AI Access rule.

    Public v2.4 CLI / Wizard / ConfigurationBundle use the ``paths`` field on
    ``set ai-access`` / Bundle rules. This helper remains for direct callers
    (tests, exact translation). MCP file capabilities fail closed when no
    scopes are bound.
    """
    ensure_v2_schema(plane_db.conn)
    row = plane_db.conn.execute(
        "SELECT id FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (rule_name,)
    ).fetchone()
    if not row:
        raise ControlPlaneError(cli_error("Rule '%s' was not found." % rule_name))
    cleaned = _replace_ai_policy_path_scopes(plane_db, row["id"], patterns)
    _commit_if_autonomous(plane_db)
    return cleaned


def parse_ai_paths_field(raw: Optional[str]) -> list[str]:
    """Parse public CLI ``paths`` value into a replacement list.

    Empty / ``-`` / ``none`` mean explicit clear (replace with no scopes).
    """
    text = str(raw or "").strip()
    if not text or text.lower() in ("-", "none"):
        return []
    return parse_csv_list(text)


def permission_includes_file_capability(plane_db, permission: str) -> bool:
    try:
        wanted = (
            expand_permissions(plane_db, permission)
            if get_permission_object(plane_db, permission) or get_permission_group(plane_db, permission)
            else {str(permission or "").strip().lower()}
        )
    except ControlPlaneError:
        wanted = {str(permission or "").strip().lower()}
    return bool(wanted & FILE_PERMISSIONS)


def _test_ai_access_atomic_v24(
    plane_db,
    *,
    identity: str,
    destination: str,
    permission: str,
    path: Optional[str] = None,
) -> dict:
    """Public AI Access test for one Permission Object or atomic permission."""
    evaluation = evaluate_ai_access_v24(
        plane_db,
        identity=identity,
        destination=destination,
        permission=permission,
    )
    evaluation = dict(evaluation)
    evaluation["path"] = path
    evaluation["path_required"] = False
    if not permission_includes_file_capability(plane_db, permission):
        return evaluation
    if evaluation.get("result") != "ALLOW":
        return evaluation
    if path is None or not str(path).strip():
        evaluation["result"] = "DENY"
        evaluation["path_required"] = True
        evaluation["reason"] = (
            "file permission requires path context; "
            "runtime DENYs without a concrete in-scope path"
        )
        return evaluation
    # Map tested permission atoms to a representative file capability.
    try:
        wanted = (
            expand_permissions(plane_db, permission)
            if get_permission_object(plane_db, permission) or get_permission_group(plane_db, permission)
            else {str(permission or "").strip().lower()}
        )
    except ControlPlaneError:
        wanted = {str(permission or "").strip().lower()}
    file_perm = next((p for p in sorted(wanted) if p in FILE_PERMISSIONS), None)
    if not file_perm:
        return evaluation
    caps = PERMISSION_TO_CAPS.get(file_perm) or ()
    if not caps:
        return evaluation
    auth = authorize_ai_capability_v24(
        plane_db,
        identity=identity,
        destination=destination,
        capability=caps[0],
        operand=str(path).strip(),
    )
    evaluation["result"] = str(auth.get("action") or "DENY").upper()
    evaluation["reason"] = auth.get("reason")
    evaluation["matched_rules"] = list(auth.get("matched_rules") or evaluation.get("matched_rules") or [])
    evaluation["patterns"] = list(auth.get("patterns") or [])
    evaluation["auth"] = auth.get("auth") or evaluation.get("auth")
    return evaluation


def test_ai_access_v24(
    plane_db,
    *,
    identity: str,
    destination: str,
    permission: str,
    path: Optional[str] = None,
) -> dict:
    """Public ``test ai-access`` decision, path-aware for file permissions.

    Permission Objects and atomic permissions keep evaluate_ai_access_v24()
    semantics. Permission Groups expand to atomic permissions and aggregate:
    top-level ALLOW only when every atomic member allows. File members retain
    Finding-AA path-aware fail-closed behavior.
    """
    pobj = get_permission_object(plane_db, permission)
    pgrp = get_permission_group(plane_db, permission)
    if pobj is not None and pgrp is not None:
        raise ControlPlaneError(
            _ambiguous_public_name_error(permission, "Permission Object", "Permission Group")
        )
    if pgrp is not None:
        atoms = expand_permissions_ordered(plane_db, permission)
        if not atoms:
            raise ControlPlaneError(
                cli_error("Permission Group '%s' has no members." % permission)
            )
        member_results: list[dict] = []
        matched_union: list[str] = []
        matched_seen = set()
        mode = None
        enforcement = None
        auth = None
        path_required_any = False
        patterns: list[str] = []
        for atom in atoms:
            one = _test_ai_access_atomic_v24(
                plane_db,
                identity=identity,
                destination=destination,
                permission=atom,
                path=path,
            )
            if mode is None:
                mode = one.get("mode")
                enforcement = one.get("enforcement")
                auth = one.get("auth")
            if one.get("path_required"):
                path_required_any = True
            for rule in list(one.get("matched_rules") or []):
                key = str(rule).lower()
                if key in matched_seen:
                    continue
                matched_seen.add(key)
                matched_union.append(rule)
            for pattern in list(one.get("patterns") or []):
                if pattern not in patterns:
                    patterns.append(pattern)
            member_results.append(
                {
                    "permission": atom,
                    "result": one.get("result"),
                    "matched_rules": list(one.get("matched_rules") or []),
                    "path_required": bool(one.get("path_required")),
                    "reason": one.get("reason"),
                }
            )
        aggregate, mixed = _aggregate_group_test_result(member_results)
        out = {
            "mode": mode,
            "enforcement": enforcement,
            "matched_rules": matched_union,
            "result": aggregate,
            "plane": "ai",
            "auth": auth,
            "path": path,
            "path_required": path_required_any and aggregate != "ALLOW",
            "member_results": member_results,
            "group_test": True,
            "mixed": mixed,
            "patterns": patterns,
        }
        if mixed:
            out["reason"] = (
                "mixed permission group member outcomes; aggregate DENY "
                "(ALLOW only when every atomic permission allows)"
            )
        elif path_required_any and aggregate == "DENY":
            out["reason"] = (
                "file permission requires path context; "
                "runtime DENYs without a concrete in-scope path"
            )
        return out

    return _test_ai_access_atomic_v24(
        plane_db,
        identity=identity,
        destination=destination,
        permission=permission,
        path=path,
    )


def _matched_ai_rule_rows(plane_db, matched_names: list[str]) -> list:
    rows = []
    for name in matched_names:
        row = plane_db.conn.execute(
            "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if row:
            rows.append(row)
    return rows


def _path_scopes_for_rules(plane_db, rule_rows) -> list[str]:
    patterns: list[str] = []
    seen = set()
    for row in rule_rows:
        for item in plane_db.conn.execute(
            "SELECT pattern FROM ai_policy_path_scopes WHERE rule_id = ? ORDER BY pattern COLLATE NOCASE",
            (row["id"],),
        ):
            text = str(item["pattern"] or "").strip()
            key = text.lower()
            if not text or key in seen:
                continue
            seen.add(key)
            patterns.append(text)
    return patterns


def authorize_ai_capability_v24(
    plane_db,
    *,
    identity: str,
    destination: str,
    capability: str,
    operand: Optional[str] = None,
) -> dict:
    """Single canonical AI authorization decision for MCP / execution / audit.

    Uses the same evaluate_ai_access_v24() semantics as public ``test ai-access``,
    then applies fail-closed canonical path-scope checks for file capabilities.
    Legacy ``ai_access_rules`` / ``ai_path_scopes`` are never consulted.
    """
    from drlink_control_plane import AI_CAPABILITIES, FILE_CAPABILITIES, path_allowed

    cap = str(capability or "").strip()
    principal = plane_db.get_principal(identity)
    endpoint = plane_db.get_object(destination) if destination else None

    def _decision(
        *,
        action: str,
        evaluation: dict,
        reason: str,
        winner=None,
        patterns: Optional[list[str]] = None,
        path_ok: bool = True,
        permission: Optional[str] = None,
    ) -> dict:
        return {
            "principal": identity,
            "identity": identity,
            "endpoint": destination,
            "destination": destination,
            "capability": cap,
            "permission": permission,
            "operand": operand,
            "action": action,
            "result": action,
            "mode": evaluation.get("mode"),
            "enforcement": evaluation.get("enforcement"),
            "matched_rules": list(evaluation.get("matched_rules") or []),
            "winner": winner,
            "patterns": list(patterns or []),
            "reason": reason,
            "plane": "ai",
            "auth": evaluation.get("auth"),
            "principal_row": principal,
            "endpoint_row": endpoint,
            "exec_timeout": None,
            "path_ok": path_ok,
            "implicit": winner is None and action == "DENY",
            "evaluation": evaluation,
        }

    if cap not in AI_CAPABILITIES:
        empty = {
            "mode": None,
            "enforcement": "enabled",
            "matched_rules": [],
            "result": "DENY",
            "plane": "ai",
            "auth": "UNAUTHENTICATED",
        }
        return _decision(
            action="DENY",
            evaluation=empty,
            reason="unknown capability",
            path_ok=False,
        )

    permission = CAP_TO_PERMISSION.get(cap)
    if not permission:
        empty = {
            "mode": None,
            "enforcement": "enabled",
            "matched_rules": [],
            "result": "DENY",
            "plane": "ai",
            "auth": "UNAUTHENTICATED",
        }
        return _decision(
            action="DENY",
            evaluation=empty,
            reason="unknown capability",
            path_ok=False,
        )

    evaluation = evaluate_ai_access_v24(
        plane_db,
        identity=identity,
        destination=destination,
        permission=permission,
    )
    matched_rows = _matched_ai_rule_rows(plane_db, evaluation.get("matched_rules") or [])
    patterns = _path_scopes_for_rules(plane_db, matched_rows)
    winner = None
    if matched_rows:
        row = matched_rows[0]
        winner = {
            "id": row["id"],
            "name": row["name"],
            "paths": list(patterns),
            "action": evaluation["result"],
        }

    action = str(evaluation.get("result") or "DENY").upper()
    if evaluation.get("auth") == "UNAUTHENTICATED":
        reason = "unknown, disabled or unverified AI Identity"
    elif action == "ALLOW" and matched_rows:
        reason = "AI Access rule %s" % matched_rows[0]["name"]
    elif action == "ALLOW":
        mode = evaluation.get("mode")
        if mode is None:
            reason = "No AI Access policy configured"
        elif str(evaluation.get("enforcement") or "").lower() == "disabled":
            reason = "AI Access enforcement disabled"
        else:
            reason = "AI Access policy ALLOW"
    elif matched_rows:
        reason = "AI Access rule %s" % matched_rows[0]["name"]
    else:
        reason = "implicit DENY"

    path_ok = True
    if action == "ALLOW" and cap in FILE_CAPABILITIES:
        # File capabilities must not become unrestricted filesystem access.
        # Public v2.4 binds scopes via the paths field; missing scopes DENY.
        if not patterns:
            action = "DENY"
            path_ok = False
            reason = "file capability has no canonical path scope"
            if winner is not None:
                winner = dict(winner)
                winner["action"] = "DENY"
        elif not operand:
            action = "DENY"
            path_ok = False
            reason = "file capability requires a path operand"
        elif not path_allowed(str(operand), patterns):
            action = "DENY"
            path_ok = False
            reason = "path is outside allowed scope"

    return _decision(
        action=action,
        evaluation=evaluation,
        reason=reason,
        winner=winner,
        patterns=patterns if action == "ALLOW" else [],
        path_ok=path_ok,
        permission=permission,
    )


# ---------------------------------------------------------------------------
# Remote Service (Agent)
# ---------------------------------------------------------------------------


def _server_reachable(plane_db) -> bool:
    return detect_server_reachable(plane_db)


def detect_server_reachable(plane_db=None, root: Optional[str] = None) -> bool:
    """Real Agent→Server reachability for Remote Service operations.

    Production path probes the configured Server management/control endpoint.
    Local SQLite health is never treated as Server reachability.

    Tests may force the value with DRLINK_SERVER_REACHABLE=0|1 (fault injection
    only). Marker files under the Agent root remain supported for lab isolation.
    """
    forced = os.environ.get("DRLINK_SERVER_REACHABLE")
    if forced is not None:
        return str(forced).strip().lower() in ("1", "yes", "y", "true", "online")
    marker_root = root
    if marker_root is None and plane_db is not None:
        marker_root = getattr(plane_db, "root", None)
    if marker_root:
        offline = Path(marker_root) / "var" / "lib" / "drlink" / "agent-server-offline"
        if offline.exists():
            return False
        online = Path(marker_root) / "var" / "lib" / "drlink" / "agent-server-online"
        if online.exists():
            return True
    endpoint = load_agent_server_endpoint(marker_root)
    if endpoint is None:
        return False
    host, port = endpoint
    return _probe_tcp(host, port, timeout=0.75)


def sync_agent_catalog_from_server(plane_db, server_plane=None, *, root: Optional[str] = None) -> int:
    """Synchronize Agent local catalog from the Server.

    Prefer the live authenticated management path. The optional ``server_plane``
    argument remains for unit fault-injection only (same-process injection).
    """
    import drlink_mgmt_sync as mgmt

    if mgmt.use_live_mgmt_path(root or getattr(plane_db, "root", None)):
        catalog = mgmt.fetch_server_catalog(root or getattr(plane_db, "root", None))
        return mgmt.apply_catalog_to_agent(plane_db, catalog)
    if server_plane is None:
        return 0
    now = utc_now_iso()
    count = 0
    for obj in server_plane.list_objects():
        if obj["type"] not in ("host", "network", "fqdn", "managed_endpoint"):
            continue
        values = server_plane._object_values(obj["id"])
        payload_obj = {
            "name": obj["name"],
            "type": obj["type"],
            "values": values,
            "origin": obj.get("origin"),
            "generation": int(obj.get("row_version") or 1),
            "id": obj["id"],
        }
        if obj["type"] == "managed_endpoint":
            cid = obj.get("client_id")
            if not cid:
                link = server_plane.conn.execute(
                    "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                    (obj["id"],),
                ).fetchone()
                cid = link["client_id"] if link else None
            if cid:
                payload_obj["client_id"] = cid
        payload = json.dumps(payload_obj, sort_keys=True)
        plane_db.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("network-object", obj["name"], payload, now),
        )
        count += 1
    for sobj in server_plane.conn.execute("SELECT id, name, type, port, row_version FROM service_objects"):
        payload = json.dumps(
            {
                "name": sobj["name"],
                "type": sobj["type"],
                "port": int(sobj["port"]),
                "generation": int(sobj["row_version"] or 1),
                "id": sobj["id"],
                "pool_class": "fixed-tcp" if sobj["type"] == "fixed-tcp" else "normal",
            },
            sort_keys=True,
        )
        plane_db.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("service-object", sobj["name"], payload, now),
        )
        count += 1
    _commit_if_autonomous(plane_db)
    return count


def _catalog_payload(plane_db, kind: str, name: str) -> Optional[dict]:
    row = plane_db.conn.execute(
        "SELECT payload FROM agent_object_catalog WHERE kind = ? AND name = ? COLLATE NOCASE",
        (kind, name),
    ).fetchone()
    if not row:
        return None
    try:
        data = json.loads(row["payload"])
    except (TypeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _row_get(row, key: str, default=None):
    if row is None:
        return default
    try:
        keys = row.keys()
    except Exception:
        keys = ()
    if key in keys:
        val = row[key]
        return default if val is None else val
    if isinstance(row, dict):
        return row.get(key, default)
    return default


def _managed_host_client_id_from_name(plane_db, name: str) -> Optional[str]:
    """Resolve a public Managed Host name/label to immutable client_id once."""
    token = str(name or "").strip()
    if not token:
        return None
    obj = plane_db.get_object(token) if hasattr(plane_db, "get_object") else None
    if obj and obj.get("type") == "managed_endpoint":
        cid = obj.get("client_id")
        if cid:
            return str(cid)
        try:
            link = plane_db.conn.execute(
                "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                (obj["id"],),
            ).fetchone()
        except sqlite3.Error:
            link = None
        if link and link["client_id"]:
            return str(link["client_id"])
    catalog = _catalog_payload(plane_db, "network-object", token)
    if catalog and str(catalog.get("type") or "").lower() == "managed_endpoint":
        cid = catalog.get("client_id")
        if cid:
            return str(cid)
    host_catalog = _catalog_payload(plane_db, "managed-host", token)
    if host_catalog and host_catalog.get("id"):
        return str(host_catalog["id"])
    # Catalog may be keyed by current label while we only have client rows locally.
    try:
        client = plane_db.get_client(token) if hasattr(plane_db, "get_client") else None
    except Exception:
        client = None
    if client is not None:
        return str(client["id"])
    return None


def _managed_host_inventory_by_client_id(plane_db, client_id: str) -> Optional[dict]:
    """Authoritative or catalog inventory for a bound Managed Host client_id."""
    cid = str(client_id or "").strip()
    if not cid:
        return None
    # Prefer live Server/Agent control-plane inventory.
    try:
        row = plane_db.conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
    except sqlite3.Error:
        row = None
    if row is not None:
        ep = plane_db.conn.execute(
            "SELECT o.name, o.id AS object_id FROM objects o "
            "JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
            (cid,),
        ).fetchone()
        addresses: list[str] = []
        if ep is not None and hasattr(plane_db, "endpoint_addresses"):
            try:
                addresses = [
                    str(a.get("address") or a)
                    for a in (plane_db.endpoint_addresses(ep["name"]) or [])
                    if (a.get("address") if isinstance(a, dict) else a)
                ]
            except Exception:
                addresses = []
        if not addresses and ep is not None:
            addresses = [str(v) for v in plane_db._object_values(ep["object_id"]) if v]
        return {
            "id": cid,
            "name": (ep["name"] if ep else None) or row["label"] or row["hostname"] or cid,
            "hostname": row["hostname"] or "",
            "label": row["label"] or "",
            "status": row["status"],
            "connected": bool(row["connected"]),
            "trust_status": row["trust_status"] if "trust_status" in row.keys() else None,
            "addresses": addresses,
            "source": "inventory",
        }
    # Fall back to synchronized Agent catalog keyed by client id or public name.
    for kind in ("managed-host", "network-object"):
        for crow in plane_db.conn.execute(
            "SELECT name, payload FROM agent_object_catalog WHERE kind = ?", (kind,)
        ):
            try:
                payload = json.loads(crow["payload"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            if str(payload.get("id") or "").strip() != cid and str(payload.get("client_id") or "").strip() != cid:
                continue
            values = [str(v) for v in (payload.get("values") or payload.get("addresses") or []) if v not in (None, "")]
            return {
                "id": cid,
                "name": payload.get("name") or crow["name"],
                "hostname": payload.get("hostname") or (values[0] if values else ""),
                "label": payload.get("name") or crow["name"],
                "status": payload.get("status"),
                "connected": bool(payload.get("connected")) if payload.get("connected") is not None else True,
                "trust_status": payload.get("trust_status"),
                "addresses": values,
                "source": "catalog",
            }
    return None


def _runtime_target_for_managed_host(inventory: dict) -> tuple[Optional[str], Optional[str]]:
    """Return (target_host, degraded_reason) from bound Managed Host inventory."""
    if not inventory:
        return None, "Bound Managed Host destination is missing or invalid."
    trust = str(inventory.get("trust_status") or "").lower()
    if trust in ("revoked", "untrusted", "denied"):
        return None, "Bound Managed Host destination is revoked or untrusted."
    status = str(inventory.get("status") or "").lower()
    if status in ("retired", "removed", "deleted"):
        return None, "Bound Managed Host destination is retired."
    addresses = [str(a).strip() for a in (inventory.get("addresses") or []) if str(a or "").strip()]
    hostname = str(inventory.get("hostname") or "").strip()
    if addresses:
        return addresses[0], None
    if hostname:
        return hostname, None
    return None, (
        "Bound Managed Host '%s' has no usable hostname or address."
        % (inventory.get("name") or inventory.get("id") or "destination")
    )


def _destination_dependency_status(
    plane_db,
    destination: str,
    *,
    root: Optional[str] = None,
    destination_client_id: Optional[str] = None,
) -> Optional[str]:
    """Return a DEGRADED reason if destination dependency is missing/changed; else None."""
    identity = load_agent_identity(root or getattr(plane_db, "root", None))
    self_id = str(identity.get("machine_id") or "").strip()
    bound = str(destination_client_id or "").strip()
    if bound:
        # Offline-created this-host/self persists the local Agent machine_id as
        # destination_client_id. That is a valid self destination and must not
        # require external Managed Host inventory before reconnect can allocate.
        if self_id and bound == self_id:
            return None
        inventory = _managed_host_inventory_by_client_id(plane_db, bound)
        if inventory is None:
            return (
                "Bound Managed Host destination (client_id=%s) is missing or invalid after reconnect."
                % bound[:12]
            )
        _target, reason = _runtime_target_for_managed_host(inventory)
        return reason
    dest = str(destination or "").strip()
    if not dest:
        return "Remote Service destination is missing after reconnect."
    if dest.lower() in ("this-host", "this_host", "self"):
        return None
    host_name = identity.get("hostname") or identity.get("label") or ""
    if host_name and dest.lower() == host_name.lower():
        return None
    obj = plane_db.get_object(dest) if hasattr(plane_db, "get_object") else None
    catalog = _catalog_payload(plane_db, "network-object", dest)
    host_catalog = _catalog_payload(plane_db, "managed-host", dest)
    if obj is None and catalog is None and host_catalog is None:
        return (
            "Required Network Object / Managed Host destination '%s' is missing or invalid after reconnect."
            % dest
        )
    if catalog:
        ctype = str(catalog.get("type") or "").lower()
        if ctype == "network":
            return (
                "Required destination '%s' is a CIDR Network Object and is not a valid single target after reconnect."
                % dest
            )
        values = catalog.get("values")
        if isinstance(values, list) and len(values) == 0:
            return (
                "Required Network Object / Managed Host destination '%s' has no address values after reconnect."
                % dest
            )
    if obj is not None and obj.get("type") == "network":
        return (
            "Required destination '%s' is a CIDR Network Object and is not a valid single target after reconnect."
            % dest
        )
    return None


def _service_dependency_status(plane_db, svc_name: str) -> Optional[str]:
    sobj = get_service_object(plane_db, svc_name)
    catalog = _catalog_payload(plane_db, "service-object", svc_name)
    if not sobj and not catalog:
        return "Required Service Object '%s' is missing or invalid after reconnect." % svc_name
    # Prefer synchronized Server catalog when present (authoritative after reconnect).
    meta = catalog if catalog is not None else sobj
    stype = str(meta.get("type") if isinstance(meta, dict) else meta["type"]).lower()
    if stype == "udp":
        return (
            "Required Service Object '%s' uses UDP; Remote Service supports TCP and Fixed TCP only."
            % svc_name
        )
    try:
        port = int(meta.get("port") if isinstance(meta, dict) else meta["port"])
    except (TypeError, ValueError, KeyError):
        return "Required Service Object '%s' is missing a valid port after reconnect." % svc_name
    if port < 1 or port > 65535:
        return "Required Service Object '%s' has an invalid port after reconnect." % svc_name
    return None


def _push_agent_remote_service_status(plane_db, *, root: Optional[str] = None, names: Optional[list] = None) -> int:
    """Tell the Server the Agent's effective Remote Service status. Never allocates.

    The authenticated Server response is the endpoint-ownership authority. Agent
    local canonical fields are reconciled from that response.
    """
    try:
        import drlink_mgmt_sync as mgmt
    except Exception:
        return 0
    target_root = root or getattr(plane_db, "root", None)
    try:
        if not mgmt.use_live_mgmt_path(target_root):
            return 0
    except Exception:
        return 0
    items = []
    rows = plane_db.conn.execute("SELECT * FROM agent_remote_services WHERE delete_pending = 0")
    for row in rows:
        if names is not None and row["name"] not in names:
            continue
        status = str(row["status"] or "DEGRADED").upper()
        if status not in ("HEALTHY", "DEGRADED", "DISABLED"):
            status = "DEGRADED"
        items.append(
            {
                "name": row["name"],
                "status": status,
                "reason": str(row["reason"] or ""),
                "runtime_verified": status == "HEALTHY",
                "endpoint_port": row["endpoint_port"],
            }
        )
    if not items:
        return 0
    try:
        result = mgmt.report_remote_service_status_on_server(root=target_root, services=items)
    except Exception:
        return 0
    return _reconcile_agent_from_server_status(plane_db, result)


def _reconcile_agent_from_server_status(plane_db, result: dict) -> int:
    """Converge Agent local endpoint projection with authenticated Server state."""
    if not isinstance(result, dict):
        return 0
    items = result.get("services") or result.get("updated") or []
    if not isinstance(items, list):
        return 0
    changed = 0
    now = utc_now_iso()
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        row = plane_db.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE AND delete_pending = 0",
            (name,),
        ).fetchone()
        if row is None:
            continue
        assignments = []
        values = []
        if "endpoint_port" in item:
            raw = item.get("endpoint_port")
            if raw is None or raw == "":
                new_port = None
            else:
                try:
                    new_port = int(raw)
                except (TypeError, ValueError):
                    continue
            if row["endpoint_port"] != new_port:
                assignments.append("endpoint_port = ?")
                values.append(new_port)
            if new_port is None:
                new_pending = 1
            elif "pending_allocation" in item:
                try:
                    new_pending = 1 if int(item.get("pending_allocation") or 0) else 0
                except (TypeError, ValueError):
                    new_pending = 0
            else:
                new_pending = 0
            if int(row["pending_allocation"] or 0) != int(new_pending):
                assignments.append("pending_allocation = ?")
                values.append(int(new_pending))
        if "status" in item:
            status = str(item.get("status") or "").strip().upper()
            if status in ("HEALTHY", "DEGRADED", "DISABLED") and str(row["status"] or "") != status:
                assignments.append("status = ?")
                values.append(status)
        if "reason" in item:
            reason = str(item.get("reason") or "")
            if str(row["reason"] or "") != reason:
                assignments.append("reason = ?")
                values.append(reason)
        if not assignments:
            continue
        assignments.append("updated_at = ?")
        values.append(now)
        values.append(name)
        plane_db.conn.execute(
            "UPDATE agent_remote_services SET %s WHERE name = ? COLLATE NOCASE"
            % ", ".join(assignments),
            tuple(values),
        )
        changed += 1
    if changed and not getattr(plane_db, "_batch_mode", False):
        _commit_if_autonomous(plane_db)
    return changed


def _collect_degraded_remote_services(plane_db) -> list[dict]:
    rows = []
    for row in plane_db.conn.execute(
        "SELECT name, reason FROM agent_remote_services WHERE delete_pending = 0 AND status = 'DEGRADED' ORDER BY name"
    ):
        rows.append({"name": row["name"], "reason": str(row["reason"] or "").strip()})
    return rows


def format_synchronize_result(result: dict) -> str:
    status = str(result.get("status") or "SYNCHRONIZED").upper()
    affected = list(result.get("affected") or [])
    if status == "OFFLINE":
        return "Synchronization OFFLINE. DRLink Server is currently unreachable.\n"
    if status != "DEGRADED":
        return "Synchronization %s (%s Remote Service(s) updated).\n" % (
            status,
            result.get("updated", 0),
        )
    lines = ["Synchronization DEGRADED.", ""]
    if affected:
        lines.append("Affected:")
        for item in affected:
            reason = str(item.get("reason") or "").strip() or "Requires operator attention."
            lines.append("  %s — %s" % (item.get("name"), reason))
        lines.append("")
    runtime_error = str(result.get("runtime_error") or "").strip()
    if runtime_error and not affected:
        lines.append(runtime_error)
        lines.append("")
    first = (affected[0].get("name") if affected else "") or ""
    if first:
        lines.extend(["Use:", "  show remote-service %s" % first])
    else:
        lines.extend(["Use:", "  show remote-services"])
    return "\n".join(lines) + "\n"


def synchronize_agent_remote_services(plane_db, *, root: Optional[str] = None) -> dict:
    """Reconnect synchronization: allocate pending endpoints, apply deletes, revalidate deps."""
    # Enrollment projection is a lifecycle write. show/status must not do it.
    projected = project_enrolled_services_into_agent_catalog(plane_db, root=root)
    # Every bootstrap seed name is protected, not only rows created this pass.
    # Otherwise a later synchronize would reapply stale client-state through
    # v2.4 revalidation and undo an operator edit.
    enrolled_names = _bootstrap_seed_names(root)
    if not detect_server_reachable(plane_db, root):
        return {
            "status": "OFFLINE",
            "updated": len(projected),
            "projected": len(projected),
        }
    import drlink_mgmt_sync as mgmt

    # Always refresh catalog when a live management path exists.
    # A management failure must not wipe desired state, but it must not
    # report SYNCHRONIZED either.
    catalog_error = ""
    try:
        if mgmt.use_live_mgmt_path(root or getattr(plane_db, "root", None)):
            sync_agent_catalog_from_server(plane_db, root=root)
    except Exception as exc:
        catalog_error = str(exc).strip()

    def _finish(result: dict) -> dict:
        if not catalog_error:
            return result
        out = dict(result)
        if str(out.get("status") or "").upper() == "SYNCHRONIZED":
            out["status"] = "DEGRADED"
        if not str(out.get("runtime_error") or "").strip():
            out["runtime_error"] = catalog_error
        return out

    updated = 0
    # Defer runtime restarts to a single apply at the end of this synchronize.
    prev_batch = bool(getattr(plane_db, "_batch_mode", False))
    plane_db._batch_mode = True
    try:
        # Process delete_pending tombstones
        for row in list(
            plane_db.conn.execute("SELECT * FROM agent_remote_services WHERE delete_pending = 1")
        ):
            try:
                unset_remote_service_agent(plane_db, row["name"], root=root, server_reachable=True)
            except ControlPlaneError as exc:
                plane_db.conn.execute(
                    "UPDATE agent_remote_services SET status = 'DEGRADED', reason = ?, updated_at = ? "
                    "WHERE name = ?",
                    (str(exc).split("\n", 2)[1] if "\n" in str(exc) else str(exc), utc_now_iso(), row["name"]),
                )
                _commit_if_autonomous(plane_db)
            updated += 1
        # Revalidate + activate remaining services
        for row in list(
            plane_db.conn.execute("SELECT * FROM agent_remote_services WHERE delete_pending = 0")
        ):
            # Bootstrap names are seeds. An existing or just-seeded row is
            # authoritative and must not be rewritten from client-state.
            if str(row["name"] or "").strip().lower() in enrolled_names:
                updated += 1
                continue
            svc_name = row["service_object"]
            dest_reason = _destination_dependency_status(
                plane_db,
                row["destination"],
                root=root,
                destination_client_id=_row_get(row, "destination_client_id"),
            )
            svc_reason = _service_dependency_status(plane_db, svc_name)
            reason = dest_reason or svc_reason
            if reason:
                plane_db.conn.execute(
                    "UPDATE agent_remote_services SET status = 'DEGRADED', reason = ?, updated_at = ? "
                    "WHERE name = ?",
                    (reason, utc_now_iso(), row["name"]),
                )
                _commit_if_autonomous(plane_db)
                updated += 1
                continue
            # Re-apply to allocate pending endpoints / refresh HEALTHY
            try:
                set_remote_service_agent(
                    plane_db,
                    row["name"],
                    destination=row["destination"],
                    service=row["service_object"],
                    enabled=bool(row["enabled"]),
                    oneshot=True,
                    root=root,
                    server_reachable=True,
                )
            except ControlPlaneError as exc:
                msg = str(exc)
                brief = msg
                if msg.startswith("ERROR:\n"):
                    brief = msg[7:].split("\n\n")[0]
                plane_db.conn.execute(
                    "UPDATE agent_remote_services SET status = 'DEGRADED', reason = ?, updated_at = ? "
                    "WHERE name = ?",
                    (brief, utc_now_iso(), row["name"]),
                )
                _commit_if_autonomous(plane_db)
            updated += 1
    finally:
        plane_db._batch_mode = prev_batch
    # Reconcile endpoint ownership with Server before runtime projection so a
    # stale Agent claim cannot keep advertising or activating a revoked port.
    _push_agent_remote_service_status(plane_db, root=root)
    # Final runtime reconciliation for all desired services.
    try:
        import drlink_v24_runtime as runtime

        applied = runtime.apply_agent_runtime(plane_db, root=root)
        if not applied.get("ok") and not applied.get("skipped"):
            runtime.mark_runtime_status(
                plane_db, ok=False, reason=applied.get("error") or "Runtime activation failed"
            )
            _push_agent_remote_service_status(plane_db, root=root)
            affected = _collect_degraded_remote_services(plane_db)
            return _finish({
                "status": "DEGRADED",
                "updated": updated,
                "affected": affected,
                "runtime_error": applied.get("error") or "Runtime activation failed",
            })
        # skipped=True is the DRLINK_SKIP_ACTIVATION unit-test shortcut; treat it
        # as verified the same way set_remote_service_agent does, so reconnect
        # sync can promote runtime-pending rows to HEALTHY.
        if applied.get("ok") or applied.get("skipped"):
            runtime.mark_runtime_status(plane_db, ok=True)
    except Exception as exc:
        _push_agent_remote_service_status(plane_db, root=root)
        affected = _collect_degraded_remote_services(plane_db)
        return _finish({
            "status": "DEGRADED",
            "updated": updated,
            "affected": affected,
            "runtime_error": str(exc),
        })
    _push_agent_remote_service_status(plane_db, root=root)
    affected = _collect_degraded_remote_services(plane_db)
    return _finish({
        "status": "DEGRADED" if affected else "SYNCHRONIZED",
        "updated": updated,
        "affected": affected,
    })


def allocate_endpoint_port(plane_db, client_id: str, service_name: str, pool_class: str) -> int:
    """Allocate an endpoint for local/test paths.

    Production online allocation must go through the FRP Allocator registry.
    This helper still consults any local registry projection and OS bind state
    so unit tests and offline-adjacent paths cannot ignore legacy ports.
    """
    with _ENDPOINT_ALLOC_LOCK:
        used = {r[0] for r in plane_db.conn.execute("SELECT public_port FROM port_reservations WHERE released = 0")}
        used |= {
            r[0]
            for r in plane_db.conn.execute(
                "SELECT public_port FROM published_services WHERE public_port IS NOT NULL AND released = 0"
            )
        }
        # Merge authoritative registry used ports when present under the plane root.
        root = getattr(plane_db, "root", None)
        base = Path(root) if root else Path("/")
        for rel in (
            "var/lib/drlink/runtime/client-inventory.json",
            "var/lib/drlink/registry.json",
        ):
            path = base / rel
            if not path.is_file():
                continue
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(state, dict):
                continue
            for item in state.get("reserved") or []:
                try:
                    used.add(int(item))
                except (TypeError, ValueError):
                    pass
            for client in (state.get("clients") or {}).values():
                if not isinstance(client, dict):
                    continue
                for svc in (client.get("services") or {}).values():
                    if not isinstance(svc, dict):
                        continue
                    try:
                        port = int(svc.get("remote_port"))
                    except (TypeError, ValueError):
                        continue
                    used.add(port)
        protected = set()
        try:
            import frp_infrastructure_ports as infra

            cfg_path = base / "etc/drlink/config.json"
            cfg = {}
            if cfg_path.is_file():
                try:
                    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    cfg = {}
            protected = set(infra.infrastructure_ports(cfg if isinstance(cfg, dict) else {}))
            if pool_class == "fixed-tcp":
                start, end = infra.tcp_relay_port_range(cfg if isinstance(cfg, dict) else {})
            else:
                start, end = infra.service_port_range(cfg if isinstance(cfg, dict) else {})
        except Exception:
            start, end = (
                (FIXED_PORT_START, FIXED_PORT_END)
                if pool_class == "fixed-tcp"
                else (NORMAL_PORT_START, NORMAL_PORT_END)
            )

        def _os_free(port: int) -> bool:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", int(port)))
                return True
            except OSError:
                return False
            finally:
                s.close()

        for port in range(int(start), int(end) + 1):
            if port in used or port in protected:
                continue
            if not _os_free(port):
                continue
            plane_db.conn.execute(
                "INSERT OR REPLACE INTO port_reservations(public_port, client_id, service_id, service_name, released, created_at) "
                "VALUES (?, ?, '', ?, 0, ?)",
                (port, client_id, service_name, utc_now_iso()),
            )
            if not getattr(plane_db, "_batch_mode", False):
                _commit_if_autonomous(plane_db)
            return port
        label = "Fixed TCP" if pool_class == "fixed-tcp" else "Remote Service"
        raise ControlPlaneError(
            "ERROR:\nNo %s ports are available.\n\nNo changes were applied." % label
        )


def set_remote_service_agent(
    plane_db,
    name: str,
    *,
    destination: Optional[str] = None,
    service: Optional[str] = None,
    enabled: Optional[bool] = None,
    oneshot: bool = False,
    root: Optional[str] = None,
    server_reachable: bool = True,
) -> dict:
    name = validate_public_name(name, "Remote Service name")
    identity = load_agent_identity(root)
    host_name = identity.get("hostname") or identity.get("label") or "this-host"
    existing = plane_db.conn.execute(
        "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()
    if oneshot and existing is None:
        missing = []
        if destination is None:
            missing.append("destination")
        if service is None:
            missing.append("service")
        if enabled is None:
            missing.append("enabled|disabled")
        if missing:
            raise ControlPlaneError(
                "ERROR:\nRemote Service is incomplete.\n\nMissing:\n%s\n\nNo changes were applied."
                % ("\n".join("  %s" % m for m in missing))
            )
    dest = destination if destination is not None else (existing["destination"] if existing else None)
    svc_name = service if service is not None else (existing["service_object"] if existing else None)
    en = enabled if enabled is not None else (bool(existing["enabled"]) if existing else True)
    if dest is None or svc_name is None:
        raise ControlPlaneError("Interactive Remote Service wizard requires a TTY session")

    # Refresh synchronized Managed Host inventory before binding/resolving so
    # runtime targets follow current hostname/address for a stable client_id.
    if server_reachable:
        try:
            import drlink_mgmt_sync as mgmt

            if mgmt.use_live_mgmt_path(root):
                sync_agent_catalog_from_server(plane_db, root=root)
        except Exception:
            pass

    # Resolve destination single-target
    dest_token = str(dest).strip()
    destination_client_id = None
    existing_dest_client_id = str(_row_get(existing, "destination_client_id") or "").strip() or None
    existing_dest_name = str(existing["destination"] if existing else "")
    self_machine_id = str(identity.get("machine_id") or "").strip() or None
    bound_inventory = None
    destination_identity_reason = None

    if dest_token.lower() in ("this-host", "this_host", "self"):
        dest_token = host_name
        relay = False
        target_mode = "self"
        target_host = "127.0.0.1"
        destination_client_id = self_machine_id
    else:
        # Preserve an existing immutable Managed Host bind unless the operator
        # explicitly changes the destination token to a different value.
        explicit_retarget = (
            destination is not None
            and existing is not None
            and existing_dest_client_id
            and dest_token.lower() != existing_dest_name.lower()
        )
        if existing_dest_client_id and not explicit_retarget:
            destination_client_id = existing_dest_client_id
            bound_inventory = _managed_host_inventory_by_client_id(plane_db, destination_client_id)
            if bound_inventory:
                dest_token = str(bound_inventory.get("name") or dest_token)
            elif not (self_machine_id and destination_client_id == self_machine_id):
                # External Managed Host bind with missing inventory remains fail-closed.
                # Self binds (destination_client_id == local machine_id) are valid without
                # a clients/catalog inventory row — e.g. offline-created this-host.
                destination_identity_reason = (
                    "Bound Managed Host destination (client_id=%s) is missing or invalid."
                    % destination_client_id[:12]
                )
        relay = True
        target_mode = "routed"
        target_host = dest_token
        # Validate single target (groups / CIDR / ordinary objects)
        grp = plane_db.get_object_group(dest_token) if hasattr(plane_db, "get_object_group") else None
        if grp is None:
            try:
                grp = plane_db.conn.execute(
                    "SELECT * FROM object_groups WHERE name = ? COLLATE NOCASE", (dest_token,)
                ).fetchone()
            except sqlite3.Error:
                grp = None
        if grp and destination_client_id is None:
            members = plane_db._expand_group_members(grp["id"], set())
            if len(members) != 1:
                raise ControlPlaneError(
                    "ERROR:\nRemote Service destination must resolve to a single target.\n\n"
                    "Network Group '%s' contains multiple targets.\n\n"
                    "No changes were applied." % dest_token
                )
            dest_token = members[0]["name"]
        obj = plane_db.get_object(dest_token) if hasattr(plane_db, "get_object") else None
        if obj and obj["type"] == "network" and destination_client_id is None:
            raise ControlPlaneError(
                "ERROR:\nRemote Service destination must resolve to a single target.\n\n"
                "CIDR Network Object '%s' is not allowed.\n\n"
                "No changes were applied." % dest_token
            )
        if destination_client_id is None:
            # Fresh bind / explicit retarget: resolve Managed Host by public name once.
            if obj and obj["type"] == "managed_endpoint":
                destination_client_id = _managed_host_client_id_from_name(plane_db, dest_token)
            else:
                catalog = _catalog_payload(plane_db, "network-object", dest_token)
                if catalog and str(catalog.get("type") or "").lower() == "managed_endpoint":
                    destination_client_id = (
                        str(catalog["client_id"]) if catalog.get("client_id") else None
                    )
                elif _catalog_payload(plane_db, "managed-host", dest_token):
                    destination_client_id = _managed_host_client_id_from_name(plane_db, dest_token)
            if destination_client_id:
                bound_inventory = _managed_host_inventory_by_client_id(
                    plane_db, destination_client_id
                )
                if bound_inventory:
                    dest_token = str(bound_inventory.get("name") or dest_token)

        if destination_client_id:
            if bound_inventory is None:
                bound_inventory = _managed_host_inventory_by_client_id(
                    plane_db, destination_client_id
                )
            if self_machine_id and destination_client_id == self_machine_id:
                relay = False
                target_mode = "self"
                target_host = "127.0.0.1"
                destination_identity_reason = None
            elif bound_inventory is None:
                relay = True
                target_mode = "routed"
                target_host = dest_token
                destination_identity_reason = destination_identity_reason or (
                    "Bound Managed Host destination (client_id=%s) is missing or invalid."
                    % destination_client_id[:12]
                )
            else:
                resolved, deg = _runtime_target_for_managed_host(bound_inventory)
                relay = True
                target_mode = "routed"
                if resolved:
                    target_host = resolved
                else:
                    target_host = dest_token
                    destination_identity_reason = destination_identity_reason or deg
                dest_token = str(bound_inventory.get("name") or dest_token)
        elif obj and obj["type"] == "host":
            vals = plane_db._object_values(obj["id"])
            target_host = vals[0] if vals else dest_token
            relay = dest_token.lower() != host_name.lower()
            target_mode = "self" if not relay else "routed"
            if not relay:
                target_host = "127.0.0.1"
        elif obj and obj["type"] == "fqdn":
            vals = plane_db._object_values(obj["id"])
            target_host = vals[0] if vals else dest_token
            relay = True
            target_mode = "routed"
        else:
            # Allow literal hostname / IP when catalog has the object synchronized
            catalog = plane_db.conn.execute(
                "SELECT payload FROM agent_object_catalog WHERE kind = 'network-object' AND name = ? COLLATE NOCASE",
                (dest_token,),
            ).fetchone()
            catalog_vals = []
            catalog_type = ""
            if catalog:
                try:
                    payload = json.loads(catalog["payload"] or "{}")
                except (TypeError, ValueError):
                    payload = {}
                catalog_vals = [str(v) for v in (payload.get("values") or []) if v not in (None, "")]
                catalog_type = str(payload.get("type") or "").lower()
            if catalog_type == "managed_endpoint":
                # Name matched a Managed Host in catalog but client_id was missing —
                # fail closed rather than routing by mutable label.
                raise ControlPlaneError(
                    "ERROR:\nManaged Host destination '%s' has no immutable client identity.\n\n"
                    "Synchronize the Managed Host catalog and retry.\n\n"
                    "No changes were applied." % dest_token
                )
            if catalog_vals:
                target_host = catalog_vals[0]
                relay = True
                target_mode = "routed"
            elif not obj and dest_token.lower() != host_name.lower():
                try:
                    target_host = str(ipaddress.ip_address(dest_token))
                except ValueError:
                    target_host = dest_token
                relay = True
                target_mode = "routed"
            else:
                relay = dest_token.lower() != host_name.lower()
                target_mode = "self" if not relay else "routed"
                target_host = dest_token if relay else "127.0.0.1"

    sobj = None
    catalog = plane_db.conn.execute(
        "SELECT payload FROM agent_object_catalog WHERE kind = 'service-object' AND name = ? COLLATE NOCASE",
        (svc_name,),
    ).fetchone()
    # After a successful Server catalog sync, Server Service Object definitions
    # outrank Agent-local seeds (ssh/http/...). Local seeds are fallback only.
    if catalog:
        try:
            sobj = json.loads(catalog["payload"] or "{}")
        except (TypeError, ValueError):
            sobj = None
    if not sobj:
        sobj = get_service_object(plane_db, svc_name)
    if not sobj:
        raise ControlPlaneError(
            "ERROR:\nService Object '%s' is not available in the local synchronized catalog.\n\n"
            "No changes were applied.\n\n"
            "Create/synchronize the required Service Object and retry." % svc_name
        )
    stype = sobj["type"] if not isinstance(sobj, dict) else sobj.get("type")
    sport = int(sobj["port"] if not isinstance(sobj, dict) else sobj.get("port"))
    if stype == "udp":
        raise ControlPlaneError(
            "ERROR:\nService Object '%s' uses UDP.\n\n"
            "Remote Service supports TCP and Fixed TCP services only.\n\n"
            "No changes were applied." % svc_name
        )
    if get_service_group(plane_db, svc_name):
        raise ControlPlaneError(
            cli_error("Remote Service uses one Service Object, not a Service Group.")
        )
    pool_class = "fixed-tcp" if stype == "fixed-tcp" else "normal"
    if existing and existing["pool_class"] != pool_class:
        raise ControlPlaneError(
            "ERROR:\nThe Service type cannot be changed between standard TCP and Fixed TCP\n"
            "for an existing Remote Service.\n\n"
            "Delete and recreate the Remote Service.\n\n"
            "No changes were applied."
        )
    # Duplicate destination+service check (identity-safe for Managed Host binds)
    if destination_client_id:
        dup = plane_db.conn.execute(
            "SELECT name FROM agent_remote_services WHERE destination_client_id = ? "
            "AND service_object = ? COLLATE NOCASE AND name != ? COLLATE NOCASE",
            (destination_client_id, svc_name, name),
        ).fetchone()
    else:
        dup = plane_db.conn.execute(
            "SELECT name FROM agent_remote_services WHERE destination = ? COLLATE NOCASE "
            "AND service_object = ? COLLATE NOCASE AND name != ? COLLATE NOCASE "
            "AND (destination_client_id IS NULL OR destination_client_id = '')",
            (dest_token, svc_name, name),
        ).fetchone()
    if dup:
        raise ControlPlaneError(
            "ERROR:\nA Remote Service already exists for:\n\n"
            "  Destination : %s\n"
            "  Service     : %s\n\n"
            "Existing Remote Service:\n  %s\n\n"
            "No changes were applied." % (dest_token, svc_name, dup["name"])
        )

    endpoint_host = "127.0.0.1"
    try:
        import frp_server_config as scfg

        endpoint_host = scfg.resolve_public_endpoint_host(root=root, fallback="") or endpoint_host
    except Exception:
        endpoint_host = os.environ.get("DRLINK_HOST") or endpoint_host
    endpoint_port = existing["endpoint_port"] if existing else None
    pending = 0
    status = "DISABLED" if not en else "DEGRADED"
    reason = "Runtime activation pending."
    client = None
    live_mgmt = False
    target_host_for_runtime = target_host
    sport_for_runtime = sport

    destination_unreachable = False
    in_batch = bool(getattr(plane_db, "_batch_mode", False))

    if not en:
        status = "DISABLED"
        reason = DISABLED_OPERATOR_REASON

    if not server_reachable:
        if en:
            pending = 1 if endpoint_port is None else 0
            status = "DEGRADED"
            reason = "DRLink Server is currently unreachable."
    else:
        import drlink_mgmt_sync as mgmt

        live_mgmt = mgmt.use_live_mgmt_path(root)
        if live_mgmt:
            # Authoritative Server allocator — Agent must not mint online reservations.
            # Disabled services still upsert so immutable destination references remain
            # visible to Server retirement / dependency checks.
            try:
                # Refresh catalog so dependency generations stay current.
                try:
                    sync_agent_catalog_from_server(plane_db, root=root)
                except Exception:
                    pass
                prev_mgmt = None
                if existing is not None:
                    prev_mgmt = _agent_remote_service_mgmt_snapshot(
                        plane_db, existing, root=root, host_name=host_name
                    )
                remote = mgmt.upsert_remote_service_on_server(
                    root=root,
                    name=name,
                    destination=dest_token,
                    destination_client_id=destination_client_id,
                    service=svc_name,
                    enabled=en,
                    pool_class=pool_class,
                    target_host=target_host,
                    target_port=sport,
                    target_mode=target_mode,
                    preserve_endpoint_port=endpoint_port,
                    runtime_verified=False,
                )
                if prev_mgmt is None:
                    _record_agent_mgmt_create(plane_db, name, root=root)
                else:
                    effect = dict(prev_mgmt)
                    effect["op"] = "update-rs"
                    _record_agent_mgmt_effect(plane_db, effect)
                endpoint_host = remote.get("endpoint_host") or endpoint_host
                endpoint_port = remote.get("endpoint_port")
                pending = int(remote.get("pending_allocation") or 0)
                if en:
                    status = remote.get("status") or "DEGRADED"
                    reason = remote.get("reason") or "Runtime activation pending."
                    if pending:
                        status = "DEGRADED"
                        reason = reason or "Endpoint allocation is pending on the Server."
                else:
                    status = "DISABLED"
                    reason = DISABLED_OPERATOR_REASON
            except ControlPlaneError:
                raise
            except Exception as exc:
                raise ControlPlaneError(
                    "ERROR:\nServer endpoint allocation failed.\n\n%s\n\nNo changes were applied."
                    % exc
                ) from exc
        else:
            client_sel = identity.get("machine_id") or identity.get("hostname") or host_name
            try:
                client = plane_db.get_client(client_sel)
            except Exception:
                client = None
            if client is None:
                # Create a local stand-in client row for tests / offline-first.
                try:
                    client = plane_db.require_client(client_sel)
                except ControlPlaneError:
                    # Register ephemeral client for this agent identity
                    def ensure_client():
                        cid = identity.get("machine_id") or _new_id("cli")
                        now = utc_now_iso()
                        plane_db.conn.execute(
                            "INSERT OR IGNORE INTO clients(id, label, hostname, status, trust_status, connected, "
                            "row_version, created_at, updated_at) VALUES (?, ?, ?, 'connected', 'trusted', 1, 1, ?, ?)",
                            (cid, host_name, host_name, now, now),
                        )
                        return {"entity": {"type": "client", "id": cid, "name": host_name}, "operation": "ensure"}

                    plane_db._mutate("ensure agent client", "ensure client", ensure_client)
                    client = plane_db.get_client(identity.get("machine_id") or host_name)
            if endpoint_port is None and en:
                try:
                    endpoint_port = allocate_endpoint_port(plane_db, client["id"], name, pool_class)
                except ControlPlaneError:
                    if existing is None:
                        # New service while pool exhausted at create time with server available → hard fail
                        raise
                    pending = 1
                    status = "DEGRADED"
                    reason = "No endpoint port is currently available"

    # Routed destination reachability is independent of proxy registration.
    if destination_identity_reason and en:
        status = "DEGRADED"
        reason = destination_identity_reason
    elif en and target_mode == "routed" and endpoint_port is not None and pending == 0:
        if not _probe_tcp(target_host, sport):
            destination_unreachable = True
            status = "DEGRADED"
            reason = DESTINATION_UNREACHABLE_REASON

    now = utc_now_iso()
    client_for_pub = client

    def write_all():
        # Nested helpers (set_published_service) also call _mutate; run them as batch
        # participants of this outer transaction.
        nested_prev = getattr(plane_db, "_batch_mode", False)
        plane_db._batch_mode = True
        try:
            if (
                server_reachable
                and not live_mgmt
                and client_for_pub is not None
                and endpoint_port is not None
                and pending == 0
            ):
                plane_db.set_published_service(
                    client_for_pub["id"],
                    name,
                    service_type="tcp",
                    target_mode=target_mode,
                    target_host=target_host,
                    target_port=sport,
                    enabled=en,
                    public_port=endpoint_port,
                )
                pub = plane_db.conn.execute(
                    "SELECT id FROM published_services WHERE client_id = ? AND name = ?",
                    (client_for_pub["id"], name),
                ).fetchone()
                sobj_row = get_service_object(plane_db, svc_name)
                plane_db.conn.execute(
                    "INSERT OR REPLACE INTO remote_service_meta"
                    "(service_id, status, pool_class, service_object_id, destination_name, "
                    "destination_client_id, pending_allocation, delete_pending, reason) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        pub["id"],
                        status if en else "DISABLED",
                        pool_class,
                        sobj_row["id"] if sobj_row else None,
                        dest_token,
                        destination_client_id,
                        pending,
                        reason,
                    ),
                )
            plane_db.conn.execute(
                "INSERT OR REPLACE INTO agent_remote_services"
                "(name, destination, destination_client_id, service_object, enabled, status, "
                "endpoint_host, endpoint_port, pending_allocation, delete_pending, pool_class, "
                "reason, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                (
                    name,
                    dest_token,
                    destination_client_id,
                    svc_name,
                    1 if en else 0,
                    status if en else "DISABLED",
                    endpoint_host,
                    endpoint_port,
                    pending,
                    pool_class,
                    reason,
                    now,
                ),
            )
            return {"entity": {"type": "remote-service", "id": name, "name": name}, "operation": "set"}
        finally:
            plane_db._batch_mode = nested_prev

    try:
        result = plane_db._mutate("set remote-service %s" % name, "set remote service", write_all)
    except Exception as exc:
        # Server mutation already happened on the live path; compensate before re-raising.
        if live_mgmt and getattr(plane_db, "_agent_mgmt_side_effects", None):
            msg = str(exc)
            if "Previous configuration was restored" in msg or "rollback was not fully successful" in msg:
                raise_agent_mgmt_activation_failure(
                    plane_db,
                    root=root,
                    cause=exc,
                    local_restored="Previous configuration was restored" in msg,
                )
            report = reconcile_agent_mgmt_side_effects(plane_db, root=root)
            if not report.get("ok"):
                details = "\n".join("  %s" % f for f in (report.get("failures") or [])) or "  unknown"
                raise ControlPlaneError(
                    "ERROR:\nRemote Service change failed after Server mutation.\n\n"
                    "PARTIAL: Server Remote Service state could not be fully restored.\n"
                    "RECOVERY_REQUIRED\n\n"
                    "Compensation failures:\n%s\n\n"
                    "Original error:\n%s\n\n"
                    "Run:\n  system diagnostics" % (details, msg)
                ) from exc
        raise

    def _persist_status(next_status: str, next_reason: str) -> None:
        plane_db.conn.execute(
            "UPDATE agent_remote_services SET status = ?, reason = ?, updated_at = ? WHERE name = ?",
            (next_status, next_reason, utc_now_iso(), name),
        )
        _commit_if_autonomous(plane_db)

    # Nested Bundle Apply writes desired state only; the outer plan activates runtime.
    if in_batch:
        result["view"] = {
            "name": name,
            "destination": dest_token,
            "relay_host": host_name if relay else "-",
            "service": svc_name,
            "enabled": en,
            "status": status if en else "DISABLED",
            "endpoint": (
                "Pending allocation"
                if pending or endpoint_port is None
                else "%s:%s" % (endpoint_host, endpoint_port)
            ),
            "endpoint_host": endpoint_host,
            "endpoint_port": endpoint_port,
            "reason": reason,
            "connection": None,
        }
        return result

    # Runtime activation: desired DB alone must never imply HEALTHY.
    runtime_ok = False
    runtime_error = ""
    if (
        en
        and endpoint_port is not None
        and pending == 0
        and server_reachable
        and not destination_identity_reason
    ):
        try:
            import drlink_v24_runtime as runtime

            applied = runtime.apply_agent_runtime(plane_db, root=root)
            if applied.get("skipped"):
                # Unit-test shortcut: treat allocation success as verified.
                runtime_ok = True
            elif applied.get("ok"):
                runtime_ok = True
            else:
                runtime_error = applied.get("error") or "Runtime activation failed"
        except Exception as exc:
            runtime_error = str(exc)
        if runtime_ok and destination_unreachable:
            status = "DEGRADED"
            reason = DESTINATION_UNREACHABLE_REASON
            _persist_status(status, reason)
            if live_mgmt:
                _push_agent_remote_service_status(plane_db, root=root, names=[name])
            _clear_agent_mgmt_side_effects(plane_db)
        elif runtime_ok:
            status = "HEALTHY"
            reason = ""
            if live_mgmt:
                try:
                    import drlink_mgmt_sync as mgmt

                    ack = mgmt.upsert_remote_service_on_server(
                        root=root,
                        name=name,
                        destination=dest_token,
                        destination_client_id=destination_client_id,
                        service=svc_name,
                        enabled=en,
                        pool_class=pool_class,
                        target_host=target_host_for_runtime,
                        target_port=sport_for_runtime,
                        target_mode=target_mode,
                        preserve_endpoint_port=endpoint_port,
                        runtime_verified=True,
                    )
                    # Server HEALTHY must not overwrite a local unreachable probe.
                    ack_status = str(ack.get("status") or status).upper()
                    ack_reason = str(ack.get("reason") or "")
                    if ack_status == "DEGRADED":
                        status = "DEGRADED"
                        reason = ack_reason or "Runtime activation pending."
                    else:
                        status = "HEALTHY"
                        reason = ""
                except Exception as exc:
                    status = "DEGRADED"
                    reason = "Runtime applied locally but Server acknowledgement failed: %s" % exc
                    runtime_ok = False
            _persist_status(status, reason)
            if live_mgmt and status != "HEALTHY":
                _push_agent_remote_service_status(plane_db, root=root, names=[name])
            # Local desired state is the new definition; do not compensate Server.
            _clear_agent_mgmt_side_effects(plane_db)
        else:
            status = "DEGRADED"
            reason = runtime_error or "Runtime activation pending."
            _persist_status(status, reason)
            # New service whose runtime failed: release Server reservation when safe.
            if existing is None and live_mgmt:
                report = reconcile_agent_mgmt_side_effects(plane_db, root=root)
                if report.get("ok"):
                    plane_db.conn.execute(
                        "UPDATE agent_remote_services SET endpoint_port = NULL, pending_allocation = 1, "
                        "status = 'DEGRADED', reason = ?, updated_at = ? WHERE name = ?",
                        (reason, utc_now_iso(), name),
                    )
                    _commit_if_autonomous(plane_db)
                    endpoint_port = None
                    pending = 1
                else:
                    details = (
                        "\n".join("  %s" % f for f in (report.get("failures") or []))
                        or "  unknown"
                    )
                    raise ControlPlaneError(
                        "ERROR:\nRuntime activation failed.\n\n"
                        "PARTIAL: Server Remote Service state could not be fully restored.\n"
                        "RECOVERY_REQUIRED\n\n"
                        "Compensation failures:\n%s\n\n"
                        "Run:\n  system diagnostics" % details
                    )
            elif live_mgmt:
                # UPDATE kept local+Server on the new definition (DEGRADED), not rolled back.
                _push_agent_remote_service_status(plane_db, root=root, names=[name])
                _clear_agent_mgmt_side_effects(plane_db)
            else:
                _clear_agent_mgmt_side_effects(plane_db)
    elif destination_identity_reason and en:
        _persist_status(status, reason or destination_identity_reason)
        if live_mgmt:
            _push_agent_remote_service_status(plane_db, root=root, names=[name])
        _clear_agent_mgmt_side_effects(plane_db)
    elif not en:
        # Disabled: ensure runtime proxy removed.
        try:
            import drlink_v24_runtime as runtime

            runtime.apply_agent_runtime(plane_db, root=root)
        except Exception:
            pass
        status = "DISABLED"
        reason = DISABLED_OPERATOR_REASON
        _persist_status(status, reason)
        if live_mgmt:
            _push_agent_remote_service_status(plane_db, root=root, names=[name])
        _clear_agent_mgmt_side_effects(plane_db)
    else:
        _clear_agent_mgmt_side_effects(plane_db)

    result["view"] = {
        "name": name,
        "destination": dest_token,
        "relay_host": host_name if relay else "-",
        "service": svc_name,
        "enabled": en,
        "status": status if en else "DISABLED",
        "endpoint": (
            "Pending allocation"
            if pending or endpoint_port is None
            else "%s:%s" % (endpoint_host, endpoint_port)
        ),
        "endpoint_host": endpoint_host,
        "endpoint_port": endpoint_port,
        "reason": reason,
        "connection": (
            None
            if pending or endpoint_port is None or status != "HEALTHY"
            else "ssh -p %s <username>@%s" % (endpoint_port, endpoint_host)
            if sport == 22
            else "%s:%s" % (endpoint_host, endpoint_port)
        ),
    }
    return result


def _probe_tcp(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def unset_remote_service_agent(plane_db, name: str, *, root: Optional[str] = None, server_reachable: bool = True) -> dict:
    name = validate_public_name(name, "Remote Service name")
    existing = plane_db.conn.execute(
        "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()
    if not existing:
        raise ControlPlaneError(cli_error("Remote Service '%s' was not found." % name))
    identity = load_agent_identity(root)
    host_name = identity.get("hostname") or identity.get("label") or "this-host"

    import drlink_mgmt_sync as mgmt

    live_mgmt = bool(server_reachable and mgmt.use_live_mgmt_path(root))
    if live_mgmt:
        prev_mgmt = _agent_remote_service_mgmt_snapshot(
            plane_db, existing, root=root, host_name=host_name
        )
        try:
            mgmt.delete_remote_service_on_server(root=root, name=name)
        except ControlPlaneError:
            raise
        except Exception as exc:
            raise ControlPlaneError(
                "ERROR:\nServer Remote Service delete failed.\n\n%s\n\nNo changes were applied." % exc
            ) from exc
        effect = dict(prev_mgmt)
        effect["op"] = "delete-rs"
        _record_agent_mgmt_effect(plane_db, effect)

    def write():
        plane_db.conn.execute("DELETE FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,))
        if server_reachable and not live_mgmt:
            client = None
            if identity.get("machine_id"):
                client = plane_db.get_client(identity["machine_id"])
            if client is None and identity.get("hostname"):
                client = plane_db.get_client(identity["hostname"])
            if client is not None:
                pub = plane_db.conn.execute(
                    "SELECT * FROM published_services WHERE client_id = ? AND name = ?",
                    (client["id"], name),
                ).fetchone()
                if pub:
                    if pub["public_port"] is not None:
                        plane_db.conn.execute(
                            "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
                            (pub["public_port"],),
                        )
                    plane_db.conn.execute("DELETE FROM remote_service_meta WHERE service_id = ?", (pub["id"],))
                    plane_db.conn.execute("DELETE FROM published_services WHERE id = ?", (pub["id"],))
        elif not server_reachable:
            # Queue deletion intent: keep a tombstone marker via insert with delete_pending
            plane_db.conn.execute(
                "INSERT OR REPLACE INTO agent_remote_services"
                "(name, destination, destination_client_id, service_object, enabled, status, "
                "endpoint_host, endpoint_port, pending_allocation, delete_pending, pool_class, "
                "reason, updated_at) "
                "VALUES (?, ?, ?, ?, 0, 'DISABLED', ?, ?, 0, 1, ?, 'delete pending sync', ?)",
                (
                    name,
                    existing["destination"],
                    _row_get(existing, "destination_client_id"),
                    existing["service_object"],
                    existing["endpoint_host"],
                    existing["endpoint_port"],
                    existing["pool_class"],
                    utc_now_iso(),
                ),
            )
        return {"entity": {"type": "remote-service", "id": name, "name": name}, "operation": "delete"}

    try:
        result = plane_db._mutate("unset remote-service %s" % name, "delete remote service", write)
    except Exception as exc:
        if live_mgmt and getattr(plane_db, "_agent_mgmt_side_effects", None):
            msg = str(exc)
            if "Previous configuration was restored" in msg or "rollback was not fully successful" in msg:
                raise_agent_mgmt_activation_failure(
                    plane_db,
                    root=root,
                    cause=exc,
                    local_restored="Previous configuration was restored" in msg,
                )
            report = reconcile_agent_mgmt_side_effects(plane_db, root=root)
            if not report.get("ok"):
                details = "\n".join("  %s" % f for f in (report.get("failures") or [])) or "  unknown"
                raise ControlPlaneError(
                    "ERROR:\nRemote Service delete failed after Server mutation.\n\n"
                    "PARTIAL: Server Remote Service state could not be fully restored.\n"
                    "RECOVERY_REQUIRED\n\n"
                    "Compensation failures:\n%s\n\n"
                    "Original error:\n%s\n\n"
                    "Run:\n  system diagnostics" % (details, msg)
                ) from exc
        raise
    # Nested synchronize / Bundle Apply defers runtime to one final apply.
    if getattr(plane_db, "_batch_mode", False):
        return result
    # Always remove local runtime proxy immediately (including offline tombstone deletes).
    try:
        import drlink_v24_runtime as runtime

        runtime.apply_agent_runtime(plane_db, root=root)
    except Exception:
        pass
    _clear_agent_mgmt_side_effects(plane_db)
    return result


def format_remote_service_view(view: dict) -> str:
    status = str(view.get("status") or "")
    if status == "HEALTHY":
        headline = "Remote Service activated."
    elif status == "DISABLED":
        headline = "Remote Service configuration saved."
    else:
        headline = "Remote Service configuration saved.\nRuntime activation pending."
    lines = [
        headline,
        "",
        "Name        : %s" % view["name"],
        "Destination : %s" % view["destination"],
    ]
    if view.get("relay_host") and view["relay_host"] != "-":
        lines.append("Relay Host  : %s" % view["relay_host"])
    lines.extend(
        [
            "Service     : %s" % view["service"],
            "Status      : %s" % view["status"],
            "Endpoint    : %s" % view["endpoint"],
        ]
    )
    if view.get("reason"):
        lines.extend(["", "Reason:", "  %s" % view["reason"]])
    if view.get("connection") and view["status"] == "HEALTHY":
        lines.extend(["", "Connection:", "  %s" % view["connection"]])
    if view.get("status") == "DEGRADED":
        reason_l = (view.get("reason") or "").lower()
        if "unreachable" in reason_l:
            follow = "The service will become available automatically when connectivity is restored."
        elif "runtime" in reason_l:
            follow = "Runtime activation will complete after a successful Agent/frpc apply."
        else:
            follow = "Endpoint allocation and activation will complete automatically after reconnect."
        lines.extend(["", "Configuration was saved.", follow])
    return "\n".join(lines) + "\n"


def probe_agent_runtime_unit(*, root: Optional[str] = None) -> dict:
    """Read-only probe of the Agent frpc unit (drlink-client / launchd).

    Returns {level, detail} where level is Healthy|Critical|Warning|Unknown.
    Does not start/stop services. Test roots may inject DRLINK_TEST_RUNTIME_UNIT.
    """
    inject = str(os.environ.get("DRLINK_TEST_RUNTIME_UNIT") or "").strip()
    if inject:
        # Formats: "failed:start-limit-hit" | "active" | "inactive" | "unknown:reason"
        parts = inject.split(":", 1)
        state = parts[0].strip().lower()
        detail = parts[1].strip() if len(parts) > 1 else ""
        if state in ("failed", "critical"):
            msg = "drlink-client.service is failed"
            if detail:
                msg = "%s (Result=%s)" % (msg, detail)
            return {"level": "Critical", "detail": msg}
        if state in ("active", "healthy", "running"):
            return {"level": "Healthy", "detail": "drlink-client.service is active"}
        if state in ("inactive", "dead"):
            return {"level": "Critical", "detail": "drlink-client.service is inactive"}
        return {"level": "Unknown", "detail": detail or inject}

    root_s = str(root or "").rstrip("/")
    if root_s not in ("", "/") or str(os.environ.get("FRP_SKIP_SYSTEMD") or "").strip() == "1":
        return {
            "level": "Unknown",
            "detail": "Runtime unit status unavailable in this environment",
        }

    import subprocess

    try:
        proc = subprocess.run(
            ["systemctl", "show", "drlink-client", "-p", "ActiveState", "-p", "Result", "-p", "SubState"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # macOS / systems without systemctl
        try:
            proc = subprocess.run(
                ["launchctl", "print", "system/com.datarelay.drlink.frpc"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            text = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode != 0:
                return {
                    "level": "Critical",
                    "detail": "macOS Agent runtime job is not loaded",
                }
            if "state = running" in text.lower() or "runs = 1" in text.lower():
                return {"level": "Healthy", "detail": "macOS Agent runtime is running"}
            return {"level": "Warning", "detail": "macOS Agent runtime is loaded but not running"}
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return {
                "level": "Unknown",
                "detail": "Runtime unit status unavailable on this platform",
            }

    props = {}
    for line in (proc.stdout or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    active = str(props.get("ActiveState") or "").lower()
    result = str(props.get("Result") or "").strip()
    if active == "failed" or result not in ("", "success"):
        msg = "drlink-client.service is failed"
        if result and result != "success":
            msg = "%s (Result=%s)" % (msg, result)
        return {"level": "Critical", "detail": msg}
    if active == "active":
        return {"level": "Healthy", "detail": "drlink-client.service is active"}
    if active in ("inactive", "dead"):
        return {"level": "Critical", "detail": "drlink-client.service is inactive"}
    if active:
        return {"level": "Warning", "detail": "drlink-client.service is %s" % active}
    return {"level": "Unknown", "detail": "drlink-client.service status could not be read"}


def inventory_remote_service_status(plane_db, client, *, enabled: bool, stored_status: str) -> str:
    """Operator-facing Remote Service status.

    Explicit disable and an offline Managed Host override a stored HEALTHY
    value. A connected, enabled service keeps a reported HEALTHY or DEGRADED
    status. Missing runtime evidence stays DEGRADED.
    """
    if not enabled:
        return "DISABLED"
    try:
        connectivity = plane_db.managed_host_connectivity(client)
    except Exception:
        connectivity = "disconnected"
    if connectivity != "connected":
        return "DEGRADED"
    stored = str(stored_status or "").strip().upper()
    if stored == "HEALTHY":
        return "HEALTHY"
    if stored == "DEGRADED":
        return "DEGRADED"
    return "DEGRADED"


def _load_enrolled_client_state(root: Optional[str], state: Optional[dict]) -> Optional[dict]:
    if isinstance(state, dict):
        return state
    for path in _agent_state_file_candidates(
        "etc/frp/client-state.json", "client-state.json", root
    ):
        if not path.is_file():
            continue
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(loaded, dict):
            return loaded
    return None


def _bootstrap_seed_names(root: Optional[str], state: Optional[dict] = None) -> set:
    """Return enrolled service ids that are seeds, not v2.4 runtime projections."""
    data = _load_enrolled_client_state(root, state)
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return set()
    names = set()
    for sid, rec in services.items():
        if not isinstance(rec, dict) or rec.get("v24_remote_service"):
            continue
        sid_s = str(rec.get("id") or sid).strip()
        if not sid_s or sid_s.lower().startswith("rs-"):
            continue
        try:
            names.add(validate_public_name(sid_s.lower(), "Remote Service name").lower())
        except ControlPlaneError:
            continue
    return names


def project_enrolled_services_into_agent_catalog(
    plane_db,
    *,
    root: Optional[str] = None,
    state: Optional[dict] = None,
) -> list:
    """Seed missing bootstrap services into the Agent catalog.

    Enrollment ``client-state`` is migration input only. An existing
    ``agent_remote_services`` row is authoritative operator state and is
    left unchanged, including enablement, destination, service, and
    public port. New rows keep the enrolled name and allocator port.
    """
    data = _load_enrolled_client_state(root, state)
    if not isinstance(data, dict):
        return []
    services = data.get("services") or {}
    if not isinstance(services, dict) or not services:
        return []
    endpoint_host = str(data.get("public_hostname") or data.get("frp_server") or "").strip()
    identity = load_agent_identity(root)
    destination = identity.get("hostname") or identity.get("label") or "this-host"
    destination_client_id = str(identity.get("machine_id") or "").strip() or None
    results = []
    wrote = False
    now = utc_now_iso()
    for sid, rec in services.items():
        if not isinstance(rec, dict):
            continue
        if rec.get("v24_remote_service"):
            continue
        sid_s = str(rec.get("id") or sid).strip()
        if not sid_s or sid_s.lower().startswith("rs-"):
            continue
        try:
            name = validate_public_name(sid_s.lower(), "Remote Service name")
        except ControlPlaneError:
            continue
        preset = str(rec.get("preset") or "tcp").strip().lower()
        service_obj = preset if preset in ("ssh", "http", "https", "tcp") else "tcp"
        enabled = rec.get("enabled", True) is not False
        # Prefer the enrolled public port so Zero-Touch keeps the allocator
        # reservation (enrolled_port) instead of minting a new endpoint.
        enrolled_port = None
        try:
            if rec.get("remote_port") is not None:
                enrolled_port = int(rec.get("remote_port"))
        except (TypeError, ValueError):
            enrolled_port = None
        existing = plane_db.conn.execute(
            "SELECT name FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if existing is not None:
            continue
        if enrolled_port is not None:
            endpoint_port = enrolled_port
            pending = 0
        else:
            endpoint_port = None
            pending = 1
        # Local target reachability is not relay verification. A new seed
        # stays runtime-pending until apply/verification promotes it.
        if not enabled:
            status, reason = "DISABLED", ""
        elif endpoint_port is None:
            status, reason = "DEGRADED", "Endpoint allocation is pending."
        else:
            status, reason = "DEGRADED", "Runtime activation pending."
        host = endpoint_host or ""
        plane_db.conn.execute(
            "INSERT INTO agent_remote_services"
            "(name, destination, destination_client_id, service_object, enabled, status, "
            "endpoint_host, endpoint_port, pending_allocation, delete_pending, pool_class, "
            "reason, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'normal', ?, ?)",
            (
                name,
                destination,
                destination_client_id,
                service_obj,
                1 if enabled else 0,
                status,
                host or None,
                endpoint_port,
                pending,
                reason,
                now,
            ),
        )
        wrote = True
        endpoint = (
            "Pending allocation"
            if pending or endpoint_port is None
            else "%s:%s" % (host or "pending", endpoint_port)
        )
        results.append(
            {
                "seeded": True,
                "view": {
                    "name": name,
                    "status": status,
                    "reason": reason,
                    "endpoint": endpoint,
                    "endpoint_port": endpoint_port,
                    "service": service_obj,
                    "enabled": enabled,
                    "destination": destination,
                },
            }
        )
    if wrote:
        _commit_if_autonomous(plane_db)
    return results


def activate_enrolled_services_as_remote_services(
    *,
    root: Optional[str] = None,
    state: Optional[dict] = None,
    runtime_verified: bool = False,
) -> list:
    """Promote enrolled client-state services into Agent Remote Services.

    Reuses allocated public ports when present. Returns a list of result
    dicts (may be empty). ``runtime_verified`` records explicit relay-proxy
    verification that already succeeded; a local target socket is not enough.
    """
    data = _load_enrolled_client_state(root, state)
    if not isinstance(data, dict):
        return []
    from drlink_control_plane import ControlPlane

    plane = ControlPlane(root)
    results = project_enrolled_services_into_agent_catalog(plane, root=root, state=data)
    if runtime_verified and results:
        now = utc_now_iso()
        for item in results:
            view = item.get("view") or {}
            name = view.get("name")
            if not name or not view.get("enabled") or view.get("endpoint_port") is None:
                continue
            plane.conn.execute(
                "UPDATE agent_remote_services SET status = 'HEALTHY', reason = '', updated_at = ? "
                "WHERE name = ? COLLATE NOCASE AND delete_pending = 0 AND enabled = 1 "
                "AND endpoint_port IS NOT NULL AND pending_allocation = 0 "
                "AND reason = 'Runtime activation pending.'",
                (now, name),
            )
            row = plane.conn.execute(
                "SELECT status, reason FROM agent_remote_services WHERE name = ? COLLATE NOCASE",
                (name,),
            ).fetchone()
            if row is not None:
                view["status"] = row["status"]
                view["reason"] = row["reason"] or ""
        _commit_if_autonomous(plane)
    if results and detect_server_reachable(plane, root):
        _push_agent_remote_service_status(plane, root=root)
    return results


def format_show_status(role: str, plane_db=None) -> str:
    lines = [
        "Data Relay Link",
        "",
        "Role: %s" % role_label(role),
        "",
    ]
    if role == "server" and plane_db is not None:
        policies = []
        configured = False
        for family in ("remote", "internet", "ai"):
            pol = get_access_policy(plane_db, family)
            title = {"remote": "Remote Access", "internet": "Internet Access", "ai": "AI Access"}[family]
            if pol["mode"] is None:
                policies.append("  %s: No Policy (ALLOW)" % title)
            else:
                configured = True
                # Show mode summary
                policies.append(
                    "  %s: %s / %s"
                    % (title, pol["mode"].upper(), str(pol["enforcement"]).upper())
                )
        if not configured:
            lines.extend(
                [
                    "No access restrictions are currently configured.",
                    "Access is allowed by default.",
                    "",
                    "Access policies:",
                    "  Remote Access",
                    "  Internet Access",
                    "  AI Access",
                    "",
                    "Policy modes:",
                    "  Blacklist — rules define what to block",
                    "  Whitelist — rules define what to allow",
                    "",
                    "Reusable objects:",
                    "  Network Objects / Groups",
                    "  Service Objects / Groups",
                    "  Permission Objects / Groups",
                    "",
                    "Objects can also be created while creating a rule.",
                    "",
                    "Type:",
                    "  menu",
                    "  help",
                ]
            )
        else:
            lines.append("Access policies:")
            lines.extend(policies)
    elif role == "agent":
        lines.append("Agent Host local configuration.")
        lines.append("Use: show remote-services")
    return "\n".join(lines) + "\n"


def format_show_agent(root: Optional[str] = None) -> str:
    """Canonical Agent Host ``show agent`` read-only view."""
    identity = load_agent_identity(root)
    runtime = probe_agent_runtime_unit(root=root)
    autostart = "unknown"
    try:
        import subprocess

        proc = subprocess.run(
            ["systemctl", "is-enabled", "drlink-client.service"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            check=False,
        )
        if proc.returncode == 0:
            autostart = (proc.stdout or "").strip() or "enabled"
        elif (proc.stdout or "").strip():
            autostart = (proc.stdout or "").strip()
    except Exception:
        pass
    server = ""
    for path in _agent_state_file_candidates(
        "etc/frp/client-state.json", "client-state.json", root
    ):
        try:
            if not path.is_file():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            server = str(data.get("frp_server") or data.get("allocator_url") or "").strip()
            break
    lines = [
        "Data Relay Link",
        "",
        "Role: Agent Host",
        "",
        "Server connection : %s" % (server or "not configured"),
        "Hostname          : %s" % (identity.get("hostname") or identity.get("label") or "-"),
        "Machine ID        : %s" % (identity.get("machine_id") or "-"),
        "Agent runtime     : %s" % (runtime.get("level") or "Unknown"),
        "Runtime detail    : %s" % (runtime.get("detail") or "-"),
        "Autostart         : %s" % autostart,
        "",
        "Remote Services:",
        "  show remote-services",
    ]
    return "\n".join(lines) + "\n"


def parse_kv_tokens(
    tokens: list[str],
    *,
    allowed: Optional[set[str] | frozenset[str] | tuple[str, ...]] = None,
    resource: str = "",
    allowed_hint: str = "",
) -> dict[str, str]:
    """Parse `key value` pairs with strict duplicate / unknown / flag rules.

    Public one-shot setters must pass ``allowed`` so typos cannot silently
    drop fields. Duplicate keys and contradictory enabled/disabled flags are
    always rejected before any authoritative mutation.
    """
    out: dict[str, str] = {}
    i = 0
    flags = {"enabled", "disabled"}
    seen_enabled_flag = False
    allowed_set = set(allowed) if allowed is not None else None
    title = str(resource or "Command").strip() or "Command"
    while i < len(tokens):
        key = str(tokens[i]).strip().lower()
        if key in flags:
            if seen_enabled_flag or "enabled" in out:
                raise ControlPlaneError(
                    "ERROR:\nContradictory or duplicate enabled/disabled flags.\n\n"
                    "No changes were applied."
                )
            if allowed_set is not None and "enabled" not in allowed_set:
                hint = allowed_hint or ", ".join(sorted(allowed_set))
                raise ControlPlaneError(
                    "ERROR:\n%s does not accept '%s'.\n\nUse: %s\n\nNo changes were applied."
                    % (title, key, hint)
                )
            out["enabled"] = "yes" if key == "enabled" else "no"
            seen_enabled_flag = True
            i += 1
            continue
        if i + 1 >= len(tokens):
            raise ControlPlaneError(
                cli_error("Incomplete argument: %s" % key)
            )
        if key in out:
            raise ControlPlaneError(
                "ERROR:\nDuplicate field '%s'.\n\nNo changes were applied." % key
            )
        if allowed_set is not None and key not in allowed_set:
            hint = allowed_hint or ", ".join(sorted(allowed_set))
            raise ControlPlaneError(
                "ERROR:\n%s does not accept '%s'.\n\nUse: %s\n\nNo changes were applied."
                % (title, key, hint)
            )
        out[key] = tokens[i + 1]
        i += 2
    return out


def parse_csv_list(value: str) -> list[str]:
    return [p.strip() for p in str(value or "").split(",") if p.strip()]
