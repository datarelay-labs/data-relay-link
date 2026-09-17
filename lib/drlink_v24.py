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
from pathlib import Path
from typing import Any, Optional

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
CAP_TO_PERMISSION = {}
for _perm, _caps in PERMISSION_TO_CAPS.items():
    for _cap in _caps:
        CAP_TO_PERMISSION[_cap] = _perm

POLICY_PLANES = ("remote", "internet", "ai")
POLICY_MODES = ("blacklist", "whitelist")

NORMAL_PORT_START, NORMAL_PORT_END = 6000, 6099
FIXED_PORT_START, FIXED_PORT_END = 6200, 6299

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

CREATE TABLE IF NOT EXISTS remote_service_meta (
  service_id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'HEALTHY',
  pool_class TEXT NOT NULL DEFAULT 'normal',
  service_object_id TEXT,
  destination_name TEXT,
  pending_allocation INTEGER NOT NULL DEFAULT 0,
  delete_pending INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (service_id) REFERENCES published_services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_remote_services (
  name TEXT PRIMARY KEY,
  destination TEXT NOT NULL,
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


def ensure_v2_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(V2_SCHEMA_SQL)
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
    return "unknown"


def role_label(role: str) -> str:
    if role == "server":
        return "DRLink Server"
    if role == "agent":
        return "Agent Host"
    return "Unknown"


def load_agent_identity(root: Optional[str] = None) -> dict:
    base = Path(root) if root else Path("/")
    path = base / "etc/frp/client-state.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "machine_id": str(data.get("machine_id") or data.get("id") or "").strip(),
        "hostname": str(data.get("hostname") or data.get("label") or "").strip(),
        "label": str(data.get("label") or data.get("hostname") or "").strip(),
    }


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
    if pol["mode"] is None:
        raise ControlPlaneError(
            cli_error(
                "No %s policy is configured yet."
                % ("Remote Access" if plane == "remote" else "Internet Access" if plane == "internet" else "AI Access")
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

    return plane_db._mutate(
        "set %s-access %s" % (plane if plane != "ai" else "ai", "enabled" if enabled else "disabled"),
        "policy enforcement",
        write,
        confirm=confirm,
    )


def reset_access_policy(plane_db, family: str, *, confirm: Optional[bool] = None) -> dict:
    plane = _plane_key(family)
    title = {
        "remote": "Remote Access",
        "internet": "Internet Access",
        "ai": "AI Access",
    }[plane]

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


def set_network_object(plane_db, name: str, *, type: Optional[str] = None, value: Optional[str] = None, oneshot: bool = False) -> dict:
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
        if existing:
            if existing["type"] != store:
                raise ControlPlaneError(
                    cli_error("Cannot change Network Object type after creation.")
                )
            plane_db.set_object_value(name, value)
            return {"operation": "update", "name": name}
        plane_db.set_object_type(name, store)
        plane_db.set_object_value(name, value)
        return {"operation": "create", "name": name}
    if type and value is not None:
        return set_network_object(plane_db, name, type=type, value=value, oneshot=True)
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


def set_network_group(plane_db, name: str, *, members: Optional[list[str]] = None, oneshot: bool = False) -> dict:
    name = validate_public_name(name, "Network Group name")
    if oneshot or members is not None:
        if members is None:
            raise ControlPlaneError(
                cli_error("Network Group is incomplete.", expected="  members")
            )
        plane_db.set_object_group(name)
        existing = plane_db.get_object_group(name)
        current = {
            m["member_id"]
            for m in plane_db.conn.execute(
                "SELECT member_id FROM object_group_members WHERE group_id = ?",
                (existing["id"],),
            )
        }
        desired_ids = set()
        for mem in members:
            kind, ref = plane_db.resolve_ref(mem)
            if kind != "object":
                raise ControlPlaneError("Network Group members must be Network Objects")
            desired_ids.add(ref["id"])
            plane_db.set_object_group_member(name, mem)
        # exact list: remove extras
        for mid in current - desired_ids:
            obj = plane_db.conn.execute("SELECT name FROM objects WHERE id = ?", (mid,)).fetchone()
            if obj:
                plane_db.unset_object_group_member(name, obj["name"])
        return {"operation": "set", "name": name}
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
) -> dict:
    name = validate_public_name(name, "Service Object name")
    existing = get_service_object(plane_db, name)
    if oneshot or (type and port is not None):
        if not type or port is None:
            missing = []
            if not type:
                missing.append("type")
            if port is None:
                missing.append("port")
            raise ControlPlaneError(
                cli_error("Service Object is incomplete.", expected="\n".join("  %s" % m for m in missing))
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

            def write():
                plane_db.conn.execute(
                    "UPDATE service_objects SET type = ?, port = ?, row_version = row_version + 1, "
                    "updated_at = ? WHERE id = ?",
                    (stype, port, utc_now_iso(), existing["id"]),
                )
                return {"entity": {"type": "service-object", "id": existing["id"], "name": name}, "operation": "update"}

            return plane_db._mutate("set service-object %s" % name, "set service object", write)

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
        refs.append({"kind": "policy", "display": "%s: %s" % (family, row["name"])})
    for g in plane_db.conn.execute(
        "SELECT g.name FROM service_group_members m JOIN service_groups g ON g.id = m.group_id "
        "WHERE m.service_object_id = ?",
        (obj["id"],),
    ):
        refs.append({"kind": "service-group", "display": "Service Group: %s" % g["name"]})
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
                "display": "%s / %s" % (host, meta["name"]),
            }
        )
    for local in plane_db.conn.execute(
        "SELECT name FROM agent_remote_services WHERE service_object = ? COLLATE NOCASE",
        (name,),
    ):
        refs.append({"kind": "remote-service", "display": "Remote Service: %s" % local["name"]})
    return refs


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


def set_service_group(plane_db, name: str, *, members: Optional[list[str]] = None, oneshot: bool = False) -> dict:
    name = validate_public_name(name, "Service Group name")
    if not (oneshot or members is not None):
        raise ControlPlaneError("Interactive Service Group wizard requires a TTY session")
    if members is None:
        raise ControlPlaneError(cli_error("Service Group is incomplete.", expected="  members"))

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
        return {"entity": {"type": "service-group", "id": gid, "name": name}, "operation": op}

    return plane_db._mutate("set service-group %s" % name, "set service group", write)


def expand_service_ref(plane_db, token: str) -> list[sqlite3.Row]:
    sobj = get_service_object(plane_db, token)
    if sobj:
        return [sobj]
    grp = get_service_group(plane_db, token)
    if not grp:
        raise ControlPlaneError(
            cli_error(
                "Service '%s' was not found." % token,
                expected="  Service Object\n  Service Group",
                next_step="Use:\n  show service-objects\n  show service-groups",
            )
        )
    return [
        r
        for r in plane_db.conn.execute(
            "SELECT s.* FROM service_group_members m JOIN service_objects s ON s.id = m.service_object_id "
            "WHERE m.group_id = ?",
            (grp["id"],),
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


def set_permission_object(plane_db, name: str, *, permissions: Optional[list[str]] = None, oneshot: bool = False) -> dict:
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

    return plane_db._mutate("set permission-object %s" % name, "set permission object", write)


def set_permission_group(plane_db, name: str, *, members: Optional[list[str]] = None, oneshot: bool = False) -> dict:
    name = validate_public_name(name, "Permission Group name")
    if members is None:
        raise ControlPlaneError(cli_error("Permission Group is incomplete.", expected="  members"))

    def write():
        existing = get_permission_group(plane_db, name)
        now = utc_now_iso()
        if existing:
            gid = existing["id"]
            plane_db.conn.execute("DELETE FROM permission_group_members WHERE group_id = ?", (gid,))
            op = "update"
        else:
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

    return plane_db._mutate("set permission-group %s" % name, "set permission group", write)


def expand_permissions(plane_db, token: str) -> set[str]:
    pobj = get_permission_object(plane_db, token)
    if pobj:
        return {
            r["permission"]
            for r in plane_db.conn.execute(
                "SELECT permission FROM permission_object_members WHERE permission_object_id = ?",
                (pobj["id"],),
            )
        }
    grp = get_permission_group(plane_db, token)
    if not grp:
        raise ControlPlaneError(cli_error("Permission '%s' was not found." % token))
    out: set[str] = set()
    for mid in plane_db.conn.execute(
        "SELECT permission_object_id FROM permission_group_members WHERE group_id = ?",
        (grp["id"],),
    ):
        for r in plane_db.conn.execute(
            "SELECT permission FROM permission_object_members WHERE permission_object_id = ?",
            (mid["permission_object_id"],),
        ):
            out.add(r["permission"])
    return out


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
        except ControlPlaneError:
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
        except ControlPlaneError:
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
                grp = get_service_group(plane_db, service)
                if grp:
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
            sobj = get_service_object(plane_db, service)
            sgrp = get_service_group(plane_db, service)
            plane_db.conn.execute("DELETE FROM rule_service_refs WHERE rule_id = ?", (rule_id,))
            plane_db.conn.execute("DELETE FROM rule_services WHERE rule_id = ?", (rule_id,))
            if sobj:
                plane_db.conn.execute(
                    "INSERT INTO rule_service_refs(rule_id, ref_kind, ref_id) VALUES (?, 'service_object', ?)",
                    (rule_id, sobj["id"]),
                )
                proto = "tcp" if sobj["type"] in ("tcp", "fixed-tcp") else "udp"
                plane_db.conn.execute(
                    "INSERT INTO rule_services(rule_id, protocol, port) VALUES (?, ?, ?)",
                    (rule_id, proto, int(sobj["port"])),
                )
            else:
                plane_db.conn.execute(
                    "INSERT INTO rule_service_refs(rule_id, ref_kind, ref_id) VALUES (?, 'service_group', ?)",
                    (rule_id, sgrp["id"]),
                )
                for member in expand_service_ref(plane_db, service):
                    proto = "tcp" if member["type"] in ("tcp", "fixed-tcp") else "udp"
                    plane_db.conn.execute(
                        "INSERT OR IGNORE INTO rule_services(rule_id, protocol, port) VALUES (?, ?, ?)",
                        (rule_id, proto, int(member["port"])),
                    )
        return {"entity": {"type": "%s-access" % plane, "id": rule_id, "name": name}, "operation": op}

    return plane_db._mutate("set %s-access %s" % (plane, name), "set access rule", write)


def unset_access_rule(plane_db, family: str, name: str) -> dict:
    plane = _plane_key(family)
    return plane_db.unset_rule(plane, name)


# ---------------------------------------------------------------------------
# Policy evaluation (BLACKLIST / WHITELIST)
# ---------------------------------------------------------------------------


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
) -> dict:
    plane = _plane_key(family)
    pol = get_access_policy(plane_db, plane)
    matched_rules = []
    for rule_row in plane_db.conn.execute(
        "SELECT * FROM policy_rules WHERE plane = ? ORDER BY name", (plane,)
    ):
        if not rule_row["enabled"]:
            continue
        view = plane_db._rule_view(rule_row)
        src_ok = False
        if source_name:
            for s in plane_db.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_sources WHERE rule_id = ?", (rule_row["id"],)
            ):
                if _ref_name_match(plane_db, s["ref_kind"], s["ref_id"], source_name):
                    src_ok = True
                    break
        elif source_ip:
            for s in plane_db.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_sources WHERE rule_id = ?", (rule_row["id"],)
            ):
                if plane_db._ref_matches_ip(s["ref_kind"], s["ref_id"], source_ip, role="source"):
                    src_ok = True
                    break
                # Managed Host name as Internet Access source via endpoint addrs already covered;
                # also allow identity match when source_name not provided but dest is MH.
        else:
            src_ok = True
        dst_ok = False
        if destination_name:
            for s in plane_db.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_destinations WHERE rule_id = ?", (rule_row["id"],)
            ):
                if _ref_name_match(plane_db, s["ref_kind"], s["ref_id"], destination_name):
                    dst_ok = True
                    break
        elif destination:
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
        if service_name:
            for s in plane_db.conn.execute(
                "SELECT ref_kind, ref_id FROM rule_service_refs WHERE rule_id = ?", (rule_row["id"],)
            ):
                if s["ref_kind"] == "service_object":
                    sobj = plane_db.conn.execute(
                        "SELECT name FROM service_objects WHERE id = ?", (s["ref_id"],)
                    ).fetchone()
                    if sobj and sobj["name"].lower() == service_name.lower():
                        svc_ok = True
                        break
                else:
                    names = [
                        r["name"]
                        for r in plane_db.conn.execute(
                            "SELECT s.name FROM service_group_members m "
                            "JOIN service_objects s ON s.id = m.service_object_id WHERE m.group_id = ?",
                            (s["ref_id"],),
                        )
                    ]
                    grp = plane_db.conn.execute(
                        "SELECT name FROM service_groups WHERE id = ?", (s["ref_id"],)
                    ).fetchone()
                    if (grp and grp["name"].lower() == service_name.lower()) or any(
                        n.lower() == service_name.lower() for n in names
                    ):
                        svc_ok = True
                        break
        elif protocol is not None and port is not None:
            proto = str(protocol).lower()
            if proto in ("http", "https"):
                proto = "tcp"
            for s in plane_db.conn.execute(
                "SELECT protocol, port FROM rule_services WHERE rule_id = ?", (rule_row["id"],)
            ):
                if s["protocol"] == proto and int(s["port"]) == int(port):
                    svc_ok = True
                    break
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
    enabled: Optional[bool] = None,
    oneshot: bool = False,
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
            pobj = get_permission_object(plane_db, permission)
            if pobj:
                plane_db.conn.execute(
                    "UPDATE ai_policy_rules SET permission_ref_kind = 'permission_object', "
                    "permission_ref_id = ?, updated_at = ? WHERE id = ?",
                    (pobj["id"], now, rule_id),
                )
            else:
                pgrp = get_permission_group(plane_db, permission)
                plane_db.conn.execute(
                    "UPDATE ai_policy_rules SET permission_ref_kind = 'permission_group', "
                    "permission_ref_id = ?, updated_at = ? WHERE id = ?",
                    (pgrp["id"], now, rule_id),
                )
        return {"entity": {"type": "ai-access", "id": rule_id, "name": name}, "operation": op}

    return plane_db._mutate("set ai-access %s" % name, "set ai access rule", write)


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


# ---------------------------------------------------------------------------
# Remote Service (Agent)
# ---------------------------------------------------------------------------


def _server_reachable(plane_db) -> bool:
    return detect_server_reachable(plane_db)


def detect_server_reachable(plane_db=None, root: Optional[str] = None) -> bool:
    """Server reachability for Agent Remote Service operations.

    Tests may force the value with DRLINK_SERVER_REACHABLE=0|1.
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
    try:
        if plane_db is not None:
            plane_db.conn.execute("SELECT 1").fetchone()
        return True
    except Exception:
        return False


def sync_agent_catalog_from_server(plane_db, server_plane) -> None:
    """Copy Server Network/Service Objects into the Agent local catalog."""
    now = utc_now_iso()
    for obj in server_plane.list_objects():
        if obj["type"] not in ("host", "network", "fqdn", "managed_endpoint"):
            continue
        values = server_plane._object_values(obj["id"])
        payload = json.dumps(
            {"name": obj["name"], "type": obj["type"], "values": values, "origin": obj.get("origin")},
            sort_keys=True,
        )
        plane_db.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("network-object", obj["name"], payload, now),
        )
    for sobj in server_plane.conn.execute("SELECT name, type, port FROM service_objects"):
        payload = json.dumps(
            {"name": sobj["name"], "type": sobj["type"], "port": int(sobj["port"])},
            sort_keys=True,
        )
        plane_db.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("service-object", sobj["name"], payload, now),
        )


def synchronize_agent_remote_services(plane_db, *, root: Optional[str] = None) -> dict:
    """Reconnect synchronization: allocate pending endpoints, apply deletes, revalidate deps."""
    if not detect_server_reachable(plane_db, root):
        return {"status": "OFFLINE", "updated": 0}
    identity = load_agent_identity(root or getattr(plane_db, "root", None))
    updated = 0
    # Process delete_pending tombstones
    for row in list(
        plane_db.conn.execute("SELECT * FROM agent_remote_services WHERE delete_pending = 1")
    ):
        unset_remote_service_agent(plane_db, row["name"], root=root, server_reachable=True)
        updated += 1
    # Revalidate + activate remaining services
    for row in list(
        plane_db.conn.execute("SELECT * FROM agent_remote_services WHERE delete_pending = 0")
    ):
        svc_name = row["service_object"]
        sobj = get_service_object(plane_db, svc_name)
        if not sobj:
            catalog = plane_db.conn.execute(
                "SELECT payload FROM agent_object_catalog WHERE kind = 'service-object' AND name = ? COLLATE NOCASE",
                (svc_name,),
            ).fetchone()
            if not catalog:
                plane_db.conn.execute(
                    "UPDATE agent_remote_services SET status = 'DEGRADED', reason = ?, updated_at = ? "
                    "WHERE name = ?",
                    (
                        "Required Service Object '%s' is missing or invalid after reconnect." % svc_name,
                        utc_now_iso(),
                        row["name"],
                    ),
                )
                updated += 1
                continue
        # Re-apply to allocate pending endpoints / refresh HEALTHY
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
        updated += 1
    return {"status": "SYNCHRONIZED", "updated": updated}


def allocate_endpoint_port(plane_db, client_id: str, service_name: str, pool_class: str) -> int:
    used = {r[0] for r in plane_db.conn.execute("SELECT public_port FROM port_reservations WHERE released = 0")}
    used |= {
        r[0]
        for r in plane_db.conn.execute(
            "SELECT public_port FROM published_services WHERE public_port IS NOT NULL AND released = 0"
        )
    }
    start, end = (FIXED_PORT_START, FIXED_PORT_END) if pool_class == "fixed-tcp" else (NORMAL_PORT_START, NORMAL_PORT_END)
    for port in range(start, end + 1):
        if port not in used:
            plane_db.conn.execute(
                "INSERT OR REPLACE INTO port_reservations(public_port, client_id, service_id, service_name, released, created_at) "
                "VALUES (?, ?, '', ?, 0, ?)",
                (port, client_id, service_name, utc_now_iso()),
            )
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

    # Resolve destination single-target
    dest_token = str(dest).strip()
    if dest_token.lower() in ("this-host", "this_host", "self"):
        dest_token = host_name
        relay = False
        target_mode = "self"
        target_host = "127.0.0.1"
    else:
        relay = dest_token.lower() != host_name.lower()
        target_mode = "self" if not relay else "routed"
        # Validate single target
        grp = plane_db.get_object_group(dest_token) if hasattr(plane_db, "get_object_group") else None
        if grp is None:
            try:
                grp = plane_db.conn.execute(
                    "SELECT * FROM object_groups WHERE name = ? COLLATE NOCASE", (dest_token,)
                ).fetchone()
            except sqlite3.Error:
                grp = None
        if grp:
            members = plane_db._expand_group_members(grp["id"], set())
            if len(members) != 1:
                raise ControlPlaneError(
                    "ERROR:\nRemote Service destination must resolve to a single target.\n\n"
                    "Network Group '%s' contains multiple targets.\n\n"
                    "No changes were applied." % dest_token
                )
            dest_token = members[0]["name"]
        obj = plane_db.get_object(dest_token)
        if obj and obj["type"] == "network":
            raise ControlPlaneError(
                "ERROR:\nRemote Service destination must resolve to a single target.\n\n"
                "CIDR Network Object '%s' is not allowed.\n\n"
                "No changes were applied." % dest_token
            )
        if obj and obj["type"] == "host":
            vals = plane_db._object_values(obj["id"])
            target_host = vals[0] if vals else dest_token
        elif obj and obj["type"] == "fqdn":
            vals = plane_db._object_values(obj["id"])
            target_host = vals[0] if vals else dest_token
        elif obj and obj["type"] == "managed_endpoint":
            target_host = "127.0.0.1" if not relay else dest_token
            target_mode = "self" if not relay else "routed"
        else:
            # Allow literal hostname / IP when catalog has the object synchronized
            catalog = plane_db.conn.execute(
                "SELECT payload FROM agent_object_catalog WHERE kind = 'network-object' AND name = ? COLLATE NOCASE",
                (dest_token,),
            ).fetchone()
            if not obj and not catalog and dest_token.lower() != host_name.lower():
                # Still allow IP/FQDN literals for relay destinations
                try:
                    target_host = str(ipaddress.ip_address(dest_token))
                except ValueError:
                    target_host = dest_token
            else:
                target_host = dest_token if relay else "127.0.0.1"

    sobj = get_service_object(plane_db, svc_name)
    if not sobj:
        catalog = plane_db.conn.execute(
            "SELECT payload FROM agent_object_catalog WHERE kind = 'service-object' AND name = ? COLLATE NOCASE",
            (svc_name,),
        ).fetchone()
        if catalog:
            payload = json.loads(catalog["payload"])
            sobj = payload
        else:
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
    # Duplicate destination+service check
    dup = plane_db.conn.execute(
        "SELECT name FROM agent_remote_services WHERE destination = ? COLLATE NOCASE "
        "AND service_object = ? COLLATE NOCASE AND name != ? COLLATE NOCASE",
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

    endpoint_host = os.environ.get("DRLINK_HOST") or "drlink.local"
    endpoint_port = existing["endpoint_port"] if existing else None
    pending = 0
    status = "DISABLED" if not en else "HEALTHY"
    reason = ""

    if not server_reachable:
        pending = 1 if endpoint_port is None else 0
        status = "DISABLED" if not en else "DEGRADED"
        reason = "DRLink Server is currently unreachable."
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
        # Reachability probe for relay destinations (non-fatal)
        if en and target_mode == "routed" and status == "HEALTHY":
            if not _probe_tcp(target_host, sport):
                status = "DEGRADED"
                reason = "Destination is currently unreachable from Relay Host."

    now = utc_now_iso()
    client_for_pub = locals().get("client")

    def write_all():
        # Nested helpers (set_published_service) also call _mutate; run them as batch
        # participants of this outer transaction.
        nested_prev = getattr(plane_db, "_batch_mode", False)
        plane_db._batch_mode = True
        try:
            if (
                server_reachable
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
                    "(service_id, status, pool_class, service_object_id, destination_name, pending_allocation, delete_pending, reason) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        pub["id"],
                        status if en else "DISABLED",
                        pool_class,
                        sobj_row["id"] if sobj_row else None,
                        dest_token,
                        pending,
                        reason,
                    ),
                )
            plane_db.conn.execute(
                "INSERT OR REPLACE INTO agent_remote_services"
                "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
                "pending_allocation, delete_pending, pool_class, reason, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                (
                    name,
                    dest_token,
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

    result = plane_db._mutate("set remote-service %s" % name, "set remote service", write_all)
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
            if pending or endpoint_port is None
            else "ssh -p %s user@%s" % (endpoint_port, endpoint_host)
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

    def write():
        plane_db.conn.execute("DELETE FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,))
        if server_reachable:
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
        else:
            # Queue deletion intent: keep a tombstone marker via insert with delete_pending
            plane_db.conn.execute(
                "INSERT OR REPLACE INTO agent_remote_services"
                "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
                "pending_allocation, delete_pending, pool_class, reason, updated_at) "
                "VALUES (?, ?, ?, 0, 'DISABLED', ?, ?, 0, 1, ?, 'delete pending sync', ?)",
                (
                    name,
                    existing["destination"],
                    existing["service_object"],
                    existing["endpoint_host"],
                    existing["endpoint_port"],
                    existing["pool_class"],
                    utc_now_iso(),
                ),
            )
        return {"entity": {"type": "remote-service", "id": name, "name": name}, "operation": "delete"}

    return plane_db._mutate("unset remote-service %s" % name, "delete remote service", write)


def format_remote_service_view(view: dict) -> str:
    lines = [
        "Remote Service activated." if view.get("status") != "DEGRADED" else "Remote Service created.",
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
        lines.extend(
            [
                "",
                "Configuration was saved.",
                "The service will become available automatically when connectivity is restored."
                if "unreachable" in (view.get("reason") or "").lower()
                else "Endpoint allocation and activation will complete automatically after reconnect.",
            ]
        )
    return "\n".join(lines) + "\n"


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
                eff = effective_policy_result(pol["mode"], pol["enforcement"], matched=False)
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


def parse_kv_tokens(tokens: list[str]) -> dict[str, str]:
    """Parse `key value` pairs from a token list."""
    out: dict[str, str] = {}
    i = 0
    flags = {"enabled", "disabled"}
    while i < len(tokens):
        key = str(tokens[i]).strip().lower()
        if key in flags:
            out["enabled"] = "yes" if key == "enabled" else "no"
            i += 1
            continue
        if i + 1 >= len(tokens):
            raise ControlPlaneError(cli_error("Incomplete argument: %s" % key))
        out[key] = tokens[i + 1]
        i += 2
    return out


def parse_csv_list(value: str) -> list[str]:
    return [p.strip() for p in str(value or "").split(",") if p.strip()]
