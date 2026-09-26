#!/usr/bin/env python3
"""Canonical v2.4 ConfigurationBundle (master schema).

Supports both:
  configurationBundle:
    context: server|agent
    ...

and rejects malformed Markdown/prose pastes atomically.
"""
from __future__ import annotations

import io
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from drlink_control_db import ControlPlaneError, utc_now_iso
from drlink_control_plane import (
    ConcurrencyError,
    ConfirmationRequired,
    ControlPlane,
)
from drlink_configuration_bundle import BundleError
import drlink_v24 as v24


def _yaml():
    try:
        import yaml as _mod
    except ImportError as exc:
        raise BundleError(
            "PyYAML is required for ConfigurationBundle YAML input and export.\n"
            "Install the python3-yaml (or PyYAML) package, then retry."
        ) from exc
    return _mod

SERVER_SECTIONS = (
    "networkObjects",
    "networkGroups",
    "serviceObjects",
    "serviceGroups",
    "permissionObjects",
    "permissionGroups",
    "remoteAccess",
    "internetAccess",
    "aiAccess",
)
AGENT_SECTIONS = ("remoteServices",)

NETWORK_OBJECT_KEYS = frozenset({"name", "type", "value", "state"})
NETWORK_GROUP_KEYS = frozenset({"name", "members", "state"})
SERVICE_OBJECT_KEYS = frozenset({"name", "type", "port", "state"})
SERVICE_GROUP_KEYS = frozenset({"name", "members", "state"})
PERMISSION_OBJECT_KEYS = frozenset({"name", "permissions", "state"})
PERMISSION_GROUP_KEYS = frozenset({"name", "members", "state"})
REMOTE_SERVICE_KEYS = frozenset({"name", "destination", "service", "enabled", "state"})
ACCESS_SECTION_KEYS = frozenset({"mode", "enforcement", "rules", "state"})
ACCESS_RULE_KEYS = frozenset({"name", "source", "destination", "service", "enabled", "state", "mode"})
AI_RULE_KEYS = frozenset(
    {"name", "source", "destination", "permission", "paths", "enabled", "state", "mode"}
)


def _bundle_error(msg: str) -> None:
    raise BundleError("ERROR:\n%s\n\nNo changes were applied." % msg)


def _require_mapping(item: Any, label: str) -> dict:
    if not isinstance(item, dict):
        _bundle_error("%s must be a mapping." % label)
    return item


def _reject_unknown_keys(item: dict, allowed: frozenset, label: str) -> None:
    unknown = sorted(set(item.keys()) - set(allowed))
    if unknown:
        _bundle_error(
            "%s contains unknown field(s): %s.\n\nUnknown or misspelled fields are rejected."
            % (label, ", ".join(unknown))
        )


def _parse_bool_field(value: Any, *, field_name: str = "enabled") -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("true", "yes", "1", "enabled"):
            return True
        if token in ("false", "no", "0", "disabled"):
            return False
    _bundle_error(
        "Invalid %s value %r.\n\nAccepted values: true, false (YAML boolean preferred)."
        % (field_name, value)
    )
    raise AssertionError("unreachable")


def _materialize_enabled(item: dict, existing_enabled: Optional[bool]) -> bool:
    """Resolve effective enabled for plan/diff/apply.

    Contract:
      - explicit enabled true/false → that value
      - omitted on an existing resource → preserve existing enabled/disabled
      - omitted on a new resource → default True (current creation semantics)
    Mutates item['enabled'] to the effective bool so plan NO_CHANGE / security
    impact / apply all see the same desired value.
    """
    if "enabled" in item:
        return bool(item["enabled"])
    if existing_enabled is not None:
        item["enabled"] = bool(existing_enabled)
        return bool(existing_enabled)
    item["enabled"] = True
    return True


def _parse_enforcement(value: Any) -> str:
    if value is None:
        return "enabled"
    if not isinstance(value, str):
        _bundle_error("enforcement must be the string 'enabled' or 'disabled'.")
    token = value.strip().lower()
    if token in ("enabled", "disabled"):
        return token
    _bundle_error(
        "Invalid enforcement value '%s'.\n\nAccepted values: enabled, disabled." % value
    )
    raise AssertionError("unreachable")


def _parse_mode(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        _bundle_error("mode must be 'blacklist' or 'whitelist'.")
    token = value.strip().lower()
    if token in ("blacklist", "whitelist"):
        return token
    _bundle_error("Invalid mode '%s'.\n\nAccepted values: blacklist, whitelist." % value)
    raise AssertionError("unreachable")


def _require_name(item: dict, label: str) -> str:
    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        _bundle_error("%s is missing required field 'name'." % label)
    return name.strip()


def _normalize_member_list(value: Any, label: str) -> list[str]:
    if value is None:
        _bundle_error("%s requires members." % label)
    if isinstance(value, str):
        return [p.strip() for p in value.split(",") if p.strip()]
    if isinstance(value, list):
        out = []
        for entry in value:
            if not isinstance(entry, str) or not entry.strip():
                _bundle_error("%s members must be a list of names." % label)
            out.append(entry.strip())
        return out
    _bundle_error("%s members must be a list or comma-separated string." % label)
    raise AssertionError("unreachable")


def _normalize_set(values: list[str]) -> list[str]:
    return sorted({v.lower(): v for v in values}.values(), key=lambda s: s.lower())


def _validate_network_object_item(item: dict) -> dict:
    item = _require_mapping(item, "networkObjects entry")
    _reject_unknown_keys(item, NETWORK_OBJECT_KEYS, "Network Object '%s'" % item.get("name", "?"))
    _absent_and_present_fields(item)
    name = _require_name(item, "Network Object")
    if str(item.get("state") or "").lower() == "absent":
        return {"name": name, "state": "absent"}
    ntype = str(item.get("type") or "").strip().lower()
    if ntype not in ("ip", "cidr", "fqdn", "host", "network"):
        _bundle_error(
            "Network Object '%s' has invalid type '%s'.\n\nAccepted: ip, cidr, fqdn."
            % (name, item.get("type"))
        )
    value = item.get("value")
    if value is None or (isinstance(value, str) and not value.strip()):
        _bundle_error(
            "Network Object '%s' is missing required field 'value'." % name
        )
    if not isinstance(value, (str, int)):
        _bundle_error("Network Object '%s' value must be a string." % name)
    return {"name": name, "type": ntype, "value": str(value).strip()}


def _validate_service_object_item(item: dict) -> dict:
    item = _require_mapping(item, "serviceObjects entry")
    _reject_unknown_keys(item, SERVICE_OBJECT_KEYS, "Service Object '%s'" % item.get("name", "?"))
    _absent_and_present_fields(item)
    name = _require_name(item, "Service Object")
    if str(item.get("state") or "").lower() == "absent":
        return {"name": name, "state": "absent"}
    stype = str(item.get("type") or "").strip().lower()
    if stype not in ("tcp", "udp", "fixed-tcp"):
        _bundle_error(
            "Service Object '%s' has invalid type '%s'.\n\nAccepted: tcp, udp, fixed-tcp."
            % (name, item.get("type"))
        )
    port = item.get("port")
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        _bundle_error("Service Object '%s' port must be an integer." % name)
        raise AssertionError("unreachable")
    if port_i < 1 or port_i > 65535:
        _bundle_error("Service Object '%s' port must be between 1 and 65535." % name)
    return {"name": name, "type": stype, "port": port_i}


def _validate_group_item(item: dict, *, kind: str, keys: frozenset, member_field: str = "members") -> dict:
    item = _require_mapping(item, "%s entry" % kind)
    _reject_unknown_keys(item, keys, "%s '%s'" % (kind, item.get("name", "?")))
    _absent_and_present_fields(item)
    name = _require_name(item, kind)
    if str(item.get("state") or "").lower() == "absent":
        return {"name": name, "state": "absent"}
    members = _normalize_member_list(item.get(member_field), "%s '%s'" % (kind, name))
    return {"name": name, member_field: members}


def _validate_remote_service_item(item: dict) -> dict:
    item = _require_mapping(item, "remoteServices entry")
    _reject_unknown_keys(item, REMOTE_SERVICE_KEYS, "Remote Service '%s'" % item.get("name", "?"))
    _absent_and_present_fields(item)
    name = _require_name(item, "Remote Service")
    if str(item.get("state") or "").lower() == "absent":
        return {"name": name, "state": "absent"}
    dest = item.get("destination")
    svc = item.get("service")
    if not isinstance(dest, str) or not dest.strip():
        _bundle_error("Remote Service '%s' is missing required field 'destination'." % name)
    if not isinstance(svc, str) or not svc.strip():
        _bundle_error("Remote Service '%s' is missing required field 'service'." % name)
    out = {
        "name": name,
        "destination": dest.strip(),
        "service": svc.strip(),
    }
    if "enabled" in item:
        out["enabled"] = _parse_bool_field(item.get("enabled"))
    return out


def _validate_access_rule(item: dict, *, family: str) -> dict:
    keys = AI_RULE_KEYS if family == "ai" else ACCESS_RULE_KEYS
    item = _require_mapping(item, "%s rule" % family)
    _reject_unknown_keys(item, keys, "%s Access Rule '%s'" % (family.title(), item.get("name", "?")))
    # Tolerate common misspelling by rejecting explicitly if present under wrong key — already covered by unknown keys
    _absent_and_present_fields(item)
    name = _require_name(item, "%s Access Rule" % family.title())
    if str(item.get("state") or "").lower() == "absent":
        return {"name": name, "state": "absent"}
    source = item.get("source")
    destination = item.get("destination")
    if not isinstance(source, str) or not source.strip():
        _bundle_error("Rule '%s' is missing required field 'source'." % name)
    if not isinstance(destination, str) or not destination.strip():
        _bundle_error("Rule '%s' is missing required field 'destination'." % name)
    out = {
        "name": name,
        "source": source.strip(),
        "destination": destination.strip(),
    }
    if "enabled" in item:
        out["enabled"] = _parse_bool_field(item.get("enabled"))
    if item.get("mode") is not None:
        out["mode"] = _parse_mode(item.get("mode"))
    if family == "ai":
        perm = item.get("permission")
        if not isinstance(perm, str) or not perm.strip():
            _bundle_error("Rule '%s' is missing required field 'permission'." % name)
        out["permission"] = perm.strip()
        if "paths" in item:
            raw_paths = item.get("paths")
            if raw_paths is None:
                out["paths"] = []
            elif isinstance(raw_paths, str):
                out["paths"] = v24.parse_ai_paths_field(raw_paths)
            elif isinstance(raw_paths, list):
                cleaned = []
                for entry in raw_paths:
                    if not isinstance(entry, str) or not entry.strip():
                        _bundle_error(
                            "Rule '%s' paths entries must be non-empty strings." % name
                        )
                    cleaned.append(entry.strip())
                out["paths"] = v24._normalize_path_scope_patterns(cleaned)
            else:
                _bundle_error(
                    "Rule '%s' paths must be a list of strings or a comma-separated string."
                    % name
                )
    else:
        svc = item.get("service")
        if not isinstance(svc, str) or not svc.strip():
            _bundle_error("Rule '%s' is missing required field 'service'." % name)
        out["service"] = svc.strip()
    return out


def _validate_access_section(section: Any, *, key: str, family: str) -> dict:
    section = _require_mapping(section, key)
    _reject_unknown_keys(section, ACCESS_SECTION_KEYS, key)
    if str(section.get("state") or "").lower() == "absent":
        extras = {k for k in section.keys() if k not in ("state",)}
        if extras:
            _bundle_error("%s declares state: absent with other fields." % key)
        return {"state": "absent"}
    out: dict[str, Any] = {}
    if "mode" in section:
        out["mode"] = _parse_mode(section.get("mode"))
    if "enforcement" in section:
        out["enforcement"] = _parse_enforcement(section.get("enforcement"))
    if "rules" in section:
        if not isinstance(section["rules"], list):
            _bundle_error("%s.rules must be a list." % key)
        out["rules"] = [_validate_access_rule(r, family=family) for r in section["rules"]]
    return out


def _desired_name_set(items: list[dict]) -> set[str]:
    return {str(i.get("name") or "").lower() for i in items if i.get("state") != "absent" and i.get("name")}


def _effective_public_name_set(db_names: Iterable[str], items: list[dict]) -> set[str]:
    """Post-apply public-name set after Bundle creates/updates/absent deletes."""
    names = {str(n or "").lower() for n in db_names if n}
    for item in items:
        key = str(item.get("name") or "").lower()
        if not key:
            continue
        if item.get("state") == "absent":
            names.discard(key)
        else:
            names.add(key)
    return names


def _reject_cross_kind_public_name_overlap(
    object_names: set[str],
    group_names: set[str],
    *,
    object_kind: str,
    group_kind: str,
) -> None:
    overlap = sorted(object_names & group_names)
    if not overlap:
        return
    name = overlap[0]
    extra = ""
    if len(overlap) > 1:
        extra = "\nAdditional ambiguous names: %s." % ", ".join(overlap[1:])
    _bundle_error(
        "Public name '%s' is ambiguous because both a %s and a %s would exist.%s\n\n"
        "%s and %s names must be unique across that selector namespace."
        % (name, object_kind, group_kind, extra, object_kind, group_kind)
    )


def _ref_exists_in_bundle_or_db(
    plane: ControlPlane,
    *,
    name: str,
    bundle_names: set[str],
    db_lookup,
    label: str,
) -> None:
    if name.lower() in bundle_names:
        return
    if db_lookup(name):
        return
    _bundle_error(
        "Required %s '%s' does not exist.\n\n"
        "Create it in the same ConfigurationBundle\n"
        "or create it before applying the Rule." % (label, name)
    )


def _ai_rule_view(plane: ControlPlane, row) -> dict:
    principal = plane.conn.execute(
        "SELECT name FROM ai_principals WHERE id = ?", (row["source_identity_id"],)
    ).fetchone()
    dest = "-"
    kind = row["destination_ref_kind"]
    if kind == "object":
        obj = plane.conn.execute(
            "SELECT name FROM objects WHERE id = ?", (row["destination_ref_id"],)
        ).fetchone()
        dest = obj["name"] if obj else dest
    elif kind == "group":
        g = plane.conn.execute(
            "SELECT name FROM object_groups WHERE id = ?", (row["destination_ref_id"],)
        ).fetchone()
        dest = g["name"] if g else dest
    elif kind == "client":
        c = plane.conn.execute(
            "SELECT COALESCE(label, hostname, id) AS name FROM clients WHERE id = ?",
            (row["destination_ref_id"],),
        ).fetchone()
        dest = c["name"] if c else dest
    perm = "-"
    pkind = row["permission_ref_kind"]
    if pkind == "permission_object":
        p = plane.conn.execute(
            "SELECT name FROM permission_objects WHERE id = ?", (row["permission_ref_id"],)
        ).fetchone()
        perm = p["name"] if p else perm
    elif pkind == "permission_group":
        g = plane.conn.execute(
            "SELECT name FROM permission_groups WHERE id = ?", (row["permission_ref_id"],)
        ).fetchone()
        perm = g["name"] if g else perm
    return {
        "source": principal["name"] if principal else "-",
        "destination": dest,
        "permission": perm,
        "enabled": bool(row["enabled"]),
        "destination_kind": kind,
        "permission_kind": pkind,
        "paths": v24.list_ai_policy_path_scopes(plane, row["name"]),
    }


def _rule_matches_desired(plane: ControlPlane, family: str, existing, desired: dict) -> bool:
    if family == "ai":
        view = _ai_rule_view(plane, existing)
        if "enabled" in desired and bool(view["enabled"]) != bool(desired["enabled"]):
            return False
        if str(view["source"] or "").lower() != str(desired.get("source") or "").lower():
            return False
        if str(view["destination"] or "").lower() != str(desired.get("destination") or "").lower():
            return False
        if str(view["permission"] or "").lower() != str(desired.get("permission") or "").lower():
            return False
        if "paths" in desired:
            if not _group_members_equal(list(view.get("paths") or []), list(desired.get("paths") or [])):
                return False
        return True
    view = plane._rule_view(existing)
    if "enabled" in desired and bool(view["enabled"]) != bool(desired["enabled"]):
        return False
    src = (view.get("sources") or [None])[0]
    dst = (view.get("destinations") or [None])[0]
    if str(src or "").lower() != str(desired.get("source") or "").lower():
        return False
    if str(dst or "").lower() != str(desired.get("destination") or "").lower():
        return False
    # service object name
    ref = plane.conn.execute(
        "SELECT ref_kind, ref_id FROM rule_service_refs WHERE rule_id = ?", (existing["id"],)
    ).fetchone()
    svc_name = None
    if ref and ref["ref_kind"] == "service_object":
        sobj = plane.conn.execute(
            "SELECT name FROM service_objects WHERE id = ?", (ref["ref_id"],)
        ).fetchone()
        svc_name = sobj["name"] if sobj else None
    elif ref and ref["ref_kind"] == "service_group":
        sgrp = plane.conn.execute(
            "SELECT name FROM service_groups WHERE id = ?", (ref["ref_id"],)
        ).fetchone()
        svc_name = sgrp["name"] if sgrp else None
    return str(svc_name or "").lower() == str(desired.get("service") or "").lower()


def _group_members_equal(existing: list[str], desired: list[str]) -> bool:
    return {m.lower() for m in existing} == {m.lower() for m in desired}


def _security_impact_for_plan(plane: ControlPlane, context: str, body: dict, changes: list[dict]) -> list[str]:
    impact: list[str] = []
    if context != "server":
        return impact
    for family, key, title in (
        ("remote", "remoteAccess", "Remote Access"),
        ("internet", "internetAccess", "Internet Access"),
        ("ai", "aiAccess", "AI Access"),
    ):
        section = body.get(key)
        if not section:
            continue
        pol = v24.get_access_policy(plane, family)
        if section.get("state") == "absent" and pol.get("mode") is not None:
            impact.append(
                "WARNING: This change resets %s.\nBefore: mode=%s enforcement=%s\nAfter: mode removed / rules removed / Effective: ALLOW"
                % (title, pol.get("mode"), pol.get("enforcement"))
            )
            continue
        want_enf = section.get("enforcement")
        if want_enf == "disabled" and str(pol.get("enforcement")).lower() == "enabled":
            blocking = v24._count_blocking_rules(plane, family if family != "ai" else "ai")
            impact.append(
                "WARNING: This change broadens %s.\nBefore:\n  %s\n  Enforcement: ENABLED\n  Effective blocking rules: %s\nAfter:\n  %s\n  Enforcement: DISABLED\n  Effective result: ALLOW ALL"
                % (title, str(pol.get("mode") or "-").upper(), blocking, str(section.get("mode") or pol.get("mode") or "-").upper())
            )
        # last blacklist rule deletion / disable
        if pol.get("mode") == "blacklist" and str(pol.get("enforcement")).lower() == "enabled":
            enabled_before = v24._count_blocking_rules(plane, family if family != "ai" else "ai")
            deleting = 0
            disabling = 0
            for rule in section.get("rules") or []:
                if family == "ai":
                    row = plane.conn.execute(
                        "SELECT enabled FROM ai_policy_rules WHERE name = ? COLLATE NOCASE",
                        (rule.get("name"),),
                    ).fetchone()
                else:
                    row = plane._get_rule(family, rule.get("name"))
                if not row or not bool(row["enabled"]):
                    continue
                if rule.get("state") == "absent":
                    deleting += 1
                elif rule.get("enabled") is False:
                    disabling += 1
            if enabled_before > 0 and enabled_before - deleting - disabling <= 0:
                impact.append(
                    "WARNING: This change broadens %s by removing the last BLACKLIST blocking Rule."
                    % title
                )
        # whitelist → zero enabled rules after merge with authoritative state
        want_mode = section.get("mode") or pol.get("mode")
        if want_mode == "whitelist":
            rules = section.get("rules")
            if rules is not None:
                if family == "ai":
                    current = {
                        str(r["name"])
                        for r in plane.conn.execute(
                            "SELECT name FROM ai_policy_rules WHERE enabled = 1"
                        )
                    }
                else:
                    current = {
                        str(r["name"])
                        for r in plane.conn.execute(
                            "SELECT name FROM policy_rules WHERE plane = ? AND enabled = 1",
                            (family,),
                        )
                    }
                for rule in rules:
                    name = str(rule.get("name") or "").strip()
                    if not name:
                        continue
                    if rule.get("state") == "absent":
                        current.discard(name)
                        # case-insensitive discard
                        current = {n for n in current if n.lower() != name.lower()}
                    elif rule.get("enabled") is False:
                        current = {n for n in current if n.lower() != name.lower()}
                    else:
                        # enabled true/default → present after apply
                        current = {n for n in current if n.lower() != name.lower()}
                        current.add(name)
                enabled_after = len(current)
                if enabled_after == 0 and str(
                    section.get("enforcement") or pol.get("enforcement")
                ).lower() != "disabled":
                    impact.append(
                        "WARNING: This change narrows %s; WHITELIST with zero "
                        "enabled Rules → DENY ALL." % title
                    )

        # Rule mutations: WHITELIST enable and BLACKLIST/WHITELIST selector changes
        # that can turn previously denied flows into ALLOW.
        for c in changes:
            if c.get("op") != "SET" or c.get("kind") != ("%s-access-rule" % family):
                continue
            rule_name = str(c.get("name") or "").strip()
            item = c.get("item") or {}
            if not rule_name:
                continue
            if family == "ai":
                hit = v24.ai_access_rule_update_security_impact(
                    plane,
                    rule_name,
                    source=item.get("source"),
                    destination=item.get("destination"),
                    permission=item.get("permission"),
                    paths=item.get("paths") if "paths" in item else None,
                    enabled=item.get("enabled"),
                )
            else:
                hit = v24.access_rule_update_security_impact(
                    plane,
                    family,
                    rule_name,
                    source=item.get("source"),
                    destination=item.get("destination"),
                    service=item.get("service"),
                    enabled=item.get("enabled"),
                )
            if hit and hit.get("warning"):
                text = "WARNING: %s" % hit["warning"]
                if text not in impact:
                    impact.append(text)

    # Referenced reusable selector mutations (Object/Group value or membership)
    # can broaden enabled BLACKLIST / WHITELIST policies without changing Rules.
    for c in changes:
        op = c.get("op")
        kind = c.get("kind")
        name = str(c.get("name") or "").strip()
        item = c.get("item") or {}
        if not name or op in ("NO_CHANGE", "DELETE"):
            continue
        hit = None
        if kind == "network-object" and op in ("UPDATE", "SET"):
            hit = v24.referenced_selector_mutation_security_impact(
                plane,
                kind="network-object",
                name=name,
                value=item.get("value"),
                type=item.get("type"),
            )
        elif kind == "network-group" and op == "SET":
            hit = v24.referenced_selector_mutation_security_impact(
                plane,
                kind="network-group",
                name=name,
                members=list(item.get("members") or []),
            )
        elif kind == "service-object" and op in ("UPDATE", "SET"):
            port = item.get("port")
            hit = v24.referenced_selector_mutation_security_impact(
                plane,
                kind="service-object",
                name=name,
                type=item.get("type"),
                port=int(port) if port is not None else None,
            )
        elif kind == "service-group" and op == "SET":
            hit = v24.referenced_selector_mutation_security_impact(
                plane,
                kind="service-group",
                name=name,
                members=list(item.get("members") or []),
            )
        elif kind == "permission-object" and op == "SET":
            hit = v24.referenced_selector_mutation_security_impact(
                plane,
                kind="permission-object",
                name=name,
                permissions=list(item.get("permissions") or []),
            )
        elif kind == "permission-group" and op == "SET":
            hit = v24.referenced_selector_mutation_security_impact(
                plane,
                kind="permission-group",
                name=name,
                members=list(item.get("members") or []),
            )
        if hit and hit.get("warning"):
            text = "WARNING: %s" % hit["warning"]
            if text not in impact:
                impact.append(text)

    # Indirect broadening: deleting Permission Object/Group still referenced by
    # enabled AI BLACKLIST rules (and those rules are not deleted in this plan).
    deleting_ai_rules = {
        str(c.get("name") or "").lower()
        for c in changes
        if c.get("op") == "DELETE" and c.get("kind") == "ai-access-rule"
    }
    pol_ai = v24.get_access_policy(plane, "ai")
    if (
        str(pol_ai.get("mode") or "").lower() == "blacklist"
        and str(pol_ai.get("enforcement") or "enabled").lower() == "enabled"
    ):
        for c in changes:
            if c.get("op") != "DELETE":
                continue
            kind = c.get("kind")
            name = str(c.get("name") or "").strip()
            if not name:
                continue
            refs: list[dict] = []
            if kind == "permission-object":
                refs = v24.permission_object_references(plane, name)
            elif kind == "permission-group":
                refs = v24.permission_group_references(plane, name)
            elif kind == "ai-identity":
                refs = v24.ai_identity_references(plane, name)
            else:
                continue
            live = [
                r
                for r in refs
                if r.get("kind") == "ai-access"
                and str(r.get("name") or "").lower() not in deleting_ai_rules
            ]
            if not live:
                continue
            # Only warn when at least one remaining referenced rule is enabled BLACKLIST
            blocking_left = False
            for r in live:
                row = plane.conn.execute(
                    "SELECT enabled FROM ai_policy_rules WHERE name = ? COLLATE NOCASE",
                    (r.get("name"),),
                ).fetchone()
                if row and bool(row["enabled"]):
                    blocking_left = True
                    break
            if blocking_left:
                impact.append(
                    "WARNING: This change broadens AI Access by deleting '%s' while enabled "
                    "BLACKLIST Rule(s) still reference it.\nReferences:\n%s"
                    % (name, "\n".join("  %s" % r["display"] for r in live))
                )
    return impact


@dataclass
class V24Plan:
    context: str
    changes: list[dict] = field(default_factory=list)
    no_change: bool = False
    security_impact: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    base_revision: Optional[int] = None
    source_text: str = ""

    @property
    def mutating_changes(self) -> list[dict]:
        return [c for c in self.changes if c.get("op") != "NO_CHANGE"]


def _strip_end_terminator(text: str) -> str:
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    if lines and lines[-1].strip() == ":end":
        lines = lines[:-1]
    return "\n".join(lines)


def _reject_markdown_prose(text: str) -> None:
    stripped = text.lstrip()
    if not stripped:
        raise BundleError(
            "ERROR:\nConfiguration input is not valid ConfigurationBundle YAML.\n\n"
            "No changes were applied."
        )
    if stripped.startswith("```") or stripped.startswith("# ") or stripped.lower().startswith("here"):
        raise BundleError(
            "ERROR:\nConfiguration input is not valid ConfigurationBundle YAML.\n\n"
            "Unexpected content before the Bundle.\n\n"
            "No changes were applied."
        )
    # Disallow leading prose paragraphs before configurationBundle/apiVersion
    first = stripped.split("\n", 1)[0].strip()
    if not (
        first.startswith("configurationBundle:")
        or first.startswith("apiVersion:")
        or first.startswith("---")
    ):
        # Allow YAML starting with a comment
        if not first.startswith("#"):
            raise BundleError(
                "ERROR:\nConfiguration input is not valid ConfigurationBundle YAML.\n\n"
                "Unexpected content before the Bundle.\n\n"
                "No changes were applied."
            )


def parse_v24_bundle(raw_text: str) -> dict:
    text = _strip_end_terminator(raw_text)
    _reject_markdown_prose(text)
    yaml = _yaml()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise BundleError(
            "ERROR:\nConfiguration input is not valid ConfigurationBundle YAML.\n\n"
            "%s\n\nNo changes were applied." % exc
        ) from exc
    if not isinstance(data, dict):
        raise BundleError(
            "ERROR:\nConfiguration input is not valid ConfigurationBundle YAML.\n\n"
            "No changes were applied."
        )
    if "configurationBundle" in data:
        body = data["configurationBundle"]
        if not isinstance(body, dict):
            raise BundleError("configurationBundle must be a mapping")
        context = str(body.get("context") or "").strip().lower()
        if context not in ("server", "agent"):
            raise BundleError(
                "ERROR:\nconfigurationBundle.context must be 'server' or 'agent'.\n\n"
                "No changes were applied."
            )
        return {"context": context, "body": body, "format": "v24"}
    # Legacy apiVersion/kind form — still accepted for transition, mapped poorly;
    # fail closed if neither schema is present.
    if data.get("kind") == "ConfigurationBundle":
        raise BundleError(
            "ERROR:\nLegacy ConfigurationBundle apiVersion/kind form is not the canonical v2.4 schema.\n\n"
            "Use:\nconfigurationBundle:\n  context: server|agent\n  ...\n\n"
            "No changes were applied."
        )
    raise BundleError(
        "ERROR:\nConfiguration input is not valid ConfigurationBundle YAML.\n\n"
        "Expected top-level key: configurationBundle\n\n"
        "No changes were applied."
    )


def _absent_and_present_fields(item: dict) -> None:
    if str(item.get("state") or "").strip().lower() != "absent":
        return
    extras = {k for k in item.keys() if k not in ("name", "state")}
    if extras:
        raise BundleError(
            "ERROR:\nResource '%s' declares state: absent and present-state fields.\n\n"
            "No changes were applied." % item.get("name", "?")
        )


def prepare_v24_plan(plane: ControlPlane, raw_text: str, *, role: Optional[str] = None) -> V24Plan:
    parsed = parse_v24_bundle(raw_text)
    context = parsed["context"]
    body = parsed["body"]
    role = role or v24.detect_cli_role(plane.root)
    if context == "server" and role == "agent":
        raise BundleError(
            "ERROR:\nConfigurationBundle context is 'server' but this CLI is Agent Host.\n\n"
            "No changes were applied."
        )
    if context == "agent" and role == "server":
        raise BundleError(
            "ERROR:\nConfigurationBundle context is 'agent' but this CLI is DRLink Server.\n\n"
            "No changes were applied."
        )
    if context == "server":
        bad = [k for k in body.keys() if k not in SERVER_SECTIONS and k != "context"]
        if "remoteServices" in body:
            raise BundleError(
                "ERROR:\nServer ConfigurationBundle cannot contain remoteServices.\n\n"
                "No changes were applied."
            )
        if bad:
            _bundle_error("Unknown Server Bundle sections: %s" % ", ".join(sorted(bad)))
    else:
        bad = [k for k in body.keys() if k not in AGENT_SECTIONS and k != "context"]
        for section in SERVER_SECTIONS:
            if section in body:
                raise BundleError(
                    "ERROR:\nAgent ConfigurationBundle cannot contain Server section '%s'.\n\n"
                    "No changes were applied." % section
                )
        if bad:
            _bundle_error("Unknown Agent Bundle sections: %s" % ", ".join(sorted(bad)))

    changes: list[dict] = []
    validated_body: dict[str, Any] = {"context": context}

    if context == "server":
        nos = [_validate_network_object_item(i) for i in (body.get("networkObjects") or [])]
        ngs = [
            _validate_group_item(i, kind="Network Group", keys=NETWORK_GROUP_KEYS)
            for i in (body.get("networkGroups") or [])
        ]
        sos = [_validate_service_object_item(i) for i in (body.get("serviceObjects") or [])]
        sgs = [
            _validate_group_item(i, kind="Service Group", keys=SERVICE_GROUP_KEYS)
            for i in (body.get("serviceGroups") or [])
        ]
        pos = []
        for raw in body.get("permissionObjects") or []:
            item = _require_mapping(raw, "permissionObjects entry")
            _reject_unknown_keys(item, PERMISSION_OBJECT_KEYS, "Permission Object '%s'" % item.get("name", "?"))
            _absent_and_present_fields(item)
            name = _require_name(item, "Permission Object")
            if str(item.get("state") or "").lower() == "absent":
                pos.append({"name": name, "state": "absent"})
            else:
                perms = _normalize_member_list(item.get("permissions"), "Permission Object '%s'" % name)
                pos.append({"name": name, "permissions": perms})
        pgs = [
            _validate_group_item(i, kind="Permission Group", keys=PERMISSION_GROUP_KEYS)
            for i in (body.get("permissionGroups") or [])
        ]
        validated_body["networkObjects"] = nos
        validated_body["networkGroups"] = ngs
        validated_body["serviceObjects"] = sos
        validated_body["serviceGroups"] = sgs
        validated_body["permissionObjects"] = pos
        validated_body["permissionGroups"] = pgs

        no_names = _desired_name_set(nos) | {
            r["name"].lower()
            for r in plane.conn.execute("SELECT name FROM objects")
        }
        ng_names = _desired_name_set(ngs) | {
            r["name"].lower()
            for r in plane.conn.execute("SELECT name FROM object_groups")
        }
        so_names = _desired_name_set(sos) | {
            r["name"].lower()
            for r in plane.conn.execute("SELECT name FROM service_objects")
        }
        sg_names = _desired_name_set(sgs) | {
            r["name"].lower()
            for r in plane.conn.execute("SELECT name FROM service_groups")
        }
        po_names = _desired_name_set(pos) | {
            r["name"].lower()
            for r in plane.conn.execute("SELECT name FROM permission_objects")
        }
        pg_names = _desired_name_set(pgs) | {
            r["name"].lower()
            for r in plane.conn.execute("SELECT name FROM permission_groups")
        }

        # Fail closed on Object/Group public-name collisions that Bundle would create
        # or retain after apply (case-insensitive).
        _reject_cross_kind_public_name_overlap(
            _effective_public_name_set(
                (r["name"] for r in plane.conn.execute("SELECT name FROM objects")),
                nos,
            ),
            _effective_public_name_set(
                (r["name"] for r in plane.conn.execute("SELECT name FROM object_groups")),
                ngs,
            ),
            object_kind="Network Object",
            group_kind="Network Group",
        )
        _reject_cross_kind_public_name_overlap(
            _effective_public_name_set(
                (r["name"] for r in plane.conn.execute("SELECT name FROM service_objects")),
                sos,
            ),
            _effective_public_name_set(
                (r["name"] for r in plane.conn.execute("SELECT name FROM service_groups")),
                sgs,
            ),
            object_kind="Service Object",
            group_kind="Service Group",
        )
        _reject_cross_kind_public_name_overlap(
            _effective_public_name_set(
                (r["name"] for r in plane.conn.execute("SELECT name FROM permission_objects")),
                pos,
            ),
            _effective_public_name_set(
                (r["name"] for r in plane.conn.execute("SELECT name FROM permission_groups")),
                pgs,
            ),
            object_kind="Permission Object",
            group_kind="Permission Group",
        )

        for item in nos:
            name = item["name"]
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "network-object", "name": name, "item": item})
                continue
            existing = plane.get_object(name)
            store_type = v24.NETWORK_STORE.get(str(item.get("type") or "").lower())
            if (
                existing
                and store_type
                and existing["type"] == store_type
                and plane._object_values(existing["id"])[:1] == [str(item.get("value"))]
            ):
                changes.append({"op": "NO_CHANGE", "kind": "network-object", "name": name})
            else:
                changes.append(
                    {
                        "op": "CREATE" if not existing else "UPDATE",
                        "kind": "network-object",
                        "name": name,
                        "item": item,
                    }
                )
        for item in ngs:
            name = item["name"]
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "network-group", "name": name, "item": item})
                continue
            existing = plane.get_object_group(name)
            if existing:
                members = [m["name"] for m in plane._expand_group_members(existing["id"], set())]
                if _group_members_equal(members, item.get("members") or []):
                    changes.append({"op": "NO_CHANGE", "kind": "network-group", "name": name})
                    continue
            changes.append({"op": "SET", "kind": "network-group", "name": name, "item": item})
        for item in sos:
            name = item["name"]
            existing = v24.get_service_object(plane, name)
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "service-object", "name": name, "item": item})
            elif (
                existing
                and existing["type"] == str(item.get("type") or "").lower()
                and int(existing["port"]) == int(item.get("port"))
            ):
                changes.append({"op": "NO_CHANGE", "kind": "service-object", "name": name})
            else:
                changes.append(
                    {
                        "op": "CREATE" if not existing else "UPDATE",
                        "kind": "service-object",
                        "name": name,
                        "item": item,
                    }
                )
        for item in sgs:
            name = item["name"]
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "service-group", "name": name, "item": item})
                continue
            existing = v24.get_service_group(plane, name)
            if existing:
                members = [
                    r["name"]
                    for r in plane.conn.execute(
                        "SELECT s.name FROM service_group_members m JOIN service_objects s ON s.id = m.service_object_id WHERE m.group_id = ?",
                        (existing["id"],),
                    )
                ]
                if _group_members_equal(members, item.get("members") or []):
                    changes.append({"op": "NO_CHANGE", "kind": "service-group", "name": name})
                    continue
            changes.append({"op": "SET", "kind": "service-group", "name": name, "item": item})
        for item in pos:
            name = item["name"]
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "permission-object", "name": name, "item": item})
                continue
            existing = v24.get_permission_object(plane, name)
            if existing:
                perms = [
                    r["permission"]
                    for r in plane.conn.execute(
                        "SELECT permission FROM permission_object_members WHERE permission_object_id = ?",
                        (existing["id"],),
                    )
                ]
                if _group_members_equal(perms, item.get("permissions") or []):
                    changes.append({"op": "NO_CHANGE", "kind": "permission-object", "name": name})
                    continue
            changes.append({"op": "SET", "kind": "permission-object", "name": name, "item": item})
        for item in pgs:
            name = item["name"]
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "permission-group", "name": name, "item": item})
                continue
            existing = v24.get_permission_group(plane, name)
            if existing:
                members = [
                    r["name"]
                    for r in plane.conn.execute(
                        "SELECT p.name FROM permission_group_members m JOIN permission_objects p ON p.id = m.permission_object_id WHERE m.group_id = ?",
                        (existing["id"],),
                    )
                ]
                if _group_members_equal(members, item.get("members") or []):
                    changes.append({"op": "NO_CHANGE", "kind": "permission-group", "name": name})
                    continue
            changes.append({"op": "SET", "kind": "permission-group", "name": name, "item": item})

        for family, key in (
            ("remote", "remoteAccess"),
            ("internet", "internetAccess"),
            ("ai", "aiAccess"),
        ):
            if key not in body or body.get(key) is None:
                continue
            section = _validate_access_section(body.get(key), key=key, family=family)
            validated_body[key] = section
            if section.get("state") == "absent":
                changes.append({"op": "RESET", "kind": "%s-access" % family, "name": "policy", "item": section})
                continue
            mode = section.get("mode")
            enforcement = section.get("enforcement")
            rules = section.get("rules")
            if mode is not None or enforcement is not None:
                changes.append(
                    {
                        "op": "CONFIGURE",
                        "kind": "%s-access" % family,
                        "name": "policy",
                        "mode": mode,
                        "enforcement": enforcement,
                    }
                )
            if rules is not None:
                for rule in rules:
                    # Reference validation against bundle + DB (declaration-order independent)
                    if rule.get("state") != "absent":
                        if family == "ai":
                            # source is AI Identity — must exist in DB (identities are not bundle resources)
                            if not plane.get_principal(rule["source"]):
                                _bundle_error(
                                    "Required AI Identity '%s' does not exist.\n\n"
                                    "Create the AI Identity before applying the Rule." % rule["source"]
                                )
                            dest = rule["destination"]
                            if dest.lower() not in no_names and dest.lower() not in ng_names:
                                client = None
                                try:
                                    client = plane.get_client(dest)
                                except Exception:
                                    client = None
                                if client is None:
                                    _bundle_error(
                                        "Required Network Object '%s' does not exist.\n\n"
                                        "Create it in the same ConfigurationBundle\n"
                                        "or create it before applying the Rule." % dest
                                    )
                            perm = rule["permission"]
                            if perm.lower() not in po_names and perm.lower() not in pg_names:
                                _bundle_error(
                                    "Required Permission Object '%s' does not exist.\n\n"
                                    "Create it in the same ConfigurationBundle\n"
                                    "or create it before applying the Rule." % perm
                                )
                        else:
                            src = rule["source"]
                            dst = rule["destination"]
                            svc = rule["service"]
                            if src.lower() not in no_names and src.lower() not in ng_names:
                                _bundle_error(
                                    "Required Network Object '%s' does not exist.\n\n"
                                    "Create it in the same ConfigurationBundle\n"
                                    "or create it before applying the Rule." % src
                                )
                            if dst.lower() not in no_names and dst.lower() not in ng_names:
                                _bundle_error(
                                    "Required Network Object '%s' does not exist.\n\n"
                                    "Create it in the same ConfigurationBundle\n"
                                    "or create it before applying the Rule." % dst
                                )
                            if svc.lower() not in so_names and svc.lower() not in sg_names:
                                _bundle_error(
                                    "Required Service Object '%s' does not exist.\n\n"
                                    "Create it in the same ConfigurationBundle\n"
                                    "or create it before applying the Rule." % svc
                                )
                    if rule.get("state") == "absent":
                        changes.append(
                            {"op": "DELETE", "kind": "%s-access-rule" % family, "name": rule.get("name"), "item": rule}
                        )
                    else:
                        if family == "ai":
                            existing_rule = plane.conn.execute(
                                "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE",
                                (rule.get("name"),),
                            ).fetchone()
                        else:
                            existing_rule = plane._get_rule(family, rule.get("name"))
                        existing_enabled = (
                            bool(existing_rule["enabled"]) if existing_rule is not None else None
                        )
                        _materialize_enabled(rule, existing_enabled)
                        if existing_rule and _rule_matches_desired(plane, family, existing_rule, rule):
                            changes.append(
                                {"op": "NO_CHANGE", "kind": "%s-access-rule" % family, "name": rule.get("name")}
                            )
                        else:
                            changes.append(
                                {
                                    "op": "SET",
                                    "kind": "%s-access-rule" % family,
                                    "name": rule.get("name"),
                                    "item": rule,
                                    "mode": mode,
                                }
                            )
            pol = v24.get_access_policy(plane, family)
            want_mode = str(mode).lower() if mode is not None else None
            want_enforcement = str(enforcement).lower() if enforcement is not None else None
            mode_same = want_mode is None or pol["mode"] == want_mode
            enf_same = want_enforcement is None or pol["enforcement"] == want_enforcement
            if mode_same and enf_same:
                for c in changes:
                    if c.get("kind") == "%s-access" % family and c.get("op") == "CONFIGURE":
                        c["op"] = "NO_CHANGE"
    else:
        rss = [_validate_remote_service_item(i) for i in (body.get("remoteServices") or [])]
        validated_body["remoteServices"] = rss
        identity = v24.load_agent_identity(plane.root)
        host_name = identity.get("hostname") or identity.get("label") or "this-host"
        for item in rss:
            name = item["name"]
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "remote-service", "name": name, "item": item})
                continue
            existing = plane.conn.execute(
                "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE AND delete_pending = 0",
                (name,),
            ).fetchone()
            existing_enabled = bool(existing["enabled"]) if existing is not None else None
            _materialize_enabled(item, existing_enabled)
            if existing:
                dest = item["destination"]
                if dest.lower() in ("this-host", "this_host", "self"):
                    dest_norm = host_name
                else:
                    dest_norm = dest
                same = (
                    str(existing["destination"]).lower() == dest_norm.lower()
                    and str(existing["service_object"]).lower() == str(item["service"]).lower()
                    and bool(existing["enabled"]) == bool(item["enabled"])
                )
                if same:
                    changes.append({"op": "NO_CHANGE", "kind": "remote-service", "name": name})
                    continue
            changes.append({"op": "SET", "kind": "remote-service", "name": name, "item": item})

    impact = _security_impact_for_plan(plane, context, validated_body, changes)
    mutating = [c for c in changes if c.get("op") != "NO_CHANGE"]
    return V24Plan(
        context=context,
        changes=changes,
        no_change=not mutating,
        security_impact=impact,
        raw=validated_body,
        base_revision=int(plane.current_revision()),
        source_text=str(raw_text or ""),
    )


def format_v24_plan(plan: V24Plan) -> str:
    lines = ["VALID" if not plan.no_change or plan.changes else "VALID", "", "Planned changes:"]
    if plan.no_change:
        lines.append("  NO CHANGE")
    else:
        for c in plan.mutating_changes:
            lines.append("  %s %s %s" % (c["op"], c["kind"], c.get("name") or ""))
    if plan.security_impact:
        lines.extend(["", "Security impact:"])
        for item in plan.security_impact:
            lines.append("  %s" % item)
    lines.extend(["", "No changes were applied."])
    return "\n".join(lines) + "\n"


def _confirm_requested(confirm: bool) -> bool:
    return confirm is True or str(os.environ.get("DRLINK_CONFIRM") or "").strip().lower() in (
        "yes",
        "y",
        "1",
        "true",
    )


def _raise_plan_confirmation(plan: V24Plan) -> None:
    texts = list(plan.security_impact or [])
    access_narrowed = any("DENY ALL" in str(t) for t in texts)
    access_broadened = any(
        "broadens" in str(t).lower() or "this change resets" in str(t).lower()
        for t in texts
    )
    raise ConfirmationRequired(
        format_v24_plan(plan) + "\nApply these changes? [y/N]",
        {
            "access_broadened": bool(access_broadened),
            "access_narrowed": bool(access_narrowed),
            "requires_confirmation": True,
        },
    )


def _resolve_plan_for_apply(plane: ControlPlane, plan: V24Plan) -> V24Plan:
    """Re-diff against authoritative state, or fail closed on stale base revision."""
    source = str(getattr(plan, "source_text", "") or "")
    if source.strip():
        return prepare_v24_plan(plane, source)
    base = getattr(plan, "base_revision", None)
    if base is not None and int(plane.current_revision()) != int(base):
        raise ConcurrencyError(
            "REVISION_CONFLICT\n"
            "Base revision: %s\n"
            "Current revision: %s\n"
            "No changes were applied.\n"
            "Re-run diff/test against current state."
            % (base, plane.current_revision())
        )
    return plan


def apply_v24_plan(plane: ControlPlane, plan: V24Plan, *, confirm: bool = False) -> dict:
    """Apply a prepared plan against *current* authoritative state.

    Canonical contract:
      read current state -> recalculate diff/security impact -> confirm -> mutate

    Decisions are made under BEGIN IMMEDIATE so concurrent writers cannot change
    relevant state between the final security-impact decision and mutation.
    """
    confirmed = _confirm_requested(confirm)
    order = {
        "network-object": 10,
        "network-group": 20,
        "service-object": 30,
        "service-group": 40,
        "permission-object": 50,
        "permission-group": 60,
        "remote-access": 70,
        "internet-access": 70,
        "ai-access": 70,
        "remote-access-rule": 80,
        "internet-access-rule": 80,
        "ai-access-rule": 80,
        "remote-service": 90,
    }
    # Deletes must reverse create dependencies: Rules before Groups before Objects.
    delete_order = {
        "remote-service": 10,
        "remote-access-rule": 20,
        "internet-access-rule": 20,
        "ai-access-rule": 20,
        "remote-access": 30,
        "internet-access": 30,
        "ai-access": 30,
        "permission-group": 40,
        "permission-object": 50,
        "service-group": 60,
        "service-object": 70,
        "network-group": 80,
        "network-object": 90,
    }

    is_agent = str(plan.context or "").lower() == "agent"
    compile_runtime = not is_agent
    plane._agent_mgmt_side_effects = []
    checkpoint = None
    fresh: V24Plan = plan
    rev: Optional[int] = None
    try:
        if (is_agent or compile_runtime) and plane._activation_should_run():
            checkpoint = plane._pre_activation_checkpoint()

        plane.conn.execute("BEGIN IMMEDIATE")
        try:
            fresh = _resolve_plan_for_apply(plane, plan)
            if fresh.no_change:
                rev = int(plane.current_revision())
                plane._rollback_open_transaction()
                return {"status": "NO_CHANGE", "revision": rev}

            if fresh.security_impact and not confirmed:
                plane._rollback_open_transaction()
                _raise_plan_confirmation(fresh)

            delete_first = [c for c in fresh.mutating_changes if c["op"] in ("DELETE", "RESET")]
            delete_first.sort(key=lambda c: delete_order.get(c["kind"], 100))
            others = [c for c in fresh.mutating_changes if c["op"] not in ("DELETE", "RESET")]
            others.sort(key=lambda c: order.get(c["kind"], 100))

            prev_batch = plane._batch_mode
            plane._batch_mode = True
            plane._batch_results = []
            try:
                for c in delete_first + others:
                    _apply_one(plane, c)
            finally:
                plane._batch_mode = prev_batch
                plane._batch_results = []

            rev = plane._write_revision(
                "system apply configuration",
                "apply configuration bundle",
                snapshot={"summary": "apply configuration bundle"},
            )
            plane._audit(
                revision=int(rev),
                action="system apply configuration",
                entity_type="configuration-bundle",
                entity_id=str(fresh.context or "bundle"),
                operation="apply",
                after="apply configuration bundle",
                impact=json.dumps(
                    {
                        "base_revision": getattr(plan, "base_revision", None),
                        "resolved_revision": getattr(fresh, "base_revision", None),
                        "security_impact": list(fresh.security_impact or [])[:20],
                    },
                    sort_keys=True,
                )[:2000],
            )
            plane._commit_open_transaction()
        except ConfirmationRequired:
            plane._rollback_open_transaction()
            raise
        except ConcurrencyError:
            plane._rollback_open_transaction()
            raise
        except ControlPlaneError:
            plane._rollback_open_transaction()
            raise
        except Exception as exc:
            plane._rollback_open_transaction()
            if isinstance(exc, sqlite3.IntegrityError) and "foreign key" in str(exc).lower():
                raise ControlPlaneError(
                    "ERROR:\nCannot apply this change because a referenced dependency still exists.\n\n"
                    "No changes were applied.\n\n"
                    "Remove dependent Rules or Groups first, or include them in the same "
                    "ConfigurationBundle with dependency-aware delete ordering."
                ) from exc
            raise ControlPlaneError("No changes were applied. %s" % exc) from exc

        if compile_runtime and plane._activation_should_run():
            try:
                if plane._forced_activation_failure():
                    raise ControlPlaneError("simulated activation failure")
                plane.compile_runtime()
            except Exception:
                try:
                    plane._rollback_activation(checkpoint or {})
                except Exception:
                    plane._mark_generation_failed("activation failed; rollback incomplete")
                    plane._cleanup_activation_checkpoint(checkpoint)
                    raise ControlPlaneError(
                        "ERROR:\nApply failed and automatic rollback was not fully successful.\n\n"
                        "The current runtime state may require operator attention.\n\n"
                        "Run:\n  system diagnostics"
                    ) from None
                plane._cleanup_activation_checkpoint(checkpoint)
                raise ControlPlaneError(
                    "ERROR:\nRuntime activation failed.\n\n"
                    "Previous configuration was restored.\n"
                    "No configuration changes remain active."
                ) from None
            plane._cleanup_activation_checkpoint(checkpoint)
            checkpoint = None

        if is_agent:
            _finalize_agent_bundle_runtime(plane, fresh, checkpoint)
            checkpoint = None
    except (ConfirmationRequired, ConcurrencyError):
        raise
    except Exception as exc:
        msg = str(exc)
        if is_agent and getattr(plane, "_agent_mgmt_side_effects", None):
            if "Previous configuration was restored" in msg or "PARTIAL:" in msg or "RECOVERY_REQUIRED" in msg:
                raise
            report = v24.reconcile_agent_mgmt_side_effects(plane, root=plane.root)
            if not report.get("ok"):
                details = "\n".join("  %s" % f for f in (report.get("failures") or [])) or "  unknown"
                raise ControlPlaneError(
                    "ERROR:\nConfigurationBundle apply failed after Server mutation.\n\n"
                    "PARTIAL: Server Remote Service state could not be fully restored.\n"
                    "RECOVERY_REQUIRED\n\n"
                    "Compensation failures:\n%s\n\n"
                    "Original error:\n%s\n\n"
                    "Run:\n  system diagnostics" % (details, msg)
                ) from exc
        elif is_agent:
            v24.reconcile_agent_mgmt_side_effects(plane, root=plane.root)
        raise
    finally:
        plane._cleanup_activation_checkpoint(checkpoint)
        plane._agent_mgmt_side_effects = []
    return {"status": "APPLIED", "revision": int(rev if rev is not None else plane.current_revision())}

def _finalize_agent_bundle_runtime(plane: ControlPlane, plan: V24Plan, checkpoint) -> None:
    """Activate Agent runtime after the desired-state transaction commits."""
    import drlink_v24_runtime as runtime

    applied = runtime.apply_agent_runtime(plane, root=plane.root)
    if applied.get("skipped") or applied.get("ok"):
        runtime.mark_runtime_status(plane, ok=True, generation=int(applied.get("generation") or 0))
        v24._push_agent_remote_service_status(plane, root=plane.root)
        plane._agent_mgmt_side_effects = []
        return
    local_restored = False
    if checkpoint:
        try:
            plane._rollback_activation(checkpoint)
            local_restored = True
        except Exception as exc:
            report = v24.reconcile_agent_mgmt_side_effects(plane, root=plane.root)
            if report.get("ok"):
                raise ControlPlaneError(
                    "ERROR:\nApply failed and automatic rollback was not fully successful.\n\n"
                    "The current runtime state may require operator attention.\n\n"
                    "Run:\n  system diagnostics"
                ) from exc
            details = "\n".join("  %s" % f for f in (report.get("failures") or [])) or "  unknown"
            raise ControlPlaneError(
                "ERROR:\nApply failed and automatic rollback was not fully successful.\n\n"
                "PARTIAL: Server Remote Service state could not be fully restored.\n"
                "RECOVERY_REQUIRED\n\n"
                "Compensation failures:\n%s\n\n"
                "Run:\n  system diagnostics" % details
            ) from exc
    v24.raise_agent_mgmt_activation_failure(
        plane, root=plane.root, local_restored=local_restored
    )


def _apply_one(plane: ControlPlane, change: dict) -> None:
    kind = change["kind"]
    item = change.get("item") or {}
    name = change.get("name")
    op = change["op"]
    if kind == "network-object":
        if op == "DELETE":
            v24.unset_network_object(plane, name)
        else:
            v24.set_network_object(
                plane,
                name,
                type=item.get("type"),
                value=item.get("value"),
                oneshot=True,
            )
    elif kind == "network-group":
        if op == "DELETE":
            plane.unset_object_group(name)
        else:
            v24.set_network_group(plane, name, members=list(item.get("members") or []), oneshot=True)
    elif kind == "service-object":
        if op == "DELETE":
            v24.unset_service_object(plane, name)
        else:
            v24.set_service_object(
                plane, name, type=item.get("type"), port=int(item.get("port")), oneshot=True
            )
    elif kind == "service-group":
        if op == "DELETE":
            v24.unset_service_group(plane, name)
        else:
            v24.set_service_group(plane, name, members=list(item.get("members") or []), oneshot=True)
    elif kind == "permission-object":
        if op == "DELETE":
            v24.unset_permission_object(plane, name)
        else:
            v24.set_permission_object(
                plane, name, permissions=list(item.get("permissions") or []), oneshot=True
            )
    elif kind == "permission-group":
        if op == "DELETE":
            v24.unset_permission_group(plane, name)
        else:
            v24.set_permission_group(plane, name, members=list(item.get("members") or []), oneshot=True)
    elif kind.endswith("-access") and op in ("RESET", "CONFIGURE"):
        family = kind.replace("-access", "")
        if op == "RESET":
            v24.reset_access_policy(plane, family, confirm=True)
        else:
            if change.get("mode"):
                v24.ensure_policy_mode(plane, family, change["mode"], oneshot=True)
            if change.get("enforcement"):
                en = str(change["enforcement"]).lower() == "enabled"
                # Only set enforcement if policy exists
                pol = v24.get_access_policy(plane, family)
                if pol["mode"] is not None:
                    v24.set_policy_enforcement(plane, family, en, confirm=True)
    elif kind.endswith("-access-rule"):
        family = kind.replace("-access-rule", "")
        if op == "DELETE":
            if family == "ai":
                v24.unset_ai_access_rule(plane, name, confirm=True)
            else:
                v24.unset_access_rule(plane, family, name, confirm=True)
        else:
            # Effective enabled is materialized during prepare/re-diff. Fall back
            # to existing-state preservation if a caller omitted the key.
            if "enabled" in item:
                enabled = bool(item.get("enabled"))
            else:
                if family == "ai":
                    existing_rule = plane.conn.execute(
                        "SELECT enabled FROM ai_policy_rules WHERE name = ? COLLATE NOCASE",
                        (name,),
                    ).fetchone()
                else:
                    existing_rule = plane._get_rule(family, name)
                enabled = _materialize_enabled(
                    item,
                    bool(existing_rule["enabled"]) if existing_rule is not None else None,
                )
            if family == "ai":
                v24.set_ai_access_rule(
                    plane,
                    name,
                    mode=change.get("mode") or item.get("mode"),
                    source=item.get("source"),
                    destination=item.get("destination"),
                    permission=item.get("permission"),
                    paths=item.get("paths") if "paths" in item else None,
                    enabled=bool(enabled),
                    oneshot=True,
                    confirm=True,
                )
            else:
                v24.set_access_rule(
                    plane,
                    family,
                    name,
                    mode=change.get("mode") or item.get("mode"),
                    source=item.get("source"),
                    destination=item.get("destination"),
                    service=item.get("service"),
                    enabled=bool(enabled),
                    oneshot=True,
                    confirm=True,
                )
    elif kind == "remote-service":
        reachable = v24.detect_server_reachable(plane, plane.root)
        if op == "DELETE":
            v24.unset_remote_service_agent(
                plane, name, root=plane.root, server_reachable=reachable
            )
        else:
            if "enabled" not in item:
                existing = plane.conn.execute(
                    "SELECT enabled FROM agent_remote_services WHERE name = ? COLLATE NOCASE AND delete_pending = 0",
                    (name,),
                ).fetchone()
                _materialize_enabled(
                    item,
                    bool(existing["enabled"]) if existing is not None else None,
                )
            v24.set_remote_service_agent(
                plane,
                name,
                destination=item.get("destination"),
                service=item.get("service"),
                enabled=bool(item["enabled"]),
                oneshot=True,
                root=plane.root,
                server_reachable=reachable,
            )
    else:
        raise ControlPlaneError("Unsupported bundle change: %s" % kind)


def export_configuration_v24(plane: ControlPlane) -> str:
    role = v24.detect_cli_role(plane.root)
    if role == "agent":
        services = []
        for row in plane.conn.execute(
            "SELECT * FROM agent_remote_services WHERE delete_pending = 0 ORDER BY name"
        ):
            services.append(
                {
                    "name": row["name"],
                    "destination": row["destination"],
                    "service": row["service_object"],
                    "enabled": bool(row["enabled"]),
                }
            )
        doc = {"configurationBundle": {"context": "agent", "remoteServices": services}}
    else:
        body: dict[str, Any] = {"context": "server"}
        nos = []
        for row in v24.list_network_objects(plane):
            if row["type"] == "Managed Host":
                continue
            type_map = {"IP": "ip", "CIDR": "cidr", "FQDN": "fqdn"}
            nos.append(
                {
                    "name": row["name"],
                    "type": type_map.get(row["type"], "ip"),
                    "value": row["value"],
                }
            )
        if nos:
            body["networkObjects"] = nos
        ngs = []
        for g in plane.conn.execute("SELECT * FROM object_groups ORDER BY name"):
            members = [m["name"] for m in plane._expand_group_members(g["id"], set())]
            ngs.append({"name": g["name"], "members": members})
        if ngs:
            body["networkGroups"] = ngs
        sos = []
        for row in plane.conn.execute("SELECT name, type, port FROM service_objects ORDER BY name"):
            sos.append({"name": row["name"], "type": row["type"], "port": int(row["port"])})
        if sos:
            body["serviceObjects"] = sos
        sgs = []
        for g in plane.conn.execute("SELECT * FROM service_groups ORDER BY name"):
            members = [
                r["name"]
                for r in plane.conn.execute(
                    "SELECT s.name FROM service_group_members m JOIN service_objects s ON s.id = m.service_object_id WHERE m.group_id = ?",
                    (g["id"],),
                )
            ]
            sgs.append({"name": g["name"], "members": members})
        if sgs:
            body["serviceGroups"] = sgs
        pos = []
        for p in plane.conn.execute("SELECT * FROM permission_objects ORDER BY name"):
            perms = [
                r["permission"]
                for r in plane.conn.execute(
                    "SELECT permission FROM permission_object_members WHERE permission_object_id = ?",
                    (p["id"],),
                )
            ]
            pos.append({"name": p["name"], "permissions": perms})
        if pos:
            body["permissionObjects"] = pos
        pgs = []
        for g in plane.conn.execute("SELECT * FROM permission_groups ORDER BY name"):
            members = [
                r["name"]
                for r in plane.conn.execute(
                    "SELECT p.name FROM permission_group_members m JOIN permission_objects p ON p.id = m.permission_object_id WHERE m.group_id = ?",
                    (g["id"],),
                )
            ]
            pgs.append({"name": g["name"], "members": members})
        if pgs:
            body["permissionGroups"] = pgs
        for family, key in (("remote", "remoteAccess"), ("internet", "internetAccess")):
            pol = v24.get_access_policy(plane, family)
            if pol["mode"] is None:
                continue
            rules = []
            for rule in plane.conn.execute(
                "SELECT * FROM policy_rules WHERE plane = ? ORDER BY name", (family,)
            ):
                view = plane._rule_view(rule)
                # Prefer service object name from rule_service_refs
                svc = "-"
                ref = plane.conn.execute(
                    "SELECT ref_kind, ref_id FROM rule_service_refs WHERE rule_id = ?", (rule["id"],)
                ).fetchone()
                if ref and ref["ref_kind"] == "service_object":
                    sobj = plane.conn.execute(
                        "SELECT name FROM service_objects WHERE id = ?", (ref["ref_id"],)
                    ).fetchone()
                    svc = sobj["name"] if sobj else svc
                elif ref and ref["ref_kind"] == "service_group":
                    sgrp = plane.conn.execute(
                        "SELECT name FROM service_groups WHERE id = ?", (ref["ref_id"],)
                    ).fetchone()
                    svc = sgrp["name"] if sgrp else svc
                rules.append(
                    {
                        "name": view["name"],
                        "source": (view.get("sources") or ["-"])[0],
                        "destination": (view.get("destinations") or ["-"])[0],
                        "service": svc,
                        "enabled": bool(view["enabled"]),
                    }
                )
            body[key] = {
                "mode": pol["mode"],
                "enforcement": pol["enforcement"],
                "rules": rules,
            }
        pol = v24.get_access_policy(plane, "ai")
        if pol["mode"] is not None:
            rules = []
            for row in plane.conn.execute("SELECT * FROM ai_policy_rules ORDER BY name"):
                view = _ai_rule_view(plane, row)
                rule_doc = {
                    "name": row["name"],
                    "source": view["source"],
                    "destination": view["destination"],
                    "permission": view["permission"],
                    "enabled": bool(view["enabled"]),
                }
                # Always export path scopes so same-state reapply is NO CHANGE.
                rule_doc["paths"] = list(view.get("paths") or [])
                rules.append(rule_doc)
            body["aiAccess"] = {
                "mode": pol["mode"],
                "enforcement": pol["enforcement"],
                "rules": rules,
            }
        doc = {"configurationBundle": body}
    return _yaml().safe_dump(doc, sort_keys=False)


def read_bundle_stdin_with_end(stdin_text: Optional[str] = None) -> str:
    """Read stdin until a line containing only :end (canonical paste terminator)."""
    import sys

    if stdin_text is not None:
        return _strip_end_terminator(stdin_text)
    sys.stdout.write(
        "Paste ConfigurationBundle YAML below.\nFinish with a line containing only:\n:end\n\n"
    )
    sys.stdout.flush()
    lines = []
    while True:
        line = sys.stdin.readline()
        if line == "":
            break
        if line.rstrip("\r\n") == ":end":
            break
        lines.append(line)
    return "".join(lines)
