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
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from drlink_control_db import ControlPlaneError, utc_now_iso
from drlink_control_plane import ConfirmationRequired, ControlPlane
from drlink_configuration_bundle import BundleError
import drlink_v24 as v24

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


@dataclass
class V24Plan:
    context: str
    changes: list[dict] = field(default_factory=list)
    no_change: bool = False
    security_impact: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

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


def _rule_matches_desired(plane: ControlPlane, family: str, existing, desired: dict) -> bool:
    if family == "ai":
        if bool(existing["enabled"]) != bool(desired.get("enabled", True)):
            return False
        principal = plane.conn.execute(
            "SELECT name FROM ai_principals WHERE id = ?", (existing["source_identity_id"],)
        ).fetchone()
        if not principal or principal["name"].lower() != str(desired.get("source") or "").lower():
            return False
        return True
    view = plane._rule_view(existing)
    if bool(view["enabled"]) != bool(desired.get("enabled", True)):
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
            raise BundleError("Unknown Server Bundle sections: %s" % ", ".join(sorted(bad)))
    else:
        bad = [k for k in body.keys() if k not in AGENT_SECTIONS and k != "context"]
        for section in SERVER_SECTIONS:
            if section in body:
                raise BundleError(
                    "ERROR:\nAgent ConfigurationBundle cannot contain Server section '%s'.\n\n"
                    "No changes were applied." % section
                )
        if bad:
            raise BundleError("Unknown Agent Bundle sections: %s" % ", ".join(sorted(bad)))

    changes: list[dict] = []
    impact: list[str] = []

    # Validate whole document before mutation — collect intended ops only.
    if context == "server":
        for item in body.get("networkObjects") or []:
            _absent_and_present_fields(item)
            name = item.get("name")
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "network-object", "name": name, "item": item})
            else:
                existing = plane.get_object(name) if name else None
                if existing and existing["type"] == v24.NETWORK_STORE.get(str(item.get("type") or "").lower(), existing["type"]):
                    vals = plane._object_values(existing["id"])
                    if vals and vals[0] == str(item.get("value")):
                        changes.append({"op": "NO_CHANGE", "kind": "network-object", "name": name})
                        continue
                changes.append(
                    {
                        "op": "CREATE" if not existing else "UPDATE",
                        "kind": "network-object",
                        "name": name,
                        "item": item,
                    }
                )
        for item in body.get("networkGroups") or []:
            _absent_and_present_fields(item)
            changes.append(
                {
                    "op": "DELETE" if item.get("state") == "absent" else "SET",
                    "kind": "network-group",
                    "name": item.get("name"),
                    "item": item,
                }
            )
        for item in body.get("serviceObjects") or []:
            _absent_and_present_fields(item)
            name = item.get("name")
            existing = v24.get_service_object(plane, name) if name else None
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "service-object", "name": name, "item": item})
            elif existing and existing["type"] == str(item.get("type") or "").lower() and int(existing["port"]) == int(item.get("port")):
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
        for item in body.get("serviceGroups") or []:
            _absent_and_present_fields(item)
            changes.append(
                {
                    "op": "DELETE" if item.get("state") == "absent" else "SET",
                    "kind": "service-group",
                    "name": item.get("name"),
                    "item": item,
                }
            )
        for item in body.get("permissionObjects") or []:
            _absent_and_present_fields(item)
            changes.append(
                {
                    "op": "DELETE" if item.get("state") == "absent" else "SET",
                    "kind": "permission-object",
                    "name": item.get("name"),
                    "item": item,
                }
            )
        for item in body.get("permissionGroups") or []:
            _absent_and_present_fields(item)
            changes.append(
                {
                    "op": "DELETE" if item.get("state") == "absent" else "SET",
                    "kind": "permission-group",
                    "name": item.get("name"),
                    "item": item,
                }
            )
        for family, key in (
            ("remote", "remoteAccess"),
            ("internet", "internetAccess"),
            ("ai", "aiAccess"),
        ):
            section = body.get(key)
            if section is None:
                continue
            if isinstance(section, dict) and section.get("state") == "absent":
                changes.append({"op": "RESET", "kind": "%s-access" % family, "name": "policy", "item": section})
                impact.append("Reset %s Access policy → ALLOW" % family.title())
                continue
            if not isinstance(section, dict):
                raise BundleError("%s must be a mapping" % key)
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
                    _absent_and_present_fields(rule)
                    if rule.get("state") == "absent":
                        changes.append(
                            {"op": "DELETE", "kind": "%s-access-rule" % family, "name": rule.get("name"), "item": rule}
                        )
                    else:
                        existing_rule = None
                        if family == "ai":
                            existing_rule = plane.conn.execute(
                                "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE",
                                (rule.get("name"),),
                            ).fetchone()
                        else:
                            existing_rule = plane._get_rule(family, rule.get("name"))
                        if existing_rule and _rule_matches_desired(plane, family, existing_rule, rule):
                            changes.append({"op": "NO_CHANGE", "kind": "%s-access-rule" % family, "name": rule.get("name")})
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
            # Policy configure is NO_CHANGE when mode/enforcement already match and only NO_CHANGE rules
            pol = v24.get_access_policy(plane, family)
            want_mode = str(mode).lower() if mode is not None else None
            want_enforcement = str(enforcement).lower() if enforcement is not None else None
            mode_same = want_mode is None or pol["mode"] == want_mode
            enf_same = want_enforcement is None or pol["enforcement"] == want_enforcement
            if mode_same and enf_same:
                # Rewrite last CONFIGURE for this family to NO_CHANGE if present
                for c in changes:
                    if c.get("kind") == "%s-access" % family and c.get("op") == "CONFIGURE":
                        c["op"] = "NO_CHANGE"
    else:
        for item in body.get("remoteServices") or []:
            _absent_and_present_fields(item)
            if item.get("state") == "absent":
                changes.append({"op": "DELETE", "kind": "remote-service", "name": item.get("name"), "item": item})
            else:
                changes.append({"op": "SET", "kind": "remote-service", "name": item.get("name"), "item": item})

    mutating = [c for c in changes if c.get("op") != "NO_CHANGE"]
    return V24Plan(
        context=context,
        changes=changes,
        no_change=not mutating,
        security_impact=impact,
        raw=body,
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


def apply_v24_plan(plane: ControlPlane, plan: V24Plan, *, confirm: bool = False) -> dict:
    if plan.no_change:
        return {"status": "NO_CHANGE", "revision": plane.current_revision()}
    if plan.security_impact and not (
        confirm is True
        or str((__import__("os").environ.get("DRLINK_CONFIRM") or "")).strip().lower()
        in ("yes", "y", "1", "true")
    ):
        raise ConfirmationRequired(
            format_v24_plan(plan) + "\nApply these changes? [y/N]",
            {"access_broadened": True},
        )

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
    delete_first = [c for c in plan.mutating_changes if c["op"] in ("DELETE", "RESET")]
    others = [c for c in plan.mutating_changes if c["op"] not in ("DELETE", "RESET")]
    others.sort(key=lambda c: order.get(c["kind"], 100))

    def write_all():
        prev = plane._batch_mode
        plane._batch_mode = True
        plane._batch_results = []
        try:
            for c in delete_first + others:
                _apply_one(plane, c)
        finally:
            plane._batch_mode = prev
            plane._batch_results = []
        return {
            "entity": {"type": "configuration-bundle", "id": "bundle", "name": plan.context},
            "operation": "apply",
        }

    plane._mutate(
        "system apply configuration",
        "apply configuration bundle",
        write_all,
        confirm=True,
    )
    return {"status": "APPLIED", "revision": plane.current_revision()}


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
            g = v24.get_service_group(plane, name)
            if g:
                plane.conn.execute("DELETE FROM service_group_members WHERE group_id = ?", (g["id"],))
                plane.conn.execute("DELETE FROM service_groups WHERE id = ?", (g["id"],))
        else:
            v24.set_service_group(plane, name, members=list(item.get("members") or []), oneshot=True)
    elif kind == "permission-object":
        if op == "DELETE":
            p = v24.get_permission_object(plane, name)
            if p:
                plane.conn.execute(
                    "DELETE FROM permission_object_members WHERE permission_object_id = ?", (p["id"],)
                )
                plane.conn.execute("DELETE FROM permission_objects WHERE id = ?", (p["id"],))
        else:
            v24.set_permission_object(
                plane, name, permissions=list(item.get("permissions") or []), oneshot=True
            )
    elif kind == "permission-group":
        if op == "DELETE":
            g = v24.get_permission_group(plane, name)
            if g:
                plane.conn.execute("DELETE FROM permission_group_members WHERE group_id = ?", (g["id"],))
                plane.conn.execute("DELETE FROM permission_groups WHERE id = ?", (g["id"],))
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
                row = plane.conn.execute(
                    "SELECT id FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (name,)
                ).fetchone()
                if row:
                    plane.conn.execute("DELETE FROM ai_policy_rules WHERE id = ?", (row["id"],))
            else:
                v24.unset_access_rule(plane, family, name)
        else:
            enabled = item.get("enabled")
            if enabled is None:
                enabled = True
            if family == "ai":
                v24.set_ai_access_rule(
                    plane,
                    name,
                    mode=change.get("mode") or item.get("mode"),
                    source=item.get("source"),
                    destination=item.get("destination"),
                    permission=item.get("permission"),
                    enabled=bool(enabled),
                    oneshot=True,
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
                )
    elif kind == "remote-service":
        if op == "DELETE":
            v24.unset_remote_service_agent(plane, name, root=plane.root, server_reachable=True)
        else:
            v24.set_remote_service_agent(
                plane,
                name,
                destination=item.get("destination"),
                service=item.get("service"),
                enabled=bool(item.get("enabled", True)),
                oneshot=True,
                root=plane.root,
                server_reachable=True,
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
                principal = plane.conn.execute(
                    "SELECT name FROM ai_principals WHERE id = ?", (row["source_identity_id"],)
                ).fetchone()
                dest = "-"
                if row["destination_ref_kind"] == "object":
                    obj = plane.conn.execute(
                        "SELECT name FROM objects WHERE id = ?", (row["destination_ref_id"],)
                    ).fetchone()
                    dest = obj["name"] if obj else dest
                perm = "-"
                if row["permission_ref_kind"] == "permission_object":
                    p = plane.conn.execute(
                        "SELECT name FROM permission_objects WHERE id = ?", (row["permission_ref_id"],)
                    ).fetchone()
                    perm = p["name"] if p else perm
                rules.append(
                    {
                        "name": row["name"],
                        "source": principal["name"] if principal else "-",
                        "destination": dest,
                        "permission": perm,
                        "enabled": bool(row["enabled"]),
                    }
                )
            body["aiAccess"] = {
                "mode": pol["mode"],
                "enforcement": pol["enforcement"],
                "rules": rules,
            }
        doc = {"configurationBundle": body}
    return yaml.safe_dump(doc, sort_keys=False)


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
