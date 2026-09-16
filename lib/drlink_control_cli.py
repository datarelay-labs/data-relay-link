#!/usr/bin/env python3
"""Canonical control-plane CLI for Data Relay Link v2.4."""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

from drlink_control_db import SCHEMA_VERSION, ControlPlaneError, SchemaTooNewError, DatabaseCorruptError
from drlink_control_plane import (
    AI_CAPABILITIES,
    ConfirmationRequired,
    ConcurrencyError,
    ControlPlane,
)

USAGE_HINT = "No changes were applied."


def _confirm_from_stdin(message: str) -> bool:
    sys.stdout.write(message.rstrip() + "\n")
    sys.stdout.flush()
    if not sys.stdin or sys.stdin.closed:
        return False
    try:
        line = sys.stdin.readline()
    except Exception:
        return False
    return str(line or "").strip().lower() in ("y", "yes")


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ConfirmationRequired as exc:
        if _confirm_from_stdin(str(exc)):
            kwargs = dict(kwargs)
            kwargs["confirm"] = True
            return fn(*args, **kwargs)
        sys.stdout.write("Cancelled.\nNo changes were applied.\n")
        return {"cancelled": True}
    except ConcurrencyError as exc:
        raise SystemExit(str(exc)) from exc
    except ControlPlaneError as exc:
        raise SystemExit(str(exc)) from exc


def _need(tokens, n, usage):
    if len(tokens) < n:
        raise SystemExit("Missing arguments.\n\nUsage:\n  %s" % usage)


def dispatch(tokens, *, root=None, plane: Optional[ControlPlane] = None, client_sel: Optional[str] = None):
    tokens = [str(t) for t in tokens if t is not None]
    plane = plane or ControlPlane(root)
    client_sel = client_sel or os.environ.get("DRLINK_LOCAL_CLIENT")
    if not tokens:
        return 0
    verb = tokens[0]
    try:
        return _dispatch(plane, verb, tokens, client_sel)
    except ConfirmationRequired:
        raise
    except (ControlPlaneError, ConcurrencyError, SchemaTooNewError, DatabaseCorruptError) as exc:
        sys.stderr.write("%s\n" % exc)
        return 1


def _dispatch(plane: ControlPlane, verb: str, tokens, client_sel):
    if verb == "show":
        return _show(plane, tokens[1:])
    if verb == "set":
        return _set(plane, tokens[1:], client_sel)
    if verb == "unset":
        return _unset(plane, tokens[1:], client_sel)
    if verb == "test":
        return _test(plane, tokens[1:])
    if verb == "system":
        return _system(plane, tokens[1:])
    raise SystemExit("Unknown command")


def _show(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing resource.")
    res = rest[0]
    if res == "status":
        sys.stdout.write(plane.format_status())
        return 0
    if res == "objects":
        rows = plane.list_objects()
        sys.stdout.write("%-16s %-18s %-12s %s\n" % ("NAME", "TYPE", "ORIGIN", "STATUS"))
        for obj in rows:
            sys.stdout.write(
                "%-16s %-18s %-12s %s\n"
                % (
                    obj["name"],
                    obj["type"],
                    "Data Relay" if obj["origin"] == "managed" else "Static",
                    obj.get("status") or "-",
                )
            )
        return 0
    if res == "object":
        _need(rest, 2, "show object <OBJECT>")
        if len(rest) >= 3 and rest[2] == "references":
            refs = plane.object_references(rest[1])
            if not refs:
                sys.stdout.write("(no references)\n")
            else:
                for r in refs:
                    sys.stdout.write("%s\n" % r["display"])
            return 0
        sys.stdout.write(plane.format_object(rest[1]))
        return 0
    if res in ("object-groups",):
        for g in plane.conn.execute("SELECT name FROM object_groups ORDER BY name"):
            sys.stdout.write("%s\n" % g["name"])
        return 0
    if res == "object-group":
        _need(rest, 2, "show object-group <GROUP>")
        if len(rest) >= 3 and rest[2] == "references":
            sys.stdout.write(plane.format_object_group(rest[1]))
            return 0
        sys.stdout.write(plane.format_object_group(rest[1]))
        return 0
    if res in ("managed-endpoints",):
        for obj in plane.list_objects():
            if obj["type"] == "managed_endpoint":
                sys.stdout.write("%s\n" % obj["name"])
        return 0
    if res == "managed-endpoint":
        _need(rest, 2, "show managed-endpoint <ENDPOINT>")
        if len(rest) >= 3 and rest[2] == "addresses":
            sys.stdout.write(plane.format_managed_endpoint(rest[1]))
            return 0
        if len(rest) >= 3 and rest[2] == "references":
            for r in plane.object_references(rest[1]):
                sys.stdout.write("%s\n" % r["display"])
            return 0
        sys.stdout.write(plane.format_managed_endpoint(rest[1]))
        return 0
    if res in ("published-services", "services"):
        for row in plane.conn.execute(
            "SELECT c.label, s.name, s.target_mode, s.public_port, s.enabled FROM published_services s "
            "JOIN clients c ON c.id = s.client_id WHERE s.released = 0 ORDER BY s.name"
        ):
            sys.stdout.write(
                "%s %s %s %s %s\n"
                % (row["label"] or "-", row["name"], row["target_mode"], row["public_port"], "enabled" if row["enabled"] else "disabled")
            )
        return 0
    if res == "published-service":
        _need(rest, 3, "show published-service <CLIENT_OR_ENDPOINT> <SERVICE>")
        sys.stdout.write(plane.format_published_service(rest[1], rest[2]))
        return 0
    if res in ("service-presets",):
        for row in plane.conn.execute("SELECT name, service_type, target_mode, target_port FROM service_presets ORDER BY name"):
            sys.stdout.write("%s %s %s %s\n" % (row["name"], row["service_type"], row["target_mode"], row["target_port"]))
        return 0
    if res == "service-preset":
        _need(rest, 2, "show service-preset <PRESET>")
        row = plane.conn.execute(
            "SELECT * FROM service_presets WHERE name = ? COLLATE NOCASE", (rest[1],)
        ).fetchone()
        if not row:
            raise SystemExit("Service Preset not found")
        sys.stdout.write(
            "Service Preset: %s\nType: %s\nTarget Mode: %s\nTarget Port: %s\nDescription: %s\n"
            "A Service Preset only supplies initial values.\nChanging it does not change existing Published Services.\n"
            % (row["name"], row["service_type"], row["target_mode"], row["target_port"], row["description"])
        )
        return 0
    if res == "remote-access":
        if len(rest) == 1:
            sys.stdout.write(plane.format_rulebase("remote"))
            return 0
        if len(rest) >= 3 and rest[2] == "impact":
            sys.stdout.write(plane.format_rule_impact("remote", rest[1]))
            sys.stdout.write(plane.format_shadow("remote"))
            return 0
        rule = plane._get_rule("remote", rest[1])
        if not rule:
            raise SystemExit("Rule not found")
        sys.stdout.write(plane.format_rule_impact("remote", rest[1]))
        return 0
    if res == "internet-access":
        if len(rest) == 1:
            sys.stdout.write(plane.format_rulebase("internet"))
            return 0
        if len(rest) >= 3 and rest[2] == "impact":
            sys.stdout.write(plane.format_rule_impact("internet", rest[1]))
            return 0
        sys.stdout.write(plane.format_rule_impact("internet", rest[1]))
        return 0
    if res == "fixed-tcp":
        if len(rest) == 1:
            for row in plane.conn.execute("SELECT name, dest_host, dest_port, enabled FROM fixed_tcp ORDER BY name"):
                sys.stdout.write("%s %s:%s %s\n" % (row["name"], row["dest_host"], row["dest_port"], "enabled" if row["enabled"] else "disabled"))
            return 0
        row = plane.conn.execute("SELECT * FROM fixed_tcp WHERE name = ? COLLATE NOCASE", (rest[1],)).fetchone()
        if not row:
            raise SystemExit("Fixed TCP entry not found")
        sys.stdout.write(
            "Fixed TCP: %s\nListen: %s\nDestination: %s:%s\nEnabled: %s\n"
            % (row["name"], row["listen_port"], row["dest_host"], row["dest_port"], "yes" if row["enabled"] else "no")
        )
        return 0
    if res in ("clients",):
        for row in plane.conn.execute("SELECT id, label, hostname, status, trust_status FROM clients ORDER BY label"):
            sys.stdout.write("%s %s %s %s\n" % (row["id"][:8], row["label"] or "-", row["hostname"] or "-", row["status"]))
        return 0
    if res == "client":
        _need(rest, 2, "show client <CLIENT>")
        client = plane.require_client(rest[1])
        view = rest[2] if len(rest) > 2 else "overview"
        if view == "endpoint":
            ep = plane.conn.execute(
                "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
                (client["id"],),
            ).fetchone()
            if ep:
                sys.stdout.write(plane.format_managed_endpoint(ep["name"]))
            return 0
        if view == "addresses":
            ep = plane.conn.execute(
                "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
                (client["id"],),
            ).fetchone()
            if ep:
                sys.stdout.write(plane.format_managed_endpoint(ep["name"]))
            return 0
        if view == "services":
            for s in plane.conn.execute(
                "SELECT name, service_type, target_mode, public_port, enabled FROM published_services WHERE client_id = ?",
                (client["id"],),
            ):
                sys.stdout.write("%s %s %s %s %s\n" % (s["name"], s["service_type"], s["target_mode"], s["public_port"], s["enabled"]))
            return 0
        if view == "groups":
            for g in plane.conn.execute(
                "SELECT g.name FROM client_groups g JOIN client_group_members m ON m.group_id = g.id WHERE m.client_id = ?",
                (client["id"],),
            ):
                sys.stdout.write("%s\n" % g["name"])
            return 0
        sys.stdout.write(
            "Client: %s\nClient ID: %s\nHostname: %s\nStatus: %s\nTrust: %s\n"
            % (client["label"] or "-", client["id"], client["hostname"] or "-", client["status"], client["trust_status"])
        )
        return 0
    if res in ("client-groups",):
        for g in plane.conn.execute("SELECT name FROM client_groups ORDER BY name"):
            sys.stdout.write("%s\n" % g["name"])
        return 0
    if res == "client-group":
        _need(rest, 2, "show client-group <GROUP>")
        g = plane.conn.execute("SELECT * FROM client_groups WHERE name = ? COLLATE NOCASE", (rest[1],)).fetchone()
        if not g:
            raise SystemExit("Client Group not found")
        sys.stdout.write("Client Group: %s\n%s\n" % (g["name"], g["description"] or ""))
        for m in plane.conn.execute(
            "SELECT c.id, c.label FROM client_group_members x JOIN clients c ON c.id = x.client_id WHERE x.group_id = ?",
            (g["id"],),
        ):
            sys.stdout.write("  %s %s\n" % (m["id"][:8], m["label"] or "-"))
        return 0
    if res in ("ai-principals",):
        for p in plane.conn.execute("SELECT name, enabled, credential_status FROM ai_principals ORDER BY name"):
            sys.stdout.write("%s enabled=%s credential=%s\n" % (p["name"], p["enabled"], p["credential_status"]))
        return 0
    if res == "ai-principal":
        _need(rest, 2, "show ai-principal <PRINCIPAL>")
        p = plane.get_principal(rest[1])
        if not p:
            raise SystemExit("AI Principal not found")
        if len(rest) >= 3 and rest[2] == "references":
            for r in plane.conn.execute("SELECT name FROM ai_access_rules WHERE principal_id = ?", (p["id"],)):
                sys.stdout.write("ai-access %s\n" % r["name"])
            return 0
        sys.stdout.write(
            "AI Principal: %s\n\n"
            "Status              : %s\n"
            "Authentication      : %s\n"
            "Credential Status   : %s\n"
            "Last Seen           : %s\n"
            "Issuer              : %s\n"
            "Subject Binding     : %s\n"
            "Fingerprint         : %s\n"
            "Rules               : %s\n"
            % (
                p["name"],
                "Enabled" if p["enabled"] else "Disabled",
                "OAuth" if str(p["auth_mode"] or "") == "oauth" else "Static Bearer",
                p["credential_status"],
                p["last_seen"] or "-",
                p["oauth_issuer"] or ("built-in" if str(p["auth_mode"] or "") == "oauth" else "-"),
                p["oauth_subject"] or ("Configured" if str(p["auth_mode"] or "") == "oauth" else "-"),
                p["credential_fingerprint"] or "-",
                plane.conn.execute(
                    "SELECT COUNT(*) FROM ai_access_rules WHERE principal_id = ?", (p["id"],)
                ).fetchone()[0],
            )
        )
        if p["description"]:
            sys.stdout.write("Description         : %s\n" % p["description"])
        return 0
    if res == "ai-access":
        if len(rest) == 1:
            sys.stdout.write("%-4s %-18s %-16s %-20s %-8s %s\n" % ("#", "NAME", "PRINCIPAL", "TARGETS", "ACTION", "STATUS"))
            for row in plane.conn.execute("SELECT * FROM ai_access_rules ORDER BY position"):
                view = plane._ai_rule_view(row)
                sys.stdout.write(
                    "%-4s %-18s %-16s %-20s %-8s %s\n"
                    % (
                        view["display_position"],
                        view["name"],
                        view["principal"] or "-",
                        ",".join(view["targets"])[:20],
                        view["action"].upper(),
                        "enabled" if view["enabled"] else "disabled",
                    )
                )
            sys.stdout.write("\nImplicit Default                                   DENY\n")
            return 0
        view = plane._ai_rule_view(plane._require_ai_rule(rest[1]))
        if len(rest) >= 3 and rest[2] == "impact":
            sys.stdout.write(
                "AI Access impact for %s\nPrincipal : %s\nTargets   : %s\nCapabilities: %s\nAction    : %s\nEnabled   : %s\n"
                % (
                    view["name"],
                    view["principal"] or "-",
                    ",".join(view["targets"]) or "-",
                    ",".join(view["capabilities"]) or "-",
                    view["action"].upper(),
                    "yes" if view["enabled"] else "no",
                )
            )
            if "exec" in view["capabilities"]:
                sys.stdout.write(
                    "\nexec can modify the target through shell/OS permissions.\n"
                    "A true read-only AI role requires exec disabled.\n"
                )
            return 0
        if view["capabilities"] and "exec" in view["capabilities"] and "write_file" not in view["capabilities"]:
            sys.stdout.write(
                "exec can modify the target through shell/OS permissions.\n"
                "A true read-only AI role requires exec disabled.\n\n"
            )
        sys.stdout.write(json.dumps(view, indent=2) + "\n")
        return 0
    if res == "ai-activity":
        principal = None
        endpoint = None
        if len(rest) >= 3 and rest[1] == "principal":
            principal = rest[2]
        if len(rest) >= 3 and rest[1] == "endpoint":
            endpoint = rest[2]
        sys.stdout.write(plane.format_ai_activity(plane.list_ai_activity(principal=principal, endpoint=endpoint)))
        return 0
    if res == "enrollments":
        for row in plane.conn.execute("SELECT id, kind, status FROM enrollments"):
            sys.stdout.write("%s %s %s\n" % (row["id"], row["kind"], row["status"]))
        return 0
    raise SystemExit("Unknown show resource.")


def _set(plane: ControlPlane, rest, client_sel):
    if not rest:
        raise SystemExit("Missing resource.")
    res = rest[0]
    if res == "object":
        _need(rest, 3, "set object <OBJECT> type|value|description|name ...")
        name, prop = rest[1], rest[2]
        if prop == "type":
            _need(rest, 4, "set object <OBJECT> type host|network|fqdn")
            _run(plane.set_object_type, name, rest[3])
            return 0
        if prop == "value":
            _need(rest, 4, "set object <OBJECT> value <VALUE>")
            _run(plane.set_object_value, name, rest[3])
            return 0
        if prop == "description":
            _run(plane.set_object_description, name, " ".join(rest[3:]))
            return 0
        if prop == "name":
            _run(plane.rename_object, name, rest[3])
            return 0
        raise SystemExit("Unknown object setting")
    if res == "object-group":
        _need(rest, 2, "set object-group <GROUP>")
        if len(rest) == 2:
            _run(plane.set_object_group, rest[1])
            return 0
        if rest[2] == "description":
            _run(plane.set_object_group, rest[1], description=" ".join(rest[3:]))
            return 0
        if rest[2] == "member":
            _run(plane.set_object_group_member, rest[1], rest[3])
            return 0
        raise SystemExit("Unknown object-group setting")
    if res == "client-group":
        _need(rest, 2, "set client-group <GROUP>")
        if len(rest) == 2:
            _run(plane.set_client_group, rest[1])
            return 0
        if rest[2] == "description":
            _run(plane.set_client_group, rest[1], description=" ".join(rest[3:]))
            return 0
        if rest[2] == "member":
            _run(plane.set_client_group_member, rest[1], rest[3])
            return 0
        raise SystemExit("Unknown client-group setting")
    if res == "client":
        _need(rest, 3, "set client <CLIENT> label|description|tag ...")
        if rest[2] == "label":
            _run(plane.set_client_label, rest[1], " ".join(rest[3:]))
            return 0
        if rest[2] in ("description", "note"):
            _run(plane.set_client_description, rest[1], " ".join(rest[3:]))
            return 0
        if rest[2] == "tag":
            raw = rest[3] if len(rest) > 3 else ""
            if "=" in raw:
                k, v = raw.split("=", 1)
            else:
                k, v = raw, rest[4] if len(rest) > 4 else ""
            _run(plane.set_client_tag, rest[1], k, v)
            return 0
        raise SystemExit("Unknown client setting")
    if res in ("remote-access", "internet-access"):
        plane_name = "remote" if res == "remote-access" else "internet"
        _need(rest, 2, "set %s <RULE>" % res)
        name = rest[1]
        if len(rest) == 2:
            _run(plane.set_rule, plane_name, name)
            return 0
        prop = rest[2]
        if prop == "source":
            _run(plane.set_rule_source, plane_name, name, rest[3])
            return 0
        if prop == "destination":
            _run(plane.set_rule_destination, plane_name, name, rest[3])
            return 0
        if prop == "service":
            proto = rest[3]
            port = rest[4] if len(rest) > 4 else (443 if proto in ("https",) else 80)
            # internet grammar: service https 443  OR service <PROTOCOL> <PORT>
            if proto.isdigit():
                port, proto = proto, rest[4] if len(rest) > 4 else "tcp"
            _run(plane.set_rule_service, plane_name, name, proto, int(port))
            return 0
        if prop == "action":
            _run(plane.set_rule_action, plane_name, name, rest[3])
            return 0
        if prop == "description":
            _run(plane.set_rule_description, plane_name, name, " ".join(rest[3:]))
            return 0
        if prop == "enabled":
            _run(plane.set_rule_enabled, plane_name, name, True)
            return 0
        if prop == "before":
            _run(plane.move_rule, plane_name, name, before=rest[3])
            return 0
        if prop == "after":
            _run(plane.move_rule, plane_name, name, after=rest[3])
            return 0
        raise SystemExit("Unknown %s setting" % res)
    if res == "published-service":
        # Client form: set published-service <SERVICE> ...
        # Test/server form: set published-service <CLIENT> <SERVICE> ...
        if len(rest) >= 3 and rest[2] in ("type", "target-mode", "target-host", "target-port", "enabled"):
            svc = rest[1]
            client = client_sel
            idx = 2
        elif len(rest) >= 4:
            client, svc, idx = rest[1], rest[2], 3
        else:
            raise SystemExit("set published-service <SERVICE> type|target-mode|...")
        if not client:
            raise SystemExit("Published Service mutation requires a client context")
        fields = {}
        while idx < len(rest):
            key = rest[idx]
            if key == "type":
                fields["service_type"] = rest[idx + 1]
                idx += 2
            elif key == "target-mode":
                fields["target_mode"] = rest[idx + 1]
                idx += 2
            elif key == "target-host":
                fields["target_host"] = rest[idx + 1]
                idx += 2
            elif key == "target-port":
                fields["target_port"] = int(rest[idx + 1])
                idx += 2
            elif key == "enabled":
                fields["enabled"] = True
                idx += 1
            else:
                raise SystemExit("Unknown published-service setting")
        _run(plane.set_published_service, client, svc, **fields)
        return 0
    if res == "service-preset":
        _need(rest, 2, "set service-preset <PRESET>")
        if len(rest) == 2:
            _run(plane.set_service_preset, rest[1])
            return 0
        fields = {}
        i = 2
        while i < len(rest):
            if rest[i] == "type":
                fields["service_type"] = rest[i + 1]
                i += 2
            elif rest[i] == "target-mode":
                fields["target_mode"] = rest[i + 1]
                i += 2
            elif rest[i] == "target-port":
                fields["target_port"] = int(rest[i + 1])
                i += 2
            elif rest[i] == "description":
                fields["description"] = " ".join(rest[i + 1 :])
                break
            else:
                raise SystemExit("Unknown service-preset setting")
        _run(plane.set_service_preset, rest[1], **fields)
        return 0
    if res == "fixed-tcp":
        _need(rest, 2, "set fixed-tcp <ENTRY>")
        kwargs = {}
        i = 2
        while i < len(rest):
            if rest[i] in ("destination", "object"):
                kwargs["destination_object"] = rest[i + 1]
                i += 2
            elif rest[i] == "host":
                kwargs["dest_host"] = rest[i + 1]
                i += 2
            elif rest[i] == "port":
                kwargs["dest_port"] = int(rest[i + 1])
                i += 2
            elif rest[i] == "enabled":
                kwargs["enabled"] = True
                i += 1
            else:
                kwargs["destination_object"] = rest[i]
                i += 1
        _run(plane.set_fixed_tcp, rest[1], **kwargs)
        return 0
    if res == "ai-principal":
        _need(rest, 2, "set ai-principal <PRINCIPAL>")
        if len(rest) == 2:
            _run(plane.set_ai_principal, rest[1])
            return 0
        if rest[2] == "description":
            _run(plane.set_ai_principal, rest[1], description=" ".join(rest[3:]))
            return 0
        if rest[2] == "enabled":
            _run(plane.set_ai_principal, rest[1], enabled=True)
            return 0
        raise SystemExit("Unknown ai-principal setting")
    if res == "ai-access":
        _need(rest, 2, "set ai-access <RULE>")
        if len(rest) == 2:
            _run(plane.set_ai_rule, rest[1])
            return 0
        prop = rest[2]
        if prop == "principal":
            _run(plane.set_ai_rule_principal, rest[1], rest[3])
            return 0
        if prop == "target":
            _run(plane.set_ai_rule_target, rest[1], rest[3], rest[4])
            return 0
        if prop == "capability":
            _run(plane.set_ai_rule_capability, rest[1], rest[3])
            return 0
        if prop == "path":
            _run(plane.set_ai_rule_path, rest[1], rest[3])
            return 0
        if prop == "exec-timeout":
            _run(plane.set_ai_rule_exec_timeout, rest[1], int(rest[3]))
            return 0
        if prop == "action":
            _run(plane.set_ai_rule_action, rest[1], rest[3])
            return 0
        if prop == "description":
            _run(plane.set_ai_rule_description, rest[1], " ".join(rest[3:]))
            return 0
        if prop == "enabled":
            _run(plane.set_ai_rule_enabled, rest[1], True)
            return 0
        if prop == "before":
            _run(plane.move_ai_rule, rest[1], before=rest[3])
            return 0
        if prop == "after":
            _run(plane.move_ai_rule, rest[1], after=rest[3])
            return 0
        raise SystemExit("Unknown ai-access setting")
    if res == "enrollment":
        kind = rest[1] if len(rest) > 1 else "manual"
        def write():
            from drlink_control_db import utc_now_iso
            from drlink_control_plane import _new_id
            eid = _new_id("enr")
            plane.conn.execute(
                "INSERT INTO enrollments(id, kind, status, created_at) VALUES (?, ?, 'issued', ?)",
                (eid, kind, utc_now_iso()),
            )
            return {"entity": {"type": "enrollment", "id": eid}, "operation": "create"}
        _run(plane._mutate, "set enrollment %s" % kind, "create enrollment", write)
        sys.stdout.write("Enrollment created. Secret is not redisplayed.\n")
        return 0
    raise SystemExit("Unknown set resource.")


def _unset(plane: ControlPlane, rest, client_sel):
    if not rest:
        raise SystemExit("Missing resource.")
    res = rest[0]
    if res == "object":
        _need(rest, 2, "unset object <OBJECT>")
        if len(rest) >= 4 and rest[2] == "value":
            _run(plane.unset_object_value, rest[1], rest[3])
            return 0
        if len(rest) >= 3 and rest[2] == "description":
            _run(plane.set_object_description, rest[1], "")
            return 0
        _run(plane.unset_object, rest[1])
        return 0
    if res == "object-group":
        if len(rest) >= 4 and rest[2] == "member":
            _run(plane.unset_object_group_member, rest[1], rest[3])
            return 0
        _run(plane.unset_object_group, rest[1])
        return 0
    if res == "client-group":
        if len(rest) >= 4 and rest[2] == "member":
            _run(plane.unset_client_group_member, rest[1], rest[3])
            return 0
        _run(plane.unset_client_group, rest[1])
        return 0
    if res == "client":
        _need(rest, 2, "unset client <CLIENT>")
        if len(rest) >= 4 and rest[2] == "tag":
            _run(plane.unset_client_tag, rest[1], rest[3])
            return 0
        _run(plane.remove_client, rest[1])
        return 0
    if res in ("remote-access", "internet-access"):
        plane_name = "remote" if res == "remote-access" else "internet"
        name = rest[1]
        if len(rest) == 2:
            _run(plane.unset_rule, plane_name, name)
            return 0
        if rest[2] == "source":
            _run(plane.unset_rule_ref, plane_name, name, "source", rest[3])
            return 0
        if rest[2] == "destination":
            _run(plane.unset_rule_ref, plane_name, name, "destination", rest[3])
            return 0
        if rest[2] == "service":
            _run(plane.unset_rule_service, plane_name, name, rest[3], int(rest[4]))
            return 0
        if rest[2] == "enabled":
            _run(plane.set_rule_enabled, plane_name, name, False)
            return 0
        raise SystemExit("Unknown unset")
    if res == "published-service":
        svc = rest[1]
        client = client_sel
        if len(rest) >= 3 and rest[2] != "enabled":
            client, svc = rest[1], rest[2]
            extra = rest[3:]
        else:
            extra = rest[2:]
        if extra and extra[0] == "enabled":
            _run(plane.set_published_service_enabled, client, svc, False)
            return 0
        _run(plane.unset_published_service, client, svc, release=True)
        return 0
    if res == "service-preset":
        _run(plane.unset_service_preset, rest[1])
        return 0
    if res == "fixed-tcp":
        _run(plane.unset_fixed_tcp, rest[1])
        return 0
    if res == "ai-principal":
        if len(rest) >= 3 and rest[2] == "enabled":
            _run(plane.set_ai_principal, rest[1], enabled=False)
            return 0
        _run(plane.unset_ai_principal, rest[1])
        return 0
    if res == "ai-access":
        name = rest[1]
        if len(rest) == 2:
            _run(plane.unset_ai_rule, name)
            return 0
        if rest[2] == "target":
            _run(plane.unset_ai_rule_target, name, rest[3], rest[4])
            return 0
        if rest[2] == "capability":
            _run(plane.unset_ai_rule_capability, name, rest[3])
            return 0
        if rest[2] == "path":
            _run(plane.unset_ai_rule_path, name, rest[3])
            return 0
        if rest[2] == "exec-timeout":
            _run(plane.unset_ai_rule_exec_timeout, name)
            return 0
        if rest[2] == "enabled":
            _run(plane.set_ai_rule_enabled, name, False)
            return 0
        raise SystemExit("Unknown unset ai-access")
    if res == "enrollment":
        plane.conn.execute("DELETE FROM enrollments WHERE id = ?", (rest[1],))
        return 0
    raise SystemExit("Unknown unset resource.")


def _test(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing test target.")
    if rest[0] == "remote-access":
        _need(rest, 5, "test remote-access <SOURCE_IP> <DESTINATION> <PROTOCOL> <PORT>")
        result = plane.evaluate_remote_access(rest[1], rest[2], rest[3], int(rest[4]))
        sys.stdout.write(plane.format_remote_explain(result))
        return 0
    if rest[0] == "internet-access":
        _need(rest, 5, "test internet-access <SOURCE_IP> <DESTINATION> <PORT> <PROTOCOL>")
        result = plane.evaluate_internet_access(rest[1], rest[2], int(rest[3]), rest[4])
        sys.stdout.write(plane.format_internet_explain(result, dns={"status": "not executed (explain only)", "security": "server-side DNS required at runtime"}))
        return 0
    if rest[0] == "ai-access":
        _need(rest, 4, "test ai-access <PRINCIPAL> <ENDPOINT> <CAPABILITY> [OPERAND]")
        operand = rest[4] if len(rest) > 4 else None
        result = plane.evaluate_ai_access(rest[1], rest[2], rest[3], operand)
        sys.stdout.write(plane.format_ai_explain(result))
        return 0
    raise SystemExit("Unknown test target.")


def _system(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing system operation.")
    if rest[0] == "diagnostics":
        kind = rest[1] if len(rest) > 1 else "all"
        if kind in ("control-plane", "all"):
            sys.stdout.write(plane.diagnostics_control_plane())
        if kind in ("runtime", "all"):
            sys.stdout.write(plane.diagnostics_runtime())
        if kind in ("mcp", "all"):
            sys.stdout.write(plane.diagnostics_mcp())
        return 0
    if rest[0] == "backup":
        if len(rest) >= 2 and rest[1] == "validate":
            plane.backup_validate(rest[2])
            sys.stdout.write("Backup valid.\n")
            return 0
        path = rest[1] if len(rest) > 1 else "/tmp/drlink-backup.tar"
        plane.backup(path)
        sys.stdout.write("Backup written: %s\n" % path)
        return 0
    if rest[0] == "restore":
        plane.restore(rest[1])
        sys.stdout.write("Restore complete.\n")
        return 0
    if rest[0] == "revisions":
        for row in plane.list_revisions():
            sys.stdout.write("%s %s %s\n" % (row["revision"], row["created_at"], row["command"]))
        return 0
    if rest[0] == "revision":
        rows = [r for r in plane.list_revisions() if int(r["revision"]) == int(rest[1])]
        sys.stdout.write(json.dumps(rows, indent=2) + "\n")
        return 0
    if rest[0] == "diff":
        a = plane.conn.execute("SELECT snapshot_json FROM revision_snapshots WHERE revision = ?", (int(rest[1]),)).fetchone()
        b = plane.conn.execute("SELECT snapshot_json FROM revision_snapshots WHERE revision = ?", (int(rest[2]),)).fetchone()
        sys.stdout.write("revision %s: %s\n" % (rest[1], a["snapshot_json"] if a else "-"))
        sys.stdout.write("revision %s: %s\n" % (rest[2], b["snapshot_json"] if b else "-"))
        return 0
    if rest[0] == "audit":
        kwargs = {}
        if len(rest) >= 3 and rest[1] == "revision":
            kwargs["revision"] = int(rest[2])
        if len(rest) >= 4 and rest[1] == "entity":
            kwargs["entity_type"] = rest[2]
            kwargs["entity_id"] = rest[3]
        if len(rest) >= 3 and rest[1] == "ai-principal":
            kwargs["principal"] = rest[2]
        rows = plane.list_audit(**kwargs)
        for row in rows:
            sys.stdout.write("%s rev=%s %s %s %s %s\n" % (row["timestamp"], row["revision"], row["action"], row["entity_type"], row["entity_id"], row["result"]))
        return 0
    if rest[0] == "revoke" and len(rest) >= 3 and rest[1] == "client":
        _run(plane.remove_client, rest[2], revoke_only=True)
        return 0
    if rest[0] == "credential":
        if len(rest) < 4:
            raise SystemExit("usage: system credential rotate|revoke|configure|approve-oauth ai-principal ...")
        if rest[1] == "rotate":
            result = _run(plane.rotate_ai_credential, rest[3])
            token = result.get("token") if isinstance(result, dict) else None
            if token:
                sys.stdout.write("Credential issued once. Store it now; it will not be shown again.\n")
                sys.stdout.write("Fingerprint: %s\n" % result.get("fingerprint"))
                sys.stdout.write("Token: %s\n" % token)
            return 0
        if rest[1] == "revoke":
            _run(plane.revoke_ai_credential, rest[3])
            sys.stdout.write("Credential revoked.\n")
            return 0
        if rest[1] == "configure":
            principal = rest[3]
            if len(rest) >= 6 and rest[4] == "authentication":
                _run(plane.configure_ai_auth, principal, rest[5])
                sys.stdout.write("Authentication configured.\n")
                return 0
            if len(rest) >= 6 and rest[4] == "oauth-redirect":
                _run(plane.add_oauth_redirect, principal, rest[5])
                sys.stdout.write("OAuth redirect registered.\n")
                return 0
            raise SystemExit(
                "usage: system credential configure ai-principal <PRINCIPAL> authentication <static-bearer|oauth>\n"
                "       system credential configure ai-principal <PRINCIPAL> oauth-redirect <URI>"
            )
        if rest[1] == "approve-oauth":
            result = _run(plane.approve_oauth_pending, rest[2] if rest[2] != "ai-principal" else rest[3])
            sys.stdout.write("Authorization code issued. It is shown once.\n")
            sys.stdout.write("code=%s\n" % result.get("code"))
            return 0
        raise SystemExit("Unknown credential operation.")
    raise SystemExit("Unknown system operation.")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    root = (
        os.environ.get("FRP_DEPLOY_TEST_ROOT")
        or os.environ.get("FRP_CTL_TEST_ROOT")
        or os.environ.get("FRP_SERVER_TEST_ROOT")
        or os.environ.get("DRLINK_TEST_ROOT")
    )
    rc = dispatch(argv, root=root)
    return rc or 0


if __name__ == "__main__":
    raise SystemExit(main())
