#!/usr/bin/env python3
"""Public CLI handlers for the v2.4 canonical command surface."""
from __future__ import annotations

import sys
from typing import Optional

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane
import drlink_v24 as v24


SERVER_ONLY = frozenset(
    {
        "network-object",
        "network-objects",
        "network-group",
        "network-groups",
        "service-object",
        "service-objects",
        "service-group",
        "service-groups",
        "permission-object",
        "permission-objects",
        "permission-group",
        "permission-groups",
        "remote-access",
        "internet-access",
        "ai-access",
        "ai-access-log",
        "ai-identity",
        "ai-identities",
        "managed-host",
        "managed-hosts",
        "enrollment",
        "enrollments",
    }
)

AGENT_ONLY_MUTATE = frozenset({"remote-service", "remote-services"})

OBSOLETE = {
    "object": "Use network-object / service-object instead.",
    "objects": "Use show network-objects / show service-objects instead.",
    "object-group": "Use network-group instead.",
    "object-groups": "Use show network-groups instead.",
    "fixed-tcp": "Fixed TCP is a Service Object type. Use: set service-object <NAME> type fixed-tcp port <PORT>",
    "published-service": "Use remote-service on the Agent Host.",
    "published-services": "Use show remote-services on the Agent Host, or show managed-host <HOST> remote-services on the Server.",
    "ai-principal": "Use ai-identity instead.",
    "ai-principals": "Use show ai-identities instead.",
    "client": "Use managed-host instead.",
    "clients": "Use show managed-hosts instead.",
    "managed-endpoint": "Use managed-host instead.",
    "managed-endpoints": "Use show managed-hosts instead.",
}


def _role(plane: ControlPlane) -> str:
    return v24.detect_cli_role(plane.root)


def _policy_resource_label(res: str) -> str:
    mapping = {
        "remote-access": "Remote Access policy",
        "internet-access": "Internet Access policy",
        "ai-access": "AI Access policy",
    }
    return mapping.get(res, res.replace("-", " ").title())


def _require_server(plane: ControlPlane, resource: str) -> None:
    if _role(plane) == "agent":
        raise ControlPlaneError(v24.role_error_server_resource(resource))


def _require_agent(plane: ControlPlane) -> None:
    if _role(plane) == "server":
        raise ControlPlaneError(v24.role_error_agent_resource())


def maybe_handle_obsolete(res: str) -> None:
    if res in OBSOLETE:
        raise ControlPlaneError(
            "ERROR:\n'%s' is not part of the canonical DRLink CLI.\n\n%s\n\nNo changes were applied."
            % (res, OBSOLETE[res])
        )


def _legacy_backend_resource(res: str) -> bool:
    """True when a non-canonical noun still has a working backend implementation.

    Discovery omits these names. Explicit invocation falls through to the
    control-plane backend rather than hard-failing operators and MCP tests.
    """
    return res in OBSOLETE


def _guided_create_available() -> bool:
    from drlink_v24_wizard import wizard_available

    return wizard_available()


def _v24_named_kv(tokens: list[str]) -> bool:
    """True when tokens look like the v2.4 named-key oneshot form."""
    if not tokens:
        return False
    return str(tokens[0]).strip().lower() in (
        "mode",
        "source",
        "destination",
        "service",
        "permission",
        "type",
        "value",
        "members",
        "port",
    )


def handle_show(plane: ControlPlane, rest: list[str]) -> Optional[int]:
    if not rest:
        return None
    res = rest[0]
    if _legacy_backend_resource(res):
        return None
    if res == "status":
        sys.stdout.write(plane.format_status())
        return 0
    if res in ("network-objects",):
        _require_server(plane, "Network Objects")
        sys.stdout.write("%-16s %s\n" % ("NAME", "TYPE"))
        for row in v24.list_network_objects(plane):
            sys.stdout.write("%-16s %s\n" % (row["name"], row["type"]))
        return 0
    if res == "network-object":
        _require_server(plane, "Network Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show network-object <OBJECT>")
        name = rest[1]
        obj = plane.get_object(name)
        if not obj:
            raise ControlPlaneError(v24.cli_error("Network Object '%s' was not found." % name))
        if len(rest) >= 3 and rest[2] == "references":
            refs = plane.object_references(name)
            sys.stdout.write(v24.format_references_view(refs))
            return 0
        if len(rest) >= 3:
            raise ControlPlaneError(
                v24.cli_error(
                    "Unknown Network Object view '%s'." % rest[2],
                    expected="  references",
                )
            )
        if obj["type"] == "managed_endpoint" or obj["origin"] == "managed":
            client = None
            try:
                client = plane.get_client(name)
            except ControlPlaneError:
                client = None
            hostname = client["hostname"] if client else "-"
            status = (
                "Connected"
                if client and client["connected"]
                else ("Disconnected" if client else "Managed Host")
            )
            sys.stdout.write(
                "Network Object: %s\nType : Managed Host\nOrigin: Managed Host\nHostname: %s\nStatus: %s\n"
                % (obj["name"], hostname or "-", status)
            )
            return 0
        payload = dict(obj)
        values = payload.get("values") or plane._object_values(payload["id"])
        sys.stdout.write(
            "Network Object: %s\nType : %s\nValue: %s\n"
            % (payload["name"], v24.display_network_type(payload["type"]), values[0] if values else "-")
        )
        return 0
    if res in ("network-groups",):
        _require_server(plane, "Network Groups")
        for g in plane.conn.execute("SELECT name FROM object_groups ORDER BY name"):
            sys.stdout.write("%s\n" % g["name"])
        return 0
    if res == "network-group":
        _require_server(plane, "Network Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show network-group <GROUP>")
        g = plane.get_object_group(rest[1])
        if not g:
            raise ControlPlaneError(v24.cli_error("Network Group '%s' was not found." % rest[1]))
        if len(rest) >= 3 and rest[2] == "references":
            refs = v24.network_group_references(plane, rest[1])
            sys.stdout.write(v24.format_references_view(refs))
            return 0
        if len(rest) >= 3:
            raise ControlPlaneError(
                v24.cli_error(
                    "Unknown Network Group view '%s'." % rest[2],
                    expected="  references",
                )
            )
        sys.stdout.write("Network Group: %s\n" % g["name"])
        for mem in plane._expand_group_members(g["id"], set()):
            sys.stdout.write("  %s\n" % mem["name"])
        return 0
    if res in ("service-objects",):
        _require_server(plane, "Service Objects")
        sys.stdout.write("%-16s %-10s %s\n" % ("NAME", "TYPE", "PORT"))
        for row in plane.conn.execute("SELECT name, type, port FROM service_objects ORDER BY name"):
            sys.stdout.write("%-16s %-10s %s\n" % (row["name"], row["type"], row["port"]))
        return 0
    if res == "service-object":
        _require_server(plane, "Service Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show service-object <SERVICE>")
        sobj = v24.get_service_object(plane, rest[1])
        if not sobj:
            raise ControlPlaneError(v24.cli_error("Service Object '%s' was not found." % rest[1]))
        if len(rest) >= 3 and rest[2] == "references":
            refs = v24.service_object_references(plane, rest[1])
            sys.stdout.write(v24.format_references_view(refs))
            return 0
        if len(rest) >= 3:
            raise ControlPlaneError(
                v24.cli_error(
                    "Unknown Service Object view '%s'." % rest[2],
                    expected="  references",
                )
            )
        sys.stdout.write(
            "Service Object: %s\nType : %s\nPort : %s\n" % (sobj["name"], sobj["type"], sobj["port"])
        )
        return 0
    if res in ("service-groups",):
        _require_server(plane, "Service Groups")
        for g in plane.conn.execute("SELECT name FROM service_groups ORDER BY name"):
            sys.stdout.write("%s\n" % g["name"])
        return 0
    if res == "service-group":
        _require_server(plane, "Service Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show service-group <GROUP>")
        g = v24.get_service_group(plane, rest[1])
        if not g:
            raise ControlPlaneError(v24.cli_error("Service Group '%s' was not found." % rest[1]))
        if len(rest) >= 3 and rest[2] == "references":
            refs = v24.service_group_references(plane, rest[1])
            sys.stdout.write(v24.format_references_view(refs))
            return 0
        if len(rest) >= 3:
            raise ControlPlaneError(
                v24.cli_error(
                    "Unknown Service Group view '%s'." % rest[2],
                    expected="  references",
                )
            )
        sys.stdout.write("Service Group: %s\n" % g["name"])
        for m in plane.conn.execute(
            "SELECT s.name FROM service_group_members x JOIN service_objects s ON s.id = x.service_object_id WHERE x.group_id = ?",
            (g["id"],),
        ):
            sys.stdout.write("  %s\n" % m["name"])
        return 0
    if res in ("permission-objects",):
        _require_server(plane, "Permission Objects")
        for row in plane.conn.execute("SELECT name FROM permission_objects ORDER BY name"):
            sys.stdout.write("%s\n" % row["name"])
        return 0
    if res == "permission-object":
        _require_server(plane, "Permission Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show permission-object <PERMISSION>")
        pobj = v24.get_permission_object(plane, rest[1])
        if not pobj:
            raise ControlPlaneError(v24.cli_error("Permission Object '%s' was not found." % rest[1]))
        sys.stdout.write("Permission Object: %s\n\nPermissions:\n" % pobj["name"])
        for r in plane.conn.execute(
            "SELECT permission FROM permission_object_members WHERE permission_object_id = ? ORDER BY permission",
            (pobj["id"],),
        ):
            sys.stdout.write("  %s\n" % r["permission"])
        return 0
    if res in ("permission-groups",):
        _require_server(plane, "Permission Groups")
        for row in plane.conn.execute("SELECT name FROM permission_groups ORDER BY name"):
            sys.stdout.write("%s\n" % row["name"])
        return 0
    if res == "permission-group":
        _require_server(plane, "Permission Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show permission-group <GROUP>")
        g = v24.get_permission_group(plane, rest[1])
        if not g:
            raise ControlPlaneError(v24.cli_error("Permission Group '%s' was not found." % rest[1]))
        sys.stdout.write("Permission Group: %s\n" % g["name"])
        for m in plane.conn.execute(
            "SELECT p.name FROM permission_group_members x JOIN permission_objects p ON p.id = x.permission_object_id WHERE x.group_id = ?",
            (g["id"],),
        ):
            sys.stdout.write("  %s\n" % m["name"])
        return 0
    if res in ("managed-hosts",):
        _require_server(plane, "Managed Hosts")
        for row in plane.conn.execute(
            "SELECT id, label, hostname, status FROM clients ORDER BY COALESCE(label, hostname, id)"
        ):
            sys.stdout.write(
                "%s %s %s\n"
                % (row["label"] or row["hostname"] or row["id"][:8], row["hostname"] or "-", row["status"])
            )
        return 0
    if res == "managed-host":
        _require_server(plane, "Managed Hosts")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show managed-host <HOST>")
        client = plane.require_client(rest[1])
        view = rest[2] if len(rest) > 2 else "overview"
        if view == "remote-services":
            sys.stdout.write("%-18s %-14s %-10s %-24s %s\n" % ("NAME", "DESTINATION", "SERVICE", "ENDPOINT", "STATUS"))
            for s in plane.conn.execute(
                "SELECT s.name, s.public_port, s.enabled, m.destination_name, m.status, m.service_object_id, m.pending_allocation "
                "FROM published_services s LEFT JOIN remote_service_meta m ON m.service_id = s.id "
                "WHERE s.client_id = ? AND s.released = 0 ORDER BY s.name",
                (client["id"],),
            ):
                sobj = None
                if s["service_object_id"]:
                    sobj = plane.conn.execute(
                        "SELECT name FROM service_objects WHERE id = ?", (s["service_object_id"],)
                    ).fetchone()
                endpoint = (
                    "Pending allocation"
                    if s["pending_allocation"]
                    else ("drlink.local:%s" % s["public_port"] if s["public_port"] else "-")
                )
                status = s["status"] or ("DISABLED" if not s["enabled"] else "DEGRADED")
                sys.stdout.write(
                    "%-18s %-14s %-10s %-24s %s\n"
                    % (
                        s["name"],
                        s["destination_name"] or "-",
                        sobj["name"] if sobj else "-",
                        endpoint,
                        status,
                    )
                )
            return 0
        if view == "agent":
            host_label = client["label"] or client["hostname"] or client["id"][:8]
            connection = "Connected" if client["connected"] else "Disconnected"
            last_seen = client["last_seen"] or "Never"
            lines = [
                "Managed Host Agent: %s" % host_label,
                "Connection   : %s" % connection,
                "Host status  : %s" % (client["status"] or "-"),
                "Last seen    : %s" % last_seen,
                "Agent version: Not reported to Server",
                "Source HEAD  : Not reported to Server",
                "FRP version  : Not reported to Server",
                "",
                "Runtime health details are reported by the Agent Host via:",
                "  show status",
            ]
            sys.stdout.write("\n".join(lines) + "\n")
            return 0
        if view == "addresses":
            host_label = client["label"] or client["hostname"] or client["id"][:8]
            ep = plane.conn.execute(
                "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id "
                "WHERE e.client_id = ?",
                (client["id"],),
            ).fetchone()
            sys.stdout.write("Managed Host Addresses: %s\n" % host_label)
            if not ep:
                sys.stdout.write("  None\n")
                return 0
            addrs = plane.endpoint_addresses(ep["name"])
            usable = [
                a
                for a in addrs
                if a.get("active") and str(a.get("scope") or "") not in ("loopback", "link-local", "special")
            ]
            if not usable:
                sys.stdout.write("  None\n")
                return 0
            for a in usable:
                sys.stdout.write(
                    "  %-18s %-8s %s\n"
                    % (a.get("address") or "-", a.get("scope") or "-", a.get("interface_name") or "-")
                )
            return 0
        if view != "overview":
            raise ControlPlaneError(
                v24.cli_error(
                    "Unknown Managed Host view '%s'." % view,
                    expected="  remote-services\n  agent\n  addresses",
                )
            )
        sys.stdout.write(
            "Managed Host: %s\nHostname: %s\nStatus: %s\nAgent: %s\n"
            % (
                client["label"] or client["hostname"] or client["id"][:8],
                client["hostname"] or "-",
                client["status"],
                "Connected" if client["connected"] else "Disconnected",
            )
        )
        return 0
    if res in ("ai-identities",):
        _require_server(plane, "AI Identities")
        for p in plane.conn.execute("SELECT name, enabled, credential_status FROM ai_principals ORDER BY name"):
            status = "VERIFIED" if str(p["credential_status"] or "").lower() in ("verified", "active", "configured", "ok") else (
                p["credential_status"] or "UNBOUND"
            )
            sys.stdout.write("%s %s\n" % (p["name"], status))
        return 0
    if res == "ai-identity":
        _require_server(plane, "AI Identities")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show ai-identity <IDENTITY>")
        p = plane.get_principal(rest[1])
        if not p:
            raise ControlPlaneError(v24.cli_error("AI Identity '%s' was not found." % rest[1]))
        status = "VERIFIED" if str(p["credential_status"] or "").lower() in ("verified", "active", "configured", "ok") else (
            p["credential_status"] or "UNBOUND"
        )
        sys.stdout.write("AI Identity : %s\nStatus      : %s\n" % (p["name"], status))
        return 0
    if res == "remote-access":
        _require_server(plane, "Remote Access policy")
        return _show_policy(plane, "remote", rest)
    if res == "internet-access":
        _require_server(plane, "Internet Access policy")
        return _show_policy(plane, "internet", rest)
    if res == "ai-access":
        _require_server(plane, "AI Access policy")
        if len(rest) == 1:
            cap_n = plane.conn.execute("SELECT COUNT(*) FROM ai_access_rules").fetchone()[0]
            v24_n = plane.conn.execute("SELECT COUNT(*) FROM ai_policy_rules").fetchone()[0]
            if int(cap_n or 0) and not int(v24_n or 0):
                return None
        if len(rest) >= 3 and rest[2] in ("impact",):
            return None
        if len(rest) >= 2:
            v24_row = plane.conn.execute(
                "SELECT id FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (rest[1],)
            ).fetchone()
            cap_row = plane.conn.execute(
                "SELECT id FROM ai_access_rules WHERE name = ? COLLATE NOCASE", (rest[1],)
            ).fetchone()
            if cap_row is not None and v24_row is None:
                return None
        return _show_ai_policy(plane, rest)
    if res == "ai-access-log":
        _require_server(plane, "AI Access Log")
        return _show_ai_log(plane, rest[1:])
    if res in ("remote-services",):
        _require_agent(plane)
        sys.stdout.write("%-18s %-14s %-10s %-24s %s\n" % ("NAME", "DESTINATION", "SERVICE", "ENDPOINT", "STATUS"))
        for row in plane.conn.execute("SELECT * FROM agent_remote_services WHERE delete_pending = 0 ORDER BY name"):
            endpoint = (
                "Pending allocation"
                if row["pending_allocation"] or row["endpoint_port"] is None
                else "%s:%s" % (row["endpoint_host"] or "drlink.local", row["endpoint_port"])
            )
            sys.stdout.write(
                "%-18s %-14s %-10s %-24s %s\n"
                % (row["name"], row["destination"], row["service_object"], endpoint, row["status"])
            )
        return 0
    if res == "remote-service":
        _require_agent(plane)
        if len(rest) < 2:
            raise ControlPlaneError("Usage: show remote-service <NAME>")
        row = plane.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (rest[1],)
        ).fetchone()
        if not row or row["delete_pending"]:
            raise ControlPlaneError(v24.cli_error("Remote Service '%s' was not found." % rest[1]))
        endpoint = (
            "Pending allocation"
            if row["pending_allocation"] or row["endpoint_port"] is None
            else "%s:%s" % (row["endpoint_host"] or "drlink.local", row["endpoint_port"])
        )
        sys.stdout.write(
            "Remote Service: %s\nDestination: %s\nService: %s\nStatus: %s\nEndpoint: %s\nEnabled: %s\n"
            % (
                row["name"],
                row["destination"],
                row["service_object"],
                row["status"],
                endpoint,
                "YES" if row["enabled"] else "NO",
            )
        )
        if row["reason"]:
            sys.stdout.write("Reason: %s\n" % row["reason"])
        return 0
    return None


def _show_policy(plane: ControlPlane, family: str, rest: list[str]) -> int:
    pol = v24.get_access_policy(plane, family)
    title = "Remote Access" if family == "remote" else "Internet Access"
    if len(rest) == 1:
        sys.stdout.write("%s\n%s\n\n" % (title, "=" * len(title)))
        if pol["mode"] is None:
            sys.stdout.write("Mode        : No Policy\nEnforcement : -\nEffective   : ALLOW\n")
        else:
            # effective with no match is mode default
            eff = v24.effective_policy_result(pol["mode"], pol["enforcement"], False)
            if str(pol["enforcement"]).lower() == "disabled":
                eff = "ALLOW ALL"
            elif pol["mode"] == "whitelist":
                # With zero rules, whitelist is DENY ALL
                count = plane.conn.execute(
                    "SELECT COUNT(*) FROM policy_rules WHERE plane = ?", (family,)
                ).fetchone()[0]
                if int(count or 0) == 0:
                    eff = "DENY ALL"
                else:
                    enabled = plane.conn.execute(
                        "SELECT COUNT(*) FROM policy_rules WHERE plane = ? AND enabled = 1", (family,)
                    ).fetchone()[0]
                    if int(enabled or 0) == 0:
                        eff = "DENY ALL"
            elif pol["mode"] == "blacklist":
                count = plane.conn.execute(
                    "SELECT COUNT(*) FROM policy_rules WHERE plane = ?", (family,)
                ).fetchone()[0]
                if int(count or 0) == 0:
                    eff = "ALLOW ALL"
            sys.stdout.write(
                "Mode        : %s\nEnforcement : %s\nEffective   : %s\n"
                % (pol["mode"].upper(), str(pol["enforcement"]).upper(), eff)
            )
        sys.stdout.write("\nRules:\n")
        for row in plane.conn.execute(
            "SELECT name, enabled FROM policy_rules WHERE plane = ? ORDER BY name", (family,)
        ):
            sys.stdout.write("  %s (%s)\n" % (row["name"], "enabled" if row["enabled"] else "disabled"))
        return 0
    rule = plane._get_rule(family, rest[1])
    if not rule:
        raise ControlPlaneError(v24.cli_error("Rule '%s' was not found." % rest[1]))
    view = plane._rule_view(rule)
    sys.stdout.write(
        "%s Rule: %s\nSource: %s\nDestination: %s\nService: %s\nEnabled: %s\n"
        % (
            title,
            view["name"],
            ", ".join(view.get("sources") or []) or "-",
            ", ".join(view.get("destinations") or []) or "-",
            ", ".join(view.get("services") or []) or "-",
            "YES" if view["enabled"] else "NO",
        )
    )
    return 0


def _show_ai_policy(plane: ControlPlane, rest: list[str]) -> int:
    pol = v24.get_access_policy(plane, "ai")
    if len(rest) == 1:
        sys.stdout.write("AI Access\n=========\n\n")
        if pol["mode"] is None:
            sys.stdout.write("Mode        : No Policy\nEnforcement : -\nEffective   : ALLOW\n")
        else:
            eff = "ALLOW ALL" if str(pol["enforcement"]).lower() == "disabled" else (
                "DENY ALL" if pol["mode"] == "whitelist" else "ALLOW ALL"
            )
            count = plane.conn.execute("SELECT COUNT(*) FROM ai_policy_rules").fetchone()[0]
            if pol["mode"] == "whitelist" and int(count or 0) == 0 and str(pol["enforcement"]).lower() != "disabled":
                eff = "DENY ALL"
            sys.stdout.write(
                "Mode        : %s\nEnforcement : %s\nEffective   : %s\n"
                % (pol["mode"].upper(), str(pol["enforcement"]).upper(), eff)
            )
        sys.stdout.write("\nRules:\n")
        for row in plane.conn.execute("SELECT name, enabled FROM ai_policy_rules ORDER BY name"):
            sys.stdout.write("  %s (%s)\n" % (row["name"], "enabled" if row["enabled"] else "disabled"))
        return 0
    row = plane.conn.execute(
        "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (rest[1],)
    ).fetchone()
    if not row:
        raise ControlPlaneError(v24.cli_error("Rule '%s' was not found." % rest[1]))
    principal = plane.conn.execute(
        "SELECT name FROM ai_principals WHERE id = ?", (row["source_identity_id"],)
    ).fetchone()
    dest_label = "-"
    if row["destination_ref_kind"] == "object" and row["destination_ref_id"]:
        dest = plane.conn.execute(
            "SELECT name FROM objects WHERE id = ?", (row["destination_ref_id"],)
        ).fetchone()
        dest_label = dest["name"] if dest else "-"
    elif row["destination_ref_kind"] == "group" and row["destination_ref_id"]:
        dest = plane.conn.execute(
            "SELECT name FROM object_groups WHERE id = ?", (row["destination_ref_id"],)
        ).fetchone()
        dest_label = dest["name"] if dest else "-"
    perm_label = "-"
    if row["permission_ref_kind"] == "permission_object" and row["permission_ref_id"]:
        perm = plane.conn.execute(
            "SELECT name FROM permission_objects WHERE id = ?", (row["permission_ref_id"],)
        ).fetchone()
        perm_label = perm["name"] if perm else "-"
    elif row["permission_ref_kind"] == "permission_group" and row["permission_ref_id"]:
        perm = plane.conn.execute(
            "SELECT name FROM permission_groups WHERE id = ?", (row["permission_ref_id"],)
        ).fetchone()
        perm_label = perm["name"] if perm else "-"
    lines = [
        "AI Access Rule: %s" % row["name"],
        "Source      : %s" % (principal["name"] if principal else "-"),
        "Destination : %s" % dest_label,
        "Permission  : %s" % perm_label,
        "Enabled     : %s" % ("YES" if row["enabled"] else "NO"),
    ]
    if pol.get("mode"):
        lines.append("Mode        : %s" % str(pol["mode"]).upper())
        lines.append("Enforcement : %s" % str(pol.get("enforcement") or "-").upper())
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def _show_ai_log(plane: ControlPlane, args: list[str]) -> int:
    identity = destination = permission = None
    i = 0
    while i < len(args):
        key = args[i].lower()
        if key in ("identity", "destination", "permission") and i + 1 < len(args):
            if key == "identity":
                identity = args[i + 1]
            elif key == "destination":
                destination = args[i + 1]
            else:
                permission = args[i + 1]
            i += 2
            continue
        i += 1
    sys.stdout.write("%-22s %-10s %-14s %-12s %s\n" % ("TIME", "IDENTITY", "DESTINATION", "PERMISSION", "RESULT"))
    rows = plane.list_ai_activity(principal=identity, endpoint=destination)
    for row in rows:
        perm = permission or "-"
        # Map capability to permission label when possible
        cap = row.get("capability") or row.get("action") or "-"
        if permission and v24.CAP_TO_PERMISSION.get(str(cap)) != permission and str(cap) != permission:
            continue
        sys.stdout.write(
            "%-22s %-10s %-14s %-12s %s\n"
            % (
                row.get("timestamp") or "-",
                row.get("principal") or row.get("principal_name") or "-",
                row.get("endpoint") or "-",
                v24.CAP_TO_PERMISSION.get(str(cap), str(cap)),
                row.get("result") or row.get("decision") or "-",
            )
        )
    return 0


def handle_set(plane: ControlPlane, rest: list[str]) -> Optional[int]:
    if not rest:
        return None
    res = rest[0]
    if _legacy_backend_resource(res):
        return None
    # Policy enable/disable without rule name
    if res in ("remote-access", "internet-access", "ai-access") and len(rest) == 2 and rest[1] in ("enabled", "disabled"):
        _require_server(plane, _policy_resource_label(res))
        from drlink_control_cli import _run

        _run(v24.set_policy_enforcement, plane, res, rest[1] == "enabled")
        title = res.replace("-", " ").title()
        pol = v24.get_access_policy(plane, res)
        sys.stdout.write(
            "%s\n%s\n\nMode        : %s\nEnforcement : %s\nEffective   : ALLOW ALL\n\nSaved rules remain unchanged.\n"
            % (
                title,
                "=" * len(title),
                (pol["mode"] or "-").upper(),
                str(pol["enforcement"]).upper(),
            )
            if rest[1] == "disabled" and str(pol["enforcement"]).lower() == "disabled"
            else "%s enforcement enabled.\n" % title
            if rest[1] == "enabled"
            else "Cancelled.\nNo changes were applied.\n"
        )
        return 0
    if res == "network-object":
        _require_server(plane, "Network Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set network-object <NAME> ...")
        name = rest[1]
        if len(rest) == 2:
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "network-object", name)
        kv = v24.parse_kv_tokens(rest[2:])
        result = v24.set_network_object(
            plane, name, type=kv.get("type"), value=kv.get("value"), oneshot=True
        )
        sys.stdout.write("Network Object %s: %s\n" % (result["operation"], name))
        return 0
    if res == "network-group":
        _require_server(plane, "Network Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set network-group <NAME> ...")
        name = rest[1]
        kv = v24.parse_kv_tokens(rest[2:]) if len(rest) > 2 else {}
        if "members" not in kv:
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "network-group", name)
        v24.set_network_group(plane, name, members=v24.parse_csv_list(kv["members"]), oneshot=True)
        sys.stdout.write("Network Group set: %s\n" % name)
        return 0
    if res == "service-object":
        _require_server(plane, "Service Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set service-object <NAME> ...")
        name = rest[1]
        if len(rest) == 2:
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "service-object", name)
        kv = v24.parse_kv_tokens(rest[2:])
        port = int(kv["port"]) if "port" in kv else None
        v24.set_service_object(plane, name, type=kv.get("type"), port=port, oneshot=True)
        sys.stdout.write("Service Object set: %s\n" % name)
        return 0
    if res == "service-group":
        _require_server(plane, "Service Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set service-group <NAME> ...")
        name = rest[1]
        kv = v24.parse_kv_tokens(rest[2:]) if len(rest) > 2 else {}
        if "members" not in kv:
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "service-group", name)
        v24.set_service_group(plane, name, members=v24.parse_csv_list(kv.get("members", "")), oneshot=True)
        sys.stdout.write("Service Group set: %s\n" % name)
        return 0
    if res == "permission-object":
        _require_server(plane, "Permission Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set permission-object <NAME> ...")
        name = rest[1]
        kv = v24.parse_kv_tokens(rest[2:]) if len(rest) > 2 else {}
        if "permissions" not in kv:
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "permission-object", name)
        v24.set_permission_object(
            plane, name, permissions=v24.parse_csv_list(kv.get("permissions", "")), oneshot=True
        )
        sys.stdout.write("Permission Object set: %s\n" % name)
        return 0
    if res == "permission-group":
        _require_server(plane, "Permission Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set permission-group <NAME> ...")
        name = rest[1]
        kv = v24.parse_kv_tokens(rest[2:]) if len(rest) > 2 else {}
        if "members" not in kv:
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "permission-group", name)
        v24.set_permission_group(plane, name, members=v24.parse_csv_list(kv.get("members", "")), oneshot=True)
        sys.stdout.write("Permission Group set: %s\n" % name)
        return 0
    if res in ("remote-access", "internet-access"):
        _require_server(plane, _policy_resource_label(res))
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set %s <RULE> ..." % res)
        name = rest[1]
        extra = rest[2:]
        if not extra:
            if not _guided_create_available():
                return None
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, res, name)
        kv = v24.parse_kv_tokens(extra)
        allowed = {"mode", "source", "destination", "service", "enabled"}
        unknown = [k for k in kv if k not in allowed]
        if unknown:
            title = "Remote Access" if res == "remote-access" else "Internet Access"
            raise ControlPlaneError(
                "ERROR:\n%s does not accept '%s'.\n\n"
                "Use: source, destination, service, mode, enabled|disabled\n\n"
                "No changes were applied."
                % (title, unknown[0])
            )
        enabled = None
        if "enabled" in kv:
            enabled = str(kv["enabled"]).lower() in ("yes", "true", "1", "enabled")
        v24.set_access_rule(
            plane,
            res,
            name,
            mode=kv.get("mode"),
            source=kv.get("source"),
            destination=kv.get("destination"),
            service=kv.get("service"),
            enabled=enabled,
            oneshot=True,
        )
        sys.stdout.write("%s rule set: %s\n" % (res, name))
        return 0
    if res == "ai-access":
        _require_server(plane, "AI Access policy")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set ai-access <RULE> ...")
        name = rest[1]
        extra = rest[2:]
        if not extra:
            if not _guided_create_available():
                return None
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "ai-access", name)
        extra_l = [str(t).strip().lower() for t in extra]
        if "mode" not in extra_l and "permission" not in extra_l:
            if len(extra) == 1 and extra_l[0] in ("enabled", "disabled"):
                existing = plane.conn.execute(
                    "SELECT id FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (name,)
                ).fetchone()
                if existing:
                    raise ControlPlaneError(
                        "ERROR:\nAI Access does not support partial enable/disable via:\n"
                        "  set ai-access <RULE> enabled|disabled\n\n"
                        "Re-set the Rule with source, destination, permission, and enabled|disabled,\n"
                        "or apply a ConfigurationBundle.\n\n"
                        "No changes were applied."
                    )
            return None
        kv = v24.parse_kv_tokens(extra)
        enabled = None
        if "enabled" in kv:
            enabled = str(kv["enabled"]).lower() in ("yes", "true", "1", "enabled")
        v24.set_ai_access_rule(
            plane,
            name,
            mode=kv.get("mode"),
            source=kv.get("source"),
            destination=kv.get("destination"),
            permission=kv.get("permission"),
            enabled=enabled,
            oneshot=True,
        )
        sys.stdout.write("AI Access rule set: %s\n" % name)
        return 0
    if res == "ai-identity":
        _require_server(plane, "AI Identities")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set ai-identity <NAME>")
        name = rest[1]
        from drlink_v24_wizard import run_wizard

        return run_wizard(plane, "ai-identity", name)
    if res == "remote-service":
        _require_agent(plane)
        if len(rest) < 2:
            raise ControlPlaneError("Usage: set remote-service <NAME> ...")
        name = rest[1]
        kv = v24.parse_kv_tokens(rest[2:]) if len(rest) > 2 else {}
        enabled = None
        if "enabled" in kv:
            enabled = str(kv["enabled"]).lower() in ("yes", "true", "1", "enabled")
        if not rest[2:]:
            from drlink_v24_wizard import run_wizard

            return run_wizard(plane, "remote-service", name)
        reachable = v24.detect_server_reachable(plane, plane.root)
        result = v24.set_remote_service_agent(
            plane,
            name,
            destination=kv.get("destination"),
            service=kv.get("service"),
            enabled=enabled,
            oneshot=True,
            root=plane.root,
            server_reachable=reachable,
        )
        sys.stdout.write(v24.format_remote_service_view(result.get("view") or {"name": name, "destination": "-", "service": "-", "status": "HEALTHY", "endpoint": "-"}))
        return 0
    return None


def handle_unset(plane: ControlPlane, rest: list[str]) -> Optional[int]:
    if not rest:
        return None
    res = rest[0]
    if _legacy_backend_resource(res):
        return None
    if res in ("remote-access", "internet-access", "ai-access") and len(rest) >= 2 and rest[1] == "policy":
        _require_server(plane, _policy_resource_label(res))
        from drlink_control_cli import _run

        result = _run(v24.reset_access_policy, plane, res)
        if isinstance(result, dict) and result.get("cancelled"):
            return 0
        sys.stdout.write("%s policy reset.\nEffective access: ALLOW\n" % res)
        return 0
    if res == "network-object":
        _require_server(plane, "Network Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset network-object <NAME>")
        v24.unset_network_object(plane, rest[1])
        sys.stdout.write("Network Object deleted: %s\n" % rest[1])
        return 0
    if res == "network-group":
        _require_server(plane, "Network Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset network-group <NAME>")
        plane.unset_object_group(rest[1])
        sys.stdout.write("Network Group deleted: %s\n" % rest[1])
        return 0
    if res == "service-object":
        _require_server(plane, "Service Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset service-object <NAME>")
        v24.unset_service_object(plane, rest[1])
        sys.stdout.write("Service Object deleted: %s\n" % rest[1])
        return 0
    if res == "service-group":
        _require_server(plane, "Service Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset service-group <NAME>")
        g = v24.get_service_group(plane, rest[1])
        if not g:
            raise ControlPlaneError(v24.cli_error("Service Group '%s' was not found." % rest[1]))

        def write():
            plane.conn.execute("DELETE FROM service_group_members WHERE group_id = ?", (g["id"],))
            plane.conn.execute("DELETE FROM service_groups WHERE id = ?", (g["id"],))
            return {"entity": {"type": "service-group", "id": g["id"], "name": rest[1]}, "operation": "delete"}

        plane._mutate("unset service-group %s" % rest[1], "delete service group", write)
        sys.stdout.write("Service Group deleted: %s\n" % rest[1])
        return 0
    if res == "permission-object":
        _require_server(plane, "Permission Objects")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset permission-object <NAME>")
        p = v24.get_permission_object(plane, rest[1])
        if not p:
            raise ControlPlaneError(v24.cli_error("Permission Object '%s' was not found." % rest[1]))

        def write():
            plane.conn.execute("DELETE FROM permission_object_members WHERE permission_object_id = ?", (p["id"],))
            plane.conn.execute("DELETE FROM permission_objects WHERE id = ?", (p["id"],))
            return {"entity": {"type": "permission-object", "id": p["id"], "name": rest[1]}, "operation": "delete"}

        plane._mutate("unset permission-object %s" % rest[1], "delete permission object", write)
        sys.stdout.write("Permission Object deleted: %s\n" % rest[1])
        return 0
    if res == "permission-group":
        _require_server(plane, "Permission Groups")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset permission-group <NAME>")
        g = v24.get_permission_group(plane, rest[1])
        if not g:
            raise ControlPlaneError(v24.cli_error("Permission Group '%s' was not found." % rest[1]))

        def write():
            plane.conn.execute("DELETE FROM permission_group_members WHERE group_id = ?", (g["id"],))
            plane.conn.execute("DELETE FROM permission_groups WHERE id = ?", (g["id"],))
            return {"entity": {"type": "permission-group", "id": g["id"], "name": rest[1]}, "operation": "delete"}

        plane._mutate("unset permission-group %s" % rest[1], "delete permission group", write)
        sys.stdout.write("Permission Group deleted: %s\n" % rest[1])
        return 0
    if res in ("remote-access", "internet-access"):
        _require_server(plane, _policy_resource_label(res))
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset %s <RULE>|policy" % res)
        if len(rest) >= 3:
            return None
        v24.unset_access_rule(plane, res, rest[1])
        sys.stdout.write("Rule deleted: %s\n" % rest[1])
        return 0
    if res == "ai-access":
        _require_server(plane, "AI Access policy")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset ai-access <RULE>|policy")
        if len(rest) >= 3:
            return None
        row = plane.conn.execute(
            "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (rest[1],)
        ).fetchone()
        if not row:
            cap = plane.conn.execute(
                "SELECT id FROM ai_access_rules WHERE name = ? COLLATE NOCASE", (rest[1],)
            ).fetchone()
            if cap is not None:
                return None
            raise ControlPlaneError(v24.cli_error("Rule '%s' was not found." % rest[1]))

        def write():
            plane.conn.execute("DELETE FROM ai_policy_rules WHERE id = ?", (row["id"],))
            return {"entity": {"type": "ai-access", "id": row["id"], "name": rest[1]}, "operation": "delete"}

        plane._mutate("unset ai-access %s" % rest[1], "delete ai access rule", write)
        sys.stdout.write("AI Access rule deleted: %s\n" % rest[1])
        return 0
    if res == "ai-identity":
        _require_server(plane, "AI Identities")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset ai-identity <NAME>")
        # Reference-safe via existing unset_ai_principal
        plane.unset_ai_principal(rest[1])
        sys.stdout.write("AI Identity deleted: %s\n" % rest[1])
        return 0
    if res == "managed-host":
        _require_server(plane, "Managed Hosts")
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset managed-host <HOST>")
        # Reuse client revoke/delete path if present
        client = plane.require_client(rest[1])
        # Check policy references via managed endpoint object
        ep = plane.conn.execute(
            "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
            (client["id"],),
        ).fetchone()
        if ep:
            refs = plane.object_references(ep["name"])
            if refs:
                raise ControlPlaneError(
                    "ERROR:\nManaged Host '%s' is still referenced.\n\nReferences:\n%s\n\nNo changes were applied."
                    % (rest[1], "\n".join("  %s" % r["display"] for r in refs))
                )
        # Reference-safe cleanup is required; full client lifecycle delete is server inventory work.
        raise ControlPlaneError(
            "ERROR:\nManaged Host removal must use the Managed Host lifecycle path with impact review.\n\n"
            "Host: %s\n\nNo changes were applied." % rest[1]
        )
    if res == "remote-service":
        _require_agent(plane)
        if len(rest) < 2:
            raise ControlPlaneError("Usage: unset remote-service <NAME>")
        reachable = v24.detect_server_reachable(plane, plane.root)
        v24.unset_remote_service_agent(
            plane, rest[1], root=plane.root, server_reachable=reachable
        )
        sys.stdout.write(
            "Remote Service deleted: %s\n" % rest[1]
            if reachable
            else "Remote Service local configuration deleted: %s\nDeletion will synchronize when the Server is reachable.\n"
            % rest[1]
        )
        return 0
    return None


def handle_test(plane: ControlPlane, rest: list[str]) -> Optional[int]:
    if not rest:
        return None
    res = rest[0]
    extra = rest[1:]
    if extra and not _v24_named_kv(extra):
        return None
    if res == "remote-access":
        _require_server(plane, "Remote Access policy")
        kv = v24.parse_kv_tokens(rest[1:])
        for req in ("source", "destination", "service"):
            if req not in kv:
                raise ControlPlaneError(
                    "Usage: test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>"
                )
        evaluation = v24.evaluate_selector_policy(
            plane,
            "remote",
            source_name=kv["source"],
            destination_name=kv["destination"],
            service_name=kv["service"],
        )
        sys.stdout.write(
            v24.format_policy_test(
                "remote",
                evaluation,
                {"source": kv["source"], "destination": kv["destination"], "service": kv["service"]},
            )
        )
        return 0
    if res == "internet-access":
        _require_server(plane, "Internet Access policy")
        kv = v24.parse_kv_tokens(rest[1:])
        for req in ("source", "destination", "service"):
            if req not in kv:
                raise ControlPlaneError(
                    "Usage: test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>"
                )
        evaluation = v24.evaluate_selector_policy(
            plane,
            "internet",
            source_name=kv["source"],
            destination_name=kv["destination"],
            service_name=kv["service"],
        )
        sys.stdout.write(
            v24.format_policy_test(
                "internet",
                evaluation,
                {"source": kv["source"], "destination": kv["destination"], "service": kv["service"]},
            )
        )
        return 0
    if res == "ai-access":
        _require_server(plane, "AI Access policy")
        kv = v24.parse_kv_tokens(rest[1:])
        for req in ("source", "destination", "permission"):
            if req not in kv:
                raise ControlPlaneError(
                    "Usage: test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>"
                )
        evaluation = v24.evaluate_ai_access_v24(
            plane, identity=kv["source"], destination=kv["destination"], permission=kv["permission"]
        )
        sys.stdout.write(
            v24.format_policy_test(
                "ai",
                evaluation,
                {
                    "source": kv["source"],
                    "destination": kv["destination"],
                    "permission": kv["permission"],
                },
            )
        )
        return 0
    return None
