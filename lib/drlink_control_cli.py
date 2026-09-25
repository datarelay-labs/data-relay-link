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
    MCP_AUTH_MODEL,
)
from drlink_configuration_bundle import (
    BundleError,
    apply_change_plan,
    export_configuration,
    format_plan_review,
    prepare_plan,
    read_bundle_from_path_or_stdin,
)
import drlink_mcp_tls as mcp_tls
from drlink_mcp_tls import McpTlsError

USAGE_HINT = "No changes were applied."


def _looks_like_v24_bundle(raw: str) -> bool:
    text = str(raw or "")
    stripped = text.lstrip()
    return stripped.startswith("configurationBundle:") or "configurationBundle:" in text[:400]


def _looks_like_legacy_bundle(raw: str) -> bool:
    head = str(raw or "")[:800]
    return "kind: ConfigurationBundle" in head or 'kind: "ConfigurationBundle"' in head or "kind: 'ConfigurationBundle'" in head


def _exit_bundle_error(exc: BaseException) -> None:
    msg = str(exc).rstrip()
    if USAGE_HINT not in msg:
        msg = "ERROR:\n%s\n\n%s" % (msg, USAGE_HINT)
    raise SystemExit(msg) from exc


def _prepare_public_bundle(plane: ControlPlane, raw: str):
    """Public CLI always prefers the canonical v2.4 bundle parser.

    Legacy apiVersion/kind documents remain accepted only when that schema is
    explicit, so existing transition tests keep working. Garbage / prose / invalid
    YAML is routed through the v2.4 parser so operators always see
    'No changes were applied.'
    """
    if _looks_like_v24_bundle(raw) or not _looks_like_legacy_bundle(raw):
        from drlink_v24_bundle import prepare_v24_plan

        return "v24", prepare_v24_plan(plane, raw)
    return "legacy", prepare_plan(plane, raw, input_path="cli", run_tests=True)


def _parse_output_flag(tokens):
    """Parse [--output PATH] from trailing tokens; return (path_or_none, remaining)."""
    out = None
    remaining = []
    i = 0
    while i < len(tokens):
        if tokens[i] in ("--output", "-o") and i + 1 < len(tokens):
            out = tokens[i + 1]
            i += 2
            continue
        remaining.append(tokens[i])
        i += 1
    return out, remaining


def _configuration_export(plane: ControlPlane, rest):
    out_path, remaining = _parse_output_flag(rest)
    # Canonical master form: system export configuration <FILE>
    if not out_path and remaining and len(remaining) == 1 and remaining[0] not in ("-",):
        out_path = remaining[0]
        remaining = []
    if remaining:
        raise SystemExit(
            "Unexpected arguments.\n\nUsage:\n  system export configuration <file>\n  system export configuration --output <file>"
        )
    if not out_path:
        raise SystemExit(
            "Missing output path.\n\nUsage:\n  system export configuration <file>\n  system export configuration --output <file>"
        )
    # Prefer canonical v2.4 export when available.
    try:
        from drlink_v24_bundle import export_configuration_v24

        text = export_configuration_v24(plane)
    except Exception:
        text = export_configuration(plane)
    Path = __import__("pathlib").Path
    Path(out_path).write_text(text, encoding="utf-8")
    sys.stdout.write("Configuration exported (redacted): %s\n" % out_path)
    return 0


def _configuration_test(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing configuration path.\n\nUsage:\n  test configuration <file|->")
    raw, label = _read_config_input(rest[0])
    try:
        kind, plan = _prepare_public_bundle(plane, raw)
    except Exception as exc:
        _exit_bundle_error(exc)
    if kind == "v24":
        from drlink_v24_bundle import format_v24_plan

        sys.stdout.write(format_v24_plan(plan))
        return 0
    sys.stdout.write(format_plan_review(plan))
    sys.stdout.write("Configuration test: PASS\n")
    return 0


def _configuration_diff(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing configuration path.\n\nUsage:\n  system diff configuration <file|->")
    raw, label = _read_config_input(rest[0])
    try:
        kind, plan = _prepare_public_bundle(plane, raw)
    except Exception as exc:
        _exit_bundle_error(exc)
    if kind == "v24":
        from drlink_v24_bundle import format_v24_plan

        sys.stdout.write(format_v24_plan(plan))
        if plan.no_change:
            sys.stdout.write("Diff result: NO CHANGE\n")
        else:
            sys.stdout.write("Diff result: CHANGES PENDING (no mutation performed)\n")
        return 0
    sys.stdout.write(format_plan_review(plan))
    if not plan.mutating_changes and not plan.client_action_required:
        sys.stdout.write("Diff result: NO CHANGE\n")
    else:
        sys.stdout.write("Diff result: CHANGES PENDING (no mutation performed)\n")
    return 0


def _configuration_apply(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing configuration path.\n\nUsage:\n  system apply configuration <file|->")
    raw, label = _read_config_input(rest[0])
    try:
        kind, plan = _prepare_public_bundle(plane, raw)
    except Exception as exc:
        _exit_bundle_error(exc)
    if kind == "v24":
        from drlink_v24_bundle import apply_v24_plan, format_v24_plan

        sys.stdout.write(format_v24_plan(plan).replace("No changes were applied.\n", ""))
        result = _run(apply_v24_plan, plane, plan)
        if isinstance(result, dict) and result.get("cancelled"):
            return 0
        if isinstance(result, dict) and result.get("status") == "NO_CHANGE":
            sys.stdout.write("NO CHANGE\nConfiguration already matches the requested state.\n")
            return 0
        sys.stdout.write("Apply result: APPLIED\n")
        if isinstance(result, dict):
            sys.stdout.write("Revision: %s\n" % result.get("revision"))
        return 0
    try:
        plan = prepare_plan(plane, raw, input_path=label, run_tests=True)
    except BundleError as exc:
        _exit_bundle_error(exc)
    sys.stdout.write(format_plan_review(plan))
    result = _run(apply_change_plan, plane, plan)
    if isinstance(result, dict) and result.get("cancelled"):
        return 0
    if not isinstance(result, dict):
        return 0
    status = result.get("status")
    if status == "NO_CHANGE":
        sys.stdout.write("Apply result: NO CHANGE\n")
        sys.stdout.write("Revision: %s\n" % result.get("revision"))
    elif status == "CLIENT_ACTION_REQUIRED":
        sys.stdout.write("Apply result: CLIENT_ACTION_REQUIRED\n")
        sys.stdout.write("Server mutations: none for client-local targets.\n")
    else:
        sys.stdout.write("Apply result: APPLIED\n")
        sys.stdout.write("Revision: %s\n" % result.get("revision"))
        sys.stdout.write("Zero-Touch tickets issued: %s\n" % result.get("tickets_issued", 0))
        if result.get("client_action_required"):
            sys.stdout.write("CLIENT_ACTION_REQUIRED: yes (see planned changes)\n")
    return 0


def _read_config_input(source: str):
    if source == "-":
        from drlink_v24_bundle import read_bundle_stdin_with_end

        return read_bundle_stdin_with_end(), "stdin"
    return read_bundle_from_path_or_stdin(source)


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


def _server_dr_tool_candidates(name: str, here):
    """Source-tree tools/ plus the installed /usr/local/lib/drlink layout."""
    from pathlib import Path

    here = Path(here)
    return (
        here.parent.parent / "tools" / name,
        here.parent / name,
        Path("/usr/local/lib/drlink") / name,
        Path("/usr/local/sbin") / name,
    )


def _server_dr_tool_path(name: str):
    from pathlib import Path

    here = Path(__file__).resolve()
    for path in _server_dr_tool_candidates(name, here):
        if path.is_file():
            return path
    raise SystemExit("ERROR: %s is not installed." % name)


def _server_dr_backup(path: str = "") -> int:
    """Public system backup → unified Server DR archive (frp-backup)."""
    import subprocess

    cmd = [sys.executable, str(_server_dr_tool_path("frp-backup"))]
    if path:
        cmd.append(path)
    return int(subprocess.run(cmd, check=False).returncode or 0)


def _server_dr_validate(path: str) -> int:
    """Public system backup validate → same DR archive contract as restore."""
    import subprocess

    return int(
        subprocess.run(
            [sys.executable, str(_server_dr_tool_path("frp-restore")), "--validate", path],
            check=False,
        ).returncode
        or 0
    )


def _server_dr_restore(path: str, *extra: str) -> int:
    """Public system restore → unified Server DR archive (frp-restore)."""
    import subprocess

    cmd = [sys.executable, str(_server_dr_tool_path("frp-restore")), path]
    # Preserve automation confirm flags for the authoritative restore gate.
    for token in extra:
        if token in ("--yes", "-Yes") and "--yes" not in cmd:
            cmd.insert(-1, "--yes")
    if _confirm_requested_env() and "--yes" not in cmd:
        cmd.insert(-1, "--yes")
    return int(subprocess.run(cmd, check=False).returncode or 0)


def _confirm_requested_env() -> bool:
    env = str(os.environ.get("DRLINK_CONFIRM") or "").strip().lower()
    if env in ("yes", "y", "1", "true"):
        return True
    return str(os.environ.get("FRP_RESTORE_YES") or "").strip() == "1"


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
    except (ConcurrencyError, ControlPlaneError):
        # Let dispatch() map these to stderr + rc=1. Converting to SystemExit
        # here bypasses that handler and breaks in-process CLI tests.
        raise


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
    except KeyboardInterrupt:
        sys.stdout.write("No changes were applied.\n")
        return 0
    except EOFError:
        sys.stdout.write("No changes were applied.\n")
        return 0
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
    import drlink_v24_cli as v24cli

    handled = v24cli.handle_show(plane, rest)
    if handled is not None:
        return handled
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
            "Auth Model          : %s\n"
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
                MCP_AUTH_MODEL,
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
    if res == "mcp-tls":
        view = mcp_tls.status_view(plane, plane.root)
        sys.stdout.write(mcp_tls.format_status(view))
        return 0
    raise SystemExit("Unknown show resource.")


def _set(plane: ControlPlane, rest, client_sel):
    if not rest:
        raise SystemExit("Missing resource.")
    import drlink_v24_cli as v24cli

    handled = v24cli.handle_set(plane, rest)
    if handled is not None:
        return handled
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
            _need(rest, 4, "set object-group <GROUP> member <OBJECT>")
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
            _need(rest, 4, "set client-group <GROUP> member <CLIENT|ENDPOINT>")
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
            _need(rest, 4, "set %s <RULE> source <OBJECT|GROUP>" % res)
            _run(plane.set_rule_source, plane_name, name, rest[3])
            return 0
        if prop == "destination":
            _need(rest, 4, "set %s <RULE> destination <OBJECT|GROUP|SERVICE>" % res)
            _run(plane.set_rule_destination, plane_name, name, rest[3])
            return 0
        if prop == "service":
            _need(rest, 4, "set %s <RULE> service <PROTOCOL> [PORT]" % res)
            proto = rest[3]
            port = rest[4] if len(rest) > 4 else (443 if proto in ("https",) else 80)
            # internet grammar: service https 443  OR service <PROTOCOL> <PORT>
            if proto.isdigit():
                port, proto = proto, rest[4] if len(rest) > 4 else "tcp"
            _run(plane.set_rule_service, plane_name, name, proto, int(port))
            return 0
        if prop == "action":
            _need(rest, 4, "set %s <RULE> action allow|deny" % res)
            _run(plane.set_rule_action, plane_name, name, rest[3])
            return 0
        if prop == "description":
            _run(plane.set_rule_description, plane_name, name, " ".join(rest[3:]))
            return 0
        if prop == "enabled":
            _run(plane.set_rule_enabled, plane_name, name, True)
            return 0
        if prop == "before":
            _need(rest, 4, "set %s <RULE> before <RULE>" % res)
            _run(plane.move_rule, plane_name, name, before=rest[3])
            return 0
        if prop == "after":
            _need(rest, 4, "set %s <RULE> after <RULE>" % res)
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
    if res == "mcp-tls":
        return _set_mcp_tls(plane, rest[1:])
    raise SystemExit("Unknown set resource.")


def _set_mcp_tls(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit(
            "Missing mcp-tls setting.\n\n"
            "Usage:\n"
            "  set mcp-tls hostname <fqdn>\n"
            "  set mcp-tls mode auto-acme|user-certificate|private-ca\n"
            "  set mcp-tls contact-email <email>\n"
            "  set mcp-tls acme-environment staging|production\n\n"
            "Default public-cloud mode is AUTO_ACME.\n"
            "PRIVATE_CA is for internal/test clients that trust the DRLink CA;\n"
            "it is not the default ChatGPT/Claude cloud connector path.\n"
            "After configure: system certificate issue|import|renew"
        )
    prop = rest[0]
    try:
        if prop == "hostname":
            _need(rest, 2, "set mcp-tls hostname <fqdn>")
            state = mcp_tls.configure_intent(plane, hostname=rest[1])
        elif prop == "mode":
            _need(rest, 2, "set mcp-tls mode auto-acme|user-certificate|private-ca")
            state = mcp_tls.configure_intent(plane, mode=rest[1])
            if state.get("mode") == mcp_tls.MODE_PRIVATE_CA:
                sys.stdout.write(
                    "Warning: PRIVATE_CA certificates are signed by the Data Relay Link private CA.\n"
                    "Cloud-hosted Remote MCP clients that do not trust this CA may reject it.\n"
                )
        elif prop in ("contact-email", "email"):
            _need(rest, 2, "set mcp-tls contact-email <email>")
            state = mcp_tls.configure_intent(plane, contact_email=rest[1])
        elif prop in ("acme-environment", "acme-env"):
            _need(rest, 2, "set mcp-tls acme-environment staging|production")
            state = mcp_tls.configure_intent(plane, acme_environment=rest[1])
        elif prop in ("acme-directory", "acme-directory-url"):
            _need(rest, 2, "set mcp-tls acme-directory <url>")
            state = mcp_tls.configure_intent(plane, acme_directory_url=rest[1])
        else:
            raise SystemExit("Unknown mcp-tls setting: %s" % prop)
    except McpTlsError as exc:
        raise SystemExit(str(exc)) from exc
    sys.stdout.write("MCP TLS intent updated.\n")
    sys.stdout.write("Mode: %s\n" % (state.get("mode") or "(unset)"))
    sys.stdout.write("Hostname: %s\n" % (state.get("hostname") or "(unset)"))
    if state.get("mode") == mcp_tls.MODE_AUTO_ACME:
        sys.stdout.write("Next: system certificate issue\n")
    elif state.get("mode") == mcp_tls.MODE_USER_CERTIFICATE:
        sys.stdout.write("Next: system certificate import <CERT> <KEY> [CHAIN]\n")
    elif state.get("mode") == mcp_tls.MODE_PRIVATE_CA:
        sys.stdout.write("Next: system certificate issue\n")
    return 0


def _unset(plane: ControlPlane, rest, client_sel):
    if not rest:
        raise SystemExit("Missing resource.")
    import drlink_v24_cli as v24cli

    handled = v24cli.handle_unset(plane, rest)
    if handled is not None:
        return handled
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
    if res == "mcp-tls":
        purge = len(rest) > 1 and rest[1] in ("purge", "--purge")
        mcp_tls.clear_tls(plane, plane.root, purge_secrets=purge)
        sys.stdout.write("MCP TLS configuration cleared.\n")
        if purge:
            sys.stdout.write("DRLink-owned certificate and ACME account material removed.\n")
        else:
            sys.stdout.write("Certificate files retained (use unset mcp-tls purge to remove secrets).\n")
        return 0
    raise SystemExit("Unknown unset resource.")


def _test(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing test target.")
    import drlink_v24_cli as v24cli

    if rest[0] == "configuration":
        return _configuration_test(plane, rest[1:])
    handled = v24cli.handle_test(plane, rest)
    if handled is not None:
        return handled
    if rest[0] == "remote-access":
        _need(rest, 5, "test remote-access <SOURCE_IP> <DESTINATION> <PROTOCOL> <PORT>")
        result = plane.evaluate_remote_access(rest[1], rest[2], rest[3], int(rest[4]))
        sys.stdout.write(plane.format_remote_explain(result))
        return 0
    if rest[0] == "internet-access":
        _need(rest, 5, "test internet-access <SOURCE_IP> <DESTINATION> <PORT> <PROTOCOL>")
        result = plane.evaluate_internet_access(rest[1], rest[2], int(rest[3]), rest[4])
        sys.stdout.write(
            plane.format_internet_explain(
                result,
                dns={
                    "status": "not executed (explain only)",
                    "security": "server-side DNS required at runtime",
                },
            )
        )
        return 0
    if rest[0] == "ai-access":
        _need(rest, 4, "test ai-access <PRINCIPAL> <ENDPOINT> <CAPABILITY> [OPERAND]")
        operand = rest[4] if len(rest) > 4 else None
        result = plane.evaluate_ai_access(rest[1], rest[2], rest[3], operand)
        sys.stdout.write(plane.format_ai_explain(result))
        return 0
    raise SystemExit(
        "Unknown test target.\n\n"
        "Usage:\n"
        "  test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>\n"
        "  test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>\n"
        "  test ai-access source <IDENTITY> destination <DESTINATION> permission <PERMISSION>\n"
        "  test configuration <FILE|->\n"
    )

def _system(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit("Missing system operation.")
    if rest[0] == "export" and len(rest) >= 2 and rest[1] == "configuration":
        return _configuration_export(plane, rest[2:])
    if rest[0] == "diff" and len(rest) >= 2 and rest[1] == "configuration":
        return _configuration_diff(plane, rest[2:])
    if rest[0] == "apply" and len(rest) >= 2 and rest[1] == "configuration":
        return _configuration_apply(plane, rest[2:])
    if rest[0] == "synchronize":
        import drlink_v24 as v24

        if v24.detect_cli_role(plane.root) != "agent":
            raise SystemExit(
                "ERROR:\nsystem synchronize is an Agent Host operation.\n\nNo changes were applied."
            )
        result = v24.synchronize_agent_remote_services(plane, root=plane.root)
        sys.stdout.write(v24.format_synchronize_result(result))
        status = str(result.get("status") or "").upper()
        if status in ("DEGRADED", "OFFLINE"):
            return 1
        return 0
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
            if len(rest) < 3:
                raise SystemExit("Usage: system backup validate <PATH>")
            return _server_dr_validate(rest[2])
        path = rest[1] if len(rest) > 1 else ""
        return _server_dr_backup(path)
    if rest[0] == "restore":
        if len(rest) < 2:
            raise SystemExit("Usage: system restore <PATH>")
        path = rest[1]
        extra = [t for t in rest[2:] if t]
        return _server_dr_restore(path, *extra)
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
        if len(rest) >= 3 and rest[1] in ("ai-principal", "ai-identity"):
            kwargs["principal"] = rest[2]
        rows = plane.list_audit(**kwargs)
        for row in rows:
            sys.stdout.write("%s rev=%s %s %s %s %s\n" % (row["timestamp"], row["revision"], row["action"], row["entity_type"], row["entity_id"], row["result"]))
        return 0
    if rest[0] == "revoke" and len(rest) >= 3 and rest[1] == "client":
        _run(plane.remove_client, rest[2], revoke_only=True)
        return 0
    if rest[0] == "credential":
        if len(rest) < 2:
            raise SystemExit(
                "usage: system credential rotate|revoke|configure|approve-oauth|deny-oauth ..."
            )
        if rest[1] == "approve-oauth":
            # system credential approve-oauth <PENDING-ID> [AI-IDENTITY]
            # or system credential approve-oauth ai-identity|ai-principal <PENDING-ID> [AI-IDENTITY]
            args = rest[2:]
            if args and args[0] in ("ai-principal", "ai-identity"):
                args = args[1:]
            if not args:
                raise SystemExit(
                    "usage: system credential approve-oauth <PENDING-ID> [AI-IDENTITY]\n"
                    "DCR/CIMD requests require AI-IDENTITY."
                )
            if len(args) > 2:
                raise SystemExit(
                    "unexpected argument: %s\n"
                    "usage: system credential approve-oauth <PENDING-ID> [AI-IDENTITY]" % args[2]
                )
            pending_id = args[0]
            principal = args[1] if len(args) > 1 else None
            _run(plane.approve_oauth_pending, pending_id, principal)
            sys.stdout.write(
                "Authorization approved. The browser continues via /oauth/continue to the registered redirect.\n"
            )
            sys.stdout.write(
                "The authorization code is delivered only through the one-time browser continuation redirect.\n"
            )
            return 0
        if rest[1] == "deny-oauth":
            args = rest[2:]
            if args and args[0] in ("ai-principal", "ai-identity"):
                args = args[1:]
            if not args:
                raise SystemExit("usage: system credential deny-oauth <PENDING-ID>")
            pending_id = args[0]
            _run(plane.deny_oauth_pending, pending_id)
            sys.stdout.write(
                "Authorization denied. The browser continues via /oauth/continue with access_denied.\n"
            )
            return 0
        if len(rest) < 4:
            raise SystemExit(
                "usage: system credential rotate|revoke|configure ai-identity <NAME> ..."
            )
        noun = rest[2]
        if noun not in ("ai-identity", "ai-principal"):
            raise SystemExit(
                "usage: system credential rotate|revoke|configure ai-identity <NAME> ..."
            )
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
                "usage: system credential configure ai-identity <NAME> authentication <static-bearer|oauth>\n"
                "       system credential configure ai-identity <NAME> oauth-redirect <URI>"
            )
        raise SystemExit("Unknown credential operation.")
    if rest[0] == "certificate":
        return _system_certificate(plane, rest[1:])
    raise SystemExit("Unknown system operation.")


def _system_certificate(plane: ControlPlane, rest):
    if not rest:
        raise SystemExit(
            "Missing certificate operation.\n\n"
            "Usage:\n"
            "  system certificate issue\n"
            "  system certificate import <CERT> <KEY> [CHAIN]\n"
            "  system certificate renew [--force]\n"
            "  system certificate status\n"
            "  system certificate preflight\n"
        )
    op = rest[0]
    root = plane.root
    try:
        if op == "status":
            view = mcp_tls.status_view(plane, root)
            sys.stdout.write(mcp_tls.format_status(view))
            return 0
        if op == "preflight":
            state = mcp_tls.load_state(plane)
            host = state.get("hostname") or ""
            if not host:
                raise SystemExit("Configure hostname first: set mcp-tls hostname <fqdn>")
            require_public = (state.get("mode") or mcp_tls.DEFAULT_PUBLIC_CLOUD_TLS_MODE) == mcp_tls.MODE_AUTO_ACME
            result = mcp_tls.preflight_hostname(host, require_public_dns=require_public)
            sys.stdout.write(json.dumps(result, indent=2) + "\n")
            return 0 if result.get("ok") else 1
        if op == "issue":
            # Directory override for tests / custom ACME.
            directory = None
            if "--directory" in rest:
                idx = rest.index("--directory")
                if idx + 1 >= len(rest):
                    raise SystemExit("Missing value for --directory")
                directory = rest[idx + 1]
            skip_reload = "--no-reload" in rest
            state = mcp_tls.issue_and_activate(
                plane,
                root,
                reload=not skip_reload,
                directory_url_override=directory,
            )
            sys.stdout.write("Certificate issued and activated.\n")
            sys.stdout.write(mcp_tls.format_status(mcp_tls.status_view(plane, root)))
            return 0
        if op == "import":
            cert = key = chain = None
            skip_reload = False
            positionals = []
            i = 1
            while i < len(rest):
                if rest[i] == "--cert" and i + 1 < len(rest):
                    cert = rest[i + 1]
                    i += 2
                elif rest[i] == "--key" and i + 1 < len(rest):
                    key = rest[i + 1]
                    i += 2
                elif rest[i] == "--chain" and i + 1 < len(rest):
                    chain = rest[i + 1]
                    i += 2
                elif rest[i] == "--no-reload":
                    skip_reload = True
                    i += 1
                elif str(rest[i]).startswith("-"):
                    raise SystemExit(
                        "Unknown input: %s\n\n"
                        "Data Relay Link commands do not use --options.\n\n"
                        "Run:\n"
                        "  system certificate import <CERT> <KEY> [CHAIN]\n"
                        % rest[i]
                    )
                else:
                    positionals.append(rest[i])
                    i += 1
            if not cert and len(positionals) >= 1:
                cert = positionals[0]
            if not key and len(positionals) >= 2:
                key = positionals[1]
            if not chain and len(positionals) >= 3:
                chain = positionals[2]
            if not cert or not key:
                raise SystemExit("usage: system certificate import <CERT> <KEY> [CHAIN]")
            mcp_tls.import_user_certificate(
                plane,
                root,
                cert_path=cert,
                key_path=key,
                chain_path=chain,
                reload="--no-reload" not in rest,
            )
            sys.stdout.write("Certificate imported and activated.\n")
            sys.stdout.write(mcp_tls.format_status(mcp_tls.status_view(plane, root)))
            return 0
        if op == "renew":
            force = "--force" in rest
            directory = None
            if "--directory" in rest:
                idx = rest.index("--directory")
                directory = rest[idx + 1]
            result = mcp_tls.renew_if_due(
                plane,
                root,
                force=force,
                reload="--no-reload" not in rest,
                directory_url_override=directory,
            )
            if result.get("renewed"):
                sys.stdout.write("Certificate renewed and activated.\n")
            else:
                sys.stdout.write("Renewal not applied (%s).\n" % result.get("reason"))
                if result.get("failure_class"):
                    sys.stdout.write("Failure class: %s\n" % result["failure_class"])
                    sys.stdout.write("Previous valid certificate retained.\n")
            sys.stdout.write(mcp_tls.format_status(mcp_tls.status_view(plane, root)))
            return 0 if result.get("renewed") or result.get("reason") in ("not_due", "backoff", "renewal_not_applicable", "renewal_disabled") else 1
        raise SystemExit("Unknown certificate operation: %s" % op)
    except McpTlsError as exc:
        raise SystemExit("%s (%s)" % (exc, exc.failure_class)) from exc


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
