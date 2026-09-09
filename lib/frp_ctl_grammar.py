#!/usr/bin/env python3
"""Safe frpctl tokenizer, command-tree help, and context-aware completion.

No eval, no glob, no variable expansion, no command substitution.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

UNQUOTED_META = set("$`;|&><*?(){}[]")
SERVICE_ADD_TYPES = ("ssh", "http", "https", "custom", "profile")
SERVICE_SET_PROPS = [
    "target-host",
    "target-port",
    "ssh-user",
    "name",
    "health-type",
    "health-timeout",
    "health-interval",
    "health-max-failed",
    "health-path",
]


def _load_service_add_concept_help():
    try:
        from frp_service_id import SERVICE_ADD_CONCEPT_HELP as text
        return text
    except ImportError:
        pass
    path = Path(__file__).resolve().parent / "frp_service_id.py"
    if path.is_file():
        spec = importlib.util.spec_from_file_location("_frp_service_id_help", str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, "SERVICE_ADD_CONCEPT_HELP", "")
    return ""


SERVICE_ADD_CONCEPT_HELP = _load_service_add_concept_help()
LEGACY_COMMANDS = {
    "clients",
    "client-info",
    "client-set",
    "edit-client",
    "enroll",
    "create-client",
    "enroll-bulk",
    "enrollments",
    "enrollment-revoke",
    "revoke-client",
    "release-service",
    "release-client",
    "project-update",
    "frp-update",
    "server-update",
    "client-update",
    "backup",
    "upstream",
    "audit",
    "services",
    "manage",
    "info",
    "client-status",
    "server-status",
}
# "system" is a client maintenance namespace; do not treat it as a shell escape.
SHELL_REJECT = {"shell", "exec", "bash", "sh"}


class ParseError(ValueError):
    pass


def tokenize(line):
    """Split an operator line into tokens. Quotes group; metacharacters do not expand."""
    tokens = []
    buf = []
    quote = None
    escaped = False
    i = 0
    text = line if line is not None else ""
    while i < len(text):
        ch = text[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue
        if quote:
            if ch == "\\" and quote == '"':
                escaped = True
                i += 1
                continue
            if ch == quote:
                quote = None
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if ch in " \t":
            if buf:
                tokens.append("".join(buf))
                buf = []
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        if ch == "\\":
            escaped = True
            i += 1
            continue
        if ch == "?" and not buf:
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if nxt in ("", " ", "\t"):
                tokens.append("?")
                i += 1
                continue
        if ch in UNQUOTED_META:
            raise ParseError(
                "shell metacharacters are not expanded. Quote the value or remove %r."
                % ch
            )
        buf.append(ch)
        i += 1
    if quote:
        raise ParseError("unclosed quote")
    if escaped:
        raise ParseError("trailing backslash")
    if buf:
        tokens.append("".join(buf))
    return tokens


def looks_secret(line):
    lowered = (line or "").lower()
    needles = (
        "ticket",
        "secret",
        "password",
        "passwd",
        "token",
        "private key",
        "enroll-secret",
        "bootstrap",
        "begin ",
    )
    return any(item in lowered for item in needles)


def quote_token(token):
    text = "" if token is None else str(token)
    if not text:
        return '""'
    if any(ch in text for ch in ' \t\'"'):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def _role_parts(role):
    role = (role or "").strip().lower()
    client = role in ("client", "both", "dual")
    server = role in ("server", "both", "dual")
    return client, server


def canonical_verbs(role):
    """Root Tab/help verbs. Legacy aliases still match() but are hidden here."""
    client, server = _role_parts(role)
    verbs = [
        "show",
        "help",
        "menu",
        "history",
        "clear",
        "exit",
    ]
    if server:
        # Server and dual keep status/version as primary discovery shortcuts.
        verbs.extend([
            "status", "version",
            "set", "unset", "create", "revoke", "purge", "release",
            "restore", "add", "remove", "delete", "rename", "access",
            "doctor", "support-bundle", "update",
        ])
    if client:
        verbs.extend(["service", "client", "system"])
        # Client-only: omit status/version from root Tab (use show …).
    if not client and not server:
        verbs.extend(["status", "version", "doctor", "support-bundle", "update"])
    return sorted(set(verbs))


def _show_resources(role):
    client, server = _role_parts(role)
    items = ["status", "version"]
    if server:
        items.extend(["clients", "client", "groups", "group", "profiles", "profile", "enrollments", "audit", "upstream"])
    if client:
        items.extend(["services", "info"])
    return items


def _set_resources(role):
    client, server = _role_parts(role)
    items = []
    if server:
        items.extend(["client", "group", "profile", "installer-url", "server"])
    if client:
        items.append("service")
    return items


def _unset_resources(role):
    _, server = _role_parts(role)
    items = []
    if server:
        items.extend(["client", "server"])
    return items


def _create_resources(role):
    _, server = _role_parts(role)
    if server:
        return ["zero-touch", "enrollment", "enrollments", "backup", "group", "profile"]
    return []


def incomplete(title, usage_lines, available=None, examples=None, tip=None):
    parts = [title]
    if available:
        parts.extend(["", "Available:"])
        for item in available:
            parts.append("  %s" % item)
    if usage_lines:
        parts.extend(["", "Usage:"])
        for line in usage_lines:
            parts.append("  %s" % line)
    if examples:
        parts.extend(["", "Examples:"])
        for item in examples:
            parts.append("  %s" % item)
    if tip:
        parts.extend(["", "Tip:", "  type: %s" % tip])
    return {"status": "incomplete", "message": "\n".join(parts)}


def _safe_names(names):
    out = []
    seen = set()
    for item in names or []:
        text = str(item or "").strip()
        if not text or "\n" in text or "\r" in text:
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return sorted(out, key=str.lower)


def missing_client_help(usage_lines, names=None, tip="show client ?"):
    """Enter-submitted incomplete client target. Tab must not call this."""
    parts = ["Missing client.", ""]
    available = _safe_names(names)
    if available:
        parts.append("Available CLIENT IDs:")
        for name in available:
            parts.append("  %s" % name)
        parts.append("")
    parts.append("Usage:")
    for line in usage_lines:
        parts.append("  %s" % line)
    parts.extend(
        [
            "",
            "Also accepted:",
            "  unique label",
            "  unique hostname",
            "",
            "Tip:",
            "  type: %s" % tip,
        ]
    )
    return {"status": "incomplete", "message": "\n".join(parts)}


def help_text(tokens, role):
    tokens = [t for t in tokens if t and t != "help"]
    client, server = _role_parts(role)
    if not tokens:
        return _root_help(role)
    verb = tokens[0]
    if verb == "legacy":
        return _legacy_help(role)
    if verb == "advanced":
        return _advanced_help(role)
    if verb == "show":
        return _show_help(tokens[1:], role)
    if verb == "set":
        return _set_help(tokens[1:], role)
    if verb == "unset":
        return _unset_help(role)
    if verb == "create":
        return _create_help(role)
    if verb == "update":
        return _update_help(role)
    if verb == "service":
        return _service_help(tokens[1:], role)
    if verb == "client":
        return _client_ns_help(role)
    if verb == "system":
        return _system_help(role)
    if verb in (
        "revoke", "purge", "release", "restore", "add", "remove",
        "delete", "rename", "enable", "disable",
    ):
        return _verb_help(verb, role)
    if verb == "doctor":
        return (
            "Doctor\n======\n\nUsage:\n  doctor\n  doctor --json\n  doctor --verbose\n"
            "\nCanonical form on client hosts:\n  system doctor\n"
        )
    if verb == "support-bundle":
        return (
            "Support Bundle\n==============\n\n"
            "Usage:\n  support-bundle\n  support-bundle --output <path>\n\n"
            "Create a sanitized read-only diagnostic archive. Never includes private keys or tokens.\n"
            "\nCanonical form on client hosts:\n  system support-bundle\n"
        )
    if verb == "access":
        return (
            "Access Control\n"
            "==============\n\n"
            "Manage Named Access Lists and service source policies.\n\n"
            "Usage:\n"
            "  access\n"
            "  access list\n"
            "  access create <name> [--description TEXT]\n"
            "  access add-source <list> --name NAME --source CIDR [--ttl 4h] [--yes]\n"
            "  access remove-source <list> --source SELECTOR [--yes]\n"
            "  access edit-info <list> [--name NAME] [--description TEXT] [--yes]\n"
            "  access remove-expired <list> [--yes]\n"
            "  access assign <client> <service> <list>\n"
            "  access public <client> <service>\n"
            "  access test <client> <service> <source-ip>\n"
            "  access menu\n\n"
            "Passthrough: remaining arguments are forwarded to frp-access.\n"
        )
    lines = [
        "Unknown help topic: %s" % " ".join(tokens),
        "",
        "Type 'help' for the command tree, or 'help legacy' for compatibility aliases.",
    ]
    if client or server:
        pass
    return "\n".join(lines) + "\n"


def _root_help(role):
    client, server = _role_parts(role)
    if client and server:
        return _root_help_dual()
    lines = [
        "FRP Auto Deploy CLI",
        "===================",
        "",
    ]
    if client and not server:
        lines.extend(
            [
                "Commands are grouped by resource:",
                "",
                "  show",
                "  service",
                "  client",
                "  system",
                "",
                "Type '<resource> ?' or press Tab to discover actions.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "Grammar: <verb> <resource> [target] [property] [value]",
                "",
                "Discover commands with Tab. Type 'help <verb>' for details.",
                "",
            ]
        )
    lines.extend(
        [
            "Show",
            "  show status",
            "  show version",
        ]
    )
    if server:
        lines.extend(
            [
                "  show clients",
                "  show client <ID>",
                "  show client <ID> services",
                "  show client <ID> tags",
                "  show enrollments",
                "  show audit",
                "  show upstream",
            ]
        )
    if client:
        lines.extend(["  show services", "  show info"])
    lines.extend(["", "Configure"])
    if server:
        lines.extend(
            [
                "  show groups",
                "  show group <GROUP>",
                "  show profiles",
                "  show profile <PROFILE>",
                "  show clients --group <GROUP>",
                "  show client <ID> groups",
                "  set client <ID> label <value>",
                "  set client <ID> note <value>",
                "  set client <ID> tag <key> <value>",
                "  unset client <ID> label",
                "  unset client <ID> note",
                "  unset client <ID> tag <key>",
                "  create group <name> [--description TEXT]",
                "  create profile <name> --preset ... --target-host ... --target-port ...",
                "  rename group <GROUP> <name>",
                "  set group <GROUP> name|description <value>",
                "  set profile <PROFILE> <prop> <value>",
                "  delete group <GROUP>",
                "  delete profile <PROFILE>",
                "  add client <ID> group <GROUP>",
                "  remove client <ID> group <GROUP>",
            ]
        )
    if client:
        lines.extend(
            [
                "  service add ssh|http|https|custom",
                "  service add profile <PROFILE>",
                "  service set <id> target-host <host>",
                "  service set <id> target-port <port>",
                "  service set <id> ssh-user <user>",
                "  service set <id> name <value>",
                "  service set <id> health-type <tcp|http|disabled>",
                "  service enable <id>",
                "  service disable <id>",
                "  service apply",
                "  service discard",
            ]
        )
    lines.extend(["", "Lifecycle"])
    if server:
        lines.extend(
            [
                "  create zero-touch",
                "  create enrollment [--ssh --ssh-user USER --label NAME]",
                "  create enrollments --count N",
                "  create backup",
                "  revoke enrollment <id>",
                "  purge enrollment <id>",
                "  purge enrollments --older-than <days>",
                "  revoke client <ID>",
                "  release service <ID> <service-id>",
                "  release client <ID>",
                "  restore backup <path>",
            ]
        )
    if client:
        lines.extend(
            [
                "  client pause",
                "  client resume",
                "  client uninstall",
            ]
        )
    if server:
        lines.extend(
            [
                "  update project [--check]",
                "  update frp [--check]",
            ]
        )
    elif client:
        lines.extend(
            [
                "  system update [--check]",
                "  system doctor",
                "  system support-bundle [--output PATH]",
            ]
        )
    other = [
        "",
        "Other",
    ]
    if server:
        other.append("  access               Access Control Pack (server)")
        other.extend(
            [
                "  doctor",
                "  support-bundle [--output PATH]",
            ]
        )
    other.extend(
        [
            "  menu                 Guided numbered menu",
            "  history              This session only (not saved to disk)",
            "  help, ?",
            "  help advanced        Automation / hidden flags",
            "  help legacy          Compatibility aliases",
            "  clear",
            "  exit",
        ]
    )
    if server:
        other.extend(
            [
                "",
                "status and version remain shortcuts for show status / show version.",
            ]
        )
    lines.extend(other)
    return "\n".join(lines) + "\n"


def _root_help_dual():
    """Full help for hosts with both client and server roles."""
    lines = [
        "FRP Auto Deploy CLI",
        "===================",
        "",
        "This host has both an FRP client and an FRP server installed.",
        "",
        "Client commands use resource groups: show, service, client, system.",
        "Server commands use verb/resource grammar:",
        "  <verb> <resource> [target] [property] [value]",
        "",
        "Type '<resource> ?' or 'help <verb>' for details. Press Tab to discover.",
        "",
        "Client commands",
        "---------------",
        "  show services",
        "  show info",
        "  service add ssh|http|https|custom",
        "  service add profile <PROFILE>",
        "  service set <id> <property> <value>",
        "  service enable <id>",
        "  service disable <id>",
        "  service apply",
        "  service discard",
        "  client pause|resume|uninstall",
        "",
        "Server commands",
        "---------------",
        "  show status|version|clients|client|groups|profiles|enrollments|audit|upstream",
        "  set client|group|profile|installer-url|server ...",
        "  unset client|server ...",
        "  create zero-touch|enrollment|enrollments|backup|group|profile",
        "  revoke|purge|release|restore ...",
        "  add|remove client <ID> group <GROUP>",
        "  delete group|profile ...",
        "  rename group <GROUP> <name>",
        "  update project|frp [--check]",
        "  access",
        "  doctor",
        "  support-bundle [--output PATH]",
        "  status, version          Shortcuts for show status / show version",
        "",
        "Common commands",
        "---------------",
        "  system update|doctor|support-bundle",
        "  menu",
        "  history",
        "  help, ?",
        "  help advanced",
        "  help legacy",
        "  clear",
        "  exit",
    ]
    return "\n".join(lines) + "\n"


def _service_help(rest, role):
    _ = rest
    client, _server = _role_parts(role)
    if not client:
        return "Service commands require a client role on this host.\n"
    return (
        "Service management\n"
        "==================\n\n"
        "Usage:\n"
        "  service add\n"
        "  service add ssh|http|https|custom\n"
        "  service add profile <PROFILE>\n"
        "  service set <id> <property> <value>\n"
        "  service enable <id>\n"
        "  service disable <id>\n"
        "  service apply\n"
        "  service discard\n\n"
        "Interactive examples:\n"
        "  service add\n"
        "  service add http\n"
        "  service add ssh\n\n"
        "Service IDs are generated automatically. Draft changes stay pending\n"
        "until service apply. service discard drops pending changes only.\n\n"
        "Advanced automation: help advanced\n"
    )


def _client_ns_help(role):
    client, _server = _role_parts(role)
    if not client:
        return "Client lifecycle commands require a client role on this host.\n"
    return (
        "Client lifecycle\n"
        "================\n\n"
        "Usage:\n"
        "  client pause\n"
        "  client resume\n"
        "  client uninstall\n\n"
        "pause blocks all FRP remote access and survives reboot.\n"
        "resume restores autostart and starts frpc with the existing identity.\n"
        "uninstall removes local software only; server reservations remain.\n"
    )


def _system_help(role):
    client, server = _role_parts(role)
    if not client and not server:
        return "System maintenance commands require an installed FRP Auto Deploy role.\n"
    return (
        "System maintenance\n"
        "==================\n\n"
        "Usage:\n"
        "  system update [--check]\n"
        "  system update project [--check]\n"
        "  system doctor\n"
        "  system support-bundle [--output PATH]\n\n"
        "On client hosts, system update updates FRP Auto Deploy client tooling.\n"
    )


def _show_help(rest, role):
    if not rest:
        avail = _show_resources(role)
        return (
            "Show information\n"
            "================\n\n"
            "Usage:\n  show <resource> ...\n\n"
            "Available:\n  " + "\n  ".join(avail) + "\n"
        )
    topic = rest[0]
    if topic == "client":
        return (
            "Show client information\n"
            "=======================\n\n"
            "Usage:\n"
            "  show client <ID>\n"
            "  show client <ID> services\n"
            "  show client <ID> tags\n\n"
            "CLIENT ID is the immutable selector. A unique label or hostname\n"
            "is also accepted as a shortcut.\n\n"
            "Examples:\n"
            "  show client 24cd7856\n"
            "  show client 24cd7856 services\n"
        )
    if topic in ("group", "groups"):
        return (
            "Show groups\n"
            "===========\n\n"
            "Usage:\n"
            "  show groups\n"
            "  show group <GROUP>\n"
            "  show clients --group <GROUP>\n"
            "  show client <ID> groups\n"
        )
    if topic in ("profile", "profiles"):
        return (
            "Show service profiles\n"
            "=====================\n\n"
            "Usage:\n"
            "  show profiles\n"
            "  show profile <PROFILE>\n\n"
            "Profiles are server-owned creation templates. They do not store\n"
            "public ports, CLIENT IDs, Service IDs, or ACL assignments.\n"
        )
    return "Usage:\n  show %s\n" % topic


def _set_help(rest, role):
    if rest and rest[0] == "client":
        return (
            "Set client configuration\n"
            "========================\n\n"
            "Usage:\n"
            "  set client <ID> label <value>\n"
            "  set client <ID> note <value>\n"
            "  set client <ID> tag <key> <value>\n\n"
            "Examples:\n"
            "  set client 24cd7856 label production\n"
            "  set client 24cd7856 note \"Seoul production gateway\"\n"
            "  set client 24cd7856 tag env oci\n\n"
            "To remove a setting:\n"
            "  unset client <ID> ...\n"
        )
    if rest and rest[0] == "service":
        return (
            "Set service configuration\n"
            "=========================\n\n"
            "Usage:\n"
            "  service set <id> target-host <host>\n"
            "  service set <id> target-port <port>\n"
            "  service set <id> ssh-user <user>\n"
            "  service set <id> name <value>\n"
            "  service set <id> health-type <tcp|http|disabled>\n"
            "  service set <id> health-timeout <seconds>\n"
            "  service set <id> health-interval <seconds>\n"
            "  service set <id> health-max-failed <count>\n"
            "  service set <id> health-path </path>\n\n"
            "Service IDs cannot be renamed. Pending changes are live only after\n"
            "service apply. Health checks are disabled by default.\n"
        )
    if rest and rest[0] == "profile":
        return (
            "Set profile configuration\n"
            "=========================\n\n"
            "Usage:\n"
            "  set profile <PROFILE> name <value>\n"
            "  set profile <PROFILE> description <value>\n"
            "  set profile <PROFILE> preset <ssh|http|https|custom>\n"
            "  set profile <PROFILE> target-host <host>\n"
            "  set profile <PROFILE> target-port <port>\n"
            "  set profile <PROFILE> ssh-user <user>\n\n"
            "Editing a profile does not mutate existing services.\n"
        )
    avail = _set_resources(role)
    return (
        "Set configuration\n"
        "=================\n\n"
        "Usage:\n  set <resource> ...\n\n"
        "Available:\n  " + "\n  ".join(avail or ["(none for this host role)"]) + "\n"
    )


def _unset_help(role):
    return (
        "Unset configuration\n"
        "===================\n\n"
        "Usage:\n"
        "  unset client <ID> label\n"
        "  unset client <ID> note\n"
        "  unset client <ID> tag <key>\n"
        "  unset server hostname\n"
        "  unset server bootstrap-hostname\n\n"
        "unset removes metadata only. It does not release ports or revoke identity.\n"
        "unset server hostname falls back to Public IP access.\n"
        "unset server bootstrap-hostname falls back to zt1 Zero-Touch commands.\n"
    )


def _create_help(role):
    return (
        "Create\n"
        "======\n\n"
        "Usage:\n"
        "  create group <name> [--description TEXT]\n"
        "  create profile <name> --preset ssh|http|https|custom\n"
        "                 --target-host HOST --target-port PORT\n"
        "                 [--description TEXT] [--ssh-user USER]\n"
        "  create zero-touch\n"
        "  create enrollment\n"
        "  create enrollments --count N\n"
        "  create enrollments --csv FILE\n"
        "  create backup [path]\n\n"
        "Recommended:\n"
        "  create zero-touch\n\n"
        "Descriptions:\n\n"
        "zero-touch\n"
        "  Generate a one-line Zero-touch client installation command.\n\n"
        "enrollment\n"
        "  Generate a Manual Enrollment Code.\n"
    )


def _update_help(role):
    lines = [
        "Update\n======\n\nUsage:\n  update project [--check]",
        "  update frp [--check]",
    ]
    lines.append("\nA software update does not re-enroll clients or rotate CA/token/ports.\n")
    return "\n".join(lines)


def _verb_help(verb, role):
    mapping = {
        "revoke": (
            "Revoke\n======\n\nUsage:\n"
            "  revoke client <ID>\n"
            "  revoke enrollment <id>\n\n"
            "revoke client removes management identity and keeps port reservations.\n"
            "revoke enrollment prevents a pending or bound enrollment credential from being used.\n"
        ),
        "purge": (
            "Purge\n=====\n\nUsage:\n"
            "  purge enrollment <id>\n"
            "  purge enrollments --older-than <days>\n\n"
            "purge permanently removes terminal enrollment metadata "
            "(expired, completed, or revoked).\n"
            "Active pending or bound enrollments must be revoked first.\n"
        ),
        "release": (
            "Release\n=======\n\nUsage:\n"
            "  release service <ID> <service-id>\n"
            "  release client <ID>\n\n"
            "release returns public port reservations. It is not revoke or unset.\n"
        ),
        "restore": "Restore\n=======\n\nUsage:\n  restore backup <path>\n",
        "add": (
            "Add\n===\n\nUsage:\n"
            "  service add\n"
            "  service add ssh|http|https|custom\n"
            "  service add profile <PROFILE>\n"
            "  add client <ID> group <GROUP>\n\n"
            "Prefer service add on client hosts (interactive wizard).\n"
            "Legacy forms still work for automation; see help advanced.\n\n"
            "Pending until service apply. Does not release server-side reservations.\n"
            "Profile seeding copies template defaults only; public ports stay\n"
            "unallocated until apply. Editing a profile never mutates services.\n"
            "Service IDs are generated automatically.\n"
        ),
        "enable": "Enable service\n==============\n\nUsage:\n  enable service <service-id>\n",
        "disable": (
            "Disable service\n===============\n\nUsage:\n  disable service <service-id>\n\n"
            "The public reservation remains until release service.\n"
        ),
        "remove": (
            "Remove group membership\n"
            "=======================\n\n"
            "Usage:\n  remove client <ID> group <GROUP>\n"
        ),
        "delete": ("Delete\n======\n\nUsage:\n  delete group <GROUP>\n  delete profile <PROFILE>\n\nDeleting a profile does not change existing services.\n"),
        "rename": "Rename group\n============\n\nUsage:\n  rename group <GROUP> <name>\n",
    }
    return mapping.get(verb, "Usage:\n  %s\n" % verb)


def _advanced_help(role):
    client, _server = _role_parts(role)
    lines = [
        "Advanced / automation",
        "=====================",
        "",
        "Normal interactive use prefers the service-add wizard:",
        "  service add",
        "  service add http",
        "",
        "Non-interactive automation may still pass explicit flags:",
        "  service add ssh --ssh-user USER [--target-host HOST] [--target-port PORT]",
        "  service add http --target-host HOST [--target-port PORT] [--name NAME]",
        "  service add https --target-host HOST [--target-port PORT] [--name NAME]",
        "  service add custom --target-port PORT [--target-host HOST] [--name NAME]",
        "  service add profile <PROFILE> [--name NAME]",
        "",
        "Hidden legacy override (not shown in Tab / normal help):",
        "  --id ID     Force a Service ID (immutable once created)",
        "",
        "service apply --verbose  Include diagnostic frpc journal output",
        "",
        "Compatibility aliases: help legacy",
    ]
    if not client:
        lines.insert(3, "(Most service-add flags require a client role.)")
        lines.insert(4, "")
    return "\n".join(lines) + "\n"


def _legacy_help(role):
    _ = role
    return (
        "Compatibility aliases\n"
        "=====================\n\n"
        "These older commands still work for scripts. Tab completion and\n"
        "canonical help hide them.\n\n"
        "Client service (prefer service …):\n"
        "  add service, set service, enable service, disable service\n"
        "  apply, discard\n\n"
        "Client maintenance (prefer system …):\n"
        "  update project, doctor, support-bundle\n\n"
        "Other compatibility forms:\n"
        "  clients, client <ID>, client-info, client-set, edit-client\n"
        "  enroll, create-client, enroll-bulk, enrollments, enrollment-revoke\n"
        "  revoke ID, revoke-client, release-service, release-client\n"
        "  project-update, frp-update, server-update, client-update\n"
        "  backup, restore PATH, upstream, audit\n"
        "  services, manage, info, client-status, server-status\n"
        "  status, version, update\n"
    )


def _fmt_available(rows):
    parts = ["Available:", ""]
    width = max((len(name) for name, _desc in rows), default=8)
    for name, desc in rows:
        parts.append("  %s  %s" % (name.ljust(width), desc))
    return "\n".join(parts) + "\n"


def context_help(tokens, role, names=None, clients=None):
    """Enter-submitted '?' help. Tab must never call this."""
    client, server = _role_parts(role)
    tokens = [t for t in (tokens or []) if t != "?"]
    if not tokens:
        return _concise_root(role)
    verb = tokens[0]
    if verb == "show":
        if len(tokens) == 1:
            rows = [("status", "Host status"), ("version", "Installed versions")]
            if server:
                rows.extend(
                    [
                        ("clients", "Registered client table"),
                        ("client", "One client (overview, services, or tags)"),
                        ("enrollments", "Issued enrollment credentials"),
                        ("audit", "Recent audit events"),
                        ("upstream", "FRP upstream check"),
                    ]
                )
            if client:
                rows.extend([("services", "Local services"), ("info", "Local connection info")])
            return _fmt_available(rows)
        if tokens[1] == "client":
            if len(tokens) == 2:
                return _context_client_list(names, clients)
            return _fmt_available(
                [
                    ("services", "Published services only"),
                    ("tags", "Administrator tags only"),
                ]
            )
        return "Usage:\n  show %s\n" % tokens[1]
    if verb == "set":
        if len(tokens) == 1:
            rows = []
            if server:
                rows.extend(
                    [
                        ("client", "Configure registered client metadata"),
                        ("installer-url", "Configure client installer URL"),
                        ("server", "Configure server access settings"),
                    ]
                )
            if client:
                rows.append(("service", "Configure a local service"))
            return _fmt_available(rows or [("(none)", "No set resources on this host")])
        if tokens[1] == "client":
            if len(tokens) == 2:
                return _context_client_list(names, clients)
            if len(tokens) == 3 or (len(tokens) == 4 and tokens[3] != "tag"):
                if len(tokens) >= 4 and tokens[3] == "tag":
                    return (
                        "Available:\n\n"
                        "  <key> <value>  Set a tag. Example: tag env oci\n"
                    )
                return (
                    "Available settings:\n\n"
                    "  label   Administrator display label\n"
                    "  note    Administrator description\n"
                    "  tag     Key/value metadata\n"
                )
            if len(tokens) >= 4 and tokens[3] == "tag":
                cid = tokens[2] if len(tokens) > 2 else "<ID>"
                return (
                    "Usage:\n"
                    "  set client <ID> tag <key> <value>\n\n"
                    "Purpose:\n"
                    "  Add or replace one client metadata tag.\n\n"
                    "Example:\n"
                    "  set client %s tag env production\n\n"
                    "Remove:\n"
                    "  unset client %s tag env\n"
                    % (cid, cid)
                )
        if tokens[1] == "service":
            return _fmt_available(
                [
                    ("target-host", "Local target host"),
                    ("target-port", "Local target port"),
                    ("ssh-user", "SSH username"),
                    ("name", "Display name"),
                    ("health-type", "tcp | http | disabled"),
                    ("health-timeout", "Probe timeout seconds"),
                    ("health-interval", "Probe interval seconds"),
                    ("health-max-failed", "Failures before unhealthy"),
                    ("health-path", "HTTP health path (http only)"),
                ]
            )
        if tokens[1] == "installer-url":
            return "Usage:\n  set installer-url <url>\n"
        if tokens[1] == "server":
            if len(tokens) == 2:
                return _fmt_available(
                    [
                        ("hostname", "Optional public DNS hostname for published services"),
                        ("bootstrap-hostname", "Optional Zero-Touch public TLS bootstrap hostname"),
                    ]
                )
            if tokens[2] == "bootstrap-hostname":
                return (
                    "Usage:\n"
                    "  set server bootstrap-hostname <fqdn>\n\n"
                    "Purpose:\n"
                    "  Set the publicly trusted Zero-Touch short URL hostname.\n"
                    "  FRP Auto Deploy does not create DNS or issue certificates.\n"
                    "  Operator terminates public TLS on a reverse proxy.\n\n"
                    "Example:\n"
                    "  set server bootstrap-hostname bootstrap.example.com\n\n"
                    "Remove:\n"
                    "  unset server bootstrap-hostname\n"
                )
            return (
                "Usage:\n"
                "  set server hostname <fqdn>\n\n"
                "Purpose:\n"
                "  Set an optional DNS alias for published service access.\n"
                "  FRP control continues to use the Public IP.\n\n"
                "Example:\n"
                "  set server hostname frp.example.com\n\n"
                "Remove:\n"
                "  unset server hostname\n"
            )
        return _fmt_available([(item, "") for item in _set_resources(role)])
    if verb == "unset":
        if len(tokens) == 1:
            return _fmt_available(
                [
                    ("client", "Remove client metadata"),
                    ("server", "Remove server access settings"),
                ]
            )
        if tokens[1] == "server":
            return (
                "Usage:\n"
                "  unset server hostname\n"
                "  unset server bootstrap-hostname\n"
            )
        if len(tokens) <= 2:
            return _context_client_list(names, clients)
        return (
            "Available settings:\n\n"
            "  label   Administrator display label\n"
            "  note    Administrator description\n"
            "  tag     Key/value metadata\n"
        )
    if verb == "create":
        if len(tokens) >= 2 and tokens[1] == "zero-touch":
            return (
                "Zero-touch enrollment\n"
                "=====================\n\n"
                "Usage:\n"
                "  create zero-touch\n\n"
                "Starts a guided workflow to generate a one-line Zero-touch\n"
                "client installation command (SSH, services, or management-only).\n\n"
                "Recommended for everyday client onboarding.\n"
            )
        if len(tokens) >= 2 and tokens[1] == "enrollment":
            return (
                "Manual Enrollment Code\n"
                "======================\n\n"
                "Usage:\n"
                "  create enrollment\n"
                "  create enrollment [--one-line] [--ssh --ssh-user USER --label NAME]\n\n"
                "Generate a Manual Enrollment Code for interactive client install.\n"
                "For everyday onboarding prefer: create zero-touch\n"
            )
        if len(tokens) >= 2 and tokens[1] == "enrollments":
            return (
                "Bulk enrollment\n"
                "===============\n\n"
                "Usage:\n"
                "  create enrollments --count N\n"
                "  create enrollments --csv FILE\n"
            )
        if len(tokens) >= 2 and tokens[1] == "backup":
            return "Usage:\n  create backup [path]\n"
        return _fmt_available(
            [
                ("zero-touch", "Zero-touch enrollment (recommended)"),
                ("enrollment", "Manual Enrollment Code"),
                ("enrollments", "Bulk enrollment"),
                ("backup", "Server backup"),
            ]
        )
    if verb == "update":
        rows = [
            ("project", "Update project management tools"),
            ("frp", "Update the FRP binary"),
        ]
        return _fmt_available(rows)
    if verb == "release":
        return _fmt_available(
            [
                ("client", "Release all reserved ports for a client"),
                ("service", "Release one service reservation"),
            ]
        )
    if verb == "revoke":
        return _fmt_available(
            [
                ("client", "Revoke management identity"),
                ("enrollment", "Revoke a pending enrollment"),
            ]
        )
    if verb == "purge":
        return _fmt_available(
            [
                ("enrollment", "Permanently remove one terminal enrollment"),
                ("enrollments", "Bulk purge terminal enrollments by age"),
            ]
        )
    if verb == "restore":
        return _fmt_available([("backup", "Restore from a backup archive")])
    if verb == "service":
        if not client:
            return "Service commands require a client role on this host.\n"
        if len(tokens) >= 2 and tokens[1] == "add":
            if len(tokens) == 2:
                text = (SERVICE_ADD_CONCEPT_HELP or "").rstrip()
                return text + "\n" if text else help_text(["service"], role)
            return _service_add_type_help(tokens[2])
        return _fmt_section(
            "Service management",
            [
                ("add", "Add a service"),
                ("set", "Change a service"),
                ("enable", "Enable a service"),
                ("disable", "Disable a service"),
                ("apply", "Apply pending service changes"),
                ("discard", "Discard pending service changes"),
            ],
        )
    if verb == "client":
        if client:
            return _fmt_section(
                "Client lifecycle",
                [
                    ("pause", "Block all FRP remote access"),
                    ("resume", "Resume FRP remote access"),
                    ("uninstall", "Remove FRP Auto Deploy from this machine"),
                ],
            )
        return help_text(tokens, role)
    if verb == "system":
        return _fmt_section(
            "System maintenance",
            [
                ("update", "Update FRP Auto Deploy"),
                ("doctor", "Run health checks"),
                ("support-bundle", "Create sanitized diagnostic archive"),
            ],
        )
    return help_text(tokens, role)


def _fmt_section(title, rows):
    parts = [title, ""]
    width = max((len(name) for name, _desc in rows), default=8)
    for name, desc in rows:
        parts.append("  %s  %s" % (name.ljust(width), desc))
    return "\n".join(parts) + "\n"


def _service_add_type_help(stype):
    stype = (stype or "").strip().lower()
    if stype == "ssh":
        return (
            "Usage:\n"
            "  service add ssh\n\n"
            "Starts the SSH service wizard (location, port, SSH user, name).\n"
            "Default target: this FRP client, TCP/22.\n"
            "Service ID is allocated automatically.\n"
            "Apply with service apply; discard with service discard.\n"
        )
    if stype in ("http", "https"):
        port = "80" if stype == "http" else "443"
        return (
            "Usage:\n"
            "  service add %s\n\n"
            "Starts the %s service wizard (location, port, name).\n"
            "Default target: this FRP client, TCP/%s.\n"
            "Service ID is allocated automatically.\n"
            "Apply with service apply; discard with service discard.\n"
            % (stype, stype.upper(), port)
        )
    if stype == "custom":
        return (
            "Usage:\n"
            "  service add custom\n\n"
            "Starts the Custom TCP wizard. Target port is required.\n"
            "Service ID is allocated automatically (tcp-<port>).\n"
            "Apply with service apply; discard with service discard.\n"
        )
    if stype == "profile":
        return (
            "Usage:\n"
            "  service add profile <PROFILE>\n\n"
            "Start from a server Service Profile. Public ports stay unallocated\n"
            "until service apply. Service ID is allocated automatically.\n"
        )
    if stype.startswith("--"):
        return (
            "Prefer the interactive wizard:\n"
            "  service add\n"
            "  service add ssh|http|https|custom\n\n"
            "Automation flags: help advanced\n"
        )
    return (
        "Unknown service type: %s\n\n"
        "Available: ssh, http, https, custom, profile\n"
        % stype
    )


def _context_client_list(names, clients):
    rows = []
    if clients:
        for item in clients:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("id") or "").strip()
            if not cid:
                continue
            rows.append((cid, item.get("label") or "-", item.get("hostname") or "-"))
    elif names:
        for name in _safe_names(names):
            rows.append((name, "-", "-"))
    if not rows:
        return "(no registered clients)\n"
    parts = ["%-10s %-10s %s" % ("CLIENT ID", "LABEL", "HOSTNAME")]
    for cid, label, host in rows:
        parts.append("%-10s %-10s %s" % (cid, label, host))
    return "\n".join(parts) + "\n"


def _concise_root(role):
    client, server = _role_parts(role)
    if client and not server:
        rows = [
            ("show", "View status and configuration"),
            ("service", "Manage published services"),
            ("client", "Control this FRP client"),
            ("system", "Maintenance and diagnostics"),
            ("help", "Detailed help"),
            ("menu", "Guided menu"),
            ("history", "Session command history"),
            ("exit", "Leave frpctl"),
        ]
        return _fmt_available(rows)
    if client and server:
        parts = [
            "Client",
            "  service              Manage published services",
            "  client               Control this FRP client",
            "",
            "Server",
            "  show                 View status and configuration",
            "  set                  Change configuration",
            "  unset                Remove configuration values",
            "  create               Create enrollment or backup",
            "  revoke               Revoke management access",
            "  purge                Remove terminal enrollment metadata",
            "  release              Return reserved public ports",
            "  update               Update project or FRP",
            "  restore              Restore backup",
            "  doctor               Run health checks",
            "  support-bundle       Create sanitized diagnostic archive",
            "  access               Access Control Pack",
            "  status               Host status shortcut",
            "  version              Installed versions shortcut",
            "",
            "Common",
            "  system               Maintenance and diagnostics",
            "  help                 Detailed help",
            "  menu                 Guided menu",
            "  history              Session command history",
            "  clear                Clear the screen",
            "  exit                 Leave frpctl",
        ]
        return "\n".join(parts) + "\n"
    rows = [
        ("show", "View status and configuration"),
        ("set", "Change configuration"),
        ("unset", "Remove configuration values"),
        ("create", "Create enrollment or backup"),
        ("revoke", "Revoke management access"),
        ("purge", "Remove terminal enrollment metadata"),
        ("release", "Return reserved public ports"),
        ("update", "Update project or FRP"),
        ("restore", "Restore backup"),
        ("doctor", "Run health checks"),
        ("support-bundle", "Create sanitized diagnostic archive"),
        ("access", "Access Control Pack"),
        ("help", "Detailed help"),
        ("menu", "Guided menu"),
        ("history", "Session command history"),
        ("exit", "Leave frpctl"),
    ]
    if not server:
        hide = {"create", "revoke", "purge", "release", "restore", "access", "set", "unset"}
        rows = [(n, d) for n, d in rows if n not in hide]
    return _fmt_available([(n, d) for n, d in rows])


def match(tokens, role, names=None, clients=None):
    if not tokens:
        return {"status": "empty"}
    if tokens[-1] == "?":
        return {
            "status": "ok",
            "action": "context_help",
            "focus": tokens[:-1],
            "message": context_help(tokens[:-1], role, names=names, clients=clients),
        }
    verb = tokens[0]
    if verb.startswith("!") or verb in SHELL_REJECT:
        return {"status": "shell"}
    if verb in LEGACY_COMMANDS:
        return {"status": "legacy"}
    client, server = _role_parts(role)
    handlers = {
        "show": _match_show,
        "set": _match_set,
        "unset": _match_unset,
        "create": _match_create,
        "revoke": _match_revoke,
        "purge": _match_purge,
        "release": _match_release,
        "update": _match_update,
        "restore": _match_restore,
        "add": _match_add,
        "remove": _match_remove,
        "delete": _match_delete,
        "rename": _match_rename,
        "enable": _match_enable_disable,
        "disable": _match_enable_disable,
        "apply": lambda toks, role, names=None: {"status": "ok", "action": "apply"},
        "discard": lambda toks, role, names=None: {"status": "ok", "action": "discard"},
        "service": _match_service,
        "client": _match_client_ns,
        "system": _match_system,
        "doctor": lambda toks, role, names=None: {"status": "ok", "action": "doctor", "passthrough": toks[1:]},
        "support-bundle": lambda toks, role, names=None: {"status": "ok", "action": "support_bundle", "passthrough": toks[1:]},
        "access": lambda toks, role, names=None: {"status": "ok", "action": "access_cmd", "passthrough": toks[1:]},
        "help": lambda toks, role, names=None: {"status": "ok", "action": "help", "passthrough": toks[1:]},
        "?": lambda toks, role, names=None: {"status": "ok", "action": "help", "passthrough": toks[1:]},
        "menu": lambda toks, role, names=None: {"status": "ok", "action": "menu"},
        "history": lambda toks, role, names=None: {"status": "ok", "action": "history"},
        "clear": lambda toks, role, names=None: {"status": "ok", "action": "clear"},
        "exit": lambda toks, role, names=None: {"status": "ok", "action": "exit"},
        "quit": lambda toks, role, names=None: {"status": "ok", "action": "exit"},
        "q": lambda toks, role, names=None: {"status": "ok", "action": "exit"},
        "status": lambda toks, role, names=None: {"status": "ok", "action": "show_status", "passthrough": toks[1:]},
        "version": lambda toks, role, names=None: {"status": "ok", "action": "show_version"},
    }
    fn = handlers.get(verb)
    if fn is None:
        return {"status": "unknown", "command": verb}
    if verb in ("set", "unset", "create", "revoke", "purge", "release", "restore", "remove", "delete", "rename", "access") and not server and verb != "set":
        if verb == "set" and client:
            return fn(tokens, role, names)
        return {"status": "role", "need": "server", "command": verb}
    if verb in ("enable", "disable", "apply", "discard", "service") and not client:
        return {"status": "role", "need": "client", "command": verb}
    if verb == "client" and not client and not server:
        return {"status": "role", "need": "client or server", "command": verb}
    if verb == "system" and not client and not server:
        return {"status": "role", "need": "client or server", "command": verb}
    if verb == "add" and not client and not server:
        return {"status": "role", "need": "client or server", "command": verb}
    return fn(tokens, role, names)


def _match_show(tokens, role, names=None):
    avail = _show_resources(role)
    if len(tokens) == 1:
        return incomplete(
            "Missing resource.",
            ["show <resource>"],
            avail,
        )
    resource = tokens[1]
    if resource == "status":
        return {"status": "ok", "action": "show_status", "passthrough": tokens[2:]}
    if resource == "version":
        return {"status": "ok", "action": "show_version"}
    if resource == "clients":
        return {"status": "ok", "action": "show_clients", "passthrough": tokens[2:]}
    if resource == "groups":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["show groups"])
        return {"status": "ok", "action": "show_groups"}
    if resource == "group":
        if len(tokens) < 3:
            return incomplete("Missing group selector.", ["show group <GROUP>"])
        if len(tokens) > 3:
            return incomplete("Unexpected arguments.", ["show group <GROUP>"])
        return {"status": "ok", "action": "show_group", "group": tokens[2]}
    if resource == "profiles":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["show profiles"])
        return {"status": "ok", "action": "show_profiles"}
    if resource == "profile":
        if len(tokens) < 3:
            return incomplete("Missing profile selector.", ["show profile <PROFILE>"])
        if len(tokens) > 3:
            return incomplete("Unexpected arguments.", ["show profile <PROFILE>"])
        return {"status": "ok", "action": "show_profile", "profile": tokens[2]}
    if resource == "enrollments":
        return {"status": "ok", "action": "show_enrollments"}
    if resource == "audit":
        return {"status": "ok", "action": "show_audit"}
    if resource == "upstream":
        return {"status": "ok", "action": "show_upstream", "passthrough": tokens[2:]}
    if resource == "services":
        return {"status": "ok", "action": "show_services"}
    if resource == "info":
        return {"status": "ok", "action": "show_info"}
    if resource == "client":
        if len(tokens) < 3:
            return missing_client_help(
                [
                    "show client <ID>",
                    "show client <ID> services",
                    "show client <ID> tags",
                ],
                names,
                tip="show client ?",
            )
        view = tokens[3] if len(tokens) > 3 else "overview"
        if view in ("info",):
            view = "overview"
        if view not in ("overview", "services", "tags", "groups"):
            return incomplete(
                "Unknown client view.",
                [
                    "show client <ID>",
                    "show client <ID> services",
                    "show client <ID> tags",
                    "show client <ID> groups",
                ],
                ["services", "tags", "groups"],
            )
        return {
            "status": "ok",
            "action": "show_client",
            "client": tokens[2],
            "view": view,
        }
    return incomplete("Unknown show resource.", ["show <resource>"], avail)


def _match_set(tokens, role, names=None, form="legacy"):
    client, server = _role_parts(role)
    avail = _set_resources(role)
    if len(tokens) == 1:
        return incomplete("Missing resource.", ["set <resource> ..."], avail, tip="set ?")
    resource = tokens[1]
    if resource == "client":
        if not server:
            return {"status": "role", "need": "server", "command": "set client"}
        if len(tokens) < 3:
            return missing_client_help(
                [
                    "set client <ID> label <value>",
                    "set client <ID> note <value>",
                    "set client <ID> tag <key> <value>",
                ],
                names,
                tip="set client ?",
            )
        if len(tokens) < 4:
            return incomplete(
                "Missing client setting.",
                [
                    "set client <ID> label <value>",
                    "set client <ID> note <value>",
                    "set client <ID> tag <key> <value>",
                ],
                ["label", "note", "tag"],
            )
        prop = tokens[3]
        if prop not in ("label", "note", "tag"):
            return incomplete(
                "Unknown client setting.",
                [
                    "set client <ID> label <value>",
                    "set client <ID> note <value>",
                    "set client <ID> tag <key> <value>",
                ],
                ["label", "note", "tag"],
            )
        if prop == "tag":
            if len(tokens) < 5:
                return incomplete(
                    "Missing tag key.",
                    ["set client <ID> tag <key> <value>"],
                    tip="set client %s tag ?" % tokens[2],
                )
            if len(tokens) == 5 and "=" in tokens[4]:
                value = tokens[4]
            elif len(tokens) < 6:
                return incomplete(
                    "Missing tag value.",
                    ["set client <ID> tag <key> <value>"],
                )
            elif len(tokens) == 6:
                value = "%s=%s" % (tokens[4], tokens[5])
            else:
                return {
                    "status": "error",
                    "message": "Too many arguments. Quote values that contain spaces.",
                }
            return {
                "status": "ok",
                "action": "set_client",
                "client": tokens[2],
                "property": "tag",
                "value": value,
            }
        if len(tokens) < 5:
            return incomplete(
                "Missing %s value." % prop,
                ["set client <ID> %s <value>" % prop],
            )
        value = tokens[4]
        if len(tokens) > 5:
            return {
                "status": "error",
                "message": "Too many arguments. Quote values that contain spaces.",
            }
        return {
            "status": "ok",
            "action": "set_client",
            "client": tokens[2],
            "property": prop,
            "value": value,
        }
    if resource == "group":
        if not server:
            return {"status": "role", "need": "server", "command": "set group"}
        if len(tokens) < 3:
            return incomplete("Missing group selector.", ["set group <GROUP> name|description <value>"])
        if len(tokens) < 4 or tokens[3] not in ("name", "description"):
            return incomplete(
                "Missing or unknown group property.",
                ["set group <GROUP> name|description <value>"],
                ["name", "description"],
            )
        if len(tokens) < 5:
            return incomplete("Missing value.", ["set group <GROUP> %s <value>" % tokens[3]])
        if len(tokens) > 5:
            return {"status": "error", "message": "Too many arguments. Quote values that contain spaces."}
        return {
            "status": "ok",
            "action": "set_group",
            "group": tokens[2],
            "property": tokens[3],
            "value": tokens[4],
        }
    if resource == "profile":
        props = [
            "name", "description", "preset", "target-host", "target-port", "ssh-user",
            "health-type", "health-timeout", "health-interval", "health-max-failed", "health-path",
        ]
        if not server:
            return {"status": "role", "need": "server", "command": "set profile"}
        if len(tokens) < 3:
            return incomplete("Missing profile selector.", ["set profile <PROFILE> <prop> <value>"])
        if len(tokens) < 4 or tokens[3] not in props:
            return incomplete(
                "Missing or unknown profile property.",
                ["set profile <PROFILE> <prop> <value>"],
                props,
            )
        if len(tokens) < 5:
            return incomplete("Missing value.", ["set profile <PROFILE> %s <value>" % tokens[3]])
        if len(tokens) > 5:
            return {"status": "error", "message": "Too many arguments. Quote values that contain spaces."}
        return {
            "status": "ok",
            "action": "set_profile",
            "profile": tokens[2],
            "property": tokens[3],
            "value": tokens[4],
        }
    if resource == "service":
        if not client:
            return {"status": "role", "need": "client", "command": "set service"}
        props = list(SERVICE_SET_PROPS)
        sid = tokens[2] if len(tokens) > 2 else "<id>"
        preferred = "Preferred: service set <id> <property> <value>"
        if form == "canonical":
            usage_full = "service set %s <property> <value>" % sid
            usage_missing_id = "service set <id> <property> <value>"

            def usage_for_prop(prop):
                return "service set %s %s <value>" % (sid, prop)
        else:
            usage_full = "set service <service-id> <property> <value>"
            usage_missing_id = "set service <service-id> <property> <value>"

            def usage_for_prop(prop):
                return "set service <id> %s <value>" % prop

        def with_preferred(usage):
            lines = [usage]
            if form != "canonical":
                lines.append(preferred)
            return lines

        if len(tokens) < 3:
            return incomplete("Missing service ID.", with_preferred(usage_missing_id))
        if len(tokens) < 4:
            return incomplete(
                "Missing service property.",
                with_preferred(usage_full),
                props,
            )
        if tokens[3] not in props:
            return incomplete(
                "Unknown service property.",
                with_preferred(usage_full),
                props,
            )
        if len(tokens) < 5:
            return incomplete(
                "Missing value.",
                with_preferred(usage_for_prop(tokens[3])),
            )
        return {
            "status": "ok",
            "action": "set_service",
            "service": tokens[2],
            "property": tokens[3],
            "value": tokens[4],
        }
    if resource == "installer-url":
        if not server:
            return {"status": "role", "need": "server", "command": "set installer-url"}
        if len(tokens) < 3:
            return incomplete("Missing installer URL.", ["set installer-url <url>"])
        return {"status": "ok", "action": "set_installer_url", "value": tokens[2]}
    if resource == "server":
        if not server:
            return {"status": "role", "need": "server", "command": "set server"}
        server_settings = ["hostname", "bootstrap-hostname"]
        if len(tokens) < 3:
            return incomplete(
                "Missing server setting.",
                [
                    "set server hostname <fqdn>",
                    "set server bootstrap-hostname <fqdn>",
                ],
                server_settings,
                tip="set server ?",
            )
        if tokens[2] not in server_settings:
            return incomplete(
                "Unknown server setting.",
                [
                    "set server hostname <fqdn>",
                    "set server bootstrap-hostname <fqdn>",
                ],
                server_settings,
            )
        if len(tokens) < 4:
            return incomplete(
                "Missing hostname.",
                ["set server %s <fqdn>" % tokens[2]],
                tip="set server %s ?" % tokens[2],
            )
        if len(tokens) > 4:
            return {
                "status": "error",
                "message": "Too many arguments. Quote values that contain spaces.",
            }
        if tokens[2] == "hostname":
            return {
                "status": "ok",
                "action": "set_server_hostname",
                "value": tokens[3],
            }
        return {
            "status": "ok",
            "action": "set_server_bootstrap_hostname",
            "value": tokens[3],
        }
    return incomplete("Unknown set resource.", ["set <resource> ..."], avail)


def _match_unset(tokens, role, names=None):
    _, server = _role_parts(role)
    if not server:
        return {"status": "role", "need": "server", "command": "unset"}
    avail = _unset_resources(role)
    if len(tokens) < 2:
        return incomplete(
            "Missing resource.",
            ["unset client <ID> <setting>", "unset server hostname"],
            avail,
        )
    if tokens[1] == "server":
        if len(tokens) < 3:
            return incomplete(
                "Missing server setting.",
                ["unset server hostname", "unset server bootstrap-hostname"],
                ["hostname", "bootstrap-hostname"],
                tip="unset server ?",
            )
        if tokens[2] not in ("hostname", "bootstrap-hostname"):
            return incomplete(
                "Unknown server setting.",
                ["unset server hostname", "unset server bootstrap-hostname"],
                ["hostname", "bootstrap-hostname"],
            )
        if len(tokens) > 3:
            return {
                "status": "error",
                "message": "Too many arguments.",
            }
        if tokens[2] == "hostname":
            return {"status": "ok", "action": "unset_server_hostname"}
        return {"status": "ok", "action": "unset_server_bootstrap_hostname"}
    if tokens[1] != "client":
        return incomplete(
            "Unknown unset resource.",
            ["unset client <ID> <setting>", "unset server hostname"],
            avail,
        )
    if len(tokens) < 3:
        return missing_client_help(
            [
                "unset client <ID> label",
                "unset client <ID> note",
                "unset client <ID> tag <key>",
            ],
            names,
                tip="unset client ?",
        )
    if len(tokens) < 4:
        return incomplete(
            "Missing client setting.",
            [
                "unset client <ID> label",
                "unset client <ID> note",
                "unset client <ID> tag <key>",
            ],
            ["label", "note", "tag"],
        )
    prop = tokens[3]
    if prop not in ("label", "note", "tag"):
        return incomplete("Unknown client setting.", ["unset client <ID> label|note|tag"], ["label", "note", "tag"])
    if prop == "tag" and len(tokens) < 5:
        return incomplete("Missing tag key.", ["unset client <ID> tag <key>"])
    return {
        "status": "ok",
        "action": "unset_client",
        "client": tokens[2],
        "property": prop,
        "value": tokens[4] if prop == "tag" else "",
    }


def _match_create(tokens, role, names=None):
    _, server = _role_parts(role)
    if not server:
        return {"status": "role", "need": "server", "command": "create"}
    avail = _create_resources(role)
    if len(tokens) == 1:
        return incomplete("Missing resource.", ["create <resource>"], avail)
    resource = tokens[1]
    if resource == "zero-touch":
        if len(tokens) > 2:
            return incomplete(
                "Unexpected arguments.",
                ["create zero-touch"],
                tip="create zero-touch ?",
            )
        return {"status": "ok", "action": "create_zero_touch"}
    if resource == "enrollment":
        return {"status": "ok", "action": "create_enrollment", "passthrough": tokens[2:]}
    if resource == "enrollments":
        return {"status": "ok", "action": "create_enrollments", "passthrough": tokens[2:]}
    if resource == "backup":
        return {"status": "ok", "action": "create_backup", "passthrough": tokens[2:]}
    if resource == "group":
        if len(tokens) < 3:
            return incomplete("Missing group name.", ["create group <name> [--description TEXT]"])
        description = ""
        if len(tokens) > 3:
            if len(tokens) != 5 or tokens[3] != "--description":
                return incomplete("Unexpected arguments.", ["create group <name> [--description TEXT]"])
            description = tokens[4]
        return {
            "status": "ok",
            "action": "create_group",
            "name": tokens[2],
            "description": description,
        }
    if resource == "profile":
        if len(tokens) < 3:
            return incomplete(
                "Missing profile name.",
                [
                    "create profile <name> --preset ssh|http|https|custom "
                    "--target-host HOST --target-port PORT "
                    "[--description TEXT] [--ssh-user USER]"
                ],
            )
        return {
            "status": "ok",
            "action": "create_profile",
            "name": tokens[2],
            "passthrough": tokens[3:],
        }
    return incomplete("Unknown create resource.", ["create <resource>"], avail)


def _match_revoke(tokens, role, names=None):
    if len(tokens) == 1:
        return incomplete(
            "Missing resource.",
            ["revoke client <ID>", "revoke enrollment <ID>"],
            ["client", "enrollment"],
        )
    if tokens[1] == "client":
        if len(tokens) < 3:
            return missing_client_help(
                ["revoke client <ID>"],
                names,
                tip="revoke client ?",
            )
        return {"status": "ok", "action": "revoke_client", "client": tokens[2], "passthrough": tokens[3:]}
    if tokens[1] == "enrollment":
        if len(tokens) < 3:
            return incomplete("Missing enrollment id.", ["revoke enrollment <ID>"])
        return {"status": "ok", "action": "revoke_enrollment", "id": tokens[2]}
    # Compatibility: `revoke <client>` without the resource word.
    return {
        "status": "ok",
        "action": "revoke_client",
        "client": tokens[1],
        "passthrough": tokens[2:],
    }


def _match_purge(tokens, role, names=None):
    if len(tokens) == 1:
        return incomplete(
            "Missing resource.",
            ["purge enrollment <ID>", "purge enrollments --older-than <days>"],
            ["enrollment", "enrollments"],
        )
    if tokens[1] == "enrollment":
        if len(tokens) < 3:
            return incomplete("Missing enrollment id.", ["purge enrollment <ID>"])
        return {"status": "ok", "action": "purge_enrollment", "id": tokens[2]}
    if tokens[1] == "enrollments":
        older_than = None
        idx = 2
        while idx < len(tokens):
            if tokens[idx] == "--older-than" and idx + 1 < len(tokens):
                try:
                    older_than = int(tokens[idx + 1])
                except ValueError:
                    return incomplete("Invalid --older-than value.", ["purge enrollments --older-than <days>"])
                idx += 2
                continue
            return incomplete("Unexpected arguments.", ["purge enrollments --older-than <days>"])
        if older_than is None:
            return incomplete("Missing --older-than.", ["purge enrollments --older-than <days>"])
        return {"status": "ok", "action": "purge_enrollments", "older_than": older_than}
    return incomplete(
        "Unknown purge resource.",
        ["purge enrollment <ID>", "purge enrollments --older-than <days>"],
        ["enrollment", "enrollments"],
    )


def _match_release(tokens, role, names=None):
    if len(tokens) == 1:
        return incomplete(
            "Missing resource.",
            ["release service <ID> <service-id>", "release client <ID>"],
            ["service", "client"],
        )
    if tokens[1] == "client":
        if len(tokens) < 3:
            return missing_client_help(
                ["release client <ID>"],
                names,
                tip="release client ?",
            )
        return {"status": "ok", "action": "release_client", "client": tokens[2], "passthrough": tokens[3:]}
    if tokens[1] == "service":
        if len(tokens) < 3:
            return missing_client_help(
                ["release service <ID> <service-id>"],
                names,
                tip="release service ?",
            )
        if len(tokens) < 4:
            return incomplete("Missing service ID.", ["release service <ID> <service-id>"])
        return {
            "status": "ok",
            "action": "release_service",
            "client": tokens[2],
            "service": tokens[3],
            "passthrough": tokens[4:],
        }
    return incomplete("Unknown release resource.", ["release service|client"], ["service", "client"])


def _match_update(tokens, role, names=None):
    client_role, server = _role_parts(role)
    if len(tokens) == 1:
        return {"status": "ok", "action": "update_default"}
    resource = tokens[1]
    if resource in ("project", "frp") or resource.startswith("-"):
        if resource.startswith("-"):
            return {"status": "ok", "action": "update_default", "passthrough": tokens[1:]}
        action = "update_project" if resource == "project" else "update_frp"
        if resource == "frp" and not server and not client_role:
            return {"status": "role", "need": "client or server", "command": "update frp"}
        return {"status": "ok", "action": action, "passthrough": tokens[2:]}
    avail = ["project", "frp"]
    return incomplete("Unknown update target.", ["update project [--check]", "update frp [--check]"], avail)


def _match_restore(tokens, role, names=None):
    if len(tokens) == 1 or (len(tokens) == 2 and tokens[1] == "backup"):
        if len(tokens) == 1:
            return incomplete("Missing resource.", ["restore backup <path>"], ["backup"])
        return incomplete("Missing backup path.", ["restore backup <path>"])
    if tokens[1] == "backup":
        return {"status": "ok", "action": "restore_backup", "path": tokens[2], "passthrough": tokens[3:]}
    return {"status": "ok", "action": "restore_backup", "path": tokens[1], "passthrough": tokens[2:]}


def _match_add(tokens, role, names=None):
    client_role, server = _role_parts(role)
    if len(tokens) >= 2 and tokens[1] == "service" and client_role:
        return {"status": "ok", "action": "add_service", "passthrough": tokens[2:]}
    if len(tokens) >= 2 and tokens[1] == "client" and server:
        if len(tokens) < 5 or tokens[3] != "group":
            return incomplete("Missing group.", ["add client <CLIENT> group <GROUP>"])
        return {"status": "ok", "action": "add_group_member", "client": tokens[2], "group": tokens[4]}
    available = []
    if client_role:
        available.append("service")
    if server:
        available.append("client")
    return incomplete("Missing resource.", ["add service ...", "add client <CLIENT> group <GROUP>"], available)


def _match_remove(tokens, role, names=None):
    if len(tokens) < 5 or tokens[1] != "client" or tokens[3] != "group":
        return incomplete("Missing client or group.", ["remove client <CLIENT> group <GROUP>"], ["client"])
    return {"status": "ok", "action": "remove_group_member", "client": tokens[2], "group": tokens[4]}


def _match_delete(tokens, role, names=None):
    if len(tokens) < 2:
        return incomplete(
            "Missing resource.",
            ["delete group <GROUP>", "delete profile <PROFILE>"],
            ["group", "profile"],
        )
    if tokens[1] == "group":
        if len(tokens) < 3:
            return incomplete("Missing group selector.", ["delete group <GROUP>"], ["group"])
        return {"status": "ok", "action": "delete_group", "group": tokens[2]}
    if tokens[1] == "profile":
        if len(tokens) < 3:
            return incomplete("Missing profile selector.", ["delete profile <PROFILE>"], ["profile"])
        return {"status": "ok", "action": "delete_profile", "profile": tokens[2]}
    return incomplete(
        "Unknown delete resource.",
        ["delete group <GROUP>", "delete profile <PROFILE>"],
        ["group", "profile"],
    )


def _match_rename(tokens, role, names=None):
    if len(tokens) < 4 or tokens[1] != "group":
        return incomplete("Missing group selector or name.", ["rename group <GROUP> <name>"], ["group"])
    return {
        "status": "ok",
        "action": "set_group",
        "group": tokens[2],
        "property": "name",
        "value": tokens[3],
    }


def _match_enable_disable(tokens, role, names=None):
    verb = tokens[0]
    if len(tokens) < 2 or tokens[1] != "service":
        return incomplete("Missing resource.", ["%s service <service-id>" % verb], ["service"])
    if len(tokens) < 3:
        return incomplete("Missing service ID.", ["%s service <service-id>" % verb])
    return {"status": "ok", "action": "%s_service" % verb, "service": tokens[2]}


def _match_service(tokens, role, names=None):
    """Canonical client service namespace → same actions as legacy forms."""
    client, _server = _role_parts(role)
    if not client:
        return {"status": "role", "need": "client", "command": "service"}
    avail = ["add", "set", "enable", "disable", "apply", "discard"]
    if len(tokens) == 1:
        return incomplete(
            "Service management",
            [
                "service add ...",
                "service set <id> <property> <value>",
                "service enable <id>",
                "service disable <id>",
                "service apply",
                "service discard",
            ],
            avail,
            tip="service ?",
        )
    sub = tokens[1]
    if sub == "add":
        return {"status": "ok", "action": "add_service", "passthrough": tokens[2:]}
    if sub == "set":
        return _match_set(["set", "service"] + tokens[2:], role, names, form="canonical")
    if sub in ("enable", "disable"):
        return _match_enable_disable([sub, "service"] + tokens[2:], role, names)
    if sub == "apply":
        rest = tokens[2:]
        for tok in rest:
            if tok not in ("--verbose", "-v"):
                return incomplete("Unexpected arguments.", ["service apply", "service apply --verbose"])
        return {"status": "ok", "action": "apply", "passthrough": rest}
    if sub == "discard":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["service discard"])
        return {"status": "ok", "action": "discard"}
    return incomplete("Unknown service command.", ["service <op> ..."], avail, tip="service ?")


def _match_client_ns(tokens, role, names=None):
    """Client lifecycle namespace. Server legacy `client <ID>` falls through."""
    client, server = _role_parts(role)
    lifecycle = ["pause", "resume", "uninstall"]
    if len(tokens) == 1:
        if client:
            return incomplete(
                "Client lifecycle",
                ["client pause", "client resume", "client uninstall"],
                lifecycle,
                tip="client ?",
            )
        if server:
            return {"status": "legacy"}
        return {"status": "role", "need": "client", "command": "client"}
    sub = tokens[1]
    if client and sub in lifecycle:
        if len(tokens) > 2 and sub != "uninstall":
            return incomplete("Unexpected arguments.", ["client %s" % sub])
        action = "client_%s" % sub
        passthrough = tokens[2:] if sub == "uninstall" else []
        return {"status": "ok", "action": action, "passthrough": passthrough}
    # Compatibility: `client <ID>` → legacy frp-client-info on server hosts.
    if server and sub not in lifecycle:
        return {"status": "legacy"}
    if client:
        return incomplete("Unknown client command.", ["client pause|resume|uninstall"], lifecycle)
    return {"status": "role", "need": "client", "command": "client"}


def _match_system(tokens, role, names=None):
    client, server = _role_parts(role)
    if not client and not server:
        return {"status": "role", "need": "client or server", "command": "system"}
    avail = ["update", "doctor", "support-bundle"]
    if len(tokens) == 1:
        return incomplete(
            "System maintenance",
            [
                "system update [--check]",
                "system doctor",
                "system support-bundle [--output PATH]",
            ],
            avail,
            tip="system ?",
        )
    sub = tokens[1]
    if sub == "update":
        # Bare `system update` / `system update --check` → project tooling update.
        rest = tokens[2:]
        if not rest:
            return {"status": "ok", "action": "update_project", "passthrough": []}
        if rest[0].startswith("-"):
            return {"status": "ok", "action": "update_project", "passthrough": rest}
        if rest[0] == "project":
            return {"status": "ok", "action": "update_project", "passthrough": rest[1:]}
        if rest[0] == "frp":
            return {"status": "ok", "action": "update_frp", "passthrough": rest[1:]}
        return incomplete(
            "Unknown update target.",
            ["system update [--check]", "system update project [--check]", "system update frp [--check]"],
            ["project", "frp", "--check"],
        )
    if sub == "doctor":
        return {"status": "ok", "action": "doctor", "passthrough": tokens[2:]}
    if sub == "support-bundle":
        return {"status": "ok", "action": "support_bundle", "passthrough": tokens[2:]}
    return incomplete("Unknown system command.", ["system update|doctor|support-bundle"], avail)


def completion_candidates(
    line,
    role,
    names,
    services,
    local_services,
    trailing=None,
    groups=None,
    profiles=None,
):
    try:
        tokens = tokenize(line)
    except ParseError:
        return []
    if trailing is None:
        trailing = bool(line) and line[-1] in " \t"
    if not tokens:
        return canonical_verbs(role)
    if tokens[0].startswith("!") or tokens[0] in SHELL_REJECT:
        return []
    if not trailing and len(tokens) == 1:
        prefix = tokens[0]
        return [v for v in canonical_verbs(role) if v.startswith(prefix)]
    verb = tokens[0]
    if verb in LEGACY_COMMANDS:
        return _legacy_completion(tokens, trailing, role, names, services)
    return _canonical_completion(
        tokens,
        trailing,
        role,
        names,
        services,
        local_services,
        groups or [],
        profiles or [],
    )


def _service_add_completion(after_add, prefix=""):
    """Candidates after `service add` / `add service` (types only for normal UX)."""
    # Do not offer --id (or other raw flags) in normal Tab completion.
    # Automation may still pass hidden legacy flags explicitly.
    if not after_add:
        if str(prefix or "").startswith("--"):
            return []
        return list(SERVICE_ADD_TYPES)
    head = after_add[0]
    if head.startswith("--"):
        return []
    if head in SERVICE_ADD_TYPES:
        # After a type, prefer wizard; do not advertise flags.
        return []
    return []


def _tab_desc_map(line, role, names=None, clients=None):
    """Token -> short description for Tab candidate display (never secrets)."""
    names = names or []
    clients = clients or []
    try:
        tokens = tokenize(line)
    except ParseError:
        return {}, "plain"
    trailing = bool(line) and line[-1:] in " \t"
    filled = tokens if trailing else tokens[:-1]
    client, server = _role_parts(role)
    verb_map = {
        "show": "View status and configuration",
        "set": "Change configuration",
        "unset": "Remove configuration values",
        "create": "Create zero-touch enrollment or backup",
        "revoke": "Revoke management access",
        "purge": "Remove terminal enrollment metadata",
        "release": "Return reserved public ports",
        "update": "Update project or FRP",
        "restore": "Restore backup",
        "doctor": "Run health checks",
        "support-bundle": "Create sanitized diagnostic archive",
        "access": "Access Control Pack",
        "help": "Detailed help",
        "menu": "Guided menu",
        "history": "Session command history",
        "exit": "Leave frpctl",
        "clear": "Clear the screen",
        "status": "Host status shortcut",
        "version": "Installed versions shortcut",
        "service": "Manage published services",
        "client": "Control this FRP client",
        "system": "Maintenance and diagnostics",
        "add": "Add a local service (legacy)",
        "enable": "Enable a local service (legacy)",
        "disable": "Disable a local service (legacy)",
        "apply": "Apply pending local changes (legacy)",
        "discard": "Discard pending local changes (legacy)",
        "quit": "Leave frpctl",
        "q": "Leave frpctl",
    }
    if not server:
        verb_map.pop("access", None)
    if not filled:
        # Tab root candidates come from canonical_verbs only.
        keep = set(canonical_verbs(role))
        return {k: v for k, v in verb_map.items() if k in keep}, "verbs"
    verb = filled[0]
    if verb == "show" and len(filled) == 1:
        rows = {
            "status": "Host status",
            "version": "Installed versions",
            "clients": "Registered client table",
            "client": "One client (overview, services, or tags)",
            "enrollments": "Issued enrollment credentials",
            "audit": "Recent audit events",
            "upstream": "FRP upstream check",
            "services": "Local services",
            "info": "Local connection info",
        }
        return rows, "named"
    if verb == "set" and len(filled) == 1:
        rows = {}
        if server:
            rows["client"] = "Configure registered client metadata"
            rows["installer-url"] = "Configure client installer URL"
            rows["server"] = "Configure server access settings"
        if client:
            rows["service"] = "Configure a local service"
        return rows, "named"
    if verb == "set" and len(filled) >= 2 and filled[1] == "server":
        if len(filled) == 2:
            return {
                "hostname": "Optional public DNS hostname for published services",
                "bootstrap-hostname": "Optional Zero-Touch public TLS bootstrap hostname",
            }, "named"
    if verb == "set" and len(filled) >= 2 and filled[1] == "client":
        if len(filled) == 2:
            return {}, "clients"
        if len(filled) == 3:
            return {
                "label": "Administrator display label",
                "note": "Administrator description",
                "tag": "Key/value metadata",
            }, "named"
    if verb == "set" and client and len(filled) == 2 and filled[1] == "service":
        return {}, "local_services"
    if verb == "unset" and len(filled) == 1:
        return {
            "client": "Remove client metadata",
            "server": "Remove server access settings",
        }, "named"
    if verb == "unset" and len(filled) >= 2 and filled[1] == "server":
        if len(filled) == 2:
            return {
                "hostname": "Remove public DNS hostname",
                "bootstrap-hostname": "Remove Zero-Touch bootstrap hostname",
            }, "named"
    if verb == "unset" and len(filled) >= 2 and filled[1] == "client":
        if len(filled) == 2:
            return {}, "clients"
        if len(filled) == 3:
            return {
                "label": "Administrator display label",
                "note": "Administrator description",
                "tag": "Key/value metadata",
            }, "named"
    if verb == "create" and len(filled) == 1:
        return {
            "zero-touch": "Zero-touch enrollment (recommended)",
            "enrollment": "Manual Enrollment Code",
            "enrollments": "Bulk enrollment",
            "backup": "Server backup",
        }, "named"
    if verb == "revoke" and len(filled) == 1:
        return {
            "client": "Revoke management identity",
            "enrollment": "Revoke a pending enrollment",
        }, "named"
    if verb == "purge" and len(filled) == 1:
        return {
            "enrollment": "Permanently remove one terminal enrollment",
            "enrollments": "Bulk purge terminal enrollments by age",
        }, "named"
    if verb == "release" and len(filled) == 1:
        return {
            "client": "Release all reserved ports for a client",
            "service": "Release one service reservation",
        }, "named"
    if verb == "update" and len(filled) == 1:
        rows = {
            "project": "Update project management tools",
            "frp": "Update the FRP binary",
            "--check": "Check only",
        }
        return rows, "named"
    if verb == "service" and client and len(filled) == 1:
        return {
            "add": "Add a service",
            "set": "Change a service",
            "enable": "Enable a service",
            "disable": "Disable a service",
            "apply": "Apply pending service changes",
            "discard": "Discard pending service changes",
        }, "named"
    if verb == "service" and client and len(filled) >= 2 and filled[1] == "add":
        if len(filled) == 2:
            return {
                "ssh": "Publish an SSH service",
                "http": "Publish an HTTP service",
                "https": "Publish an HTTPS service",
                "custom": "Publish another TCP service",
                "profile": "Start from a server Service Profile",
            }, "named"
    if verb == "service" and client and len(filled) == 2 and filled[1] in (
        "set",
        "enable",
        "disable",
    ):
        return {}, "local_services"
    if verb == "add" and client and len(filled) >= 2 and filled[1] == "service":
        if len(filled) == 2:
            return {
                "ssh": "Publish an SSH service",
                "http": "Publish an HTTP service",
                "https": "Publish an HTTPS service",
                "custom": "Publish another TCP service",
                "profile": "Start from a server Service Profile",
            }, "named"
    if verb in ("enable", "disable") and client and len(filled) == 2 and filled[1] == "service":
        return {}, "local_services"
    if verb == "client" and client and len(filled) == 1:
        return {
            "pause": "Block all FRP remote access",
            "resume": "Resume FRP remote access",
            "uninstall": "Remove FRP Auto Deploy from this machine",
        }, "named"
    if verb == "system" and len(filled) == 1:
        return {
            "update": "Update FRP Auto Deploy",
            "doctor": "Run health checks",
            "support-bundle": "Create sanitized diagnostic archive",
        }, "named"
    if verb == "show" and len(filled) >= 2 and filled[1] == "client" and len(filled) == 2:
        return {}, "clients"
    if verb == "revoke" and len(filled) >= 2 and filled[1] == "client" and len(filled) == 2:
        return {}, "clients"
    if verb == "release" and len(filled) >= 2 and filled[1] == "client" and len(filled) == 2:
        return {}, "clients"
    return {}, "plain"


def format_tab_candidates(
    line,
    matches,
    role,
    names=None,
    clients=None,
    local_service_details=None,
):
    """Format ambiguous Tab matches for operator display. Never prints secrets."""
    matches = [m.rstrip() for m in (matches or []) if m is not None and str(m).strip()]
    if not matches:
        return ""
    descs, style = _tab_desc_map(line, role, names=names, clients=clients)
    if style == "clients":
        by_id = {}
        for item in clients or []:
            if isinstance(item, dict) and item.get("id"):
                by_id[str(item["id"])] = item
        lines = ["%-10s %-10s %s" % ("CLIENT ID", "LABEL", "HOSTNAME")]
        for mid in matches:
            item = by_id.get(mid) or {}
            lines.append(
                "%-10s %-10s %s"
                % (mid, item.get("label") or "-", item.get("hostname") or "-")
            )
        return "\n".join(lines)
    if style == "local_services":
        by_id = {}
        for item in local_service_details or []:
            if isinstance(item, dict) and item.get("id"):
                by_id[str(item["id"])] = item
        if by_id:
            lines = ["%-12s %-16s %-22s %s" % ("ID", "NAME", "TARGET", "STATE")]
            for mid in matches:
                item = by_id.get(mid) or {}
                name = item.get("name") or "-"
                target = item.get("target") or "-"
                enabled = item.get("enabled")
                if enabled is True:
                    state = "enabled"
                elif enabled is False:
                    state = "disabled"
                else:
                    state = str(item.get("state") or item.get("preset") or "-")
                lines.append(
                    "%-12s %-16s %-22s %s" % (mid, name, target, state)
                )
            return "\n".join(lines)
    if style in ("named", "verbs") and any(descs.get(m) for m in matches):
        # Prefer grammar insertion order over readline alphabetical sort.
        seen = set(matches)
        ordered = [k for k in descs if k in seen]
        ordered.extend(m for m in matches if m not in descs)
        width = max(len(m) for m in ordered) if ordered else 8
        lines = []
        for mid in ordered:
            desc = descs.get(mid) or ""
            if desc:
                lines.append("%s  %s" % (mid.ljust(width), desc))
            else:
                lines.append(mid)
        return "\n".join(lines)
    # Compact multi-column layout for plain token lists.
    col_w = max((len(m) for m in matches), default=8) + 2
    cols = max(1, min(4, 80 // col_w))
    lines = []
    for i in range(0, len(matches), cols):
        chunk = matches[i : i + cols]
        lines.append("".join(m.ljust(col_w) for m in chunk).rstrip())
    return "\n".join(lines)


def _current_prefix(tokens, trailing):
    if trailing:
        return ""
    return tokens[-1] if tokens else ""


def _filter(items, prefix):
    return [item for item in items if item.startswith(prefix)]


def _canonical_completion(tokens, trailing, role, names, services, local_services, groups, profiles=None):
    client, server = _role_parts(role)
    profiles = profiles or []
    prefix = _current_prefix(tokens, trailing)
    filled = tokens if trailing else tokens[:-1]
    if not filled:
        return _filter(canonical_verbs(role), prefix)
    verb = filled[0]
    if verb == "help":
        topics = [
            "show", "set", "unset", "create", "add", "remove", "delete",
            "rename", "update", "revoke", "purge", "release", "legacy",
            "service", "client", "system",
        ]
        if len(filled) == 1:
            return _filter(topics, prefix)
        if filled[1] == "show" and len(filled) == 2:
            return _filter(_show_resources(role), prefix)
        if filled[1] == "set" and len(filled) == 2:
            return _filter(_set_resources(role), prefix)
        return []
    if verb == "show":
        if len(filled) == 1:
            return _filter(_show_resources(role), prefix)
        if filled[1] == "client" and server:
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(["services", "tags", "groups"], prefix)
        if filled[1] == "group" and server and len(filled) == 2:
            return _filter(groups, prefix)
        if filled[1] == "profile" and server and len(filled) == 2:
            return _filter(profiles, prefix)
        return []
    if verb == "set":
        if len(filled) == 1:
            return _filter(_set_resources(role), prefix)
        if filled[1] == "client" and server:
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(["label", "note", "tag"], prefix)
        if filled[1] == "group" and server:
            if len(filled) == 2:
                return _filter(groups, prefix)
            if len(filled) == 3:
                return _filter(["name", "description"], prefix)
        if filled[1] == "profile" and server:
            if len(filled) == 2:
                return _filter(profiles, prefix)
            if len(filled) == 3:
                return _filter(
                    [
                        "name",
                        "description",
                        "preset",
                        "target-host",
                        "target-port",
                        "ssh-user",
                        "health-type",
                        "health-timeout",
                        "health-interval",
                        "health-max-failed",
                        "health-path",
                    ],
                    prefix,
                )
        if filled[1] == "server" and server:
            if len(filled) == 2:
                return _filter(["hostname", "bootstrap-hostname"], prefix)
        if filled[1] == "service" and client:
            if len(filled) == 2:
                return _filter(local_services, prefix)
            if len(filled) == 3:
                return _filter(list(SERVICE_SET_PROPS), prefix)
        return []
    if verb == "unset":
        if len(filled) == 1:
            return _filter(_unset_resources(role), prefix)
        if filled[1] == "server" and server:
            if len(filled) == 2:
                return _filter(["hostname", "bootstrap-hostname"], prefix)
        if filled[1] == "client":
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(["label", "note", "tag"], prefix)
        return []
    if verb == "create":
        if len(filled) == 1:
            return _filter(_create_resources(role), prefix)
        if filled[1] == "enrollment":
            return _filter(
                ["--one-line", "--ssh", "--ssh-user", "--ssh-port", "--ttl", "--note", "--label", "--client-name"],
                prefix,
            )
        if filled[1] == "enrollments":
            return _filter(["--count", "--csv", "--label-prefix", "--ssh-user", "--note", "--ttl"], prefix)
        return []
    if verb == "revoke":
        if len(filled) == 1:
            return _filter(["client", "enrollment"], prefix)
        if filled[1] == "client" and len(filled) == 2:
            return _filter(names, prefix)
        return []
    if verb == "purge":
        if len(filled) == 1:
            return _filter(["enrollment", "enrollments"], prefix)
        if filled[1] == "enrollments" and len(filled) == 2:
            return _filter(["--older-than"], prefix)
        return []
    if verb == "release":
        if len(filled) == 1:
            return _filter(["client", "service"], prefix)
        if filled[1] == "client" and len(filled) == 2:
            return _filter(names, prefix)
        if filled[1] == "service":
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(services.get(filled[2], []), prefix)
        return []
    if verb == "update":
        if len(filled) == 1:
            return _filter(["project", "frp", "--check"], prefix)
        if filled[1] in ("project", "frp"):
            return _filter(["--check"], prefix)
        return []
    if verb == "restore":
        if len(filled) == 1:
            return _filter(["backup"], prefix)
        return []
    if verb == "add":
        if len(filled) == 1:
            items = []
            if client:
                items.append("service")
            if server:
                items.append("client")
            return _filter(items, prefix)
        if filled[1] == "client" and server:
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(["group"], prefix)
            if len(filled) == 4:
                return _filter(groups, prefix)
        if filled[1] == "service" and client:
            return _filter(_service_add_completion(filled[2:], prefix), prefix)
        return []
    if verb in ("enable", "disable"):
        if len(filled) == 1:
            return _filter(["service"], prefix)
        if filled[1] == "service" and len(filled) == 2:
            return _filter(local_services, prefix)
        return []
    if verb == "service" and client:
        if len(filled) == 1:
            return _filter(
                ["add", "set", "enable", "disable", "apply", "discard"],
                prefix,
            )
        sub = filled[1]
        if sub == "add":
            return _filter(_service_add_completion(filled[2:], prefix), prefix)
        if sub == "set":
            if len(filled) == 2:
                return _filter(local_services, prefix)
            if len(filled) == 3:
                return _filter(list(SERVICE_SET_PROPS), prefix)
            return []
        if sub in ("enable", "disable"):
            if len(filled) == 2:
                return _filter(local_services, prefix)
            return []
        return []
    if verb == "client":
        if client and len(filled) == 1:
            return _filter(["pause", "resume", "uninstall"], prefix)
        # Compatibility: server `client <ID>` → frp-client-info
        if server and not client and len(filled) == 1:
            return _filter(names, prefix)
        return []
    if verb == "system":
        if len(filled) == 1:
            return _filter(["update", "doctor", "support-bundle"], prefix)
        if filled[1] == "update":
            return _filter(["project", "frp", "--check"], prefix)
        if filled[1] == "doctor":
            return _filter(["--json", "--verbose", "--quiet", "--skip-network"], prefix)
        if filled[1] == "support-bundle":
            return _filter(["--output"], prefix)
        return []
    if verb == "remove":
        if len(filled) == 1:
            return _filter(["client"], prefix)
        if filled[1] == "client":
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(["group"], prefix)
            if len(filled) == 4:
                return _filter(groups, prefix)
        return []
    if verb == "delete":
        if len(filled) == 1:
            return _filter(["group", "profile"], prefix)
        if filled[1] == "group" and len(filled) == 2:
            return _filter(groups, prefix)
        if filled[1] == "profile" and len(filled) == 2:
            return _filter(profiles, prefix)
        return []
    if verb == "rename":
        if len(filled) == 1:
            return _filter(["group"], prefix)
        if filled[1] == "group" and len(filled) == 2:
            return _filter(groups, prefix)
        return []
    if verb == "doctor":
        return _filter(["--json", "--verbose", "--quiet"], prefix)
    if verb == "support-bundle":
        return _filter(["--output"], prefix)
    return []


def _legacy_completion(tokens, trailing, role, names, services):
    prefix = _current_prefix(tokens, trailing)
    filled = tokens if trailing else tokens[:-1]
    cmd = filled[0] if filled else tokens[0]
    if cmd in ("client", "client-info", "revoke", "revoke-client", "release-client") and len(filled) == 1:
        return _filter(names, prefix)
    if cmd in ("client-set", "edit-client"):
        if len(filled) == 1:
            return _filter(names, prefix)
        return _filter(["--label", "--note", "--tag", "--remove-tag"], prefix)
    if cmd == "release-service":
        if len(filled) == 1:
            return _filter(names, prefix)
        if len(filled) == 2:
            return _filter(services.get(filled[1], []), prefix)
        return []
    if cmd in ("enroll", "create-client"):
        return _filter(
            ["--one-line", "--ssh", "--ssh-user", "--ssh-port", "--ttl", "--note", "--client-name", "--label"],
            prefix,
        )
    if cmd == "doctor":
        return _filter(["--json", "--verbose", "--quiet"], prefix)
    if cmd == "support-bundle":
        return _filter(["--output"], prefix)
    return []


def complete_line(line, role, names, services, local_services, groups=None, profiles=None):
    trailing = bool(line) and line[-1:] in " \t"
    cands = completion_candidates(
        line, role, names, services, local_services,
        trailing=trailing, groups=groups or [], profiles=profiles or [],
    )
    if not cands:
        return line
    if len(cands) == 1:
        return _replace_last(line, quote_token(cands[0]), add_space=True)
    shared = cands[0]
    for item in cands[1:]:
        while shared and not item.startswith(shared):
            shared = shared[:-1]
    prefix = ""
    try:
        tokens = tokenize(line)
        if tokens and not trailing:
            prefix = tokens[-1]
    except ParseError:
        prefix = ""
    if shared and shared != prefix:
        return _replace_last(line, shared, add_space=False)
    return line


def _replace_last(line, token, add_space):
    stripped = line.rstrip()
    if not stripped:
        new = token
    elif line[-1:] in " \t":
        new = stripped + " " + token
    else:
        try:
            tokens = tokenize(stripped)
        except ParseError:
            tokens = stripped.split()
        if len(tokens) <= 1:
            new = token
        else:
            head = stripped
            # Remove the last whitespace-separated raw suffix conservatively.
            idx = len(stripped)
            while idx > 0 and stripped[idx - 1] not in " \t":
                idx -= 1
            new = stripped[:idx] + token
    if add_space:
        new += " "
    return new


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        raise SystemExit("usage: frp_ctl_grammar.py tokenize|match|help|complete|complete-line ...")
    cmd = argv[0]
    if cmd == "tokenize":
        line = argv[1] if len(argv) > 1 else sys.stdin.read()
        try:
            tokens = tokenize(line)
        except ParseError as exc:
            sys.stderr.write("ERROR: %s\n" % exc)
            raise SystemExit(2)
        json.dump(tokens, sys.stdout)
        sys.stdout.write("\n")
        return 0
    payload = {}
    if not sys.stdin.isatty():
        raw = sys.stdin.read()
        if raw.strip():
            payload = json.loads(raw)
    role = payload.get("role") or (argv[2] if len(argv) > 2 else "server")
    names = payload.get("names") or []
    services = payload.get("services") or {}
    local_services = payload.get("local_services") or []
    groups = payload.get("groups") or []
    profiles = payload.get("profiles") or []
    if cmd == "match":
        tokens = payload.get("tokens") or argv[1:]
        json.dump(match(tokens, role, names=names, clients=payload.get("clients") or []), sys.stdout)
        sys.stdout.write("\n")
        return 0
    if cmd == "help":
        tokens = payload.get("tokens") or argv[1:]
        sys.stdout.write(help_text(tokens, role))
        return 0
    if cmd == "complete":
        line = payload.get("line") or (argv[1] if len(argv) > 1 else "")
        for item in completion_candidates(
            line, role, names, services, local_services, groups=groups, profiles=profiles
        ):
            sys.stdout.write(item + "\n")
        return 0
    if cmd == "complete-line":
        line = payload.get("line") or (argv[1] if len(argv) > 1 else "")
        sys.stdout.write(
            complete_line(
                line, role, names, services, local_services, groups=groups, profiles=profiles
            )
        )
        return 0
    raise SystemExit("unknown grammar action")


if __name__ == "__main__":
    raise SystemExit(main())
