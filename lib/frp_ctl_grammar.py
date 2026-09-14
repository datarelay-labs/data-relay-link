#!/usr/bin/env python3
"""Safe drlink tokenizer, command-tree help, and context-aware completion.

The canonical grammar is action-first (``<action> <resource> ...``) and is
described once in :mod:`frp_cli_catalog`. This module tokenizes, resolves a
canonical command against that catalog, rewrites hidden resource-first
compatibility aliases into action-first tokens, and renders help, context
help, and Tab completion from the same catalog.

No eval, no glob, no variable expansion, no command substitution.
Public UX never advertises GNU-style ``--options`` or backend ``frp-*`` names.
"""
from __future__ import annotations

import json
import os
import re
import sys


def _load_catalog():
    """Import the command catalog whether installed, vendored, or path-loaded."""
    try:
        import frp_cli_catalog as catalog  # noqa: WPS433
    except ImportError:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        try:
            import frp_cli_catalog as catalog  # noqa: WPS433
        except ImportError:
            import importlib.util

            path = os.path.join(here, "frp_cli_catalog.py")
            spec = importlib.util.spec_from_file_location("frp_cli_catalog", path)
            catalog = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(catalog)
            sys.modules["frp_cli_catalog"] = catalog
    return catalog


CATALOG = _load_catalog()

# Roots that also exist as historical flat commands. When the second token is
# not a canonical action, the old flat meaning wins so scripts keep working.
FALLTHROUGH_ROOTS = frozenset({"access", "egress"})

_CLIENT_ACTION_LIKE = frozenset(
    {
        "create",
        "delete",
        "add",
        "remove",
        "update",
        "restore",
        "backup",
        "release-service",
        "release-client",
        "client-set",
        "edit-client",
        "client-info",
        "revoke",
        "purge",
        "enroll",
        "create-client",
        "manage",
        "services",
        "info",
        "status",
        "show",
        "set",
        "unset",
    }
)

UNQUOTED_META = set("$`;|&><*?(){}[]")
LEGACY_COMMANDS = {
    "clients",
    "client",
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
SHELL_REJECT = {"shell", "exec", "bash", "sh", "system"}


class ParseError(ValueError):
    pass


def tokenize(line):
    """Split an operator line into tokens. Quotes group; metacharacters do not expand.

    Empty quoted tokens (``""`` / ``''``) are preserved. Adjacent quoted and
    unquoted segments concatenate into one token (``"a""b"`` → ``ab``).
    Token existence is tracked with ``token_started``, not buffer length.
    """
    tokens = []
    buf = []
    quote = None
    escaped = False
    token_started = False
    i = 0
    text = line if line is not None else ""

    def flush():
        nonlocal token_started
        if token_started:
            tokens.append("".join(buf))
            buf.clear()
            token_started = False

    while i < len(text):
        ch = text[i]
        if escaped:
            buf.append(ch)
            token_started = True
            escaped = False
            i += 1
            continue
        if quote:
            if ch == "\\" and quote == '"':
                escaped = True
                i += 1
                continue
            if ch == quote:
                # Close quote but keep the current token open so adjacent
                # quoted/unquoted segments concatenate.
                quote = None
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if ch in " \t":
            flush()
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            token_started = True
            i += 1
            continue
        if ch == "\\":
            escaped = True
            token_started = True
            i += 1
            continue
        if ch == "?" and not token_started:
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
        token_started = True
        i += 1
    if quote:
        raise ParseError("unclosed quote")
    if escaped:
        raise ParseError("trailing backslash")
    flush()
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
    """Canonical root resources for this host role (catalog order)."""
    return CATALOG.roots_for_role(role)


def _show_resources(role):
    client, server = _role_parts(role)
    items = ["status", "version"]
    if server:
        items.extend(
            [
                "clients",
                "client",
                "services",
                "groups",
                "group",
                "service-profiles",
                "service-profile",
                "access-lists",
                "access-list",
                "egress",
                "egress-profiles",
                "egress-profile",
                "enrollments",
                "enrollment",
                "audit",
                "upstream",
                "backups",
                "info",
            ]
        )
    if client and not server:
        items.extend(["services", "info"])
    elif client and server and "info" not in items:
        items.append("info")
    return items


def _set_resources(role):
    client, server = _role_parts(role)
    items = []
    if server:
        items.extend(["client", "group", "profile", "egress-profile", "installer-url", "server"])
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
        return ["zero-touch", "enrollment", "enrollments", "backup", "group", "service-profile", "egress-profile", "access-list", "support-bundle"]
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
        parts.extend(["", "Try:", "  %s" % tip])
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


def missing_client_help(usage_lines, names=None, tip="Press Tab after \"show client \" to select a client."):
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
            "  %s" % tip,
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
    if verb in ("workflow", "workflows"):
        return CATALOG.workflow_help(role)
    catalog_topic = _catalog_help_topic(tokens, role)
    if catalog_topic is not None:
        return catalog_topic
    # Hidden resource-first help topics → action-first usage redirect.
    if verb == "group":
        return (
            "Groups\n"
            "======\n\n"
            "Usage:\n"
            "  show groups\n"
            "  show group <GROUP>\n"
            "  create group <NAME>\n"
            "  set group <GROUP> description|name <value>\n"
            "  rename group <GROUP> <NAME>\n"
            "  add client <CLIENT> group <GROUP>\n"
            "  remove client <CLIENT> group <GROUP>\n"
            "  delete group <GROUP>\n"
        )
    # Action-first topics are served by _catalog_help_topic above.
    if verb == "update":
        return _update_help(role)
    if verb == "doctor":
        return (
            "Doctor\n======\n\nUsage:\n  doctor\n"
        )
    if verb == "support-bundle":
        return (
            "Support Bundle\n==============\n\n"
            "Usage:\n  create support-bundle\n\n"
            "Create a sanitized read-only diagnostic archive. Never includes private keys or tokens.\n"
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


def _catalog_help_topic(tokens, role):
    """Catalog-driven 'help <topic>' for canonical resources and commands."""
    if not tokens:
        return None
    root = canonical_root(tokens[0])
    probe = [root] + list(tokens[1:])
    cmd = CATALOG.find(probe)
    if cmd is not None and len(cmd["path"]) == len(probe):
        return CATALOG.command_help(cmd)
    if len(probe) == 1 and CATALOG.canonical_actions(root):
        text = CATALOG.resource_help(root, role)
        if text is not None:
            return text
    return None


def _root_help(role):
    return CATALOG.root_help(role)


def _root_help_legacy(role):
    client, server = _role_parts(role)
    lines = [
        "Data Relay Link CLI",
        "===================",
        "",
        "Grammar: <verb> <resource> [target] [property] [value]",
        "",
        "Discover commands with Tab. Type 'help <verb>' for details.",
        "",
        "Show",
        "  show status",
        "  show version",
    ]
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
                "  show clients",
                "  show client <ID> groups",
                "  set client <ID> label <value>",
                "  set client <ID> note <value>",
                "  set client <ID> tag <key> <value>",
                "  unset client <ID> label",
                "  unset client <ID> note",
                "  unset client <ID> tag <key>",
                "  create group <name>",
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
                "  add service",
                "  add service",
                "  set service <id> target-host <host>",
                "  set service <id> target-port <port>",
                "  set service <id> ssh-user <user>",
                "  set service <id> name <value>",
                "  set service <id> health-type <tcp|http|disabled>",
                "  set service <id> health-timeout <seconds>",
                "  set service <id> health-interval <seconds>",
                "  set service <id> health-max-failed <count>",
                "  set service <id> health-path </path>",
                "  enable service <id>",
                "  disable service <id>",
                "  apply",
                "  discard",
            ]
        )
    lines.extend(["", "Lifecycle"])
    if server:
        lines.extend(
            [
                "  create zero-touch",
                "  create enrollment",
                "  create enrollments",
                "  create backup",
                "  revoke enrollment <id>",
                "  delete enrollment <id>",
                "  revoke client <ID>",
                "  release service <ID> <service-id>",
                "  release client <ID>",
                "  restore backup <path>",
            ]
        )
    lines.extend(
        [
            "  update product",
            "  update engine",
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
            "  menu                 Guided numbered menu",
            "  history              This session only (not saved to disk)",
            "  help, ?",
            "  help legacy          Compatibility aliases",
            "  clear",
            "  exit",
            "",
            "status and version remain shortcuts for show status / show version.",
        ]
    )
    lines.extend(other)
    return "\n".join(lines) + "\n"


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
            "  show clients\n"
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
            "  set service <service-id> target-host <host>\n"
            "  set service <service-id> target-port <port>\n"
            "  set service <service-id> ssh-user <user>\n"
            "  set service <service-id> name <value>\n"
            "  set service <service-id> health-type <tcp|http|disabled>\n"
            "  set service <service-id> health-timeout <seconds>\n"
            "  set service <service-id> health-interval <seconds>\n"
            "  set service <service-id> health-max-failed <count>\n"
            "  set service <service-id> health-path </path>\n\n"
            "Service IDs cannot be renamed. Pending changes are live only after apply.\n"
            "Health checks are disabled by default. Enabling tcp/http uses FRP healthCheck.\n"
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
        "  unset server public-hostname\n"
        "  unset server bootstrap-hostname\n\n"
        "unset removes metadata only. It does not release ports or revoke identity.\n"
        "unset server public-hostname falls back to Public IP access.\n"
        "unset server bootstrap-hostname falls back to zt1 Zero-Touch commands.\n"
    )


def _create_help(role):
    return (
        "Create\n"
        "======\n\n"
        "Usage:\n"
        "  create zero-touch\n"
        "  create enrollment\n"
        "  create enrollments\n"
        "  create group <name>\n"
        "  create service-profile <name>\n"
        "  create access-list <name>\n"
        "  create egress-profile <name>\n"
        "  create backup [path]\n"
        "  create support-bundle\n\n"
        "Recommended:\n"
        "  create zero-touch\n\n"
        "Complex creates use guided prompts. Data Relay Link does not use "
        "--options.\n"
    )


def _update_help(role):
    return (
        "Update\n======\n\nUsage:\n"
        "  update product\n"
        "  update engine\n\n"
        "update product updates Data Relay Link management tools.\n"
        "update engine updates the pinned upstream FRP binary.\n"
        "A software update does not re-enroll clients or rotate CA/token/ports.\n"
    )


def _verb_help(verb, role):
    mapping = {
        "revoke": (
            "Revoke\n======\n\nUsage:\n"
            "  revoke client <CLIENT>\n"
            "  revoke enrollment <ENROLLMENT>\n\n"
            "revoke blocks management trust / credential use while preserving "
            "appropriate registry and reservation state.\n"
        ),
        "purge": (
            "Delete enrollment metadata\n"
            "==========================\n\n"
            "Canonical:\n"
            "  delete enrollment <ENROLLMENT>\n\n"
            "Deletes only terminal enrollment metadata "
            "(expired, completed, or revoked).\n"
            "Active enrollments must be revoked first.\n"
        ),
        "release": (
            "Release\n=======\n\nUsage:\n"
            "  release client <CLIENT>\n"
            "  release service <CLIENT> <SERVICE>\n\n"
            "release returns public port reservations. It is not revoke or unset.\n"
        ),
        "restore": "Restore\n=======\n\nUsage:\n  restore backup <BACKUP>\n",
        "add": (
            "Add\n===\n\nUsage:\n"
            "  add client <CLIENT> group <GROUP>\n"
            "  add egress-destination <PROFILE>\n"
            "  add egress-source <PROFILE>\n"
            "  add access-source <LIST>\n"
            "  add service\n\n"
            "Complex source/destination parameters use guided prompts.\n"
            "Pending client service changes apply with apply.\n"
        ),
        "enable": "Enable\n======\n\nUsage:\n  enable service <SERVICE>\n  enable egress-profile <PROFILE>\n",
        "disable": (
            "Disable\n=======\n\nUsage:\n"
            "  disable service <SERVICE>\n"
            "  disable egress-profile <PROFILE>\n\n"
            "Service public reservations remain until release service.\n"
        ),
        "remove": (
            "Remove\n======\n\nUsage:\n"
            "  remove client <CLIENT> group <GROUP>\n"
            "  remove egress-destination <PROFILE>\n"
            "  remove egress-source <PROFILE>\n"
            "  remove access-source <LIST>\n"
        ),
        "delete": (
            "Delete\n======\n\nUsage:\n"
            "  delete group <GROUP>\n"
            "  delete service-profile <PROFILE>\n"
            "  delete access-list <LIST>\n"
            "  delete egress-profile <PROFILE>\n"
            "  delete enrollment <ENROLLMENT>\n\n"
            "Destructive deletes ask for confirmation.\n"
        ),
        "rename": "Rename group\n============\n\nUsage:\n  rename group <GROUP> <name>\n",
    }
    return mapping.get(verb, "Usage:\n  %s\n" % verb)


def _legacy_help(role):
    return CATALOG.legacy_help(role)


def _fmt_available(rows):
    parts = ["Available:", ""]
    width = max((len(name) for name, _desc in rows), default=8)
    for name, desc in rows:
        parts.append("  %s  %s" % (name.ljust(width), desc))
    return "\n".join(parts) + "\n"


def _catalog_context_help(tokens, role, names=None, clients=None):
    """Catalog-driven '?' help for the canonical resource-first grammar."""
    if not tokens:
        return None
    root = canonical_root(tokens[0])
    actions = CATALOG.canonical_actions(root)
    if not actions:
        return None
    rows = CATALOG.subcommands(root, role)
    if len(tokens) == 1:
        if not rows:
            return None
        return _fmt_available(rows)
    if tokens[1] not in actions:
        if root in FALLTHROUGH_ROOTS:
            return None
        if not rows:
            return None
        return _fmt_available(rows)
    probe = [root] + list(tokens[1:])
    cmd = CATALOG.find(probe)
    if cmd is None or not CATALOG.role_allows(cmd["roles"], role):
        return None
    index = len(probe) - len(cmd["path"])
    if index < len(cmd["args"]):
        arg = cmd["args"][index]
        complete = arg["complete"]
        if complete == CATALOG.C_CLIENT:
            return _context_client_list(names, clients)
        if isinstance(complete, (list, tuple)):
            return _fmt_available([(item, "") for item in complete])
    return CATALOG.command_help(cmd)


def context_help(tokens, role, names=None, clients=None):
    """Enter-submitted '?' help. Tab must never call this."""
    client, server = _role_parts(role)
    tokens = [t for t in (tokens or []) if t != "?"]
    if not tokens:
        return _concise_root(role)
    if tokens == ["release"] and server:
        return (
            "release client <CLIENT>\n"
            "  Revoke port reservations for the whole client and clear its registry entry.\n\n"
            "release service <CLIENT> <SERVICE>\n"
            "  Release one service reservation only; the client record remains.\n\n"
            "These are destructive. Prefer revoke when you only need to block management trust.\n"
        )
    if tokens == ["revoke"] and server:
        return (
            "revoke client <CLIENT>\n"
            "  Block management trust / credential use for a registered client.\n\n"
            "revoke enrollment <ENROLLMENT>\n"
            "  Prevent a pending or bound enrollment credential from being used.\n\n"
            "Revoke preserves the appropriate registry/reservation state.\n"
            "Use release to free ports, or delete enrollment for terminal metadata only.\n"
        )
    if tokens == ["delete"] and server:
        return (
            "delete group <GROUP>\n"
            "delete service-profile <PROFILE>\n"
            "delete access-list <LIST>\n"
            "delete egress-profile <PROFILE>\n"
            "delete enrollment <ENROLLMENT>\n\n"
            "delete enrollment removes terminal enrollment metadata only.\n"
            "If the enrollment is still active, revoke it first:\n"
            "  revoke enrollment <ID>\n"
        )
    catalog_text = _catalog_context_help(tokens, role, names=names, clients=clients)
    if catalog_text is not None:
        return catalog_text
    verb = tokens[0]
    if verb == "show":
        if len(tokens) == 1:
            rows = [("status", "Host status"), ("version", "Installed versions")]
            if server:
                rows.extend(
                    [
                        ("clients", "Registered client table"),
                        ("client", "One client (overview, services, or tags)"),
                        ("enrollment", "Enrollment credentials (list/create/revoke)"),
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
                        ("public-hostname", "Optional public DNS hostname for published services"),
                        ("bootstrap-hostname", "Optional Zero-Touch public TLS bootstrap hostname"),
                    ]
                )
            if tokens[2] == "bootstrap-hostname":
                return (
                    "Usage:\n"
                    "  set server bootstrap-hostname <fqdn>\n\n"
                    "Purpose:\n"
                    "  Set the publicly trusted Zero-Touch short URL hostname.\n"
                    "  Data Relay Link does not create DNS or issue certificates.\n"
                    "  Operator terminates public TLS on a reverse proxy.\n\n"
                    "Example:\n"
                    "  set server bootstrap-hostname bootstrap.example.com\n\n"
                    "Remove:\n"
                    "  unset server bootstrap-hostname\n"
                )
            return (
                "Usage:\n"
                "  set server public-hostname <fqdn>\n\n"
                "Purpose:\n"
                "  Set an optional DNS alias for published service access.\n"
                "  FRP control continues to use the Public IP.\n\n"
                "Example:\n"
                "  set server public-hostname frp.example.com\n\n"
                "Remove:\n"
                "  unset server public-hostname\n"
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
                "  unset server public-hostname\n"
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
                "  enrollment create\n"
                "  enrollment create [--one-line] [--ssh --ssh-user USER --label NAME]\n\n"
                "Generate a Manual Enrollment Code for interactive client install.\n"
                "For everyday onboarding prefer: create zero-touch\n"
            )
        if len(tokens) >= 2 and tokens[1] == "enrollments":
            return (
                "Bulk enrollment\n"
                "===============\n\n"
                "Usage:\n"
                "  enrollment bulk --count N\n"
                "  enrollment bulk --csv FILE\n"
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
    return help_text(tokens, role)


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
    return CATALOG.concise_root(role)


def _concise_root_legacy(role):
    client, server = _role_parts(role)
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
        ("exit", "Leave drlink"),
    ]
    if not server:
        hide = {"create", "revoke", "purge", "release", "restore", "access"}
        if not client:
            hide.update({"set", "unset"})
        rows = [(n, d) for n, d in rows if n not in hide]
        if client:
            rows = [(n, d) for n, d in rows if n not in {"revoke", "purge", "release", "restore", "create", "access"}]
            extra = [
                ("add", "Add a local service"),
                ("enable", "Enable a local service"),
                ("disable", "Disable a local service"),
                ("apply", "Apply pending service changes"),
                ("discard", "Discard pending service changes"),
            ]
            # Keep a stable everyday list for client-only hosts.
            keep = {
                "show", "set", "add", "enable", "disable", "apply", "discard",
                "update", "doctor", "support-bundle", "help", "menu", "history", "exit",
            }
            rows = extra + rows
            rows = [(n, d) for n, d in rows if n in keep]
    return _fmt_available([(n, d) for n, d in rows])


def canonical_root(token):
    """Normalize a root token, resolving hidden resource aliases."""
    if token == "profile":
        return "service-profile"
    if token == "egress-profile":
        return "egress"
    return token


def _looks_like_client_action(token):
    text = str(token or "").strip()
    if not text or text.startswith("-"):
        return False
    # Hyphenated tokens may be either action verbs (release-service) or client
    # IDs (customer-dp). Prefer the explicit allowlist; unknown hyphen forms
    # fall through to the legacy client-id shortcut when they are not catalog
    # actions.
    return text.lower() in _CLIENT_ACTION_LIKE


def _client_legacy_selector(tokens, names=None):
    """True when ``client <ID> [view]`` should keep the legacy shortcut.

    Only known-looking client selectors fall through. Unknown second tokens
    stay with the canonical parser as terminal syntax errors.
    """
    if len(tokens) < 2:
        return False
    second = str(tokens[1] or "").strip()
    actions = CATALOG.canonical_actions("client")
    if second in actions or second.startswith("-"):
        return False
    if _looks_like_client_action(second):
        return False
    if len(tokens) > 4:
        return False
    known = {str(n).strip().lower() for n in (names or []) if str(n).strip()}
    looks_id = bool(re.fullmatch(r"[0-9a-fA-F]{6,32}", second))
    looks_named = second.lower() in known
    # Allow common short labels/hostnames used in legacy scripts when they
    # contain a hyphen or look like inventory names (alphanumeric + -._).
    looks_label = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", second)) and (
        "-" in second or "." in second or looks_named or looks_id
    )
    if not (looks_id or looks_named or looks_label):
        return False
    if len(tokens) == 3:
        return tokens[2] in ("services", "tags", "groups", "info", "overview")
    return len(tokens) == 2


def canonical_tokens(tokens):
    """Return the canonical token list, or None when this is not canonical.

    A root that also exists as a historical flat command only becomes
    canonical when the second token is a known action for that resource.
    """
    if not tokens:
        return None
    root = canonical_root(tokens[0])
    actions = CATALOG.canonical_actions(root)
    if not actions:
        cmd = CATALOG.find([root])
        if cmd is None or len(cmd["path"]) != 1:
            return None
        return [root] + list(tokens[1:])
    if len(tokens) < 2 or tokens[1] not in actions:
        return None
    return [root] + list(tokens[1:])


def public_option_error(tokens):
    return public_option_rejection(tokens)


def public_option_rejection(tokens):
    """Reject public GNU-style option tokens with a drlink-owned message.

    Always reject bare ``--`` / ``-``. Also reject dash tokens on guided
    create/onboarding commands so backend argparse never leaks.
    """
    toks = [str(t) for t in (tokens or ())]
    bad = None
    for tok in toks:
        if tok in ("-", "--") or tok.startswith("-"):
            bad = tok
            break
    if bad is None:
        return None
    focus = [t for t in toks if not t.startswith("-")]
    # Guided / no-flag public commands (reject all dash tokens).
    # Enrollment / zero-touch / destination create flows are prompt-driven.
    # Other commands may still accept catalog-declared hidden machine flags.
    guided_prefixes = (
        ("create", "enrollment"),
        ("create", "enrollments"),
        ("create", "zero-touch"),
        ("add", "egress-destination"),
        ("delete", "enrollment"),
        ("enrollment", "create"),
        ("enrollment", "bulk"),
        ("enrollment", "purge"),
        ("zero-touch", "create"),
        ("egress", "add-destination"),
    )
    is_guided = False
    for prefix in guided_prefixes:
        if tuple(focus[: len(prefix)]) == prefix:
            is_guided = True
            break
    if bad not in ("-", "--") and not is_guided:
        return None
    hint = " ".join(focus[:2]) if len(focus) >= 2 else (focus[0] if focus else "help")
    return {
        "status": "error",
        "exit_code": 2,
        "message": (
            "Unknown input: %s\n\n"
            "Data Relay Link commands do not use --options.\n\n"
            "Run:\n"
            "  %s\n\n"
            "and follow the guided prompts."
        )
        % (bad, hint),
    }


def _machine_allowed_flags(tokens):
    """Hidden machine/script flags still accepted for a resolved command.

    Public Tab/help never advertise these; they exist for automation and
    backend passthrough only.
    """
    toks = [str(t) for t in (tokens or ())]
    allowed = set()
    if toks and toks[0] == "doctor":
        allowed.update({"--json", "--verbose"})
    if toks[:2] in (
        ["update", "product"],
        ["update", "engine"],
        ["update", "project"],
        ["update", "frp"],
    ):
        allowed.add("--check")
    cmd = CATALOG.find(toks)
    if cmd is None:
        focus = [t for t in toks if not t.startswith("-")]
        cmd = CATALOG.find(focus)
    if cmd is not None:
        allowed.update(CATALOG.flag_names(cmd.get("flags") or (), include_hidden=True))
    return allowed


def _option_rejection_message(tok, focus):
    return {
        "status": "error",
        "exit_code": 2,
        "message": (
            "Unknown input: %s\n\n"
            "Data Relay Link commands do not use --options.\n\n"
            "Run:\n"
            "  %s\n\n"
            "and follow the guided prompts when more detail is required."
        )
        % (tok, focus),
    }


def _canonical_result(tokens, role, names=None):
    """Resolve canonical action-first commands; expand hidden resource-first.

    Returns ``(internal_tokens, error_result)``. ``internal_tokens`` is None
    when the caller should keep the original tokens for verb-handler matching.
    """
    if not tokens:
        return None, None

    opt_err = public_option_error(tokens)
    if opt_err is not None:
        return None, opt_err

    # Hidden resource-first compatibility → action-first.
    expanded = None
    if hasattr(CATALOG, "expand_compat_alias"):
        expanded = CATALOG.expand_compat_alias(tokens)
    work = list(expanded) if expanded is not None else list(tokens)

    cmd = CATALOG.find(work)
    if cmd is None:
        root = canonical_root(work[0])
        if root == "client" and _client_legacy_selector(work, names=names):
            return None, None
        if root in FALLTHROUGH_ROOTS:
            return None, None
        return None, None

    if not CATALOG.role_allows(cmd["roles"], role):
        return None, {
            "status": "role",
            "need": cmd["roles"],
            "command": " ".join(cmd["path"]),
        }
    problem = CATALOG.strict_error(work)
    if problem:
        if "flag" in problem or "required flag" in problem or problem.startswith("missing value for -"):
            return None, public_option_rejection(work + ["--"]) or {
                "status": "error",
                "exit_code": 2,
                "message": (
                    "Data Relay Link commands do not use --options.\n"
                    "Run the action and follow guided prompts."
                ),
            }
        return None, {"status": "error", "message": problem}
    internal = CATALOG.to_internal(work)
    if internal is None:
        return None, None
    return internal, None


def match(tokens, role, names=None, clients=None):
    if not tokens:
        return {"status": "empty"}
    # Binary shell meta-flags (not REPL command options).
    if list(tokens) in (["--help"], ["-h"]):
        return {"status": "unknown", "command": tokens[0]}
    if tokens[-1] == "?":
        focus = CATALOG.resolve_tokens(tokens[:-1], role=role)
        return {
            "status": "ok",
            "action": "context_help",
            "focus": focus,
            "message": context_help(focus, role, names=names, clients=clients),
        }
    # Hidden resource-first compatibility → canonical action-first tokens.
    tokens = CATALOG.resolve_tokens(tokens, role=role)
    opt_err = public_option_error(tokens)
    if opt_err is None:
        # Reject undeclared dash tokens. Catalog-declared flags and a small
        # set of machine interfaces remain callable but never Tab/help-advertised.
        allowed = _machine_allowed_flags(tokens)
        for tok in tokens:
            raw = str(tok)
            if raw in ("-h", "--help"):
                continue
            if raw in allowed:
                continue
            # Flag values are not options (e.g. --ttl 4h).
            name = raw.split("=", 1)[0]
            if name in allowed:
                continue
            if raw == "--" or raw.startswith("--") or (
                len(raw) >= 2 and raw.startswith("-") and not raw[1:].replace(".", "", 1).isdigit()
            ):
                focus = " ".join(t for t in tokens if not str(t).startswith("-")) or "help"
                opt_err = _option_rejection_message(raw, focus)
                break
    if opt_err is not None:
        return opt_err
    verb = tokens[0]
    if verb.startswith("!") or verb in SHELL_REJECT:
        return {"status": "shell"}
    internal, problem = _canonical_result(tokens, role, names=names)
    if problem is not None:
        return problem
    rewritten = internal is not None
    if rewritten:
        tokens = internal
        verb = tokens[0]
    # Hidden resource-first bare roots must discover, never mutate.
    if not rewritten and list(tokens) == ["backup"]:
        return incomplete(
            "Missing action.",
            ["create backup [path]", "restore backup <path>"],
            available=["create", "restore"],
        )
    # Resource-first client root: unknown actions must not fall through as a
    # client-id shortcut (e.g. "client release-service").
    if (
        not rewritten
        and verb == "client"
        and len(tokens) >= 2
        and not _client_legacy_selector(tokens, names=names)
    ):
        actions = sorted(set(CATALOG.canonical_actions("client")) | set(_CLIENT_ACTION_LIKE))
        return incomplete(
            "Unknown action.",
            ["client <ID>", "show client <ID>", "revoke client <ID>", "release client <ID>"],
            available=actions[:12] or None,
            tip="Use action-first commands such as show client / revoke client / release client.",
        )
    if not rewritten and verb in LEGACY_COMMANDS:
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
        "doctor": lambda toks, role, names=None: {"status": "ok", "action": "doctor", "passthrough": toks[1:]},
        "support-bundle": lambda toks, role, names=None: {"status": "ok", "action": "support_bundle", "passthrough": toks[1:]},
        "access": lambda toks, role, names=None: {"status": "ok", "action": "access_cmd", "passthrough": toks[1:]},
        "egress": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": toks[1:]},
        "help": lambda toks, role, names=None: {"status": "ok", "action": "help", "passthrough": toks[1:]},
        "?": lambda toks, role, names=None: {"status": "ok", "action": "help", "passthrough": toks[1:]},
        "menu": lambda toks, role, names=None: {"status": "ok", "action": "menu"},
        "history": lambda toks, role, names=None: {"status": "ok", "action": "history"},
        "clear": lambda toks, role, names=None: {"status": "ok", "action": "clear"},
        "exit": lambda toks, role, names=None: {"status": "ok", "action": "exit"},
        "quit": lambda toks, role, names=None: {"status": "ok", "action": "exit"},
        "q": lambda toks, role, names=None: {"status": "ok", "action": "exit"},
        "status": lambda toks, role, names=None: {"status": "ok", "action": "show_status", "passthrough": toks[1:]},
        "server-status": lambda toks, role, names=None: {"status": "ok", "action": "show_server_status", "passthrough": toks[1:]},
        "version": lambda toks, role, names=None: {"status": "ok", "action": "show_version"},
        "test": lambda toks, role, names=None: (
            {"status": "ok", "action": "access_cmd", "passthrough": ["test"] + list(toks[2:])}
            if len(toks) > 1 and toks[1] == "access"
            else {"status": "ok", "action": "egress_cmd", "passthrough": list(toks[1:])}
        ),
        "explain": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": ["explain"] + list(toks[2:])},
        "export": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": ["export"] + list(toks[2:])},
        "import": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": ["import"] + list(toks[2:])},
        "diff": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": ["diff"] + list(toks[2:])},
    }
    fn = handlers.get(verb)
    if fn is None:
        return {"status": "unknown", "command": verb}
    if verb in ("set", "unset", "create", "revoke", "purge", "release", "restore", "remove", "delete", "rename", "access", "egress") and not server and verb != "set":
        if verb == "set" and client:
            return fn(tokens, role, names)
        return {"status": "role", "need": "server", "command": verb}
    if verb in ("apply", "discard") and not client:
        return {"status": "role", "need": "client", "command": verb}
    if verb in ("enable", "disable"):
        if not client and not server:
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
        if len(tokens) > 3:
            return incomplete(
                "Unexpected arguments.",
                ["show clients", "show clients <GROUP>"],
            )
        if len(tokens) == 3:
            group = tokens[2]
            if str(group).startswith("-"):
                return {
                    "status": "error",
                    "exit_code": 2,
                    "message": (
                        "Unknown input: %s\n\n"
                        "Data Relay Link commands do not use --options.\n\n"
                        "Run:\n  show clients <GROUP>\n"
                        % group
                    ),
                }
            return {
                "status": "ok",
                "action": "show_clients",
                "passthrough": ["--group", group],
            }
        return {"status": "ok", "action": "show_clients", "passthrough": []}
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
    if resource in ("profile", "service-profile"):
        if len(tokens) < 3:
            return incomplete("Missing profile selector.", ["show profile <PROFILE>"])
        if len(tokens) > 3:
            return incomplete("Unexpected arguments.", ["show profile <PROFILE>"])
        return {"status": "ok", "action": "show_profile", "profile": tokens[2]}
    if resource == "egress-profiles":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["show egress-profiles"])
        return {"status": "ok", "action": "show_egress_profiles"}
    if resource == "access-lists":
        return {"status": "ok", "action": "access_cmd", "passthrough": ["list"] + list(tokens[2:])}
    if resource == "access-list":
        if len(tokens) < 3:
            return incomplete("Missing access list.", ["show access-list <LIST>"])
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["show", tokens[2]] + list(tokens[3:]),
        }
    if resource == "access-service":
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["show-service"] + list(tokens[2:]),
        }
    if resource == "access-log":
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["log"] + list(tokens[2:]),
        }
    if resource == "egress":
        return {"status": "ok", "action": "egress_cmd", "passthrough": ["status"] + list(tokens[2:])}
    if resource == "service-profiles":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["show service-profiles"])
        return {"status": "ok", "action": "show_profiles"}
    if resource == "backups":
        return incomplete("Use create backup / restore backup.", ["create backup", "restore backup <path>"])
    if resource == "egress-profile":
        if len(tokens) < 3:
            return incomplete("Missing egress profile selector.", ["show egress-profile <PROFILE>"])
        if len(tokens) > 3:
            return incomplete("Unexpected arguments.", ["show egress-profile <PROFILE>"])
        return {"status": "ok", "action": "show_egress_profile", "profile": tokens[2]}
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
                tip="Press Tab after \"show client \" to select a client.",
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


def _match_set(tokens, role, names=None):
    client, server = _role_parts(role)
    avail = _set_resources(role)
    if len(tokens) == 1:
        return incomplete("Missing resource.", ["set <resource> ..."], avail, tip="drlink help set")
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
                tip="drlink help set",
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
                    tip="drlink help set",
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
    if resource in ("profile", "service-profile"):
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
        # Allow trailing --ssh-user for atomic non-SSH → SSH transitions.
        idx = 5
        while idx < len(tokens):
            if not str(tokens[idx]).startswith("-"):
                return {
                    "status": "error",
                    "message": "Too many arguments. Quote values that contain spaces.",
                }
            idx += 1
            if idx < len(tokens) and not str(tokens[idx]).startswith("-"):
                idx += 1
        return {
            "status": "ok",
            "action": "set_profile",
            "profile": tokens[2],
            "property": tokens[3],
            "value": tokens[4],
            "passthrough": tokens[5:],
        }
    if resource == "service":
        if not client:
            return {"status": "role", "need": "client", "command": "set service"}
        props = ["target-host", "target-port", "ssh-user", "name",
                 "health-type", "health-timeout", "health-interval",
                 "health-max-failed", "health-path"]
        if len(tokens) < 3:
            return incomplete("Missing service ID.", ["set service <service-id> <property> <value>"])
        if len(tokens) < 4:
            return incomplete(
                "Missing service property.",
                ["set service <service-id> <property> <value>"],
                props,
            )
        if tokens[3] not in props:
            return incomplete("Unknown service property.", ["set service <id> <property> <value>"], props)
        if len(tokens) < 5:
            return incomplete("Missing value.", ["set service <id> %s <value>" % tokens[3]])
        return {
            "status": "ok",
            "action": "set_service",
            "service": tokens[2],
            "property": tokens[3],
            "value": tokens[4],
        }
    if resource == "access-list":
        if len(tokens) < 3:
            return incomplete(
                "Missing access list.",
                ["set access-list <LIST>"],
            )
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["edit-info"] + list(tokens[2:]),
        }
    if resource == "access-source":
        if len(tokens) < 3:
            return incomplete("Missing access list.", ["set access-source <LIST>"])
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["replace-source"] + list(tokens[2:]),
        }
    if resource == "access-assign":
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["assign"] + list(tokens[2:]),
        }
    if resource == "access-public":
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["public"] + list(tokens[2:]),
        }
    if resource == "egress-profile":
        if not server:
            return {"status": "role", "need": "server", "command": "set egress-profile"}
        if len(tokens) < 3:
            return incomplete(
                "Missing egress profile selector.",
                [
                    "set egress-profile <PROFILE> name <VALUE>",
                    "set egress-profile <PROFILE> description <VALUE>",
                ],
            )
        # Canonical property form.
        if len(tokens) >= 4 and tokens[3] in ("name", "description"):
            if len(tokens) < 5:
                return incomplete(
                    "Missing value.",
                    ["set egress-profile <PROFILE> %s <value>" % tokens[3]],
                )
            if len(tokens) > 5:
                return {
                    "status": "error",
                    "message": "Too many arguments. Quote values that contain spaces.",
                }
            return {
                "status": "ok",
                "action": "set_egress_profile",
                "profile": tokens[2],
                "passthrough": ["--%s" % tokens[3], tokens[4]],
            }
        return {
            "status": "ok",
            "action": "set_egress_profile",
            "profile": tokens[2],
            "passthrough": tokens[3:],
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
        # Canonical: public-hostname. Hidden compat: hostname.
        server_settings = ["public-hostname", "bootstrap-hostname"]
        if len(tokens) < 3:
            return incomplete(
                "Missing server setting.",
                [
                    "set server public-hostname <fqdn>",
                    "set server bootstrap-hostname <fqdn>",
                ],
                server_settings,
                tip="drlink help set",
            )
        setting = tokens[2]
        if setting == "hostname":
            setting = "public-hostname"
        if setting not in server_settings:
            return incomplete(
                "Unknown server setting.",
                [
                    "set server public-hostname <fqdn>",
                    "set server bootstrap-hostname <fqdn>",
                ],
                server_settings,
            )
        if len(tokens) < 4:
            return incomplete(
                "Missing hostname.",
                ["set server %s <fqdn>" % setting],
                tip="drlink help set",
            )
        if len(tokens) > 4:
            return {
                "status": "error",
                "message": "Too many arguments. Quote values that contain spaces.",
            }
        if setting == "public-hostname":
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
            ["unset client <ID> <setting>", "unset server public-hostname"],
            avail,
        )
    if tokens[1] == "server":
        if len(tokens) < 3:
            return incomplete(
                "Missing server setting.",
                ["unset server public-hostname", "unset server bootstrap-hostname"],
                ["public-hostname", "bootstrap-hostname"],
                tip="drlink help unset",
            )
        setting = tokens[2]
        if setting == "hostname":
            setting = "public-hostname"
        if setting not in ("public-hostname", "bootstrap-hostname"):
            return incomplete(
                "Unknown server setting.",
                ["unset server public-hostname", "unset server bootstrap-hostname"],
                ["public-hostname", "bootstrap-hostname"],
            )
        if len(tokens) > 3:
            return {
                "status": "error",
                "message": "Too many arguments.",
            }
        if setting == "public-hostname":
            return {"status": "ok", "action": "unset_server_hostname"}
        return {"status": "ok", "action": "unset_server_bootstrap_hostname"}
    if tokens[1] != "client":
        return incomplete(
            "Unknown unset resource.",
            ["unset client <ID> <setting>", "unset server public-hostname"],
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
                tip="drlink help unset",
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
                tip="drlink help create",
            )
        return {"status": "ok", "action": "create_zero_touch"}
    if resource == "enrollment":
        return {
            "status": "ok",
            "action": "create_enrollment",
            "passthrough": tokens[2:],
            "guided": len(tokens) == 2,
        }
    if resource == "enrollments":
        return {"status": "ok", "action": "create_enrollments", "passthrough": tokens[2:]}
    if resource == "backup":
        return {"status": "ok", "action": "create_backup", "passthrough": tokens[2:]}
    if resource == "group":
        if len(tokens) < 3:
            return incomplete("Missing group name.", ["create group <name>"])
        description = ""
        if len(tokens) > 3:
            if len(tokens) != 5 or tokens[3] != "--description":
                return incomplete("Unexpected arguments.", ["create group <name>"])
            description = tokens[4]
        return {
            "status": "ok",
            "action": "create_group",
            "name": tokens[2],
            "description": description,
        }
    if resource in ("profile", "service-profile"):
        if len(tokens) < 3:
            return incomplete(
                "Missing profile name.",
                ["create service-profile <name>"],
            )
        return {
            "status": "ok",
            "action": "create_profile",
            "name": tokens[2],
            "passthrough": tokens[3:],
        }
    if resource == "access-list":
        if len(tokens) < 3:
            return incomplete(
                "Missing access list name.",
                ["create access-list <NAME>"],
            )
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["create"] + list(tokens[2:]),
        }
    if resource == "egress-profile":
        if len(tokens) < 3:
            return incomplete(
                "Missing egress profile name.",
                ["create egress-profile <name>"],
            )
        description = ""
        if len(tokens) > 3:
            if len(tokens) != 5 or tokens[3] != "--description":
                return incomplete(
                    "Unexpected arguments.",
                    ["create egress-profile <name>"],
                )
            description = tokens[4]
        return {
            "status": "ok",
            "action": "create_egress_profile",
            "name": tokens[2],
            "description": description,
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
                tip='Press Tab after "revoke client " to select a client.',
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
            return incomplete("Missing enrollment id.", ["delete enrollment <ID>"])
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
        ["delete enrollment <ID>", "delete enrollments older-than <days>"],
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
                tip='Press Tab after "release client " to select a client.',
            )
        return {"status": "ok", "action": "release_client", "client": tokens[2], "passthrough": tokens[3:]}
    if tokens[1] == "service":
        if len(tokens) < 3:
            return missing_client_help(
                ["release service <ID> <service-id>"],
                names,
                tip='Press Tab after "release client " to select a client.',
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
        return incomplete(
            "Missing update target.",
            ["update product", "update engine"],
            ["product", "engine"],
            tip="drlink help update",
        )
    resource = tokens[1]
    if resource in ("product", "project", "frp", "engine") or resource.startswith("-"):
        if resource.startswith("-"):
            return public_option_rejection(tokens) or {
                "status": "error",
                "exit_code": 2,
                "message": "Data Relay Link commands do not use --options.",
            }
        action = "update_project" if resource in ("product", "project") else "update_frp"
        if resource in ("frp", "engine") and not server and not client_role:
            return {"status": "role", "need": "client or server", "command": "update engine"}
        return {"status": "ok", "action": action, "passthrough": tokens[2:]}
    avail = ["product", "engine"]
    return incomplete(
        "Unknown update target.",
        ["update product", "update engine"],
        avail,
        tip="drlink help update",
    )


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
    if len(tokens) >= 2 and tokens[1] == "egress-destination" and server:
        if len(tokens) < 3:
            return incomplete(
                "Missing egress profile.",
                ["add egress-destination <PROFILE>"],
                tip="Press Tab after \"add egress-destination \" to select a profile.",
            )
        # Profile only → guided prompt in frpctl. Full host/port may be provided positionally.
        if len(tokens) == 3:
            return {
                "status": "ok",
                "action": "add_egress_destination",
                "profile": tokens[2],
                "host": "",
                "port": "",
                "passthrough": [],
                "guided": True,
            }
        if len(tokens) < 5:
            return incomplete(
                "Destination FQDN and port required.",
                ["add egress-destination <PROFILE> <FQDN> <PORT>"],
            )
        return {
            "status": "ok",
            "action": "add_egress_destination",
            "profile": tokens[2],
            "host": tokens[3],
            "port": tokens[4],
            "passthrough": tokens[5:],
        }
    if len(tokens) >= 2 and tokens[1] == "egress-source" and server:
        if len(tokens) < 3:
            return incomplete(
                "Missing egress profile.",
                ["add egress-source <PROFILE>"],
            )
        if len(tokens) == 3:
            return {
                "status": "ok",
                "action": "add_egress_source",
                "profile": tokens[2],
                "cidr": "",
                "passthrough": [],
                "guided": True,
            }
        return {
            "status": "ok",
            "action": "add_egress_source",
            "profile": tokens[2],
            "cidr": tokens[3],
            "passthrough": tokens[4:],
        }
    if len(tokens) >= 2 and tokens[1] == "access-source" and server:
        if len(tokens) < 3:
            return incomplete(
                "Missing access list.",
                ["add access-source <LIST>"],
            )
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["add-source", tokens[2]] + list(tokens[3:]),
            "guided": len(tokens) == 3,
        }
    if len(tokens) >= 2 and tokens[1] == "client" and server:
        if len(tokens) < 5 or tokens[3] != "group":
            return incomplete("Missing group.", ["add client <CLIENT> group <GROUP>"])
        return {"status": "ok", "action": "add_group_member", "client": tokens[2], "group": tokens[4]}
    if len(tokens) >= 2 and tokens[1] == "egress-profile" and server:
        if len(tokens) < 3:
            return incomplete(
                "Missing egress profile selector.",
                [
                    "add egress-profile <PROFILE> destination <FQDN> <PORT>",
                    "add egress-profile <PROFILE> source <CIDR>",
                ],
            )
        if len(tokens) < 4:
            return incomplete(
                "Missing destination|source.",
                [
                    "add egress-profile <PROFILE> destination <FQDN> <PORT>",
                    "add egress-profile <PROFILE> source <CIDR>",
                ],
                ["destination", "source"],
            )
        kind = tokens[3]
        if kind == "destination":
            if len(tokens) < 6:
                return incomplete(
                    "Missing destination host/port.",
                    ["add egress-profile <PROFILE> destination <FQDN> <PORT> [--protocol http|https]"],
                )
            # Allow trailing option flags after host/port (e.g. --protocol).
            idx = 6
            while idx < len(tokens):
                if not str(tokens[idx]).startswith("-"):
                    return incomplete(
                        "Unexpected arguments.",
                        ["add egress-profile <PROFILE> destination <FQDN> <PORT> [--protocol http|https]"],
                    )
                idx += 1
                if idx < len(tokens) and not str(tokens[idx]).startswith("-"):
                    idx += 1
            return {
                "status": "ok",
                "action": "add_egress_destination",
                "profile": tokens[2],
                "host": tokens[4],
                "port": tokens[5],
                "passthrough": tokens[6:],
            }
        if kind == "source":
            if len(tokens) < 5:
                return incomplete(
                    "Missing source CIDR.",
                    ["add egress-profile <PROFILE> source <CIDR> [--name NAME]"],
                )
            idx = 5
            while idx < len(tokens):
                if not str(tokens[idx]).startswith("-"):
                    return incomplete(
                        "Unexpected arguments.",
                        ["add egress-profile <PROFILE> source <CIDR> [--name NAME]"],
                    )
                idx += 1
                if idx < len(tokens) and not str(tokens[idx]).startswith("-"):
                    idx += 1
            return {
                "status": "ok",
                "action": "add_egress_source",
                "profile": tokens[2],
                "cidr": tokens[4],
                "passthrough": tokens[5:],
            }
        return incomplete(
            "Unknown egress-profile add target.",
            [
                "add egress-profile <PROFILE> destination <FQDN> <PORT>",
                "add egress-profile <PROFILE> source <CIDR>",
            ],
            ["destination", "source"],
        )
    available = []
    if client_role:
        available.append("service")
    if server:
        available.extend(["client", "egress-destination", "egress-source", "access-source"])
    return incomplete(
        "Missing resource.",
        [
            "add service ...",
            "add client <CLIENT> group <GROUP>",
            "add egress-destination <PROFILE>",
            "add egress-source <PROFILE>",
            "add access-source <LIST>",
        ],
        available,
    )


def _match_remove(tokens, role, names=None):
    _, server = _role_parts(role)
    if len(tokens) >= 2 and tokens[1] == "egress-destination" and server:
        if len(tokens) < 3:
            return incomplete("Missing egress profile.", ["remove egress-destination <PROFILE> <SELECTOR>"])
        if len(tokens) < 4:
            return {
                "status": "ok",
                "action": "remove_egress_destination",
                "profile": tokens[2],
                "destination": "",
                "passthrough": [],
                "guided": True,
            }
        return {
            "status": "ok",
            "action": "remove_egress_destination",
            "profile": tokens[2],
            "destination": tokens[3],
            "passthrough": tokens[4:],
        }
    if len(tokens) >= 2 and tokens[1] == "egress-source" and server:
        if len(tokens) < 3:
            return incomplete("Missing egress profile.", ["remove egress-source <PROFILE> <SELECTOR>"])
        if len(tokens) < 4:
            return {
                "status": "ok",
                "action": "remove_egress_source",
                "profile": tokens[2],
                "source": "",
                "passthrough": [],
                "guided": True,
            }
        return {
            "status": "ok",
            "action": "remove_egress_source",
            "profile": tokens[2],
            "source": tokens[3],
            "passthrough": tokens[4:],
        }
    if len(tokens) >= 2 and tokens[1] == "access-source" and server:
        if len(tokens) < 3:
            return incomplete("Missing access list.", ["remove access-source <LIST>"])
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["remove-source", tokens[2]] + list(tokens[3:]),
            "guided": len(tokens) == 3,
        }
    if len(tokens) >= 2 and tokens[1] == "egress-profile" and server:
        if len(tokens) < 5:
            return incomplete(
                "Missing egress remove arguments.",
                [
                    "remove egress-profile <PROFILE> destination <SELECTOR>",
                    "remove egress-profile <PROFILE> source <SELECTOR>",
                ],
                ["destination", "source"],
            )
        kind = tokens[3]
        if kind == "destination" and len(tokens) >= 5:
            idx = 5
            while idx < len(tokens):
                if not str(tokens[idx]).startswith("-"):
                    return incomplete(
                        "Unexpected arguments.",
                        ["remove egress-profile <PROFILE> destination <SELECTOR> [--yes]"],
                    )
                idx += 1
                if idx < len(tokens) and not str(tokens[idx]).startswith("-"):
                    idx += 1
            return {
                "status": "ok",
                "action": "remove_egress_destination",
                "profile": tokens[2],
                "destination": tokens[4],
                "passthrough": tokens[5:],
            }
        if kind == "source" and len(tokens) >= 5:
            idx = 5
            while idx < len(tokens):
                if not str(tokens[idx]).startswith("-"):
                    return incomplete(
                        "Unexpected arguments.",
                        ["remove egress-profile <PROFILE> source <SELECTOR> [--yes]"],
                    )
                idx += 1
                if idx < len(tokens) and not str(tokens[idx]).startswith("-"):
                    idx += 1
            return {
                "status": "ok",
                "action": "remove_egress_source",
                "profile": tokens[2],
                "source": tokens[4],
                "passthrough": tokens[5:],
            }
        return incomplete(
            "Unknown egress-profile remove target.",
            [
                "remove egress-profile <PROFILE> destination <SELECTOR> [--yes]",
                "remove egress-profile <PROFILE> source <SELECTOR> [--yes]",
            ],
            ["destination", "source"],
        )
    if len(tokens) < 5 or tokens[1] != "client" or tokens[3] != "group":
        avail = ["client"]
        if server:
            avail.append("egress-profile")
        return incomplete(
            "Missing client or group.",
            [
                "remove client <CLIENT> group <GROUP>",
                "remove egress-profile <PROFILE> destination|source <SELECTOR>",
            ],
            avail,
        )
    return {"status": "ok", "action": "remove_group_member", "client": tokens[2], "group": tokens[4]}


def _match_delete(tokens, role, names=None):
    if len(tokens) < 2:
        return incomplete(
            "Missing resource.",
            [
                "delete group <GROUP>",
                "delete service-profile <PROFILE>",
                "delete egress-profile <PROFILE>",
                "delete access-list <LIST>",
                "delete enrollment <ENROLLMENT-ID>",
            ],
            ["group", "service-profile", "egress-profile", "access-list", "enrollment"],
        )
    if tokens[1] == "enrollment":
        if len(tokens) < 3:
            return incomplete(
                "Missing enrollment id.",
                ["delete enrollment <ENROLLMENT-ID>"],
                tip="Revoke active enrollments first with: revoke enrollment <ID>",
            )
        return {"status": "ok", "action": "purge_enrollment", "id": tokens[2]}
    if tokens[1] == "access-list":
        if len(tokens) < 3:
            return incomplete("Missing access list.", ["delete access-list <LIST>"])
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["delete", tokens[2]] + list(tokens[3:]),
        }
    if tokens[1] == "service-profile":
        if len(tokens) < 3:
            return incomplete(
                "Missing profile selector.",
                ["delete service-profile <PROFILE>"],
            )
        return {"status": "ok", "action": "delete_profile", "profile": tokens[2]}
    if tokens[1] == "group":
        if len(tokens) < 3:
            return incomplete(
                "Missing group selector.", ["delete group <GROUP> [--yes]"], ["group"]
            )
        for token in tokens[3:]:
            if not str(token).startswith("-"):
                return incomplete(
                    "Unexpected arguments.", ["delete group <GROUP> [--yes]"]
                )
        return {
            "status": "ok",
            "action": "delete_group",
            "group": tokens[2],
            "passthrough": tokens[3:],
        }
    if tokens[1] == "profile":
        if len(tokens) < 3:
            return incomplete("Missing profile selector.", ["delete profile <PROFILE>"], ["profile"])
        return {"status": "ok", "action": "delete_profile", "profile": tokens[2]}
    if tokens[1] == "egress-profile":
        if len(tokens) < 3:
            return incomplete(
                "Missing egress profile selector.",
                ["delete egress-profile <PROFILE> [--yes]"],
                ["egress-profile"],
            )
        idx = 3
        while idx < len(tokens):
            if not str(tokens[idx]).startswith("-"):
                return incomplete(
                    "Unexpected arguments.",
                    ["delete egress-profile <PROFILE> [--yes]"],
                )
            idx += 1
            if idx < len(tokens) and not str(tokens[idx]).startswith("-"):
                idx += 1
        return {
            "status": "ok",
            "action": "delete_egress_profile",
            "profile": tokens[2],
            "passthrough": tokens[3:],
        }
    return incomplete(
        "Unknown delete resource.",
        ["delete group <GROUP>", "delete profile <PROFILE>", "delete egress-profile <PROFILE>"],
        ["group", "profile", "egress-profile"],
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
    client_role, server = _role_parts(role)
    if len(tokens) >= 2 and tokens[1] == "egress-profile" and server:
        if len(tokens) < 3:
            return incomplete(
                "Missing egress profile selector.",
                ["%s egress-profile <PROFILE>" % verb],
            )
        return {
            "status": "ok",
            "action": "%s_egress_profile" % verb,
            "profile": tokens[2],
        }
    if len(tokens) < 2 or tokens[1] != "service":
        avail = []
        if client_role:
            avail.append("service")
        if server:
            avail.append("egress-profile")
        return incomplete(
            "Missing resource.",
            ["%s service <service-id>" % verb, "%s egress-profile <PROFILE>" % verb],
            avail,
        )
    if not client_role:
        return {"status": "role", "need": "client", "command": "%s service" % verb}
    if len(tokens) < 3:
        return incomplete("Missing service ID.", ["%s service <service-id>" % verb])
    return {"status": "ok", "action": "%s_service" % verb, "service": tokens[2]}


def completion_candidates(
    line,
    role,
    names,
    services,
    local_services,
    trailing=None,
    groups=None,
    egress_profiles=None,
    access_lists=None,
    service_profiles=None,
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
    filled = tokens if trailing else tokens[:-1]
    hit = _catalog_candidates(
        filled,
        _current_prefix(tokens, trailing),
        role,
        names,
        services,
        local_services,
        groups or [],
        egress_profiles=egress_profiles,
        access_lists=access_lists,
        service_profiles=service_profiles,
        tokens=tokens,
        trailing=trailing,
    )
    if hit is not None:
        return hit
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
        egress_profiles=egress_profiles,
        access_lists=access_lists,
        service_profiles=service_profiles,
    )


def _catalog_desc_map(filled, role):
    """Tab descriptions for the canonical grammar. None means 'not canonical'."""
    if not filled:
        rows = CATALOG.root_rows(role)
        return ({name: desc for name, desc in rows}, "verbs") if rows else None
    root = canonical_root(filled[0])
    actions = CATALOG.canonical_actions(root)
    if not actions:
        return None
    if len(filled) == 1:
        rows = CATALOG.subcommands(root, role)
        return ({name: desc for name, desc in rows}, "named") if rows else None
    if filled[1] not in actions:
        return None
    probe = [root] + list(filled[1:])
    cmd = CATALOG.find(probe)
    if cmd is None or not CATALOG.role_allows(cmd["roles"], role):
        return None
    index = len(probe) - len(cmd["path"])
    if index < len(cmd["args"]):
        complete = cmd["args"][index]["complete"]
        if complete == CATALOG.C_CLIENT:
            return {}, "clients"
        if isinstance(complete, (list, tuple)):
            return {item: "" for item in complete}, "named"
    return {}, "plain"


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
    catalog_rows = _catalog_desc_map(filled, role)
    if catalog_rows is not None:
        return catalog_rows
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
        "exit": "Leave drlink",
        "clear": "Clear the screen",
        "status": "Host status shortcut",
        "version": "Installed versions shortcut",
        "add": "Add a local service",
        "enable": "Enable a local service",
        "disable": "Disable a local service",
        "apply": "Apply pending local changes",
        "discard": "Discard pending local changes",
        "quit": "Leave drlink",
        "q": "Leave drlink",
    }
    if not server:
        verb_map.pop("access", None)
    if not filled:
        return verb_map, "verbs"
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
                "public-hostname": "Optional public DNS hostname for published services",
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
    if verb == "unset" and len(filled) == 1:
        return {
            "client": "Remove client metadata",
            "server": "Remove server access settings",
        }, "named"
    if verb == "unset" and len(filled) >= 2 and filled[1] == "server":
        if len(filled) == 2:
            return {
                "public-hostname": "Remove public DNS hostname",
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
    if verb == "show" and len(filled) >= 2 and filled[1] == "client" and len(filled) == 2:
        return {}, "clients"
    if verb == "revoke" and len(filled) >= 2 and filled[1] == "client" and len(filled) == 2:
        return {}, "clients"
    if verb == "release" and len(filled) >= 2 and filled[1] == "client" and len(filled) == 2:
        return {}, "clients"
    return {}, "plain"


def format_tab_candidates(line, matches, role, names=None, clients=None):
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


def _inventory(
    names,
    services,
    local_services,
    groups,
    egress_profiles=None,
    access_lists=None,
    service_profiles=None,
):
    return {
        CATALOG.C_CLIENT: list(names or []),
        CATALOG.C_GROUP: list(groups or []),
        CATALOG.C_LOCAL_SERVICE: list(local_services or []),
        CATALOG.C_EGRESS: list(egress_profiles or []),
        CATALOG.C_ACCESS_LIST: list(access_lists or []),
        CATALOG.C_PROFILE: list(service_profiles or []),
    }


def _pending_flag_value(tokens, cmd, *, trailing):
    """When completing a flag value, return (flag_meta, value_prefix) or None."""
    if not tokens or not cmd.get("flags"):
        return None
    flags = {item["name"]: item for item in CATALOG._normalize_flags(cmd["flags"])}
    if trailing and tokens[-1] in flags and flags[tokens[-1]]["arity"] == 1:
        return flags[tokens[-1]], ""
    if len(tokens) >= 2 and tokens[-2] in flags and flags[tokens[-2]]["arity"] == 1:
        return flags[tokens[-2]], tokens[-1]
    return None


def _catalog_candidates(
    filled,
    prefix,
    role,
    names,
    services,
    local_services,
    groups,
    egress_profiles=None,
    access_lists=None,
    service_profiles=None,
    tokens=(),
    trailing=False,
):
    """Catalog-driven Tab candidates. None means 'not a canonical command'."""
    if not filled:
        return None
    root = canonical_root(filled[0])
    actions = CATALOG.canonical_actions(root)
    if not actions:
        return None
    allowed = [name for name, _desc in CATALOG.subcommands(root, role)]
    if len(filled) == 1:
        hits = _filter(allowed, prefix)
        # Legacy ``client <ID>`` shortcut: also offer CLIENT IDs when the
        # prefix does not uniquely select a canonical action.
        if root == "client":
            id_hits = _filter(list(names or []), prefix)
            merged = sorted(set(hits + id_hits))
            if merged:
                return merged
        elif hits:
            return hits
        # A root that is also a historical flat command keeps completing its
        # old operand when no action matches.
        return None if root in FALLTHROUGH_ROOTS else []
    if filled[1] not in actions:
        if root == "client" and _client_legacy_selector([root, filled[1]]):
            return None  # fall through to legacy operand completion
        # Fall through to verb-specific completion (action-first handlers).
        return None
    probe = [root] + list(filled[1:])
    cmd = CATALOG.find(probe)
    if cmd is None or not CATALOG.role_allows(cmd["roles"], role):
        return None if root in FALLTHROUGH_ROOTS else []
    index = len(probe) - len(cmd["path"])
    if index < len(cmd["args"]):
        arg = cmd["args"][index]
        complete = arg["complete"]
        if isinstance(complete, (list, tuple)):
            return _filter(list(complete), prefix)
        if complete == CATALOG.C_CLIENT_SERVICE:
            selector = _selector_before(cmd, probe, CATALOG.C_CLIENT)
            return _filter((services or {}).get(selector, []), prefix)
        pool = _inventory(
            names,
            services,
            local_services,
            groups,
            egress_profiles=egress_profiles,
            access_lists=access_lists,
            service_profiles=service_profiles,
        ).get(complete)
        if pool is not None:
            return _filter(pool, prefix)
        pending = _pending_flag_value(tokens or filled, cmd, trailing=trailing)
        if pending is not None:
            flag_meta, value_prefix = pending
            choices = flag_meta.get("choices") or ()
            if choices:
                return _filter(list(choices), value_prefix)
        return []
    # Public Tab never offers --options.
    return []


def _selector_before(cmd, probe, kind):
    base = len(cmd["path"])
    for offset, arg in enumerate(cmd["args"]):
        if arg["complete"] == kind and base + offset < len(probe):
            return probe[base + offset]
    return ""


def _canonical_completion(
    tokens,
    trailing,
    role,
    names,
    services,
    local_services,
    groups,
    egress_profiles=None,
    access_lists=None,
    service_profiles=None,
):
    client, server = _role_parts(role)
    prefix = _current_prefix(tokens, trailing)
    filled = tokens if trailing else tokens[:-1]
    if not filled:
        return _filter(canonical_verbs(role), prefix)
    catalog_hit = _catalog_candidates(
        filled,
        prefix,
        role,
        names,
        services,
        local_services,
        groups,
        egress_profiles=egress_profiles,
        access_lists=access_lists,
        service_profiles=service_profiles,
        tokens=tokens,
        trailing=trailing,
    )
    if catalog_hit is not None:
        return catalog_hit
    verb = filled[0]
    if verb == "help":
        topics = list(canonical_verbs(role)) + ["workflows", "legacy"]
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
        if filled[1] == "server" and server:
            if len(filled) == 2:
                return _filter(["public-hostname", "bootstrap-hostname"], prefix)
        if filled[1] == "service" and client:
            if len(filled) == 2:
                return _filter(local_services, prefix)
            if len(filled) == 3:
                return _filter(
                    [
                        "target-host",
                        "target-port",
                        "ssh-user",
                        "name",
                        "health-type",
                        "health-timeout",
                        "health-interval",
                        "health-max-failed",
                        "health-path",
                    ],
                    prefix,
                )
        return []
    if verb == "unset":
        if len(filled) == 1:
            return _filter(_unset_resources(role), prefix)
        if filled[1] == "server" and server:
            if len(filled) == 2:
                return _filter(["public-hostname", "bootstrap-hostname"], prefix)
        if filled[1] == "client":
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(["label", "note", "tag"], prefix)
        return []
    if verb == "create":
        if len(filled) == 1:
            return _filter(_create_resources(role), prefix)
        # Public UX is guided — never offer --options after create resources.
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
            return []
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
            return _filter(["product", "project", "engine", "frp"], prefix)
        if filled[1] in ("product", "project", "frp", "engine"):
            return []
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
            return _filter(
                ["--preset", "--id", "--name", "--target-host", "--target-port", "--ssh-user"],
                prefix,
            )
        return []
    if verb in ("enable", "disable"):
        if len(filled) == 1:
            return _filter(["service"], prefix)
        if filled[1] == "service" and len(filled) == 2:
            return _filter(local_services, prefix)
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
    if verb in ("delete", "rename"):
        if len(filled) == 1:
            return _filter(["group"], prefix)
        if filled[1] == "group" and len(filled) == 2:
            return _filter(groups, prefix)
        return []
    if verb == "doctor":
        return []
    if verb == "support-bundle":
        return []
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
        return []
    if cmd == "release-service":
        if len(filled) == 1:
            return _filter(names, prefix)
        if len(filled) == 2:
            return _filter(services.get(filled[1], []), prefix)
        return []
    if cmd in ("enroll", "create-client"):
        # Hidden aliases remain runnable, but Tab never advertises --options.
        return []
    if cmd == "doctor":
        return []
    if cmd == "support-bundle":
        return []
    return []


def complete_line(
    line,
    role,
    names,
    services,
    local_services,
    groups=None,
    egress_profiles=None,
    access_lists=None,
    service_profiles=None,
):
    trailing = bool(line) and line[-1:] in " \t"
    cands = completion_candidates(
        line,
        role,
        names,
        services,
        local_services,
        trailing=trailing,
        groups=groups or [],
        egress_profiles=egress_profiles,
        access_lists=access_lists,
        service_profiles=service_profiles,
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


def _command_edit_distance(a, b):
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def suggest_commands(unknown, cmds):
    """Rank likely command names for typo recovery (prefix + edit distance ≤ 2)."""
    needle = str(unknown or "").strip()
    if not needle:
        return []
    ranked = []
    seen = set()
    for cmd in cmds or []:
        text = str(cmd or "").strip()
        if not text or text == "?" or text in seen:
            continue
        keep = False
        if len(needle) >= 3 and text.startswith(needle):
            keep = True
        elif len(text) >= 3 and needle.startswith(text):
            keep = True
        else:
            dist = _command_edit_distance(needle, text)
            if 1 <= dist <= 2:
                keep = True
        if keep:
            seen.add(text)
            ranked.append(text)
    return ranked


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        raise SystemExit(
            "usage: frp_ctl_grammar.py tokenize|match|help|complete|complete-line|suggest ..."
        )
    cmd = argv[0]
    if cmd == "suggest":
        unknown = argv[1] if len(argv) > 1 else ""
        cmds = []
        if not sys.stdin.isatty():
            cmds = [
                line.strip()
                for line in sys.stdin.read().splitlines()
                if line.strip() and line.strip() != "?"
            ]
        for item in suggest_commands(unknown, cmds):
            sys.stdout.write(item + "\n")
        return 0
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
    egress_profiles = payload.get("egress") or []
    access_lists = payload.get("access_lists") or []
    service_profiles = payload.get("service_profiles") or []
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
            line,
            role,
            names,
            services,
            local_services,
            groups=groups,
            egress_profiles=egress_profiles,
            access_lists=access_lists,
            service_profiles=service_profiles,
        ):
            sys.stdout.write(item + "\n")
        return 0
    if cmd == "complete-line":
        line = payload.get("line") or (argv[1] if len(argv) > 1 else "")
        sys.stdout.write(
            complete_line(
                line,
                role,
                names,
                services,
                local_services,
                groups=groups,
                egress_profiles=egress_profiles,
                access_lists=access_lists,
                service_profiles=service_profiles,
            )
        )
        return 0
    raise SystemExit("unknown grammar action")


if __name__ == "__main__":
    raise SystemExit(main())
