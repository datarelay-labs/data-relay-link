#!/usr/bin/env python3
"""Safe drlink tokenizer, command-tree help, and context-aware completion.

The canonical grammar is the final public ``drlink`` tree
(``show`` / ``set`` / ``unset`` / ``test`` / ``system`` / ``menu`` / ``help`` /
``exit``) described once in :mod:`frp_cli_catalog`. This module tokenizes,
resolves a command against that catalog, expands hidden compatibility aliases,
and renders help, context help, and Tab completion from the same catalog.

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

CONTROL_PLANE_SHOW = frozenset(
    {
        "status",
        "network-objects",
        "network-object",
        "network-groups",
        "network-group",
        "service-objects",
        "service-object",
        "service-groups",
        "service-group",
        "permission-objects",
        "permission-object",
        "permission-groups",
        "permission-group",
        "managed-hosts",
        "managed-host",
        "enrollments",
        "enrollment",
        "remote-access",
        "internet-access",
        "ai-identities",
        "ai-identity",
        "ai-access",
        "ai-access-log",
        "remote-services",
        "remote-service",
        "agent",
        "mcp-tls",
        # Legacy rejected with guidance inside control CLI
        "objects",
        "object",
        "object-groups",
        "object-group",
        "managed-endpoints",
        "managed-endpoint",
        "published-services",
        "published-service",
        "service-presets",
        "service-preset",
        "client-groups",
        "client-group",
        "ai-principals",
        "ai-principal",
        "ai-activity",
        "fixed-tcp",
    }
)
CONTROL_PLANE_MUTATE = frozenset(
    {
        "network-object",
        "network-group",
        "service-object",
        "service-group",
        "permission-object",
        "permission-group",
        "managed-host",
        "enrollment",
        "remote-access",
        "internet-access",
        "ai-identity",
        "ai-access",
        "remote-service",
        "mcp-tls",
        # Legacy rejected with guidance
        "object",
        "object-group",
        "client-group",
        "managed-endpoint",
        "published-service",
        "service-preset",
        "ai-principal",
        "fixed-tcp",
    }
)
CONTROL_PLANE_TEST = frozenset({"remote-access", "internet-access", "ai-access", "configuration"})
CONTROL_PLANE_SYSTEM = frozenset(
    {
        "backup",
        "restore",
        "revisions",
        "revision",
        "diff",
        "credential",
        "export",
        "apply",
        "certificate",
        "synchronize",
    }
)


def _control_plane_ok(tokens):
    return {"status": "ok", "action": "control_plane", "tokens": [str(t) for t in tokens]}


# Obsolete development-era surfaces — reject rather than translate.
_OBSOLETE_ROOTS = frozenset(
    {
        "access",
        "egress",
        "acl",
        "service-profile",
        "internet-profile",
        "access-list",
        "egress-profile",
        "profile",
    }
)
_OBSOLETE_RESOURCES = frozenset(
    {
        "acl",
        "access-list",
        "access-rule",
        "access-rules",
        "access-source",
        "access-service",
        "service-access",
        "service-profile",
        "service-profiles",
        "internet-profile",
        "internet-profiles",
        "egress-profile",
        "egress-profiles",
        "internet-source",
        "internet-destination",
        "egress-destination",
        "egress-source",
        "egress-destinations",
        "egress-sources",
        "profile",
        "profiles",
        "acls",
        "internet-templates",
        "internet-template",
        "egress-recipes",
        "egress-recipe",
    }
)
_OBSOLETE_POINTERS = {
    "access": "Use show/set/unset/test remote-access and Objects instead.",
    "egress": "Use show/set/unset/test internet-access and set fixed-tcp instead.",
    "acl": "Use remote-access ordered rules with Objects instead.",
    "service-profile": "Use published-service and service-preset instead.",
    "internet-profile": "Use internet-access ordered rules with Objects instead.",
    "internet-destination": "Use set internet-access … with Objects instead.",
    "egress-destination": "Use set internet-access … with Objects instead.",
    "egress-source": "Use set internet-access … with Objects instead.",
    "profile": "Use published-service / service-preset / internet-access instead.",
    "legacy": "Use help commands for the current grammar.",
}


def reject_obsolete_surface(tokens):
    """Return an error result when tokens are obsolete current-surface grammar."""
    if not tokens:
        return None
    raw = [str(t) for t in tokens]
    verb = raw[0]
    if verb == "help" and len(raw) >= 2 and raw[1] == "legacy":
        return {
            "status": "error",
            "exit_code": 2,
            "message": (
                "'help legacy' has been removed.\n"
                "Use: help commands\n"
                "Canonical roots: show, set, unset, test, system, menu, help, exit"
            ),
        }
    if verb in _OBSOLETE_ROOTS:
        tip = _OBSOLETE_POINTERS.get(verb, "Use the canonical v2.4.0 grammar (help commands).")
        return {
            "status": "error",
            "exit_code": 2,
            "message": (
                "Obsolete command '%s' is not part of the current Data Relay Link grammar.\n%s"
                % (verb, tip)
            ),
        }
    if verb == "show" and len(raw) >= 2 and raw[1] in ("clients", "client"):
        return {
            "status": "error",
            "exit_code": 2,
            "message": (
                "Obsolete resource '%s' is not part of the current Data Relay Link grammar.\n"
                "Use show managed-hosts / show managed-host <HOST> instead."
                % raw[1]
            ),
        }
    if verb == "set" and len(raw) >= 3 and raw[1] == "client":
        return {
            "status": "error",
            "exit_code": 2,
            "message": (
                "Obsolete resource 'client' is not part of the current Data Relay Link grammar.\n"
                "Use set managed-host <HOST> … instead."
            ),
        }
    if verb == "unset" and len(raw) >= 2 and raw[1] == "client":
        return {
            "status": "error",
            "exit_code": 2,
            "message": (
                "Obsolete resource 'client' is not part of the current Data Relay Link grammar.\n"
                "Use unset managed-host <HOST> instead."
            ),
        }
    if verb in ("show", "set", "unset", "test", "create", "add", "remove", "enable", "disable", "delete", "system") and len(raw) >= 2:
        resource = raw[1]
        # system export/import/diff internet-profile
        if verb == "system" and len(raw) >= 3 and raw[1] in ("export", "import", "diff", "cleanup"):
            resource = raw[2]
        if resource in _OBSOLETE_RESOURCES:
            key = resource
            for candidate in (
                "service-profile",
                "internet-profile",
                "egress-destination",
                "egress-source",
                "internet-destination",
                "acl",
                "access",
                "egress",
                "profile",
            ):
                if candidate in resource or resource == candidate:
                    key = candidate
                    break
            tip = _OBSOLETE_POINTERS.get(key, "Use help commands for the current grammar.")
            return {
                "status": "error",
                "exit_code": 2,
                "message": (
                    "Obsolete resource '%s' is not part of the current Data Relay Link grammar.\n%s"
                    % (resource, tip)
                ),
            }
    return None


# Roots that previously fell through to flat legacy commands. Kept empty so
# obsolete access/egress roots cannot regain silent translation.
FALLTHROUGH_ROOTS = frozenset()

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
SHELL_REJECT = {"shell", "exec", "bash", "sh"}


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


def _catalog_children(root, role):
    """Public first-level children under a root from the command catalog."""
    return [name for name, _summary in CATALOG.subcommands(root, role)]


def _show_resources(role):
    return _catalog_children("show", role)


def _set_resources(role):
    return _catalog_children("set", role)


def _unset_resources(role):
    return _catalog_children("unset", role)


def _test_resources(role):
    return _catalog_children("test", role)


def _system_resources(role):
    return _catalog_children("system", role)


def _create_resources(role):
    # Hidden compatibility only — not public discovery.
    # Keep only resources that still resolve; never Tab-offer obsolete ACL/profile nouns.
    _, server = _role_parts(role)
    if server:
        return ["zero-touch", "enrollment", "enrollments", "backup", "group", "support-bundle"]
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
        rejected = reject_obsolete_surface(["help", "legacy"])
        return rejected["message"] if rejected else "help legacy removed"
    if verb in ("workflow", "workflows"):
        return CATALOG.workflow_help(role)
    if verb in ("command", "commands"):
        return CATALOG.commands_help(role)
    domain = CATALOG.domain_help(verb, role)
    if domain is not None:
        return domain
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
            "  set group <NAME>\n"
            "  set group <GROUP> description|name <value>\n"
            "  set client <CLIENT> group <GROUP>\n"
            "  unset client <CLIENT> group <GROUP>\n"
            "  unset group <GROUP>\n"
        )
    # Action-first topics are served by _catalog_help_topic above.
    if verb == "update":
        return _update_help(role)
    if verb == "doctor":
        return (
            "Diagnostics\n"
            "===========\n\n"
            "Public command:\n"
            "  system diagnostics\n\n"
            "See: help system / help commands\n"
        )
    if verb == "support-bundle":
        return (
            "Support Bundle\n==============\n\n"
            "Usage:\n  system support-bundle\n\n"
            "Create a sanitized read-only diagnostic archive. Never includes private keys or tokens.\n"
        )
    if verb == "access":
        return (
            "Access Rules\n"
            "============\n\n"
            "Control which source IPs may reach published services.\n\n"
            "Usage:\n"
            "  show access-rules\n"
            "  show access-rule <RULE>\n"
            "  set access-rule <RULE>\n"
            "  set access-source <RULE> <SOURCE>\n"
            "  set service-access <CLIENT> <SERVICE> <RULE>\n"
            "  unset access-source <RULE> <SELECTOR>\n"
            "  unset service-access <CLIENT> <SERVICE>\n"
            "  unset access-rule <RULE>\n"
            "  test access <CLIENT> <SERVICE> <SOURCE-IP>\n"
            "  show access-log\n"
        )
    lines = [
        "Unknown help topic: %s" % " ".join(tokens),
        "",
        "Type 'help' for domains, or 'help commands' for the full command",
        "reference.",
        "Canonical roots: show, set, unset, test, system, menu, help, exit",
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
        '"create" is not a current public root.\n\n'
        "Preferred onboarding:\n"
        "  set enrollment\n"
        "  set enrollment zero-touch\n"
        "  help managed-hosts\n\n"
        "Hidden compatibility forms still accepted:\n"
        "  create zero-touch\n"
        "  create enrollment\n"
        "  create enrollments\n"
        "  create backup [path]\n"
        "  create support-bundle\n\n"
        "See: help commands\n"
    )


def _update_help(role):
    return (
        "Update\n======\n\n"
        "Public commands:\n"
        "  system update product\n"
        "  system update engine\n"
        "  system update check-engine\n\n"
        "system update product updates Data Relay Link management tools.\n"
        "system update engine updates the pinned upstream Relay Engine (FRP) binary.\n"
        "system update check-engine checks upstream Relay Engine releases (read-only).\n"
        "A software update does not re-enroll clients or rotate CA/token/ports.\n"
        "See: help system / help commands\n"
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
        "enable": "Enable\n======\n\nUsage:\n  enable service <SERVICE>\n  enable internet-profile <PROFILE>\n",
        "disable": (
            "Disable\n=======\n\nUsage:\n"
            "  disable service <SERVICE>\n"
            "  disable internet-profile <PROFILE>\n\n"
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
    names = [name for name, _desc in rows]
    groups = CATALOG.group_completion_candidates(names)
    if groups:
        desc_map = {name: desc for name, desc in rows}
        for title, members in groups:
            parts.append(title)
            width = max((len(n) for n in members), default=8)
            for name in members:
                desc = desc_map.get(name) or ""
                if desc:
                    parts.append("  %s  %s" % (name.ljust(width), desc))
                else:
                    parts.append("  %s" % name)
            parts.append("")
        return "\n".join(parts).rstrip() + "\n"
    width = max((len(name) for name, _desc in rows), default=8)
    for name, desc in rows:
        parts.append("  %s  %s" % (name.ljust(width), desc))
    return "\n".join(parts) + "\n"


def _catalog_next_path_tokens(probe, role):
    """Public child tokens for a command-path prefix (e.g. system update)."""
    nxt = []
    for row in CATALOG.COMMANDS:
        if row.get("hidden"):
            continue
        if not CATALOG.role_allows(row["roles"], role):
            continue
        path = list(row["path"])
        if len(path) > len(probe) and path[: len(probe)] == probe:
            tok = path[len(probe)]
            if tok not in nxt:
                nxt.append(tok)
    return nxt


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
    # Final client-removal model must be explicit before listing clients.
    if probe == ["unset", "client"]:
        lines = [
            "Client removal model",
            "====================",
            "",
            "unset client <CLIENT> trust",
            "  identity/trust: management blocked",
            "  public ports: reserved",
            "",
            "unset client <CLIENT> service <SERVICE>",
            "  client identity: kept",
            "  selected service port: released",
            "",
            "unset client <CLIENT>",
            "  client record/management identity: removed",
            "  all service ports: released",
            "",
            "Also: unset client <CLIENT> group|label|note|tag …",
            "",
            "Select a client:",
            "",
        ]
        return "\n".join(lines) + _context_client_list(names, clients)
    cmd = CATALOG.find(probe)
    if cmd is None or not CATALOG.role_allows(cmd["roles"], role):
        nxt = _catalog_next_path_tokens(probe, role)
        if nxt:
            return _fmt_available([(tok, "") for tok in nxt])
        return None
    # Exact path is also a prefix of longer public commands (system update …).
    nxt = _catalog_next_path_tokens(probe, role)
    if nxt and len(probe) == len(cmd["path"]):
        return _fmt_available([(tok, "") for tok in nxt])
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
    hidden_roots = {
        "create": (
            '"create" is not a current public root.\n\n'
            "Current commands:\n"
            "  set client\n"
            "  set enrollment\n"
            "  set client-group <NAME>\n"
            "  set object <NAME>\n"
            "  set object-group <NAME>\n"
            "  set published-service <NAME>\n"
            "  set service-preset <NAME>\n"
            "  set remote-access <NAME>\n"
            "  set internet-access <NAME>\n"
            "  set fixed-tcp <NAME>\n"
            "  system backup\n"
            "  system support-bundle\n\n"
            "Use:\n"
            "  ?\n"
            "  help managed-hosts\n"
            "  help commands\n"
        ),
        "add": (
            '"add" is not a current public root.\n\n'
            "Current commands:\n"
            "  set published-service …\n"
            "  set client <CLIENT> group <GROUP>\n"
            "  set internet-access …\n"
            "  set remote-access …\n\n"
            "Use:\n"
            "  ?\n"
            "  help commands\n"
        ),
        "remove": (
            '"remove" is not a current public root.\n\n'
            "Prefer unset … forms. See: help commands\n"
        ),
        "enable": (
            '"enable" is not a current public root.\n\n'
            "Prefer:\n"
            "  set published-service <SERVICE> enabled\n"
            "  set fixed-tcp <ENTRY> enabled\n\n"
            "See: help commands\n"
        ),
        "disable": (
            '"disable" is not a current public root.\n\n'
            "Prefer:\n"
            "  unset published-service <SERVICE> enabled\n"
            "  unset fixed-tcp <ENTRY> enabled\n\n"
            "See: help commands\n"
        ),
        "delete": (
            '"delete" is not a current public root.\n\n'
            "Prefer unset …. See: help commands\n"
        ),
        "revoke": (
            '"revoke" is not a current public root.\n\n'
            "Prefer:\n"
            "  unset client <CLIENT> trust\n"
            "  unset enrollment <ENROLLMENT>\n\n"
            "See: help commands\n"
        ),
        "release": (
            '"release" is not a current public root.\n\n'
            "Prefer:\n"
            "  unset client <CLIENT>\n"
            "  unset published-service <SERVICE>\n\n"
            "See: help commands\n"
        ),
        "update": (
            '"update" is not a current public root.\n\n'
            "Prefer:\n"
            "  system update product\n"
            "  system update engine\n"
            "  system update check-engine\n\n"
            "See: help commands\n"
        ),
        "doctor": (
            '"doctor" is not a current public root.\n\n'
            "Prefer:\n"
            "  system diagnostics\n\n"
            "See: help commands\n"
        ),
        "history": (
            '"history" is not a current public root.\n\n'
            "Prefer:\n"
            "  system history\n"
        ),
        "clear": (
            '"clear" is not a current public root.\n\n'
            "Prefer:\n"
            "  system clear\n"
        ),
        "access": (
            '"access" is not a current public root.\n\n'
            "Prefer Remote Access commands:\n"
            "  show remote-access\n"
            "  set remote-access …\n"
            "  test remote-access …\n\n"
            "See: help remote-access / help commands\n"
        ),
        "egress": (
            '"egress" is not a current public root.\n\n'
            "Prefer Internet Access commands:\n"
            "  show internet-access\n"
            "  set internet-access …\n"
            "  set fixed-tcp …\n"
            "  test internet-access …\n\n"
            "See: help internet-access / help commands\n"
        ),
        "client": (
            '"client" is not a current public root.\n\n'
            "Prefer:\n"
            "  show managed-hosts / show managed-host …\n"
            "  set enrollment\n"
            "  unset managed-host …\n\n"
            "See: help managed-hosts / help commands\n"
        ),
        "service": (
            '"service" is not a current public root.\n\n'
            "Prefer set published-service / show published-services.\n"
            "See: help commands\n"
        ),
        "group": (
            '"group" is not a current public root.\n\n'
            "Prefer show client-groups / set client-group ….\n"
            "See: help commands\n"
        ),
        "enrollment": (
            '"enrollment" is not a current public root.\n\n'
            "Prefer set enrollment / show enrollments / unset enrollment.\n"
            "See: help managed-hosts / help commands\n"
        ),
        "apply": (
            '"apply" is not a current public root.\n\n'
            "Prefer: system synchronize\n"
            "Or ConfigurationBundle: system apply configuration <PATH|->\n"
        ),
        "discard": (
            '"discard" is not a current public root.\n\n'
            "Prefer: system services discard\n"
        ),
        "sync": (
            '"sync" is not a current public root.\n\n'
            "Prefer: system synchronize\n"
        ),
        "restore": (
            '"restore" is not a current public root.\n\n'
            "Prefer: system restore <PATH>\n"
        ),
        "support-bundle": (
            '"support-bundle" is not a current public root.\n\n'
            "Prefer: system support-bundle\n"
        ),
    }
    if tokens and tokens[0] in hidden_roots:
        return hidden_roots[tokens[0]]
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
                        ("installer-url", "Linux client installer URL"),
                        ("windows-installer-url", "Windows client installer URL"),
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
        if tokens[1] == "client":
            if len(tokens) == 2:
                lines = [
                    "Client removal model",
                    "====================",
                    "",
                    "unset client <CLIENT> trust",
                    "  identity/trust: management blocked",
                    "  public ports: reserved",
                    "",
                    "unset client <CLIENT> service <SERVICE>",
                    "  client identity: kept",
                    "  selected service port: released",
                    "",
                    "unset client <CLIENT>",
                    "  client record/management identity: removed",
                    "  all service ports: released",
                    "",
                    "Select a client:",
                    "",
                ]
                return "\n".join(lines) + _context_client_list(names, clients)
            return (
                "Available:\n\n"
                "  trust    Block management trust (ports reserved)\n"
                "  service  Release one service reservation\n"
                "  group    Remove group membership\n"
                "  label    Administrator display label\n"
                "  note     Administrator description\n"
                "  tag      Key/value metadata\n"
                "\n"
                "Or omit a property to remove the whole client:\n"
                "  unset client <CLIENT>\n"
            )
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
                "client installation command (SSH, RDP, or chosen services).\n\n"
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
    # ConfigurationBundle stdin path uses a lone "-" (not a GNU option).
    if bad == "-":
        for prefix in (
            ("test", "configuration"),
            ("system", "diff", "configuration"),
            ("system", "apply", "configuration"),
        ):
            if tuple(focus[: len(prefix)]) == prefix:
                return None
    # Guided / no-flag public commands (reject all dash tokens).
    # Enrollment / zero-touch / destination create flows are prompt-driven.
    # Other commands may still accept catalog-declared hidden machine flags.
    guided_prefixes = (
        ("create", "enrollment"),
        ("create", "enrollments"),
        ("create", "zero-touch"),
        ("create-client",),
        ("enroll",),
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
    ) or toks[:3] in (
        ["system", "update", "product"],
        ["system", "update", "engine"],
        ["system", "update", "project"],
        ["system", "update", "frp"],
    ):
        allowed.add("--check")
    if toks[:1] == ["release-client"] or toks[:2] == ["release", "client"]:
        allowed.add("--yes")
    # Flag allowlisting must use the canonical public path only. Alias lookup
    # here would let obsolete forms such as `enroll --one-line` inherit hidden
    # machine flags from `set enrollment`. Those flags stay valid on the
    # current command; obsolete aliases remain guided and reject --options.
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


def _ownership_error_message(path, need):
    """Actionable wrong-role error using the canonical CLI helpers when available."""
    resource = path[1] if len(path) > 1 else (path[0] if path else "that command")
    need_s = str(need or "").strip().lower()
    agent_resource = resource in ("remote-service", "remote-services") or need_s in (
        "client",
        "agent",
    )
    try:
        import drlink_v24 as v24
    except ImportError:
        v24 = None
    if agent_resource and resource in ("remote-service", "remote-services"):
        if v24 is not None:
            return v24.role_error_agent_resource()
        return (
            "ERROR:\n"
            "Remote Service is managed from the DRLink Agent Host.\n\n"
            "Run this command on the Agent Host that will own the Remote Service.\n\n"
            "No changes were applied."
        )
    if agent_resource and need_s in ("client", "agent"):
        if v24 is not None:
            return v24.role_error_agent_resource(str(resource).replace("-", " ").title())
        return (
            "ERROR:\n"
            "%s is managed from the DRLink Agent Host.\n\n"
            "Run this command on the Agent Host that will own the Remote Service.\n\n"
            "No changes were applied." % str(resource).replace("-", " ").title()
        )
    labels = {
        "internet-access": "Internet Access policy",
        "remote-access": "Remote Access policy",
        "ai-access": "AI Access policy",
        "ai-access-log": "AI Access Log",
        "managed-host": "Managed Host",
        "managed-hosts": "Managed Hosts",
        "network-object": "Network Object",
        "network-objects": "Network Objects",
        "network-group": "Network Group",
        "network-groups": "Network Groups",
        "service-object": "Service Object",
        "service-objects": "Service Objects",
        "service-group": "Service Group",
        "service-groups": "Service Groups",
        "permission-object": "Permission Object",
        "permission-objects": "Permission Objects",
        "permission-group": "Permission Group",
        "permission-groups": "Permission Groups",
        "ai-identity": "AI Identity",
        "ai-identities": "AI Identities",
        "enrollment": "Enrollment",
        "enrollments": "Enrollments",
    }
    label = labels.get(resource, str(resource).replace("-", " ").title())
    if v24 is not None:
        return v24.role_error_server_resource(label)
    return (
        "ERROR:\n"
        "%s is managed on the DRLink Server.\n\n"
        "Run this command on the DRLink Server.\n\n"
        "No changes were applied." % label
    )


def _canonical_result(tokens, role, names=None):
    """Resolve canonical action-first commands; expand hidden resource-first.

    Returns ``(internal_tokens, error_result)``. ``internal_tokens`` is None
    when the caller should keep the original tokens for verb-handler matching.
    """
    if not tokens:
        return None, None

    # Hidden resource-first compatibility → action-first.
    # Keep the caller's original tokens for to_internal so aliases that share a
    # public path (access create vs access edit-info → set acl) stay distinct.
    original = [str(t) for t in tokens]
    expanded = None
    if hasattr(CATALOG, "expand_compat_alias"):
        expanded = CATALOG.expand_compat_alias(tokens)
    work = list(expanded) if expanded is not None else list(tokens)
    # Option policy applies to the canonical/expanded form so hidden machine
    # flags declared on the public target (e.g. set enrollment) are accepted
    # when invoked via create enrollment / enroll aliases.
    opt_err = public_option_error(work)
    if opt_err is not None:
        return None, opt_err

    # Alias-aware lookup is required: resolve_tokens may already have lifted a
    # hidden form such as `update engine` to `system update engine`, but this
    # helper is called with the pre-resolve tokens. Without aliases, find()
    # misses the command, to_internal never runs, and match() then feeds the
    # lifted `system …` tokens to _match_system as a dead-end.
    cmd = CATALOG.find(work, include_aliases=True)
    if cmd is None:
        root = canonical_root(work[0])
        if root == "client" and _client_legacy_selector(work, names=names):
            return None, None
        if root in FALLTHROUGH_ROOTS:
            return None, None
        return None, None

    if not CATALOG.role_allows(cmd["roles"], role):
        path = tuple(cmd.get("path") or ())
        return None, {
            "status": "role",
            "need": cmd["roles"],
            "command": " ".join(path) if path else " ".join(work[:2]),
            "message": _ownership_error_message(path, cmd["roles"]),
        }
    # Documented enrollment modes rewrite before strict positional checks
    # (set enrollment has tail=flags and would otherwise reject zero-touch/manual).
    if (
        work[:2] == ["set", "enrollment"]
        and len(work) >= 3
        and work[2] in ("zero-touch", "manual")
    ):
        internal = CATALOG.to_internal(original)
        if internal is not None:
            return internal, None
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
    internal = CATALOG.to_internal(original)
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
    # Bang-prefix is always shell — check before option scanning.
    if str(tokens[0]).startswith("!"):
        return {"status": "shell"}
    # Keep pre-resolve tokens so to_internal can preserve create vs edit-info
    # (both alias to set acl) and similar distinct safety semantics.
    raw_tokens = [str(t) for t in tokens]
    rejected = reject_obsolete_surface(raw_tokens)
    if rejected is not None:
        return rejected
    # Hidden resource-first compatibility → canonical action-first tokens.
    tokens = CATALOG.resolve_tokens(tokens, role=role)
    rejected = reject_obsolete_surface(tokens)
    if rejected is not None:
        return rejected
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
    internal, problem = _canonical_result(raw_tokens, role, names=names)
    if problem is not None:
        return problem
    rewritten = internal is not None
    if rewritten:
        tokens = internal
        verb = tokens[0]
    # Reject shell-like tokens only when they are not catalog-resolved commands.
    if (not rewritten) and verb in SHELL_REJECT:
        return {"status": "shell"}
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
        "apply": lambda toks, role, names=None: (
            {
                "status": "ok",
                "action": "egress_cmd",
                "passthrough": ["recipe", "apply"] + list(toks[2:]),
            }
            if len(toks) > 1 and toks[1] == "egress-recipe"
            else {"status": "ok", "action": "apply"}
        ),
        "discard": lambda toks, role, names=None: {"status": "ok", "action": "discard"},
        "sync": lambda toks, role, names=None: {"status": "ok", "action": "sync"},
        "doctor": lambda toks, role, names=None: {"status": "ok", "action": "doctor", "passthrough": toks[1:]},
        "support-bundle": lambda toks, role, names=None: {"status": "ok", "action": "support_bundle", "passthrough": toks[1:]},
        "pause": lambda toks, role, names=None: {"status": "ok", "action": "client_pause"},
        "resume": lambda toks, role, names=None: {"status": "ok", "action": "client_resume"},
        "restart": lambda toks, role, names=None: {"status": "ok", "action": "client_restart"},
        "autostart": _match_autostart,
        "uninstall": _match_system_uninstall,
        "access": _match_access_root,
        "egress": _match_egress_root,
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
        "test": _match_test,
        "explain": _match_explain_egress,
        "export": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": ["export"] + list(toks[2:])},
        "import": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": ["import"] + list(toks[2:])},
        "diff": lambda toks, role, names=None: {"status": "ok", "action": "egress_cmd", "passthrough": ["diff"] + list(toks[2:])},
        "system": _match_system,
    }
    fn = handlers.get(verb)
    if fn is None:
        return {"status": "unknown", "command": verb}
    if verb in ("set", "unset", "create", "revoke", "purge", "release", "restore", "remove", "delete", "rename", "access", "egress") and not server and verb != "set":
        if verb == "set" and client:
            return fn(tokens, role, names)
        if verb == "unset" and client:
            return fn(tokens, role, names)
        return {"status": "role", "need": "server", "command": verb}
    if verb in ("apply", "discard", "sync", "pause", "resume", "restart", "autostart") and not client:
        return {"status": "role", "need": "client", "command": verb}
    if verb in ("enable", "disable"):
        if not client and not server:
            return {"status": "role", "need": "client or server", "command": verb}
    if verb == "add" and not client and not server:
        return {"status": "role", "need": "client or server", "command": verb}
    return fn(tokens, role, names)


def _match_test(tokens, role, names=None):
    avail = _test_resources(role)
    if len(tokens) == 1:
        return incomplete(
            "Missing test target.",
            ["test <target> ..."],
            avail,
        )
    target = tokens[1]
    if target in CONTROL_PLANE_TEST:
        return _control_plane_ok(tokens)
    if target in ("access", "acl"):
        if len(tokens) < 5:
            return {
                "status": "incomplete",
                "message": (
                    "Missing arguments.\n\n"
                    "Usage:\n"
                    "  test acl <CLIENT> <SERVICE> <SOURCE-IP>\n\n"
                    "Example:\n"
                    "  test acl dp1 ssh 10.10.10.25\n\n"
                    "This checks ACL policy only.\n"
                    "It does not open a live connection."
                ),
            }
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["test"] + list(tokens[2:]),
        }
    if target == "internet":
        return _egress_explain_passthrough(list(tokens[2:]))
    if target == "fixed-tcp":
        if len(tokens) < 4:
            return incomplete(
                "Missing arguments.",
                ["test fixed-tcp <ENTRY> <SOURCE-IP>"],
                examples=["test fixed-tcp vendor-license 10.10.30.25"],
            )
        return {
            "status": "ok",
            "action": "egress_cmd",
            "passthrough": ["tcp", "explain"] + list(tokens[2:]),
        }
    # Legacy absorbed forms after to_internal may already be explain/egress.
    if target == "egress":
        return _egress_explain_passthrough(list(tokens[2:]))
    return incomplete("Unknown test target.", ["test <target> ..."], avail)


def _egress_explain_passthrough(args):
    """Map optional trailing PROTOCOL to backend --protocol for explain."""
    args = list(args or [])
    if len(args) < 3:
        return {
            "status": "incomplete",
            "message": (
                "Missing arguments.\n\n"
                "Usage:\n"
                "  test internet <SOURCE-IP> <HOST> <PORT> [PROTOCOL]\n\n"
                "Example:\n"
                "  test internet 10.10.20.25 archive.ubuntu.com 443 https\n\n"
                "This checks policy and DNS safety.\n"
                "It does not make a live Internet connection."
            ),
        }
    if len(args) >= 4 and not str(args[3]).startswith("-"):
        proto = str(args[3]).lower()
        if proto not in ("http", "https", "tcp"):
            return {
                "status": "error",
                "exit_code": 2,
                "message": (
                    "Invalid PROTOCOL %r.\n\n"
                    "PROTOCOL must be one of: http, https, tcp"
                )
                % args[3],
            }
        args = args[:3] + ["--protocol", proto] + args[4:]
    return {
        "status": "ok",
        "action": "egress_cmd",
        "passthrough": ["explain"] + args,
    }


def _match_explain_egress(tokens, role, names=None):
    # explain egress SOURCE HOST PORT [PROTOCOL]
    return _egress_explain_passthrough(list(tokens[2:]))


def _match_access_root(tokens, role, names=None):
    pt = list(tokens[1:])
    if pt and pt[0] == "remove-expired":
        if len(pt) < 2:
            return incomplete(
                "Missing ACL.",
                ["system cleanup access-rule <RULE> expired"],
            )
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["remove-expired", pt[1]] + list(pt[2:]),
            "confirm_expired": True,
        }
    if pt and pt[0] == "log" and len(pt) < 3:
        return incomplete(
            "Missing arguments.",
            ["show access-log <CLIENT> <SERVICE>"],
            examples=["show access-log dp1 ssh"],
        )
    if pt and pt[0] == "test" and len(pt) < 4:
        return incomplete(
            "Missing arguments.",
            ["test acl <CLIENT> <SERVICE> <SOURCE-IP>"],
            examples=["test acl dp1 ssh 10.10.10.25"],
        )
    return {"status": "ok", "action": "access_cmd", "passthrough": pt}


def _match_egress_root(tokens, role, names=None):
    pt = list(tokens[1:])
    # Guided Fixed TCP create: egress tcp create <NAME>
    if len(pt) >= 2 and pt[0] == "tcp" and pt[1] == "create":
        if len(pt) < 3:
            return incomplete(
                "Missing Fixed TCP name.",
                ["set fixed-tcp <NAME>"],
            )
        return {
            "status": "ok",
            "action": "create_egress_tcp",
            "name": pt[2],
            "passthrough": list(pt[3:]),
        }
    if len(pt) >= 2 and pt[0] == "tcp" and pt[1] == "delete":
        if len(pt) < 3:
            return incomplete(
                "Missing Fixed TCP entry.",
                ["unset fixed-tcp <ENTRY>"],
            )
        return {
            "status": "ok",
            "action": "delete_egress_tcp",
            "name": pt[2],
            "passthrough": list(pt[3:]),
        }
    if len(pt) >= 2 and pt[0] == "tcp" and pt[1] == "explain":
        if len(pt) < 4:
            return incomplete(
                "Missing arguments.",
                ["test fixed-tcp <ENTRY> <SOURCE-IP>"],
                examples=["test fixed-tcp vendor-license 10.10.30.25"],
            )
    if len(pt) >= 1 and pt[0] == "explain" and len(pt) < 4:
        return incomplete(
            "Missing arguments.",
            ["test internet <SOURCE-IP> <HOST> <PORT> [PROTOCOL]"],
            examples=["test internet 10.10.20.25 archive.ubuntu.com 443 https"],
        )
    return {"status": "ok", "action": "egress_cmd", "passthrough": pt}


def _catalog_child_tokens(tokens, role):
    """Return next public catalog tokens when ``tokens`` is an incomplete parent."""
    probe = [str(t) for t in tokens]
    nxt = []
    rows = []
    for row in CATALOG.COMMANDS:
        if row.get("hidden"):
            continue
        if not CATALOG.role_allows(row["roles"], role):
            continue
        path = list(row["path"])
        if len(path) > len(probe) and path[: len(probe)] == probe:
            tok = path[len(probe)]
            if tok not in nxt:
                nxt.append(tok)
                summary = str(row.get("summary") or "").strip()
                rows.append((tok, summary))
    return nxt, rows


def _parent_discovery(tokens, role, *, title=None):
    """Treat a valid public parent as discovery, never 'Unknown'."""
    children, rows = _catalog_child_tokens(tokens, role)
    if not children:
        return None
    label = title or " ".join(str(t) for t in tokens)
    heading = label[:1].upper() + label[1:] if label else "Available"
    lines = [heading, "=" * len(heading), "", "Available:"]
    width = max((len(tok) for tok, _ in rows), default=0)
    for tok, summary in rows:
        if summary:
            lines.append("  %s  %s" % (tok.ljust(width), summary))
        else:
            lines.append("  %s" % tok)
    return {"status": "incomplete", "message": "\n".join(lines)}


def _match_system(tokens, role, names=None):
    avail = _system_resources(role)
    if len(tokens) == 1:
        return incomplete(
            "Missing system operation.",
            ["system <operation>"],
            avail,
        )
    discovery = _parent_discovery(tokens, role)
    if discovery is not None:
        return discovery
    op = tokens[1]
    # Bare aliases (history/clear/doctor/…) resolve to `system <op>` but
    # _canonical_result still sees the pre-resolve token list, so these must
    # be handled here or operators hit a dead-end "Unknown system operation".
    if op == "history":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["system history", "history"])
        return {"status": "ok", "action": "history"}
    if op == "clear":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["system clear", "clear"])
        return {"status": "ok", "action": "clear"}
    if op == "version":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["system version"])
        return {"status": "ok", "action": "show_version"}
    if op == "status":
        # Canonical public spelling. show status stays the summary action.
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["system status"])
        _client, server = _role_parts(role)
        if not server:
            return {"status": "role", "need": "server", "command": "system status"}
        return {"status": "ok", "action": "show_server_status", "passthrough": []}
    if op == "diagnostics":
        if len(tokens) > 2 and tokens[2] not in ("control-plane", "runtime", "mcp"):
            return incomplete(
                "Unknown diagnostics scope.",
                [
                    "system diagnostics",
                    "system diagnostics control-plane",
                    "system diagnostics runtime",
                    "system diagnostics mcp",
                ],
            )
        return {"status": "ok", "action": "doctor", "passthrough": list(tokens[2:])}
    if op == "support-bundle":
        return {"status": "ok", "action": "support_bundle", "passthrough": list(tokens[2:])}
    if op == "export" and len(tokens) >= 3 and tokens[2] == "configuration":
        return _control_plane_ok(tokens)
    if op == "apply" and len(tokens) >= 3 and tokens[2] == "configuration":
        return _control_plane_ok(tokens)
    if op == "diff" and len(tokens) >= 3 and tokens[2] == "configuration":
        return _control_plane_ok(tokens)
    if op in CONTROL_PLANE_SYSTEM:
        return _control_plane_ok(tokens)
    if op == "audit" and len(tokens) > 2 and tokens[2] in (
        "ai-principal",
        "revision",
        "entity",
        "object",
    ):
        return _control_plane_ok(tokens)
    if op == "revoke":
        return _match_revoke(["revoke"] + list(tokens[2:]), role, names)
    if op == "info":
        if len(tokens) > 2:
            return incomplete("Unexpected arguments.", ["system info", "info"])
        return {"status": "ok", "action": "show_info"}
    if op == "update":
        return _match_update(["update"] + list(tokens[2:]), role, names)
    if op == "pause":
        return {"status": "ok", "action": "client_pause"}
    if op == "resume":
        return {"status": "ok", "action": "client_resume"}
    if op == "restart":
        return {"status": "ok", "action": "client_restart"}
    # Prefer catalog-driven rewrite via to_internal; if we still see system *,
    # the rewrite missed — guide the operator.
    return incomplete(
        "Unknown system operation.",
        ["system <operation>"],
        avail,
        tip="Type: system ?",
    )


def _match_system_uninstall(tokens, role, names=None):
    """Help flags must not enter the destructive uninstall flow."""
    extra = [str(t) for t in tokens[1:]]
    if any(t in ("-h", "--help") for t in extra):
        return {
            "status": "ok",
            "action": "help",
            "passthrough": ["system", "uninstall"],
        }
    return {
        "status": "ok",
        "action": "system_uninstall",
        "passthrough": extra,
    }


def _match_autostart(tokens, role, names=None):
    if len(tokens) == 1:
        return {"status": "ok", "action": "client_autostart", "mode": "status"}
    mode = tokens[1]
    if mode in ("enable", "disable", "status"):
        if len(tokens) > 2:
            return incomplete(
                "Unexpected arguments.",
                [
                    "system autostart",
                    "system autostart enable",
                    "system autostart disable",
                ],
            )
        return {"status": "ok", "action": "client_autostart", "mode": mode}
    return incomplete(
        "Unknown autostart operation.",
        [
            "system autostart",
            "system autostart enable",
            "system autostart disable",
        ],
        ["enable", "disable"],
    )


def _match_show(tokens, role, names=None):
    avail = _show_resources(role)
    if len(tokens) == 1:
        return incomplete(
            "Missing resource.",
            ["show <resource>"],
            avail,
        )
    resource = tokens[1]
    if resource in CONTROL_PLANE_SHOW:
        return _control_plane_ok(tokens)
    # Final public terminology → existing actions (also covered by to_internal).
    _show_alias = {
        "acls": "access-lists",
        "acl": "access-list",
        "access-rules": "access-lists",
        "access-rule": "access-list",
        "internet": "egress",
        "internet-profiles": "egress-profiles",
        "internet-profile": "egress-profile",
        "internet-templates": "egress-recipes",
        "internet-template": "egress-recipe",
        "fixed-tcp": "egress-tcp",
    }
    resource = _show_alias.get(resource, resource)
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
            return incomplete("Missing ACL.", ["show acl <ACL>"])
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
        if len(tokens) < 4:
            return incomplete(
                "Missing arguments.",
                ["show access-log <CLIENT> <SERVICE>"],
                examples=["show access-log dp1 ssh"],
            )
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
        return {"status": "ok", "action": "show_audit", "passthrough": list(tokens[2:])}
    if resource == "upstream":
        return {"status": "ok", "action": "show_upstream", "passthrough": tokens[2:]}
    if resource == "services":
        return {"status": "ok", "action": "show_services"}
    if resource == "info":
        return {"status": "ok", "action": "show_info"}
    if resource in ("egress-tcp", "egress-tcp-entry"):
        if resource == "egress-tcp" and len(tokens) == 2:
            return {"status": "ok", "action": "egress_cmd", "passthrough": ["tcp", "list"]}
        if len(tokens) < 3:
            return incomplete("Missing Fixed TCP entry.", ["show fixed-tcp <ENTRY>"])
        return {
            "status": "ok",
            "action": "egress_cmd",
            "passthrough": ["tcp", "show", tokens[2]] + list(tokens[3:]),
        }
    if resource in ("egress-recipes", "egress-recipe"):
        if resource == "egress-recipes":
            return {"status": "ok", "action": "egress_cmd", "passthrough": ["recipe", "list"] + list(tokens[2:])}
        if len(tokens) < 3:
            return incomplete("Missing template.", ["show internet-template <TEMPLATE>"])
        return {
            "status": "ok",
            "action": "egress_cmd",
            "passthrough": ["recipe", "show", tokens[2]] + list(tokens[3:]),
        }
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
    if resource in CONTROL_PLANE_MUTATE:
        return _control_plane_ok(tokens)
    if resource == "client":
        if not server:
            return {"status": "role", "need": "server", "command": "set client"}
        # Bare set client → Zero-Touch onboarding (final public grammar).
        if len(tokens) == 2:
            return {"status": "ok", "action": "create_zero_touch"}
        if len(tokens) < 3:
            return missing_client_help(
                [
                    "set client",
                    "set client <ID> label <value>",
                    "set client <ID> note <value>",
                    "set client <ID> tag <key> <value>",
                    "set client <ID> group <GROUP>",
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
                "Missing ACL.",
                ["set acl <ACL>"],
                examples=["set acl office-network"],
            )
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["edit-info"] + list(tokens[2:]),
        }
    if resource == "acl":
        if len(tokens) < 3:
            return incomplete(
                "Missing ACL.",
                [
                    "set acl <ACL>",
                    "set acl <ACL> source <IP-or-CIDR>",
                    "set acl <ACL> service <CLIENT> <SERVICE>",
                ],
                examples=[
                    "set acl office-network",
                    "set acl office-network source 10.10.10.0/24",
                    "set acl office-network service dp1 ssh",
                ],
            )
        # Name-only create is rewritten before match; leftover nested forms
        # should not reach here without rewrite.
        return incomplete(
            "Unknown ACL operation.",
            [
                "set acl <ACL>",
                "set acl <ACL> name <VALUE>",
                "set acl <ACL> description <VALUE>",
                "set acl <ACL> source <IP-or-CIDR>",
                "set acl <ACL> service <CLIENT> <SERVICE>",
            ],
        )
    if resource == "access-source":
        if len(tokens) < 3:
            return incomplete("Missing ACL.", ["set acl <ACL> source <IP-or-CIDR>"])
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
            return {"status": "role", "need": "server", "command": "set internet-profile"}
        if len(tokens) < 3:
            return incomplete(
                "Missing Internet Access profile.",
                [
                    "set internet-profile <PROFILE>",
                    "set internet-profile <PROFILE> source <CIDR>",
                    "set internet-profile <PROFILE> destination <FQDN> <PORT> <PROTOCOL>",
                    "set internet-profile <PROFILE> enabled",
                ],
                examples=[
                    "set internet-profile ubuntu-update",
                    "set internet-profile ubuntu-update source 10.10.20.0/24",
                ],
            )
        # Canonical property form.
        if len(tokens) >= 4 and tokens[3] in ("name", "description"):
            if len(tokens) < 5:
                return incomplete(
                    "Missing value.",
                    ["set internet-profile <PROFILE> %s <value>" % tokens[3]],
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
    if resource == "internet-profile":
        if not server:
            return {"status": "role", "need": "server", "command": "set internet-profile"}
        return incomplete(
            "Missing Internet Access profile.",
            [
                "set internet-profile <PROFILE>",
                "set internet-profile <PROFILE> source <CIDR>",
                "set internet-profile <PROFILE> destination <FQDN> <PORT> <PROTOCOL>",
                "set internet-profile <PROFILE> enabled",
            ],
            examples=[
                "set internet-profile ubuntu-update",
                "set internet-profile ubuntu-update source 10.10.20.0/24",
            ],
        )
    if resource == "installer-url":
        if not server:
            return {"status": "role", "need": "server", "command": "set installer-url"}
        if len(tokens) < 3:
            return incomplete("Missing installer URL.", ["set installer-url <url>"])
        return {"status": "ok", "action": "set_installer_url", "value": tokens[2]}
    if resource == "windows-installer-url":
        if not server:
            return {"status": "role", "need": "server", "command": "set windows-installer-url"}
        if len(tokens) < 3:
            return incomplete(
                "Missing Windows installer URL.",
                ["set windows-installer-url <url>"],
            )
        return {
            "status": "ok",
            "action": "set_windows_installer_url",
            "value": tokens[2],
        }
    if resource == "server":
        if not server:
            return {"status": "role", "need": "server", "command": "set server"}
        # Canonical: public-hostname / bootstrap-hostname / installer URLs.
        # Hidden compat: hostname → public-hostname.
        server_settings = [
            "public-hostname",
            "bootstrap-hostname",
            "installer-url",
            "windows-installer-url",
        ]
        if len(tokens) < 3:
            return incomplete(
                "Missing server setting.",
                [
                    "set server public-hostname <fqdn>",
                    "set server bootstrap-hostname <fqdn>",
                    "set server installer-url <URL>",
                    "set server windows-installer-url <URL>",
                ],
                server_settings,
                tip="drlink help set",
            )
        setting = tokens[2]
        if setting == "hostname":
            setting = "public-hostname"
        if setting == "installer-url":
            if len(tokens) < 4:
                return incomplete(
                    "Missing installer URL.",
                    ["set server installer-url <URL>"],
                )
            if len(tokens) > 4:
                return {
                    "status": "error",
                    "message": "Too many arguments. Quote values that contain spaces.",
                }
            return {
                "status": "ok",
                "action": "set_installer_url",
                "value": tokens[3],
            }
        if setting == "windows-installer-url":
            if len(tokens) < 4:
                return incomplete(
                    "Missing Windows installer URL.",
                    ["set server windows-installer-url <URL>"],
                )
            if len(tokens) > 4:
                return {
                    "status": "error",
                    "message": "Too many arguments. Quote values that contain spaces.",
                }
            return {
                "status": "ok",
                "action": "set_windows_installer_url",
                "value": tokens[3],
            }
        if setting not in ("public-hostname", "bootstrap-hostname"):
            return incomplete(
                "Unknown server setting.",
                [
                    "set server public-hostname <fqdn>",
                    "set server bootstrap-hostname <fqdn>",
                    "set server installer-url <URL>",
                    "set server windows-installer-url <URL>",
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
    client, server = _role_parts(role)
    avail = _unset_resources(role)
    if len(tokens) < 2:
        return incomplete(
            "Missing resource.",
            ["unset <resource> ..."],
            avail,
        )
    resource = tokens[1]
    if resource in CONTROL_PLANE_MUTATE:
        return _control_plane_ok(tokens)
    if resource == "service":
        if not client:
            return {"status": "role", "need": "client", "command": "unset service"}
        # Prefer rewrite to disable; keep a direct path for safety.
        if len(tokens) >= 4 and tokens[3] == "enabled":
            return {
                "status": "ok",
                "action": "disable_service",
                "service": tokens[2],
            }
        return incomplete(
            "Only disabling a pending local service is supported.",
            ["unset service <SERVICE> enabled"],
        )
    if not server:
        return {"status": "role", "need": "server", "command": "unset %s" % resource}
    if resource == "server":
        settings = [
            "public-hostname",
            "bootstrap-hostname",
            "installer-url",
            "windows-installer-url",
        ]
        if len(tokens) < 3:
            return incomplete(
                "Missing server setting.",
                [
                    "unset server public-hostname",
                    "unset server bootstrap-hostname",
                    "unset server installer-url",
                    "unset server windows-installer-url",
                ],
                settings,
                tip="drlink help unset",
            )
        setting = tokens[2]
        if setting == "hostname":
            setting = "public-hostname"
        if setting not in settings:
            return incomplete(
                "Unknown server setting.",
                [
                    "unset server public-hostname",
                    "unset server bootstrap-hostname",
                    "unset server installer-url",
                    "unset server windows-installer-url",
                ],
                settings,
            )
        if len(tokens) > 3:
            return {"status": "error", "message": "Too many arguments."}
        if setting == "public-hostname":
            return {"status": "ok", "action": "unset_server_hostname"}
        if setting == "bootstrap-hostname":
            return {"status": "ok", "action": "unset_server_bootstrap_hostname"}
        if setting == "installer-url":
            return {"status": "ok", "action": "unset_installer_url"}
        return {"status": "ok", "action": "unset_windows_installer_url"}
    if resource == "enrollment":
        if len(tokens) < 3:
            return incomplete(
                "Missing enrollment id.",
                ["unset enrollment <ENROLLMENT>"],
            )
        return {
            "status": "ok",
            "action": "unset_enrollment",
            "id": tokens[2],
            "passthrough": tokens[3:],
        }
    if resource == "client":
        if len(tokens) < 3:
            return missing_client_help(
                [
                    "unset client <CLIENT>",
                    "unset client <CLIENT> trust",
                    "unset client <CLIENT> service <SERVICE>",
                    "unset client <CLIENT> group <GROUP>",
                    "unset client <CLIENT> label",
                    "unset client <CLIENT> note",
                    "unset client <CLIENT> tag <KEY>",
                ],
                names,
                tip="drlink help unset",
            )
        if len(tokens) == 3:
            return {
                "status": "ok",
                "action": "release_client",
                "client": tokens[2],
                "passthrough": [],
            }
        prop = tokens[3]
        if prop.startswith("-"):
            return {
                "status": "ok",
                "action": "release_client",
                "client": tokens[2],
                "passthrough": list(tokens[3:]),
            }
        if prop == "trust":
            return {
                "status": "ok",
                "action": "revoke_client",
                "client": tokens[2],
                "passthrough": tokens[4:],
            }
        if prop == "service":
            if len(tokens) < 5:
                return incomplete(
                    "Missing service id.",
                    ["unset client <CLIENT> service <SERVICE>"],
                )
            return {
                "status": "ok",
                "action": "release_service",
                "client": tokens[2],
                "service": tokens[4],
                "passthrough": tokens[5:],
            }
        if prop == "group":
            if len(tokens) < 5:
                return incomplete(
                    "Missing group.",
                    ["unset client <CLIENT> group <GROUP>"],
                )
            return {
                "status": "ok",
                "action": "remove_group_member",
                "client": tokens[2],
                "group": tokens[4],
            }
        if prop not in ("label", "note", "tag"):
            return incomplete(
                "Unknown client setting.",
                [
                    "unset client <CLIENT> trust",
                    "unset client <CLIENT> service <SERVICE>",
                    "unset client <CLIENT> group <GROUP>",
                    "unset client <CLIENT> label|note|tag",
                ],
                ["trust", "service", "group", "label", "note", "tag"],
            )
        if prop == "tag" and len(tokens) < 5:
            return incomplete("Missing tag key.", ["unset client <CLIENT> tag <KEY>"])
        return {
            "status": "ok",
            "action": "unset_client",
            "client": tokens[2],
            "property": prop,
            "value": tokens[4] if prop == "tag" else "",
        }
    if resource in ("acl", "access-rule", "access-list"):
        return incomplete(
            "Missing ACL.",
            [
                "unset acl <ACL>",
                "unset acl <ACL> source <IP-or-CIDR>",
                "unset acl <ACL> service <CLIENT> <SERVICE>",
            ],
            examples=["unset acl office-network"],
        )
    if resource in ("internet-profile", "egress-profile"):
        return incomplete(
            "Missing Internet Access profile.",
            [
                "unset internet-profile <PROFILE>",
                "unset internet-profile <PROFILE> enabled",
                "unset internet-profile <PROFILE> source <CIDR>",
                "unset internet-profile <PROFILE> destination <FQDN> <PORT> [PROTOCOL]",
            ],
            examples=["unset internet-profile ubuntu-update"],
        )
    # Other unset forms should normally be rewritten by to_internal.
    return incomplete(
        "Unknown unset resource.",
        ["unset <resource> ..."],
        avail,
    )


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
                tip="Prefer: set client   (or help clients)",
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
                "Missing ACL name.",
                ["set acl <ACL>"],
                examples=["set acl office-network"],
            )
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["create"] + list(tokens[2:]),
        }
    if resource == "egress-profile":
        if len(tokens) < 3:
            return incomplete(
                "Missing Internet Access profile name.",
                ["set internet-profile <PROFILE>"],
                examples=["set internet-profile ubuntu-update"],
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
            ["system update product", "system update engine"],
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
        ["system update product", "system update engine"],
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
                "protocol": "",
                "passthrough": [],
                "guided": True,
            }
        if len(tokens) < 5:
            return incomplete(
                "Destination FQDN and port required.",
                ["set internet-destination <PROFILE> <FQDN> <PORT> <PROTOCOL>"],
            )
        protocol = ""
        passthrough = list(tokens[5:])
        if passthrough and not str(passthrough[0]).startswith("-"):
            proto = str(passthrough[0]).lower()
            if proto not in ("http", "https", "tcp"):
                return {
                    "status": "error",
                    "exit_code": 2,
                    "message": (
                        "Invalid PROTOCOL %r.\n\n"
                        "PROTOCOL must be one of: http, https, tcp"
                    )
                    % passthrough[0],
                }
            protocol = proto
            passthrough = passthrough[1:]
        elif len(tokens) >= 5 and len(tokens) == 5:
            return incomplete(
                "PROTOCOL is required.",
                ["set internet-destination <PROFILE> <FQDN> <PORT> <PROTOCOL>"],
                ["http", "https", "tcp"],
            )
        return {
            "status": "ok",
            "action": "add_egress_destination",
            "profile": tokens[2],
            "host": tokens[3],
            "port": tokens[4],
            "protocol": protocol,
            "passthrough": passthrough,
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
                "Missing Access Rule.",
                ["set access-source <RULE> <SOURCE>"],
            )
        if len(tokens) == 3:
            return {
                "status": "ok",
                "action": "access_cmd",
                "passthrough": ["add-source", tokens[2]],
                "guided": True,
            }
        # Flag form: add access-source <LIST> --name … --source …
        if str(tokens[3]).startswith("-"):
            return {
                "status": "ok",
                "action": "access_cmd",
                "passthrough": ["add-source", tokens[2]] + list(tokens[3:]),
                "guided": False,
            }
        # Positional: add access-source <LIST> <SOURCE> [flags…]
        source = tokens[3]
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": [
                "add-source",
                tokens[2],
                "--name",
                source,
                "--source",
                source,
            ]
            + list(tokens[4:]),
            "guided": False,
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
            return incomplete(
                "Missing Internet Access profile.",
                ["unset internet-destination <PROFILE> <FQDN> <PORT> [PROTOCOL]"],
            )
        if len(tokens) < 4:
            return {
                "status": "ok",
                "action": "remove_egress_destination",
                "profile": tokens[2],
                "destination": "",
                "host": "",
                "port": "",
                "protocol": "",
                "passthrough": [],
                "guided": True,
            }
        # Legacy selector form: remove egress-destination PROFILE SELECTOR
        if len(tokens) == 4:
            return {
                "status": "ok",
                "action": "remove_egress_destination",
                "profile": tokens[2],
                "destination": tokens[3],
                "host": "",
                "port": "",
                "protocol": "",
                "passthrough": [],
            }
        # Public form: PROFILE FQDN PORT [PROTOCOL]
        protocol = ""
        extra = list(tokens[5:])
        if extra and not str(extra[0]).startswith("-"):
            proto = str(extra[0]).lower()
            if proto not in ("http", "https", "tcp"):
                return {
                    "status": "error",
                    "exit_code": 2,
                    "message": (
                        "Invalid PROTOCOL %r.\n\n"
                        "PROTOCOL must be one of: http, https, tcp"
                    )
                    % extra[0],
                }
            protocol = proto
            extra = extra[1:]
        return {
            "status": "ok",
            "action": "remove_egress_destination",
            "profile": tokens[2],
            "destination": "%s:%s" % (tokens[3], tokens[4]),
            "host": tokens[3],
            "port": tokens[4],
            "protocol": protocol,
            "passthrough": extra,
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
            return incomplete("Missing Access Rule.", ["unset access-source <RULE> <SOURCE>"])
        if len(tokens) == 3:
            return {
                "status": "ok",
                "action": "access_cmd",
                "passthrough": ["remove-source", tokens[2]],
                "guided": True,
            }
        # Flag form: remove access-source <LIST> --source …
        if str(tokens[3]).startswith("-"):
            return {
                "status": "ok",
                "action": "access_cmd",
                "passthrough": ["remove-source", tokens[2]] + list(tokens[3:]),
                "guided": False,
            }
        source = tokens[3]
        return {
            "status": "ok",
            "action": "access_cmd",
            "passthrough": ["remove-source", tokens[2], "--source", source] + list(tokens[4:]),
            "guided": False,
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
    profile_resource = None
    if len(tokens) >= 2 and tokens[1] in ("internet-profile", "egress-profile") and server:
        profile_resource = tokens[1]
    if profile_resource is not None:
        public_resource = "internet-profile"
        if len(tokens) < 3:
            return incomplete(
                "Missing Internet Access profile selector.",
                ["%s internet-profile <PROFILE>" % verb],
            )
        return {
            "status": "ok",
            "action": "%s_egress_profile" % verb,
            "profile": tokens[2],
        }
    if len(tokens) < 2 or tokens[1] != "service":
        avail = []
        usage = []
        if client_role:
            avail.append("service")
            usage.append("%s service <service-id>" % verb)
        if server:
            avail.append("internet-profile")
            usage.append("%s internet-profile <PROFILE>" % verb)
        return incomplete(
            "Missing resource.",
            usage or ["%s internet-profile <PROFILE>" % verb],
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
    if tokens[0].startswith("!"):
        return []
    if not trailing and len(tokens) == 1:
        prefix = tokens[0]
        root_hits = [v for v in canonical_verbs(role) if v.startswith(prefix)]
        # Exact shell tokens stay rejected unless they are a public-root prefix
        # (e.g. ``sh`` → ``show``).
        if prefix in SHELL_REJECT and not root_hits:
            return []
        return root_hits
    if tokens[0] in SHELL_REJECT:
        return []
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
        "sync": "Reconcile local services against server releases",
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
                "group": "Add client to a group",
            }, "named"
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
                "trust": "Block management trust (ports reserved)",
                "service": "Release one service reservation",
                "group": "Remove group membership",
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
    # Progressive disclosure: group large resource lists by product domain.
    groups = CATALOG.group_completion_candidates(matches)
    if groups and style != "clients" and len(matches) >= 6:
        out = []
        for title, members in groups:
            out.append(title)
            for mid in members:
                desc = (descs or {}).get(mid) or ""
                if desc:
                    out.append("  %s  %s" % (mid, desc))
                else:
                    out.append("  %s" % mid)
            out.append("")
        return "\n".join(out).rstrip()
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
    if cmd is None:
        # Prefix of a longer public command (e.g. system update → product|engine).
        nxt = []
        for row in CATALOG.COMMANDS:
            if row.get("hidden"):
                continue
            if not CATALOG.role_allows(row["roles"], role):
                continue
            path = list(row["path"])
            if len(path) > len(probe) and path[: len(probe)] == probe:
                tok = path[len(probe)]
                if tok not in nxt:
                    nxt.append(tok)
        if nxt:
            return _filter(nxt, prefix)
        return None if root in FALLTHROUGH_ROOTS else []
    if not CATALOG.role_allows(cmd["roles"], role):
        return None if root in FALLTHROUGH_ROOTS else []
    def _longer_path_children():
        nxt = []
        for row in CATALOG.COMMANDS:
            if row.get("hidden"):
                continue
            if not CATALOG.role_allows(row["roles"], role):
                continue
            path = list(row["path"])
            if len(path) > len(probe) and path[: len(probe)] == probe:
                tok = path[len(probe)]
                if tok not in nxt:
                    nxt.append(tok)
        return _filter(nxt, prefix)

    index = len(probe) - len(cmd["path"])
    # Hidden / arity-1 flags take precedence over positional arg completion so
    # Tab never advertises preset/property overlays after `--preset `.
    pending = _pending_flag_value(tokens or filled, cmd, trailing=trailing)
    if pending is not None:
        flag_meta, value_prefix = pending
        if flag_meta.get("hidden"):
            return []
        choices = flag_meta.get("choices") or ()
        if choices:
            return _filter(list(choices), value_prefix)
        return []
    if index < len(cmd["args"]):
        arg = cmd["args"][index]
        complete = arg["complete"]
        hits = []
        if isinstance(complete, (list, tuple)):
            hits = _filter(list(complete), prefix)
        elif complete == CATALOG.C_CLIENT_SERVICE:
            selector = _selector_before(cmd, probe, CATALOG.C_CLIENT)
            hits = _filter((services or {}).get(selector, []), prefix)
        else:
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
                hits = _filter(pool, prefix)
        longer = _longer_path_children()
        merged = []
        for item in list(hits) + list(longer or []):
            if item not in merged:
                merged.append(item)
        return merged
    # Path fully matched: offer longer public children (e.g. set enrollment → bulk)
    # and never advertise --options.
    longer = _longer_path_children()
    if longer:
        return longer
    # No further catalog tokens — allow verb-specific overlays (set service
    # properties, set client metadata, …) instead of hard-stopping with [].
    return None


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
        topics = list(canonical_verbs(role)) + [
            "clients",
            "services",
            "internet",
            "system",
            "workflows",
            "commands",
            "legacy",
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
        return []
    if verb == "set":
        if len(filled) == 1:
            return _filter(_set_resources(role), prefix)
        if filled[1] == "client" and server:
            if len(filled) == 2:
                return _filter(names, prefix)
            if len(filled) == 3:
                return _filter(["label", "note", "tag", "group"], prefix)
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
                return _filter(
                    ["trust", "service", "group", "label", "note", "tag"],
                    prefix,
                )
            if len(filled) == 4 and filled[3] == "service":
                return _filter((services or {}).get(filled[2], []), prefix)
            if len(filled) == 4 and filled[3] == "group":
                return _filter(groups or [], prefix)
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
            return _filter(["service", "internet-profile"], prefix)
        if filled[1] == "service" and len(filled) == 2:
            return _filter(local_services, prefix)
        if filled[1] in ("internet-profile", "egress-profile") and len(filled) == 2:
            return _filter(egress_profiles or [], prefix)
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
