#!/usr/bin/env python3
"""Canonical Data Relay Link CLI command catalog (CLI-011).

Single source of truth for the final public ``drlink`` grammar:

    show | set | unset | test | system | menu | help | exit

Root help, ``help <topic>``, context ``?``, Tab discovery, and the guided
menu are all derived from :data:`PUBLIC_COMMANDS` / :data:`COMMANDS`.

Public UX never advertises GNU-style ``--options`` or backend ``frp-*``
tool names. Obsolete development-era aliases are rejected by the grammar
rather than silently translated; :data:`HIDDEN_COMPAT_ALIASES` must stay empty.
"""
from __future__ import annotations

# --- completion provider names -------------------------------------------
# Resolved by the caller against the live read-only inventory payload.
C_CLIENT = "clients"
C_GROUP = "groups"
C_LOCAL_SERVICE = "local-services"
C_CLIENT_SERVICE = "client-services"
C_PROFILE = "service-profiles"
C_EGRESS = "egress-profiles"
C_ACCESS_LIST = "access-lists"
C_PATH = "path"
C_OBJECT = "objects"
C_OBJECT_GROUP = "object-groups"
C_CLIENT_GROUP = "client-groups"
C_ENDPOINT = "managed-endpoints"
C_REMOTE_RULE = "remote-access-rules"
C_INTERNET_RULE = "internet-access-rules"
C_RA_SOURCE = "remote-access-sources"
C_RA_DEST = "remote-access-destinations"
C_IA_SOURCE = "internet-access-sources"
C_IA_DEST = "internet-access-destinations"
C_PRESET = "service-presets"
C_FIXED_TCP = "fixed-tcp"
C_AI_PRINCIPAL = "ai-principals"
C_AI_RULE = "ai-access-rules"
C_NONE = None

CLIENT_PROPS = ("label", "note", "tag")
SERVER_SETTINGS = (
    "public-hostname",
    "bootstrap-hostname",
    "installer-url",
    "windows-installer-url",
)
INSTALLER_URL_SETTINGS = ("installer-url", "windows-installer-url")
GROUP_PROPS = ("name", "description")
SERVICE_PROPS = (
    "target-host",
    "target-port",
    "ssh-user",
    "name",
    "health-type",
    "health-timeout",
    "health-interval",
    "health-max-failed",
    "health-path",
)
PROFILE_PROPS = (
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
)
CLIENT_VIEWS = ("services", "tags", "groups")


def _arg(name, complete=C_NONE, required=True):
    return {"name": name, "complete": complete, "required": bool(required)}


# Lightweight operator risk / confirmation vocabulary (not a policy engine).
RISK_LEVELS = frozenset(
    {"none", "metadata", "outage", "irreversible", "security_widening"}
)
CONFIRMATION_MODES = frozenset({"none", "y_n", "typed_token", "yes_flag"})


def _flag(
    name,
    arity=1,
    choices=(),
    hidden=False,
    required=False,
    description="",
    metavar="",
    examples=(),
    effect="",
    risk="",
    type="",
    unit="",
    default="",
    platform="",
    role="",
    maximum="",
):
    """Describe one option flag.

    ``arity`` is ``0`` for boolean switches (no value) and ``1`` for flags that
    consume the next token as a value (AUDIT-014).
    """
    risk_text = str(risk or "")
    if risk_text and risk_text not in RISK_LEVELS:
        raise ValueError("unknown flag risk: %s" % risk_text)
    out = {
        "name": str(name),
        "arity": 0 if int(arity) == 0 else 1,
        "choices": tuple(choices) if choices else (),
        "hidden": bool(hidden),
        "required": bool(required),
        "description": str(description or ""),
        "metavar": str(metavar or ""),
        "examples": tuple(examples) if examples else (),
        "effect": str(effect or ""),
        "risk": risk_text,
    }
    if type:
        out["type"] = str(type)
    if unit:
        out["unit"] = str(unit)
    if default != "":
        out["default"] = default
    if maximum != "":
        out["maximum"] = maximum
    if platform:
        out["platform"] = str(platform)
    if role:
        out["role"] = str(role)
    return out


ENROLL_FLAGS = (
    _flag(
        "--one-line",
        arity=0,
        description="Print a one-line zero-touch client install command",
        effect="Emits installer/bootstrap output instead of interactive manual steps",
        risk="metadata",
    ),
    _flag(
        "--ssh",
        arity=0,
        description="Seed an SSH convenience service (127.0.0.1:22)",
        effect="Requires --one-line; mutually exclusive with --rdp and --services-file",
        risk="metadata",
        platform="linux",
    ),
    _flag(
        "--ssh-user",
        arity=1,
        metavar="USER",
        description="SSH login user for the ssh preset",
        effect="Required for non-interactive --ssh creation",
        risk="metadata",
    ),
    _flag(
        "--ssh-port",
        arity=1,
        metavar="PORT",
        description="Local SSH listen port (default 22)",
        type="integer",
        unit="port",
        default=22,
        risk="metadata",
    ),
    _flag(
        "--ttl",
        arity=1,
        metavar="DURATION|SECONDS",
        description=(
            "Enrollment lifetime as duration (30m|1h|4h|1d) or raw seconds "
            "(maximum 30d / 2592000 seconds)"
        ),
        examples=("4h", "600"),
        default=600,
        maximum=2592000,
        effect="Credential expires automatically after TTL",
        risk="metadata",
        type="duration",
        unit="s|m|h|d|seconds",
        role="enrollment",
    ),
    _flag("--note", arity=1, metavar="TEXT", description="Operator note", risk="metadata"),
    _flag(
        "--label",
        arity=1,
        metavar="NAME",
        hidden=True,
        description="Alias for --client-name",
        risk="metadata",
    ),
    _flag(
        "--client-name",
        arity=1,
        metavar="NAME",
        description="Administrator label seeded at enrollment",
        effect="Display metadata only; does not replace client hostname",
        risk="metadata",
    ),
    _flag(
        "--services-file",
        arity=1,
        metavar="PATH",
        description="JSON service list (same schema as FRP_SERVICES_JSON)",
        effect="Requires --one-line; mutually exclusive with --ssh and --rdp",
        risk="metadata",
        type="path",
    ),
    _flag(
        "--platform",
        arity=1,
        choices=("linux", "windows"),
        default="linux",
        description="Client platform for the one-line installer command",
        effect="Windows requires windows_client_installer_url in server config",
        risk="metadata",
        type="enum",
    ),
    _flag(
        "--rdp",
        arity=0,
        description="Windows RDP convenience service (127.0.0.1:3389)",
        effect="Requires --one-line and --platform windows",
        risk="metadata",
        platform="windows",
    ),
    _flag(
        "--rdp-port",
        arity=1,
        metavar="PORT",
        description="Local RDP listen port (default 3389)",
        effect="Requires --rdp",
        type="integer",
        unit="port",
        default=3389,
        risk="metadata",
        platform="windows",
    ),
)
BULK_FLAGS = ("--count", "--csv", "--label-prefix", "--ssh-user", "--note", "--ttl")
PROFILE_CREATE_FLAGS = (
    "--preset",
    "--target-host",
    "--target-port",
    "--description",
    "--ssh-user",
    "--health-type",
    "--health-timeout",
    "--health-interval",
    "--health-max-failed",
    "--health-path",
)
SERVICE_ADD_FLAGS = (
    "--profile",
    "--preset",
    "--id",
    "--name",
    "--target-host",
    "--target-port",
    "--ssh-user",
)

# --- root actions ---------------------------------------------------------
# (name, roles, category, summary)
# Categories are display-only groupings for help/menu discoverability.
ROOTS = (
    ("show", "any", "View", "View Managed Hosts, Remote Services, policies and status"),
    ("set", "any", "Change", "Create, add, change or enable configuration"),
    ("unset", "any", "Change", "Remove, delete, revoke, release or disable configuration"),
    ("test", "server", "Validate", "Check policy decisions without changing configuration"),
    ("system", "any", "System", "Updates, backup, restore, diagnostics and system operations"),
    ("menu", "any", "Session", "Open the guided menu"),
    ("help", "any", "Session", "Show help"),
    ("exit", "any", "Session", "Exit Data Relay Link"),
)

CATEGORY_ORDER = (
    "View",
    "Change",
    "Validate",
    "System",
    "Session",
)


# Surfaces intentionally absent from the public catalog (ARCH-AUDIT-001).
# Format: ("tool", "subcommand", "flag-or-*")
BACKEND_SURFACE_EXEMPT = frozenset(
    {
        # Compat / hidden create path; public create is always disabled.
        ("frp-egress", "create", "--enable"),
        ("frp-egress", "create", "--disabled"),
        # Short -o stays accepted by the backend; catalog advertises --output.
        ("frp-egress", "export", "-o"),
    }
)


def _normalize_flags(flags):
    """Accept ``_flag(...)`` dicts or legacy bare ``"--name"`` strings."""
    out = []
    for item in flags or ():
        if isinstance(item, dict):
            out.append(
                _flag(
                    item["name"],
                    arity=item.get("arity", 1),
                    choices=item.get("choices") or (),
                    hidden=item.get("hidden", False),
                    required=item.get("required", False),
                    description=item.get("description") or "",
                    metavar=item.get("metavar") or "",
                    examples=item.get("examples") or (),
                    effect=item.get("effect") or "",
                    risk=item.get("risk") or "",
                    type=item.get("type", ""),
                    unit=item.get("unit", ""),
                    default=item.get("default", ""),
                    maximum=item.get("maximum", ""),
                    platform=item.get("platform", ""),
                    role=item.get("role", ""),
                )
            )
            continue
        name = str(item)
        # Historical bare strings: treat known switches as arity-0.
        arity = 0 if name in _BOOLEAN_FLAG_NAMES else 1
        meta = _FLAG_DEFAULT_META.get(name, {})
        out.append(
            _flag(
                name,
                arity=arity,
                choices=meta.get("choices") or (),
                description=meta.get("description", ""),
                metavar=meta.get("metavar", ""),
                examples=meta.get("examples", ()),
                effect=meta.get("effect", ""),
                risk=meta.get("risk", ""),
                type=meta.get("type", ""),
                unit=meta.get("unit", ""),
                default=meta.get("default", ""),
                maximum=meta.get("maximum", ""),
                platform=meta.get("platform", ""),
                role=meta.get("role", ""),
            )
        )
    return tuple(out)


# Boolean switches historically listed as bare strings in flag tuples.
_BOOLEAN_FLAG_NAMES = frozenset(
    {
        "--one-line",
        "--ssh",
        "--rdp",
        "--yes",
        "--force",
        "--check",
        "--json",
        "--verbose",
        "--quiet",
        "--allow",
        "--deny",
        "--enable",
        "--disabled",
    }
)

# Shared help metadata applied when flags are listed as bare strings.
_FLAG_DEFAULT_META = {
    "--yes": {
        "description": "Confirm without an interactive prompt (automation)",
        "effect": "Skips y/N confirmation when the backend requires it",
        "risk": "security_widening",
    },
    "--force": {
        "description": "Override a safety gate (active publish or typed confirm)",
        "effect": "Bypasses an interactive or active-state guard",
        "risk": "irreversible",
    },
    "--ttl": {
        "description": "Temporary entry lifetime (access lists; max 3650d)",
        "metavar": "30m|1h|4h|1d",
        "examples": ("4h", "1d"),
        "effect": "Entry expires automatically after the TTL (maximum 3650d)",
        "risk": "metadata",
        "type": "duration",
        "unit": "s|m|h|d",
        "role": "access",
    },
    "--preset": {
        "description": "Service preset template (ssh, http, https, custom)",
        "metavar": "PRESET",
        "examples": ("ssh", "http", "https"),
        "effect": "Seeds target defaults from a preset",
        "risk": "metadata",
        "type": "enum",
        "choices": ("ssh", "http", "https", "custom"),
    },
    "--profile": {
        "description": "Service profile template name or id",
        "metavar": "PROFILE",
        "effect": "Copies template defaults into a pending service",
        "risk": "metadata",
        "type": "profile",
    },
    "--target-host": {
        "description": "Local target host or IP for the service",
        "metavar": "HOST",
        "type": "host",
        "risk": "metadata",
    },
    "--target-port": {
        "description": "Local target TCP port",
        "metavar": "PORT",
        "type": "integer",
        "unit": "port",
        "risk": "metadata",
    },
    "--health-timeout": {
        "description": "Health check timeout",
        "metavar": "SECONDS",
        "type": "integer",
        "unit": "seconds",
        "risk": "metadata",
    },
    "--health-interval": {
        "description": "Health check interval",
        "metavar": "SECONDS",
        "type": "integer",
        "unit": "seconds",
        "risk": "metadata",
    },
    "--older-than": {
        "description": "Purge enrollments older than this many days",
        "metavar": "DAYS",
        "type": "integer",
        "unit": "days",
        "default": 30,
        "effect": "Bulk purge terminal enrollment metadata",
        "risk": "irreversible",
    },
    "--name": {
        "description": "Human-readable name for the entry or object",
        "metavar": "NAME",
        "effect": "Sets display name only; selectors stay immutable IDs",
        "risk": "metadata",
    },
    "--ssh-user": {
        "description": "SSH login user for ssh preset targets",
        "metavar": "USER",
        "effect": "Required for ssh presets; shown in connect hints",
        "risk": "metadata",
    },
    "--output": {
        "description": "Write output to this path instead of stdout",
        "metavar": "PATH",
        "risk": "none",
    },
    "--description": {
        "description": "Free-form operator note",
        "metavar": "TEXT",
        "risk": "metadata",
    },
    "--source": {
        "description": "Source IP, CIDR, entry name, or entry id",
        "metavar": "IP|CIDR|NAME|ID",
        "risk": "metadata",
    },
    "--new-source": {
        "description": "Replacement source IP or CIDR",
        "metavar": "IP|CIDR",
        "risk": "metadata",
    },
    "--protocol": {
        "description": "Allowed application protocol",
        "metavar": "http|https|tcp",
        "choices": ("http", "https", "tcp"),
        "type": "enum",
        "risk": "metadata",
    },
}


def flag_names(flags, *, include_hidden=False):
    """Return advertised (or all) flag names from a command's flag metadata."""
    names = []
    for flag in _normalize_flags(flags):
        if flag["hidden"] and not include_hidden:
            continue
        names.append(flag["name"])
    return names


def _cmd(
    path,
    roles,
    category,
    summary,
    detail="",
    examples=(),
    args=(),
    flags=(),
    tail=None,
    internal=None,
    aliases=(),
    destructive=False,
    hidden=False,
    risk="none",
    confirmation="none",
    surface="",
):
    """Describe one canonical command.

    ``tail`` is ``None`` for a strict command (no tokens beyond ``args``),
    ``"flags"`` when trailing option flags are forwarded, and ``"any"`` when
    the remainder is an opaque passthrough.

    ``hidden=True`` keeps the command parseable (compat alias) but excludes it
    from Tab / help / menu / parity discovery surfaces.

    ``risk`` / ``confirmation`` are lightweight operator-facing metadata for
    help and tests (not an enforcement engine).

    ``surface`` may be ``""`` (public), ``legacy_only``, ``internal_only``, or
    ``hidden_compat`` for ARCH-AUDIT-001 reverse-parity annotations.
    """
    risk_text = str(risk or "none")
    confirm_text = str(confirmation or "none")
    surface_text = str(surface or "")
    if risk_text not in RISK_LEVELS:
        raise ValueError("unknown risk: %s" % risk_text)
    if confirm_text not in CONFIRMATION_MODES:
        raise ValueError("unknown confirmation: %s" % confirm_text)
    if surface_text and surface_text not in (
        "legacy_only",
        "internal_only",
        "hidden_compat",
    ):
        raise ValueError("unknown surface: %s" % surface_text)
    return {
        "path": tuple(path),
        "roles": roles,
        "category": category,
        "summary": summary,
        "detail": detail,
        "examples": tuple(examples),
        "args": tuple(args),
        "flags": _normalize_flags(flags),
        "tail": tail,
        "internal": internal,
        "aliases": tuple(tuple(a) for a in aliases),
        "destructive": bool(destructive),
        "hidden": bool(hidden),
        "risk": risk_text,
        "confirmation": confirm_text,
        "surface": surface_text,
    }


# Historical inline command table removed. Current product surface is
# loaded from frp_cli_final_commands.json via _load_final_commands().
# Prior-release migration fixtures live under tests/fixtures only.
_MIGRATION_SOURCE_COMMANDS = ()



# --- FINAL PUBLIC COMMAND SSOT (v2.4.0) -----------------------------------
# Public grammar is the literal command tree in frp_cli_final_commands.json.
# Migration source above is retained only as a private reference for internals;
# it is NOT the public SSOT and is not flipped at runtime.

import json as _json
import os as _os

_FINAL_JSON = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "frp_cli_final_commands.json")


def _load_final_commands():
    with open(_FINAL_JSON, "r", encoding="utf-8") as fh:
        rows = _json.load(fh)
    out = []
    for row in rows:
        args = tuple(
            _arg(a["name"], a.get("complete"), required=a.get("required", True))
            for a in (row.get("args") or [])
        )
        raw_flags = row.get("flags") or []
        if raw_flags and isinstance(raw_flags[0] if raw_flags else None, str):
            raw_flags = [{"name": n, "hidden": True} for n in raw_flags]
        if not raw_flags and row.get("flag_names"):
            raw_flags = [{"name": n, "hidden": True} for n in row["flag_names"]]
        flags = []
        for f in raw_flags:
            if not isinstance(f, dict):
                f = {"name": str(f), "hidden": True}
            flags.append(
                _flag(
                    f["name"],
                    arity=f.get("arity", 1),
                    choices=tuple(f.get("choices") or ()),
                    hidden=bool(f.get("hidden", True)),
                    required=False,
                    description=f.get("description") or "",
                    metavar=f.get("metavar") or "",
                    examples=tuple(f.get("examples") or ()),
                    effect=f.get("effect") or "",
                    risk=f.get("risk") or "",
                    type=f.get("type", ""),
                    unit=f.get("unit", ""),
                    default=f.get("default", ""),
                    maximum=f.get("maximum", ""),
                    platform=f.get("platform", ""),
                    role=f.get("role", ""),
                )
            )
        flags = tuple(flags)
        out.append(
            _cmd(
                tuple(row["path"]),
                row["roles"],
                row["category"],
                row["summary"],
                detail=row.get("detail") or "",
                examples=tuple(row.get("examples") or ()),
                args=args,
                flags=flags,
                tail=row.get("tail"),
                internal=tuple(row["internal"]) if row.get("internal") else None,
                aliases=tuple(tuple(a) for a in (row.get("aliases") or ())),
                destructive=bool(row.get("destructive")),
                hidden=bool(row.get("hidden")),
                risk=row.get("risk") or "none",
                confirmation=row.get("confirmation") or "none",
                # Hidden keeps parser compatibility without advertising nouns.
                # Do not auto-label as hidden_compat (forbidden on current gate).
                surface=str(row.get("surface") or ""),
            )
        )
    return tuple(out)


COMMANDS = _load_final_commands()
PUBLIC_COMMANDS = tuple(cmd for cmd in COMMANDS if not cmd.get("hidden"))
# Compatibility alias catalog must stay empty for current product surface.
# Historical aliases belong in migration fixtures / prior-release tests only.
# Public discovery must not advertise compatibility aliases.
HIDDEN_COMPAT_ALIASES = {}

# --- role helpers ---------------------------------------------------------
def role_parts(role):
    role = (role or "").strip().lower()
    return role in ("client", "both", "dual"), role in ("server", "both", "dual")


def role_allows(roles, role):
    client, server = role_parts(role)
    if roles == "any":
        return True
    if roles == "server":
        return server
    if roles == "client":
        return client
    return False


def roots_for_role(role):
    """Ordered canonical root actions visible for this host role."""
    out = []
    for name, roles, _category, _summary in ROOTS:
        if not role_allows(roles, role):
            continue
        if name in ("help", "menu", "exit"):
            out.append(name)
            continue
        if not _root_has_commands(name, role):
            continue
        out.append(name)
    return out

def root_rows(role):
    """(name, summary) rows for the canonical root actions."""
    rows = []
    allowed = set(roots_for_role(role))
    client, server = role_parts(role)
    for name, roles, _category, summary in ROOTS:
        if name not in allowed:
            continue
        if name == "show":
            if server and not client:
                summary = "View Managed Hosts, policies and status"
            elif client and not server:
                summary = "View Remote Services and status"
        elif name == "set":
            if client and not server:
                summary = "Create or change Remote Services on this Agent Host"
            elif server and not client:
                summary = "Create, add, change or enable Server configuration"
        elif name == "unset":
            if client and not server:
                summary = "Remove or disable Remote Services on this Agent Host"
            elif server and not client:
                summary = "Remove, delete, revoke, release or disable Server configuration"
        elif name == "test":
            summary = "Check policy decisions without changing configuration"
        elif name == "system":
            if client and not server:
                summary = "Updates, diagnostics and Agent system operations"
            elif server and not client:
                summary = "Updates, backup, restore, diagnostics and system operations"
        rows.append((name, summary))
    return rows

def _root_has_commands(root, role):
    for cmd in COMMANDS:
        if cmd["path"][0] == root and role_allows(cmd["roles"], role):
            return True
    return False


def commands_for_role(role):
    return [cmd for cmd in COMMANDS if role_allows(cmd["roles"], role)]


def subcommands(root, role):
    """Ordered (action, summary) pairs under one root resource."""
    rows = []
    seen = set()
    for cmd in COMMANDS:
        path = cmd["path"]
        if len(path) < 2 or path[0] != root:
            continue
        if cmd.get("hidden"):
            continue
        if not role_allows(cmd["roles"], role):
            continue
        if path[1] in seen:
            continue
        seen.add(path[1])
        rows.append((path[1], cmd["summary"]))
    return rows


def find(tokens, role=None, include_aliases=False):
    """Longest canonical command whose path is a prefix of ``tokens``.

    When ``include_aliases`` is true, also match hidden compatibility aliases
    (historical resource-first forms) and return the canonical command.
    """
    best = None
    best_len = -1
    for cmd in COMMANDS:
        candidates = [cmd["path"]]
        if include_aliases:
            candidates.extend(cmd.get("aliases") or ())
        for path in candidates:
            path = tuple(path)
            if len(tokens) < len(path):
                continue
            if tuple(tokens[: len(path)]) != path:
                continue
            if role is not None and not role_allows(cmd["roles"], role):
                continue
            if len(path) > best_len:
                best = cmd
                best_len = len(path)
    return best


def resolve_tokens(tokens, role=None):
    """Expand a hidden compatibility alias into the canonical action-first path."""
    if not tokens:
        return list(tokens)
    cmd = find(tokens, role=role, include_aliases=True)
    if cmd is None:
        return list(tokens)
    # Prefer exact path match length when both path and alias could apply.
    path = cmd["path"]
    if tuple(tokens[: len(path)]) == path:
        return list(tokens)
    for alias in cmd.get("aliases") or ():
        alias = tuple(alias)
        if tuple(tokens[: len(alias)]) == alias:
            rest = list(tokens[len(alias) :])
            rewrite = REWRITES.get(alias)
            if rewrite is not None:
                return rewrite(rest)
            return list(path) + rest
    return list(tokens)


def usage_line(cmd):
    parts = list(cmd["path"])
    for arg in cmd["args"]:
        name = arg["name"]
        parts.append(name if arg["required"] else "[%s]" % name)
    # Public UX is positional / guided — never advertise [options].
    if cmd["tail"] == "any":
        parts.append("...")
    return " ".join(parts)


# --- alias expansion ------------------------------------------------------
def _alias_index():
    index = {}
    for cmd in COMMANDS:
        for alias in cmd["aliases"]:
            index.setdefault(alias, cmd)
    return index


ALIASES = _alias_index()


def alias_rows():
    """(alias, canonical) rows for 'help legacy'."""
    rows = []
    for cmd in COMMANDS:
        for alias in cmd["aliases"]:
            rows.append((" ".join(alias), " ".join(cmd["path"])))
    return rows


# --- canonical -> internal verb-first rewrite -----------------------------
def _rw_client_release(rest):
    # client release <CLIENT> <SERVICE> … → release service
    # client release <CLIENT> [--yes] → release client
    if len(rest) >= 2 and not str(rest[1]).startswith("-"):
        return ["release", "service", rest[0], rest[1]] + list(rest[2:])
    return ["release", "client"] + list(rest)


def _rw_enrollment_purge(rest):
    if rest and rest[0] == "--older-than":
        return ["purge", "enrollments"] + list(rest)
    return ["purge", "enrollment"] + list(rest)


def _rw_group_member(verb):
    def inner(rest):
        if len(rest) < 2:
            return [verb, "client"] + list(rest)
        return [verb, "client", rest[1], "group", rest[0]] + list(rest[2:])

    return inner


def _rw_server_set(rest):
    if not rest:
        return ["set", "server"]
    key = rest[0]
    if key == "installer-url":
        return ["set", "installer-url"] + list(rest[1:])
    if key == "windows-installer-url":
        return ["set", "windows-installer-url"] + list(rest[1:])
    if key == "public-hostname":
        return ["set", "server", "hostname"] + list(rest[1:])
    return ["set", "server"] + list(rest)


def _rw_server_unset(rest):
    if rest and rest[0] == "public-hostname":
        return ["unset", "server", "hostname"] + list(rest[1:])
    return ["unset", "server"] + list(rest)


def _rw_egress_set(rest):
    # Canonical: PROFILE name|description VALUE → flag form for frp-egress.
    if (
        len(rest) >= 3
        and rest[1] in ("name", "description")
        and not str(rest[0]).startswith("-")
        and not str(rest[1]).startswith("-")
    ):
        return [
            "set",
            "egress-profile",
            rest[0],
            "--%s" % rest[1],
            rest[2],
        ] + list(rest[3:])
    return ["set", "egress-profile"] + list(rest)


def _rw_egress_add_destination(rest):
    # Keep trailing flags (e.g. --protocol) after host/port.
    flags = []
    values = []
    idx = 0
    while idx < len(rest):
        tok = rest[idx]
        if str(tok).startswith("-"):
            flags.append(tok)
            idx += 1
            if idx < len(rest) and not str(rest[idx]).startswith("-"):
                flags.append(rest[idx])
                idx += 1
            continue
        values.append(tok)
        idx += 1
    if len(values) >= 3:
        return (
            ["add", "egress-profile", values[0], "destination", values[1], values[2]]
            + values[3:]
            + flags
        )
    return ["add", "egress-profile"] + list(rest) + ["destination"]


def _rw_egress_add_source(rest):
    flags = []
    values = []
    idx = 0
    while idx < len(rest):
        tok = rest[idx]
        if str(tok).startswith("-"):
            flags.append(tok)
            idx += 1
            if idx < len(rest) and not str(rest[idx]).startswith("-"):
                flags.append(rest[idx])
                idx += 1
            continue
        values.append(tok)
        idx += 1
    if len(values) >= 2:
        return ["add", "egress-profile", values[0], "source", values[1]] + flags + values[2:]
    return ["add", "egress-profile"] + list(rest) + ["source"]


def _rw_egress_remove(kind):
    def inner(rest):
        flags = []
        values = []
        idx = 0
        while idx < len(rest):
            tok = rest[idx]
            if str(tok).startswith("-"):
                flags.append(tok)
                idx += 1
                if idx < len(rest) and not str(rest[idx]).startswith("-"):
                    flags.append(rest[idx])
                    idx += 1
                continue
            values.append(tok)
            idx += 1
        if len(values) >= 2:
            return ["remove", "egress-profile", values[0], kind, values[1]] + flags
        return ["remove", "egress-profile"] + list(rest) + [kind]

    return inner


def _rw_access_remove_expired(rest):
    """Map access remove-expired <RULE> [--yes] → system cleanup … expired."""
    if not rest:
        return ["system", "cleanup", "access-rule"]
    rule = rest[0]
    flags = list(rest[1:])
    if flags and flags[0] == "expired":
        return ["system", "cleanup", "access-rule", rule] + flags
    return ["system", "cleanup", "access-rule", rule, "expired"] + flags


def _rw_enable_service(rest):
    # enable service <ID> / service enable <ID> → set service <ID> enabled
    if not rest:
        return ["set", "service"]
    return ["set", "service", rest[0], "enabled"] + list(rest[1:])


def _rw_disable_service(rest):
    # disable service <ID> / service disable <ID> → unset service <ID> enabled
    if not rest:
        return ["unset", "service"]
    return ["unset", "service", rest[0], "enabled"] + list(rest[1:])


REWRITES = {
    ("client", "release"): _rw_client_release,
    ("enrollment", "purge"): _rw_enrollment_purge,
    ("group", "add-client"): _rw_group_member("add"),
    ("group", "remove-client"): _rw_group_member("remove"),
    ("group", "add-member"): _rw_group_member("add"),
    ("group", "remove-member"): _rw_group_member("remove"),
    ("server", "set"): _rw_server_set,
    ("server", "unset"): _rw_server_unset,
    ("egress", "set"): _rw_egress_set,
    ("egress", "add-destination"): _rw_egress_add_destination,
    ("egress", "add-source"): _rw_egress_add_source,
    ("egress", "remove-destination"): _rw_egress_remove("destination"),
    ("egress", "remove-source"): _rw_egress_remove("source"),
    ("access", "remove-expired"): _rw_access_remove_expired,
    ("remove", "access-expired"): _rw_access_remove_expired,
    ("enable", "service"): _rw_enable_service,
    ("service", "enable"): _rw_enable_service,
    ("disable", "service"): _rw_disable_service,
    ("service", "disable"): _rw_disable_service,
}

# Roots that also exist as historical flat commands. A bare root token (or a
# root followed by something that is not a canonical action) keeps the old
# meaning so scripts do not change behavior.
AMBIGUOUS_ROOTS = ("client", "backup", "restore", "profile", "access", "egress")


def canonical_actions(root):
    return tuple(
        cmd["path"][1] for cmd in COMMANDS if len(cmd["path"]) > 1 and cmd["path"][0] == root
    )


def to_internal(tokens):
    """Rewrite a final public token list into dispatcher tokens.

    Returns ``None`` when ``tokens`` is not a known command (public or alias).
    """
    if not tokens:
        return None
    original = [str(t) for t in tokens]
    # Preserve distinct legacy safety semantics that collapse onto unset client.
    if original[:2] in (["revoke", "client"], ["client", "revoke"]):
        return ["revoke", "client"] + original[2:]
    if original[:2] == ["release", "service"] or original[:1] == ["release-service"]:
        return ["release", "service"] + original[2:] if original[:2] == ["release", "service"] else ["release", "service"] + original[1:]
    if original[:1] == ["release-client"]:
        # Hyphenated legacy: release-client <ID> [--yes]; never <SERVICE>.
        return ["release", "client"] + original[1:]
    if original[:2] in (["release", "client"], ["client", "release"]):
        rest = original[2:]
        if len(rest) >= 2 and not str(rest[1]).startswith("-"):
            return ["release", "service", rest[0], rest[1]] + rest[2:]
        return ["release", "client"] + rest
    if original[:2] in (["revoke", "enrollment"], ["enrollment", "revoke"]):
        return ["revoke", "enrollment"] + original[2:]
    if original[:2] in (["delete", "enrollment"], ["purge", "enrollment"], ["enrollment", "purge"]):
        return ["purge", "enrollment"] if original[0] != "delete" else ["delete", "enrollment"] + original[2:]
    # access create and access edit-info both alias to set acl; keep create
    # vs metadata-edit distinct so --description on create does not become
    # edit-info against a missing list.
    if original[:2] in (["access", "create"], ["create", "access-list"]):
        return ["create", "access-list"] + original[2:]
    if original[:2] == ["access", "edit-info"]:
        return ["set", "access-list"] + original[2:]
    if original[:2] == ["access", "replace-source"]:
        return ["set", "access-source"] + original[2:]
    if original[:2] in (["access", "add-source"], ["add", "access-source"]):
        return ["add", "access-source"] + original[2:]
    if original[:2] in (["create", "profile"], ["create", "service-profile"]):
        return ["create", "service-profile"] + original[2:]
    if original[:2] == ["add", "service"]:
        return ["add", "service"] + original[2:]
    # Prefer alias-aware resolution so legacy forms still dispatch.
    resolved = resolve_tokens(tokens)
    cmd = find(resolved, include_aliases=True)
    if cmd is None:
        cmd = find(tokens, include_aliases=True)
        if cmd is None:
            return None
        resolved = resolve_tokens(tokens)
    path = cmd["path"]
    # If tokens matched via alias length, use resolved canonical tokens.
    if tuple(resolved[: len(path)]) != path:
        # resolve_tokens should have canonicalized; fall back.
        work = list(resolved)
    else:
        work = list(resolved)
    rest = list(work[len(path) :])

    CONTROL_PLANE_RES = {
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
        "remote-access",
        "internet-access",
        "client-groups",
        "client-group",
        "ai-principals",
        "ai-principal",
        "ai-access",
        "ai-activity",
        "fixed-tcp",
        "configuration",
    }
    if len(path) >= 2 and path[0] in ("show", "set", "unset", "test") and path[1] in CONTROL_PLANE_RES:
        return list(work)
    if path[:3] == ("system", "credential", "rotate") or path[:3] == ("system", "credential", "revoke"):
        return list(work)
    if path[:3] in (
        ("system", "export", "configuration"),
        ("system", "apply", "configuration"),
        ("system", "diff", "configuration"),
    ):
        return list(work)
    if path[:2] == ("system", "revisions") or path[:2] == ("system", "revision") or path[:2] == ("system", "diff"):
        return list(work)

    # --- Merged final-grammar specials (preserve distinct safety semantics) ---
    if path == ("set", "client"):
        if not rest:
            return ["create", "zero-touch"]
        # set client <CLIENT> group <GROUP>
        if len(rest) >= 3 and rest[1] == "group":
            return ["add", "client", rest[0], "group", rest[2]] + rest[3:]
        # metadata
        return ["set", "client"] + rest

    if path == ("unset", "client"):
        if not rest:
            return ["unset", "client"]
        client = rest[0]
        if len(rest) == 1:
            return ["release", "client", client]
        if rest[1] == "trust":
            return ["revoke", "client", client] + rest[2:]
        if rest[1] == "service" and len(rest) >= 3:
            return ["release", "service", client, rest[2]] + rest[3:]
        if rest[1] == "group" and len(rest) >= 3:
            return ["remove", "client", client, "group", rest[2]] + rest[3:]
        # metadata label/note/tag
        return ["unset", "client"] + rest

    if path == ("set", "group"):
        if not rest:
            return ["set", "group"]
        if len(rest) == 1:
            return ["create", "group", rest[0]]
        if len(rest) >= 3 and rest[1] in ("name", "description"):
            return ["set", "group"] + rest
        return ["create", "group"] + rest

    if path == ("set", "enrollment"):
        if rest[:1] == ["zero-touch"]:
            return ["create", "zero-touch"] + rest[1:]
        if rest[:1] == ["manual"]:
            return ["create", "enrollment"] + rest[1:]
        return ["create", "enrollment"] + rest

    if path == ("set", "enrollment", "bulk"):
        return ["create", "enrollments"] + rest

    if path == ("set", "service-profile"):
        if not rest:
            return ["set", "service-profile"]
        if len(rest) == 1:
            return ["create", "service-profile", rest[0]]
        # Positional property edit: set service-profile <P> name|preset|… <value>
        props = (
            "name", "description", "preset", "target-host", "target-port", "ssh-user",
            "health-type", "health-timeout", "health-interval", "health-max-failed", "health-path",
        )
        if len(rest) >= 3 and rest[1] in props:
            return ["set", "service-profile"] + rest
        # Create-time machine flags (--preset, --target-host, …).
        return ["create", "service-profile"] + rest

    if path == ("set", "acl"):
        if not rest:
            return ["set", "acl"]
        if len(rest) == 1:
            return ["create", "access-list", rest[0]]
        if len(rest) >= 3 and rest[1] == "source":
            return ["add", "access-source", rest[0], rest[2]] + rest[3:]
        if len(rest) >= 4 and rest[1] == "service":
            # set acl <ACL> service <CLIENT> <SERVICE> → assign list to service
            return ["set", "access-assign", rest[2], rest[3], rest[0]] + rest[4:]
        if len(rest) >= 3 and rest[1] in ("name", "description"):
            return ["set", "access-list", rest[0], rest[1], rest[2]] + rest[3:]
        # Create-time machine flags (--description / --name). Positional
        # name|description is metadata edit; --yes marks confirmed edit-info.
        if any(str(t).startswith("-") for t in rest[1:]):
            if "--yes" in rest:
                return ["set", "access-list"] + rest
            return ["create", "access-list"] + rest
        return ["set", "access-list"] + rest

    if path == ("set", "access-rule"):
        if not rest:
            return ["set", "access-rule"]
        if len(rest) == 1:
            return ["create", "access-list", rest[0]]
        if any(str(t).startswith("-") for t in rest[1:]):
            if "--yes" in rest:
                return ["set", "access-list"] + rest
            return ["create", "access-list"] + rest
        return ["set", "access-list"] + rest

    if path == ("set", "access-source"):
        if not rest:
            return ["set", "access-source"]
        # --new-source marks atomic replace; otherwise add.
        if "--new-source" in rest:
            return ["set", "access-source"] + rest
        return ["add", "access-source"] + rest

    if path == ("set", "service-access"):
        return ["set", "access-assign"] + rest

    if path == ("unset", "service-access"):
        return ["set", "access-public"] + rest

    if path == ("set", "internet-profile"):
        if not rest:
            return ["set", "internet-profile"]
        if len(rest) == 1:
            return ["create", "egress-profile", rest[0]]
        if len(rest) >= 2 and rest[1] == "enabled":
            return ["enable", "egress-profile", rest[0]] + rest[2:]
        if len(rest) >= 3 and rest[1] == "template":
            # egress recipe apply <TEMPLATE> --name <NEW_PROFILE>
            return ["egress", "recipe", "apply", rest[2], "--name", rest[0]] + rest[3:]
        if len(rest) >= 3 and rest[1] == "source":
            return ["add", "egress-source", rest[0], rest[2]] + rest[3:]
        if len(rest) >= 5 and rest[1] == "destination":
            # Keep positional PROTOCOL for match → backend --protocol mapping.
            return [
                "add",
                "egress-destination",
                rest[0],
                rest[2],
                rest[3],
                rest[4],
            ] + rest[5:]
        if len(rest) >= 3 and rest[1] in ("name", "description"):
            return ["set", "egress-profile"] + rest
        return ["set", "egress-profile"] + rest

    if path == ("set", "internet-source"):
        if len(rest) >= 2:
            return ["add", "egress-source", rest[0], rest[1]] + rest[2:]
        return ["add", "egress-source"] + rest

    if path == ("set", "internet-destination"):
        if len(rest) >= 4:
            # Keep positional PROTOCOL for match → backend --protocol mapping.
            return ["add", "egress-destination", rest[0], rest[1], rest[2], rest[3]] + rest[4:]
        return ["add", "egress-destination"] + rest

    if path == ("set", "server"):
        if not rest:
            return ["set", "server"]
        if rest[0] == "installer-url":
            return ["set", "installer-url"] + rest[1:]
        if rest[0] == "windows-installer-url":
            return ["set", "windows-installer-url"] + rest[1:]
        return ["set", "server"] + rest

    if path == ("set", "service"):
        if not rest:
            return ["add", "service"]
        if len(rest) >= 2 and rest[1] == "enabled":
            return ["enable", "service", rest[0]] + rest[2:]
        # Create/add with machine flags only: set service --profile …
        if str(rest[0]).startswith("-"):
            return ["add", "service"] + rest
        return ["set", "service"] + rest

    if path == ("unset", "service"):
        # Only enabled is supported publicly
        if len(rest) >= 2 and rest[1] == "enabled":
            return ["disable", "service", rest[0]] + rest[2:]
        return ["disable", "service"] + rest

    if path == ("unset", "group"):
        return ["delete", "group"] + rest

    if path == ("unset", "enrollment"):
        # State-aware handling is done in the match/dispatch layer.
        return ["unset", "enrollment"] + rest

    if path == ("unset", "service-profile"):
        return ["delete", "service-profile"] + rest

    if path == ("unset", "acl"):
        if not rest:
            return ["unset", "acl"]
        if len(rest) >= 3 and rest[1] == "source":
            return ["remove", "access-source", rest[0], rest[2]] + rest[3:]
        if len(rest) >= 4 and rest[1] == "service":
            # Preserve the ACL selector so the backend can fail closed when the
            # service is not actually assigned to that ACL (never silently
            # broaden via a typo'd selector).
            return ["access", "unassign", rest[0], rest[2], rest[3]] + rest[4:]
        return ["delete", "access-list", rest[0]] + rest[1:]

    if path == ("unset", "access-rule"):
        return ["delete", "access-list"] + rest

    if path == ("unset", "access-source"):
        return ["remove", "access-source"] + rest

    if path == ("unset", "internet-profile"):
        if not rest:
            return ["unset", "internet-profile"]
        if len(rest) >= 2 and rest[1] == "enabled":
            return ["disable", "egress-profile", rest[0]] + rest[2:]
        if len(rest) >= 3 and rest[1] == "source":
            return ["remove", "egress-source", rest[0], rest[2]] + rest[3:]
        if len(rest) >= 4 and rest[1] == "destination":
            return [
                "remove",
                "egress-destination",
                rest[0],
                rest[2],
                rest[3],
            ] + rest[4:]
        return ["delete", "egress-profile"] + rest

    if path == ("unset", "internet-source"):
        return ["remove", "egress-source"] + rest

    if path == ("unset", "internet-destination"):
        return ["remove", "egress-destination"] + rest

    if path == ("unset", "server"):
        return ["unset", "server"] + rest

    if path == ("show", "acls"):
        return ["show", "access-lists"] + rest
    if path == ("show", "acl"):
        return ["show", "access-list"] + rest
    if path == ("show", "access-rules"):
        return ["show", "access-lists"] + rest
    if path == ("show", "access-rule"):
        return ["show", "access-list"] + rest
    if path == ("show", "internet"):
        return ["show", "egress"] + rest
    if path == ("show", "internet-profiles"):
        return ["show", "egress-profiles"] + rest
    if path == ("show", "internet-profile"):
        return ["show", "egress-profile"] + rest
    if path == ("show", "internet-templates"):
        return ["egress", "recipe", "list"] + rest
    if path == ("show", "internet-template"):
        return ["egress", "recipe", "show"] + rest

    if path == ("test", "internet"):
        # Optional trailing PROTOCOL is remapped in the matcher.
        return ["explain", "egress"] + rest
    if path == ("test", "fixed-tcp"):
        return ["egress", "tcp", "explain"] + rest
    if path == ("test", "acl"):
        return ["test", "access"] + rest
    if path == ("test", "access"):
        return ["test", "access"] + rest

    if path == ("system", "version"):
        return ["show", "version"] + rest
    if path == ("system", "status"):
        # Detailed server host view. system server-status remains a compatibility alias.
        return ["server-status"] + rest
    if path == ("system", "info"):
        return ["show", "info"] + rest
    if path == ("system", "backup"):
        return ["create", "backup"] + rest
    if path == ("system", "restore"):
        return ["restore", "backup"] + rest
    if path == ("system", "update", "product"):
        return ["update", "product"] + rest
    if path == ("system", "update", "engine"):
        return ["update", "engine"] + rest
    if path == ("system", "update", "check-engine"):
        return ["show", "upstream"] + rest
    if path == ("system", "diagnostics"):
        if rest and rest[0] in ("control-plane", "runtime", "mcp"):
            return ["system", "diagnostics"] + rest
        return ["doctor"] + rest
    if path == ("system", "support-bundle"):
        # Direct dispatcher action (not create support-bundle).
        if rest:
            return ["support-bundle", "--output", rest[0]] + list(rest[1:])
        return ["support-bundle"]
    if path == ("system", "audit"):
        if rest and rest[0] in ("ai-principal", "revision", "entity", "object"):
            return ["system", "audit"] + rest
        return ["show", "audit"] + rest
    if path == ("system", "export", "internet-profile"):
        if len(rest) >= 2:
            return ["export", "egress", rest[0], "--output", rest[1]] + list(rest[2:])
        return ["export", "egress"] + rest
    if path == ("system", "import", "internet-profile"):
        return ["import", "egress"] + rest
    if path == ("system", "diff", "internet-profile"):
        return ["diff", "egress"] + rest
    if path == ("system", "cleanup", "access-rule"):
        # system cleanup access-rule <RULE> expired → frp-access remove-expired
        rule_tokens = [t for t in rest if t != "expired"]
        return ["access", "remove-expired"] + rule_tokens
    if path == ("system", "services", "apply"):
        return ["apply"] + rest
    if path == ("system", "services", "discard"):
        return ["discard"] + rest
    if path == ("system", "services", "sync"):
        return ["sync"] + rest
    if path == ("system", "pause"):
        return ["pause"] + rest
    if path == ("system", "resume"):
        return ["resume"] + rest
    if path == ("system", "restart"):
        return ["restart"] + rest
    if path == ("system", "autostart"):
        return ["autostart"] + rest
    if path == ("system", "autostart", "enable"):
        return ["autostart", "enable"] + rest
    if path == ("system", "autostart", "disable"):
        return ["autostart", "disable"] + rest
    if path == ("system", "uninstall"):
        return ["uninstall"] + rest
    if path == ("system", "history"):
        return ["history"] + rest
    if path == ("system", "clear"):
        return ["clear"] + rest

    # Compat rewrites still keyed by historical resource-first paths.
    for alias in cmd.get("aliases") or ():
        rewrite = REWRITES.get(tuple(alias))
        if rewrite is not None and tuple(tokens[: len(alias)]) == tuple(alias):
            return rewrite(list(tokens[len(alias) :]))
    rewrite = REWRITES.get(path)
    if rewrite is not None:
        return rewrite(rest)
    rewrite = REWRITES.get(tuple(cmd.get("internal") or ()))
    if rewrite is not None and cmd.get("internal"):
        return rewrite(rest)

    # Legacy specials retained for absorbed forms that still appear as internal.
    # release client <ID> <SERVICE> → release service; flags like --yes stay on client.
    if path == ("release", "client") and len(rest) >= 2 and not str(rest[1]).startswith("-"):
        return ["release", "service", rest[0], rest[1]] + rest[2:]
    if path == ("delete", "enrollment") and rest and rest[0] == "--older-than":
        return ["purge", "enrollments"] + list(rest)

    internal = cmd["internal"]
    if internal is None:
        return list(path) + rest
    return list(internal) + rest



def expand_compat_alias(tokens):
    """Compatibility alias expansion is disabled for current product surface.

    Obsolete forms must be rejected by the grammar with an actionable pointer.
    Returns ``None`` always.
    """
    return None


def strict_error(tokens):
    """Reject unexpected trailing arguments and flag arity mistakes (CLI-016 / AUDIT-014).

    Returns an error message, or ``None`` when the token list is acceptable.
    """
    cmd = find(tokens, include_aliases=True)
    if cmd is None:
        return None
    # Normalize to canonical path length when tokens used a hidden alias.
    resolved = resolve_tokens(tokens)
    rest = list(resolved[len(cmd["path"]) :])
    idx = 0
    used = 0
    slots = len(cmd["args"])
    if cmd["tail"] == "any":
        # Arbitrary positionals allowed — advance to the first flag (if any).
        while idx < len(rest) and not str(rest[idx]).startswith("-"):
            idx += 1
    else:
        while idx < len(rest) and used < slots and not rest[idx].startswith("-"):
            idx += 1
            used += 1
        if cmd["tail"] is None:
            # Required positionals only — but still allow declared trailing flags
            # (e.g. system cleanup access-rule <RULE> expired --yes).
            if idx < len(rest) and not str(rest[idx]).startswith("-"):
                return "unexpected argument: %s" % rest[idx]
    # Trailing option flags: enforce arity for catalog-known flags; reject
    # stray positionals. Unknown flags stay forwarded to the backend tool.
    known = {flag["name"]: flag for flag in cmd["flags"]}
    seen_flags = set()
    while idx < len(rest):
        tok = rest[idx]
        if not tok.startswith("-"):
            if cmd["tail"] == "any":
                # Positionals may interleave after flags for free-form tails;
                # skip them without treating as errors.
                idx += 1
                continue
            return "unexpected argument: %s" % tok
        flag = known.get(tok)
        if flag is None:
            idx += 1
            if idx < len(rest) and not rest[idx].startswith("-"):
                idx += 1
            continue
        if flag["arity"] == 0:
            if idx + 1 < len(rest) and not rest[idx + 1].startswith("-"):
                return "flag %s does not take a value" % tok
            seen_flags.add(tok)
            idx += 1
            continue
        if idx + 1 >= len(rest) or rest[idx + 1].startswith("-"):
            return "missing value for %s" % tok
        value = rest[idx + 1]
        if flag["choices"] and value not in flag["choices"]:
            return "invalid value for %s: expected %s" % (
                tok,
                "|".join(flag["choices"]),
            )
        seen_flags.add(tok)
        idx += 2
    for flag in cmd["flags"]:
        # Hidden flags are never required on the public grammar.
        if flag.get("required") and not flag.get("hidden") and flag["name"] not in seen_flags:
            return "missing required flag: %s" % flag["name"]
    return None


# --- help rendering -------------------------------------------------------
def _fmt_rows(rows, indent="  "):
    rows = [(name, desc) for name, desc in rows]
    if not rows:
        return []
    width = max(len(name) for name, _desc in rows)
    out = []
    for name, desc in rows:
        if desc:
            out.append("%s%s  %s" % (indent, name.ljust(width), desc))
        else:
            out.append("%s%s" % (indent, name))
    return out


def root_help(role):
    """Root help — same mental model as bare '?'."""
    return root_command_overview(role, detailed=True)


def concise_root(role):
    """Short root listing used by bare '?'."""
    return root_command_overview(role, detailed=False)


def domain_overview(role, detailed=False):
    """Compatibility alias for root_command_overview."""
    return root_command_overview(role, detailed=detailed)


def root_command_overview(role, detailed=False):
    """Final public root command overview for help / '?'."""
    client, server = role_parts(role)
    lines = [
        "Data Relay Link",
        "===============",
        "",
    ]
    rows = []
    for name, summary in root_rows(role):
        rows.append((name, summary))
    # Render each root with its summary and discovery tip for primary verbs.
    tip_roots = {"show", "set", "unset", "test", "system"}
    for name, summary in rows:
        lines.append(name)
        if summary:
            lines.append("  %s" % summary)
        if name in tip_roots:
            lines.append("  Type: %s ?" % name)
        lines.append("")
    lines.extend(
        [
            "Tip:",
            '  Type "<command> ?" or press Tab to see valid next choices.',
            "",
        ]
    )
    if detailed:
        lines.extend(["Help topics:"])
        client, server = role_parts(role)
        if server or not client:
            lines.extend(
                [
                    "  help managed-hosts",
                    "  help network-objects",
                    "  help service-objects",
                    "  help remote-access",
                    "  help internet-access",
                    "  help ai-access",
                ]
            )
        if client or not server:
            lines.append("  help remote-services")
        lines.extend(
            [
                "  help system",
                "  help workflows",
                "  help commands",
                "",
                "Relay Engine (FRP) is the upstream tunnel engine.",
                "This project does not fork FRP.",
                "",
            ]
        )
    return "\n".join(lines)


def domain_help(topic, role):
    """Conceptual help for product domains (v2.4 public nouns)."""
    topic = str(topic or "").strip().lower()
    client, server = role_parts(role)
    if topic in ("managed-host", "managed-hosts", "client", "clients"):
        if not server:
            return "Managed Hosts help is available on a Data Relay Link server.\n"
        return (
            "Managed Hosts\n"
            "=============\n\n"
            "Managed Hosts are enrolled machines managed by this server.\n"
            "A Managed Host may also be selected as a Network Object where valid.\n\n"
            "Guided path:\n"
            "  menu → Managed Hosts\n\n"
            "Everyday commands:\n"
            "  show managed-hosts\n"
            "  show managed-host <HOST>\n"
            "  show managed-host <HOST> remote-services\n"
            "  show managed-host <HOST> agent\n"
            "  show managed-host <HOST> addresses\n"
            "  set enrollment\n"
            "  set enrollment zero-touch\n"
            "  unset managed-host <HOST>\n\n"
            "Obsolete noun 'clients' redirects here.\n"
        )
    if topic in ("network-object", "network-objects", "object", "objects"):
        if not server:
            return "Network Objects help is available on a Data Relay Link server.\n"
        return (
            "Network Objects\n"
            "===============\n\n"
            "Reusable IP, CIDR, FQDN and Managed Host selectors.\n"
            "Network Groups are flat collections of Network Objects.\n\n"
            "Guided path:\n"
            "  menu → Network Objects\n\n"
            "Everyday commands:\n"
            "  show network-objects\n"
            "  show network-object <NAME>\n"
            "  show network-object <NAME> references\n"
            "  set network-object <NAME> type <ip|cidr|fqdn> value <VALUE>\n"
            "  set network-object <NAME> value <VALUE>\n"
            "  set network-group <NAME> members a,b,c\n"
            "  show network-group <NAME> references\n"
            "  unset network-object <NAME>\n"
        )
    if topic in ("service-object", "service-objects"):
        if not server:
            return "Service Objects help is available on a Data Relay Link server.\n"
        return (
            "Service Objects\n"
            "===============\n\n"
            "TCP, UDP and Fixed TCP service definitions.\n"
            "Fixed TCP is a Service Object subtype with a separate endpoint pool.\n\n"
            "Guided path:\n"
            "  menu → Service Objects\n\n"
            "Everyday commands:\n"
            "  show service-objects\n"
            "  show service-object <NAME>\n"
            "  show service-object <NAME> references\n"
            "  set service-object <NAME> type <tcp|udp|fixed-tcp> port <PORT>\n"
            "  set service-object <NAME> port <PORT>\n"
            "  set service-group <NAME> members a,b\n"
            "  show service-group <NAME> references\n"
        )
    if topic in ("remote-access", "remote"):
        if not server:
            return "Remote Access help is available on a Data Relay Link server.\n"
        return (
            "Remote Access\n"
            "=============\n\n"
            "BLACKLIST / WHITELIST authorization for Remote Services.\n"
            "No ordering model. Rules authorize; they do not create connectivity.\n\n"
            "Guided path:\n"
            "  menu → Remote Access\n\n"
            "Everyday commands:\n"
            "  show remote-access\n"
            "  set remote-access <RULE>\n"
            "  test remote-access source <SRC> destination <DST> service <SVC>\n"
        )
    if topic in ("service", "services", "remote-service", "remote-services"):
        if server:
            return (
                "Remote Services are owned by Agent Hosts.\n\n"
                "On the Server:\n"
                "  show managed-host <HOST> remote-services\n\n"
                "On an Agent Host:\n"
                "  show remote-services\n"
                "  set remote-service <NAME>\n"
            )
        return (
            "Remote Services\n"
            "===============\n\n"
            "Agent-local connectivity objects with DRLink endpoints.\n"
            "UDP Remote Service is not supported.\n\n"
            "Everyday commands:\n"
            "  show remote-services\n"
            "  set remote-service <NAME> destination <DEST|this-host> service <SERVICE> enabled\n"
            "  unset remote-service <NAME>\n"
        )
    if topic in ("internet", "egress", "internet-access"):
        if not server:
            return "Internet Access help is available on a Data Relay Link server.\n"
        return (
            "Internet Access\n"
            "===============\n\n"
            "BLACKLIST / WHITELIST authorization for outbound access.\n"
            "Managed Host may be used as a source; Managed Host destination is rejected.\n\n"
            "Guided path:\n"
            "  menu → Internet Access\n\n"
            "Everyday commands:\n"
            "  show internet-access\n"
            "  set internet-access <RULE>\n"
            "  test internet-access source <SRC> destination <DST> service <SVC>\n"
        )
    if topic in ("ai", "ai-access", "mcp", "ai-identity", "ai-identities"):
        if not server:
            return "AI Access help is available on a Data Relay Link server.\n"
        return (
            "AI Access\n"
            "=========\n\n"
            "AI Identity authentication is separate from AI Access authorization.\n"
            "Display name alone is not a verified identity.\n\n"
            "Lifecycle:\n"
            "  1. Create and authenticate an AI Identity\n"
            "  2. Create Permission Object(s) and optional Permission Group(s)\n"
            "  3. Create an AI Access Rule binding Identity → Destination → Permission\n"
            "  4. Test / explain, then review the Access Log\n\n"
            "Guided path:\n"
            "  menu → AI Access\n\n"
            "Everyday commands:\n"
            "  set ai-identity <NAME>\n"
            "  show ai-identities\n"
            "  set permission-object <NAME> permissions <PERM>[,PERM...]\n"
            "  set permission-group <NAME> members <PO>[,PO...]\n"
            "  set ai-access <RULE> mode <blacklist|whitelist> source <IDENTITY> \\\n"
            "      destination <DEST> permission <PERM|GROUP> enabled\n"
            "  set ai-access <RULE> enabled|disabled\n"
            "  test ai-access source <IDENTITY> destination <DEST> permission <PERM>\n"
            "  show ai-access\n"
            "  show ai-access-log\n"
        )
    if topic in ("system", "operate"):
        client, server = role_parts(role)
        if client and not server:
            intro = "Operate Data Relay Link itself: updates, diagnostics and Agent system operations."
        else:
            intro = "Operate Data Relay Link itself: status, settings, backup, updates, and diagnostics."
        lines = [
            "System",
            "======",
            "",
            intro,
            "",
            "Guided path:",
            "  menu → System",
            "",
            "Everyday commands:",
            "  show status",
            "  system version",
            "  system diagnostics",
            "  system support-bundle",
            "  system update product",
            "  system update engine",
            "  system update check-engine",
            "  system uninstall",
        ]
        if server:
            lines.extend(
                [
                    "  system backup",
                    "  system backup validate <PATH>",
                    "  system restore <PATH>",
                    "  system revisions",
                    "  system audit",
                    "  system export configuration <PATH>",
                    "  test configuration <PATH|->",
                    "  system diff configuration <PATH|->",
                    "  system apply configuration <PATH|->",
                    "  system credential rotate ai-identity <NAME>",
                    "  system credential revoke ai-identity <NAME>",
                    "  system credential configure ai-identity <NAME> authentication static-bearer",
                    "  system credential configure ai-identity <NAME> authentication oauth",
                    "  system credential approve-oauth <PENDING-ID> [AI-IDENTITY]",
                    "  system credential deny-oauth <PENDING-ID>",
                    "  system diagnostics mcp",
                    "  show mcp-tls",
                    "  set mcp-tls hostname <fqdn>",
                    "  set mcp-tls mode auto-acme",
                    "  system certificate issue",
                    "  system certificate import <CERT> <KEY> [CHAIN]",
                    "  system certificate renew",
                    "  system certificate status",
                    "  set server public-hostname <FQDN>",
                    "  set server bootstrap-hostname <FQDN>",
                ]
            )
        if client:
            lines.extend(
                [
                    "  system info",
                    "  system pause",
                    "  system resume",
                    "  system restart",
                    "  system autostart",
                    "  system autostart enable",
                    "  system autostart disable",
                    "  system synchronize",
                    "  system export configuration <PATH>",
                    "  test configuration <PATH|->",
                    "  system diff configuration <PATH|->",
                    "  system apply configuration <PATH|->",
                ]
            )
        return "\n".join(lines) + "\n"
    if topic in ("command", "commands"):
        return commands_help(role)
    return None


def commands_help(role):
    """Complete expert action-first command reference from COMMANDS."""
    lines = [
        "Command reference",
        "=================",
        "",
        "Grammar: <action> <resource> [target] [value]",
        "",
        "Every public non-hidden command for this host role:",
        "",
    ]
    by_root = {}
    for cmd in COMMANDS:
        if cmd.get("hidden"):
            continue
        if not role_allows(cmd["roles"], role):
            continue
        root = cmd["path"][0]
        by_root.setdefault(root, []).append(cmd)
    root_order = [name for name, _roles, _cat, _sum in ROOTS]
    seen = set()
    for root in root_order:
        cmds = by_root.get(root)
        if not cmds:
            continue
        seen.add(root)
        for cmd in cmds:
            lines.append("  %s" % usage_line(cmd))
        lines.append("")
    for root, cmds in by_root.items():
        if root in seen:
            continue
        for cmd in cmds:
            lines.append("  %s" % usage_line(cmd))
        lines.append("")
    lines.append("See also: help commands")
    return "\n".join(lines).rstrip() + "\n"


def resource_help(root, role):
    rows = subcommands(root, role)
    if not rows:
        return None
    title = "%s" % root
    lines = [title, "=" * len(title), ""]
    summary = None
    for name, roles, _category, text in ROOTS:
        if name == root and role_allows(roles, role):
            summary = text
    if root == "system":
        client, server = role_parts(role)
        if client and not server:
            summary = "Updates, diagnostics and Agent system operations"
        elif server and not client:
            summary = "Updates, backup, restore, diagnostics and system operations"
    if summary:
        lines.extend([summary, ""])
    lines.append("Usage:")
    for cmd in COMMANDS:
        if cmd["path"][0] != root or len(cmd["path"]) < 2:
            continue
        if cmd.get("hidden"):
            continue
        if not role_allows(cmd["roles"], role):
            continue
        lines.append("  %s" % usage_line(cmd))
    lines.append("")
    lines.append("Actions:")
    lines.extend(_fmt_rows(rows))
    destructive = [
        " ".join(cmd["path"])
        for cmd in COMMANDS
        if cmd["path"][0] == root
        and cmd["destructive"]
        and not cmd.get("hidden")
        and role_allows(cmd["roles"], role)
    ]
    if destructive:
        lines.extend(["", "Destructive:", "  " + ", ".join(destructive)])
    return "\n".join(lines) + "\n"


def command_help(cmd):
    title = " ".join(cmd["path"])
    lines = [title, "=" * len(title), "", "Usage:", "  %s" % usage_line(cmd), ""]
    lines.append(cmd["summary"])
    if cmd["detail"]:
        lines.extend(["", cmd["detail"]])
    if cmd["args"]:
        rows = []
        for arg in cmd["args"]:
            complete = arg["complete"]
            if isinstance(complete, (list, tuple)):
                rows.append((arg["name"], "one of: %s" % ", ".join(complete)))
            else:
                rows.append((arg["name"], "required" if arg["required"] else "optional"))
        lines.extend(["", "Arguments:"])
        lines.extend(_fmt_rows(rows))
    shown_flags = []
    # Public command help never advertises GNU-style --options.
    if False:
        shown_flags = [flag for flag in cmd["flags"] if not flag.get("hidden")]
    if shown_flags:
        rows = []
        for flag in shown_flags:
            label = flag["name"]
            if flag["arity"] != 0 and flag.get("metavar"):
                label = "%s %s" % (flag["name"], flag["metavar"])
            bits = []
            if flag.get("description"):
                bits.append(flag["description"])
            elif flag["arity"] == 0:
                bits.append("boolean switch")
            elif flag["choices"]:
                bits.append("one of: %s" % "|".join(flag["choices"]))
            else:
                bits.append("value")
            if flag.get("effect"):
                bits.append("effect: %s" % flag["effect"])
            if flag.get("risk") and flag["risk"] != "none":
                bits.append("risk: %s" % flag["risk"])
            if flag.get("examples"):
                bits.append("e.g. %s" % ", ".join(flag["examples"]))
            rows.append((label, "; ".join(bits)))
        lines.extend(["", "Options:"])
        lines.extend(_fmt_rows(rows))
    if cmd.get("risk") and cmd["risk"] != "none":
        lines.extend(["", "Risk: %s" % cmd["risk"]])
    if cmd.get("confirmation") and cmd["confirmation"] != "none":
        lines.extend(["", "Confirmation: %s" % cmd["confirmation"]])
    if cmd["examples"]:
        lines.extend(["", "Examples:"])
        for item in cmd["examples"]:
            lines.append("  %s" % item)
    if cmd["destructive"]:
        lines.extend(["", "This command is destructive."])
    return "\n".join(lines) + "\n"


WORKFLOWS = (
    (
        "Connect a Managed Host",
        (
            "set enrollment zero-touch",
            "show enrollments",
            "show managed-hosts",
            "show managed-host <HOST>",
        ),
        "Zero-Touch enrollment is the recommended path. Use "
        "'set enrollment bulk' for bounded multi-ticket issuance "
        "(max 10 per request, max 10 active unused).",
        "server",
    ),
    (
        "Create a Remote Service — Agent Host",
        (
            "set remote-service ssh-access destination this-host service ssh enabled",
            "show remote-service ssh-access",
            "show remote-services",
        ),
        "Remote Services are owned by the Agent Host. The Server allocates "
        "the public endpoint when the Agent is connected.",
        "agent",
    ),
    (
        "Remote Access BLACKLIST",
        (
            "set remote-access block-partner mode blacklist source partner-office destination ubuntu-prod service ssh enabled",
            "test remote-access source partner-office destination ubuntu-prod service ssh",
        ),
        "Remote Access uses explicit BLACKLIST or WHITELIST mode with "
        "Network Objects / Groups and Service Objects / Groups — not legacy ordered ALLOW/DENY row evaluation.",
        "server",
    ),
    (
        "Internet Access WHITELIST",
        (
            "set internet-access github-https mode whitelist source ubuntu-prod destination github service https enabled",
            "test internet-access source ubuntu-prod destination github service https",
        ),
        "Internet Access uses explicit WHITELIST or BLACKLIST mode.",
        "server",
    ),
    (
        "AI Access lifecycle",
        (
            "set ai-identity automation-bot",
            "set permission-object exec-only permissions command-exec",
            "set ai-access allow-exec mode whitelist source automation-bot destination ubuntu-prod permission exec-only enabled",
            "test ai-access source automation-bot destination ubuntu-prod permission command-exec",
            "show ai-access",
            "show ai-access-log",
        ),
        "Authenticate the AI Identity before authorization. Permission Objects/Groups "
        "are required for AI Access Rules.",
        "server",
    ),
    (
        "ConfigurationBundle",
        (
            "test configuration drlink.yaml",
            "system diff configuration drlink.yaml",
            "system apply configuration drlink.yaml",
            "system export configuration exported.yaml",
        ),
        "File or stdin ('-') input is supported. Apply validates, tests, "
        "diffs, confirms, then commits atomically.",
        "both",
    ),
    (
        "Routine maintenance — Server",
        (
            "system diagnostics",
            "system backup",
            "system update product",
            "system support-bundle",
            "system version",
        ),
        "'system update engine' updates the upstream Relay Engine (FRP) binary separately. "
        "Use 'system update check-engine' to check upstream releases.",
        "server",
    ),
    (
        "Routine maintenance — Agent Host",
        (
            "system diagnostics",
            "system support-bundle",
            "system version",
            "system synchronize",
        ),
        "Agent Host maintenance focuses on local diagnostics and Server synchronization.",
        "agent",
    ),
)


def workflow_help(role):
    client, server = role_parts(role)
    lines = ["Common workflows", "================", ""]
    for title, steps, note, scope in WORKFLOWS:
        if scope == "server" and not server:
            continue
        if scope == "agent" and not client:
            continue
        lines.append(title)
        lines.append("-" * len(title))
        for step in steps:
            lines.append("  %s" % step)
        if note:
            lines.extend(["", "  %s" % note])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def legacy_help(role):
    return (
        "'help legacy' has been removed.\n"
        "Use: help commands\n"
        "Canonical roots: show, set, unset, test, system, menu, help, exit\n"
    )


def parity_paths(role):
    """Canonical command paths that discovery surfaces must expose."""
    return [
        " ".join(cmd["path"])
        for cmd in COMMANDS
        if role_allows(cmd["roles"], role) and not cmd.get("hidden")
    ]


def suggestion_roots(role):
    """Root tokens used for 'Did you mean' suggestions (canonical first)."""
    return list(roots_for_role(role))


def shell_usage_lines(role):
    """Compact usage bullets for ``drlink --help`` / unknown-command recovery."""
    lines = [
        "Canonical grammar:",
        "  <action> <resource> [target] [value]",
        "",
        "Design: action-first · guided domains · no user-facing --options",
        "",
        "Guided UI:  menu",
        "Commands:   help commands",
        "Discovery:  ?  (executable roots; not domain work areas)",
        "",
    ]
    for root, summary in root_rows(role):
        actions = [name for name, _desc in subcommands(root, role)]
        if not actions:
            lines.append("  %s" % root)
            continue
        if len(actions) <= 4:
            lines.append("  %s %s" % (root, " | ".join(actions)))
        else:
            lines.append(
                "  %s %s | ..."
                % (root, " | ".join(actions[:4]))
            )
        _ = summary
    return lines


# --- Guided navigation tree (task domains; not flat parser verbs) ---------
# Each entry: (action_id, label, description, kind, target)
# kind: submenu | command | workflow | exit | back | help
# target: submenu key | canonical command string | workflow id | None

NAVIGATION_TREE = {
    # Single Agent Host menu SSOT (v2.4). Do not expose a second client.system
    # tree as a competing root. Agent lifecycle stays under Agent; generic
    # operational items live under System (parity with Server).
    "client": (
        (
            "client_remote_services",
            "Remote Services",
            "Create and manage Remote Services on this Agent Host",
            "submenu",
            "client.remote_services",
        ),
        (
            "client_agent",
            "Agent",
            "Pause, resume, restart and autostart",
            "submenu",
            "client.agent",
        ),
        (
            "client_configuration",
            "Configuration",
            "Test, diff, apply and export ConfigurationBundle",
            "submenu",
            "client.configuration",
        ),
        (
            "client_system",
            "System",
            "Status, connection, diagnostics, updates and support",
            "submenu",
            "client.system",
        ),
        ("client_help", "Help", "", "help", None),
        ("exit", "Exit", "", "exit", None),
    ),
    "client.remote_services": (
        ("client_rs_list", "List Remote Services", "", "command", "show remote-services"),
        ("client_rs_create", "Create Remote Service", "", "command", "set remote-service"),
        ("client_rs_manage", "Manage Remote Service", "", "command", "show remote-services"),
        ("back", "Back", "", "back", None),
    ),
    "client.agent": (
        ("client_agent_show", "Show Agent", "", "command", "show agent"),
        ("client_sys_pause", "Pause", "", "command", "system pause"),
        ("client_sys_resume", "Resume", "", "command", "system resume"),
        ("client_sys_restart", "Restart", "", "command", "system restart"),
        ("client_sys_autostart", "Autostart", "", "command", "system autostart"),
        ("back", "Back", "", "back", None),
    ),
    "client.configuration": (
        ("client_cfg_test", "Test Configuration", "", "command", "test configuration"),
        ("client_cfg_diff", "Diff Configuration", "", "command", "system diff configuration"),
        ("client_cfg_apply", "Apply Configuration", "", "command", "system apply configuration"),
        ("client_cfg_export", "Export Configuration", "", "command", "system export configuration"),
        ("back", "Back", "", "back", None),
    ),
    "client.services": (
        ("client_svc_list", "List Remote Services", "", "command", "show remote-services"),
        ("client_svc_add", "Create Remote Service", "", "command", "set remote-service"),
        ("back", "Back", "", "back", None),
    ),
    "client.system": (
        ("client_sys_status", "Status", "", "command", "show status"),
        ("client_sys_info", "Connection Information", "", "command", "system info"),
        ("client_sys_doctor", "Diagnostics", "", "command", "system diagnostics"),
        ("client_sys_support", "Support Bundle", "", "command", "system support-bundle"),
        ("client_sys_version", "Version Information", "", "command", "system version"),
        (
            "client_sys_updates",
            "Updates",
            "Update Data Relay Link or Relay Engine",
            "submenu",
            "client.system.updates",
        ),
        ("client_sys_uninstall", "Uninstall Data Relay Link", "", "command", "system uninstall"),
        ("back", "Back", "", "back", None),
    ),
    "client.system.updates": (
        ("client_sys_update_product", "Update Data Relay Link", "", "command", "system update product"),
        ("client_sys_update_engine", "Update Relay Engine", "", "command", "system update engine"),
        ("back", "Back", "", "back", None),
    ),
    "server": (
        (
            "server_hosts",
            "Managed Hosts",
            "Connect and manage Managed Hosts / Agents",
            "submenu",
            "server.hosts",
        ),
        (
            "server_network_objects",
            "Network Objects",
            "IP, CIDR, FQDN Network Objects and Groups",
            "submenu",
            "server.network_objects",
        ),
        (
            "server_service_objects",
            "Service Objects",
            "TCP, UDP and Fixed TCP Service Objects and Groups",
            "submenu",
            "server.service_objects",
        ),
        (
            "server_remote",
            "Remote Access",
            "Remote Access policy rules and tests",
            "submenu",
            "server.remote",
        ),
        (
            "server_internet",
            "Internet Access",
            "Internet Access policy rules and tests",
            "submenu",
            "server.internet",
        ),
        (
            "server_ai",
            "AI Access",
            "AI Identities, Permissions, Rules and Access Log",
            "submenu",
            "server.ai",
        ),
        (
            "server_system",
            "System",
            "Status, settings, backup, updates and diagnostics",
            "submenu",
            "server.system",
        ),
        ("server_help", "Help", "", "help", None),
        ("exit", "Exit", "", "exit", None),
    ),
    "server.hosts": (
        ("server_hosts_list", "List Managed Hosts", "", "command", "show managed-hosts"),
        ("server_zt", "Connect New Host", "", "workflow", "create_zero_touch"),
        ("server_hosts_manage", "Manage Host", "", "command", "show managed-hosts"),
        ("server_enrollments", "Enrollments", "", "submenu", "server.clients.enrollments"),
        ("back", "Back", "", "back", None),
    ),
    "server.clients": (
        ("server_zt", "Connect a new host", "", "workflow", "create_zero_touch"),
        ("server_clients_list", "List Managed Hosts", "", "command", "show managed-hosts"),
        ("server_clients_manage", "View or manage a host", "", "command", "show managed-hosts"),
        ("server_enrollments", "Enrollments", "", "submenu", "server.clients.enrollments"),
        ("back", "Back", "", "back", None),
    ),
    "server.clients.groups": (
        ("back", "Back", "", "back", None),
    ),
    "server.network_objects": (
        ("server_no_list", "Network Objects", "", "command", "show network-objects"),
        ("server_no_create", "Create Network Object", "", "command", "set network-object"),
        ("server_ng_list", "Network Groups", "", "command", "show network-groups"),
        ("server_ng_create", "Create Network Group", "", "command", "set network-group"),
        ("back", "Back", "", "back", None),
    ),
    "server.service_objects": (
        ("server_so_list", "Service Objects", "", "command", "show service-objects"),
        ("server_so_create", "Create Service Object", "", "command", "set service-object"),
        ("server_sg_list", "Service Groups", "", "command", "show service-groups"),
        ("server_sg_create", "Create Service Group", "", "command", "set service-group"),
        ("back", "Back", "", "back", None),
    ),
    "server.objects": (
        ("server_obj_list", "Network Objects", "", "command", "show network-objects"),
        ("server_obj_create", "Create Network Object", "", "command", "set network-object"),
        ("server_og_list", "Network Groups", "", "command", "show network-groups"),
        ("back", "Back", "", "back", None),
    ),
    "server.remote": (
        ("server_ra_list", "Rules", "", "command", "show remote-access"),
        ("server_ra_create", "Create Remote Access rule", "", "command", "set remote-access"),
        ("server_ra_test", "Test / Explain", "", "command", "test remote-access"),
        ("back", "Back", "", "back", None),
    ),
    "server.ai": (
        ("server_ai_identities", "Connect AI / AI Identities", "", "command", "show ai-identities"),
        ("server_ai_perm", "Permission Objects", "", "command", "show permission-objects"),
        ("server_ai_perm_groups", "Permission Groups", "", "command", "show permission-groups"),
        ("server_ai_rules", "Rules", "", "command", "show ai-access"),
        ("server_ai_log", "Access Log", "", "command", "show ai-access-log"),
        ("server_ai_test", "Test / Explain", "", "command", "test ai-access"),
        ("back", "Back", "", "back", None),
    ),
    "server.clients.enrollments": (
        ("server_enroll_list", "List enrollments", "", "command", "show enrollments"),
        ("server_enroll_create", "Create manual enrollment code", "", "workflow", "create_enrollment"),
        ("server_enroll_bulk", "Create enrollment codes in bulk", "", "command", "set enrollment bulk"),
        ("server_enroll_revoke", "Revoke active enrollment", "", "workflow", "revoke_enrollment"),
        ("server_enroll_delete", "Delete terminal enrollment record", "", "workflow", "delete_enrollment"),
        ("back", "Back", "", "back", None),
    ),
    "server.services": (
        ("server_svc_list", "Remote Services (inspect via Managed Host)", "", "command", "show managed-hosts"),
        ("back", "Back", "", "back", None),
    ),
    "server.internet": (
        ("server_ia_list", "Rules", "", "command", "show internet-access"),
        ("server_ia_create", "Create Internet Access rule", "", "command", "set internet-access"),
        ("server_ia_test", "Test / Explain", "", "command", "test internet-access"),
        ("back", "Back", "", "back", None),
    ),
    "server.internet.tcp": (
        ("server_egt_list", "Fixed TCP Service Objects", "", "command", "show service-objects"),
        ("server_egt_create", "Create Fixed TCP Service Object", "", "command", "set service-object"),
        ("back", "Back", "", "back", None),
    ),
    "server.system": (
        ("server_sys_status", "Status", "", "command", "system status"),
        ("server_sys_settings", "Server Settings", "", "submenu", "server.system.settings"),
        ("server_sys_backup", "Backup & Restore", "", "submenu", "server.system.backup"),
        ("server_sys_updates", "Updates", "", "submenu", "server.system.updates"),
        ("server_sys_diag", "Diagnostics", "", "submenu", "server.system.diagnostics"),
        ("server_sys_audit", "Audit Log", "", "command", "system audit"),
        ("server_sys_export", "Export configuration", "", "command", "system export configuration"),
        ("server_sys_version", "Version Information", "", "command", "system version"),
        ("server_sys_uninstall", "Uninstall Data Relay Link", "", "command", "system uninstall"),
        ("back", "Back", "", "back", None),
    ),
    "server.system.settings": (
        ("server_set_public", "Published service hostname", "", "workflow", "set_public_hostname"),
        ("server_set_bootstrap", "Bootstrap hostname", "", "workflow", "set_bootstrap_hostname"),
        ("server_set_installer", "Linux/macOS client installer URL", "", "workflow", "set_installer_url"),
        ("server_set_win_installer", "Windows client installer URL", "", "workflow", "set_windows_installer_url"),
        ("back", "Back", "", "back", None),
    ),
    "server.system.backup": (
        ("server_bak_create", "Create backup", "", "command", "system backup"),
        ("server_bak_restore", "Restore backup", "", "workflow", "restore_backup"),
        ("back", "Back", "", "back", None),
    ),
    "server.system.updates": (
        ("server_upd_product", "Update Data Relay Link", "", "command", "system update product"),
        ("server_upd_upstream", "Check upstream relay-engine release", "", "command", "system update check-engine"),
        ("server_upd_engine", "Update Relay Engine (FRP)", "", "command", "system update engine"),
        ("back", "Back", "", "back", None),
    ),
    "server.system.diagnostics": (
        ("server_diag_doctor", "Run health checks", "", "command", "system diagnostics"),
        ("server_diag_support", "Create support bundle", "", "command", "system support-bundle"),
        ("back", "Back", "", "back", None),
    ),
}

# Dual-role hosts use the server product-domain root (not Client/Server ops),
# and distinguish published vs local services inside Services.
NAVIGATION_TREE["both"] = (
    (
        "both_hosts",
        "Managed Hosts",
        "Connect and manage Managed Hosts / Agents",
        "submenu",
        "server.hosts",
    ),
    (
        "both_network_objects",
        "Network Objects",
        "IP, CIDR, FQDN Network Objects and Groups",
        "submenu",
        "server.network_objects",
    ),
    (
        "both_service_objects",
        "Service Objects",
        "TCP, UDP and Fixed TCP Service Objects and Groups",
        "submenu",
        "server.service_objects",
    ),
    (
        "both_remote",
        "Remote Access",
        "Remote Access policy rules and tests",
        "submenu",
        "server.remote",
    ),
    (
        "both_remote_services",
        "Remote Services",
        "Agent-local Remote Services on this host",
        "submenu",
        "client.remote_services",
    ),
    (
        "both_internet",
        "Internet Access",
        "Internet Access policy rules and tests",
        "submenu",
        "server.internet",
    ),
    (
        "both_ai",
        "AI Access",
        "AI Identities, Permissions, Rules and Access Log",
        "submenu",
        "server.ai",
    ),
    (
        "both_system",
        "System",
        "Status, settings, backup, updates, agent lifecycle and diagnostics",
        "submenu",
        "both.system",
    ),
    ("both_help", "Help", "", "help", None),
    ("exit", "Exit", "", "exit", None),
)
NAVIGATION_TREE["both.system"] = (
    ("both_sys_status", "Status", "", "command", "system status"),
    ("both_sys_settings", "Server Settings", "", "submenu", "server.system.settings"),
    ("both_sys_backup", "Backup & Restore", "", "submenu", "server.system.backup"),
    ("both_sys_pause", "Pause Agent", "", "command", "system pause"),
    ("both_sys_resume", "Resume Agent", "", "command", "system resume"),
    ("both_sys_restart", "Restart Agent", "", "command", "system restart"),
    ("both_sys_autostart", "Agent autostart", "", "command", "system autostart"),
    ("both_sys_updates", "Updates", "", "submenu", "server.system.updates"),
    ("both_sys_diag", "Diagnostics", "", "submenu", "server.system.diagnostics"),
    ("both_sys_audit", "Audit Log", "", "command", "system audit"),
    ("both_sys_version", "Version Information", "", "command", "system version"),
    ("both_sys_uninstall", "Uninstall Data Relay Link", "", "command", "system uninstall"),
    ("back", "Back", "", "back", None),
)
NAVIGATION_TREE["both.services"] = (
    ("both_svc_published", "Remote Services (Agent)", "", "command", "show remote-services"),
    (
        "both_svc_local",
        "Remote Services on this machine",
        "",
        "submenu",
        "client.remote_services",
    ),
    ("back", "Back", "", "back", None),
)


def _nav_key_for_role(role):
    client, server = role_parts(role)
    if client and server:
        return "both"
    if client:
        return "client"
    return "server"


def navigation_entries(menu_key):
    """Return navigation rows for a menu key."""
    return list(NAVIGATION_TREE.get(menu_key, ()))


def render_navigation_menu(menu_key, title=None):
    """Render one navigation level without backend command hints."""
    entries = navigation_entries(menu_key)
    lines = []
    if title:
        lines.append(title)
        lines.append("=" * len(title))
        lines.append("")
    n = 0
    for _action_id, label, description, _kind, _target in entries:
        n += 1
        lines.append("%s) %s" % (n, label))
        if description:
            lines.append("   %s" % description)
    return "\n".join(lines) + ("\n" if lines else "")


def navigation_resolve(menu_key, choice):
    """Resolve a numeric choice to (action_id, label, description, kind, target)."""
    text = str(choice or "").strip()
    if not text.isdigit():
        return None
    n = int(text)
    entries = navigation_entries(menu_key)
    if n < 1 or n > len(entries):
        return None
    return entries[n - 1]


# Backwards-compatible guided-menu helpers (flat listing of root domains).
GUIDED_MENU = NAVIGATION_TREE


def _guided_menu_key(role):
    return _nav_key_for_role(role)


def _guided_menu_sections(role):
    key = _guided_menu_key(role)
    entries = navigation_entries(key)
    yield None, tuple((a, label, desc) for a, label, desc, _k, _t in entries)


def guided_menu_entries(role):
    """Ordered guided-menu rows for role: list of (n, action_id, label, hint)."""
    rows = []
    n = 0
    for _category, entries in _guided_menu_sections(role):
        for action_id, label, hint in entries:
            n += 1
            rows.append((n, action_id, label, hint))
    return rows


def render_guided_menu(role):
    """Text block for the numbered guided menu (root domains only)."""
    key = _guided_menu_key(role)
    title = "Data Relay Link"
    return render_navigation_menu(key, title=title)


def guided_menu_action(role, choice):
    """Resolve a numeric root-menu choice to action_id, or None."""
    resolved = navigation_resolve(_guided_menu_key(role), choice)
    if not resolved:
        return None
    return resolved[0]


# Resource-domain grouping for large Tab / context candidate lists.
COMPLETION_DOMAIN_GROUPS = (
    (
        "Managed Hosts",
        (
            "managed-hosts",
            "managed-host",
            "clients",
            "client",
            "groups",
            "group",
            "client-groups",
            "client-group",
            "enrollments",
            "enrollment",
        ),
    ),
    (
        "Remote Services",
        (
            "remote-services",
            "remote-service",
            "services",
            "service",
            "service-profiles",
            "service-profile",
        ),
    ),
    (
        "Network Objects",
        (
            "network-objects",
            "network-object",
            "network-groups",
            "network-group",
            "objects",
            "object",
            "object-groups",
            "object-group",
        ),
    ),
    (
        "Service Objects",
        (
            "service-objects",
            "service-object",
            "service-groups",
            "service-group",
        ),
    ),
    (
        "Access Control",
        (
            "acls",
            "acl",
            "access-log",
            # Hidden compatibility tokens (must not create "Other").
            "access-rules",
            "access-rule",
            "access-source",
            "service-access",
            "access-service",
            "access-lists",
            "access-list",
        ),
    ),
    (
        "Remote Access",
        (
            "remote-access",
            "published-services",
            "published-service",
            "service-presets",
            "service-preset",
            "managed-endpoints",
            "managed-endpoint",
        ),
    ),
    (
        "Internet Access",
        (
            "internet-access",
            "internet",
            "internet-profiles",
            "internet-profile",
            "internet-templates",
            "internet-template",
            "fixed-tcp",
            # Hidden compatibility tokens.
            "internet-source",
            "internet-destination",
            "egress-destination",
            "egress-source",
        ),
    ),
    (
        "AI Access",
        (
            "ai-access",
            "ai-identities",
            "ai-identity",
            "ai-principals",
            "ai-principal",
            "ai-activity",
            "ai-access-log",
            "permission-objects",
            "permission-object",
            "permission-groups",
            "permission-group",
        ),
    ),
    (
        "System",
        (
            "status",
            "version",
            "server-status",
            "upstream",
            "audit",
            "backup",
            "support-bundle",
            "info",
            "installer-url",
            "windows-installer-url",
            "server",
            "product",
            "engine",
        ),
    ),
)


def group_completion_candidates(candidates):
    """Group resource tokens by product domain for large Tab/context lists."""
    items = [str(c) for c in (candidates or []) if str(c).strip()]
    if len(items) < 6:
        return None
    assigned = set()
    groups = []
    for title, members in COMPLETION_DOMAIN_GROUPS:
        hit = [c for c in items if c in members]
        if hit:
            groups.append((title, hit))
            assigned.update(hit)
    other = [c for c in items if c not in assigned]
    # Never advertise an "Other" bucket in normal product discovery.
    if other:
        # Attach leftovers to System rather than inventing a catch-all label.
        for i, (title, members) in enumerate(groups):
            if title == "System":
                groups[i] = (title, list(members) + other)
                other = []
                break
        if other:
            groups.append(("System", other))
    if len(groups) <= 1:
        return None
    return groups
