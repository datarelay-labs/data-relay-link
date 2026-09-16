#!/usr/bin/env python3
"""Canonical Data Relay Link CLI command catalog (CLI-011).

Single source of truth for the final public ``drlink`` grammar:

    show | set | unset | test | system | menu | help | exit

Root help, ``help <topic>``, context ``?``, Tab discovery, and the guided
menu are all derived from :data:`PUBLIC_COMMANDS` / :data:`COMMANDS`.
Hidden compatibility aliases live in :data:`HIDDEN_COMPAT_ALIASES` and must
not appear in normal discovery surfaces.

Public UX never advertises GNU-style ``--options`` or backend ``frp-*``
tool names.
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
    ("show", "any", "View", "View current clients, services, policies and status"),
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


_MIGRATION_SOURCE_COMMANDS = (
    # --- status / version -------------------------------------------------
    _cmd(
        ("status",),
        "any",
        "Status",
        "Show host status",
        detail="Role-aware host status. On a dual-role host both the client "
        "and the server sections are printed.",
        examples=("status",),
        aliases=(("show", "status"),),
    ),
    _cmd(
        ("version",),
        "any",
        "Status",
        "Show installed versions",
        detail="Data Relay Link display identity, release channel, source HEAD, "
        "Relay Engine (FRP) version, and optional bundle checksum. Stable is "
        "never claimed from PROJECT_VERSION alone.",
        examples=("version",),
        aliases=(("show", "version"),),
    ),
    # --- zero touch -------------------------------------------------------
    _cmd(
        ("zero-touch", "create"),
        "server",
        "Onboarding",
        "Guided Zero-Touch onboarding (recommended)",
        detail="Starts the guided workflow that produces a one-line Zero-Touch "
        "client installation command. This is the recommended everyday way to "
        "onboard a client.",
        examples=("zero-touch create",),
        internal=("create", "zero-touch"),
        aliases=(("create", "zero-touch"),),
    ),
    # --- enrollment -------------------------------------------------------
    _cmd(
        ("enrollment", "list"),
        "server",
        "Onboarding",
        "List issued enrollment credentials",
        detail="Lists manual Enrollment Codes and Zero-Touch bootstrap tickets "
        "still on disk. Secrets are never printed.",
        examples=("show enrollments",),
        internal=("show", "enrollments"),
        aliases=(("show", "enrollments"), ("enrollments",)),
    ),
    _cmd(
        ("enrollment", "create"),
        "server",
        "Onboarding",
        "Create one Manual Enrollment Code",
        detail="Generates a Manual Enrollment Code for an interactive client "
        "install. Lifetime maximum is 30d (2592000 seconds). For everyday "
        "onboarding prefer 'create zero-touch'.",
        examples=(
            "enrollment create",
            "enrollment create --ssh --ssh-user aella --label dp01",
        ),
        flags=ENROLL_FLAGS,
        tail="flags",
        internal=("create", "enrollment"),
        aliases=(("create", "enrollment"), ("enroll",), ("create-client",)),
    ),
    _cmd(
        ("enrollment", "bulk"),
        "server",
        "Onboarding",
        "Create enrollment codes in bulk",
        detail="Bulk issuance from a count or a CSV file.",
        examples=("enrollment bulk --count 10", "enrollment bulk --csv clients.csv"),
        flags=BULK_FLAGS,
        tail="flags",
        internal=("create", "enrollments"),
        aliases=(("create", "enrollments"), ("enroll-bulk",)),
    ),
    _cmd(
        ("enrollment", "revoke"),
        "server",
        "Onboarding",
        "Revoke a pending or bound enrollment",
        detail="Prevents a pending or bound enrollment credential from being "
        "used. Terminal records (expired, completed, revoked) are purged, not "
        "revoked.",
        examples=("revoke enrollment 0011223344556677",),
        args=(_arg("<ENROLLMENT-ID>"),),
        internal=("revoke", "enrollment"),
        aliases=(("revoke", "enrollment"), ("enrollment-revoke",)),
        destructive=True,
    ),
    _cmd(
        ("enrollment", "purge"),
        "server",
        "Onboarding",
        "Permanently remove terminal enrollment metadata",
        detail="Removes terminal enrollment records (expired, completed, or "
        "revoked). Active pending or bound enrollments must be revoked first.\n"
        "Use --older-than <days> for a bulk purge.",
        examples=(
            "enrollment purge 0011223344556677",
            "enrollment purge --older-than 30",
        ),
        args=(_arg("<ENROLLMENT-ID>", required=False),),
        flags=("--older-than",),
        tail="flags",
        aliases=(("purge", "enrollment"), ("purge", "enrollments")),
        destructive=True,
    ),
    # --- client (server role) --------------------------------------------
    _cmd(
        ("client", "list"),
        "server",
        "Inventory",
        "List registered clients",
        detail="CLIENT ID is the immutable selector and the first identity "
        "column. Label and hostname are display metadata. Optional GROUP "
        "filters the list to members of that group.",
        examples=("client list", "client list edge"),
        args=(_arg("<GROUP>", required=False),),
        flags=(
            _flag(
                "--group",
                arity=1,
                description="Hidden compatibility filter by group",
                effect="Same as positional GROUP",
                risk="none",
                hidden=True,
            ),
        ),
        tail="flags",
        internal=("show", "clients"),
        aliases=(("show", "clients"), ("clients",)),
    ),
    _cmd(
        ("client", "show"),
        "server",
        "Inventory",
        "Show one client (overview, services, tags, groups)",
        detail="CLIENT ID is the immutable selector. A unique label or unique "
        "hostname is also accepted as a shortcut.",
        examples=(
            "client show 24cd7856",
            "client show 24cd7856 services",
            "client show 24cd7856 tags",
        ),
        args=(
            _arg("<CLIENT-ID>", C_CLIENT),
            _arg("services|tags|groups", CLIENT_VIEWS, required=False),
        ),
        internal=("show", "client"),
        aliases=(("show", "client"), ("client-info",)),
    ),
    _cmd(
        ("client", "set"),
        "server",
        "Inventory",
        "Set client metadata (label, note, tag)",
        detail="Administrator metadata only. Changing a label never changes "
        "CLIENT ID, ports, or enrollment.",
        examples=(
            "client set 24cd7856 label production",
            'client set 24cd7856 note "Seoul production gateway"',
            "client set 24cd7856 tag env oci",
        ),
        args=(
            _arg("<CLIENT-ID>", C_CLIENT),
            _arg("label|note|tag", CLIENT_PROPS),
            _arg("<value>", required=False),
        ),
        tail="any",
        internal=("set", "client"),
        aliases=(("set", "client"), ("client-set",), ("edit-client",)),
    ),
    _cmd(
        ("client", "unset"),
        "server",
        "Inventory",
        "Remove client metadata",
        detail="Removes stored metadata only. It does not release ports and "
        "does not revoke identity.",
        examples=(
            "client unset 24cd7856 label",
            "client unset 24cd7856 tag env",
        ),
        args=(
            _arg("<CLIENT-ID>", C_CLIENT),
            _arg("label|note|tag", CLIENT_PROPS),
            _arg("<tag-key>", required=False),
        ),
        internal=("unset", "client"),
        aliases=(("unset", "client"),),
    ),
    _cmd(
        ("client", "revoke"),
        "server",
        "Inventory",
        "Block a client's management trust",
        detail=(
            "Blocks management identity / trust. Reservations and the client "
            "registry record stay.\n\n"
            "WHAT WILL BE REMOVED\n"
            "  management identity / trust (re-enrollment required)\n\n"
            "WHAT STAYS\n"
            "  client registry record\n"
            "  all service reservations\n"
            "  all public ports\n\n"
            "Confirmation: type REVOKE (or pass --force to skip).\n"
            "Not the same as 'release client', 'unset client', disable, or "
            "uninstall. This does not delete the remote host or local software."
        ),
        examples=("revoke client 24cd7856", "revoke client 24cd7856 --force"),
        args=(_arg("<CLIENT-ID>", C_CLIENT),),
        flags=(
            _flag(
                "--force",
                arity=0,
                description="Skip typed REVOKE confirmation",
                effect="Proceeds without typing REVOKE",
                risk="irreversible",
            ),
        ),
        tail="flags",
        internal=("revoke", "client"),
        aliases=(("revoke", "client"), ("revoke-client",)),
        destructive=True,
        risk="irreversible",
        confirmation="typed_token",
    ),
    _cmd(
        ("client", "release"),
        "server",
        "Inventory",
        "Release client record and ports, or one service reservation",
        detail=(
            "client release <CLIENT-ID>\n"
            "  WHAT WILL BE REMOVED\n"
            "    client registry record\n"
            "    management identity\n"
            "    ALL service reservations\n"
            "    ALL public ports\n"
            "  WHAT WILL NOT HAPPEN\n"
            "    no remote host deletion\n"
            "    no local software uninstall\n"
            "  Confirmation: type RELEASE\n\n"
            "client release <CLIENT-ID> <SERVICE-ID>\n"
            "  Release only that service reservation.\n"
            "  WHAT STAYS: management identity, client record, other services.\n"
            "  Confirmation: type RELEASE\n\n"
            "--force allows release while a published port is still active.\n"
            "Not the same as revoke, unset, disable, or uninstall."
        ),
        examples=(
            "client release 24cd7856",
            "client release 24cd7856 ssh",
            "client release 24cd7856 --force",
        ),
        args=(
            _arg("<CLIENT-ID>", C_CLIENT),
            _arg("<SERVICE-ID>", C_CLIENT_SERVICE, required=False),
        ),
        flags=(
            _flag(
                "--force",
                arity=0,
                description="Release even if a published port is still active",
                effect="Overrides the active-publish safety gate",
                risk="outage",
            ),
        ),
        tail="flags",
        aliases=(
            ("release", "client"),
            ("release", "service"),
            ("release-client",),
            ("release-service",),
        ),
        destructive=True,
        risk="irreversible",
        confirmation="typed_token",
    ),
    _cmd(
        ("client", "info"),
        "client",
        "Inventory",
        "Show local client connection information",
        detail="Connection information for this installed client host.",
        examples=("client info",),
        internal=("show", "info"),
        aliases=(("show", "info"), ("info",)),
    ),
    # --- service -------------------------------------------------------------
    _cmd(
        ("service", "list"),
        "any",
        "Inventory",
        "List published services",
        detail="On the server: global inventory across clients (CLIENT / SERVICE / "
        "PUBLIC ENDPOINT / ACCESS / STATE / PORT STATE). On a client host: local "
        "published services.",
        examples=("service list",),
        internal=("show", "services"),
        aliases=(("show", "services"), ("services",)),
    ),
    _cmd(
        ("service", "add"),
        "client",
        "Inventory",
        "Add a pending local service",
        detail="Pending until 'service apply'. Seeding from a service profile "
        "copies template defaults only; public ports stay unallocated until "
        "apply.",
        examples=(
            "service add --preset ssh --ssh-user aella",
            "service add --profile office-ssh --id ssh2",
        ),
        flags=SERVICE_ADD_FLAGS,
        tail="flags",
        internal=("add", "service"),
        aliases=(("add", "service"),),
    ),
    _cmd(
        ("service", "set"),
        "client",
        "Inventory",
        "Change a local service property",
        detail="Service IDs cannot be renamed. Pending changes are live only "
        "after 'service apply'. Health checks are disabled by default.",
        examples=(
            "service set ssh target-port 2222",
            "service set web health-type http",
        ),
        args=(
            _arg("<SERVICE-ID>", C_LOCAL_SERVICE),
            _arg("<property>", SERVICE_PROPS),
            _arg("<value>"),
        ),
        internal=("set", "service"),
        aliases=(("set", "service"),),
    ),
    _cmd(
        ("service", "enable"),
        "client",
        "Inventory",
        "Enable a local service",
        examples=("service enable ssh",),
        args=(_arg("<SERVICE-ID>", C_LOCAL_SERVICE),),
        internal=("enable", "service"),
        aliases=(("enable", "service"),),
    ),
    _cmd(
        ("service", "disable"),
        "client",
        "Inventory",
        "Disable a local service",
        detail="The public reservation remains until 'client release' is run "
        "on the server.",
        examples=("service disable ssh",),
        args=(_arg("<SERVICE-ID>", C_LOCAL_SERVICE),),
        internal=("disable", "service"),
        aliases=(("disable", "service"),),
    ),
    _cmd(
        ("service", "apply"),
        "client",
        "Inventory",
        "Apply pending local service changes",
        detail="Applies the pending draft and restarts the Data Relay Link "
        "client. It does not release server-side reservations.",
        examples=("service apply",),
        internal=("apply",),
        aliases=(("apply",),),
    ),
    _cmd(
        ("service", "discard"),
        "client",
        "Inventory",
        "Discard pending local service changes",
        examples=("service discard",),
        internal=("discard",),
        aliases=(("discard",),),
    ),
    _cmd(
        ("service", "sync"),
        "client",
        "Inventory",
        "Reconcile local services against server releases",
        examples=("sync",),
        internal=("sync",),
        aliases=(("sync",),),
    ),
    # --- group ------------------------------------------------------------
    _cmd(
        ("group", "list"),
        "server",
        "Inventory",
        "List client groups",
        examples=("group list",),
        internal=("show", "groups"),
        aliases=(("show", "groups"),),
    ),
    _cmd(
        ("group", "show"),
        "server",
        "Inventory",
        "Show one group and its members",
        examples=("group show edge",),
        args=(_arg("<GROUP>", C_GROUP),),
        internal=("show", "group"),
        aliases=(("show", "group"),),
    ),
    _cmd(
        ("group", "create"),
        "server",
        "Inventory",
        "Create a group",
        detail="Group IDs are immutable ('grp_' plus eight hex digits). Names "
        "and descriptions are mutable.",
        examples=('group create edge --description "Edge sites"',),
        args=(_arg("<name>"),),
        flags=("--description",),
        tail="flags",
        internal=("create", "group"),
        aliases=(("create", "group"),),
    ),
    _cmd(
        ("group", "set"),
        "server",
        "Inventory",
        "Change a group name or description",
        examples=(
            "group set edge name edge-sites",
            "group set edge description 'Edge sites'",
        ),
        args=(
            _arg("<GROUP>", C_GROUP),
            _arg("name|description", GROUP_PROPS),
            _arg("<value>"),
        ),
        internal=("set", "group"),
        aliases=(("set", "group"),),
    ),
    _cmd(
        ("group", "rename"),
        "server",
        "Inventory",
        "Rename a group (compatibility alias for 'group set … name')",
        examples=("group rename edge edge-sites",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<name>")),
        internal=("rename", "group"),
        aliases=(("rename", "group"),),
        hidden=True,
    ),
    _cmd(
        ("group", "delete"),
        "server",
        "Inventory",
        "Delete a group",
        detail="Removes membership references. Client identity, services, and "
        "ports are unchanged. Requires interactive confirmation or --yes.",
        examples=("group delete edge", "group delete edge --yes"),
        args=(_arg("<GROUP>", C_GROUP),),
        flags=("--yes",),
        tail="flags",
        internal=("delete", "group"),
        aliases=(("delete", "group"),),
        destructive=True,
        risk="irreversible",
        confirmation="yes_flag",
    ),
    _cmd(
        ("group", "add-client"),
        "server",
        "Inventory",
        "Add a client to a group",
        examples=("group add-client edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
        # Flipped to: add client <CLIENT-ID> group <GROUP>
        aliases=(("add", "client"),),
    ),
    _cmd(
        ("group", "remove-client"),
        "server",
        "Inventory",
        "Remove a client from a group",
        examples=("group remove-client edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
        # Flipped to: remove client <CLIENT-ID> group <GROUP>
        aliases=(("remove", "client"),),
    ),
    _cmd(
        ("group", "add-member"),
        "server",
        "Inventory",
        "Add a client to a group (compatibility alias for 'group add-client')",
        examples=("group add-member edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
        hidden=True,
        aliases=(("add", "client"),),
    ),
    _cmd(
        ("group", "remove-member"),
        "server",
        "Inventory",
        "Remove a client from a group (compatibility alias for 'group remove-client')",
        examples=("group remove-member edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
        hidden=True,
        aliases=(("remove", "client"),),
    ),
    # --- service profiles -------------------------------------------------
    _cmd(
        ("service-profile", "list"),
        "server",
        "Templates",
        "List service profiles",
        detail="Service profiles are server-owned creation templates. They "
        "never store public ports, CLIENT IDs, Service IDs, or ACL "
        "assignments.",
        examples=("service-profile list",),
        internal=("show", "profiles"),
        aliases=(("show", "profiles"), ("profile", "list")),
    ),
    _cmd(
        ("service-profile", "show"),
        "server",
        "Templates",
        "Show one service profile",
        examples=("service-profile show office-ssh",),
        args=(_arg("<PROFILE>", C_PROFILE),),
        internal=("show", "profile"),
        aliases=(("show", "profile"), ("profile", "show")),
    ),
    _cmd(
        ("service-profile", "create"),
        "server",
        "Templates",
        "Create a service profile",
        examples=(
            "service-profile create office-ssh --preset ssh "
            "--target-host 127.0.0.1 --target-port 22 --ssh-user ubuntu",
        ),
        args=(_arg("<name>"),),
        flags=PROFILE_CREATE_FLAGS,
        tail="flags",
        internal=("create", "profile"),
        aliases=(("create", "profile"), ("profile", "create")),
    ),
    _cmd(
        ("service-profile", "set"),
        "server",
        "Templates",
        "Change a service profile property",
        detail="Editing a profile never mutates existing services.\n"
        "Atomic non-SSH → SSH: "
        "'service-profile set <PROFILE> preset ssh --ssh-user USER'.",
        examples=(
            "service-profile set office-ssh target-port 2222",
            "service-profile set office-web preset ssh --ssh-user ubuntu",
        ),
        args=(
            _arg("<PROFILE>", C_PROFILE),
            _arg("<property>", PROFILE_PROPS),
            _arg("<value>"),
        ),
        flags=(
            _flag(
                "--ssh-user",
                arity=1,
                description="With property=preset ssh, set ssh_user atomically",
                metavar="USER",
                effect="Required for non-SSH → SSH transitions",
                risk="metadata",
            ),
        ),
        tail="flags",
        internal=("set", "profile"),
        aliases=(("set", "profile"), ("profile", "set")),
        risk="metadata",
    ),
    _cmd(
        ("service-profile", "delete"),
        "server",
        "Templates",
        "Delete a service profile",
        detail="Deleting a profile does not change existing services.",
        examples=("service-profile delete office-ssh",),
        args=(_arg("<PROFILE>", C_PROFILE),),
        internal=("delete", "profile"),
        aliases=(("delete", "profile"), ("profile", "delete")),
        destructive=True,
    ),
    # --- access -----------------------------------------------------------
    _cmd(
        ("access", "list"),
        "server",
        "Policy",
        "List Named Access Lists",
        examples=("access list",),
    ),
    _cmd(
        ("access", "create"),
        "server",
        "Policy",
        "Create a Named Access List",
        detail="Descriptions are limited to 1024 characters; control characters, "
        "newlines, and ANSI escapes are rejected.",
        examples=('access create office --description "Office ranges"',),
        args=(_arg("<name>"),),
        flags=("--description",),
        tail="flags",
        risk="metadata",
    ),
    _cmd(
        ("access", "show"),
        "server",
        "Policy",
        "Show one Named Access List",
        examples=("access show office",),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
    ),
    _cmd(
        ("access", "delete"),
        "server",
        "Policy",
        "Delete a Named Access List",
        examples=("access delete office",),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        flags=("--yes",),
        tail="flags",
        destructive=True,
        risk="irreversible",
        confirmation="yes_flag",
    ),
    _cmd(
        ("access", "add-source"),
        "server",
        "Policy",
        "Add a source range to a list",
        detail="--ttl accepts Ns/Nm/Nh/Nd up to 3650d (10 years); larger values are rejected.",
        examples=("access add-source office --name hq --source 203.0.113.0/24 --ttl 4h",),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        flags=("--name", "--source", "--ttl", "--yes"),
        tail="flags",
        risk="metadata",
        confirmation="yes_flag",
    ),
    _cmd(
        ("access", "remove-source"),
        "server",
        "Policy",
        "Remove a source range from a list",
        examples=("access remove-source office --source 203.0.113.0/24",),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        flags=("--source", "--yes"),
        tail="flags",
        destructive=True,
        risk="outage",
        confirmation="yes_flag",
    ),
    _cmd(
        ("access", "replace-source"),
        "server",
        "Policy",
        "Replace a source entry atomically",
        detail="Updates name/source/TTL for an existing entry in one step. "
        "Shared-list mutations still require confirmation or --yes.",
        examples=(
            "access replace-source office --source 203.0.113.0/24 "
            "--name hq --new-source 198.51.100.0/24 --ttl 1d",
        ),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        flags=("--source", "--name", "--new-source", "--ttl", "--yes"),
        tail="flags",
        risk="metadata",
        confirmation="yes_flag",
    ),
    _cmd(
        ("access", "edit-info"),
        "server",
        "Policy",
        "Edit a list name or description",
        detail="Descriptions are limited to 1024 characters; control characters, "
        "newlines, and ANSI escapes are rejected.",
        examples=('access edit-info office --description "HQ only"',),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        flags=("--name", "--description", "--yes"),
        tail="flags",
        risk="metadata",
        confirmation="yes_flag",
    ),
    _cmd(
        ("access", "remove-expired"),
        "server",
        "Policy",
        "Remove expired TTL entries from a list",
        examples=("access remove-expired office",),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        flags=("--yes",),
        tail="flags",
        risk="metadata",
        confirmation="yes_flag",
    ),
    _cmd(
        ("access", "assign"),
        "server",
        "Policy",
        "Assign a list to one client service (ALLOWLIST)",
        examples=("access assign 24cd7856 ssh office",),
        args=(
            _arg("<CLIENT-ID>", C_CLIENT),
            _arg("<SERVICE-ID>", C_CLIENT_SERVICE),
            _arg("<LIST>", C_ACCESS_LIST),
        ),
        tail="flags",
        risk="outage",
    ),
    _cmd(
        ("access", "public"),
        "server",
        "Policy",
        "Set one client service back to PUBLIC",
        detail="ALLOWLIST → PUBLIC widens who may reach the published port. "
        "Requires interactive confirmation or --yes for automation.",
        examples=(
            "access public 24cd7856 ssh",
            "access public 24cd7856 ssh --yes",
        ),
        args=(_arg("<CLIENT-ID>", C_CLIENT), _arg("<SERVICE-ID>", C_CLIENT_SERVICE)),
        flags=("--yes",),
        tail="flags",
        risk="security_widening",
        confirmation="yes_flag",
    ),
    _cmd(
        ("access", "show-service"),
        "server",
        "Policy",
        "Show the access policy for one service",
        examples=("access show-service 24cd7856 ssh",),
        args=(_arg("<CLIENT-ID>", C_CLIENT), _arg("<SERVICE-ID>", C_CLIENT_SERVICE)),
    ),
    _cmd(
        ("access", "test"),
        "server",
        "Policy",
        "Preview the decision for one source IP",
        examples=("access test 24cd7856 ssh 203.0.113.9",),
        args=(
            _arg("<CLIENT-ID>", C_CLIENT),
            _arg("<SERVICE-ID>", C_CLIENT_SERVICE),
            _arg("<SOURCE-IP>"),
        ),
    ),
    _cmd(
        ("access", "log"),
        "server",
        "Policy",
        "Show recent authorization decisions",
        examples=("access log 24cd7856 ssh --limit 20",),
        args=(_arg("<CLIENT-ID>", C_CLIENT), _arg("<SERVICE-ID>", C_CLIENT_SERVICE)),
        flags=("--limit", "--allow", "--deny"),
        tail="flags",
    ),
    _cmd(
        ("access", "menu"),
        "server",
        "Policy",
        "Guided Access Control menu",
        examples=("access menu",),
    ),
    # --- egress -----------------------------------------------------------
    _cmd(
        ("egress", "list"),
        "server",
        "Policy",
        "List Controlled Egress profiles",
        examples=("egress list",),
        internal=("show", "egress-profiles"),
        aliases=(("show", "egress-profiles"), ("egress-profile", "list")),
    ),
    _cmd(
        ("egress", "show"),
        "server",
        "Policy",
        "Show one egress profile",
        examples=("egress show vendor-api",),
        args=(_arg("<PROFILE>", C_EGRESS),),
        internal=("show", "egress-profile"),
        aliases=(("show", "egress-profile"), ("egress-profile", "show")),
    ),
    _cmd(
        ("egress", "create"),
        "server",
        "Policy",
        "Create a DISABLED egress profile",
        detail="A new profile is created disabled so an incomplete policy can "
        "never widen egress. Add sources and destinations first, then run "
        "'egress enable'.\n\n"
        "Safe workflow:\n"
        "  1. egress create <name>\n"
        "  2. egress add-source <name> <CIDR>\n"
        "  3. egress add-destination <name> <FQDN> <PORT> --protocol https\n"
        "  4. egress explain <SOURCE-IP> <FQDN> <PORT>\n"
        "  5. egress enable <name>",
        examples=('egress create vendor-api --description "Vendor API"',),
        args=(_arg("<name>"),),
        flags=("--description",),
        tail="flags",
        internal=("create", "egress-profile"),
        aliases=(("create", "egress-profile"), ("egress-profile", "create")),
    ),
    _cmd(
        ("egress", "set"),
        "server",
        "Policy",
        "Change egress profile metadata",
        detail="Canonical form sets one property at a time. Hidden "
        "compatibility flags --name / --description remain accepted.",
        examples=(
            "egress set vendor-api name partner-api",
            "egress set vendor-api description 'Partner API'",
        ),
        args=(
            _arg("<PROFILE>", C_EGRESS),
            _arg("name|description", ("name", "description")),
            _arg("<value>"),
        ),
        flags=(
            _flag("--name", arity=1, hidden=True),
            _flag("--description", arity=1, hidden=True),
        ),
        # Allow either property args or hidden --name/--description flags.
        tail="flags",
        internal=("set", "egress-profile"),
        aliases=(("set", "egress-profile"), ("egress-profile", "set")),
    ),
    _cmd(
        ("egress", "add-destination"),
        "server",
        "Policy",
        "Allow one destination FQDN, port, and protocol",
        detail="Require an explicit --protocol http|https|tcp. HTTP destinations "
        "accept absolute-form proxy requests only; HTTPS destinations require "
        "CONNECT plus ClientHello SNI binding on every https port; TCP "
        "destinations are exact-FQDN only and used by Fixed TCP Egress relays.",
        examples=(
            "egress add-destination vendor-api api.example.com 443 --protocol https",
            "egress add-destination vendor-api archive.example.com 80 --protocol http",
            "egress add-destination vendor-api license.example.com 27000 --protocol tcp",
        ),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<FQDN>"), _arg("<PORT>")),
        flags=(
            _flag(
                "--protocol",
                arity=1,
                choices=("http", "https", "tcp"),
                required=True,
                metavar="http|https|tcp",
                type="enum",
                description="Destination protocol (http|https|tcp)",
            ),
        ),
        tail="flags",
        aliases=(),
    ),
    _cmd(
        ("egress", "add-source"),
        "server",
        "Policy",
        "Allow one source CIDR",
        examples=(
            "egress add-source vendor-api 10.0.0.0/24",
            "egress add-source vendor-api 10.0.0.0/24 --name office",
        ),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<CIDR>")),
        flags=("--name",),
        tail="flags",
        risk="metadata",
    ),
    _cmd(
        ("egress", "remove-destination"),
        "server",
        "Policy",
        "Remove one destination",
        detail="When the profile is enabled, requires interactive confirmation "
        "or --yes. Disabled profiles mutate without that confirm.",
        examples=(
            "egress remove-destination vendor-api api.example.com:443",
            "egress remove-destination vendor-api api.example.com:443 --yes",
        ),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<SELECTOR>")),
        flags=("--yes",),
        tail="flags",
        aliases=(),
        destructive=True,
        risk="outage",
        confirmation="yes_flag",
    ),
    _cmd(
        ("egress", "remove-source"),
        "server",
        "Policy",
        "Remove one source",
        detail="When the profile is enabled, requires interactive confirmation "
        "or --yes. Disabled profiles mutate without that confirm.",
        examples=(
            "egress remove-source vendor-api 10.0.0.0/24",
            "egress remove-source vendor-api 10.0.0.0/24 --yes",
        ),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<SELECTOR>")),
        flags=("--yes",),
        tail="flags",
        destructive=True,
        risk="outage",
        confirmation="yes_flag",
    ),
    _cmd(
        ("egress", "enable"),
        "server",
        "Policy",
        "Enable an egress profile",
        detail="Enable only after the profile has both sources and "
        "destinations. Default policy stays DENY.",
        examples=("egress enable vendor-api",),
        args=(_arg("<PROFILE>", C_EGRESS),),
        internal=("enable", "egress-profile"),
        aliases=(("enable", "egress-profile"),),
        risk="security_widening",
    ),
    _cmd(
        ("egress", "disable"),
        "server",
        "Policy",
        "Disable an egress profile",
        examples=("egress disable vendor-api",),
        args=(_arg("<PROFILE>", C_EGRESS),),
        internal=("disable", "egress-profile"),
        aliases=(("disable", "egress-profile"),),
        risk="outage",
    ),
    _cmd(
        ("egress", "delete"),
        "server",
        "Policy",
        "Delete an egress profile",
        detail="When the profile is enabled, requires interactive confirmation "
        "or --yes. Disabled profiles delete without that confirm.",
        examples=("egress delete vendor-api", "egress delete vendor-api --yes"),
        args=(_arg("<PROFILE>", C_EGRESS),),
        flags=("--yes",),
        tail="flags",
        internal=("delete", "egress-profile"),
        aliases=(("delete", "egress-profile"),),
        destructive=True,
        risk="irreversible",
        confirmation="yes_flag",
    ),
    _cmd(
        ("egress", "status"),
        "server",
        "Policy",
        "Show Controlled Egress status",
        examples=("egress status",),
    ),
    _cmd(
        ("egress", "explain"),
        "server",
        "Policy",
        "Explain authorize(source, host, port) — policy + DNS only",
        detail="Dry-run against the live policy store and optional DNS "
        "resolution. It does not open a live TCP/TLS connection to the "
        "destination and does not mutate policy. Use this before 'egress enable'.",
        examples=(
            "egress explain 10.0.0.5 api.example.com 443",
            "egress explain 10.0.0.5 license.example.com 27000 --protocol tcp",
        ),
        args=(_arg("<SOURCE-IP>"), _arg("<HOST>"), _arg("<PORT>")),
        flags=(
            _flag(
                "--protocol",
                arity=1,
                choices=("http", "https", "tcp"),
                metavar="http|https|tcp",
                type="enum",
                description="Wire protocol for the explain probe",
            ),
        ),
        tail="flags",
    ),
    _cmd(
        ("egress", "test"),
        "server",
        "Policy",
        "Compat alias for egress explain",
        detail="Hidden compatibility alias for 'egress explain'. Prefer explain. "
        "Same dry-run: evaluates live policy and optional DNS; does not open a "
        "live connection and does not mutate policy.",
        examples=("egress test 10.0.0.5 api.example.com 443",),
        args=(_arg("<SOURCE-IP>"), _arg("<HOST>"), _arg("<PORT>")),
        flags=(
            _flag(
                "--protocol",
                arity=1,
                choices=("http", "https", "tcp"),
                metavar="http|https|tcp",
                type="enum",
                description="Wire protocol for the probe",
            ),
        ),
        tail="flags",
        hidden=True,
        surface="hidden_compat",
    ),
    _cmd(
        ("egress", "tcp", "list"),
        "server",
        "Policy",
        "List Fixed TCP Egress relays",
        examples=("egress tcp list",),
    ),
    _cmd(
        ("egress", "tcp", "show"),
        "server",
        "Policy",
        "Show one Fixed TCP Egress relay",
        examples=("egress tcp show vendor-license",),
        args=(_arg("<RELAY>"),),
    ),
    _cmd(
        ("egress", "tcp", "create"),
        "server",
        "Policy",
        "Create a DISABLED Fixed TCP Egress relay",
        detail="Always created disabled. Destination must be protocol=tcp with exact FQDN. "
        "Listen ports auto-allocate from 6200-6299 unless --listen-port is set.",
        examples=(
            "egress tcp create vendor-license --profile vendor-api --destination license.example.com:27000",
        ),
        args=(_arg("<NAME>"),),
        flags=(
            _flag("--profile", arity=1, required=True, metavar="PROFILE"),
            _flag("--destination", arity=1, required=True, metavar="DEST"),
            _flag("--listen-port", arity=1, metavar="N"),
            _flag("--listen-addr", arity=1, metavar="A"),
        ),
        tail="flags",
        risk="security_widening",
    ),
    _cmd(
        ("egress", "tcp", "enable"),
        "server",
        "Policy",
        "Enable a Fixed TCP Egress relay",
        examples=("egress tcp enable vendor-license",),
        args=(_arg("<RELAY>"),),
        risk="security_widening",
    ),
    _cmd(
        ("egress", "tcp", "disable"),
        "server",
        "Policy",
        "Disable a Fixed TCP Egress relay",
        examples=("egress tcp disable vendor-license",),
        args=(_arg("<RELAY>"),),
        risk="security_widening",
    ),
    _cmd(
        ("egress", "tcp", "delete"),
        "server",
        "Policy",
        "Delete a Fixed TCP Egress relay",
        examples=("egress tcp delete vendor-license", "egress tcp delete vendor-license --yes"),
        args=(_arg("<RELAY>"),),
        flags=(_flag("--yes", arity=0),),
        tail="flags",
        risk="security_widening",
        destructive=True,
        confirmation="y_n",
    ),
    _cmd(
        ("egress", "tcp", "explain"),
        "server",
        "Policy",
        "Explain Fixed TCP Egress authorize for a source IP",
        examples=("egress tcp explain vendor-license 10.0.0.5",),
        args=(_arg("<RELAY>"), _arg("<SOURCE-IP>")),
    ),
    _cmd(
        ("egress", "recipe", "list"),
        "server",
        "Policy",
        "List egress recipe templates",
        examples=("egress recipe list",),
    ),
    _cmd(
        ("egress", "recipe", "show"),
        "server",
        "Policy",
        "Show one egress recipe template",
        examples=("egress recipe show tcp-fixed",),
        args=(_arg("<RECIPE>"),),
    ),
    _cmd(
        ("egress", "recipe", "apply"),
        "server",
        "Policy",
        "Apply an egress recipe (always DISABLED; never auto-enable)",
        examples=(
            "egress recipe apply https-api --name vendor-api --source 10.0.0.0/24",
            "egress recipe apply tcp-fixed --name vendor-license --source 10.0.0.0/24",
        ),
        args=(_arg("<RECIPE>"),),
        flags=(
            _flag("--name", arity=1, metavar="NAME"),
            _flag("--source", arity=1, metavar="CIDR"),
        ),
        tail="flags",
        risk="security_widening",
    ),
    _cmd(
        ("egress", "export"),
        "server",
        "Policy",
        "Export one egress profile to JSON",
        detail="Portable profile document for review/vendor updates. Import never auto-enables.",
        examples=("egress export vendor-api --output /tmp/vendor.json",),
        args=(_arg("<PROFILE>", C_EGRESS),),
        flags=(_flag("--output", arity=1),),
        tail="flags",
    ),
    _cmd(
        ("egress", "import"),
        "server",
        "Policy",
        "Import profile JSON (always DISABLED; never auto-enable)",
        detail="Validate schema/protocol/PSL/duplicates, show diff, leave profile disabled for explicit egress enable.",
        examples=(
            "egress import /tmp/vendor.json",
            "egress import /tmp/vendor.json vendor-api",
        ),
        args=(_arg("<FILE>", C_PATH), _arg("<PROFILE>", C_EGRESS, required=False)),
        tail="flags",
    ),
    _cmd(
        ("egress", "diff"),
        "server",
        "Policy",
        "Diff a profile against an import candidate file",
        detail="Compare live profile to a candidate without applying changes.",
        examples=("egress diff vendor-api /tmp/vendor.json",),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<FILE>", C_PATH)),
    ),
    # --- server -----------------------------------------------------------
    _cmd(
        ("server", "status"),
        "server",
        "Server",
        "Show server status",
        examples=("server status",),
        internal=("server-status",),
        aliases=(("server-status",),),
    ),
    _cmd(
        ("server", "set"),
        "server",
        "Server",
        "Change a server setting",
        detail="public-hostname is the optional DNS alias used for published "
        "service access. FRP control keeps using the Public IP.\n"
        "bootstrap-hostname is the optional publicly trusted Zero-Touch short "
        "URL hostname. Data Relay Link never creates DNS records or issues "
        "certificates.\n"
        "Client installer URLs use: set installer-url / set windows-installer-url.",
        examples=(
            "server set public-hostname frp.example.com",
            "server set bootstrap-hostname bootstrap.example.com",
        ),
        args=(
            _arg("public-hostname|bootstrap-hostname", SERVER_SETTINGS),
            _arg("<value>"),
        ),
        aliases=(("set", "server"),),
    ),
    # Dedicated installer URL commands (must not be aliases of set server:
    # alias expansion would drop the setting name and treat the URL as a
    # server setting key).
    _cmd(
        ("set", "installer-url"),
        "server",
        "Server",
        "Set the Linux client installer URL",
        detail="installer-url is the client installer URL handed to new Linux clients.",
        examples=("set installer-url https://example.com/install-client.sh",),
        args=(_arg("<url>"),),
        internal=("set", "installer-url"),
        aliases=(("server", "set", "installer-url"),),
    ),
    _cmd(
        ("set", "windows-installer-url"),
        "server",
        "Server",
        "Set the Windows client installer URL",
        detail="windows-installer-url is handed to new Windows clients.",
        examples=("set windows-installer-url https://example.com/install-client.ps1",),
        args=(_arg("<url>"),),
        internal=("set", "windows-installer-url"),
    ),
    _cmd(
        ("server", "unset"),
        "server",
        "Server",
        "Remove a server setting",
        detail="Unsetting public-hostname falls back to Public IP access. "
        "Unsetting bootstrap-hostname falls back to zt1 Zero-Touch commands.",
        examples=("server unset public-hostname",),
        args=(_arg("public-hostname|bootstrap-hostname", SERVER_SETTINGS),),
        aliases=(("unset", "server"),),
    ),
    _cmd(
        ("server", "upstream"),
        "server",
        "Server",
        "Check the upstream FRP release feed",
        examples=("server upstream",),
        internal=("show", "upstream"),
        tail="flags",
        aliases=(("show", "upstream"), ("upstream",)),
    ),
    _cmd(
        ("server", "audit"),
        "server",
        "Server",
        "Show recent audit events",
        examples=("server audit",),
        internal=("show", "audit"),
        aliases=(("show", "audit"), ("audit",)),
    ),
    # --- backup -----------------------------------------------------------
    _cmd(
        ("backup", "create"),
        "server",
        "Maintenance",
        "Create a server backup",
        examples=("backup create", "backup create /var/lib/drlink/backups/b.tar.gz"),
        args=(_arg("<path>", C_PATH, required=False),),
        tail="flags",
        internal=("create", "backup"),
        aliases=(("create", "backup"),),
    ),
    _cmd(
        ("backup", "restore"),
        "server",
        "Maintenance",
        "Restore from a backup archive",
        detail="Keeps archive validation, snapshot, restart, doctor, and "
        "rollback behavior.",
        examples=("backup restore /var/lib/drlink/backups/b.tar.gz",),
        args=(_arg("<path>", C_PATH),),
        tail="flags",
        internal=("restore", "backup"),
        aliases=(("restore", "backup"), ("restore",)),
        destructive=True,
    ),
    # --- update -----------------------------------------------------------
    _cmd(
        ("update", "project"),
        "any",
        "Maintenance",
        "Update the Data Relay Link management tools",
        detail="A software update does not re-enroll clients and does not "
        "rotate the CA, token, or ports.",
        examples=("update project", "update project --check"),
        flags=("--check",),
        tail="flags",
        internal=("update", "project"),
        aliases=(("project-update",), ("client-update",)),
    ),
    _cmd(
        ("update", "engine"),
        "any",
        "Maintenance",
        "Update the upstream FRP engine binary",
        detail="Updates the official upstream FRP binary (frps / frpc). This "
        "project does not fork FRP.",
        examples=("update engine", "update engine --check"),
        flags=("--check",),
        tail="flags",
        internal=("update", "frp"),
        aliases=(("update", "frp"), ("frp-update",), ("server-update",)),
    ),
    # --- doctor / support -------------------------------------------------
    _cmd(
        ("doctor",),
        "any",
        "Maintenance",
        "Run read-only health checks",
        examples=("doctor", "doctor --json"),
        flags=("--json", "--verbose", "--quiet"),
        tail="flags",
    ),
    _cmd(
        ("support", "bundle"),
        "any",
        "Maintenance",
        "Create a sanitized diagnostic archive",
        detail="Read-only. Private keys, tokens, enrollment secrets, and auth "
        "material are omitted or redacted. Services are not restarted.",
        examples=("support bundle", "support bundle --output /tmp/b.tar.gz"),
        flags=("--output",),
        tail="flags",
        internal=("support-bundle",),
        aliases=(("support-bundle",),),
    ),
    # --- session ----------------------------------------------------------
    _cmd(
        ("help",),
        "any",
        "Session",
        "Detailed help",
        examples=("help", "help client", "help workflows"),
        tail="any",
    ),
    _cmd(
        ("menu",),
        "any",
        "Session",
        "Guided numbered menu",
        examples=("menu",),
    ),
    _cmd(
        ("history",),
        "any",
        "Session",
        "Session command history (never written to disk)",
        examples=("history",),
    ),
    _cmd(
        ("clear",),
        "any",
        "Session",
        "Clear the screen",
        examples=("clear",),
    ),
    _cmd(
        ("exit",),
        "any",
        "Session",
        "Leave the CLI",
        examples=("exit",),
    ),
)



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
                surface=row.get("surface")
                or ("hidden_compat" if row.get("hidden") else ""),
            )
        )
    return tuple(out)


COMMANDS = _load_final_commands()
PUBLIC_COMMANDS = tuple(cmd for cmd in COMMANDS if not cmd.get("hidden"))
HIDDEN_COMPAT_ALIASES = {
    tuple(alias): cmd["path"]
    for cmd in COMMANDS
    for alias in (cmd.get("aliases") or ())
}

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
    for name, roles, _category, summary in ROOTS:
        if name not in allowed:
            continue
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

    if path == ("set", "fixed-tcp"):
        if not rest:
            return ["set", "fixed-tcp"]
        if len(rest) >= 2 and rest[1] == "enabled":
            return ["egress", "tcp", "enable", rest[0]] + rest[2:]
        # Name-only create is handled as a guided product action.
        return ["egress", "tcp", "create"] + rest

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

    if path == ("unset", "fixed-tcp"):
        if len(rest) >= 2 and rest[1] == "enabled":
            return ["egress", "tcp", "disable", rest[0]] + rest[2:]
        return ["egress", "tcp", "delete"] + rest

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
    if path == ("show", "fixed-tcp"):
        if rest:
            return ["egress", "tcp", "show"] + rest
        return ["egress", "tcp", "list"]

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
    if path == ("system", "server-status"):
        # Top-level server-status action (detailed server host view).
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
        return ["doctor"] + rest
    if path == ("system", "support-bundle"):
        # Direct dispatcher action (not create support-bundle).
        if rest:
            return ["support-bundle", "--output", rest[0]] + list(rest[1:])
        return ["support-bundle"]
    if path == ("system", "audit"):
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
    """Expand a hidden resource-first alias into canonical action-first tokens.

    Returns ``None`` when ``tokens`` is not a known compatibility alias.
    """
    if not tokens:
        return None
    best = None
    best_len = 0
    for alias, cmd in ALIASES.items():
        n = len(alias)
        if n > best_len and n <= len(tokens) and tuple(tokens[:n]) == alias:
            # Only treat non-canonical (hidden) aliases here.
            if tuple(alias) == tuple(cmd["path"]):
                continue
            best = (alias, cmd)
            best_len = n
    if best is None:
        return None
    alias, cmd = best
    rest = list(tokens[best_len:])
    rewrite = REWRITES.get(tuple(alias))
    if rewrite is not None:
        return rewrite(rest)
    return list(cmd["path"]) + rest


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
        lines.extend(
            [
                "Help topics:",
                "  help clients",
                "  help services",
                "  help internet",
                "  help system",
                "  help commands",
                "  help workflows",
                "  help legacy",
                "",
                "Relay Engine (FRP) is the upstream tunnel engine.",
                "This project does not fork FRP.",
                "",
            ]
        )
    return "\n".join(lines)


def domain_help(topic, role):
    """Conceptual help for product domains (clients/services/internet/system)."""
    topic = str(topic or "").strip().lower()
    client, server = role_parts(role)
    if topic in ("client", "clients"):
        if not server:
            return "Clients help is available on a Data Relay Link server.\n"
        return (
            "Clients\n"
            "=======\n\n"
            "Clients are enrolled machines managed by this server.\n\n"
            "Guided path:\n"
            "  menu → Clients\n\n"
            "  1) Connect a new client   (set client)\n"
            "  2) List clients          (show clients)\n"
            "  3) View or manage a client\n"
            "  4) Groups\n"
            "  5) Enrollments\n\n"
            "Everyday commands:\n"
            "  show clients\n"
            "  show client <CLIENT-ID>\n"
            "  set client\n"
            "  set client <CLIENT-ID> label <value>\n"
            "  unset client <CLIENT-ID> trust\n"
            "  unset client <CLIENT-ID> service <SERVICE-ID>\n"
            "  unset client <CLIENT-ID>\n\n"
            "CLIENT ID is the immutable selector. Labels and hostnames are\n"
            "convenient display shortcuts when unique.\n"
        )
    if topic in ("service", "services"):
        if server:
            return (
                "Services\n"
                "========\n\n"
                "Published SSH / HTTP / HTTPS / TCP services and who may reach them.\n\n"
                "Guided path:\n"
                "  menu → Services\n\n"
                "  List published services\n"
                "  View a client's services\n"
                "  Access Rules (source-IP controls)\n"
                "  Service Profiles (reusable templates)\n"
                "  Release a published service\n\n"
                "Service definitions are changed on the client.\n"
                "Use drlink on that client to add or edit services.\n\n"
                "Everyday commands:\n"
                "  show services\n"
                "  show client <CLIENT-ID> services\n"
                "  set access-rule <NAME>\n"
                "  set service-profile <NAME>\n"
                "  unset client <CLIENT-ID> service <SERVICE-ID>\n"
            )
        if client:
            return (
                "Services\n"
                "========\n\n"
                "Configure services published from this machine.\n\n"
                "Guided path:\n"
                "  menu → Services\n\n"
                "Everyday commands:\n"
                "  show services\n"
                "  add service\n"
                "  set service <ID> ...\n"
                "  enable service <ID>\n"
                "  disable service <ID>\n"
                "  apply\n"
                "  discard\n"
                "  sync\n"
            )
        return "Services help requires an installed Data Relay Link role.\n"
    if topic in ("internet", "egress", "internet-access"):
        if not server:
            return "Internet Access help is available on a Data Relay Link server.\n"
        return (
            "Internet Access\n"
            "===============\n\n"
            "Allow clients to reach approved Internet destinations.\n"
            "Everything else remains denied by default.\n\n"
            "This is the beginner-facing navigation name for the product's\n"
            "Controlled Egress capability.\n\n"
            "Guided path:\n"
            "  menu → Internet Access\n\n"
            "  Overview\n"
            "  Access Profiles\n"
            "  Fixed TCP\n"
            "  Templates\n"
            "  Check policy   (policy + DNS; not a live connection test)\n\n"
            "Everyday commands:\n"
            "  show internet\n"
            "  show internet-profiles\n"
            "  set internet-profile <NAME>\n"
            "  set internet-source <NAME> <CIDR>\n"
            "  set internet-destination <NAME> <FQDN> <PORT> <PROTOCOL>\n"
            "  test internet\n"
            "  show fixed-tcp\n"
            "  show internet-templates\n"
        )
    if topic in ("system", "operate"):
        lines = [
            "System",
            "======",
            "",
            "Operate Data Relay Link itself: status, settings, backup,",
            "updates, and diagnostics.",
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
                    "  system restore <PATH>",
                    "  system audit",
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
    lines.append("Compatibility aliases: help legacy")
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
        "Onboard a new client",
        (
            "set client",
            "show clients",
            "show client <CLIENT-ID>",
        ),
        "Zero-Touch via set client is the recommended path. Use 'set enrollment' "
        "only when an interactive install is required.",
    ),
    (
        "Publish and reach a remote service",
        (
            "set service",
            "apply",
            "show client <CLIENT-ID> services",
        ),
        "Public ports are assigned by the server at apply time and stay "
        "reserved until 'unset client … service …' / 'unset client …'.",
    ),
    (
        "Restrict who may reach a service",
        (
            "set access-rule office",
            "set access-source office 203.0.113.0/24",
            "set service-access <CLIENT-ID> <SERVICE-ID> office",
            "test access <CLIENT-ID> <SERVICE-ID> 203.0.113.9",
        ),
        "Services are PUBLIC until an Access Rule is assigned.",
    ),
    (
        "Allow one outbound destination",
        (
            "set internet-profile vendor-api",
            "set internet-source vendor-api 10.0.0.0/24",
            "set internet-destination vendor-api api.example.com 443 https",
            "set internet-profile vendor-api enabled",
        ),
        "A new Internet Access profile is created disabled. Default policy is DENY.",
    ),
    (
        "Routine maintenance",
        (
            "system diagnostics",
            "system backup",
            "system update product",
            "system support-bundle",
        ),
        "'system update engine' updates the upstream Relay Engine (FRP) binary separately. "
        "Use 'system update check-engine' to check upstream releases.",
    ),
)


def workflow_help(role):
    _client, server = role_parts(role)
    lines = ["Common workflows", "================", ""]
    for title, steps, note in WORKFLOWS:
        if not server and title in (
            "Onboard a new client",
            "Restrict who may reach a service",
            "Allow one outbound destination",
        ):
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
    lines = [
        "Legacy compatibility commands",
        "=============================",
        "",
        "These forms are accepted only for backward compatibility.",
        "",
        "Do not use them for new interactive operation, documentation, or scripts.",
        "",
        "Use:",
        "  help commands",
        "",
        "for the current Data Relay Link command grammar.",
        "",
    ]
    rows = []
    seen = set()
    for cmd in COMMANDS:
        if not role_allows(cmd["roles"], role):
            continue
        for alias in cmd["aliases"]:
            text_alias = " ".join(alias)
            if text_alias in seen:
                continue
            seen.add(text_alias)
            rows.append((text_alias, " ".join(cmd["path"])))
    lines.extend(_fmt_rows(rows))
    lines.extend(
        [
            "",
            "Also accepted: client-status, manage, revoke <ID>, restore <PATH>.",
            "",
        ]
    )
    return "\n".join(lines)


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
    "client": (
        (
            "client_services",
            "Services",
            "Configure services published from this machine",
            "submenu",
            "client.services",
        ),
        (
            "client_system",
            "System",
            "Status, connection information, updates and diagnostics",
            "submenu",
            "client.system",
        ),
        ("client_help", "Help", "", "help", None),
        ("exit", "Exit", "", "exit", None),
    ),
    "client.services": (
        ("client_svc_list", "List services", "", "command", "show services"),
        ("client_svc_add", "Add service", "", "command", "set service"),
        ("client_svc_edit", "Edit service", "", "workflow", "edit_service"),
        ("client_svc_enable", "Enable service", "", "workflow", "enable_service"),
        ("client_svc_disable", "Disable service", "", "workflow", "disable_service"),
        ("client_svc_apply", "Apply pending changes", "", "command", "system services apply"),
        ("client_svc_discard", "Discard pending changes", "", "command", "system services discard"),
        ("client_svc_sync", "Sync with server", "", "command", "system services sync"),
        ("back", "Back", "", "back", None),
    ),
    "client.system": (
        ("client_sys_status", "Status", "", "command", "show status"),
        ("client_sys_info", "Connection information", "", "command", "system info"),
        ("client_sys_pause", "Pause client", "", "command", "system pause"),
        ("client_sys_resume", "Resume client", "", "command", "system resume"),
        ("client_sys_restart", "Restart client", "", "command", "system restart"),
        ("client_sys_autostart", "Autostart", "", "command", "system autostart"),
        ("client_sys_update_product", "Update Data Relay Link", "", "command", "system update product"),
        ("client_sys_update_engine", "Update Relay Engine (FRP)", "", "command", "system update engine"),
        ("client_sys_doctor", "Diagnostics", "", "command", "system diagnostics"),
        ("client_sys_support", "Support Bundle", "", "command", "system support-bundle"),
        ("client_sys_version", "Version Information", "", "command", "system version"),
        ("client_sys_uninstall", "Uninstall Data Relay Link", "", "command", "system uninstall"),
        ("back", "Back", "", "back", None),
    ),
    "server": (
        (
            "server_clients",
            "Clients",
            "Connect and manage client machines",
            "submenu",
            "server.clients",
        ),
        (
            "server_services",
            "Services",
            "View published services and control who can reach them",
            "submenu",
            "server.services",
        ),
        (
            "server_internet",
            "Internet Access",
            "Allow clients to reach approved Internet destinations",
            "submenu",
            "server.internet",
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
    "server.clients": (
        ("server_zt", "Connect a new client", "", "workflow", "create_zero_touch"),
        ("server_clients_list", "List clients", "", "command", "show clients"),
        ("server_clients_manage", "View or manage a client", "", "workflow", "manage_client"),
        ("server_groups", "Groups", "", "submenu", "server.clients.groups"),
        ("server_enrollments", "Enrollments", "", "submenu", "server.clients.enrollments"),
        ("back", "Back", "", "back", None),
    ),
    "server.clients.groups": (
        ("server_groups_list", "List groups", "", "command", "show groups"),
        ("server_groups_create", "Create group", "", "workflow", "create_group"),
        ("server_groups_manage", "View or manage a group", "", "workflow", "manage_group"),
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
        (
            "server_svc_list",
            "List published services",
            "View services currently exposed through Data Relay Link",
            "command",
            "show services",
        ),
        (
            "server_svc_client",
            "View a client's services",
            "See published services for a selected client",
            "workflow",
            "client_services",
        ),
        (
            "server_access",
            "ACLs",
            "Control which IP addresses or networks may reach published services",
            "submenu",
            "server.services.access",
        ),
        (
            "server_profiles",
            "Service Profiles",
            "Reusable templates for configuring services",
            "submenu",
            "server.services.profiles",
        ),
        (
            "server_svc_release",
            "Release a published service",
            "Remove its reservation and return the public port",
            "workflow",
            "release_service",
        ),
        ("back", "Back", "", "back", None),
    ),
    "server.services.access": (
        ("server_access_list", "List ACLs", "", "command", "show acls"),
        ("server_access_create", "Create ACL", "", "workflow", "create_access_list"),
        ("server_access_edit", "View or manage ACL", "", "workflow", "manage_access_list"),
        ("server_access_assign", "Assign ACL to a service", "", "workflow", "assign_access"),
        ("server_access_public", "Set published service to public", "", "workflow", "public_access"),
        ("server_access_check", "Check access for a source IP", "", "workflow", "test_access"),
        ("server_access_log", "Recent access decisions", "", "workflow", "show_access_log"),
        ("back", "Back", "", "back", None),
    ),
    "server.services.profiles": (
        ("server_prof_list", "List profiles", "", "command", "show service-profiles"),
        ("server_prof_create", "Create profile", "", "workflow", "create_service_profile"),
        ("server_prof_edit", "View or manage profile", "", "workflow", "manage_service_profile"),
        ("server_prof_delete", "Delete profile", "", "workflow", "delete_service_profile"),
        ("back", "Back", "", "back", None),
    ),
    "server.internet": (
        ("server_egress_overview", "Overview", "", "command", "show internet"),
        (
            "server_egress_profiles",
            "Access Profiles",
            "Define which sources may reach approved Internet destinations",
            "submenu",
            "server.internet.profiles",
        ),
        (
            "server_egress_tcp",
            "Fixed TCP",
            "Allow approved TCP connections for apps that cannot use HTTP/HTTPS proxy",
            "submenu",
            "server.internet.tcp",
        ),
        (
            "server_egress_templates",
            "Templates",
            "Start from predefined Internet Access configurations",
            "submenu",
            "server.internet.templates",
        ),
        (
            "server_egress_check",
            "Check policy",
            "Check whether a connection would be allowed",
            "workflow",
            "explain_egress",
        ),
        ("back", "Back", "", "back", None),
    ),
    "server.internet.profiles": (
        ("server_egp_list", "List profiles", "", "command", "show internet-profiles"),
        ("server_egp_create", "Create profile", "", "workflow", "create_egress_profile"),
        ("server_egp_manage", "View or manage profile", "", "workflow", "manage_egress_profile"),
        ("server_egp_import", "Import profile", "", "workflow", "import_egress"),
        ("server_egp_diff", "Compare with import file", "", "workflow", "diff_egress"),
        ("back", "Back", "", "back", None),
    ),
    "server.internet.tcp": (
        ("server_egt_list", "List Fixed TCP entries", "", "command", "show fixed-tcp"),
        ("server_egt_create", "Create Fixed TCP entry", "", "workflow", "create_egress_tcp"),
        ("server_egt_manage", "View or manage an entry", "", "workflow", "manage_egress_tcp"),
        ("back", "Back", "", "back", None),
    ),
    "server.internet.templates": (
        ("server_egr_list", "List templates", "", "command", "show internet-templates"),
        ("server_egr_view", "View template", "", "workflow", "view_egress_recipe"),
        ("server_egr_create", "Create configuration from template", "", "workflow", "apply_egress_recipe"),
        ("back", "Back", "", "back", None),
    ),
    "server.system": (
        ("server_sys_status", "Status", "", "command", "show status"),
        ("server_sys_settings", "Server Settings", "", "submenu", "server.system.settings"),
        ("server_sys_backup", "Backup & Restore", "", "submenu", "server.system.backup"),
        ("server_sys_updates", "Updates", "", "submenu", "server.system.updates"),
        ("server_sys_diag", "Diagnostics", "", "submenu", "server.system.diagnostics"),
        ("server_sys_audit", "Audit Log", "", "command", "system audit"),
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
        "both_clients",
        "Clients",
        "Connect and manage client machines",
        "submenu",
        "server.clients",
    ),
    (
        "both_services",
        "Services",
        "View published services and control who can reach them",
        "submenu",
        "both.services",
    ),
    (
        "both_internet",
        "Internet Access",
        "Allow clients to reach approved Internet destinations",
        "submenu",
        "server.internet",
    ),
    (
        "both_system",
        "System",
        "Status, settings, backup, updates, client lifecycle and diagnostics",
        "submenu",
        "both.system",
    ),
    ("both_help", "Help", "", "help", None),
    ("exit", "Exit", "", "exit", None),
)
NAVIGATION_TREE["both.system"] = (
    ("both_sys_status", "Status", "", "command", "show status"),
    ("both_sys_settings", "Server Settings", "", "submenu", "server.system.settings"),
    ("both_sys_backup", "Backup & Restore", "", "submenu", "server.system.backup"),
    ("both_sys_pause", "Pause client", "", "command", "system pause"),
    ("both_sys_resume", "Resume client", "", "command", "system resume"),
    ("both_sys_restart", "Restart client", "", "command", "system restart"),
    ("both_sys_autostart", "Client autostart", "", "command", "system autostart"),
    ("both_sys_updates", "Updates", "", "submenu", "server.system.updates"),
    ("both_sys_diag", "Diagnostics", "", "submenu", "server.system.diagnostics"),
    ("both_sys_audit", "Audit Log", "", "command", "system audit"),
    ("both_sys_version", "Version Information", "", "command", "system version"),
    ("both_sys_uninstall", "Uninstall Data Relay Link", "", "command", "system uninstall"),
    ("back", "Back", "", "back", None),
)
NAVIGATION_TREE["both.services"] = (
    ("both_svc_published", "Published services", "", "command", "show services"),
    (
        "both_svc_local",
        "Local services on this machine",
        "",
        "submenu",
        "client.services",
    ),
    (
        "server_svc_client",
        "View a client's services",
        "See published services for a selected client",
        "workflow",
        "client_services",
    ),
    (
        "server_access",
        "ACLs",
        "Control which IP addresses or networks may reach published services",
        "submenu",
        "server.services.access",
    ),
    (
        "server_profiles",
        "Service Profiles",
        "Reusable templates for configuring services",
        "submenu",
        "server.services.profiles",
    ),
    (
        "server_svc_release",
        "Release a published service",
        "Remove its reservation and return the public port",
        "workflow",
        "release_service",
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
        "Clients",
        (
            "clients",
            "client",
            "groups",
            "group",
            "enrollments",
            "enrollment",
        ),
    ),
    (
        "Services",
        (
            "services",
            "service",
            "service-profiles",
            "service-profile",
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
        "Internet Access",
        (
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
