#!/usr/bin/env python3
"""Canonical Data Relay Link CLI command catalog (CLI-011).

Single source of truth for the resource-first ``drlink`` grammar:

    drlink <resource|domain> <action> [target] [options]

Root help, ``help <topic>``, context ``?``, Tab discovery, and the guided
menu are all derived from :data:`COMMANDS`. Nothing else may hard-code the
canonical command list.

Every canonical entry also records how it rewrites into the older verb-first
token sequence (``internal``). The older verb-first commands keep working as
hidden compatibility aliases; they are simply not advertised.
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
SERVER_SETTINGS = ("public-hostname", "bootstrap-hostname", "installer-url")
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

ENROLL_FLAGS = (
    "--one-line",
    "--ssh",
    "--ssh-user",
    "--ssh-port",
    "--ttl",
    "--note",
    "--label",
    "--client-name",
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

# --- root resources -------------------------------------------------------
# (name, roles, category, summary)
# Categories are display-only groupings for help/menu discoverability.
ROOTS = (
    ("status", "any", "Operate", "Host status"),
    ("version", "any", "Session", "Installed versions"),
    ("zero-touch", "server", "Remote Access — Outside → Inside", "Connect a new machine (Zero-Touch)"),
    ("enrollment", "server", "Remote Access — Outside → Inside", "Enrollment credentials"),
    ("client", "any", "Remote Access — Outside → Inside", "Registered clients and local client info"),
    ("service", "any", "Remote Access — Outside → Inside", "Published services (local or global)"),
    ("access", "server", "Remote Access — Outside → Inside", "Restrict who can reach published services"),
    ("egress", "server", "Controlled Egress — Inside → Internet", "Allow internal hosts to reach specific Internet destinations"),
    ("group", "server", "Organize", "Client groups"),
    ("service-profile", "server", "Organize", "Reusable service creation templates"),
    ("server", "server", "Operate", "Server settings and server-side views"),
    ("backup", "server", "Operate", "Backup and restore"),
    ("update", "any", "Operate", "Update project tools or the FRP engine"),
    ("doctor", "any", "Operate", "Run health checks"),
    ("support", "any", "Operate", "Sanitized diagnostic archive"),
    ("help", "any", "Session", "Detailed help"),
    ("menu", "any", "Session", "Guided numbered menu"),
    ("history", "any", "Session", "Session command history"),
    ("clear", "any", "Session", "Clear the screen"),
    ("exit", "any", "Session", "Leave the CLI"),
)

CATEGORY_ORDER = (
    "Remote Access — Outside → Inside",
    "Controlled Egress — Inside → Internet",
    "Organize",
    "Operate",
    "Session",
)


def _arg(name, complete=C_NONE, required=True):
    return {"name": name, "complete": complete, "required": bool(required)}


# Lightweight operator risk / confirmation vocabulary (not a policy engine).
RISK_LEVELS = frozenset(
    {"none", "metadata", "outage", "irreversible", "security_widening"}
)
CONFIRMATION_MODES = frozenset({"none", "y_n", "typed_token", "yes_flag"})

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
):
    """Describe one option flag.

    ``arity`` is ``0`` for boolean switches (no value) and ``1`` for flags that
    consume the next token as a value (AUDIT-014).
    """
    risk_text = str(risk or "")
    if risk_text and risk_text not in RISK_LEVELS:
        raise ValueError("unknown flag risk: %s" % risk_text)
    return {
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
                description=meta.get("description", ""),
                metavar=meta.get("metavar", ""),
                examples=meta.get("examples", ()),
                effect=meta.get("effect", ""),
                risk=meta.get("risk", ""),
            )
        )
    return tuple(out)


# Boolean switches historically listed as bare strings in flag tuples.
_BOOLEAN_FLAG_NAMES = frozenset(
    {
        "--one-line",
        "--ssh",
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
        "description": "Temporary entry lifetime",
        "metavar": "30m|1h|4h|1d",
        "examples": ("4h", "1d"),
        "effect": "Entry expires automatically after the TTL",
        "risk": "metadata",
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
        "metavar": "http|https",
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


COMMANDS = (
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
        detail="Project version, release channel, source ref, FRP version, "
        "and the installed bundle checksum.",
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
        examples=("enrollment list",),
        internal=("show", "enrollments"),
        aliases=(("show", "enrollments"), ("enrollments",)),
    ),
    _cmd(
        ("enrollment", "create"),
        "server",
        "Onboarding",
        "Create one Manual Enrollment Code",
        detail="Generates a Manual Enrollment Code for an interactive client "
        "install. For everyday onboarding prefer 'zero-touch create'.",
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
        examples=("enrollment revoke 0011223344556677",),
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
        "column. Label and hostname are display metadata.",
        examples=("client list", "client list --group edge"),
        flags=("--group",),
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
            "Not the same as 'client release', 'client unset', disable, or "
            "uninstall. This does not delete the remote host or local software."
        ),
        examples=("client revoke 24cd7856", "client revoke 24cd7856 --force"),
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
        "ports are unchanged.",
        examples=("group delete edge",),
        args=(_arg("<GROUP>", C_GROUP),),
        internal=("delete", "group"),
        aliases=(("delete", "group"),),
        destructive=True,
    ),
    _cmd(
        ("group", "add-client"),
        "server",
        "Inventory",
        "Add a client to a group",
        examples=("group add-client edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
        aliases=(("add", "client"),),
    ),
    _cmd(
        ("group", "remove-client"),
        "server",
        "Inventory",
        "Remove a client from a group",
        examples=("group remove-client edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
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
    ),
    _cmd(
        ("group", "remove-member"),
        "server",
        "Inventory",
        "Remove a client from a group (compatibility alias for 'group remove-client')",
        examples=("group remove-member edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
        hidden=True,
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
        aliases=(("show", "profiles"), ("show", "profile"), ("profile", "list")),
    ),
    _cmd(
        ("service-profile", "show"),
        "server",
        "Templates",
        "Show one service profile",
        examples=("service-profile show office-ssh",),
        args=(_arg("<PROFILE>", C_PROFILE),),
        internal=("show", "profile"),
        aliases=(("profile", "show"),),
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
        "  4. egress test <SOURCE-IP> <FQDN> <PORT>\n"
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
        detail="Require an explicit --protocol http|https. HTTP destinations "
        "accept absolute-form proxy requests only; HTTPS destinations require "
        "CONNECT plus ClientHello SNI binding on every https port.",
        examples=(
            "egress add-destination vendor-api api.example.com 443 --protocol https",
            "egress add-destination vendor-api archive.example.com 80 --protocol http",
        ),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<FQDN>"), _arg("<PORT>")),
        flags=(_flag("--protocol", arity=1, choices=("http", "https"), required=True),),
        tail="flags",
        aliases=(("add", "egress-profile"),),
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
        aliases=(("remove", "egress-profile"),),
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
        ("egress", "test"),
        "server",
        "Policy",
        "Preview authorize(source, host, port) — policy + DNS only",
        detail="Dry-run against the live policy store and optional DNS "
        "resolution. It does not open a live TCP/TLS connection to the "
        "destination. Use this before 'egress enable'.",
        examples=("egress test 10.0.0.5 api.example.com 443",),
        args=(_arg("<SOURCE-IP>"), _arg("<HOST>"), _arg("<PORT>")),
        flags=(_flag("--protocol", arity=1, choices=("http", "https")),),
        tail="flags",
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
        "installer-url is the client installer URL handed to new clients.",
        examples=(
            "server set public-hostname frp.example.com",
            "server set bootstrap-hostname bootstrap.example.com",
            "server set installer-url https://example.com/install-client.sh",
        ),
        args=(
            _arg("public-hostname|bootstrap-hostname|installer-url", SERVER_SETTINGS),
            _arg("<value>"),
        ),
        aliases=(("set", "server"), ("set", "installer-url")),
    ),
    _cmd(
        ("server", "unset"),
        "server",
        "Server",
        "Remove a server setting",
        detail="Unsetting public-hostname falls back to Public IP access. "
        "Unsetting bootstrap-hostname falls back to zt1 Zero-Touch commands.",
        examples=("server unset public-hostname",),
        args=(_arg("public-hostname|bootstrap-hostname", SERVER_SETTINGS[:2]),),
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
    """Ordered canonical root resources visible for this host role."""
    out = []
    for name, roles, _category, _summary in ROOTS:
        if not role_allows(roles, role):
            continue
        if name == "client" and not _root_has_commands("client", role):
            continue
        out.append(name)
    return out


def root_rows(role):
    """(name, summary) rows for the canonical root resources."""
    rows = []
    for name, roles, _category, summary in ROOTS:
        if not role_allows(roles, role):
            continue
        if name == "client" and not _root_has_commands("client", role):
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


def find(tokens, role=None):
    """Longest canonical command whose path is a prefix of ``tokens``."""
    best = None
    for cmd in COMMANDS:
        path = cmd["path"]
        if len(tokens) < len(path):
            continue
        if tuple(tokens[: len(path)]) != path:
            continue
        if role is not None and not role_allows(cmd["roles"], role):
            continue
        if best is None or len(path) > len(best["path"]):
            best = cmd
    return best


def usage_line(cmd):
    parts = list(cmd["path"])
    for arg in cmd["args"]:
        name = arg["name"]
        parts.append(name if arg["required"] else "[%s]" % name)
    shown = flag_names(cmd["flags"])
    if cmd["tail"] == "flags" and shown:
        parts.append("[options]")
    elif cmd["tail"] == "any":
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
    if len(rest) >= 2:
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
    """Rewrite a canonical token list into the internal verb-first form.

    Returns ``None`` when ``tokens`` is not a canonical command.
    """
    if not tokens:
        return None
    root = tokens[0]
    if root == "profile":
        tokens = ["service-profile"] + list(tokens[1:])
        root = "service-profile"
    elif root == "egress-profile":
        tokens = ["egress"] + list(tokens[1:])
        root = "egress"
    cmd = find(tokens)
    if cmd is None:
        return None
    path = cmd["path"]
    rest = list(tokens[len(path) :])
    rewrite = REWRITES.get(path)
    if rewrite is not None:
        return rewrite(rest)
    internal = cmd["internal"]
    if internal is None:
        return list(path) + rest
    return list(internal) + rest


def strict_error(tokens):
    """Reject unexpected trailing arguments and flag arity mistakes (CLI-016 / AUDIT-014).

    Returns an error message, or ``None`` when the token list is acceptable.
    """
    cmd = find(tokens)
    if cmd is None:
        return None
    rest = list(tokens[len(cmd["path"]) :])
    if cmd["tail"] == "any":
        return None
    idx = 0
    used = 0
    slots = len(cmd["args"])
    while idx < len(rest) and used < slots and not rest[idx].startswith("-"):
        idx += 1
        used += 1
    if cmd["tail"] is None:
        if idx < len(rest):
            return "unexpected argument: %s" % rest[idx]
        return None
    # Trailing option flags: enforce arity for catalog-known flags; reject
    # stray positionals. Unknown flags stay forwarded to the backend tool.
    known = {flag["name"]: flag for flag in cmd["flags"]}
    seen_flags = set()
    while idx < len(rest):
        tok = rest[idx]
        if not tok.startswith("-"):
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
        if flag.get("required") and flag["name"] not in seen_flags:
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
    """Canonical root help. Shows canonical commands only."""
    lines = [
        "Data Relay Link CLI",
        "===================",
        "",
        "Grammar: <resource> <action> [target] [options]",
        "",
        "Discover commands with Tab. Type 'help <resource>' for details,",
        "'help workflows' for end-to-end examples, or '?' for context help.",
    ]
    by_category = {}
    for name, roles, category, summary in ROOTS:
        if not role_allows(roles, role):
            continue
        if name == "client" and not _root_has_commands("client", role):
            continue
        by_category.setdefault(category, []).append((name, summary))
    for category in CATEGORY_ORDER:
        rows = by_category.get(category)
        if not rows:
            continue
        lines.append("")
        lines.append(category)
        lines.extend(_fmt_rows(rows))
    lines.extend(
        [
            "",
            "Compatibility aliases still run for scripts. See 'help legacy'.",
            "",
            "Official upstream FRP binaries are frps (server) and frpc (client).",
            "This project does not fork FRP.",
        ]
    )
    return "\n".join(lines) + "\n"


def concise_root(role):
    """Short root listing used by a bare '?'."""
    rows = root_rows(role)
    lines = ["Available:", ""]
    lines.extend(_fmt_rows(rows))
    return "\n".join(lines) + "\n"


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
            "zero-touch create",
            "client list",
            "client show <CLIENT-ID>",
        ),
        "Zero-Touch is the recommended path. Use 'enrollment create' only when "
        "an interactive install is required.",
    ),
    (
        "Publish and reach a remote service",
        (
            "service add --preset ssh --ssh-user aella      # on the client",
            "service apply                                  # on the client",
            "client show <CLIENT-ID> services               # on the server",
        ),
        "Public ports are assigned by the server at apply time and stay "
        "reserved until 'client release'.",
    ),
    (
        "Restrict who may reach a service",
        (
            "access create office --description \"Office ranges\"",
            "access add-source office --name hq --source 203.0.113.0/24",
            "access assign <CLIENT-ID> <SERVICE-ID> office",
            "access test <CLIENT-ID> <SERVICE-ID> 203.0.113.9",
        ),
        "Services are PUBLIC until a list is assigned. 'access public' reverts.",
    ),
    (
        "Allow one outbound destination",
        (
            "egress create vendor-api",
            "egress add-source vendor-api 10.0.0.0/24",
            "egress add-destination vendor-api api.example.com 443 --protocol https",
            "egress test 10.0.0.5 api.example.com 443",
            "egress enable vendor-api",
        ),
        "A new egress profile is created disabled. Default policy is DENY.",
    ),
    (
        "Routine maintenance",
        (
            "doctor",
            "backup create",
            "update project --check",
            "support bundle",
        ),
        "'update engine' updates the upstream FRP binary separately.",
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
        "Compatibility aliases",
        "=====================",
        "",
        "These older verb-first commands still run for scripts and muscle",
        "memory. Root help, Tab discovery, and the guided menu show the",
        "canonical resource-first form only.",
        "",
    ]
    rows = []
    seen = set()
    for cmd in COMMANDS:
        if not role_allows(cmd["roles"], role):
            continue
        for alias in cmd["aliases"]:
            text = " ".join(alias)
            if text in seen:
                continue
            seen.add(text)
            rows.append((text, " ".join(cmd["path"])))
    lines.extend(_fmt_rows(rows))
    lines.extend(
        [
            "",
            "Also accepted: client-status, manage, revoke <ID>, restore <PATH>.",
        ]
    )
    return "\n".join(lines) + "\n"


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
        "  <resource> <action> [target] [options]",
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
    lines.extend(
        [
            "",
            "Compatibility aliases still run for scripts. See 'help legacy'.",
        ]
    )
    return lines


# --- Guided numbered menu (single declarative source) ---------------------
# Server menu is grouped like root help IA. Each section is
# (category_label, ((action_id, label, canonical_hint), ...)).
# Client/both stay flat lists of (action_id, label, hint).
# Numbers are assigned at render time across all choices (not categories).
GUIDED_MENU = {
    "client": (
        ("client_status", "Status", "status"),
        ("client_services", "Service list", "service list"),
        ("client_info", "Connection information", "client info"),
        ("client_manage", "Manage services", "service add / service set / service apply"),
        ("client_update", "Update project", "update project"),
        ("client_doctor", "Doctor", "doctor"),
        ("client_help", "Commands and workflows", "help / help workflows"),
        ("exit", "Exit", ""),
    ),
    "server": (
        (
            "Remote Access",
            (
                ("server_clients", "Clients", "client list / client show / client set"),
                ("server_zt", "Enrollment / Zero-Touch", "zero-touch create / enrollment create"),
                ("server_bulk", "Bulk enrollment", "enrollment bulk"),
                ("server_enrollments", "Enrollment list", "enrollment list"),
                ("server_access", "Access Control", "access ..."),
            ),
        ),
        (
            "Controlled Egress",
            (
                ("server_egress", "Profiles / policy", "egress list / show / test / enable"),
            ),
        ),
        (
            "Organize",
            (
                ("server_groups", "Groups", "group list / group create"),
                ("server_profiles", "Service profiles", "service-profile list / create"),
            ),
        ),
        (
            "Operate",
            (
                ("server_status", "Status", "status"),
                ("server_doctor", "Doctor", "doctor"),
                ("server_audit", "Audit", "server audit"),
                ("server_backup", "Backup / Restore", "backup create / backup restore"),
                ("server_support", "Support bundle", "support bundle"),
                ("server_update_project", "Update project", "update project"),
                ("server_update_engine", "Update FRP engine", "update engine"),
                ("server_help", "Commands and workflows", "help / help workflows"),
            ),
        ),
        (
            None,
            (
                ("exit", "Exit", ""),
            ),
        ),
    ),
    "both": (
        ("both_client", "Client operations", ""),
        ("both_server", "Server operations", ""),
        ("both_status", "Status (both)", "status"),
        ("both_doctor", "System diagnostics", "doctor"),
        ("both_help", "Commands and workflows", "help / help workflows"),
        ("exit", "Exit", ""),
    ),
}


def _guided_menu_key(role):
    client, server = role_parts(role)
    if client and server:
        return "both"
    if client:
        return "client"
    return "server"


def _guided_menu_sections(role):
    """Yield (category_or_None, entries) where entries are (action_id, label, hint)."""
    key = _guided_menu_key(role)
    raw = GUIDED_MENU.get(key, ())
    if key == "server":
        for category, entries in raw:
            yield category, entries
        return
    yield None, raw


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
    """Text block for the numbered guided menu (without catalog overview)."""
    lines = []
    n = 0
    for category, entries in _guided_menu_sections(role):
        if category:
            if lines:
                lines.append("")
            lines.append(category)
        elif lines:
            # Uncategorized trailer (Exit): separate from prior section.
            lines.append("")
        for action_id, label, hint in entries:
            _ = action_id
            n += 1
            if hint:
                lines.append("%s) %-25s (%s)" % (n, label, hint))
            else:
                lines.append("%s) %s" % (n, label))
    return "\n".join(lines) + ("\n" if lines else "")


def guided_menu_action(role, choice):
    """Resolve a numeric menu choice to action_id, or None."""
    text = str(choice or "").strip()
    if not text.isdigit():
        return None
    n = int(text)
    for idx, action_id, _label, _hint in guided_menu_entries(role):
        if idx == n:
            return action_id
    return None
