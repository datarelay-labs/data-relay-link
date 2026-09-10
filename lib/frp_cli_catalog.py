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
ROOTS = (
    ("status", "any", "Status", "Host status"),
    ("version", "any", "Status", "Installed versions"),
    ("zero-touch", "server", "Onboarding", "Zero-Touch client onboarding"),
    ("enrollment", "server", "Onboarding", "Enrollment credentials"),
    ("client", "any", "Inventory", "Registered clients and local client info"),
    ("service", "client", "Inventory", "Local published services"),
    ("group", "server", "Inventory", "Client groups"),
    ("service-profile", "server", "Templates", "Reusable service creation templates"),
    ("access", "server", "Policy", "Access Control Pack (inbound source policy)"),
    ("egress", "server", "Policy", "Controlled Egress (outbound proxy policy)"),
    ("server", "server", "Server", "Server settings and server-side views"),
    ("backup", "server", "Maintenance", "Backup and restore"),
    ("update", "any", "Maintenance", "Update project tools or the FRP engine"),
    ("doctor", "any", "Maintenance", "Run health checks"),
    ("support", "any", "Maintenance", "Sanitized diagnostic archive"),
    ("help", "any", "Session", "Detailed help"),
    ("menu", "any", "Session", "Guided numbered menu"),
    ("history", "any", "Session", "Session command history"),
    ("clear", "any", "Session", "Clear the screen"),
    ("exit", "any", "Session", "Leave the CLI"),
)

CATEGORY_ORDER = (
    "Status",
    "Onboarding",
    "Inventory",
    "Templates",
    "Policy",
    "Server",
    "Maintenance",
    "Session",
)


def _arg(name, complete=C_NONE, required=True):
    return {"name": name, "complete": complete, "required": bool(required)}


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
):
    """Describe one canonical command.

    ``tail`` is ``None`` for a strict command (no tokens beyond ``args``),
    ``"flags"`` when trailing option flags are forwarded, and ``"any"`` when
    the remainder is an opaque passthrough.
    """
    return {
        "path": tuple(path),
        "roles": roles,
        "category": category,
        "summary": summary,
        "detail": detail,
        "examples": tuple(examples),
        "args": tuple(args),
        "flags": tuple(flags),
        "tail": tail,
        "internal": internal,
        "aliases": tuple(tuple(a) for a in aliases),
        "destructive": bool(destructive),
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
        tail="any",
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
        "Revoke a client's management identity",
        detail="Removes management identity and keeps port reservations. Use "
        "'client release' to return public ports.",
        examples=("client revoke 24cd7856",),
        args=(_arg("<CLIENT-ID>", C_CLIENT),),
        tail="flags",
        internal=("revoke", "client"),
        aliases=(("revoke", "client"), ("revoke-client",)),
        destructive=True,
    ),
    _cmd(
        ("client", "release"),
        "server",
        "Inventory",
        "Return reserved public ports for a client or one service",
        detail="With a CLIENT ID alone, every reservation for that client is "
        "returned. With a Service ID as well, only that reservation is "
        "returned. release is not revoke and not unset.",
        examples=(
            "client release 24cd7856",
            "client release 24cd7856 ssh",
        ),
        args=(
            _arg("<CLIENT-ID>", C_CLIENT),
            _arg("<SERVICE-ID>", C_CLIENT_SERVICE, required=False),
        ),
        tail="flags",
        aliases=(
            ("release", "client"),
            ("release", "service"),
            ("release-client",),
            ("release-service",),
        ),
        destructive=True,
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
    # --- service (client role) -------------------------------------------
    _cmd(
        ("service", "list"),
        "client",
        "Inventory",
        "List local services",
        detail="Local published services with CLIENT / TUNNEL / TARGET "
        "reported separately.",
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
        examples=("group set edge description 'Edge sites'",),
        args=(_arg("name|description", GROUP_PROPS),),
        tail="any",
        internal=("set", "group"),
        aliases=(("set", "group"),),
    ),
    _cmd(
        ("group", "rename"),
        "server",
        "Inventory",
        "Rename a group",
        examples=("group rename edge edge-sites",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<name>")),
        internal=("rename", "group"),
        aliases=(("rename", "group"),),
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
        ("group", "add-member"),
        "server",
        "Inventory",
        "Add a client to a group",
        examples=("group add-member edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
        aliases=(("add", "client"),),
    ),
    _cmd(
        ("group", "remove-member"),
        "server",
        "Inventory",
        "Remove a client from a group",
        examples=("group remove-member edge 24cd7856",),
        args=(_arg("<GROUP>", C_GROUP), _arg("<CLIENT-ID>", C_CLIENT)),
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
        detail="Editing a profile never mutates existing services.",
        examples=("service-profile set office-ssh target-port 2222",),
        args=(
            _arg("<PROFILE>", C_PROFILE),
            _arg("<property>", PROFILE_PROPS),
            _arg("<value>"),
        ),
        internal=("set", "profile"),
        aliases=(("set", "profile"), ("profile", "set")),
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
        tail="any",
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
    ),
    _cmd(
        ("access", "show"),
        "server",
        "Policy",
        "Show one Named Access List",
        examples=("access show office",),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        tail="any",
    ),
    _cmd(
        ("access", "delete"),
        "server",
        "Policy",
        "Delete a Named Access List",
        examples=("access delete office",),
        args=(_arg("<LIST>", C_ACCESS_LIST),),
        tail="flags",
        destructive=True,
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
    ),
    _cmd(
        ("access", "public"),
        "server",
        "Policy",
        "Set one client service back to PUBLIC",
        examples=("access public 24cd7856 ssh",),
        args=(_arg("<CLIENT-ID>", C_CLIENT), _arg("<SERVICE-ID>", C_CLIENT_SERVICE)),
        tail="flags",
    ),
    _cmd(
        ("access", "show-service"),
        "server",
        "Policy",
        "Show the access policy for one service",
        examples=("access show-service 24cd7856 ssh",),
        args=(_arg("<CLIENT-ID>", C_CLIENT), _arg("<SERVICE-ID>", C_CLIENT_SERVICE)),
        tail="any",
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
        tail="any",
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
        tail="any",
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
        "  3. egress add-destination <name> <FQDN> <PORT>\n"
        "  4. egress show <name>\n"
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
        examples=("egress set vendor-api --name partner-api",),
        args=(_arg("<PROFILE>", C_EGRESS),),
        flags=("--name", "--description"),
        tail="flags",
        internal=("set", "egress-profile"),
        aliases=(("set", "egress-profile"), ("egress-profile", "set")),
    ),
    _cmd(
        ("egress", "add-destination"),
        "server",
        "Policy",
        "Allow one destination FQDN and port",
        examples=("egress add-destination vendor-api api.example.com 443",),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<FQDN>"), _arg("<PORT>")),
        aliases=(("add", "egress-profile"),),
    ),
    _cmd(
        ("egress", "add-source"),
        "server",
        "Policy",
        "Allow one source CIDR",
        examples=("egress add-source vendor-api 10.0.0.0/24",),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<CIDR>")),
    ),
    _cmd(
        ("egress", "remove-destination"),
        "server",
        "Policy",
        "Remove one destination",
        examples=("egress remove-destination vendor-api api.example.com:443",),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<SELECTOR>")),
        aliases=(("remove", "egress-profile"),),
        destructive=True,
    ),
    _cmd(
        ("egress", "remove-source"),
        "server",
        "Policy",
        "Remove one source",
        examples=("egress remove-source vendor-api 10.0.0.0/24",),
        args=(_arg("<PROFILE>", C_EGRESS), _arg("<SELECTOR>")),
        destructive=True,
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
    ),
    _cmd(
        ("egress", "delete"),
        "server",
        "Policy",
        "Delete an egress profile",
        examples=("egress delete vendor-api",),
        args=(_arg("<PROFILE>", C_EGRESS),),
        internal=("delete", "egress-profile"),
        aliases=(("delete", "egress-profile"),),
        destructive=True,
    ),
    _cmd(
        ("egress", "status"),
        "server",
        "Policy",
        "Show Controlled Egress status",
        examples=("egress status",),
        tail="any",
    ),
    _cmd(
        ("egress", "test"),
        "server",
        "Policy",
        "Preview authorize(source, host, port)",
        examples=("egress test 10.0.0.5 api.example.com 443",),
        args=(_arg("<SOURCE-IP>"), _arg("<HOST>"), _arg("<PORT>")),
        tail="any",
    ),
    # --- server -----------------------------------------------------------
    _cmd(
        ("server", "status"),
        "server",
        "Server",
        "Show server status",
        examples=("server status",),
        internal=("server-status",),
        tail="any",
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
        aliases=(("create", "backup"), ("backup",)),
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
    if cmd["tail"] == "flags" and cmd["flags"]:
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


def _rw_egress_add_destination(rest):
    if len(rest) >= 3:
        return ["add", "egress-profile", rest[0], "destination", rest[1], rest[2]]
    return ["add", "egress-profile"] + list(rest) + ["destination"]


def _rw_egress_add_source(rest):
    if len(rest) >= 2:
        return ["add", "egress-profile", rest[0], "source", rest[1]]
    return ["add", "egress-profile"] + list(rest) + ["source"]


def _rw_egress_remove(kind):
    def inner(rest):
        if len(rest) >= 2:
            return ["remove", "egress-profile", rest[0], kind, rest[1]]
        return ["remove", "egress-profile"] + list(rest) + [kind]

    return inner


REWRITES = {
    ("client", "release"): _rw_client_release,
    ("enrollment", "purge"): _rw_enrollment_purge,
    ("group", "add-member"): _rw_group_member("add"),
    ("group", "remove-member"): _rw_group_member("remove"),
    ("server", "set"): _rw_server_set,
    ("server", "unset"): _rw_server_unset,
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
    """Reject unexpected trailing arguments (CLI-016).

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
    # Trailing option flags are forwarded and validated by the backend tool;
    # only stray positional arguments are rejected here.
    while idx < len(rest):
        if not rest[idx].startswith("-"):
            return "unexpected argument: %s" % rest[idx]
        idx += 1
        if idx < len(rest) and not rest[idx].startswith("-"):
            idx += 1
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
            "Older verb-first commands (show clients, set client, enroll, ...)",
            "still run for scripts. See 'help legacy'.",
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
        if not role_allows(cmd["roles"], role):
            continue
        lines.append("  %s" % usage_line(cmd))
    lines.append("")
    lines.append("Actions:")
    lines.extend(_fmt_rows(rows))
    destructive = [
        " ".join(cmd["path"])
        for cmd in COMMANDS
        if cmd["path"][0] == root and cmd["destructive"] and role_allows(cmd["roles"], role)
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
    if cmd["flags"]:
        lines.extend(["", "Options:", "  " + " ".join(cmd["flags"])])
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
            "egress add-destination vendor-api api.example.com 443",
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
        " ".join(cmd["path"]) for cmd in COMMANDS if role_allows(cmd["roles"], role)
    ]
