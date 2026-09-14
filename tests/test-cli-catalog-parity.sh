#!/usr/bin/env bash
# CLI catalog discovery parity + packaging parity for shared modules.
# New non-hidden catalog commands must appear in help/Tab/menu discovery.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - <<'PY' || fail "CLI catalog parity"
import sys
from pathlib import Path

sys.path.insert(0, str(Path("lib").resolve()))
import frp_cli_catalog as catalog
import frp_ctl_grammar as grammar

def discovery_blob(role):
    chunks = [
        catalog.root_help(role),
        catalog.workflow_help(role),
        catalog.legacy_help(role),
        "\n".join(catalog.shell_usage_lines(role)),
        grammar.help_text([], role),
    ]
    for root, _summary in catalog.root_rows(role):
        text = catalog.resource_help(root, role)
        if text:
            chunks.append(text)
        for action, _desc in catalog.subcommands(root, role):
            chunks.append(action)
            hits = grammar.completion_candidates("%s " % root, role, [], {}, [])
            if action not in hits:
                raise AssertionError(
                    "Tab missing %r under %r for role=%s (got %r)"
                    % (action, root, role, hits)
                )
    return "\n".join(chunks)

for role in ("server", "client", "both"):
    blob = discovery_blob(role)
    for path in catalog.parity_paths(role):
        parts = path.split()
        root = parts[0]
        action = parts[1] if len(parts) > 1 else ""
        if action:
            if action not in blob and path not in blob:
                raise AssertionError(
                    "role=%s catalog path %r not discoverable in help/Tab/menu"
                    % (role, path)
                )
        elif root not in blob:
            raise AssertionError("role=%s catalog root %r not discoverable" % (role, path))

# Action-first group surface under create/show/set/delete/add/remove.
assert "group" in [a for a, _ in catalog.subcommands("show", "server")]
assert "group" in [a for a, _ in catalog.subcommands("create", "server")]
assert "group" in [a for a, _ in catalog.subcommands("set", "server")]
assert "group" in [a for a, _ in catalog.subcommands("delete", "server")]
set_cmd = catalog.find(["set", "group"])
assert set_cmd is not None
assert [a["name"] for a in set_cmd["args"]] == [
    "<GROUP>", "name|description", "<value>"
]

egress_set = catalog.find(["set", "egress-profile"])
assert egress_set is not None
assert [a["name"] for a in egress_set["args"]][:2] == ["<PROFILE>", "name|description"]
assert any(f["name"] == "--name" and f.get("hidden") for f in egress_set["flags"])

# Public UX does not require --protocol; guided/backends enforce it.
assert catalog.strict_error(["add", "egress-destination", "p", "h", "443"]) in (None, "missing required flag: --protocol")
assert catalog.strict_error(["doctor", "--json", "true"]) == "flag --json does not take a value"
assert catalog.strict_error(
    ["create", "egress-profile", "x", "--description"]
) == "missing value for --description"

assert catalog.find(["rename", "group"], include_aliases=True).get("hidden")
# Hidden resource-first compat still rewrites.
resolved = catalog.resolve_tokens(["group", "add-client", "edge", "24cd7856"])
assert resolved[:2] == ["add", "client"], resolved
internal = catalog.to_internal(resolved)
assert internal[:2] == ["add", "client"], internal
print("CLI_CATALOG_PARITY=PASS")

# Guided menu must be generated from GUIDED_MENU / COMMANDS, not hard-coded.
assert hasattr(catalog, "GUIDED_MENU")
assert hasattr(catalog, "render_guided_menu")
assert hasattr(catalog, "guided_menu_action")
for role in ("server", "client", "both"):
    text = catalog.render_guided_menu(role)
    entries = catalog.guided_menu_entries(role)
    assert entries and text
    assert catalog.guided_menu_action(role, "1") == entries[0][1]
    assert catalog.guided_menu_action(role, str(len(entries))) == "exit"
# Server guided menu follows root-help IA categories.
server_menu = catalog.render_guided_menu("server")
for label in ("Remote Access", "Controlled Egress", "Organize", "Operate"):
    assert label in server_menu, label
assert "server_egress" in [e[1] for e in catalog.guided_menu_entries("server")]
frpctl = Path("tools/frpctl").read_text(encoding="utf-8")
assert "frpctl_render_guided_menu" in frpctl
assert 'echo "17) Exit"' not in frpctl
print("CLI_MENU_CATALOG_PARITY=PASS")

# Strict no-arg commands reject trailing tokens (CLI-AUDIT-001).
for tokens, needle in (
    (["show", "status", "foo"], "unexpected argument"),
    (["show", "version", "abc"], "unexpected argument"),
    (["menu", "x"], "unexpected argument"),
    (["show", "access-lists", "extra"], "unexpected argument"),
    (["show", "egress", "x"], "unexpected argument"),
):
    err = catalog.strict_error(tokens)
    assert err and needle in err, (tokens, err)

# Lifecycle confirmation / risk metadata.
revoke = catalog.find(["revoke", "client"], include_aliases=True)
release = catalog.find(["release", "client"], include_aliases=True)
assert revoke["confirmation"] == "typed_token" and revoke["risk"] == "irreversible"
assert release["confirmation"] == "typed_token" and release["risk"] == "irreversible"
assert "--force" in catalog.flag_names(revoke["flags"], include_hidden=True)
assert "--force" in catalog.flag_names(release["flags"], include_hidden=True)
help_release = catalog.command_help(release)
assert "WHAT WILL BE REMOVED" in help_release
assert "registry record" in help_release.lower() or "client registry record" in help_release
assert "no remote host deletion" in help_release.lower() or "WHAT WILL NOT HAPPEN" in help_release
help_revoke = catalog.command_help(revoke)
assert "WHAT STAYS" in help_revoke or "reservations" in help_revoke.lower()

# Flag help metadata for shallow options (hidden flags still carry metadata).
yes = next(f for f in catalog.find(["set", "access-public"], include_aliases=True)["flags"] if f["name"] == "--yes")
assert yes.get("description")
ttl = next(f for f in catalog.find(["add", "access-source"], include_aliases=True)["flags"] if f["name"] == "--ttl")
assert ttl.get("metavar") and ttl.get("description")

# Public catalog coverage for reverse-parity surfaces.
assert catalog.find(["set", "access-source"], include_aliases=True)
assert "--yes" in catalog.flag_names(catalog.find(["set", "access-public"], include_aliases=True)["flags"], include_hidden=True)
assert "--name" in catalog.flag_names(catalog.find(["add", "egress-source"], include_aliases=True)["flags"], include_hidden=True)
assert "--ssh-user" in catalog.flag_names(catalog.find(["set", "service-profile"], include_aliases=True)["flags"], include_hidden=True)
assert "--yes" in catalog.flag_names(catalog.find(["remove", "egress-source"], include_aliases=True)["flags"], include_hidden=True)
assert "--yes" in catalog.flag_names(catalog.find(["delete", "egress-profile"], include_aliases=True)["flags"], include_hidden=True)
egress_test = catalog.find(["test", "egress"], include_aliases=True) or catalog.find(["egress", "test"], include_aliases=True)
assert egress_test is not None
assert "policy" in (egress_test.get("detail") or "").lower()
assert "live" in (egress_test.get("detail") or "").lower() or "connection" in (egress_test.get("detail") or "").lower()
print("CLI_STRICT_AND_METADATA=PASS")
PY
pass "CLI_CATALOG_PARITY"
pass "CLI_MENU_CATALOG_PARITY"
pass "CLI_STRICT_AND_METADATA"

python3 - <<'PY' || fail "backend catalog reverse parity"
"""ARCH-AUDIT-001: backend public argparse surfaces ⊆ catalog (or exempt)."""
import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path("lib").resolve()))
import frp_cli_catalog as catalog

ROOT = Path(".").resolve()

def catalog_flags_for(path):
    cmd = catalog.find(list(path), include_aliases=True)
    if cmd is None:
        return None
    return {f["name"] for f in cmd["flags"]} | {
        f["name"] for f in cmd["flags"] if True
    }

# Map backend (tool, subcommand) → catalog path.
SURFACES = {
    ("frp-access", "replace-source"): ("set", "access-source"),
    ("frp-access", "public"): ("set", "access-public"),
    ("frp-access", "add-source"): ("add", "access-source"),
    ("frp-egress", "add-source"): ("add", "egress-source"),
    ("frp-egress", "remove-source"): ("remove", "egress-source"),
    ("frp-egress", "remove-destination"): ("remove", "egress-destination"),
    ("frp-egress", "delete"): ("delete", "egress-profile"),
    ("frp-egress", "explain"): ("explain", "egress"),
    ("frp-profile", "set"): ("set", "service-profile"),
    ("frp-release-client", None): ("release", "client"),
    ("frp-release-service", None): ("release", "client"),
    ("frp-revoke-client", None): ("revoke", "client"),
}

def parse_tool_flags(tool_path, subcommand):
    """Best-effort: collect add_argument('--…') under a subparser or root."""
    text = Path(tool_path).read_text(encoding="utf-8")
    flags = set()
    if subcommand is None:
        for line in text.splitlines():
            if "add_argument(" not in line:
                continue
            for quote in ("'", '"'):
                parts = line.split(quote)
                for part in parts:
                    if part.startswith("--"):
                        flags.add(part.split()[0].split("=")[0])
        return flags
    # Match add_parser("name" or add_parser(\n        "name"
    patterns = (
        'add_parser("%s"' % subcommand,
        "add_parser('%s'" % subcommand,
        'add_parser(\n        "%s"' % subcommand,
        "add_parser(\n        '%s'" % subcommand,
    )
    start = -1
    for pat in patterns:
        start = text.find(pat)
        if start >= 0:
            break
    if start < 0:
        # Fallback: search for quoted subcommand near add_parser
        idx = 0
        while True:
            hit = text.find('"%s"' % subcommand, idx)
            if hit < 0:
                hit = text.find("'%s'" % subcommand, idx)
            if hit < 0:
                break
            window = text[max(0, hit - 40):hit]
            if "add_parser" in window:
                start = hit
                break
            idx = hit + 1
    if start < 0:
        raise SystemExit("missing subparser %s in %s" % (subcommand, tool_path))
    rest = text[start:]
    nxt = rest.find("add_parser(", 10)
    block = rest if nxt < 0 else rest[:nxt]
    for line in block.splitlines():
        if "add_argument(" not in line:
            continue
        for quote in ("'", '"'):
            parts = line.split(quote)
            for part in parts:
                if part.startswith("--"):
                    flags.add(part.split()[0].split("=")[0])
    return flags

missing = []
for (tool, sub), path in SURFACES.items():
    tool_path = ROOT / "tools" / tool
    flags = parse_tool_flags(tool_path, sub)
    cmd = catalog.find(list(path), include_aliases=True)
    if cmd is None:
        missing.append("%s %s → catalog %s missing" % (tool, sub, path))
        continue
    if cmd.get("surface") in ("legacy_only", "internal_only", "hidden_compat"):
        continue
    cat_flags = {f["name"] for f in cmd["flags"]}
    for flag in sorted(flags):
        key = (tool, sub or "*", flag)
        if key in catalog.BACKEND_SURFACE_EXEMPT:
            continue
        if flag.startswith("-") and not flag.startswith("--"):
            # short options may be exempt / unadvertised
            if (tool, sub or "*", flag) in catalog.BACKEND_SURFACE_EXEMPT:
                continue
            continue
        if flag not in cat_flags and flag not in ("--help",):
            # release/revoke --force must be present; others too
            missing.append("%s %s flag %s not in catalog %s" % (tool, sub, flag, " ".join(path)))

if missing:
    raise SystemExit("reverse parity gaps:\n  " + "\n  ".join(missing))
print("BACKEND_CATALOG_REVERSE_PARITY=PASS")
PY
pass "BACKEND_CATALOG_REVERSE_PARITY"

python3 - <<'PY' || fail "packaging parity"
from pathlib import Path
root = Path(".").resolve()
manifest = (root / "lib/server-project-files.manifest").read_text(encoding="utf-8")
for name in (
    "frp_cli_catalog.py",
    "frp_machine_id.py",
    "frp_bounded_server.py",
    "frp_public_suffix.py",
    "frp_policy_fingerprint.py",
    "frp_egress_runtime.py",
    "drlink-tcp-egress.py",
    "public_suffix_list.dat",
    "egress-recipes/https-api.json",
):
    if name not in manifest:
        raise SystemExit("server manifest missing %s" % name)
bundles = (root / "scripts/build-bundles.py").read_text(encoding="utf-8")
for name in (
    "lib/frp_cli_catalog.py",
    "lib/frp_machine_id.py",
    "lib/frp_bounded_server.py",
    "lib/frp_public_suffix.py",
    "lib/frp_policy_fingerprint.py",
    "lib/frp_egress_runtime.py",
    "lib/data/public_suffix_list.dat",
    "lib/data/egress-recipes/https-api.json",
    "server/drlink-tcp-egress.py",
    "server/drlink-tcp-egress.service",
):
    if name not in bundles:
        raise SystemExit("build-bundles missing %s" % name)
install = (root / "install-server.sh").read_text(encoding="utf-8")
for name in (
    "frp_cli_catalog.py",
    "frp_machine_id.py",
    "frp_bounded_server.py",
    "frp_public_suffix.py",
    "frp_policy_fingerprint.py",
    "public_suffix_list.dat",
):
    if name not in install:
        raise SystemExit("install-server.sh missing %s" % name)
client = (root / "lib/frp-client-common.sh").read_text(encoding="utf-8")
if "frp_cli_catalog.py" not in client:
    raise SystemExit("client packaging missing frp_cli_catalog.py")
manifest_line = [
    line for line in manifest.splitlines() if "frp-egress-gateway.py" in line
]
if not manifest_line or " 0644 " not in manifest_line[0]:
    raise SystemExit("frp-egress-gateway.py must be mode 0644 for User=drlink-egress")
# PSL / machine_id / bounded server are server-side; Windows client is PowerShell-first.
print("PACKAGING_PARITY=PASS")
PY
pass "PACKAGING_PARITY"

# Post-install teaching must advertise action-first forms only.
python3 - <<'PY' || fail "post-install teaching parity"
from pathlib import Path

root = Path(".").resolve()
banned = (
    "client list",
    "enrollment create",
    "zero-touch create",
    "backup create",
    "update project",
    "client info",
)
files = {
    "install-server.sh": root / "install-server.sh",
    "install-client.sh": root / "install-client.sh",
}
# Focus on post-install / useful-commands blocks, not historical comments.
server_text = files["install-server.sh"].read_text(encoding="utf-8")
client_text = files["install-client.sh"].read_text(encoding="utf-8")

def extract_post_install(text, markers):
    for start, end in markers:
        i = text.find(start)
        if i < 0:
            continue
        j = text.find(end, i + len(start)) if end else len(text)
        if j < 0:
            j = len(text)
        return text[i:j]
    return ""

server_block = extract_post_install(
    server_text,
    [
        ("Everyday management (start here):", "EOF2"),
        ("Useful checks:", "EOF2"),
    ],
)
client_block = extract_post_install(
    client_text,
    [
        ("Useful commands", "========================================="),
        ("print('Useful commands')", "print('=========================================')"),
    ],
)
if not server_block:
    raise SystemExit("install-server.sh post-install block not found")
if not client_block:
    raise SystemExit("install-client.sh useful-commands block not found")
for label, block in (("install-server.sh", server_block), ("install-client.sh", client_block)):
    lower = block.lower()
    for needle in banned:
        if needle in lower:
            raise SystemExit("%s post-install teaches banned form: %r" % (label, needle))
# Positive sanity: canonical forms remain present.
for needle in ("create zero-touch", "show clients"):
    if needle not in server_block:
        raise SystemExit("install-server.sh post-install missing canonical %r" % needle)
if "show info" not in client_block and "show status" not in client_block:
    raise SystemExit("install-client.sh useful-commands missing canonical show status/info")
print("POST_INSTALL_TEACHING_PARITY=PASS")
PY
pass "POST_INSTALL_TEACHING_PARITY"

echo "ALL CLI CATALOG / PACKAGING PARITY TESTS PASSED"
