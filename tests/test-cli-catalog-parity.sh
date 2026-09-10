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

server_group = [a for a, _ in catalog.subcommands("group", "server")]
assert server_group == [
    "list", "show", "create", "set", "delete", "add-client", "remove-client"
], server_group
assert "rename" not in server_group and "add-member" not in server_group
set_cmd = catalog.find(["group", "set"])
assert [a["name"] for a in set_cmd["args"]] == [
    "<GROUP>", "name|description", "<value>"
]

egress_set = catalog.find(["egress", "set"])
assert [a["name"] for a in egress_set["args"]][:2] == ["<PROFILE>", "name|description"]
assert any(f["name"] == "--name" and f.get("hidden") for f in egress_set["flags"])

assert catalog.strict_error(
    ["egress", "add-destination", "p", "h", "443"]
) == "missing required flag: --protocol"
assert catalog.strict_error(["doctor", "--json", "true"]) == "flag --json does not take a value"
assert catalog.strict_error(
    ["egress", "create", "x", "--description"]
) == "missing value for --description"

assert catalog.find(["group", "add-member"]).get("hidden")
internal = catalog.to_internal(["group", "add-client", "edge", "24cd7856"])
assert internal[:2] == ["add", "client"], internal
print("CLI_CATALOG_PARITY=PASS")
PY
pass "CLI_CATALOG_PARITY"

python3 - <<'PY' || fail "packaging parity"
from pathlib import Path
root = Path(".").resolve()
manifest = (root / "lib/server-project-files.manifest").read_text(encoding="utf-8")
for name in (
    "frp_cli_catalog.py",
    "frp_machine_id.py",
    "frp_bounded_server.py",
    "frp_public_suffix.py",
    "public_suffix_list.dat",
):
    if name not in manifest:
        raise SystemExit("server manifest missing %s" % name)
bundles = (root / "scripts/build-bundles.py").read_text(encoding="utf-8")
for name in (
    "lib/frp_cli_catalog.py",
    "lib/frp_machine_id.py",
    "lib/frp_bounded_server.py",
    "lib/frp_public_suffix.py",
    "lib/data/public_suffix_list.dat",
):
    if name not in bundles:
        raise SystemExit("build-bundles missing %s" % name)
install = (root / "install-server.sh").read_text(encoding="utf-8")
for name in (
    "frp_cli_catalog.py",
    "frp_machine_id.py",
    "frp_bounded_server.py",
    "frp_public_suffix.py",
    "public_suffix_list.dat",
):
    if name not in install:
        raise SystemExit("install-server.sh missing %s" % name)
client = (root / "lib/frp-client-common.sh").read_text(encoding="utf-8")
if "frp_cli_catalog.py" not in client:
    raise SystemExit("client packaging missing frp_cli_catalog.py")
# PSL / machine_id / bounded server are server-side; Windows client is PowerShell-first.
print("PACKAGING_PARITY=PASS")
PY
pass "PACKAGING_PARITY"

echo "ALL CLI CATALOG / PACKAGING PARITY TESTS PASSED"
