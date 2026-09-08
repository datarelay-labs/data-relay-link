#!/usr/bin/env bash
# Access Control Pack: frpctl grammar dispatch + frps.toml httpPlugins wiring.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
TREE="$WORKDIR/root"
export FRP_DEPLOY_TEST_ROOT="$TREE"
export FRP_CTL_TEST_ROOT="$TREE"
export FRP_CTL_BIN_DIR="$ROOT/tools"
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

mkdir -p \
  "$TREE/etc/frp-auto-deploy" \
  "$TREE/etc/frp" \
  "$TREE/var/lib/frp-auto-deploy" \
  "$TREE/var/log/frp-auto-deploy" \
  "$TREE/usr/local/lib/frp-auto-deploy"

cp "$ROOT/lib/frp_access_control.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_client_registry.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_ctl_grammar.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_ctl_repl.py" "$TREE/usr/local/lib/frp-auto-deploy/"

python3 - <<'PY'
import importlib.util
import json
import os
from pathlib import Path

root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
cfg = {
    "public_host": "203.0.113.10",
    "public_ip": "203.0.113.10",
    "registry_file": "/var/lib/frp-auto-deploy/registry.json",
    "access_control_file": "/var/lib/frp-auto-deploy/access-control.json",
    "access_conn_log_file": "/var/log/frp-auto-deploy/access-conn.jsonl",
    "access_plugin_addr": "127.0.0.1:6101",
    "access_plugin_path": "/access-auth",
}
(root / "etc/frp-auto-deploy/config.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
registry = {
    "schema_version": 2,
    "clients": {
        "machine-abcdef012345": {
            "label": "demo",
            "hostname": "demo-host",
            "services": {"ssh": {"remote_port": 6001, "enabled": True}},
        }
    },
    "reserved": [6001],
}
(root / "var/lib/frp-auto-deploy/registry.json").write_text(
    json.dumps(registry, indent=2) + "\n", encoding="utf-8"
)
spec = importlib.util.spec_from_file_location(
    "frp_access_control",
    str(root / "usr/local/lib/frp-auto-deploy/frp_access_control.py"),
)
acl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acl)
acl.save_access_state(
    acl.empty_access_state(),
    path=root / "var/lib/frp-auto-deploy/access-control.json",
)
PY

python3 - "$ROOT/lib/frp_ctl_grammar.py" <<'PY' || fail "grammar access match"
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("frp_ctl_grammar", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
result = mod.match(["access", "list"], "server")
assert result["status"] == "ok", result
assert result["action"] == "access_cmd", result
assert result.get("passthrough") == ["list"], result
role = mod.match(["access", "list"], "client")
assert role["status"] == "role", role
print("ok")
PY
pass "frpctl grammar access passthrough"

CTL="$ROOT/tools/frpctl"
chmod +x "$ROOT/tools/frpctl" "$ROOT/tools/frp-access"

"$CTL" access list >"$WORKDIR/list.out"
grep -q 'Access Lists' "$WORKDIR/list.out" || fail "access list header"
grep -q '(none)' "$WORKDIR/list.out" || fail "empty access list"

"$CTL" access create Office --description 'corp' >"$WORKDIR/create.out"
"$CTL" access add-source Office --name home --source 198.51.100.10 --yes >"$WORKDIR/add.out"
"$CTL" access assign demo ssh Office >"$WORKDIR/assign.out"
"$CTL" access test demo ssh 198.51.100.10 >"$WORKDIR/test-allow.out"
grep -qi 'ALLOW' "$WORKDIR/test-allow.out" || fail "test allow"
"$CTL" access test demo ssh 203.0.113.9 >"$WORKDIR/test-deny.out"
grep -qi 'DENY' "$WORKDIR/test-deny.out" || fail "test deny"
"$CTL" access public demo ssh >"$WORKDIR/public.out"
"$CTL" access test demo ssh 203.0.113.9 >"$WORKDIR/test-public.out"
grep -qi 'ALLOW' "$WORKDIR/test-public.out" || fail "public allow"
pass "frpctl access list/create/add-source/assign/test/public"

# Shared-list confirmation: non-interactive requires --yes before mutation.
"$CTL" access assign demo ssh Office >/dev/null
if "$CTL" access add-source Office --name other --source 198.51.100.20 \
  >"$WORKDIR/shared-add.out" 2>"$WORKDIR/shared-add.err"; then
  fail "shared add-source without --yes should fail"
fi
grep -qi '\-\-yes' "$WORKDIR/shared-add.err" || fail "shared add-source --yes hint"
grep -q 'This Access List is used by' "$WORKDIR/shared-add.out" \
  || fail "shared add-source should show impacted services before fail"
if "$CTL" access remove-source Office --source 198.51.100.10 \
  >"$WORKDIR/shared-rm.out" 2>"$WORKDIR/shared-rm.err"; then
  fail "shared remove-source without --yes should fail"
fi
grep -qi '\-\-yes' "$WORKDIR/shared-rm.err" || fail "shared remove-source --yes hint"
if "$CTL" access edit-info Office --description 'updated' \
  >"$WORKDIR/shared-edit.out" 2>"$WORKDIR/shared-edit.err"; then
  fail "shared edit-info without --yes should fail"
fi
grep -qi '\-\-yes' "$WORKDIR/shared-edit.err" || fail "shared edit-info --yes hint"

# Seed an expired entry, then shared remove-expired requires --yes.
python3 - <<'PY' || fail "seed expired entry"
import importlib.util, json, os
from datetime import datetime, timedelta, timezone
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
spec = importlib.util.spec_from_file_location(
    "frp_access_control",
    str(root / "usr/local/lib/frp-auto-deploy/frp_access_control.py"),
)
acl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acl)
path = root / "var/lib/frp-auto-deploy/access-control.json"
state = acl.load_access_state(path=path)
lid, _ = acl.resolve_access_list(state, "Office")
past = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
acl.add_source_entry(state, lid, "oldtmp", "203.0.113.50", expires_at=past)
acl.save_access_state(state, path=path)
PY
if "$CTL" access remove-expired Office \
  >"$WORKDIR/shared-exp.out" 2>"$WORKDIR/shared-exp.err"; then
  fail "shared remove-expired without --yes should fail"
fi
grep -qi '\-\-yes' "$WORKDIR/shared-exp.err" || fail "shared remove-expired --yes hint"
"$CTL" access remove-expired Office --yes >"$WORKDIR/shared-exp-yes.out"
"$CTL" access add-source Office --name other --source 198.51.100.20 --yes >"$WORKDIR/shared-add-yes.out"
grep -q 'This Access List is used by' "$WORKDIR/shared-add-yes.out" || fail "shared add with --yes shows impact"
"$CTL" access edit-info Office --description 'updated' --yes >"$WORKDIR/shared-edit-yes.out"
"$CTL" access remove-source Office --source 198.51.100.20 --yes >"$WORKDIR/shared-rm-yes.out"
pass "shared list confirmation + --yes automation"

# Last usable source cannot be removed while referenced (no PUBLIC fallback).
if "$CTL" access remove-source Office --source 198.51.100.10 --yes \
  >"$WORKDIR/last.out" 2>"$WORKDIR/last.err"; then
  fail "last usable remove-source should fail"
fi
grep -qi 'empty ALLOWLIST\|Use Disable' "$WORKDIR/last.err" || fail "last usable guard message"
"$CTL" access test demo ssh 198.51.100.10 >"$WORKDIR/last-still.out"
grep -qi 'ALLOW' "$WORKDIR/last-still.out" || fail "previous source must remain after failed last-remove"
MODE="$("$CTL" access show-service demo ssh | awk -F: '/Access mode/{print $2}' | tr -d ' ')"
[[ "$MODE" == "ALLOWLIST" ]] || fail "must stay ALLOWLIST after failed last-remove"
pass "last usable source removal safety"

# Failed atomic replace-source must preserve previous entry.
if "$CTL" access replace-source Office --source 198.51.100.10 --name bad --new-source 'not-an-ip' --yes \
  >"$WORKDIR/repl.out" 2>"$WORKDIR/repl.err"; then
  fail "invalid replace-source should fail"
fi
"$CTL" access test demo ssh 198.51.100.10 >"$WORKDIR/repl-still.out"
grep -qi 'ALLOW' "$WORKDIR/repl-still.out" || fail "failed replace must preserve old source"
"$CTL" access replace-source Office --source 198.51.100.10 --name home2 --new-source 198.51.100.11 --yes \
  >"$WORKDIR/repl-ok.out"
"$CTL" access test demo ssh 198.51.100.11 >"$WORKDIR/repl-ok-test.out"
grep -qi 'ALLOW' "$WORKDIR/repl-ok-test.out" || fail "successful replace should allow new source"
pass "atomic replace-source preserves on failure"

"$CTL" access public demo ssh >/dev/null

export FRP_SERVER_SOURCED=1
# shellcheck disable=SC1091
. "$ROOT/lib/frp-common.sh"
# shellcheck disable=SC1091
. "$ROOT/install-server.sh"
export FRP_CONTROL_LISTEN_PORT=443
export FRP_PORT_START=6000
export FRP_PORT_END=6098
export FRP_DEPLOYMENT_MODE=direct
write_frps_toml "$WORKDIR/frps-direct.toml"
export FRP_DEPLOYMENT_MODE=single443
export FRP_CONTROL_BIND_ADDR=127.0.0.1
write_frps_toml "$WORKDIR/frps-s443.toml"

for f in "$WORKDIR/frps-direct.toml" "$WORKDIR/frps-s443.toml"; do
  grep -q '\[\[httpPlugins\]\]' "$f" || fail "missing httpPlugins in $f"
  grep -q 'name = "frp-access"' "$f" || fail "missing plugin name in $f"
  grep -q 'NewUserConn' "$f" || fail "missing NewUserConn in $f"
  grep -q 'path = "/access-auth"' "$f" || fail "missing path in $f"
done
pass "write_frps_toml httpPlugins present"

python3 - "$ROOT/install-server.sh" <<'PY' || fail "install-server write_frps_toml source check"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "write_frps_toml()" in text
assert text.count("[[httpPlugins]]") >= 2
assert 'name = "frp-access"' in text
assert 'ops = ["NewUserConn"]' in text
assert "access_control_file" in text
assert "access_conn_log_file" in text
assert "access_plugin_addr" in text
assert "frp-access-plugin" in text
print("ok")
PY
pass "install-server.sh embeds access plugin wiring"

echo "All access-control shell checks passed."
