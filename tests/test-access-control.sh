#!/usr/bin/env bash
# Access Control Pack: frpctl grammar dispatch + frps.toml httpPlugins wiring.

# PRIOR_RELEASE_MIGRATION_TEST: tools/frp-access|frp-egress|frp-profile removed
echo "SKIP: dead legacy policy tools removed from current product surface" >&2
exit 0
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
export FRP_AUDIT_LOG=/var/log/drlink/audit.jsonl
mkdir -p "$HOME"

mkdir -p \
  "$TREE/etc/drlink" \
  "$TREE/etc/frp" \
  "$TREE/var/lib/drlink" \
  "$TREE/var/log/drlink" \
  "$TREE/var/log/drlink/access" \
  "$TREE/usr/local/lib/drlink"

cp "$ROOT/lib/frp_access_control.py" "$TREE/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_audit.py" "$TREE/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_control_locks.py" "$TREE/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_client_registry.py" "$TREE/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_ctl_grammar.py" "$TREE/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_cli_catalog.py" "$TREE/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_ctl_repl.py" "$TREE/usr/local/lib/drlink/"

python3 - <<'PY'
import importlib.util
import json
import os
from pathlib import Path

root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
cfg = {
    "public_host": "203.0.113.10",
    "public_ip": "203.0.113.10",
    "registry_file": "/var/lib/drlink/registry.json",
    "access_control_file": "/var/lib/drlink/access-control.json",
    "access_conn_log_file": "/var/log/drlink/access/connections.jsonl",
    "access_plugin_addr": "127.0.0.1:6101",
    "access_plugin_path": "/access-auth",
}
(root / "etc/drlink/config.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
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
(root / "var/lib/drlink/registry.json").write_text(
    json.dumps(registry, indent=2) + "\n", encoding="utf-8"
)
spec = importlib.util.spec_from_file_location(
    "frp_access_control",
    str(root / "usr/local/lib/drlink/frp_access_control.py"),
)
acl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acl)
acl.save_access_state(
    acl.empty_access_state(),
    path=root / "var/lib/drlink/access-control.json",
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
grep -qE 'Access Lists|ACLs' "$WORKDIR/list.out" || fail "access list header"
grep -q '(none)' "$WORKDIR/list.out" || fail "empty access list"

"$CTL" access create Office --description 'corp' >"$WORKDIR/create.out"
"$CTL" access add-source Office --name home --source 198.51.100.10 --yes >"$WORKDIR/add.out"
"$CTL" access assign demo ssh Office >"$WORKDIR/assign.out"
"$CTL" access test demo ssh 198.51.100.10 >"$WORKDIR/test-allow.out"
grep -qi 'ALLOW' "$WORKDIR/test-allow.out" || fail "test allow"
"$CTL" access test demo ssh 203.0.113.9 >"$WORKDIR/test-deny.out"
grep -qi 'DENY' "$WORKDIR/test-deny.out" || fail "test deny"
"$CTL" access public demo ssh --yes >"$WORKDIR/public.out"
grep -qi 'Exposure' "$WORKDIR/public.out" || fail "public exposure banner"
grep -qi 'Existing established connections' "$WORKDIR/public.out" || fail "session semantics on public"

# ALLOWLIST → PUBLIC requires --yes in non-interactive mode.
"$CTL" access assign demo ssh Office >/dev/null
if "$CTL" access public demo ssh >"$WORKDIR/public-no.out" 2>"$WORKDIR/public-no.err"; then
  fail "ALLOWLIST→PUBLIC without --yes should fail non-interactive"
fi
grep -qi '\-\-yes\|confirmation' "$WORKDIR/public-no.err" "$WORKDIR/public-no.out" \
  || fail "ALLOWLIST→PUBLIC must mention --yes/confirmation"
"$CTL" access public demo ssh --yes >"$WORKDIR/public-yes.out"
grep -qi 'become PUBLIC\|publicly reachable' "$WORKDIR/public-yes.out" || fail "broadening warning shown with --yes"
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
grep -qE 'This (Access List|ACL) is used by' "$WORKDIR/shared-add.out" \
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
    str(root / "usr/local/lib/drlink/frp_access_control.py"),
)
acl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acl)
path = root / "var/lib/drlink/access-control.json"
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
grep -qE 'This (Access List|ACL) is used by' "$WORKDIR/shared-add-yes.out" || fail "shared add with --yes shows impact"
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

# Expired-only cleanup must succeed while binding stays ALLOWLIST (no PUBLIC).
python3 - <<'PY' || fail "seed only-expired allowlist"
import importlib.util, os
from datetime import datetime, timedelta, timezone
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
spec = importlib.util.spec_from_file_location(
    "frp_access_control",
    str(root / "usr/local/lib/drlink/frp_access_control.py"),
)
acl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acl)
path = root / "var/lib/drlink/access-control.json"
state = acl.load_access_state(path=path)
lid, _ = acl.resolve_access_list(state, "Office")
past = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
state["access_lists"][lid]["entries"] = []
acl.add_source_entry(state, lid, "expired-only", "203.0.113.77", expires_at=past)
acl.save_access_state(state, path=path)
PY
"$CTL" access remove-expired Office --yes >"$WORKDIR/exp-only.out"
"$CTL" access test demo ssh 203.0.113.77 >"$WORKDIR/exp-only-test.out"
grep -qi 'DENY' "$WORKDIR/exp-only-test.out" || fail "after expired cleanup auth must DENY"
MODE="$("$CTL" access show-service demo ssh | awk -F: '/Access mode/{print $2}' | tr -d ' ')"
[[ "$MODE" == "ALLOWLIST" ]] || fail "expired cleanup must stay ALLOWLIST"
"$CTL" access show Office >"$WORKDIR/exp-only-list.out"
if grep -qi '203.0.113.77' "$WORKDIR/exp-only-list.out"; then
  fail "expired entry should be removed"
fi
pass "expired-only cleanup stays ALLOWLIST"

"$CTL" access public demo ssh --yes >/dev/null

# Access Control mutations must emit structured audit events without secrets.
AUDIT="$TREE/var/log/drlink/audit.jsonl"
SECRET_DESC='shared note bt1.deadbeef.0123456789abcdef'
"$CTL" access create AuditLab --description "$SECRET_DESC" >/dev/null
"$CTL" access add-source AuditLab --name lab --source 203.0.113.128/25 --ttl 4h --yes >/dev/null
"$CTL" access replace-source AuditLab --source 203.0.113.128/25 --name lab2 \
  --new-source 203.0.113.192/26 --ttl 1d --yes >/dev/null
"$CTL" access assign demo ssh AuditLab >/dev/null
"$CTL" access public demo ssh --yes >/dev/null
"$CTL" access edit-info AuditLab --description 'plain note' --yes >/dev/null
"$CTL" access remove-source AuditLab --source 203.0.113.192/26 --yes >/dev/null
"$CTL" access delete AuditLab >/dev/null

[[ -f "$AUDIT" ]] || fail "access mutations must write an audit log"
python3 - "$AUDIT" <<'PY' || fail "access mutation audit events"
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
by_event = {}
for record in records:
    by_event.setdefault(record.get("event"), []).append(record)

required = {
    "access.list.created": ("list_id", "list_name"),
    "access.list.updated": ("list_id", "list_name"),
    "access.list.deleted": ("list_id", "list_name"),
    "access.source.added": ("list_id", "entry_id", "entry_name", "cidr"),
    "access.source.updated": ("list_id", "entry_id", "cidr"),
    "access.source.removed": ("list_id", "entry_id", "cidr"),
    "access.service.assigned": ("client_id", "service_id", "list_id", "access_mode"),
    "access.service.public": ("client_id", "service_id", "access_mode"),
}
for event, fields in required.items():
    hits = by_event.get(event)
    assert hits, "missing audit event %s" % event
    for field in fields:
        assert all(field in hit for hit in hits), "%s missing %s" % (event, field)

assert by_event["access.source.added"][-1]["cidr"] == "203.0.113.128/25"
assert by_event["access.source.updated"][-1]["details"]["previous_cidr"] == "203.0.113.128/25"
assert by_event["access.service.assigned"][-1]["access_mode"] == "ALLOWLIST"
assert by_event["access.service.public"][-1]["access_mode"] == "PUBLIC"

access_records = [r for r in records if str(r.get("event", "")).startswith("access.")]
blob = json.dumps(access_records)
for leak in ("bt1.deadbeef", "shared note", "plain note", "description\":\"" ):
    assert leak not in blob, "audit leaked %r" % leak
print("ok")
PY
pass "access mutation audit events (no secrets)"

# Description hygiene: bounded length, no control characters or ANSI escapes.
if "$CTL" access create BadDesc --description $'evil\x1b[31mred' \
  >"$WORKDIR/desc-ansi.out" 2>"$WORKDIR/desc-ansi.err"; then
  fail "ANSI escape in description should be rejected"
fi
grep -qi 'control characters' "$WORKDIR/desc-ansi.err" || fail "ANSI description error message"
if "$CTL" access create BadDesc --description $'line\nbreak' \
  >"$WORKDIR/desc-nl.out" 2>"$WORKDIR/desc-nl.err"; then
  fail "newline in description should be rejected"
fi
LONG_DESC="$(python3 -c 'import sys; sys.stdout.write("a" * 1025)')"
if "$CTL" access create BadDesc --description "$LONG_DESC" \
  >"$WORKDIR/desc-long.out" 2>"$WORKDIR/desc-long.err"; then
  fail "over-long description should be rejected"
fi
grep -qi 'too long' "$WORKDIR/desc-long.err" || fail "over-long description error message"
"$CTL" access list >"$WORKDIR/desc-list.out"
if grep -q 'BadDesc' "$WORKDIR/desc-list.out"; then
  fail "rejected description must not create a list"
fi
pass "access list description validation"

# TTL upper bound: giant values are a user-facing error, not an overflow.
"$CTL" access create TtlLab >/dev/null
if "$CTL" access add-source TtlLab --name huge --source 198.51.100.77 \
  --ttl 99999999999999d --yes >"$WORKDIR/ttl-big.out" 2>"$WORKDIR/ttl-big.err"; then
  fail "giant TTL should be rejected"
fi
grep -qi '3650d' "$WORKDIR/ttl-big.err" || fail "giant TTL must name the documented maximum"
if grep -qi 'traceback\|OverflowError' "$WORKDIR/ttl-big.err"; then
  fail "giant TTL must not surface a Python traceback"
fi
"$CTL" access add-source TtlLab --name bounded --source 198.51.100.78 --ttl 3650d --yes >/dev/null
"$CTL" access delete TtlLab >/dev/null
"$CTL" access add-source --help 2>/dev/null | grep -qi '3650d' \
  || fail "--ttl help must document the maximum"
python3 - "$ROOT/lib/frp_cli_catalog.py" <<'PY' || fail "catalog --ttl maximum note"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("frp_cli_catalog", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cmd = mod.find(["add", "access-source"]) or mod.find(["access", "add-source"], include_aliases=True)
assert cmd is not None, "add access-source catalog entry missing"
flag = next(f for f in cmd["flags"] if f["name"] == "--ttl")
assert "3650d" in flag["description"], flag
assert "3650d" in cmd["detail"], cmd["detail"]
create = mod.find(["create", "access-list"]) or mod.find(["access", "create"], include_aliases=True)
assert create is not None, "create access-list catalog entry missing"
assert "1024" in create["detail"], create["detail"]
print("ok")
PY
pass "access TTL upper bound documented and enforced"

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
assert "drlink-access" in text
print("ok")
PY
pass "install-server.sh embeds access plugin wiring"

echo "All access-control shell checks passed."
