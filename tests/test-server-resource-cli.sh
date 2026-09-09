#!/usr/bin/env bash
# Targeted tests for server category-first frpctl UX.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

chmod +x "$ROOT/tools/frpctl"

CTL="$ROOT/tools/frpctl"
export FRP_CTL_BIN_DIR="$ROOT/tools"
export FRP_SKIP_SYSTEMD=1
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

SERVER="$WORKDIR/server"
mkdir -p "$SERVER/etc/frp-auto-deploy" \
  "$SERVER/var/lib/frp-auto-deploy/enrollments" \
  "$SERVER/var/lib/frp-auto-deploy/bootstrap" \
  "$SERVER/usr/local/bin"

python3 - "$SERVER/etc/frp-auto-deploy/config.json" "$SERVER/var/lib/frp-auto-deploy/registry.json" <<'PY'
import json, sys
from pathlib import Path
cfg_path, reg_path = Path(sys.argv[1]), Path(sys.argv[2])
cfg_path.write_text(json.dumps({
    "public_ip": "203.0.113.10",
    "public_hostname": "frp.example.com",
    "bootstrap_hostname": "bootstrap.example.com",
    "allocator_public_url": "https://203.0.113.10:9443/enroll",
    "client_installer_url": "https://example.com/install-client.sh",
    "deployment_mode": "direct",
    "frp_control_public_port": 443,
    "control_port": 443,
    "port_start": 6000,
    "port_end": 6098,
    "enrollments_dir": "/var/lib/frp-auto-deploy/enrollments",
    "bootstrap_dir": "/var/lib/frp-auto-deploy/bootstrap",
    "registry_file": "/var/lib/frp-auto-deploy/registry.json",
}, indent=2, sort_keys=True) + "\n")
reg_path.write_text(json.dumps({
    "schema_version": 2,
    "reserved": [],
    "clients": {
        "aabbccdd0011": {
            "hostname": "edge-one",
            "label": "edge",
            "mgmt_status": "enrolled",
            "services": {},
        }
    },
    "groups": {},
}, indent=2, sort_keys=True) + "\n")
PY

python3 - "$SERVER/var/lib/frp-auto-deploy/enrollments/enroll1.json" <<'PY'
import json, sys, time
from pathlib import Path
now = int(time.time())
Path(sys.argv[1]).write_text(json.dumps({
    "id": "enroll1abcdef",
    "label": "manual-one",
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": now + 86400,
    "expires_at_iso": "2099-01-01T00:00:00Z",
    "enroll_secret": "SECRET_MUST_NOT_LEAK",
}, indent=2, sort_keys=True) + "\n")
PY

export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_DEPLOY_TEST_ROOT="$SERVER"
export FRP_CTL_DRY_RUN=1

# Grammar / discovery
python3 - <<'PY' || fail "server grammar discovery"
import sys
sys.path.insert(0, "lib")
import frp_ctl_grammar as g

root = g.canonical_verbs("server")
for need in ("show", "client", "enrollment", "group", "profile", "access", "server", "system", "help", "menu", "exit"):
    if need not in root:
        raise SystemExit("server root missing %s: %r" % (need, root))
for hide in ("create", "doctor", "set", "status", "version", "update", "revoke", "purge", "release", "restore"):
    if hide in root:
        raise SystemExit("server root must hide %s: %r" % (hide, root))

dual = g.canonical_verbs("both")
for need in ("service", "client", "system", "enrollment", "group", "profile", "server", "access"):
    if need not in dual:
        raise SystemExit("dual root missing %s: %r" % (need, dual))
for hide in ("create", "doctor", "set"):
    if hide in dual:
        raise SystemExit("dual root must hide %s: %r" % (hide, dual))

def ok(tokens, action, **extra):
    got = g.match(tokens, "server", names=["aabbccdd"])
    if got.get("status") != "ok" or got.get("action") != action:
        raise SystemExit("match %r -> %r" % (tokens, got))
    for k, v in extra.items():
        if got.get(k) != v:
            raise SystemExit("match %r missing %s=%r in %r" % (tokens, k, v, got))

ok(["show", "health"], "doctor")
ok(["doctor"], "doctor")
ok(["client", "set", "aabbccdd", "label", "prod"], "set_client", client="aabbccdd", property="label", value="prod")
ok(["client", "release", "aabbccdd"], "release_client", client="aabbccdd")
ok(["client", "revoke", "aabbccdd"], "revoke_client", client="aabbccdd")
ok(["enrollment", "zero-touch"], "create_zero_touch")
ok(["enrollment", "create"], "create_enrollment")
ok(["enrollment", "list"], "show_enrollments")
ok(["enrollment", "show", "enroll1abcdef"], "show_enrollment", id="enroll1abcdef")
ok(["enrollment", "revoke", "enroll1abcdef"], "revoke_enrollment", id="enroll1abcdef")
ok(["enrollment", "purge", "enroll1abcdef"], "purge_enrollment", id="enroll1abcdef")
ok(["group", "list"], "show_groups")
ok(["group", "create", "ops"], "create_group", name="ops")
ok(["group", "add-member", "aabbccdd", "ops"], "add_group_member", client="aabbccdd", group="ops")
ok(["profile", "list"], "show_profiles")
ok(["server", "show"], "server_show")
ok(["server", "installer", "https://example.com/x.sh"], "set_installer_url", value="https://example.com/x.sh")
ok(["server", "reconfigure"], "server_reconfigure")
ok(["system", "backup"], "create_backup")
ok(["system", "restore", "/tmp/b.tgz"], "restore_backup", path="/tmp/b.tgz")
ok(["system", "update-frp"], "update_frp")
ok(["system", "doctor"], "doctor")

# Legacy aliases still match
ok(["create", "zero-touch"], "create_zero_touch")
ok(["show", "enrollments"], "show_enrollments")
ok(["set", "client", "aabbccdd", "note", "x"], "set_client")
ok(["revoke", "enrollment", "enroll1abcdef"], "revoke_enrollment")
ok(["create", "backup"], "create_backup")
ok(["support-bundle"], "support_bundle")

# Dual: lifecycle + server client management coexist
got = g.match(["client", "pause"], "both")
if got.get("action") != "client_pause":
    raise SystemExit("dual pause: %r" % got)
got = g.match(["client", "set", "aabbccdd", "label", "x"], "both", names=["aabbccdd"])
if got.get("action") != "set_client":
    raise SystemExit("dual client set: %r" % got)

concise = g.context_help([], "server")
for need in ("enrollment", "group", "profile", "server", "system", "client"):
    if need not in concise:
        raise SystemExit("concise missing %s" % need)
if "create" in concise.split() and "  create  " in concise:
    raise SystemExit("concise should not lead with create")
PY
pass "SERVER_GRAMMAR_NAMESPACES"

# Dispatch: server show (real, no secrets)
unset FRP_CTL_DRY_RUN
"$CTL" server show >"$WORKDIR/server-show.out"
grep -q 'Public IP            : 203.0.113.10' "$WORKDIR/server-show.out" || fail "server show public ip"
grep -q 'Public hostname      : frp.example.com' "$WORKDIR/server-show.out" || fail "server show hostname"
grep -q 'Allocator URL        : https://203.0.113.10:9443/enroll' "$WORKDIR/server-show.out" || fail "server show allocator"
grep -q 'Bootstrap hostname   : bootstrap.example.com' "$WORKDIR/server-show.out" || fail "server show bootstrap"
grep -q 'Client installer URL : https://example.com/install-client.sh' "$WORKDIR/server-show.out" || fail "server show installer"
grep -q 'Deployment mode      : direct' "$WORKDIR/server-show.out" || fail "server show mode"
grep -q 'Control port         : 443' "$WORKDIR/server-show.out" || fail "server show control"
grep -q 'Service port range   : 6000-6098' "$WORKDIR/server-show.out" || fail "server show range"
if grep -qiE 'SECRET|token|BEGIN |private' "$WORKDIR/server-show.out"; then
  fail "server show leaked secret-like material"
fi
pass "SERVER_SHOW_DISPATCH"

# Non-interactive cancel path (EOF / defaults → no mutation when unchanged).
printf '%s\n' '203.0.113.10' 'frp.example.com' 'https://203.0.113.10:9443/enroll' 'n' \
  | "$CTL" server reconfigure >"$WORKDIR/server-reconf.out" 2>"$WORKDIR/server-reconf.err" || true
grep -qi 'Server Public Endpoint\|Changes\|Cancelled\|No changes\|Public IP' \
  "$WORKDIR/server-reconf.out" "$WORKDIR/server-reconf.err" || fail "server reconfigure interactive"
pass "SERVER_RECONFIGURE_GUIDED"

"$CTL" enrollment show enroll1abcdef >"$WORKDIR/enroll-show.out"
grep -q 'enroll1abcdef' "$WORKDIR/enroll-show.out" || fail "enrollment show id"
grep -q 'manual' "$WORKDIR/enroll-show.out" || fail "enrollment show type"
if grep -q 'SECRET_MUST_NOT_LEAK' "$WORKDIR/enroll-show.out"; then
  fail "enrollment show leaked secret"
fi
pass "ENROLLMENT_SHOW_DISPATCH"

export FRP_CTL_DRY_RUN=1
"$CTL" enrollment list >"$WORKDIR/enroll-list.out"
grep -q 'DISPATCH frp-enrollments' "$WORKDIR/enroll-list.out" || fail "enrollment list"
"$CTL" show enrollments >"$WORKDIR/leg-enroll.out"
grep -q 'DISPATCH frp-enrollments' "$WORKDIR/leg-enroll.out" || fail "legacy show enrollments"
"$CTL" client set aabbccdd label prod >"$WORKDIR/client-set.out"
grep -q 'DISPATCH frp-client-set aabbccdd --label prod' "$WORKDIR/client-set.out" || fail "client set"
"$CTL" set client aabbccdd label prod >"$WORKDIR/leg-set.out"
grep -q 'DISPATCH frp-client-set aabbccdd --label prod' "$WORKDIR/leg-set.out" || fail "legacy set client"
"$CTL" client release aabbccdd >"$WORKDIR/client-rel.out"
grep -q 'DISPATCH frp-release-client aabbccdd' "$WORKDIR/client-rel.out" || fail "client release"
"$CTL" client revoke aabbccdd >"$WORKDIR/client-rev.out"
grep -q 'DISPATCH frp-revoke-client aabbccdd' "$WORKDIR/client-rev.out" || fail "client revoke"
"$CTL" group list >"$WORKDIR/group-list.out"
grep -q 'DISPATCH frp-groups' "$WORKDIR/group-list.out" || fail "group list"
"$CTL" profile list >"$WORKDIR/profile-list.out"
grep -q 'DISPATCH frp-profile list' "$WORKDIR/profile-list.out" || fail "profile list"
"$CTL" system backup >"$WORKDIR/sys-backup.out"
grep -q 'DISPATCH frp-backup' "$WORKDIR/sys-backup.out" || fail "system backup"
"$CTL" system restore /tmp/b.tgz >"$WORKDIR/sys-restore.out"
grep -q 'DISPATCH frp-restore /tmp/b.tgz' "$WORKDIR/sys-restore.out" || fail "system restore"
"$CTL" system support-bundle --output /tmp/x.zip >"$WORKDIR/sys-sb.out"
grep -q 'DISPATCH frp-support-bundle --output /tmp/x.zip' "$WORKDIR/sys-sb.out" || fail "system support-bundle"
"$CTL" server installer https://example.com/install-client.sh >"$WORKDIR/installer.out"
grep -q 'DISPATCH frp-set-client-installer-url https://example.com/install-client.sh' "$WORKDIR/installer.out" || fail "server installer"
pass "SERVER_NAMESPACE_DISPATCH"
pass "LEGACY_SERVER_ALIASES"

# Context help
FRP_CTL_TEST_INPUT="$(printf '%s\n' 'enrollment ?' 'group ?' 'profile ?' 'server ?' 'system ?' 'client ?' exit)"
export FRP_CTL_TEST_INPUT
unset FRP_CTL_DRY_RUN
"$CTL" >"$WORKDIR/ctx.out" 2>"$WORKDIR/ctx.err" || true
grep -q 'Enrollment' "$WORKDIR/ctx.out" || fail "enrollment ?"
grep -q 'Groups' "$WORKDIR/ctx.out" || fail "group ?"
grep -q 'Service Profiles\|Profiles' "$WORKDIR/ctx.out" || fail "profile ?"
grep -q 'Server settings' "$WORKDIR/ctx.out" || fail "server ?"
grep -q 'System maintenance' "$WORKDIR/ctx.out" || fail "system ?"
grep -q 'set\|release\|revoke' "$WORKDIR/ctx.out" || fail "client ?"
pass "SERVER_CONTEXT_HELP"

echo "All server resource CLI tests passed."
