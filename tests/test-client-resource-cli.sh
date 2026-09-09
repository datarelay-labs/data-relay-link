#!/usr/bin/env bash
# Targeted tests for client resource-first frpctl UX (service/client/system).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

chmod +x "$ROOT/tools/frpctl" "$ROOT/tools/frp-client"

CTL="$ROOT/tools/frpctl"
export FRP_CTL_BIN_DIR="$ROOT/tools"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_SKIP_SYSTEMD=1
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

CLIENT="$WORKDIR/client"
mkdir -p "$CLIENT/etc/frp" "$CLIENT/etc/frp-auto-deploy" "$CLIENT/usr/local/bin"
python3 - "$CLIENT/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://127.0.0.1:9/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "resource-cli",
    "machine_id": "00112233445566778899aabbccddeeff",
    "host_id": "resource-cli-00112233",
    "services": {
        "ssh": {
            "id": "ssh", "name": "SSH", "preset": "ssh", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 6002,
            "enabled": True, "ssh_user": "aella",
        }
    },
}, indent=2, sort_keys=True) + "\n")
PY
cat >"$CLIENT/etc/frp-auto-deploy/version" <<'EOF'
PROJECT_VERSION=2.3.0
FRP_VERSION=0.71.0
EOF
cp "$CLIENT/etc/frp/client-state.json" "$WORKDIR/state.before"

export FRP_CTL_TEST_ROOT="$CLIENT"
export FRP_CLIENT_TEST_ROOT="$CLIENT"
export FRP_CTL_DRY_RUN=1

# Canonical service namespace dispatches
"$CTL" service apply >"$WORKDIR/svc-apply.out"
grep -qx 'DISPATCH frp-client apply-pending' "$WORKDIR/svc-apply.out" || fail "service apply"
"$CTL" service discard >"$WORKDIR/svc-discard.out"
grep -qx 'DISPATCH frp-client discard-pending' "$WORKDIR/svc-discard.out" || fail "service discard"
"$CTL" service enable ssh >"$WORKDIR/svc-en.out"
grep -qx 'DISPATCH frp-client enable-service ssh' "$WORKDIR/svc-en.out" || fail "service enable"
"$CTL" service disable ssh >"$WORKDIR/svc-dis.out"
grep -qx 'DISPATCH frp-client disable-service ssh' "$WORKDIR/svc-dis.out" || fail "service disable"
"$CTL" service set ssh target-port 2222 >"$WORKDIR/svc-set.out"
grep -qx 'DISPATCH frp-client set-service ssh target-port 2222' "$WORKDIR/svc-set.out" || fail "service set"
"$CTL" service add --preset ssh --id web >"$WORKDIR/svc-add.out"
grep -qx 'DISPATCH frp-client add-service --preset ssh --id web' "$WORKDIR/svc-add.out" || fail "service add"
pass "SERVICE_NAMESPACE_DISPATCH"

# Legacy aliases still dispatch
"$CTL" apply >"$WORKDIR/leg-apply.out"
grep -qx 'DISPATCH frp-client apply-pending' "$WORKDIR/leg-apply.out" || fail "legacy apply"
"$CTL" discard >"$WORKDIR/leg-discard.out"
grep -qx 'DISPATCH frp-client discard-pending' "$WORKDIR/leg-discard.out" || fail "legacy discard"
"$CTL" enable service ssh >"$WORKDIR/leg-en.out"
grep -qx 'DISPATCH frp-client enable-service ssh' "$WORKDIR/leg-en.out" || fail "legacy enable"
"$CTL" disable service ssh >"$WORKDIR/leg-dis.out"
grep -qx 'DISPATCH frp-client disable-service ssh' "$WORKDIR/leg-dis.out" || fail "legacy disable"
"$CTL" set service ssh target-port 2222 >"$WORKDIR/leg-set.out"
grep -qx 'DISPATCH frp-client set-service ssh target-port 2222' "$WORKDIR/leg-set.out" || fail "legacy set"
"$CTL" add service --preset ssh --id web >"$WORKDIR/leg-add.out"
grep -qx 'DISPATCH frp-client add-service --preset ssh --id web' "$WORKDIR/leg-add.out" || fail "legacy add"
pass "LEGACY_SERVICE_DISPATCH"

# System namespace
"$CTL" system update --check >"$WORKDIR/sys-upd.out"
grep -q 'DISPATCH' "$WORKDIR/sys-upd.out" || fail "system update --check"
export FRP_DOCTOR_SKIP_NETWORK=1
set +e
"$CTL" system doctor --skip-network >"$WORKDIR/sys-doc.out" 2>"$WORKDIR/sys-doc.err"
sys_doc_rc=$?
set -e
[[ "$sys_doc_rc" -eq 0 || "$sys_doc_rc" -eq 1 ]] || fail "system doctor rc=$sys_doc_rc"
grep -q 'FRP Auto Deploy Doctor\|DISPATCH' "$WORKDIR/sys-doc.out" || fail "system doctor body"
"$CTL" system support-bundle --output /tmp/x.zip >"$WORKDIR/sys-sb.out"
grep -q 'DISPATCH frp-support-bundle --output /tmp/x.zip' "$WORKDIR/sys-sb.out" || fail "system support-bundle"
"$CTL" support-bundle --output /tmp/y.zip >"$WORKDIR/leg-sb.out"
grep -q 'DISPATCH frp-support-bundle --output /tmp/y.zip' "$WORKDIR/leg-sb.out" || fail "legacy support-bundle"
pass "SYSTEM_NAMESPACE_DISPATCH"

# Client lifecycle dry-run
"$CTL" client pause >"$WORKDIR/pause.out"
grep -qx 'DISPATCH frp-client pause' "$WORKDIR/pause.out" || fail "client pause dry-run"
"$CTL" client resume >"$WORKDIR/resume.out"
grep -qx 'DISPATCH frp-client resume' "$WORKDIR/resume.out" || fail "client resume dry-run"
"$CTL" client uninstall --yes >"$WORKDIR/uninst.out"
grep -qx 'DISPATCH uninstall-client.sh' "$WORKDIR/uninst.out" || fail "client uninstall dry-run"
pass "CLIENT_LIFECYCLE_DISPATCH"

unset FRP_CTL_DRY_RUN

# Real pause/resume against fixture helpers (no systemd)
HOOK="$WORKDIR/hooks.log"
export FRP_CLIENT_HOOK_LOG="$HOOK"
: >"$HOOK"
"$ROOT/tools/frp-client" pause >"$WORKDIR/pause-real.out"
[[ -f "$CLIENT/etc/frp/client-paused" ]] || fail "pause marker missing"
grep -q 'Client paused' "$WORKDIR/pause-real.out" || fail "pause message"
"$ROOT/tools/frp-client" pause >"$WORKDIR/pause-again.out"
grep -qi 'already paused' "$WORKDIR/pause-again.out" || fail "pause idempotent"
"$ROOT/tools/frp-client" status >"$WORKDIR/status-paused.out"
grep -q 'Client state    : PAUSED' "$WORKDIR/status-paused.out" || fail "status paused"
grep -q 'Autostart       : disabled' "$WORKDIR/status-paused.out" || fail "status autostart disabled"
grep -q 'frpc            : inactive' "$WORKDIR/status-paused.out" || fail "status frpc inactive"

"$ROOT/tools/frp-client" resume >"$WORKDIR/resume-real.out"
[[ ! -f "$CLIENT/etc/frp/client-paused" ]] || fail "pause marker not cleared"
grep -q 'Client resumed' "$WORKDIR/resume-real.out" || fail "resume message"
"$ROOT/tools/frp-client" resume >"$WORKDIR/resume-again.out"
grep -qi 'already running' "$WORKDIR/resume-again.out" || fail "resume idempotent"
"$ROOT/tools/frp-client" status >"$WORKDIR/status-active.out"
grep -q 'Client state    : ACTIVE' "$WORKDIR/status-active.out" || fail "status active"

# Identity / services / ports unchanged
python3 - "$WORKDIR/state.before" "$CLIENT/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
a = json.loads(Path(sys.argv[1]).read_text())
b = json.loads(Path(sys.argv[2]).read_text())
assert a.get("machine_id") == b.get("machine_id")
assert a.get("host_id") == b.get("host_id")
assert a.get("services") == b.get("services")
print("state_ok")
PY
pass "CLIENT_PAUSE_RESUME_IDEMPOTENT"
pass "CLIENT_STATE_PRESERVED_ON_PAUSE"

# Context help
FRP_CTL_TEST_INPUT="$(printf '%s\n' 'service ?' 'client ?' 'system ?' exit)"
export FRP_CTL_TEST_INPUT
"$CTL" >"$WORKDIR/ctx.out" 2>"$WORKDIR/ctx.err" || true
grep -q 'Service management' "$WORKDIR/ctx.out" || fail "service ?"
grep -q 'Client lifecycle' "$WORKDIR/ctx.out" || fail "client ?"
grep -q 'System maintenance' "$WORKDIR/ctx.out" || fail "system ?"
pass "RESOURCE_CONTEXT_HELP"

# Uninstall confirmation + backend dispatch under test root
export FRP_CTL_DRY_RUN=1
FRP_CTL_TEST_INPUT="$(printf '%s\n' 'client uninstall' 'UNINSTALL' exit)"
export FRP_CTL_TEST_INPUT
"$CTL" >"$WORKDIR/uninst-confirm.out" 2>"$WORKDIR/uninst-confirm.err" || true
grep -q 'DISPATCH uninstall-client.sh' "$WORKDIR/uninst-confirm.out" || fail "uninstall confirm dispatch"
grep -q 'This removes FRP Auto Deploy from this machine' "$WORKDIR/uninst-confirm.out" || fail "uninstall warning"
pass "CLIENT_UNINSTALL_CONFIRM_DISPATCH"

echo "CLIENT_RESOURCE_CLI_TESTS=PASS"
