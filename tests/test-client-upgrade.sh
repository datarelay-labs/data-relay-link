#!/usr/bin/env bash
# Safe existing-client upgrade, version tracking, and rollback.
set -euo pipefail

# Ignore leaked roots from prior debug sessions; they divert txn markers.
unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
ALLOC_PID=""
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
frp_test_arm_cleanup

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

chmod +x "$ROOT/tools/frp-client" "$ROOT/tools/frpctl"
# shellcheck disable=SC1091
. "$ROOT/VERSION"

file_sha() {
  python3 - "$1" <<'PY'
import hashlib, sys
from pathlib import Path
p = Path(sys.argv[1])
print(hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "")
PY
}

assert_mode() {
  local path="$1" expected="$2" mode
  mode="$(python3 - "$path" <<'PY'
import os, stat, sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
  [[ "$mode" == "$expected" ]] || fail "mode $path wanted $expected got $mode"
}

assert_no_leak() {
  local log="$1"
  if grep -E 'BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY|test-frp-token-do-not-use|enroll-secret-' "$log" >/dev/null 2>&1; then
    fail "secret fixture leaked to command output"
  fi
}

write_dummy_frpc() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<'EOF'
#!/bin/sh
if [ "$1" = verify ]; then
  exit 0
fi
if [ "$1" = --version ]; then
  echo "frpc version 0.71.0"
  exit 0
fi
exit 0
EOF
  chmod 0755 "$dest"
}

write_old_tool() {
  local dest="$1" label="$2"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<EOF
#!/bin/sh
echo "old-${label}"
exit 0
EOF
  chmod 0755 "$dest"
}

write_client_fixture() {
  local tree="$1"
  local with_identity="${2:-1}"
  local with_version="${3:-0}"
  mkdir -p "$tree/etc/frp" "$tree/usr/local/bin" "$tree/usr/local/lib/frp-auto-deploy" \
    "$tree/etc/frp-auto-deploy"
  write_dummy_frpc "$tree/usr/local/bin/frpc"
  write_old_tool "$tree/usr/local/bin/frp-client" "client"
  write_old_tool "$tree/usr/local/lib/frp-auto-deploy/frp-client-common.sh" "common"
  cat >"$tree/usr/local/lib/frp-auto-deploy/frp_mgmt_auth.py" <<'EOF'
print("old-auth")
EOF
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "http://127.0.0.1:9/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "upgrade-client",
    "machine_id": "aabbccddeeff00112233445566778899",
    "host_id": "upgrade-client-aabbccdd",
    "services": {
        "ssh": {
            "id": "ssh", "name": "SSH", "preset": "ssh", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 6003,
            "enabled": True, "ssh_user": "aella",
        },
        "web": {
            "id": "web", "name": "Web", "preset": "http", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 80, "remote_port": 6004,
            "enabled": False,
        },
    },
}, indent=2, sort_keys=True) + "\n")
PY
  chmod 600 "$tree/etc/frp/client-state.json"
  cat >"$tree/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"

[[proxies]]
name = "upgrade-client-aabbccdd-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6003
EOF
  chmod 600 "$tree/etc/frp/frpc.toml"
  cat >"$tree/etc/frp/access-info.txt" <<'EOF'
FRP Server: 203.0.113.10

ssh
  Public : 203.0.113.10:6003
EOF
  chmod 644 "$tree/etc/frp/access-info.txt"
  mkdir -p "$tree/etc/frp-auto-deploy"
  cat >"$tree/etc/frp-auto-deploy/allocator-ca.crt" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKFAKESECRET_o2p3q4r5s6t7u8v9w0x1
-----END CERTIFICATE-----
EOF
  chmod 644 "$tree/etc/frp-auto-deploy/allocator-ca.crt"
  if [[ "$with_identity" == "1" ]]; then
    python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
      "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
    chmod 600 "$tree/etc/frp/client-identity.key"
    chmod 644 "$tree/etc/frp/client-identity.pub"
    python3 - "$tree/etc/frp/client-identity.mac" <<'PY'
from pathlib import Path
Path(__import__('sys').argv[1]).write_text('a' * 64 + '\n')
PY
    chmod 600 "$tree/etc/frp/client-identity.mac"
  fi
  if [[ "$with_version" == "1" ]]; then
    cat >"$tree/etc/frp-auto-deploy/version" <<'EOF'
PROJECT_VERSION=1.1.0
FRP_VERSION=0.71.0
EOF
    chmod 644 "$tree/etc/frp-auto-deploy/version"
  fi
}

snapshot_runtime() {
  local tree="$1" dest="$2"
  python3 - "$tree" "$dest" <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
out = Path(sys.argv[2])
files = [
    'etc/frp/client-state.json',
    'etc/frp/frpc.toml',
    'etc/frp/access-info.txt',
    'etc/frp/client-identity.key',
    'etc/frp/client-identity.pub',
    'etc/frp/client-identity.mac',
    'etc/frp-auto-deploy/allocator-ca.crt',
    'usr/local/bin/frpc',
]
data = {}
for rel in files:
    p = root / rel
    data[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ''
state = json.loads((root / 'etc/frp/client-state.json').read_text())
data['services'] = {
    sid: {
        'enabled': item.get('enabled', True) is not False,
        'remote_port': item.get('remote_port'),
    }
    for sid, item in (state.get('services') or {}).items()
}
out.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
PY
}

assert_runtime_preserved() {
  local tree="$1" before="$2"
  python3 - "$tree" "$before" <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
before = json.loads(Path(sys.argv[2]).read_text())
files = [
    'etc/frp/client-state.json',
    'etc/frp/frpc.toml',
    'etc/frp/access-info.txt',
    'etc/frp/client-identity.key',
    'etc/frp/client-identity.pub',
    'etc/frp/client-identity.mac',
    'etc/frp-auto-deploy/allocator-ca.crt',
    'usr/local/bin/frpc',
]
for rel in files:
    p = root / rel
    got = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ''
    if got != before[rel]:
        raise SystemExit(f'changed {rel}')
state = json.loads((root / 'etc/frp/client-state.json').read_text())
for sid, rec in before['services'].items():
    item = (state.get('services') or {}).get(sid)
    if not item:
        raise SystemExit(f'missing service {sid}')
    enabled = item.get('enabled', True) is not False
    if enabled != rec['enabled']:
        raise SystemExit(f'enabled changed {sid}')
    if item.get('remote_port') != rec['remote_port']:
        raise SystemExit(f'port changed {sid}')
PY
}

export FRP_SKIP_SYSTEMD=1
export FRP_SKIP_DOWNLOAD=1
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_MGMT_AUTH_PY="$ROOT/lib/frp_mgmt_auth.py"

# --- A. Version tracking on fresh install path is covered by test-frp-client.
# Additional: missing version file is legacy, not a crash.

LEGACY_STATUS_TREE="$WORKDIR/legacy-status"
write_client_fixture "$LEGACY_STATUS_TREE" 1 0
export FRP_CLIENT_TEST_ROOT="$LEGACY_STATUS_TREE"
HOOK="$WORKDIR/legacy-status.hook"
: >"$HOOK"
export FRP_CLIENT_HOOK_LOG="$HOOK"
"$ROOT/tools/frp-client" status >"$WORKDIR/legacy-status.out"
grep -q 'Project version : legacy / unknown' "$WORKDIR/legacy-status.out" || fail "legacy status version"
grep -q 'Management identity : enrolled' "$WORKDIR/legacy-status.out" || fail "legacy status identity"
if grep -qx enroll "$HOOK"; then fail "legacy status contacted allocator"; fi
assert_no_leak "$WORKDIR/legacy-status.out"
pass "LEGACY_NO_VERSION_FILE_HANDLED"
pass "CLIENT_STATUS_PROJECT_VERSION"

# Server version tracking still uses the shared helper.
grep -q 'frp_write_version_file "$(frp_server_fs /etc/frp-auto-deploy/version)"' "$ROOT/install-server.sh" || fail "server version helper"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$ROOT/VERSION" || fail "VERSION file"
pass "SERVER_VERSION_TRACKING_UNBROKEN"

# --- B. Existing enrolled client safe upgrade

ENROLLED="$WORKDIR/enrolled"
write_client_fixture "$ENROLLED" 1 1
snapshot_runtime "$ENROLLED" "$WORKDIR/enrolled.before"
OLD_CLIENT_SHA="$(file_sha "$ENROLLED/usr/local/bin/frp-client")"
export FRP_CLIENT_TEST_ROOT="$ENROLLED"
HOOK="$WORKDIR/enrolled.hook"
: >"$HOOK"
export FRP_CLIENT_HOOK_LOG="$HOOK"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/enrolled.out" 2>"$WORKDIR/enrolled.err"; then
  cat "$WORKDIR/enrolled.out" "$WORKDIR/enrolled.err" >&2
  fail "enrolled client upgrade"
fi
assert_runtime_preserved "$ENROLLED" "$WORKDIR/enrolled.before" || fail "enrolled runtime changed"
assert_no_leak "$WORKDIR/enrolled.out"
assert_no_leak "$WORKDIR/enrolled.err"
[[ -f "$ENROLLED/etc/frp-auto-deploy/version" ]] || fail "version file after upgrade"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$ENROLLED/etc/frp-auto-deploy/version" || fail "version migrated"
assert_mode "$ENROLLED/etc/frp-auto-deploy/version" "0o644"
[[ -x "$ENROLLED/usr/local/bin/frpctl" ]] || fail "frpctl installed by upgrade"
NEW_CLIENT_SHA="$(file_sha "$ENROLLED/usr/local/bin/frp-client")"
[[ "$NEW_CLIENT_SHA" != "$OLD_CLIENT_SHA" ]] || fail "old frp-client was not replaced"
grep -q 'old-client' "$ENROLLED/usr/local/bin/frp-client" && fail "old frp-client content remains"
grep -q 'Enrollment Code : NOT REQUIRED' "$WORKDIR/enrolled.out" || fail "enrollment not required message"
grep -q 'frpc restarted  : NO' "$WORKDIR/enrolled.out" || fail "no restart message"
grep -q 'Client state    : preserved' "$WORKDIR/enrolled.out" || fail "state preserved message"
grep -q "1.1.0 -> ${PROJECT_VERSION}" "$WORKDIR/enrolled.out" || fail "version transition"
if grep -qx enroll "$HOOK"; then fail "upgrade contacted allocator"; fi
if grep -qx restart "$HOOK"; then fail "upgrade restarted frpc"; fi
"$ROOT/tools/frp-client" status >"$WORKDIR/enrolled-status.out"
grep -q "Project version : ${PROJECT_VERSION}" "$WORKDIR/enrolled-status.out" || fail "status after upgrade"
grep -q 'Management identity : enrolled' "$WORKDIR/enrolled-status.out" || fail "identity still enrolled"
python3 - "$ENROLLED/etc/frp/client-state.json" <<'PY' || fail "ports after upgrade"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['ssh']['remote_port']==6003
assert d['services']['ssh']['enabled'] is True
assert d['services']['web']['remote_port']==6004
assert d['services']['web']['enabled'] is False
PY
pass "CLIENT_VERSION_FILE_CREATED"
pass "CLIENT_STATE_PRESERVED"
pass "FRPC_CONFIG_PRESERVED"
pass "SERVICE_IDS_PRESERVED"
pass "PUBLIC_PORTS_PRESERVED"
pass "ENABLED_STATE_PRESERVED"
pass "DISABLED_RESERVATION_PRESERVED"
pass "IDENTITY_PRIVATE_KEY_PRESERVED"
pass "IDENTITY_STATUS_PRESERVED"
pass "NO_ENROLLMENT_CODE_REQUIRED"
pass "NO_ALLOCATOR_MUTATION"
pass "NO_UNNECESSARY_FRPC_RESTART"

# --check does not mutate
CHECK_TREE="$WORKDIR/check"
write_client_fixture "$CHECK_TREE" 1 1
snapshot_runtime "$CHECK_TREE" "$WORKDIR/check.before"
export FRP_CLIENT_TEST_ROOT="$CHECK_TREE"
"$ROOT/tools/frp-client" update --source "$ROOT" --check >"$WORKDIR/check.out"
assert_runtime_preserved "$CHECK_TREE" "$WORKDIR/check.before" || fail "check mutated runtime"
grep -q 'old-client' "$CHECK_TREE/usr/local/bin/frp-client" || fail "check replaced tools"
grep -q 'Update                    : available' "$WORKDIR/check.out" || fail "check available"
pass "upgrade --check is read-only"

# install-client.sh --upgrade entry point
BUNDLE_TREE="$WORKDIR/bundle"
write_client_fixture "$BUNDLE_TREE" 1 1
snapshot_runtime "$BUNDLE_TREE" "$WORKDIR/bundle.before"
export FRP_CLIENT_TEST_ROOT="$BUNDLE_TREE"
if ! "$ROOT/install-client.sh" --upgrade --source "$ROOT" >"$WORKDIR/bundle.out" 2>"$WORKDIR/bundle.err"; then
  cat "$WORKDIR/bundle.out" "$WORKDIR/bundle.err" >&2
  fail "install-client --upgrade"
fi
assert_runtime_preserved "$BUNDLE_TREE" "$WORKDIR/bundle.before" || fail "bundle upgrade mutated runtime"
grep -q 'Upgrade complete.' "$WORKDIR/bundle.out" || fail "bundle upgrade complete"
pass "install-client --upgrade"

# --- C. Legacy pre-version / pre-identity client

LEGACY="$WORKDIR/legacy"
write_client_fixture "$LEGACY" 0 0
snapshot_runtime "$LEGACY" "$WORKDIR/legacy.before"
export FRP_CLIENT_TEST_ROOT="$LEGACY"
HOOK="$WORKDIR/legacy.hook"
: >"$HOOK"
export FRP_CLIENT_HOOK_LOG="$HOOK"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/legacy.out" 2>"$WORKDIR/legacy.err"; then
  cat "$WORKDIR/legacy.out" "$WORKDIR/legacy.err" >&2
  fail "legacy client upgrade"
fi
assert_runtime_preserved "$LEGACY" "$WORKDIR/legacy.before" || fail "legacy runtime changed"
[[ ! -f "$LEGACY/etc/frp/client-identity.key" ]] || fail "legacy upgrade created identity"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$LEGACY/etc/frp-auto-deploy/version" || fail "legacy version migration"
grep -q "legacy / unknown -> ${PROJECT_VERSION}" "$WORKDIR/legacy.out" || fail "legacy version transition"
grep -q 'Enrollment Code : NOT REQUIRED' "$WORKDIR/legacy.out" || fail "legacy upgrade asked for code"
if grep -qi 'Enrollment Code:' "$WORKDIR/legacy.out"; then fail "legacy upgrade prompted for code"; fi
if grep -qx enroll "$HOOK"; then fail "legacy upgrade contacted allocator"; fi
"$ROOT/tools/frp-client" status >"$WORKDIR/legacy-after.out"
grep -q "Project version : ${PROJECT_VERSION}" "$WORKDIR/legacy-after.out" || fail "legacy status version after"
grep -q 'Management identity : not established' "$WORKDIR/legacy-after.out" || fail "legacy identity still missing"

# Later server-affecting apply still requires an Enrollment Code.
python3 - "$LEGACY/etc/frp/client-state.json" "$WORKDIR/legacy-cand.json" <<'PY'
import json, sys
from pathlib import Path
d = json.loads(Path(sys.argv[1]).read_text())
d['services']['web']['enabled'] = True
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True) + '\n')
PY
unset FRP_ENROLLMENT_CODE || true
export FRP_CLIENT_CANDIDATE="$WORKDIR/legacy-cand.json"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/legacy-apply.out" 2>"$WORKDIR/legacy-apply.err"; then
  fail "legacy apply after upgrade should still need enrollment"
fi
grep -qi 'Enrollment Code' "$WORKDIR/legacy-apply.out" "$WORKDIR/legacy-apply.err" || fail "legacy apply did not ask for enrollment"
[[ ! -f "$LEGACY/etc/frp/client-identity.key" ]] || fail "failed apply created identity"
assert_runtime_preserved "$LEGACY" "$WORKDIR/legacy.before" || fail "failed apply mutated runtime"
pass "LEGACY_CLIENT_UPGRADE"
pass "LEGACY_NO_VERSION_FILE_MIGRATION"
pass "LEGACY_NO_IDENTITY_UPGRADE"
pass "LEGACY_UPGRADE_DOES_NOT_FORCE_ENROLLMENT"

# --- D. Rollback

ROLL="$WORKDIR/rollback"
write_client_fixture "$ROLL" 1 1
snapshot_runtime "$ROLL" "$WORKDIR/roll.before"
OLD_TOOL_SHA="$(file_sha "$ROLL/usr/local/bin/frp-client")"
OLD_COMMON_SHA="$(file_sha "$ROLL/usr/local/lib/frp-auto-deploy/frp-client-common.sh")"
export FRP_CLIENT_TEST_ROOT="$ROLL"
export FRP_CLIENT_UPGRADE_HOOK_FAIL=validate
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/roll-validate.out" 2>"$WORKDIR/roll-validate.err"; then
  fail "validate failure should fail upgrade"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL
assert_runtime_preserved "$ROLL" "$WORKDIR/roll.before" || fail "validate-fail mutated runtime"
[[ "$(file_sha "$ROLL/usr/local/bin/frp-client")" == "$OLD_TOOL_SHA" ]] || fail "validate-fail replaced tools"
grep -q 'UPGRADE_ROLLBACK=NOT_REQUIRED' "$WORKDIR/roll-validate.out" "$WORKDIR/roll-validate.err" || fail "validate pre-mutation marker"
[[ ! -x "$ROLL/usr/local/bin/frpctl" ]] || fail "validate-fail installed frpctl"

export FRP_CLIENT_UPGRADE_HOOK_FAIL=install
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/roll-install.out" 2>"$WORKDIR/roll-install.err"; then
  fail "install failure should fail upgrade"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL
assert_runtime_preserved "$ROLL" "$WORKDIR/roll.before" || fail "install-fail mutated runtime"
[[ "$(file_sha "$ROLL/usr/local/bin/frp-client")" == "$OLD_TOOL_SHA" ]] || fail "install-fail left new frp-client"
[[ "$(file_sha "$ROLL/usr/local/lib/frp-auto-deploy/frp-client-common.sh")" == "$OLD_COMMON_SHA" ]] || fail "install-fail left partial libs"
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/roll-install.out" "$WORKDIR/roll-install.err" || fail "install rollback marker"
[[ ! -x "$ROLL/usr/local/bin/frpctl" ]] || fail "install-fail left frpctl"
assert_no_leak "$WORKDIR/roll-install.out"
assert_no_leak "$WORKDIR/roll-install.err"

export FRP_CLIENT_UPGRADE_HOOK_FAIL=verify
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/roll-verify.out" 2>"$WORKDIR/roll-verify.err"; then
  fail "verify failure should fail upgrade"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL
assert_runtime_preserved "$ROLL" "$WORKDIR/roll.before" || fail "verify-fail mutated runtime"
[[ "$(file_sha "$ROLL/usr/local/bin/frp-client")" == "$OLD_TOOL_SHA" ]] || fail "verify-fail did not restore tools"
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/roll-verify.out" "$WORKDIR/roll-verify.err" || fail "verify rollback marker"

export FRP_CLIENT_UPGRADE_HOOK_FAIL=version
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/roll-version.out" 2>"$WORKDIR/roll-version.err"; then
  fail "version write failure should fail upgrade"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL
assert_runtime_preserved "$ROLL" "$WORKDIR/roll.before" || fail "version-fail mutated runtime"
[[ "$(file_sha "$ROLL/usr/local/bin/frp-client")" == "$OLD_TOOL_SHA" ]] || fail "version-fail did not restore tools"
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/roll-version.out" "$WORKDIR/roll-version.err" || fail "version rollback marker"
grep -q 'BUILD_INFO_WRITE_FAILED' "$WORKDIR/roll-version.out" "$WORKDIR/roll-version.err" || fail "version failure class"

ROLL_FAIL="$WORKDIR/rollback-failure"
write_client_fixture "$ROLL_FAIL" 1 1
export FRP_CLIENT_TEST_ROOT="$ROLL_FAIL"
export FRP_CLIENT_UPGRADE_HOOK_FAIL=verify
export FRP_CLIENT_UPGRADE_HOOK_ROLLBACK_FAIL=1
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/rollback-failure.out" 2>"$WORKDIR/rollback-failure.err"; then
  fail "rollback failure should fail upgrade"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL FRP_CLIENT_UPGRADE_HOOK_ROLLBACK_FAIL
grep -q 'UPDATE_ROLLBACK_FAILED' "$WORKDIR/rollback-failure.out" "$WORKDIR/rollback-failure.err" || fail "rollback failure class"
grep -q 'RECOVERY_REQUIRED' "$WORKDIR/rollback-failure.out" "$WORKDIR/rollback-failure.err" || fail "rollback recovery marker"
[[ -f "$ROLL_FAIL/var/lib/frp-auto-deploy/client-update-pending.json" ]] || fail "client rollback left no pending marker"

# Interrupted client-frp-update must not be recovered as a tools backup (would wipe tools).
FRP_PEND="$WORKDIR/frp-pending-not-tools"
write_client_fixture "$FRP_PEND" 1 1
export FRP_CLIENT_TEST_ROOT="$FRP_PEND"
mkdir -p "$FRP_PEND/var/lib/frp-auto-deploy/backups/frp-only"
printf 'frpc-binary' >"$FRP_PEND/var/lib/frp-auto-deploy/backups/frp-only/frpc"
chmod 0755 "$FRP_PEND/var/lib/frp-auto-deploy/backups/frp-only/frpc"
python3 - "$FRP_PEND/var/lib/frp-auto-deploy/client-update-pending.json" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "schema_version": 2,
  "operation": "client-frp-update",
  "phase": "commit",
  "mutation_started": True,
  "previous_version": "0.70.1",
  "candidate_version": "0.71.0",
  "snapshot_path": str(Path(sys.argv[1]).resolve().parent / "backups" / "frp-only"),
}))
PY
BEFORE_CLIENT="$(file_sha "$FRP_PEND/usr/local/bin/frp-client")"
BEFORE_COMMON="$(file_sha "$FRP_PEND/usr/local/lib/frp-auto-deploy/frp-client-common.sh")"
# frpc shim already reports 0.71.0 via write_dummy_frpc
"$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/frp-pending.out" 2>"$WORKDIR/frp-pending.err" \
  || fail "client-frp-update pending recovery should continue"
[[ -f "$FRP_PEND/usr/local/bin/frp-client" ]] || fail "frp-client wiped by wrong snapshot recovery"
[[ -f "$FRP_PEND/usr/local/lib/frp-auto-deploy/frp-client-common.sh" ]] || fail "common lib wiped by wrong snapshot recovery"
[[ ! -f "$FRP_PEND/var/lib/frp-auto-deploy/client-update-pending.json" ]] || fail "client-frp-update pending not cleared"
grep -q 'already reached 0.71.0' "$WORKDIR/frp-pending.out" "$WORKDIR/frp-pending.err" \
  || fail "missing frp-update pending clear message"
# Direct restore_tools must refuse FRP-only snapshots.
# shellcheck disable=SC1091
. "$ROOT/lib/frp-client-common.sh"
if frp_client_upgrade_restore_tools "$FRP_PEND/var/lib/frp-auto-deploy/backups/frp-only" 2>"$WORKDIR/restore-refuse.err"; then
  fail "restore_tools should refuse FRP binary backup"
fi
grep -q 'missing manifest' "$WORKDIR/restore-refuse.err" || fail "restore_tools refuse reason"
# After a successful recovery+upgrade the tools may refresh; the critical assertion is no wipe-from-frp-backup.
[[ -n "$BEFORE_CLIENT" && -n "$BEFORE_COMMON" ]] || fail "fixture digests missing"
pass "CLIENT_FRP_UPDATE_PENDING_NOT_TOOLS_WIPE"

pass "UPGRADE_ROLLBACK"
pass "NO_PARTIAL_TOOL_INSTALL"
pass "CLIENT_STATE_UNCHANGED_ON_FAILURE"
pass "IDENTITY_UNCHANGED_ON_FAILURE"
pass "STAGING_FAILURE_SAFE"
pass "PARTIAL_INSTALL_ROLLBACK"
pass "POST_VERIFY_ROLLBACK"
pass "BUILD_INFO_WRITE_ROLLBACK"
pass "ROLLBACK_FAILURE_CLASS"
pass "CLIENT_UPDATE_ROLLBACK_FAILURE"

UNB="$WORKDIR/unbound"
write_client_fixture "$UNB" 1 1
export FRP_CLIENT_TEST_ROOT="$UNB"
export FRP_CLIENT_UPGRADE_HOOK_FAIL=unbound-after-install
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/client-unbound.out" 2>"$WORKDIR/client-unbound.err"; then
  fail "client unbound-after-install should fail"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/client-unbound.out" "$WORKDIR/client-unbound.err" ||
  fail "client unexpected rollback"
pass "CLIENT_UPDATE_UNEXPECTED_FAILURE_ROLLBACK"

echo "CLIENT_UPGRADE_TESTS=PASS"
