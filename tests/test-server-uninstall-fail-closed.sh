#!/usr/bin/env bash
# Finding D: server uninstall/purge is fail-closed on stop/lock failure.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

MOCK="$WORKDIR/mock-systemctl"
cat >"$MOCK" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
log="${FRP_MOCK_SYSTEMCTL_LOG:-}"
if [[ -n "$log" ]]; then
  printf '%s\n' "$*" >>"$log"
fi
cmd="${1:-}"
shift || true
unit=""
for arg in "$@"; do
  case "$arg" in
    -p|--value|LoadState) continue ;;
    *) unit="$arg" ;;
  esac
done
state_dir="${FRP_MOCK_UNIT_DIR:-}"
fail_stop="${FRP_MOCK_STOP_FAIL:-0}"
still_active="${FRP_MOCK_STILL_ACTIVE:-0}"
fail_disable="${FRP_MOCK_DISABLE_FAIL:-0}"
unit_state() {
  if [[ -f "${state_dir}/${1}.active" ]]; then
    echo active
  elif [[ -f "${state_dir}/${1}.loaded" ]]; then
    echo inactive
  else
    echo not-found
  fi
}
case "$cmd" in
  show)
    st="$(unit_state "$unit")"
    if [[ "$st" == "not-found" ]]; then
      echo not-found
    else
      echo loaded
    fi
    exit 0
    ;;
  is-active)
    st="$(unit_state "$unit")"
    if [[ "$st" == "active" ]]; then
      echo active
      exit 0
    fi
    echo inactive
    exit 3
    ;;
  stop)
    if [[ "$fail_stop" == "1" ]]; then
      exit 1
    fi
    if [[ "$still_active" != "1" && -n "$state_dir" ]]; then
      rm -f "${state_dir}/${unit}.active"
      : >"${state_dir}/${unit}.loaded"
    fi
    exit 0
    ;;
  disable)
    if [[ "$fail_disable" == "1" ]]; then
      exit 1
    fi
    exit 0
    ;;
  is-enabled)
    if [[ -f "${state_dir}/${unit}.enabled" ]]; then
      echo enabled
      exit 0
    fi
    echo disabled
    exit 1
    ;;
  daemon-reload|reset-failed)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
chmod +x "$MOCK"

seed() {
  local tree="$1"
  mkdir -p \
    "$tree/etc/drlink/pki" \
    "$tree/etc/frp" \
    "$tree/var/lib/drlink" \
    "$tree/usr/local/sbin" \
    "$tree/usr/local/bin" \
    "$tree/usr/local/lib/drlink" \
    "$tree/etc/systemd/system"
  printf '{"deployment_mode":"direct"}\n' >"$tree/etc/drlink/config.json"
  printf 'token-secret\n' >"$tree/etc/frp/server_token"
  printf '{"schema_version":2,"clients":{},"reserved":[6001]}\n' \
    >"$tree/var/lib/drlink/registry.json"
  printf 'ca-key\n' >"$tree/etc/drlink/pki/ca.key"
  printf 'ca-crt\n' >"$tree/etc/drlink/pki/ca.crt"
  printf 'srv-key\n' >"$tree/etc/drlink/pki/server.key"
  printf 'srv-crt\n' >"$tree/etc/drlink/pki/server.crt"
  printf 'bindPort = 443\n' >"$tree/etc/frp/frps.toml"
  printf 'PROJECT_VERSION=2.1.3\n' >"$tree/etc/drlink/version"
  printf '#!/bin/true\n' >"$tree/usr/local/sbin/frpctl"
  chmod +x "$tree/usr/local/sbin/frpctl"
  printf '[Unit]\nDescription=frps\n' >"$tree/etc/systemd/system/drlink-server.service"
}

assert_state_present() {
  local tree="$1"
  [[ -f "$tree/etc/frp/server_token" ]] || fail "token missing"
  [[ -f "$tree/etc/drlink/pki/ca.key" ]] || fail "CA missing"
  [[ -f "$tree/var/lib/drlink/registry.json" ]] || fail "registry missing"
}

# 1. normal inactive uninstall
TREE="$WORKDIR/inactive"
seed "$TREE"
UNIT="$WORKDIR/units-inactive"
mkdir -p "$UNIT"
: >"$UNIT/drlink-server.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_UNINSTALL_HOOK_SYSTEMCTL="$MOCK"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_MOCK_SYSTEMCTL_LOG="$WORKDIR/inactive.log"
export FRP_PURGE_CONFIRM=yes
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/inactive.out" 2>"$WORKDIR/inactive.err"; then
  fail "inactive uninstall: $(cat "$WORKDIR/inactive.err")"
fi
assert_state_present "$TREE"
grep -q 'preserved' "$WORKDIR/inactive.out" || fail "inactive preserve message"
pass "UNINSTALL_INACTIVE"

# 2. already-uninstalled idempotent
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/idemp.out" 2>"$WORKDIR/idemp.err"; then
  fail "idempotent uninstall: $(cat "$WORKDIR/idemp.err")"
fi
pass "UNINSTALL_IDEMPOTENT"

# 3. service stop failure
TREE="$WORKDIR/stopfail"
seed "$TREE"
UNIT="$WORKDIR/units-stopfail"
mkdir -p "$UNIT"
: >"$UNIT/drlink-server.active"
: >"$UNIT/drlink-server.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_MOCK_STOP_FAIL=1
if "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/stop.out" 2>"$WORKDIR/stop.err"; then
  fail "stop failure uninstall succeeded"
fi
grep -q 'FAILURE_CLASS=SERVICE_STOP_FAILED' "$WORKDIR/stop.err" || fail "stop failure class"
assert_state_present "$TREE"
pass "UNINSTALL_STOP_FAILURE"

# 4. remains active after stop
export FRP_MOCK_STOP_FAIL=0
export FRP_MOCK_STILL_ACTIVE=1
if "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/still.out" 2>"$WORKDIR/still.err"; then
  fail "still-active uninstall succeeded"
fi
grep -q 'FAILURE_CLASS=SERVICE_STILL_ACTIVE' "$WORKDIR/still.err" || fail "still-active class"
assert_state_present "$TREE"
pass "UNINSTALL_STILL_ACTIVE"
unset FRP_MOCK_STILL_ACTIVE

# 5. disable failure while still enabled
TREE="$WORKDIR/disablefail"
seed "$TREE"
UNIT="$WORKDIR/units-disable"
mkdir -p "$UNIT"
: >"$UNIT/drlink-server.loaded"
: >"$UNIT/drlink-server.enabled"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_MOCK_DISABLE_FAIL=1
if "$ROOT/uninstall-server.sh" >"$WORKDIR/dis.out" 2>"$WORKDIR/dis.err"; then
  fail "disable failure uninstall succeeded"
fi
grep -q 'FAILURE_CLASS=SERVICE_DISABLE_FAILED' "$WORKDIR/dis.err" || fail "disable class"
assert_state_present "$TREE"
pass "UNINSTALL_DISABLE_FAILURE"
unset FRP_MOCK_DISABLE_FAIL

# 6. lock contention
TREE="$WORKDIR/lock"
seed "$TREE"
UNIT="$WORKDIR/units-lock"
mkdir -p "$UNIT"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_UNINSTALL_LOCK_TIMEOUT=1
LOCK="$TREE/var/lib/drlink/registry.lock"
: >"$LOCK"
python3 - "$LOCK" <<'PY' &
import fcntl
import os
import sys
import time

fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
time.sleep(8)
PY
LOCK_PID=$!
sleep 0.2
if "$ROOT/uninstall-server.sh" >"$WORKDIR/lock.out" 2>"$WORKDIR/lock.err"; then
  kill "$LOCK_PID" 2>/dev/null || true
  fail "lock contention uninstall succeeded"
fi
kill "$LOCK_PID" 2>/dev/null || true
wait "$LOCK_PID" 2>/dev/null || true
grep -q 'FAILURE_CLASS=LOCK_CONTENTION' "$WORKDIR/lock.err" || fail "lock class $(cat "$WORKDIR/lock.err")"
assert_state_present "$TREE"
pass "UNINSTALL_LOCK_CONTENTION"
unset FRP_UNINSTALL_LOCK_TIMEOUT

# 7/8. purge refuses when stop fails; state untouched
TREE="$WORKDIR/purgefail"
seed "$TREE"
UNIT="$WORKDIR/units-purgefail"
mkdir -p "$UNIT"
: >"$UNIT/drlink-server.active"
: >"$UNIT/drlink-server.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_MOCK_STOP_FAIL=1
TOKEN_BEFORE="$(cat "$TREE/etc/frp/server_token")"
if "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/purgefail.out" 2>"$WORKDIR/purgefail.err"; then
  fail "purge succeeded after stop failure"
fi
[[ "$(cat "$TREE/etc/frp/server_token")" == "$TOKEN_BEFORE" ]] || fail "purge mutated token after stop fail"
assert_state_present "$TREE"
pass "PURGE_FAIL_CLOSED"
unset FRP_MOCK_STOP_FAIL

# 9. default uninstall preserves secrets
TREE="$WORKDIR/preserve"
seed "$TREE"
UNIT="$WORKDIR/units-preserve"
mkdir -p "$UNIT"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/preserve.out" 2>"$WORKDIR/preserve.err"; then
  fail "preserve uninstall: $(cat "$WORKDIR/preserve.err")"
fi
assert_state_present "$TREE"
pass "UNINSTALL_PRESERVES_STATE"

# 10. purge success removes intended state
TREE="$WORKDIR/purgesuccess"
seed "$TREE"
UNIT="$WORKDIR/units-purgeok"
mkdir -p "$UNIT"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
if ! "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/purgeok.out" 2>"$WORKDIR/purgeok.err"; then
  fail "purge success: $(cat "$WORKDIR/purgeok.err")"
fi
[[ ! -f "$TREE/etc/frp/server_token" ]] || fail "purge left token"
[[ ! -f "$TREE/etc/drlink/pki/ca.key" ]] || fail "purge left CA"
[[ ! -f "$TREE/var/lib/drlink/registry.json" ]] || fail "purge left registry"
pass "PURGE_SUCCESS"

# 11. dual-role server uninstall preserves client
TREE="$WORKDIR/dual"
seed "$TREE"
printf '{"schema_version":1,"machine_id":"aabb"}\n' >"$TREE/etc/frp/client-state.json"
printf '#!/bin/true\n' >"$TREE/usr/local/bin/frp-client"
printf '#!/bin/true\n' >"$TREE/usr/local/bin/drlink"
chmod +x "$TREE/usr/local/bin/frp-client" "$TREE/usr/local/bin/drlink"
printf 'shared\n' >"$TREE/usr/local/lib/drlink/frp-common.sh"
UNIT="$WORKDIR/units-dual"
mkdir -p "$UNIT"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/dual.out" 2>"$WORKDIR/dual.err"; then
  fail "dual-role uninstall: $(cat "$WORKDIR/dual.err")"
fi
[[ -f "$TREE/etc/frp/client-state.json" ]] || fail "dual-role removed client state"
[[ -x "$TREE/usr/local/bin/drlink" ]] || fail "dual-role removed client frpctl"
[[ -f "$TREE/usr/local/lib/drlink/frp-common.sh" ]] || fail "dual-role removed shared lib"
pass "DUAL_ROLE_SERVER_UNINSTALL"

# 12. second uninstall remains safe
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/dual2.out" 2>"$WORKDIR/dual2.err"; then
  fail "second dual-role uninstall: $(cat "$WORKDIR/dual2.err")"
fi
[[ -f "$TREE/etc/frp/client-state.json" ]] || fail "second uninstall removed client"
pass "SECOND_UNINSTALL_SAFE"

# 13. util-linux flock CLI must not be required (Amazon Linux containers)
TREE="$WORKDIR/noflock"
seed "$TREE"
UNIT="$WORKDIR/units-noflock"
mkdir -p "$UNIT"
NOFLOCK="$WORKDIR/noflock-bin"
mkdir -p "$NOFLOCK"
printf '#!/bin/sh\necho flock-should-not-run >&2\nexit 127\n' >"$NOFLOCK/flock"
chmod +x "$NOFLOCK/flock"
if ! (
  export FRP_UNINSTALL_TEST_ROOT="$TREE"
  export FRP_MOCK_UNIT_DIR="$UNIT"
  export PATH="$NOFLOCK:$PATH"
  "$ROOT/uninstall-server.sh" >"$WORKDIR/noflock.out" 2>"$WORKDIR/noflock.err"
); then
  fail "uninstall without flock CLI: $(cat "$WORKDIR/noflock.err")"
fi
grep -q flock-should-not-run "$WORKDIR/noflock.err" && fail "uninstall invoked flock CLI"
assert_state_present "$TREE"
pass "UNINSTALL_WITHOUT_FLOCK_CLI"

# 12. control-state.lock contention (NEW-002)
TREE="$WORKDIR/ctrl-lock"
seed "$TREE"
printf '{"schema_version":2,"egress_profiles":{}}\n' >"$TREE/var/lib/drlink/egress-control.json"
UNIT="$WORKDIR/units-ctrl-lock"
mkdir -p "$UNIT"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_UNINSTALL_LOCK_TIMEOUT=1
CTRL_LOCK="$TREE/var/lib/drlink/control-state.lock"
: >"$CTRL_LOCK"
python3 - "$CTRL_LOCK" <<'PY' &
import fcntl
import os
import sys
import time

fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
time.sleep(8)
PY
CTRL_PID=$!
sleep 0.2
if "$ROOT/uninstall-server.sh" >"$WORKDIR/ctrl-lock.out" 2>"$WORKDIR/ctrl-lock.err"; then
  kill "$CTRL_PID" 2>/dev/null || true
  fail "control-state lock contention uninstall succeeded"
fi
kill "$CTRL_PID" 2>/dev/null || true
wait "$CTRL_PID" 2>/dev/null || true
grep -q 'FAILURE_CLASS=LOCK_CONTENTION' "$WORKDIR/ctrl-lock.err" \
  || fail "control-state lock class $(cat "$WORKDIR/ctrl-lock.err")"
assert_state_present "$TREE"
pass "UNINSTALL_CONTROL_STATE_LOCK_CONTENTION"
unset FRP_UNINSTALL_LOCK_TIMEOUT

# 13. active control-state mutation cannot race destructive uninstall
TREE="$WORKDIR/mut-vs-uninst"
seed "$TREE"
printf '{"schema_version":2,"egress_profiles":{}}\n' >"$TREE/var/lib/drlink/egress-control.json"
printf '{"schema_version":1,"access_lists":{},"service_access":{}}\n' \
  >"$TREE/var/lib/drlink/access-control.json"
printf '{"schema_version":1,"profiles":{}}\n' >"$TREE/var/lib/drlink/service-profiles.json"
printf '{"deployment_mode":"direct","egress_control_file":"/var/lib/drlink/egress-control.json"}\n' \
  >"$TREE/etc/drlink/config.json"
UNIT="$WORKDIR/units-mut-uninst"
mkdir -p "$UNIT"
READY="$WORKDIR/uninst.ready"
GO="$WORKDIR/uninst.go"
rm -f "$READY" "$GO"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_UNINSTALL_LOCK_HOOK_READY="$READY"
export FRP_UNINSTALL_LOCK_HOOK_GO="$GO"
export FRP_UNINSTALL_LOCK_HOOK_WAIT=15
"$ROOT/uninstall-server.sh" >"$WORKDIR/mut-uninst.out" 2>"$WORKDIR/mut-uninst.err" &
UNINST_PID=$!
for _ in $(seq 1 80); do
  [[ -f "$READY" ]] && break
  sleep 0.05
done
[[ -f "$READY" ]] || { kill "$UNINST_PID" 2>/dev/null || true; fail "uninstall lock hook"; }
BEFORE="$(cat "$TREE/var/lib/drlink/egress-control.json")"
if FRP_DEPLOY_TEST_ROOT="$TREE" FRP_CONTROL_STATE_LOCK_TIMEOUT=1 \
  python3 "$ROOT/tools/frp-egress" create raced-profile \
  >"$WORKDIR/mut-uninst-cli.out" 2>"$WORKDIR/mut-uninst-cli.err"; then
  kill "$UNINST_PID" 2>/dev/null || true
  fail "egress mutation succeeded during uninstall lock hold"
fi
grep -q 'timed out waiting for control-state lock' "$WORKDIR/mut-uninst-cli.err" \
  || fail "mutation did not fail-closed on uninstall lock: $(cat "$WORKDIR/mut-uninst-cli.err")"
[[ "$(cat "$TREE/var/lib/drlink/egress-control.json")" == "$BEFORE" ]] \
  || fail "egress state mutated during uninstall"
assert_state_present "$TREE"
touch "$GO"
wait "$UNINST_PID" || fail "uninstall after mutation contention: $(cat "$WORKDIR/mut-uninst.err")"
unset FRP_UNINSTALL_LOCK_HOOK_READY FRP_UNINSTALL_LOCK_HOOK_GO FRP_UNINSTALL_LOCK_HOOK_WAIT
pass "UNINSTALL_VS_CONTROL_STATE_MUTATION"

# Unrelated admin frps.service must remain enabled/running/untouched.
TREE="$WORKDIR/admin-frps"
seed "$TREE"
cat >"$TREE/etc/systemd/system/frps.service" <<'EOF'
[Unit]
Description=Company Custom FRP Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/custom/frps -c /opt/custom/frps.ini
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
UNIT="$WORKDIR/units-admin-frps"
mkdir -p "$UNIT"
: >"$UNIT/frps.active"
: >"$UNIT/frps.loaded"
: >"$UNIT/frps.enabled"
: >"$UNIT/drlink-server.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_MOCK_SYSTEMCTL_LOG="$WORKDIR/admin-frps.log"
: >"$WORKDIR/admin-frps.log"
export FRP_MOCK_STOP_FAIL=0
export FRP_MOCK_DISABLE_FAIL=0
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/admin-frps.out" 2>"$WORKDIR/admin-frps.err"; then
  fail "admin frps uninstall: $(cat "$WORKDIR/admin-frps.err")"
fi
[[ -f "$TREE/etc/systemd/system/frps.service" ]] || fail "admin frps.service removed"
grep -q 'non-product frps.service' "$WORKDIR/admin-frps.err" || fail "missing admin frps warn"
if grep -E '^(stop|disable)( |$).*frps' "$WORKDIR/admin-frps.log" >/dev/null 2>&1; then
  fail "admin frps touched via systemctl"
fi
[[ -f "$UNIT/frps.active" ]] || fail "admin frps mock active cleared"
[[ -f "$UNIT/frps.enabled" ]] || fail "admin frps mock enabled cleared"
pass "UNRELATED_ADMIN_FRPS_PRESERVED"

echo "SERVER_UNINSTALL_FAIL_CLOSED_TEST=PASS"
echo "NEW_002_UNINSTALL_CONTROL_STATE_LOCK=PASS"
