#!/usr/bin/env bash
# P1: fresh-install sandbox dirs + absent-unit rollback semantics.
set -euo pipefail

unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT \
  FRP_INSTALL_TXN_HOOK_SYSTEMCTL FRP_INSTALL_TXN_HOOK_SYSTEMD_FAIL \
  FRP_SERVER_UPGRADE_HOOK_ROLLBACK_SYSTEMD FRP_INSTALL_HOOK_START_FAIL \
  FRP_INSTALL_HOOK_HEALTH_FAIL || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
export FRP_SERVER_SOURCED=1
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

assert_mode() {
  local path="$1" expected="$2" mode
  mode="$(python3 - "$path" <<'PY'
import os, stat, sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
  [[ "$mode" == "$expected" ]] || fail "mode $path wanted $expected got $mode"
}

write_dummy_frps() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "frps version 0.70.1"
  exit 0
fi
if [[ "${1:-}" == "verify" ]]; then
  exit 0
fi
exit 0
EOF
  chmod 0755 "$dest"
}

write_mock_systemctl() {
  local dest="$1"
  cat >"$dest" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE="${FRP_MOCK_SYSTEMCTL_STATE:?}"
LOG="${FRP_MOCK_SYSTEMCTL_LOG:-}"
mkdir -p "$STATE"
[[ -z "$LOG" ]] || printf '%s\n' "$*" >>"$LOG"

unit=""
cmd="${1:-}"
shift || true
case "$cmd" in
  show)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -p|--value|LoadState) shift ;;
        *) unit="$1"; shift ;;
      esac
    done
    if [[ -f "${STATE}/${unit}.load" ]]; then
      cat "${STATE}/${unit}.load"
    else
      echo not-found
    fi
    exit 0
    ;;
  is-enabled)
    unit="${1:-}"
    if [[ -f "${STATE}/${unit}.enabled" ]]; then
      cat "${STATE}/${unit}.enabled"
      grep -qx enabled "${STATE}/${unit}.enabled" && exit 0
      exit 1
    fi
    echo not-found
    exit 1
    ;;
  is-active)
    unit="${1:-}"
    if [[ -f "${STATE}/${unit}.active" ]]; then
      cat "${STATE}/${unit}.active"
      grep -qx active "${STATE}/${unit}.active" && exit 0
      exit 3
    fi
    echo inactive
    exit 3
    ;;
  daemon-reload)
    exit 0
    ;;
  reset-failed)
    unit="${1:-}"
    echo reset-failed >>"${STATE}/${unit}.events"
    if [[ -f "${STATE}/${unit}.load" ]] && grep -qx not-found "${STATE}/${unit}.load"; then
      exit 1
    fi
    if [[ ! -f "${STATE}/${unit}.load" ]]; then
      exit 1
    fi
    echo inactive >"${STATE}/${unit}.active"
    exit 0
    ;;
  stop)
    unit="${1:-}"
    echo stop >>"${STATE}/${unit}.events"
    if [[ -f "${STATE}/${unit}.stop-fail" ]]; then
      exit 1
    fi
    load="not-found"
    [[ -f "${STATE}/${unit}.load" ]] && load="$(tr -d '\n' <"${STATE}/${unit}.load")"
    if [[ "$load" == "not-found" || -z "$load" ]]; then
      echo "Failed to stop ${unit}: Unit ${unit} not loaded." >&2
      exit 5
    fi
    echo inactive >"${STATE}/${unit}.active"
    exit 0
    ;;
  restart|start)
    unit="${1:-}"
    echo "$cmd" >>"${STATE}/${unit}.events"
    if [[ -f "${STATE}/${unit}.restart-fail" ]]; then
      exit 1
    fi
    echo loaded >"${STATE}/${unit}.load"
    echo active >"${STATE}/${unit}.active"
    exit 0
    ;;
  enable)
    unit="${1:-}"
    echo enable >>"${STATE}/${unit}.events"
    echo enabled >"${STATE}/${unit}.enabled"
    echo loaded >"${STATE}/${unit}.load"
    exit 0
    ;;
  disable)
    unit="${1:-}"
    echo disable >>"${STATE}/${unit}.events"
    echo disabled >"${STATE}/${unit}.enabled"
    echo loaded >"${STATE}/${unit}.load"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
  chmod +x "$dest"
}

seed_absent_units() {
  local state="$1"
  mkdir -p "$state"
  for unit in frps.service frp-port-allocator.service frp-frontend.service nginx.service; do
    echo not-found >"${state}/${unit}.load"
    echo not-found >"${state}/${unit}.enabled"
    echo inactive >"${state}/${unit}.active"
  done
}

write_dummy_frps "$WORKDIR/frps-0.70.1"
write_mock_systemctl "$WORKDIR/mock-systemctl"

export FRP_PUBLIC_IP=203.0.113.10
export FRP_INTERNAL_IP=203.0.113.10
export FRP_DEPLOYMENT_MODE=direct
export FRP_CONTROL_PUBLIC_PORT=443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=6099
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_ALLOCATOR_PUBLIC_URL=https://203.0.113.10:6099/enroll
export FRP_PORT_START=6000
export FRP_PORT_END=6098
export FRP_INSTALL_HOOK_NEW_BINARY="$WORKDIR/frps-0.70.1"
export FRP_INSTALL_HOOK_SKIP_SYSTEMD=1
unset FRP_SERVER_CONFIG FRP_PKI_DIR FRP_PUBLIC_HOSTNAME || true

# 1-3. Fresh install creates sandbox dirs with secure mode even if missing.
TREE="$WORKDIR/fresh"
mkdir -p "$TREE"
# Intentionally do not pre-create /var/log/frp-auto-deploy.
export FRP_SERVER_TEST_ROOT="$TREE"
if ! frp_server_main >"$WORKDIR/fresh.out" 2>"$WORKDIR/fresh.err"; then
  cat "$WORKDIR/fresh.out" "$WORKDIR/fresh.err" >&2
  fail "fresh install"
fi
[[ -d "$TREE/var/log/frp-auto-deploy" ]] || fail "log dir not created"
[[ -d "$TREE/var/lib/frp-auto-deploy" ]] || fail "var/lib not created"
[[ -d "$TREE/etc/frp-auto-deploy" ]] || fail "etc project dir missing"
[[ -d "$TREE/etc/frp" ]] || fail "etc/frp missing"
assert_mode "$TREE/var/log/frp-auto-deploy" "0o700"
assert_mode "$TREE/var/lib/frp-auto-deploy" "0o700"
assert_mode "$TREE/etc/frp-auto-deploy" "0o700"
assert_mode "$TREE/etc/frp" "0o700"
if [[ ${EUID} -eq 0 ]]; then
  owner="$(stat -c '%U:%G' "$TREE/var/log/frp-auto-deploy")"
  [[ "$owner" == "root:root" ]] || fail "log dir owner $owner"
fi
grep -q '^ProtectSystem=strict$' "$ROOT/server/frp-port-allocator.service" \
  || fail "allocator ProtectSystem weakened"
grep -q 'ReadWritePaths=/var/lib/frp-auto-deploy /var/log/frp-auto-deploy' \
  "$ROOT/server/frp-port-allocator.service" || fail "allocator ReadWritePaths weakened"
pass "FRESH_INSTALL_SANDBOX_DIRS"
pass "LOG_DIR_CREATED_WHEN_MISSING"
pass "SANDBOX_DIR_MODES"

# 4-9. Forced allocator start failure on a clean tree uses real txn apply-services.
FAIL="$WORKDIR/start-fail"
mkdir -p "$FAIL"
STATE="$WORKDIR/state-absent"
seed_absent_units "$STATE"
export FRP_SERVER_TEST_ROOT="$FAIL"
export FRP_INSTALL_HOOK_START_FAIL=1
export FRP_INSTALL_TXN_HOOK_SYSTEMCTL="$WORKDIR/mock-systemctl"
export FRP_MOCK_SYSTEMCTL_STATE="$STATE"
export FRP_MOCK_SYSTEMCTL_LOG="$WORKDIR/sys-absent.log"
if frp_server_main >"$WORKDIR/start-fail.out" 2>"$WORKDIR/start-fail.err"; then
  fail "start failure should not succeed"
fi
unset FRP_INSTALL_HOOK_START_FAIL
grep -q 'FAILURE_CLASS=SERVICE_START_FAILED' "$WORKDIR/start-fail.out" "$WORKDIR/start-fail.err" \
  || fail "start-fail class"
if grep -q 'UPGRADE_ROLLBACK=FAIL' "$WORKDIR/start-fail.out" "$WORKDIR/start-fail.err"; then
  fail "absent-unit rollback reported FAIL"
fi
if grep -q 'RECOVERY_REQUIRED=YES' "$WORKDIR/start-fail.out" "$WORKDIR/start-fail.err"; then
  fail "successful rollback set RECOVERY_REQUIRED"
fi
[[ ! -f "$FAIL/var/lib/frp-auto-deploy/server-update-pending.json" ]] \
  || fail "successful rollback left pending marker"
[[ ! -f "$FAIL/etc/systemd/system/frps.service" ]] || fail "frps unit remained"
[[ ! -f "$FAIL/etc/systemd/system/frp-port-allocator.service" ]] || fail "allocator unit remained"
[[ ! -f "$FAIL/etc/systemd/system/frp-frontend.service" ]] || fail "frontend unit remained"
if grep -E '^stop (frps|frp-port-allocator|frp-frontend)(\.service)?$' "$WORKDIR/sys-absent.log"; then
  fail "rollback stopped a previously absent unit: $(cat "$WORKDIR/sys-absent.log")"
fi
python3 - "$STATE" <<'PY' || fail "product unit left active after rollback"
from pathlib import Path
import sys
state = Path(sys.argv[1])
for unit in ("frps.service", "frp-port-allocator.service", "frp-frontend.service"):
    active = (state / (unit + ".active")).read_text(encoding="utf-8").strip()
    if active == "active":
        raise SystemExit(unit)
PY
# Test-mode install does not bind host ports; absence of active units is the
# listener/process restoration check for this fixture.
pass "ALLOCATOR_START_FAILURE_FRESH_INSTALL"
pass "ABSENT_UNIT_ROLLBACK"
pass "PENDING_CLEARED_AFTER_SUCCESSFUL_ROLLBACK"
pass "NO_PRODUCT_UNIT_ACTIVE_AFTER_ROLLBACK"

# 10. Genuine rollback failure retains the pending marker.
GEN="$WORKDIR/genuine-fail"
mkdir -p "$GEN"
export FRP_SERVER_TEST_ROOT="$GEN"
export FRP_INSTALL_HOOK_START_FAIL=1
export FRP_SERVER_UPGRADE_HOOK_ROLLBACK_SYSTEMD=1
unset FRP_INSTALL_TXN_HOOK_SYSTEMCTL || true
if frp_server_main >"$WORKDIR/genuine.out" 2>"$WORKDIR/genuine.err"; then
  fail "genuine rollback failure should not succeed"
fi
unset FRP_INSTALL_HOOK_START_FAIL FRP_SERVER_UPGRADE_HOOK_ROLLBACK_SYSTEMD
grep -q 'UPGRADE_ROLLBACK=FAIL' "$WORKDIR/genuine.out" "$WORKDIR/genuine.err" \
  || fail "genuine rollback missing FAIL"
grep -q 'RECOVERY_REQUIRED=YES' "$WORKDIR/genuine.out" "$WORKDIR/genuine.err" \
  || fail "genuine rollback missing recovery"
grep -q 'PENDING_MARKER_CLEARED=NO' "$WORKDIR/genuine.out" "$WORKDIR/genuine.err" \
  || fail "genuine rollback cleared marker flag"
[[ -f "$GEN/var/lib/frp-auto-deploy/server-update-pending.json" ]] \
  || fail "genuine rollback missing pending file"
pass "GENUINE_ROLLBACK_KEEPS_PENDING"

# 11-13. Existing-server apply_service_states preserves prior unit state.
python3 - "$ROOT" "$WORKDIR" <<'PY'
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "lib"))
import frp_install_txn

root = Path(sys.argv[2])
mock = str(root / "mock-systemctl")
os.environ["FRP_INSTALL_TXN_HOOK_SYSTEMCTL"] = mock
os.environ.pop("FRP_INSTALL_TXN_HOOK_SYSTEMD_FAIL", None)
os.environ.pop("FRP_SERVER_TEST_ROOT", None)

def seed(name, load, enabled, active, extra=None):
    state = root / name
    state.mkdir(parents=True, exist_ok=True)
    for unit in (
        "frps.service",
        "frp-port-allocator.service",
        "frp-frontend.service",
        "nginx.service",
    ):
        (state / (unit + ".load")).write_text(load + "\n", encoding="utf-8")
        (state / (unit + ".enabled")).write_text(enabled + "\n", encoding="utf-8")
        (state / (unit + ".active")).write_text(active + "\n", encoding="utf-8")
        if extra:
            (state / (unit + extra)).write_text("1\n", encoding="utf-8")
    os.environ["FRP_MOCK_SYSTEMCTL_STATE"] = str(state)
    os.environ["FRP_MOCK_SYSTEMCTL_LOG"] = str(root / (name + ".log"))
    return state

meta_active = {
    "services": {
        "skipped": False,
        "units": [
            {
                "unit": "frps.service",
                "existed": True,
                "load_state": "loaded",
                "enabled": "enabled",
                "active": "active",
            }
        ],
        "nginx": {"unit": "nginx.service", "existed": False, "enabled": "not-found", "active": "inactive", "load_state": "not-found"},
    }
}
seed("existing-active", "loaded", "enabled", "inactive")
if not frp_install_txn.apply_service_states(meta_active, skip=False):
    raise SystemExit("active restore failed")
events = (Path(os.environ["FRP_MOCK_SYSTEMCTL_STATE"]) / "frps.service.events").read_text(encoding="utf-8")
if "enable" not in events or "restart" not in events:
    raise SystemExit("active unit did not enable+restart: %s" % events)
if not frp_install_txn.verify_service_states(meta_active, skip=False):
    raise SystemExit("active verify failed")

meta_inactive = {
    "services": {
        "skipped": False,
        "units": [
            {
                "unit": "frps.service",
                "existed": True,
                "load_state": "loaded",
                "enabled": "disabled",
                "active": "inactive",
            }
        ],
        "nginx": {"existed": False, "enabled": "not-found", "active": "inactive", "load_state": "not-found"},
    }
}
seed("existing-inactive", "loaded", "enabled", "active")
if not frp_install_txn.apply_service_states(meta_inactive, skip=False):
    raise SystemExit("inactive restore failed")
events = (Path(os.environ["FRP_MOCK_SYSTEMCTL_STATE"]) / "frps.service.events").read_text(encoding="utf-8")
if "disable" not in events or "stop" not in events:
    raise SystemExit("inactive unit did not disable+stop: %s" % events)
if not frp_install_txn.verify_service_states(meta_inactive, skip=False):
    raise SystemExit("inactive verify failed")

# Previously absent + is-active inactive must not fail on stop-not-found.
meta_absent = {
    "services": {
        "skipped": False,
        "units": [
            {
                "unit": "frp-port-allocator.service",
                "existed": False,
                "load_state": "not-found",
                "enabled": "not-found",
                "active": "inactive",
            }
        ],
        "nginx": {"existed": False, "enabled": "not-found", "active": "inactive", "load_state": "not-found"},
    }
}
seed("compat-absent", "not-found", "not-found", "inactive")
if not frp_install_txn.apply_service_states(meta_absent, skip=False):
    raise SystemExit("absent inactive restore failed")
events_path = Path(os.environ["FRP_MOCK_SYSTEMCTL_STATE"]) / "frp-port-allocator.service.events"
events = events_path.read_text(encoding="utf-8") if events_path.is_file() else ""
if "stop" in events.split():
    raise SystemExit("absent unit invoked stop: %s" % events)

# Compatibility: old snapshots without existed, active=inactive, enabled=not-found.
meta_old = {
    "services": {
        "skipped": False,
        "units": [
            {
                "unit": "frps.service",
                "enabled": "not-found",
                "active": "inactive",
            }
        ],
    }
}
seed("compat-old", "not-found", "not-found", "inactive")
if not frp_install_txn.apply_service_states(meta_old, skip=False):
    raise SystemExit("old-snapshot absent restore failed")

# Existing unit that cannot be restored stays fail-closed.
seed("existing-stop-fail", "loaded", "disabled", "active", extra=".stop-fail")
if frp_install_txn.apply_service_states(meta_inactive, skip=False):
    raise SystemExit("stop failure should fail closed")

print("APPLY_SERVICE_STATE_SEMANTICS_OK")
PY
pass "EXISTING_ACTIVE_UNIT_RESTORED"
pass "EXISTING_INACTIVE_UNIT_RESTORED"
pass "ENABLED_DISABLED_PRESERVED"
pass "ABSENT_INACTIVE_DOES_NOT_FAIL_STOP"

# Dual-role: client files survive a failed server install rollback.
DUAL="$WORKDIR/dual"
mkdir -p "$DUAL/etc/frp" "$DUAL/usr/local/bin" "$DUAL/usr/local/lib/frp-auto-deploy"
printf '{"schema_version":1,"machine_id":"aabbccddeeff0011"}\n' >"$DUAL/etc/frp/client-state.json"
printf '#!/bin/true\n' >"$DUAL/usr/local/bin/frpctl"
printf '#!/bin/true\n' >"$DUAL/usr/local/bin/frp-client"
chmod +x "$DUAL/usr/local/bin/frpctl" "$DUAL/usr/local/bin/frp-client"
printf 'shared\n' >"$DUAL/usr/local/lib/frp-auto-deploy/frp-common.sh"
seed_absent_units "$WORKDIR/state-dual"
export FRP_SERVER_TEST_ROOT="$DUAL"
export FRP_INSTALL_HOOK_START_FAIL=1
export FRP_INSTALL_TXN_HOOK_SYSTEMCTL="$WORKDIR/mock-systemctl"
export FRP_MOCK_SYSTEMCTL_STATE="$WORKDIR/state-dual"
export FRP_MOCK_SYSTEMCTL_LOG="$WORKDIR/sys-dual.log"
if frp_server_main >"$WORKDIR/dual.out" 2>"$WORKDIR/dual.err"; then
  fail "dual-role start-fail should not succeed"
fi
unset FRP_INSTALL_HOOK_START_FAIL FRP_INSTALL_TXN_HOOK_SYSTEMCTL
[[ -f "$DUAL/etc/frp/client-state.json" ]] || fail "rollback removed client state"
[[ -x "$DUAL/usr/local/bin/frpctl" ]] || fail "rollback removed client frpctl"
pass "DUAL_ROLE_ROLLBACK_PRESERVES_CLIENT"

# Bash 4.2 (Amazon Linux 2) + set -u rejects empty "${arr[@]}".
if grep -nE '\$\{apply\[@\]\}' "$ROOT/install-server.sh"; then
  fail "empty-array restore args break bash 4.2 set -u"
fi
pass "BASH42_EMPTY_ARRAY_SAFE"

echo "FRESH_INSTALL_SANDBOX_ROLLBACK_TEST=PASS"
