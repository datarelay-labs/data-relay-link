#!/usr/bin/env bash
# Allocator HTTP readiness wait used by install-server.sh.
# Mocks systemd/curl; does not touch a live FRP install.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

unset FRP_PUBLIC_IP FRP_PUBLIC_HOST FRP_INTERNAL_IP FRP_CONTROL_PORT \
  FRP_PORT_START FRP_PORT_END FRP_ALLOCATOR_PORT FRP_ALLOCATOR_URL \
  FRP_ALLOCATOR_PUBLIC_URL FRP_CLIENT_INSTALLER_URL FRP_SERVER_CONFIG \
  DETECTED_PUBLIC_IP DETECTED_INTERNAL_IP \
  FRP_ALLOCATOR_READY_TIMEOUT_SEC FRP_ALLOCATOR_READY_INTERVAL_SEC || true

export FRP_SERVER_SOURCED=1
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"

ALLOC_ACTIVE=1
FRPS_ACTIVE=1
CURL_FAILS_REMAINING=0
CURL_ALWAYS_FAIL=0
CURL_CALLS=0
SLEEP_COUNT=0
IS_ACTIVE_CALLS=0
DIE_AFTER_ACTIVE_CALLS=0

reset_ready_mocks() {
  ALLOC_ACTIVE=1
  FRPS_ACTIVE=1
  CURL_FAILS_REMAINING=0
  CURL_ALWAYS_FAIL=0
  CURL_CALLS=0
  SLEEP_COUNT=0
  IS_ACTIVE_CALLS=0
  DIE_AFTER_ACTIVE_CALLS=0
  export FRP_ALLOCATOR_READY_TIMEOUT_SEC=2
  export FRP_ALLOCATOR_READY_INTERVAL_SEC=0.05
}

frp_server_systemctl() {
  case "${1:-}" in
    is-active)
      local unit="${3:-}"
      if [[ "$unit" == "frp-port-allocator" ]]; then
        IS_ACTIVE_CALLS=$((IS_ACTIVE_CALLS + 1))
        if [[ "$DIE_AFTER_ACTIVE_CALLS" -gt 0 && "$IS_ACTIVE_CALLS" -gt "$DIE_AFTER_ACTIVE_CALLS" ]]; then
          ALLOC_ACTIVE=0
        fi
        if [[ "$ALLOC_ACTIVE" == "1" ]]; then
          return 0
        fi
        return 3
      fi
      if [[ "$unit" == "frps" && "$FRPS_ACTIVE" == "1" ]]; then
        return 0
      fi
      return 3
      ;;
    status)
      echo "MOCK-SYSTEMCTL-STATUS ${2:-unknown}"
      echo "     Active: mock"
      return 0
      ;;
    *)
      echo "MOCK-SYSTEMCTL ${*}"
      return 0
      ;;
  esac
}

frp_server_curl() {
  CURL_CALLS=$((CURL_CALLS + 1))
  if [[ "$CURL_ALWAYS_FAIL" == "1" ]]; then
    return 7
  fi
  if [[ "$CURL_FAILS_REMAINING" -gt 0 ]]; then
    CURL_FAILS_REMAINING=$((CURL_FAILS_REMAINING - 1))
    return 7
  fi
  printf '%s\n' '{"status": "ok"}'
  return 0
}

frp_server_journalctl() {
  echo "MOCK-JOURNALCTL ${*}"
  return 0
}

frp_server_sleep() {
  SLEEP_COUNT=$((SLEEP_COUNT + 1))
  sleep "$@"
}

# --- Immediate /healthz success, no sleep.
reset_ready_mocks
if ! frp_wait_allocator_ready 6099 >"$WORKDIR/immediate.out" 2>"$WORKDIR/immediate.err"; then
  cat "$WORKDIR/immediate.out" "$WORKDIR/immediate.err" >&2
  fail "immediate ready should succeed"
fi
[[ "$CURL_CALLS" -eq 1 ]] || fail "immediate ready curl count"
[[ "$SLEEP_COUNT" -eq 0 ]] || fail "immediate ready should not sleep"
pass "SERVER_ALLOCATOR_IMMEDIATE_READY"

# --- Healthz fails a few times, then succeeds.
reset_ready_mocks
CURL_FAILS_REMAINING=3
if ! frp_wait_allocator_ready 6099 >"$WORKDIR/delayed.out" 2>"$WORKDIR/delayed.err"; then
  cat "$WORKDIR/delayed.out" "$WORKDIR/delayed.err" >&2
  fail "delayed ready should succeed"
fi
[[ "$CURL_CALLS" -ge 4 ]] || fail "delayed ready retry count"
[[ "$SLEEP_COUNT" -ge 3 ]] || fail "delayed ready should retry"
grep -q 'Waiting for FRP allocator HTTPS listener' "$WORKDIR/delayed.out" || fail "delayed ready wait message"
pass "SERVER_ALLOCATOR_DELAYED_READY"

# --- Healthz never succeeds: bounded timeout, non-zero exit.
reset_ready_mocks
CURL_ALWAYS_FAIL=1
export FRP_ALLOCATOR_READY_TIMEOUT_SEC=2
export FRP_ALLOCATOR_READY_INTERVAL_SEC=0.1
set +e
frp_wait_allocator_ready 6099 >"$WORKDIR/timeout.out" 2>"$WORKDIR/timeout.err"
timeout_rc=$?
set -e
[[ "$timeout_rc" -ne 0 ]] || fail "timeout should fail"
grep -q 'ERROR: FRP allocator did not become ready within 2 seconds' "$WORKDIR/timeout.err" || fail "timeout error text"
[[ "$SLEEP_COUNT" -ge 1 ]] || fail "timeout should have retried"
[[ "$CURL_CALLS" -ge 2 ]] || fail "timeout should have curled more than once"
pass "SERVER_ALLOCATOR_TIMEOUT"

# --- Service dies while waiting: fail early, not after full timeout.
reset_ready_mocks
CURL_ALWAYS_FAIL=1
DIE_AFTER_ACTIVE_CALLS=2
export FRP_ALLOCATOR_READY_TIMEOUT_SEC=10
export FRP_ALLOCATOR_READY_INTERVAL_SEC=0.05
start_s="$(date +%s)"
set +e
frp_wait_allocator_ready 6099 >"$WORKDIR/dies.out" 2>"$WORKDIR/dies.err"
dies_rc=$?
set -e
end_s="$(date +%s)"
[[ "$dies_rc" -ne 0 ]] || fail "service death should fail"
grep -q 'stopped before becoming ready' "$WORKDIR/dies.err" || fail "service death error text"
if grep -q 'did not become ready within' "$WORKDIR/dies.err"; then
  fail "service death waited for full timeout"
fi
elapsed=$((end_s - start_s))
[[ "$elapsed" -lt 5 ]] || fail "service death did not fail early (elapsed=${elapsed}s)"
pass "SERVER_ALLOCATOR_SERVICE_DIES"

# --- Failure path prints systemd/journal diagnostics without secrets.
reset_ready_mocks
CURL_ALWAYS_FAIL=1
export FRP_ALLOCATOR_READY_TIMEOUT_SEC=1
export FRP_ALLOCATOR_READY_INTERVAL_SEC=0.1
set +e
frp_wait_allocator_ready 6099 >"$WORKDIR/diag.out" 2>"$WORKDIR/diag.err"
set -e
grep -q 'MOCK-SYSTEMCTL-STATUS frp-port-allocator' "$WORKDIR/diag.err" || fail "missing systemctl status"
grep -q 'MOCK-JOURNALCTL' "$WORKDIR/diag.err" || fail "missing journalctl"
if grep -qiE 'server_token|auth.token|BEGIN .*PRIVATE KEY|enrollment' "$WORKDIR/diag.out" "$WORKDIR/diag.err"; then
  fail "diagnostics leaked secret-like text"
fi
pass "SERVER_ALLOCATOR_DIAGNOSTICS"

# --- Installer no longer assumes a fixed 2s sleep.
if grep -nE '^[[:space:]]*sleep[[:space:]]+2[[:space:]]*$' "$ROOT/install-server.sh"; then
  fail "install-server.sh still has a fixed sleep 2"
fi
grep -q 'frp_wait_allocator_ready' "$ROOT/install-server.sh" || fail "missing wait helper"
grep -q 'frp_wait_unit_active frps' "$ROOT/install-server.sh" || fail "missing frps active wait"
pass "NO_FIXED_TWO_SECOND_ASSUMPTION"

echo
echo "ALLOCATOR_READY_TEST=PASS"
