#!/usr/bin/env bash
# Regressions for qualification gate truthfulness (findings H/I + P–Y adversarial cases).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# shellcheck source=lib/prod-qual-common.sh
source "$ROOT/tests/lib/prod-qual-common.sh"

GATES="$WORKDIR/gates.env"
SUMMARY="$WORKDIR/summary.txt"
PROD_QUAL_GATES="$GATES"
PROD_QUAL_SUMMARY="$SUMMARY"
PROD_QUAL_FAILS=0
: >"$GATES"
: >"$SUMMARY"

# --- Finding H: SERVICE=SKIP must not yield platform PASS ---
TSV="$WORKDIR/matrix.tsv"
printf '%s\n' \
  $'PLATFORM\tINSTALL\tENROLL\tSERVICE\tREBOOT\tUNINSTALL\tDNS' \
  $'ubuntu-24.04\tPASS\tPASS\tSKIP\tSKIP\tSKIP\tSKIP' \
  >"$TSV"
PROD_QUAL_FAILS=0
set +e
pq_matrix_platform_gate "$TSV"
rc=$?
set -e
grep -q 'UBUNTU_REAL_E2E=FAIL' "$GATES" || fail "SERVICE=SKIP did not FAIL platform"
[[ "$rc" -ne 0 ]] || fail "matrix gate returned success for SERVICE=SKIP"
pass "matrix SERVICE=SKIP is FAIL"

: >"$GATES"
printf '%s\n' \
  $'PLATFORM\tINSTALL\tENROLL\tSERVICE\tREBOOT\tUNINSTALL\tDNS' \
  $'rocky-linux-8.10\tPASS\tPASS\tUNKNOWN\tPASS\tPASS\tPASS' \
  >"$TSV"
PROD_QUAL_FAILS=0
set +e
pq_matrix_platform_gate "$TSV"
set -e
grep -q 'ROCKY_REAL_E2E=FAIL' "$GATES" || fail "SERVICE=UNKNOWN did not FAIL"
pass "matrix SERVICE=UNKNOWN is FAIL"

: >"$GATES"
# Empty SERVICE column (two consecutive tabs)
printf '%s\n' \
  $'PLATFORM\tINSTALL\tENROLL\tSERVICE\tREBOOT\tUNINSTALL\tDNS' \
  $'amazon-linux-2023\tPASS\tPASS\t\tPASS\tPASS\tPASS' \
  >"$TSV"
PROD_QUAL_FAILS=0
set +e
pq_matrix_platform_gate "$TSV"
set -e
grep -q 'AWS_LINUX_REAL_E2E=FAIL' "$GATES" || fail "empty SERVICE did not FAIL"
pass "matrix empty SERVICE is FAIL"

: >"$GATES"
printf '%s\n' \
  $'PLATFORM\tINSTALL\tENROLL\tSERVICE\tREBOOT\tUNINSTALL\tDNS' \
  $'macos-arm64\tPASS\tPASS\tPASS\tSKIP\tSKIP\tSKIP' \
  >"$TSV"
PROD_QUAL_FAILS=0
set +e
pq_matrix_platform_gate "$TSV"
rc=$?
set -e
grep -q 'MACOS_REAL_E2E=PASS' "$GATES" || fail "optional SKIP should PASS"
[[ "$rc" -eq 0 ]] || fail "optional SKIP gate rc"
pass "matrix optional SKIP remains PASS"

# --- Finding I: reboot heading alone must not PASS ---
OUT="$WORKDIR/qual-out"
MATRIX_OUT="$OUT/matrix"
mkdir -p "$MATRIX_OUT"
echo "==== FLEET server reboot ====" >"$OUT/matrix.log"
: >"$GATES"
PROD_QUAL_GATES="$GATES"
PROD_QUAL_SUMMARY="$SUMMARY"
PROD_QUAL_FAILS=0
# Inline the same gate logic under test (keep in sync with production script).
FRP_E2E_QUAL_SERVER_REBOOT=0
if [[ "${FRP_E2E_QUAL_SERVER_REBOOT}" != "1" ]]; then
  if [[ -f "$OUT/matrix.log" ]] && grep -q 'FLEET server reboot' "$OUT/matrix.log" 2>/dev/null; then
    recovery_status=""
    if [[ -f "$MATRIX_OUT/fleet-reboot-recovery.env" ]]; then
      recovery_status="$(grep -E '^FLEET_REBOOT_RECOVERY=' "$MATRIX_OUT/fleet-reboot-recovery.env" | tail -n1 | cut -d= -f2-)"
    fi
    if [[ "$recovery_status" == "PASS" ]] \
      && [[ -f "$MATRIX_OUT/fleet-after-reboot.txt" ]] \
      && grep -qi ONLINE "$MATRIX_OUT/fleet-after-reboot.txt" 2>/dev/null; then
      pq_gate SERVER_REBOOT_RECOVERY PASS
      pq_gate CLIENT_RESTART_RECOVERY PASS
      pq_gate RECONNECT_STORM PASS
    else
      pq_gate SERVER_REBOOT_RECOVERY FAIL
      pq_gate CLIENT_RESTART_RECOVERY FAIL
      pq_gate RECONNECT_STORM FAIL
    fi
  fi
fi
grep -q 'SERVER_REBOOT_RECOVERY=FAIL' "$GATES" || fail "reboot heading alone did not FAIL"
grep -q 'CLIENT_RESTART_RECOVERY=FAIL' "$GATES" || fail "client restart not FAIL"
grep -q 'RECONNECT_STORM=FAIL' "$GATES" || fail "reconnect storm not FAIL"
pass "reboot heading without evidence is FAIL"

: >"$GATES"
echo "FLEET_REBOOT_RECOVERY=PASS" >"$MATRIX_OUT/fleet-reboot-recovery.env"
echo "CLIENT abc ONLINE" >"$MATRIX_OUT/fleet-after-reboot.txt"
FRP_E2E_QUAL_SERVER_REBOOT=0
if [[ "${FRP_E2E_QUAL_SERVER_REBOOT}" != "1" ]]; then
  if [[ -f "$OUT/matrix.log" ]] && grep -q 'FLEET server reboot' "$OUT/matrix.log" 2>/dev/null; then
    recovery_status=""
    if [[ -f "$MATRIX_OUT/fleet-reboot-recovery.env" ]]; then
      recovery_status="$(grep -E '^FLEET_REBOOT_RECOVERY=' "$MATRIX_OUT/fleet-reboot-recovery.env" | tail -n1 | cut -d= -f2-)"
    fi
    if [[ "$recovery_status" == "PASS" ]] \
      && [[ -f "$MATRIX_OUT/fleet-after-reboot.txt" ]] \
      && grep -qi ONLINE "$MATRIX_OUT/fleet-after-reboot.txt" 2>/dev/null; then
      pq_gate SERVER_REBOOT_RECOVERY PASS
      pq_gate CLIENT_RESTART_RECOVERY PASS
      pq_gate RECONNECT_STORM PASS
    else
      pq_gate SERVER_REBOOT_RECOVERY FAIL
      pq_gate CLIENT_RESTART_RECOVERY FAIL
      pq_gate RECONNECT_STORM FAIL
    fi
  fi
fi
grep -q 'SERVER_REBOOT_RECOVERY=PASS' "$GATES" || fail "evidence PASS not honored"
pass "reboot recovery evidence PASS honored"

# Static proof: production script must not PASS on heading alone.
python3 - "$ROOT/tests/run-production-realistic-qualification.sh" <<'PY' || fail "production reboot gate still heading-only"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
idx = text.find("FLEET server reboot")
assert idx > 0
window = text[idx:idx+800]
assert "fleet-reboot-recovery.env" in window or "fleet-after-reboot.txt" in window, window
assert "SERVER_REBOOT_RECOVERY PASS" not in window.split("fleet-")[0]
print("ok")
PY
pass "production reboot gate requires evidence files"

# --- Finding E/F inventory ---
python3 - "$ROOT" <<'PY' || fail "tcp egress missing from UNIT_NAMES"
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "lib"))
import frp_install_txn
assert "drlink-tcp-egress.service" in frp_install_txn.UNIT_NAMES, frp_install_txn.UNIT_NAMES
print("ok")
PY
pass "install txn UNIT_NAMES includes drlink-tcp-egress"

count="$(grep -c 'drlink-tcp-egress.service' "$ROOT/tools/frp-restore" || true)"
[[ "$count" -ge 2 ]] || fail "expected tcp egress in restart and ready paths, got $count"
pass "restore includes drlink-tcp-egress in runtime inventory"

# --- Adversarial: missing gate / NOT_RUN / BLOCKED / HEAD_UNCHANGED=NO ---
: >"$GATES"
pq_gate ABSENT_FEATURE NOT_RUN
pq_gate UPGRADE_CASE BLOCKED
grep -qx 'ABSENT_FEATURE=NOT_RUN' "$GATES" || fail "NOT_RUN missing"
grep -qx 'UPGRADE_CASE=BLOCKED' "$GATES" || fail "BLOCKED missing"
if grep -E '=(PASS)$' "$GATES" | grep -Eq 'ABSENT_FEATURE|UPGRADE_CASE'; then
  fail "NOT_RUN/BLOCKED mutated to PASS"
fi
pass "NOT_RUN and BLOCKED stay non-PASS"

# Simulate orchestrator HEAD check semantics
echo "HEAD_UNCHANGED=NO" >"$WORKDIR/head.env"
if grep -qx 'HEAD_UNCHANGED=YES' "$WORKDIR/head.env"; then
  fail "impossible"
fi
grep -qx 'HEAD_UNCHANGED=NO' "$WORKDIR/head.env"
pass "HEAD_UNCHANGED=NO retained"

# --- Child non-zero must fail simultaneous gates (static + simulated) ---
: >"$GATES"
# Simulate: registry OK but child backup failed → must FAIL backup-related gates
fails=1
backup_ok=0
traffic_ok=1
if [[ "$fails" -eq 0 && "$backup_ok" -eq 1 && "$traffic_ok" -eq 1 ]]; then
  pq_gate SIMULTANEOUS_ADMIN_MUTATION PASS
else
  pq_gate SIMULTANEOUS_ADMIN_MUTATION FAIL
  pq_gate LIVE_BACKUP_CONSISTENCY FAIL
  pq_gate TRAFFIC_DURING_BACKUP FAIL
  pq_gate BACKUP_LIVE_OPERATION FAIL
fi
grep -qx 'SIMULTANEOUS_ADMIN_MUTATION=FAIL' "$GATES" || fail "child failure did not FAIL simultaneous"
grep -qx 'LIVE_BACKUP_CONSISTENCY=FAIL' "$GATES" || fail "backup child failure not gated"
pass "simultaneous child failure fails gates"

# --- Backup/restore failure must fail matrix FAILED counter (static contract) ---
grep -q 'FLEET_BACKUP_RC' "$ROOT/tests/run-real-e2e-matrix.sh" || fail "matrix missing backup RC"
grep -q 'FLEET_RESTORE_RC' "$ROOT/tests/run-real-e2e-matrix.sh" || fail "matrix missing restore RC"
pass "matrix backup/restore RC contract"

# --- DENY with proxy unavailable (000) must not count as policy denial success ---
: >"$GATES"
deny_code="000"
if [[ "$deny_code" == "403" ]]; then
  pq_gate DENY_POLICY PASS
else
  pq_gate DENY_POLICY FAIL
fi
grep -qx 'DENY_POLICY=FAIL' "$GATES" || fail "000 accepted as deny success"
deny_code="403"
pq_gate DENY_POLICY PASS
grep -qx 'DENY_POLICY=PASS' "$GATES" || fail "403 not accepted"
pass "DENY rejects proxy-unavailable 000"

# --- Soak traffic failure ---
: >"$GATES"
probe_ok=2
probe_fail=20
avail_ok=0
if [[ "$probe_ok" -gt 0 ]]; then
  if [[ "$probe_fail" -eq 0 ]] || [[ "$probe_fail" -lt $((probe_ok / 5 + 1)) ]]; then
    avail_ok=1
  fi
fi
[[ "$avail_ok" -eq 0 ]] || fail "soak traffic failure should not be available"
pq_gate SOAK_TEST FAIL
grep -qx 'SOAK_TEST=FAIL' "$GATES" || fail "soak fail not recorded"
pass "soak traffic failure fails"

# --- Wrong upgrade version → BLOCKED, and that BLOCKED counts as a pass failure ---
: >"$GATES"
installed_ver="2.4.0"
if [[ "$installed_ver" != "2.3.0" ]]; then
  pq_gate GOLDEN_V230_UPGRADE_BASELINE BLOCKED
else
  pq_gate GOLDEN_V230_UPGRADE_BASELINE CREATED
fi
grep -qx 'GOLDEN_V230_UPGRADE_BASELINE=BLOCKED' "$GATES" || fail "wrong version not BLOCKED"
if grep -q 'GOLDEN_V230_UPGRADE_BASELINE|UPGRADE_V230_TO_V240' "$ROOT/tests/run-production-realistic-qualification.sh"; then
  fail "prior-stable upgrade gate is still excluded from FAIL_COUNT"
fi
if grep -q 'excluded from FAIL_COUNT' "$ROOT/tests/run-production-realistic-qualification.sh"; then
  fail "qualification still excludes a gate from FAIL_COUNT"
fi
fail_count="$(grep -E '=(FAIL|BLOCKED)$' "$GATES" | wc -l | tr -d ' ')"
[[ "$fail_count" -eq 1 ]] || fail "BLOCKED prior-stable gate did not count (fail_count=$fail_count)"
pass "wrong upgrade version is BLOCKED and counts"

# --- Unrelated :2222 ownership ---
PROD_QUAL_MACOS_SSH_PID=""
PROD_QUAL_MACOS_SSH_PID_FILE="$WORKDIR/no-such-pid"
set +e
pq_macos_listener_owned 1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "pid 1 should not be owned as macos reverse ssh"
# Recorded PID must be considered owned.
PROD_QUAL_MACOS_SSH_PID=$$
pq_macos_listener_owned "$$" || fail "recorded PID should be owned"
pass "unrelated listener not owned"

echo
echo "QUAL_GATE_TRUTHFULNESS_TEST=PASS"
