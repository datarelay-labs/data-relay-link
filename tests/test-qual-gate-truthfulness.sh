#!/usr/bin/env bash
# Regressions for qualification gate truthfulness (findings H/I) and TCP egress inventory.
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
if grep -n "FLEET server reboot" "$ROOT/tests/run-production-realistic-qualification.sh" | head -5; then
  :
fi
python3 - "$ROOT/tests/run-production-realistic-qualification.sh" <<'PY' || fail "production reboot gate still heading-only"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
# The anti-pattern: grep heading then immediately pq_gate PASS without evidence file.
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

echo
echo "QUAL_GATE_TRUTHFULNESS_TEST=PASS"
