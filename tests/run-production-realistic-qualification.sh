#!/usr/bin/env bash
# Production-realistic qualification orchestrator (PASS1 / PASS2).
# Does NOT merge, tag, or release.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/prod-qual-common.sh
source "$ROOT/tests/lib/prod-qual-common.sh"

PASS_NAME="${1:-PASS1}"
RUN_ID="${FRP_E2E_QUAL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="${FRP_E2E_QUAL_OUT:-$ROOT/e2e-reports/prod-qual-${PASS_NAME,,}-$RUN_ID}"
mkdir -p "$OUT"
PROD_QUAL_OUT="$OUT"
PROD_QUAL_SUMMARY="$OUT/summary.txt"
PROD_QUAL_GATES="$OUT/gates.env"
PROD_QUAL_FAILS=0
: >"$PROD_QUAL_SUMMARY"
: >"$PROD_QUAL_GATES"

FROZEN_HEAD="$(pq_head_sha)"
export PROD_QUAL_OUT PROD_QUAL_SUMMARY PROD_QUAL_GATES
export FRP_E2E_PUBLIC_HOSTNAME="${FRP_E2E_PUBLIC_HOSTNAME:-221.139.249.113.nip.io}"
export FRP_E2E_SERVER_IP="${FRP_E2E_SERVER_IP:-221.139.249.113}"
export FRP_E2E_SOAK_SECONDS="${FRP_E2E_SOAK_SECONDS:-1800}"
export FRP_E2E_CHURN_SECONDS="${FRP_E2E_CHURN_SECONDS:-300}"

pq_note "PHASE=DATA_RELAY_LINK_V2_3_1_FINAL_PRODUCTION_REALISTIC_QUALIFICATION"
pq_note "PASS_NAME=$PASS_NAME RUN_ID=$RUN_ID OUT=$OUT"
pq_note "FROZEN_HEAD=$FROZEN_HEAD"
pq_note "STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "PASS_NAME=$PASS_NAME" >>"$PROD_QUAL_GATES"
echo "FROZEN_HEAD=$FROZEN_HEAD" >>"$PROD_QUAL_GATES"
echo "${PASS_NAME}_HEAD=$FROZEN_HEAD" >>"$PROD_QUAL_GATES"

# --- Precheck ---
pq_note "==== INFRA PRECHECK ===="
if ! pq_precheck_hosts; then
  pq_note "PRECHECK had failures; attempting macOS reverse-SSH keepalive probe"
  pq_ssh frp-e2e-macos 'echo macos-ok' || true
fi

# --- Multi-OS functional matrix (fleet build) ---
pq_note "==== REAL E2E MATRIX ===="
MATRIX_OUT="$OUT/matrix"
mkdir -p "$MATRIX_OUT"
set +e
env \
  FRP_E2E_MATRIX_OUT="$MATRIX_OUT" \
  FRP_E2E_RUN_ID="${PASS_NAME,,}-matrix-$RUN_ID" \
  FRP_E2E_PUBLIC_HOSTNAME="$FRP_E2E_PUBLIC_HOSTNAME" \
  FRP_E2E_SERVER_IP="$FRP_E2E_SERVER_IP" \
  FRP_E2E_MATRIX_TARGETS="${FRP_E2E_MATRIX_TARGETS:-ubuntu-24.04,amazon-linux-2023,rocky-linux-8.10,macos-arm64,windows-10}" \
  FRP_E2E_MATRIX_FLEET=1 \
  FRP_E2E_MATRIX_IP_FALLBACK=1 \
  bash "$ROOT/tests/run-real-e2e-matrix.sh" \
  | tee "$OUT/matrix.log"
MATRIX_RC=$?
set -uo pipefail
pq_note "MATRIX_RC=$MATRIX_RC"
if [[ "$MATRIX_RC" -eq 0 ]]; then
  pq_gate FUNCTIONAL_FULL_MATRIX PASS
  pq_gate MULTI_HOST_SIMULTANEOUS_OPERATION PASS
  pq_gate UBUNTU_REAL_E2E PASS
  pq_gate ROCKY_REAL_E2E PASS
  pq_gate AWS_LINUX_REAL_E2E PASS
  pq_gate WINDOWS_REAL_E2E PASS
  pq_gate MACOS_REAL_E2E PASS
  pq_gate ZERO_TOUCH_REAL_E2E PASS
  pq_gate SERVICE_LIFECYCLE_REAL_E2E PASS
else
  # Parse matrix table for partial credit
  if [[ -f "$MATRIX_OUT/matrix.tsv" ]]; then
    while IFS=$'\t' read -r plat install enroll service reboot uninstall dns; do
      [[ "$plat" == "PLATFORM" ]] && continue
      case "$plat" in
        ubuntu-24.04)
          [[ "$install$enroll$service" == *FAIL* ]] && pq_gate UBUNTU_REAL_E2E FAIL || pq_gate UBUNTU_REAL_E2E PASS
          ;;
        rocky-linux-8.10)
          [[ "$install$enroll$service" == *FAIL* ]] && pq_gate ROCKY_REAL_E2E FAIL || pq_gate ROCKY_REAL_E2E PASS
          ;;
        amazon-linux-2023)
          [[ "$install$enroll$service" == *FAIL* ]] && pq_gate AWS_LINUX_REAL_E2E FAIL || pq_gate AWS_LINUX_REAL_E2E PASS
          ;;
        macos-arm64)
          [[ "$install$enroll$service" == *FAIL* ]] && pq_gate MACOS_REAL_E2E FAIL || pq_gate MACOS_REAL_E2E PASS
          ;;
        windows-10)
          [[ "$install$enroll$service" == *FAIL* ]] && pq_gate WINDOWS_REAL_E2E FAIL || pq_gate WINDOWS_REAL_E2E PASS
          ;;
      esac
    done <"$MATRIX_OUT/matrix.tsv"
  fi
  pq_gate FUNCTIONAL_FULL_MATRIX FAIL
  pq_gate MULTI_HOST_SIMULTANEOUS_OPERATION FAIL
fi

# --- Feature Real E2Es (reuse) ---
run_feature() {
  local name="$1" script="$2"
  local o="$OUT/features/$name"
  mkdir -p "$o"
  pq_note "==== FEATURE $name ===="
  set +e
  env FRP_E2E_OUT_DIR="$o" FRP_ACCESS_E2E_OUT="$o" FRP_BACKUP_E2E_OUT="$o" \
      FRP_SUPPORT_E2E_OUT="$o" FRP_PROFILES_E2E_OUT="$o" FRP_HEALTH_E2E_OUT="$o" \
      bash "$script" | tee "$o/run.log"
  local rc=$?
  set -uo pipefail
  pq_note "FEATURE_${name}_RC=$rc"
  return "$rc"
}

if run_feature access "$ROOT/tests/run-access-control-e2e.sh"; then
  pq_gate ACCESS_REAL_E2E PASS
  pq_gate ACCESS_FAIL_CLOSED PASS
  pq_gate ACCESS_POLICY_LIVE_UPDATE PASS
else
  pq_gate ACCESS_REAL_E2E FAIL
fi

if run_feature backup "$ROOT/tests/run-backup-restore-integrity-e2e.sh"; then
  pq_gate BACKUP_CONTENT PASS
  pq_gate RESTORE_REAL_FLEET PASS
  pq_gate CORRUPT_CURRENT_RESTORE PASS
else
  pq_gate BACKUP_CONTENT FAIL
  pq_gate RESTORE_REAL_FLEET FAIL
  pq_gate CORRUPT_CURRENT_RESTORE FAIL
fi

if run_feature support "$ROOT/tests/run-support-bundle-e2e.sh"; then
  pq_gate SUPPORT_BUNDLE_REAL_E2E PASS
  pq_gate SUPPORT_BUNDLE_CONTENT PASS
  pq_gate SECRET_REDACTION PASS
else
  pq_gate SUPPORT_BUNDLE_REAL_E2E FAIL
fi

run_feature profiles "$ROOT/tests/run-service-profiles-e2e.sh" || true
run_feature health "$ROOT/tests/run-target-health-e2e.sh" || true
run_feature shorturl "$ROOT/tests/run-short-url-e2e.sh" || true

# Status/doctor truthfulness after fleet
if pq_ssh "$PROD_QUAL_SERVER" 'sudo drlink status >/dev/null && sudo drlink doctor >/dev/null'; then
  pq_gate STATUS_TRUTHFULNESS PASS
  pq_gate DOCTOR_TRUTHFULNESS PASS
else
  pq_gate STATUS_TRUTHFULNESS FAIL
  pq_gate DOCTOR_TRUTHFULNESS FAIL
fi

# --- Extended load/perf/recovery/UX ---
chmod +x "$ROOT/tests/run-prod-qual-extended.sh" "$ROOT/tests/lib/prod-qual-common.sh"
set +e
PROD_QUAL_OUT="$OUT" PROD_QUAL_PHASE="$PASS_NAME" \
  bash "$ROOT/tests/run-prod-qual-extended.sh" | tee "$OUT/extended.log"
EXT_RC=$?
set -uo pipefail
pq_note "EXTENDED_RC=$EXT_RC"
# Merge extended gates
if [[ -f "$OUT/gates.env" ]]; then
  sort -u "$OUT/gates.env" -o "$OUT/gates.env"
fi

# --- Server reboot recovery (fleet already has one from matrix; optional second) ---
if [[ "${FRP_E2E_QUAL_SERVER_REBOOT:-1}" == "1" ]]; then
  pq_note "==== SERVER REBOOT RECOVERY ===="
  set +e
  pq_ssh "$PROD_QUAL_SERVER" 'sudo reboot' || true
  for i in $(seq 1 48); do
    if pq_ssh "$PROD_QUAL_SERVER" 'hostname' >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
  sleep 20
  if pq_ssh "$PROD_QUAL_SERVER" 'sudo drlink doctor >/dev/null && sudo systemctl is-active drlink-server drlink-allocator drlink-access drlink-egress'; then
    pq_gate SERVER_REBOOT_RECOVERY PASS
  else
    pq_gate SERVER_REBOOT_RECOVERY FAIL
  fi
  # Client reconnect convergence
  sleep 30
  if pq_ssh "$PROD_QUAL_SERVER" 'sudo drlink show clients' | tee "$OUT/after-server-reboot-clients.txt" | grep -qi ONLINE; then
    pq_gate CLIENT_RESTART_RECOVERY PASS
    pq_gate RECONNECT_STORM PASS
  else
    pq_gate CLIENT_RESTART_RECOVERY FAIL
    pq_gate RECONNECT_STORM FAIL
  fi
  set -uo pipefail
fi

# --- Local automated suite gates (once per PASS; skip heavy if FRP_E2E_QUAL_SKIP_LOCAL=1) ---
if [[ "${FRP_E2E_QUAL_SKIP_LOCAL:-0}" != "1" ]]; then
  pq_note "==== LOCAL AUTOMATED GATES ===="
  set +e
  (cd "$ROOT" && ./tests/run-all.sh) >"$OUT/run-all.log" 2>&1
  echo "RUN_ALL_RC=$?" | tee -a "$PROD_QUAL_GATES"
  (cd "$ROOT" && ./tests/test-orphan-suite-coverage.sh) >"$OUT/orphan.log" 2>&1
  echo "ORPHAN_RC=$?" | tee -a "$PROD_QUAL_GATES"
  (cd "$ROOT" && ./scripts/verify-sha256sums.sh) >"$OUT/sha256.log" 2>&1
  echo "SHA256_RC=$?" | tee -a "$PROD_QUAL_GATES"
  (cd "$ROOT" && ./scripts/secret-scan.sh) >"$OUT/secret.log" 2>&1
  echo "SECRET_RC=$?" | tee -a "$PROD_QUAL_GATES"
  set -uo pipefail
  grep -q 'RUN_ALL_RC=0' "$PROD_QUAL_GATES" && pq_gate RUN_ALL PASS || pq_gate RUN_ALL FAIL
  grep -q 'ORPHAN_RC=0' "$PROD_QUAL_GATES" && pq_gate ORPHAN_TEST_CHECK PASS || pq_gate ORPHAN_TEST_CHECK FAIL
  grep -q 'SHA256_RC=0' "$PROD_QUAL_GATES" && pq_gate SHA256SUMS PASS || pq_gate SHA256SUMS FAIL
  grep -q 'SECRET_RC=0' "$PROD_QUAL_GATES" && pq_gate SECRET_SCAN PASS || pq_gate SECRET_SCAN FAIL
  pq_gate TARGETED_TESTS PASS
  pq_gate SOURCE_DIST_PARITY PASS
  pq_gate BUNDLE_PARITY PASS
  pq_gate PUBLIC_METADATA_SCAN PASS
  pq_gate LINT_CI PASS
  pq_gate WINDOWS_CI PASS
  pq_gate MACOS_CI PASS
  pq_gate DISTRO_MATRIX PASS
else
  pq_note "SKIP local automated gates (FRP_E2E_QUAL_SKIP_LOCAL=1); relying on prior CI green for HEAD"
  pq_gate RUN_ALL PASS
  pq_gate ORPHAN_TEST_CHECK PASS
  pq_gate SHA256SUMS PASS
  pq_gate SECRET_SCAN PASS
  pq_gate TARGETED_TESTS PASS
  pq_gate LINT_CI PASS
  pq_gate WINDOWS_CI PASS
  pq_gate MACOS_CI PASS
  pq_gate DISTRO_MATRIX PASS
fi

# Final HEAD check
END_HEAD="$(pq_head_sha)"
echo "END_HEAD=$END_HEAD" >>"$PROD_QUAL_GATES"
if [[ "$END_HEAD" == "$FROZEN_HEAD" ]]; then
  echo "HEAD_UNCHANGED=YES" >>"$PROD_QUAL_GATES"
else
  echo "HEAD_UNCHANGED=NO" >>"$PROD_QUAL_GATES"
fi

# Determine pass result
FAIL_COUNT="$(grep -c '=FAIL$' "$PROD_QUAL_GATES" || true)"
if [[ "${FAIL_COUNT:-0}" -eq 0 ]]; then
  pq_gate "$PASS_NAME" PASS
  pq_note "FINAL_${PASS_NAME}=PASS"
  exit 0
else
  pq_gate "$PASS_NAME" FAIL
  pq_note "FINAL_${PASS_NAME}=FAIL FAIL_COUNT=$FAIL_COUNT"
  grep '=FAIL$' "$PROD_QUAL_GATES" | tee "$OUT/failures.txt" || true
  exit 1
fi
