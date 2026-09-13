#!/usr/bin/env bash
# Regression: BUG-MACOS-PROXY-WAIT-CURSOR
# Darwin wait_for_proxies must use a file byte-offset (logpos) cursor, not UTC
# ISO timestamp substring matching against local-time frpc log lines.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

# Source contract: no Darwin ISO/awk timestamp cursor filtering.
if grep -nE 'date -u \+%Y-%m-%dT%H:%M:%SZ' "$ROOT/lib/frp-client-common.sh" \
  | grep -v '^#' >/dev/null 2>&1; then
  if grep -A6 'frp_client_journal_cursor' "$ROOT/lib/frp-client-common.sh" \
    | grep -q 'date -u'; then
    fail "frp_client_journal_cursor still emits UTC ISO on Darwin"
  fi
fi
if grep -A20 'frp_client_recent_runtime_logs' "$ROOT/lib/frp-client-common.sh" \
  | grep -q 'index(\$0, since)'; then
  fail "frp_client_recent_runtime_logs still filters Darwin logs by timestamp substring"
fi
grep -q 'frp_macos_log_cursor' "$ROOT/lib/frp-macos.sh" \
  || fail "missing frp_macos_log_cursor helper"
grep -q 'logpos:v1' "$ROOT/lib/frp-macos.sh" \
  || fail "missing logpos:v1 cursor format"
pass "SOURCE_USES_LOGPOS_CURSOR"

export FRP_TEST_UNAME_S=Darwin
export FRP_MACOS_STATE_ROOT="$WORK/state"
export FRP_CLIENT_TEST_ROOT="$WORK/root"
mkdir -p "$WORK/root$WORK/state/logs"

# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
# shellcheck source=../lib/frp-client-common.sh
. "$ROOT/lib/frp-client-common.sh"

OUT_LOG="$(frp_macos_fs /etc/frp)/logs/frpc.out.log"
ERR_LOG="$(frp_macos_fs /etc/frp)/logs/frpc.err.log"
: >"$OUT_LOG"
: >"$ERR_LOG"

export FRP_PROXY_WAIT_SLEEP_S=0
export FRP_PROXY_WAIT_MAX_ATTEMPTS=4
export FRP_PROXY_WAIT_MAX_SLEEP_S=0

# --- Test A: local-time log lines PASS with logpos cursor (UTC ISO would miss) ---
{
  printf '%s\n' \
    '2026-09-13 09:32:20.000 [I] [host-ssh] stale prior generation' \
    >"$OUT_LOG"
}
CURSOR_A="$(frp_client_journal_cursor)"
case "$CURSOR_A" in
  logpos:v1:*) ;;
  *) fail "Test A cursor is not logpos:v1 (got: $CURSOR_A)" ;;
esac
case "$CURSOR_A" in
  *T*Z*) fail "Test A cursor still looks like UTC ISO: $CURSOR_A" ;;
esac
# Exact Real E2E shape: UTC wall clock vs local-time frpc line.
printf '%s\n' \
  '2026-09-13 09:32:28.730 [I] [host-ssh] start proxy success' \
  'login to server success' \
  >>"$OUT_LOG"
export FRP_PROXY_WAIT_CURSOR="$CURSOR_A"
if ! wait_for_proxies host-ssh; then
  fail "Test A: logpos cursor must accept local-time proxy-success lines"
fi
pass "TEST_A_UTC_VS_LOCAL_TIME_LOGPOS"

# --- Test B: stale line before cursor must NOT satisfy wait ---
printf '%s\n' \
  'login to server success' \
  '[host-ssh] start proxy success' \
  >"$OUT_LOG"
CURSOR_B="$(frp_client_journal_cursor)"
export FRP_PROXY_WAIT_CURSOR="$CURSOR_B"
export FRP_PROXY_WAIT_MAX_ATTEMPTS=3
if wait_for_proxies host-ssh; then
  fail "Test B: stale pre-cursor proxy-success must not PASS"
fi
pass "TEST_B_STALE_LOG_CAUSALITY"

# --- Test C: new appended line after cursor PASS ---
printf '%s\n' \
  'login to server success' \
  '[old] start proxy success' \
  >"$OUT_LOG"
CURSOR_C="$(frp_client_journal_cursor)"
export FRP_PROXY_WAIT_CURSOR="$CURSOR_C"
printf '%s\n' \
  'login to server success' \
  '[host-ssh] start proxy success' \
  >>"$OUT_LOG"
export FRP_PROXY_WAIT_MAX_ATTEMPTS=4
if ! wait_for_proxies host-ssh; then
  fail "Test C: appended proxy-success after cursor must PASS"
fi
pass "TEST_C_NEW_APPENDED_LINE"

# --- Test D: log recreated / rotated (inode change) ---
printf '%s\n' 'old generation clutter [host-ssh] start proxy success' >"$OUT_LOG"
CURSOR_D="$(frp_client_journal_cursor)"
export FRP_PROXY_WAIT_CURSOR="$CURSOR_D"
rm -f "$OUT_LOG"
printf '%s\n' \
  'login to server success' \
  '[host-ssh] start proxy success' \
  >"$OUT_LOG"
if ! wait_for_proxies host-ssh; then
  fail "Test D: rotated/replaced log with fresh proxy-success must PASS"
fi
pass "TEST_D_LOG_ROTATION_CAUSALITY"

# --- Test E: truncated log (saved offset > current size) ---
python3 - "$OUT_LOG" <<'PY'
import pathlib
path = pathlib.Path(__import__('sys').argv[1])
path.write_text('x' * 4096 + '\nlogin to server success\n[host-ssh] start proxy success\n', encoding='utf-8')
PY
CURSOR_E="$(frp_client_journal_cursor)"
export FRP_PROXY_WAIT_CURSOR="$CURSOR_E"
# Truncate below saved offset, then write fresh evidence.
: >"$OUT_LOG"
printf '%s\n' \
  'login to server success' \
  '[host-ssh] start proxy success' \
  >"$OUT_LOG"
if ! wait_for_proxies host-ssh; then
  fail "Test E: truncated log with fresh proxy-success must PASS"
fi
pass "TEST_E_TRUNCATED_LOG"

# --- Test F: expected proxy missing ---
: >"$OUT_LOG"
CURSOR_F="$(frp_client_journal_cursor)"
export FRP_PROXY_WAIT_CURSOR="$CURSOR_F"
printf '%s\n' \
  'login to server success' \
  '[host-ssh] start proxy success' \
  >>"$OUT_LOG"
export FRP_PROXY_WAIT_MAX_ATTEMPTS=3
if wait_for_proxies host-ssh host-http; then
  fail "Test F: missing expected proxy must FAIL"
fi
pass "TEST_F_EXPECTED_PROXY_MISSING"

# --- Legacy ISO cursor must not accept pre-existing stale success ---
printf '%s\n' \
  'login to server success' \
  '[host-ssh] start proxy success' \
  >"$OUT_LOG"
export FRP_PROXY_WAIT_CURSOR='2026-09-13T00:32:28Z'
export FRP_PROXY_WAIT_MAX_ATTEMPTS=3
if wait_for_proxies host-ssh; then
  fail "legacy ISO cursor must not accept already-written stale success lines"
fi
pass "LEGACY_ISO_CURSOR_FAIL_CLOSED"

# Ensure err.log path is also covered by cursor format.
CURSOR_BOTH="$(frp_client_journal_cursor)"
case "$CURSOR_BOTH" in
  logpos:v1:out=*,*,*:err=*,*,*) ;;
  *) fail "cursor missing out/err fingerprint fields: $CURSOR_BOTH" ;;
esac
pass "CURSOR_COVERS_OUT_AND_ERR"

echo "MACOS_PROXY_WAIT_REGRESSION=PASS"
echo "STALE_LOG_CAUSALITY=PASS"
echo "LOG_ROTATION_CAUSALITY=PASS"
