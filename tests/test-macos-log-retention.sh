#!/usr/bin/env bash
# F24: launchd stdout/stderr must have a product-enforced retention bound.
# launchd rotates nothing on its own, so the product bounds the two frpc log
# files it owns: FRP_MACOS_LOG_MAX_BYTES per file, FRP_MACOS_LOG_KEEP copies.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_TEST_UNAME_S=Darwin
export FRP_CLIENT_TEST_ROOT="$TMP/root"
export FRP_MACOS_STATE_ROOT="$TMP/state"
# Small bound keeps the fixture cheap; the shipped default is asserted below.
export FRP_MACOS_LOG_MAX_BYTES=4096
export FRP_MACOS_LOG_KEEP=3
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

LOGS="$FRP_CLIENT_TEST_ROOT$FRP_MACOS_STATE_ROOT/logs"
OUT="$LOGS/frpc.out.log"
ERR="$LOGS/frpc.err.log"
mkdir -p "$LOGS"

file_size() { wc -c <"$1" | tr -d '[:space:]'; }
grow() { head -c "$2" /dev/zero | tr '\0' "$3" >>"$1"; }

# Defaults are the shipped product bound, not just whatever the test exports.
python3 - "$ROOT/lib/frp-macos.sh" <<'PY' || fail "shipped defaults"
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(encoding="utf-8")
max_bytes = re.search(r'FRP_MACOS_LOG_MAX_BYTES:-(\d+)', text)
keep = re.search(r'FRP_MACOS_LOG_KEEP:-(\d+)', text)
assert max_bytes and keep, "retention defaults are not declared"
assert int(max_bytes.group(1)) == 5 * 1024 * 1024, max_bytes.group(1)
assert int(keep.group(1)) == 3, keep.group(1)
PY
pass "shipped default bound is 5MB x 3"

# Under the bound: nothing moves.
grow "$OUT" 1024 a
frp_macos_rotate_logs
[[ -f "$OUT.1" ]] && fail "rotated a log that is under the size bound"
[[ "$(file_size "$OUT")" == "1024" ]] || fail "under-bound log was modified"
pass "logs under the bound are left alone"

# Over the bound: current file is emptied, content preserved in generation 1.
grow "$OUT" 8192 a
frp_macos_rotate_logs
[[ -f "$OUT.1" ]] || fail "rotation did not create generation 1"
[[ "$(file_size "$OUT")" == "0" ]] || fail "current log was not truncated"
[[ "$(file_size "$OUT.1")" == "9216" ]] || fail "generation 1 lost content"
pass "over-bound log truncates and preserves content in .1"

# Truncate-in-place, not rename: launchd hands frpc an already-open fd, so the
# inode must survive or frpc keeps writing to the rotated generation forever.
INODE_BEFORE="$(frp_macos_log_file_meta "$OUT")"
INODE_BEFORE="${INODE_BEFORE%% *}"
grow "$OUT" 8192 b
frp_macos_rotate_logs
INODE_AFTER="$(frp_macos_log_file_meta "$OUT")"
INODE_AFTER="${INODE_AFTER%% *}"
[[ "$INODE_BEFORE" == "$INODE_AFTER" ]] || fail "rotation replaced the live log inode"
pass "rotation preserves the inode launchd already opened"

# Generations shift and stop at KEEP: total retained bytes stay bounded.
for _ in 1 2 3 4 5; do
  grow "$OUT" 8192 c
  frp_macos_rotate_logs
done
[[ -f "$OUT.3" ]] || fail "generation 3 missing"
[[ -f "$OUT.4" ]] && fail "retained more generations than FRP_MACOS_LOG_KEEP"
pass "retention keeps exactly FRP_MACOS_LOG_KEEP generations"

# Both launchd files are bounded, not just stdout.
grow "$ERR" 8192 e
frp_macos_rotate_logs
[[ -f "$ERR.1" ]] || fail "stderr log was not rotated"
[[ "$(file_size "$ERR")" == "0" ]] || fail "stderr log was not truncated"
pass "stdout and stderr are both bounded"

# Lifecycle entry points enforce the bound without a manual rotate call.
grow "$OUT" 8192 d
frp_macos_log_cursor >/dev/null
[[ "$(file_size "$OUT")" == "0" ]] || fail "log cursor did not enforce retention"
pass "status/apply cursor path enforces retention"

grow "$OUT" 8192 f
FRP_MACOS_LAUNCHD_LABEL=com.datarelay.drlink.frpc frp_macos_launchd_kickstart >/dev/null 2>&1 || true
[[ "$(file_size "$OUT")" == "0" ]] || fail "kickstart did not enforce retention"
pass "service restart path enforces retention"

# Missing files and hostile settings must not abort a lifecycle command.
rm -f "$OUT"
frp_macos_rotate_logs || fail "rotation failed on a missing log file"
FRP_MACOS_LOG_MAX_BYTES=notanumber frp_macos_rotate_logs || fail "rotation failed on bad max"
FRP_MACOS_LOG_KEEP=0 frp_macos_rotate_logs || fail "rotation failed on zero keep"
pass "rotation is non-fatal on missing files and bad settings"

echo "MACOS_LOG_RETENTION_TEST=PASS"
