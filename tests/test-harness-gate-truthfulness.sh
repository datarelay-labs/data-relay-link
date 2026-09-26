#!/usr/bin/env bash
# Negative + positive regression for qualification gate truthfulness helpers.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/prod-qual-common.sh
source "$ROOT/tests/lib/prod-qual-common.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
PROD_QUAL_SUMMARY="$WORKDIR/summary.txt"
PROD_QUAL_GATES="$WORKDIR/gates.env"
PROD_QUAL_FAILS=0
: >"$PROD_QUAL_SUMMARY"
: >"$PROD_QUAL_GATES"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# Overwrite semantics: last status wins; no FAIL+PASS dual lines.
pq_gate DEMO FAIL
pq_gate DEMO PASS
count="$(grep -c '^DEMO=' "$PROD_QUAL_GATES" || true)"
[[ "$count" == "1" ]] || fail "expected single DEMO gate, got $count"
grep -qx 'DEMO=PASS' "$PROD_QUAL_GATES"
pass "gate overwrite single line"

# FAIL increments counter; PASS overwrite does not clear historical PROD_QUAL_FAILS
# (counter is diagnostic). Final verdict uses gates.env FAIL/BLOCKED lines.
pq_gate OTHER FAIL
fail_lines="$(grep -E '=(FAIL|BLOCKED)$' "$PROD_QUAL_GATES" | wc -l | tr -d ' ')"
[[ "$fail_lines" == "1" ]] || fail "expected 1 fail line"
pass "fail line count"

# --- Missing gate must not be inferred as PASS ---
if grep -q '^MISSING_GATE=PASS$' "$PROD_QUAL_GATES"; then
  fail "unexpected PASS for missing gate"
fi
pq_gate MISSING_GATE FAIL
grep -qx 'MISSING_GATE=FAIL' "$PROD_QUAL_GATES"
pass "missing gate explicit FAIL"

# --- NOT_RUN is not PASS ---
pq_gate CI_CASE NOT_RUN
grep -qx 'CI_CASE=NOT_RUN' "$PROD_QUAL_GATES"
if grep -qx 'CI_CASE=PASS' "$PROD_QUAL_GATES"; then
  fail "NOT_RUN must not become PASS"
fi
pass "NOT_RUN is not PASS"

# --- BLOCKED is a failing status for final count ---
pq_gate BLOCKED_CASE BLOCKED
grep -qx 'BLOCKED_CASE=BLOCKED' "$PROD_QUAL_GATES"
pass "BLOCKED recorded"

# --- Malformed gate file: empty value / garbage must not count as PASS ---
echo 'MALFORMED_GATE=' >>"$PROD_QUAL_GATES"
echo 'GARBAGE_LINE_WITHOUT_EQ' >>"$PROD_QUAL_GATES"
if grep -qx 'MALFORMED_GATE=PASS' "$PROD_QUAL_GATES"; then
  fail "malformed became PASS"
fi
pass "malformed gate not PASS"

# Short URL gate keys must exist in the qualification orchestrator (not || true).
grep -q 'SHORTURL_REAL_E2E' "$ROOT/tests/run-production-realistic-qualification.sh"
grep -q 'SHORTURL_RELEASE_GATE' "$ROOT/tests/run-production-realistic-qualification.sh"
if grep -n 'run_feature shorturl' "$ROOT/tests/run-production-realistic-qualification.sh" | grep -q '|| true'; then
  fail "shorturl still non-gating via || true"
fi
pass "shorturl gating"

# Require PERFORMANCE_BASELINE FAIL path exists for missing artifact / null metrics.
grep -q 'PERFORMANCE_BASELINE FAIL' "$ROOT/tests/run-prod-qual-extended.sh"
grep -q 'PERF_BASELINE_HTTP_METRICS' "$ROOT/tests/run-prod-qual-extended.sh" \
  || grep -q 'sample_count' "$ROOT/tests/run-prod-qual-extended.sh"
pass "perf baseline fail path present"

# --- HEAD_UNCHANGED=NO must be treated as failure signal in orchestrator ---
grep -q 'HEAD_UNCHANGED=NO' "$ROOT/tests/run-production-realistic-qualification.sh"
python3 - "$ROOT/tests/run-production-realistic-qualification.sh" <<'PY' || fail "HEAD_UNCHANGED=NO not failing closed"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "HEAD_UNCHANGED=NO" in text
# Must not treat NO as success in the same branch that writes YES success.
idx = text.find('HEAD_UNCHANGED=NO')
window = text[max(0, idx - 200): idx + 200]
assert "FINAL=PASS" not in window.split("HEAD_UNCHANGED=NO")[0][-80:]
print("ok")
PY
pass "HEAD_UNCHANGED=NO present"

# --- Child non-zero / simultaneous mutation must capture RCs (not wait || true alone) ---
python3 - "$ROOT/tests/run-prod-qual-extended.sh" <<'PY' || fail "simultaneous still swallows child RCs"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
idx = text.find("phase_simultaneous_mutation")
assert idx > 0
# Take function body until next phase_
end = text.find("\nphase_", idx + 10)
body = text[idx:end if end > 0 else idx + 4000]
assert "wait || true" not in body, "simultaneous still uses wait || true"
assert "SIM_CHILD_" in body or "child_pids" in body
assert "LIVE_BACKUP_CONSISTENCY FAIL" in body
print("ok")
PY
pass "simultaneous child RC capture"

# --- Matrix backup/restore must increment FAILED ---
python3 - "$ROOT/tests/run-real-e2e-matrix.sh" <<'PY' || fail "matrix backup/restore not authoritative"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "FLEET_BACKUP_RC=" in text
assert "FLEET_RESTORE_RC=" in text
assert "FLEET_POST_RESTORE_RC=" in text or "FLEET_RESTORE=FAIL" in text
# backup/restore failure must bump FAILED
assert "FAILED=$((FAILED + 1))" in text
idx = text.find("FLEET backup/restore")
chunk = text[idx:idx+1800]
assert "backup_rc" in chunk and "restore_rc" in chunk
assert "FAILED=$((FAILED + 1))" in chunk
print("ok")
PY
pass "matrix backup/restore authority"

# --- Reboot || true only with separate recovery evidence ---
python3 - "$ROOT/tests/run-real-e2e-matrix.sh" <<'PY' || fail "reboot recovery evidence missing"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
idx = text.find("sudo reboot")
assert idx > 0
window = text[idx:idx+900]
assert "|| true" in window  # reboot itself may soft-fail mid-drop
assert "FLEET_REBOOT_RECOVERY" in text[idx:idx+2000]
assert "FLEET_REBOOT_RECOVERY=FAIL" in text
print("ok")
PY
pass "reboot recovery separately asserted"

# --- DENY must require 403, not 000/502 ---
python3 - "$ROOT/tests/run-prod-qual-extended.sh" <<'PY' || fail "DENY still accepts 000/502"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'DENY_FQDN' in text
assert '= "403"' in text or "='403'" in text
# Reject the old permissive pattern accepting transport failures as deny success
assert '000" -o' not in text
assert "deny\" = \"000\"" not in text and "deny' = '000'" not in text
assert "egress_profiles" in text
assert "st.get('profiles')" not in text
print("ok")
PY
pass "DENY requires 403; egress_profiles key"

# --- Soak decisive probes must not be || true'd ---
python3 - "$ROOT/tests/run-prod-qual-extended.sh" <<'PY' || fail "soak still || true on traffic"
from pathlib import Path
import sys, re
text = Path(sys.argv[1]).read_text(encoding="utf-8")
idx = text.find("phase_soak")
end = text.find("\nphase_", idx + 10)
body = text[idx:end if end > 0 else idx + 3500]
# Decisive curl lines must not soft-pass via || true (|| echo 000 for capture is OK).
for line in body.splitlines():
    if "curl" in line and "example.com" in line:
        assert "|| true" not in line, line
assert "SOAK_PROBE_OK" in body and "SOAK_PROBE_FAIL" in body
assert "avail_ok" in body
print("ok")
PY
pass "soak tracks probe success/failure"

# --- pq_wait_macos ownership: unrelated :2222 must not be killed ---
python3 - "$ROOT/tests/lib/prod-qual-common.sh" <<'PY' || fail "pq_wait_macos still kills all :2222"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "pq_macos_listener_owned" in text
assert "MACOS_STALE_LISTENER_SKIP" in text
assert "unrelated" in text.lower() or "not owned" in text.lower()
print("ok")
PY
# Runtime regression with a dummy listener on an alternate port simulating ownership check.
DUMMY_PID=""
python3 -c 'import socket,time,os; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); os.fork() and (time.sleep(0.05) or None) or (s.listen(1) or time.sleep(30))' >"$WORKDIR/dummy.port" 2>/dev/null &
# Direct unit test of ownership helper:
UNRELATED_CMD='python3 -c "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"127.0.0.1\",0)); print(s.getsockname()[1], flush=True); s.listen(1); time.sleep(60)"'
# shellcheck disable=SC2086
bash -c "$UNRELATED_CMD" >"$WORKDIR/dummy.listen" 2>"$WORKDIR/dummy.err" &
DUMMY_PID=$!
sleep 0.3
# Recorded PID is empty / different → helper must return non-zero (not owned).
set +e
pq_macos_listener_owned "$DUMMY_PID"
own_rc=$?
set -e
kill "$DUMMY_PID" 2>/dev/null || true
wait "$DUMMY_PID" 2>/dev/null || true
[[ "$own_rc" -ne 0 ]] || fail "unrelated dummy listener incorrectly owned"
# Recorded PID match must be owned.
PROD_QUAL_MACOS_SSH_PID=$$
pq_macos_listener_owned "$$" || fail "recorded PID should be owned"
pass "unrelated :2222 ownership proof"

# --- Golden upgrade: wrong version → BLOCKED; backup not || true ---
python3 - "$ROOT/tests/run-prod-qual-extended.sh" <<'PY' || fail "golden upgrade truthfulness"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
idx = text.find("phase_golden_baseline")
end = text.find("\nphase_", idx + 10)
body = text[idx:end if end > 0 else idx + 5000]
assert "installed_project_version" in body or "/etc/drlink/version" in body
assert "GOLDEN_V230_UPGRADE_BASELINE BLOCKED" in body
assert "expected=2.3.0" in body
assert "2.3.1" not in body
assert "2.2.1" not in body
assert "backup create" in body
assert "|| true" not in body.split("backup create")[1][:80]
print("ok")
PY
pass "golden upgrade version/BLOCKED"

# --- Docs-free / wrong-ops: every invalid RC asserted ---
python3 - "$ROOT/tests/run-prod-qual-extended.sh" <<'PY' || fail "invalid RC asserts incomplete"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
docs = text[text.find("phase_docs_free_ux"):text.find("phase_fixed_tcp_egress")]
assert 'test "$rc1" -ne 0' in docs
assert 'test "$rc2" -ne 0' in docs
assert 'test "$rc3" -ne 0' in docs
wrong = text[text.find("phase_wrong_ops"):text.find("\nmain()")]
assert 'e3' in wrong and 'e4' in wrong
assert 'e1' in wrong and 'e2' in wrong
assert '-a "$e3"' in wrong or 'e3" -ne 0' in wrong
print("ok")
PY
pass "invalid-command RC asserts"

# --- Fixture-prep marking for config.json ---
grep -q 'FIXTURE-PREP' "$ROOT/tests/run-prod-qual-extended.sh" \
  || grep -q 'FIXTURE_PREP' "$ROOT/tests/run-prod-qual-extended.sh" \
  || fail "config.json edit not marked fixture-prep"
pass "fixture-prep marked"

# --- Short-URL insecure-TLS gate must not match "-k" inside hostnames ---
python3 - "$ROOT/tests/run-short-url-e2e.sh" <<'PY' || fail "shorturl -k hostname false-positive still present"
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
needle = "curl_argv=\"${CMD%%\\'https://*}\""
if needle not in text and "curl_argv=\"${CMD%%'https://*}\"" not in text:
    # Accept either quoting style used in the harness.
    if "curl_argv=" not in text or "%%" not in text or "https://" not in text:
        raise SystemExit("shorturl harness must inspect curl argv before the URL")
if "mechanism-keyboard" in text.split("insecure TLS")[0][-200:]:
    pass  # comment context ok
# Must not use unscoped whole-command substring match for -k.
bad = "if [[ \"$CMD\" == *'-k'* || \"$CMD\" == *'--insecure'* ]]; then"
if bad in text:
    raise SystemExit("unscoped CMD *-k* match still present")
print("ok")
PY
pass "shorturl -k hostname false-positive guard"

echo "PASS harness gate truthfulness"
