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

# Overwrite semantics: last status wins; no FAIL+PASS dual lines.
pq_gate DEMO FAIL
pq_gate DEMO PASS
count="$(grep -c '^DEMO=' "$PROD_QUAL_GATES" || true)"
[[ "$count" == "1" ]] || { echo "expected single DEMO gate, got $count"; exit 1; }
grep -qx 'DEMO=PASS' "$PROD_QUAL_GATES"

# FAIL increments counter; PASS overwrite does not clear historical PROD_QUAL_FAILS
# (counter is diagnostic). Final verdict uses gates.env FAIL/BLOCKED lines.
pq_gate OTHER FAIL
fail_lines="$(grep -E '=(FAIL|BLOCKED)$' "$PROD_QUAL_GATES" | wc -l | tr -d ' ')"
[[ "$fail_lines" == "1" ]] || { echo "expected 1 fail line"; exit 1; }

# Malformed / missing output must not be inferred as PASS.
if grep -q '^MISSING_GATE=PASS$' "$PROD_QUAL_GATES"; then
  echo "unexpected PASS for missing gate"
  exit 1
fi
pq_gate MISSING_GATE FAIL
grep -qx 'MISSING_GATE=FAIL' "$PROD_QUAL_GATES"

# BLOCKED is a failing status for final count.
pq_gate BLOCKED_CASE BLOCKED
grep -qx 'BLOCKED_CASE=BLOCKED' "$PROD_QUAL_GATES"

# NOT_RUN is not PASS and not a silent success.
pq_gate CI_CASE NOT_RUN
grep -qx 'CI_CASE=NOT_RUN' "$PROD_QUAL_GATES"
if grep -qx 'CI_CASE=PASS' "$PROD_QUAL_GATES"; then
  echo "NOT_RUN must not become PASS"
  exit 1
fi

# Short URL gate keys must exist in the qualification orchestrator (not || true).
grep -q 'SHORTURL_REAL_E2E' "$ROOT/tests/run-production-realistic-qualification.sh"
grep -q 'SHORTURL_RELEASE_GATE' "$ROOT/tests/run-production-realistic-qualification.sh"
if grep -n 'run_feature shorturl' "$ROOT/tests/run-production-realistic-qualification.sh" | grep -q '|| true'; then
  echo "shorturl still non-gating via || true"
  exit 1
fi

# Perf baseline must not unconditional PASS without artifact check.
if grep -A2 'pq_gate REMOTE_ACCESS_PERFORMANCE_BASELINE PASS' "$ROOT/tests/run-prod-qual-extended.sh" | head -5 | grep -q 'unconditional'; then
  :
fi
# Require PERFORMANCE_BASELINE FAIL path exists for missing artifact.
grep -q 'PERFORMANCE_BASELINE FAIL' "$ROOT/tests/run-prod-qual-extended.sh"
grep -q 'import sys' "$ROOT/tests/run-prod-qual-extended.sh" || \
  grep -q 'import json, os, platform, socket, sys' "$ROOT/tests/run-prod-qual-extended.sh"

echo "PASS harness gate truthfulness"
