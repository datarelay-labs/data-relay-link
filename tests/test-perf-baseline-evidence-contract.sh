#!/usr/bin/env bash
# Negative regression: PERFORMANCE_BASELINE must require real measurements.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/prod-qual-common.sh
source "$ROOT/tests/lib/prod-qual-common.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
OUT="$WORKDIR/out"
mkdir -p "$OUT/perf/raw" "$OUT/resources"
PROD_QUAL_SUMMARY="$OUT/summary.txt"
PROD_QUAL_GATES="$OUT/gates.env"
PROD_QUAL_FAILS=0
: >"$PROD_QUAL_SUMMARY"
: >"$PROD_QUAL_GATES"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# Extract the validator python block from the extended harness (+ required imports).
python3 - "$ROOT/tests/run-prod-qual-extended.sh" "$WORKDIR/validate_baseline.py" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
needle = "path, expected_head, out_root = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])"
idx = text.index(needle)
end = text.index("raise SystemExit(0 if ok else 3)", idx)
body = text[idx : end + len("raise SystemExit(0 if ok else 3)")] + "\n"
Path(sys.argv[2]).write_text(
    "import json, sys\nfrom pathlib import Path\n" + body,
    encoding="utf-8",
)
PY
VALIDATOR="$WORKDIR/validate_baseline.py"

# Case 1: missing artifact → FAIL
baseline_out="$OUT/perf/baseline.json"
if [[ ! -f "$baseline_out" || ! -s "$baseline_out" ]]; then
  pq_gate PERFORMANCE_BASELINE FAIL
else
  pq_gate PERFORMANCE_BASELINE PASS
fi
grep -qx 'PERFORMANCE_BASELINE=FAIL' "$PROD_QUAL_GATES"
pass "missing baseline fails"

# Case 2: schema+HEAD+raw with null HTTP/connect metrics → FAIL
HEAD="$(git -C "$ROOT" rev-parse HEAD)"
raw="$OUT/perf/raw/sample.txt"
printf 'placeholder\n' >"$raw"
python3 - "$baseline_out" "$HEAD" <<'PY'
import json, sys
from pathlib import Path
out, head = Path(sys.argv[1]), sys.argv[2]
doc = {
  "schema_version": 1,
  "timestamp": "2026-01-01T00:00:00Z",
  "git_head": head,
  "project_version": "2.4.0",
  "frp_version": "0.71.0",
  "environment": {"hostname": "test", "os": "Linux", "kernel": "x", "cpu": 1, "ram": None},
  "remote_access": {"concurrency": None, "throughput": None, "latency": {}, "failure_rate": 0},
  "controlled_egress": {
    "sample_count": 0,
    "attempt_count": 0,
    "success_count": 0,
    "failure_count": 0,
    "failure_rate": 0.0,
    "connect_p50": None, "connect_p95": None, "connect_p99": None,
    "http": {
      "sample_count": 0, "attempt_count": 0, "success_count": 0,
      "failure_count": 0, "failure_rate": 0.0,
      "p50": None, "p95": None, "p99": None,
    },
  },
  "fixed_tcp_egress": {
    "sample_count": None, "attempt_count": None, "success_count": None,
    "failure_count": None, "failure_rate": None,
    "setup_p50": None, "setup_p95": None, "setup_p99": None,
  },
  "resources": {"server_peak": {"rss_kb": 1, "fds": 1, "threads": 1}},
  "raw_evidence_paths": ["perf/raw/sample.txt"],
}
out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
set +e
python3 "$VALIDATOR" "$baseline_out" "$HEAD" "$OUT" >"$WORKDIR/null-metrics.out" 2>&1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "null metrics unexpectedly passed validator"
grep -Eq 'PERF_BASELINE_(CONNECT|HTTP)_METRICS=FAIL' "$WORKDIR/null-metrics.out" \
  || { cat "$WORKDIR/null-metrics.out"; fail "null metrics missing FAIL reason"; }
pass "null HTTP/connect metrics fail"

# Case 3: TCP qual PASS + null Fixed TCP metrics → FAIL
echo 'TCP_EGRESS_QUALIFICATION=PASS' >>"$PROD_QUAL_GATES"
python3 - "$baseline_out" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text(encoding="utf-8"))
d["controlled_egress"].update({
  "sample_count": 3, "attempt_count": 3, "success_count": 3,
  "failure_count": 0, "failure_rate": 0.0,
  "connect_p50": 10.0, "connect_p95": 12.0, "connect_p99": 15.0,
})
d["controlled_egress"]["http"].update({
  "sample_count": 2, "attempt_count": 2, "success_count": 2,
  "failure_count": 0, "failure_rate": 0.0,
  "p50": 20.0, "p95": 22.0, "p99": 25.0,
})
p.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
PY
set +e
python3 "$VALIDATOR" "$baseline_out" "$HEAD" "$OUT" >"$WORKDIR/tcp-null.out" 2>&1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "null Fixed TCP metrics passed while TCP_EGRESS_QUALIFICATION=PASS"
grep -q 'PERF_BASELINE_FIXED_TCP_METRICS=FAIL' "$WORKDIR/tcp-null.out" \
  || { cat "$WORKDIR/tcp-null.out"; fail "missing Fixed TCP metrics FAIL"; }
pass "null Fixed TCP metrics fail when TCP qual PASS"

# Case 4: complete metrics → PASS
python3 - "$baseline_out" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text(encoding="utf-8"))
d["fixed_tcp_egress"].update({
  "sample_count": 4, "attempt_count": 4, "success_count": 4,
  "failure_count": 0, "failure_rate": 0.0,
  "setup_p50": 5.0, "setup_p95": 6.0, "setup_p99": 7.0,
})
p.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
PY
set +e
python3 "$VALIDATOR" "$baseline_out" "$HEAD" "$OUT" >"$WORKDIR/ok.out" 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || { cat "$WORKDIR/ok.out"; fail "complete metrics should PASS"; }
grep -q 'PERF_BASELINE_HTTP_METRICS=PASS' "$WORKDIR/ok.out" || fail "HTTP metrics not PASS"
grep -q 'PERF_BASELINE_FIXED_TCP_METRICS=PASS' "$WORKDIR/ok.out" || fail "Fixed TCP metrics not PASS"
pass "complete metrics pass"

# Case 5: content-keyed aggregator (host-named files still yield CONNECT/HTTP metrics)
RAW_DIR="$OUT/perf/raw-content"
mkdir -p "$RAW_DIR"
cat >"$RAW_DIR/frp-e2e-client.txt" <<'EOF'
OS=Linux
DRLINK_HTTP_1K code=200 ttfb=0.01 total=0.02 size=10
CONNECT_SAMPLE_MS=12.5
CONNECT_SAMPLE_MS=13.0
CONNECT_p50=12.5 p95=13.0 p99=13.0
EOF
AGG="$OUT/perf/agg-from-content.json"
python3 - "$ROOT/tests/run-prod-qual-extended.sh" "$RAW_DIR" "$AGG" "$OUT/resources" "$HEAD" "$ROOT/VERSION" <<'PY'
# Execute the aggregator block from the extended harness against host-named raw files.
from pathlib import Path
import re, subprocess, sys, tempfile, textwrap
src = Path(sys.argv[1]).read_text(encoding="utf-8")
start = src.index("import json, os, platform, re, socket, sys, tempfile, time")
end = src.index("print(\"PERF_BASELINE_WRITTEN\", out)", start)
block = src[start:end] + "print(\"PERF_BASELINE_WRITTEN\", out)\n"
# The block expects argv: raw, out, res, git_head, version_path
path = Path(tempfile.mkdtemp()) / "agg.py"
path.write_text(block, encoding="utf-8")
rc = subprocess.call([sys.executable, str(path), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]])
raise SystemExit(rc)
PY
python3 - "$AGG" <<'PY' || fail "content aggregator missed host-named CONNECT/HTTP"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
ce=d["controlled_egress"]
assert ce["sample_count"] > 0 and ce["attempt_count"] > 0 and ce["success_count"] > 0
assert ce["connect_p50"] is not None and ce["connect_p95"] is not None and ce["connect_p99"] is not None
http=ce["http"]
assert http["sample_count"] > 0 and http["success_count"] > 0
assert http["p50"] is not None
print("content_agg_ok", ce["sample_count"], http["sample_count"])
PY
pass "host-named raw content populates metrics"

echo "PASS perf baseline evidence contract"
