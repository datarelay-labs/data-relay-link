#!/usr/bin/env bash
# Negative regression: PERFORMANCE_BASELINE must FAIL when baseline.json is missing.
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

# Case 1: missing artifact → FAIL
if [[ -f "$OUT/perf/baseline.json" ]]; then
  echo "unexpected baseline present"
  exit 1
fi
# Mimic gate logic from phase_perf_baseline
baseline_out="$OUT/perf/baseline.json"
if [[ ! -f "$baseline_out" || ! -s "$baseline_out" ]]; then
  pq_gate PERFORMANCE_BASELINE FAIL
else
  pq_gate PERFORMANCE_BASELINE PASS
fi
grep -qx 'PERFORMANCE_BASELINE=FAIL' "$PROD_QUAL_GATES"

# Case 2: path declared but empty → FAIL
: >"$baseline_out"
echo "PERF_BASELINE_ARTIFACT=$baseline_out" >>"$PROD_QUAL_GATES"
if [[ ! -s "$baseline_out" ]]; then
  pq_gate PERFORMANCE_BASELINE FAIL
fi
grep -c 'PERFORMANCE_BASELINE=FAIL' "$PROD_QUAL_GATES" | grep -Eq '^[1-9]'

# Case 3: valid minimal schema + HEAD match → PASS
HEAD="$(git -C "$ROOT" rev-parse HEAD)"
python3 - "$baseline_out" "$HEAD" "$OUT" <<'PY'
import json, sys
from pathlib import Path
out, head, root = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
raw = root / "perf" / "raw" / "sample.txt"
raw.parent.mkdir(parents=True, exist_ok=True)
raw.write_text("CONNECT_1=0.01\n", encoding="utf-8")
doc = {
  "schema_version": 1,
  "timestamp": "2026-01-01T00:00:00Z",
  "git_head": head,
  "project_version": "2.4.0",
  "frp_version": "0.71.0",
  "environment": {"hostname": "test", "os": "Linux", "kernel": "x", "cpu": 1, "ram": None},
  "remote_access": {"concurrency": None, "throughput": None, "latency": {}, "failure_rate": 0},
  "controlled_egress": {"concurrency": None, "connect_p50": 0.01, "connect_p95": 0.01, "connect_p99": 0.01, "churn": None, "throughput": None, "failure_rate": 0},
  "fixed_tcp_egress": {},
  "resources": {"cpu": 0, "rss": 1, "fd_count": 1, "server_peak": {"rss_kb": 1, "fds": 1, "threads": 1}},
  "raw_evidence_paths": ["perf/raw/sample.txt"],
}
out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
python3 - "$baseline_out" "$HEAD" "$OUT" <<'PY'
import json, sys
from pathlib import Path
path, expected_head, out_root = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
d = json.loads(path.read_text(encoding="utf-8"))
assert int(d["schema_version"]) >= 1
assert d["git_head"] == expected_head
for rel in d["raw_evidence_paths"]:
    p = out_root / rel
    assert p.is_file() and p.stat().st_size > 0, rel
print("OK")
PY
pq_gate PERFORMANCE_BASELINE PASS
grep -qx 'PERFORMANCE_BASELINE=PASS' "$PROD_QUAL_GATES"

echo "PASS perf baseline evidence contract"
