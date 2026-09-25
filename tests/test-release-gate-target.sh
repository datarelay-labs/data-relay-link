#!/usr/bin/env bash
# Release-gate targets must be explicit and must not fall back to historical .113.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/require-release-target.sh
source "$ROOT/tests/lib/require-release-target.sh"

fail() { echo "FAIL $*" >&2; exit 1; }

for rel in \
  tests/run-real-e2e.sh \
  tests/run-real-e2e-matrix.sh \
  tests/run-production-realistic-qualification.sh \
  tests/lib/prod-qual-common.sh \
  tests/run-release-qualification-passes.sh \
  .engineering/release.yaml
do
  if grep -q '221\.139\.249\.113' "$ROOT/$rel"; then
    fail "$rel still references historical .113"
  fi
  if grep -q '129\.225\.184\.60' "$ROOT/$rel"; then
    fail "$rel commits the live release address"
  fi
done

unset FRP_E2E_SERVER_IP FRP_E2E_PUBLIC_HOSTNAME FRP_E2E_SERVER_ALIAS
if frp_require_release_target >/tmp/release-target.out 2>/tmp/release-target.err; then
  fail "empty target was accepted"
fi
grep -q 'explicitly' /tmp/release-target.err || fail "empty target error"

export FRP_E2E_SERVER_IP=221.139.249.113
export FRP_E2E_PUBLIC_HOSTNAME=203.0.113.10.nip.io
export FRP_E2E_SERVER_ALIAS=frp-release-example
if frp_require_release_target >/tmp/release-target.out 2>/tmp/release-target.err; then
  fail "historical IP was accepted"
fi

export FRP_E2E_SERVER_IP=203.0.113.10
export FRP_E2E_PUBLIC_HOSTNAME=221.139.249.113.nip.io
if frp_require_release_target >/tmp/release-target.out 2>/tmp/release-target.err; then
  fail "historical hostname was accepted"
fi

export FRP_E2E_PUBLIC_HOSTNAME=203.0.113.10.nip.io
export FRP_E2E_SERVER_ALIAS=frp-e2e-server
if frp_require_release_target >/tmp/release-target.out 2>/tmp/release-target.err; then
  fail "historical alias was accepted"
fi

export FRP_E2E_SERVER_ALIAS=frp-release-example
frp_require_release_target || fail "explicit non-historical target rejected"

if ! grep -q 'PASS1' "$ROOT/tests/run-release-qualification-pass.sh" \
  || ! grep -q 'PASS2' "$ROOT/tests/run-release-qualification-pass.sh"; then
  fail "qualification pass entry does not name both passes"
fi
python3 - "$ROOT/tests/run-production-realistic-qualification.sh" <<'PY'
import sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
seen = 0
for index, line in enumerate(lines):
    if 'bash "$ROOT/tests/run-real-e2e' not in line:
        continue
    seen += 1
    window = "\n".join(lines[max(0, index - 18):index])
    for key in ("FRP_E2E_SERVER_ALIAS", "FRP_E2E_SERVER_IP", "FRP_E2E_PUBLIC_HOSTNAME"):
        if key not in window:
            raise SystemExit("missing %s before %s" % (key, line.strip()))
if seen < 3:
    raise SystemExit("expected matrix, macos retry, and fleet-keep invocations, saw %s" % seen)
print("PASS ALIAS_PROPAGATION")
PY
echo "PASS RELEASE_GATE_TARGET"
echo "RELEASE_GATE_TARGET_TEST=PASS"
