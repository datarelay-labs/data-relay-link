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
if grep -q '129\.225\.184\.60' "$ROOT/tests/lib/require-release-target.sh"; then
  fail "require-release-target.sh commits the live release address"
fi

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

RESOLVER="$(mktemp -d)"
cat >"$RESOLVER/getent" <<'EOF'
#!/bin/sh
if [ "$1" != "ahostsv4" ]; then
  exit 2
fi
case "$2" in
  match.example.test) printf '%s\n' "203.0.113.10 STREAM match.example.test" ;;
  mismatch.example.test) printf '%s\n' "198.51.100.20 STREAM mismatch.example.test" ;;
  *) exit 2 ;;
esac
EOF
cat >"$RESOLVER/ssh" <<'EOF'
#!/bin/sh
alias_name=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-G" ]; then
    alias_name="$arg"
  fi
  prev="$arg"
done
case "$alias_name" in
  frp-release-example) printf '%s\n' "hostname match.example.test" ;;
  frp-mismatch-alias) printf '%s\n' "hostname 198.51.100.21" ;;
  *) exit 1 ;;
esac
EOF
chmod 755 "$RESOLVER/getent" "$RESOLVER/ssh"
export PATH="$RESOLVER:$PATH"

export FRP_E2E_SERVER_IP=203.0.113.10
export FRP_E2E_PUBLIC_HOSTNAME=mismatch.example.test
export FRP_E2E_SERVER_ALIAS=frp-release-example
if frp_require_release_target >/tmp/release-target.out 2>/tmp/release-target.err; then
  fail "mismatched hostname/IP was accepted"
fi
grep -q 'FRP_E2E_PUBLIC_HOSTNAME' /tmp/release-target.err || fail "hostname mismatch error"

export FRP_E2E_PUBLIC_HOSTNAME=match.example.test
export FRP_E2E_SERVER_ALIAS=frp-mismatch-alias
if frp_require_release_target >/tmp/release-target.out 2>/tmp/release-target.err; then
  fail "mismatched alias/IP was accepted"
fi
grep -q 'FRP_E2E_SERVER_ALIAS' /tmp/release-target.err || fail "alias mismatch error"

export FRP_E2E_SERVER_ALIAS=frp-release-example
frp_require_release_target || fail "matching alias/hostname/IP rejected"

python3 - "$ROOT/tests/run-production-realistic-qualification.sh" <<'PY'
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(encoding="utf-8")
lines = text.splitlines()
call = next(
    (index for index, line in enumerate(lines) if "pq_precheck_hosts" in line and not line.strip().startswith("#")),
    None,
)
if call is None:
    raise SystemExit("pq_precheck_hosts call missing")
if "|| true" in lines[call]:
    raise SystemExit("pq_precheck_hosts is non-fatal")
window = "\n".join(lines[call:call + 6])
if "exit 1" not in window:
    raise SystemExit("pq_precheck_hosts failure does not exit")
matrix = next(index for index, line in enumerate(lines) if "run-real-e2e" in line)
if call > matrix:
    raise SystemExit("precheck runs after a matrix path")
print("PASS PRECHECK_FAIL_CLOSED")
PY

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
