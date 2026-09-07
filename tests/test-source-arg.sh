#!/usr/bin/env bash
# Finding E: --source requires a directory argument before any mutation.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/frp" "$TREE/usr/local/bin"
export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_SKIP_DOWNLOAD=1
export FRP_SKIP_SYSTEMD=1

if "$ROOT/install-client.sh" --upgrade --source >"$WORKDIR/missing.out" 2>"$WORKDIR/missing.err"; then
  fail "missing --source argument succeeded"
fi
grep -q 'ERROR: --source requires a directory' "$WORKDIR/missing.err" || fail "missing --source message"
[[ ! -f "$TREE/usr/local/bin/frp-client" ]] || fail "missing --source mutated tree"
pass "CLIENT_SOURCE_MISSING_ARG"

if "$ROOT/install-client.sh" --upgrade --source --check >"$WORKDIR/flag.out" 2>"$WORKDIR/flag.err"; then
  fail "--source --check succeeded"
fi
grep -q 'ERROR: --source requires a directory' "$WORKDIR/flag.err" || fail "--source --check message"
pass "CLIENT_SOURCE_FLAG_AS_VALUE"

if "$ROOT/install-server.sh" --upgrade --source >"$WORKDIR/srv.out" 2>"$WORKDIR/srv.err"; then
  fail "server missing --source succeeded"
fi
grep -q 'ERROR: --source requires a directory' "$WORKDIR/srv.err" || fail "server missing --source message"
pass "SERVER_SOURCE_MISSING_ARG"

if "$ROOT/install-server.sh" --upgrade --source --check >"$WORKDIR/srvflag.out" 2>"$WORKDIR/srvflag.err"; then
  fail "server --source --check succeeded"
fi
grep -q 'ERROR: --source requires a directory' "$WORKDIR/srvflag.err" || fail "server --source --check message"
pass "SERVER_SOURCE_FLAG_AS_VALUE"

# Valid syntax is accepted by the parser (check-only may still report not enrolled).
set +e
"$ROOT/install-client.sh" --upgrade --source "$ROOT" --check >"$WORKDIR/ok.out" 2>"$WORKDIR/ok.err"
set -e
if grep -q 'ERROR: --source requires a directory' "$WORKDIR/ok.err" "$WORKDIR/ok.out"; then
  fail "valid --source DIR treated as missing"
fi
pass "CLIENT_SOURCE_DIR_ACCEPTED"

echo "SOURCE_ARG_VALIDATION_TEST=PASS"
