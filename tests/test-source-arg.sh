#!/usr/bin/env bash
# Finding E: --source requires a directory argument before any mutation.
#
# TEST_CHANGE_REASON=ambient FRP_SERVER_SOURCED=1 from a parent shell that
# previously sourced install-server.sh makes the installer entrypoint no-op,
# causing a false FAIL ("missing --source succeeded").
# PRODUCT_CONTRACT=install-server.sh/--client must validate --source when
# executed as an entrypoint (FRP_*_SOURCED unset/not 1).
# WHY_OLD_ASSERTION_WAS_WRONG=assertion was correct; the test harness could
# inherit SOURCED=1 and skip the entrypoint entirely.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# Installer entrypoints no-op when SOURCED=1. Never inherit ambient pollution
# from a parent shell that previously sourced install-*.sh for unit tests.
unset FRP_SERVER_SOURCED FRP_CLIENT_SOURCED || true

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

# Executed installers must still parse CLI even if a parent leaked SOURCED=1.
# (BASH_SOURCE gate; unsetting alone is not enough when env is polluted.)
export FRP_CLIENT_SOURCED=1
export FRP_SERVER_SOURCED=1
if "$ROOT/install-client.sh" --upgrade --source >"$WORKDIR/leak-client.out" 2>"$WORKDIR/leak-client.err"; then
  fail "leaked FRP_CLIENT_SOURCED made missing --source succeed"
fi
grep -q 'ERROR: --source requires a directory' "$WORKDIR/leak-client.err" \
  || fail "leaked FRP_CLIENT_SOURCED skipped client entrypoint"
if "$ROOT/install-server.sh" --upgrade --source >"$WORKDIR/leak-server.out" 2>"$WORKDIR/leak-server.err"; then
  fail "leaked FRP_SERVER_SOURCED made missing --source succeed"
fi
grep -q 'ERROR: --source requires a directory' "$WORKDIR/leak-server.err" \
  || fail "leaked FRP_SERVER_SOURCED skipped server entrypoint"
unset FRP_CLIENT_SOURCED FRP_SERVER_SOURCED || true
pass "SOURCED_LEAK_DOES_NOT_SKIP_EXECUTED_ENTRYPOINT"

echo "SOURCE_ARG_VALIDATION_TEST=PASS"
