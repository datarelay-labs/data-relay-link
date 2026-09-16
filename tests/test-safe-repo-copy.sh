#!/usr/bin/env bash
# Regression: guarded repo copy must reject unsafe ROOT and dest-inside-source.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/tests/lib/frp-test-safe-copy.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d /tmp/frp-test-safe-copy.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# Empty ROOT must fail (bash "$ROOT/." → "/." footgun).
if frp_test_require_repo_root "" 2>"$WORKDIR/empty.err"; then
  fail "empty ROOT should be rejected"
fi
grep -qi 'unsafe\|empty' "$WORKDIR/empty.err" || fail "empty ROOT error unclear"
pass "REJECT_EMPTY_ROOT"

# ROOT=/ must fail.
if frp_test_require_repo_root "/" 2>"$WORKDIR/slash.err"; then
  fail "ROOT=/ should be rejected"
fi
grep -qi 'unsafe\|empty' "$WORKDIR/slash.err" || fail "ROOT=/ error unclear"
pass "REJECT_ROOT_SLASH"

# Non-repo path must fail.
mkdir -p "$WORKDIR/not-a-repo"
if frp_test_require_repo_root "$WORKDIR/not-a-repo" 2>"$WORKDIR/norepo.err"; then
  fail "non-repo ROOT should be rejected"
fi
grep -qi 'release-manifest' "$WORKDIR/norepo.err" || fail "missing-manifest error unclear"
pass "REJECT_NON_REPO_ROOT"

# Destination inside source must fail (recursive self-copy).
NEST="$WORKDIR/nest-src"
mkdir -p "$NEST"
cp "$ROOT/release-manifest.json" "$NEST/release-manifest.json"
if frp_test_copy_repo_tree "$NEST" "$NEST/inside" 2>"$WORKDIR/nested.err"; then
  fail "dest-inside-source should be rejected"
fi
grep -qi 'inside source\|self-copy' "$WORKDIR/nested.err" || fail "nested dest error unclear"
pass "REJECT_DEST_INSIDE_SOURCE"

# Valid copy succeeds and is bounded (no .git).
GOOD="$WORKDIR/good-copy"
frp_test_copy_repo_tree "$ROOT" "$GOOD" || fail "valid copy should succeed"
[[ -f "$GOOD/release-manifest.json" ]] || fail "copied manifest missing"
[[ ! -e "$GOOD/.git" ]] || fail "copy must exclude .git"
pass "VALID_BOUNDED_COPY"

# Cleanup of named temp root on EXIT (prove trap path).
PROOF="$(mktemp -d /tmp/frp-test-safe-copy-cleanup.XXXXXX)"
bash -c '
  set -euo pipefail
  ROOT="'"$ROOT"'"
  # shellcheck disable=SC1091
  . "$ROOT/tests/lib/frp-test-procs.sh"
  WORKDIR="'"$PROOF"'"
  frp_test_arm_cleanup
  touch "$WORKDIR/marker"
  exit 0
'
[[ ! -e "$PROOF" ]] || fail "EXIT cleanup should remove WORKDIR"
pass "TEMP_CLEANUP_ON_EXIT"

# Failed run also cleans.
PROOF2="$(mktemp -d /tmp/frp-test-safe-copy-cleanup-fail.XXXXXX)"
bash -c '
  set -euo pipefail
  ROOT="'"$ROOT"'"
  # shellcheck disable=SC1091
  . "$ROOT/tests/lib/frp-test-procs.sh"
  WORKDIR="'"$PROOF2"'"
  frp_test_arm_cleanup
  touch "$WORKDIR/marker"
  exit 1
' || true
[[ ! -e "$PROOF2" ]] || fail "FAIL-path cleanup should remove WORKDIR"
pass "TEMP_CLEANUP_ON_FAIL"

echo "ALL PASS test-safe-repo-copy"
