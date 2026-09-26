#!/usr/bin/env bash
# One Full Real E2E release pass. The Engineering System contract invokes this
# twice (full_e2e_passes: 2): the first call is PASS1 and the second is PASS2.
# Both calls must observe the same Git HEAD. This script does not commit, tag,
# or release.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/require-release-target.sh
source "$ROOT/tests/lib/require-release-target.sh"
frp_require_release_target

HEAD="$(git -C "$ROOT" rev-parse HEAD)"
STATE_DIR="$ROOT/e2e-reports/release-qualification"
STATE="$STATE_DIR/state.env"
mkdir -p "$STATE_DIR"

if [[ ! -f "$STATE" ]]; then
  printf 'QUALIFIED_HEAD=%s\nNEXT=PASS2\n' "$HEAD" >"$STATE"
  if ! bash "$ROOT/tests/run-production-realistic-qualification.sh" PASS1; then
    rm -f "$STATE"
    exit 1
  fi
  now="$(git -C "$ROOT" rev-parse HEAD)"
  if [[ "$now" != "$HEAD" ]]; then
    echo "ERROR: PASS1 changed HEAD from $HEAD to $now" >&2
    rm -f "$STATE"
    exit 1
  fi
  echo "PASS1_HEAD=$HEAD"
  exit 0
fi

# shellcheck disable=SC1090
source "$STATE"
if [[ "${QUALIFIED_HEAD:-}" != "$HEAD" ]]; then
  echo "ERROR: PASS2 HEAD $HEAD != PASS1_HEAD ${QUALIFIED_HEAD:-}" >&2
  exit 1
fi
if [[ "${NEXT:-}" != "PASS2" ]]; then
  echo "ERROR: qualification for $HEAD is already recorded; do not add a commit and reuse it" >&2
  exit 1
fi
if ! bash "$ROOT/tests/run-production-realistic-qualification.sh" PASS2; then
  exit 1
fi
now="$(git -C "$ROOT" rev-parse HEAD)"
if [[ "$now" != "$HEAD" ]]; then
  echo "ERROR: PASS2 changed HEAD from $HEAD to $now" >&2
  exit 1
fi
printf 'QUALIFIED_HEAD=%s\nNEXT=DONE\n' "$HEAD" >"$STATE"
echo "PASS1_HEAD=$HEAD"
echo "PASS2_HEAD=$HEAD"
echo "FINAL_QUALIFIED_HEAD=$HEAD"
