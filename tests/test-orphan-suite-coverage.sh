#!/usr/bin/env bash
# Meta-test: every tests/test-*.{sh,py} must be invoked by run-all.sh unless
# allowlisted (E2E / special infrastructure / intentionally separate).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ALL="$ROOT/tests/run-all.sh"
ALLOWLIST="$ROOT/tests/orphan-test-allowlist.txt"

[[ -f "$RUN_ALL" ]] || { echo "FAIL: missing run-all.sh"; exit 1; }
[[ -f "$ALLOWLIST" ]] || { echo "FAIL: missing orphan-test-allowlist.txt"; exit 1; }

mapfile -t ALLOWED < <(grep -vE '^\s*(#|$)' "$ALLOWLIST" | sed 's/\r$//' | sort -u)
declare -A allow
for a in "${ALLOWED[@]}"; do allow["$a"]=1; done

run_all_text="$(cat "$RUN_ALL")"

covered_by_glob() {
  local f="$1"
  # run-all uses: for macos_test in ./tests/test-macos-*.sh; do
  if [[ "$f" == test-macos-*.sh ]] && grep -q 'test-macos-\*\.sh' <<<"$run_all_text"; then
    return 0
  fi
  return 1
}

mapfile -t FOUND < <(
  cd "$ROOT"
  find tests -maxdepth 1 -type f \( -name 'test-*.sh' -o -name 'test-*.py' \) \
    | sed 's|^tests/||' | sort
)

missing=()
for f in "${FOUND[@]}"; do
  if [[ "$f" == "test-orphan-suite-coverage.sh" ]]; then
    continue
  fi
  if grep -qE "(^|[[:space:]/\"'])${f//./\\.}" <<<"$run_all_text"; then
    continue
  fi
  if covered_by_glob "$f"; then
    continue
  fi
  if [[ -n "${allow[$f]:-}" ]]; then
    continue
  fi
  missing+=("$f")
done

if ((${#missing[@]})); then
  echo "FAIL: tests not invoked by run-all.sh and not allowlisted:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi
echo "ORPHAN_TEST_CHECK=PASS (${#FOUND[@]} candidates)"
