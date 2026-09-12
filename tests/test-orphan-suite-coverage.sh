#!/usr/bin/env bash
# Meta-test: every tests/test-*.{sh,py} must be invoked by run-all.sh unless
# allowlisted (E2E / special infrastructure / intentionally separate).
# Also: every tests/windows/test-*.ps1 must be listed by tests/windows/run-all.ps1.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ALL="$ROOT/tests/run-all.sh"
WIN_RUN_ALL="$ROOT/tests/windows/run-all.ps1"
ALLOWLIST="$ROOT/tests/orphan-test-allowlist.txt"

[[ -f "$RUN_ALL" ]] || { echo "FAIL: missing run-all.sh"; exit 1; }
[[ -f "$ALLOWLIST" ]] || { echo "FAIL: missing orphan-test-allowlist.txt"; exit 1; }
[[ -f "$WIN_RUN_ALL" ]] || { echo "FAIL: missing tests/windows/run-all.ps1"; exit 1; }

mapfile -t ALLOWED < <(grep -vE '^\s*(#|$)' "$ALLOWLIST" | sed 's/\r$//' | sort -u)
declare -A allow
for a in "${ALLOWED[@]}"; do allow["$a"]=1; done

run_all_text="$(cat "$RUN_ALL")"
win_run_all_text="$(cat "$WIN_RUN_ALL")"

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

mapfile -t WIN_FOUND < <(
  cd "$ROOT"
  find tests/windows -maxdepth 1 -type f -name 'test-*.ps1' \
    | sed 's|^tests/windows/||' | sort
)

win_missing=()
for f in "${WIN_FOUND[@]}"; do
  if grep -qF "'$f'" <<<"$win_run_all_text" || grep -qF "\"$f\"" <<<"$win_run_all_text"; then
    continue
  fi
  if [[ -n "${allow[windows/$f]:-}" || -n "${allow[$f]:-}" ]]; then
    continue
  fi
  win_missing+=("windows/$f")
done

if ((${#missing[@]})) || ((${#win_missing[@]})); then
  echo "FAIL: tests not invoked by platform runners and not allowlisted:" >&2
  printf '  %s\n' "${missing[@]}" "${win_missing[@]}" >&2
  exit 1
fi
echo "ORPHAN_TEST_CHECK=PASS (${#FOUND[@]} top-level + ${#WIN_FOUND[@]} windows candidates)"
