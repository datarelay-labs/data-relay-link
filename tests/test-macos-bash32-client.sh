#!/usr/bin/env bash
# macOS ships Bash 3.2. Client-side scripts must not use Bash 4+-only features.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL $*" >&2; exit 1; }

# Product paths that can run under Darwin system Bash 3.2.
files=(
  "$ROOT/tools/frp-client"
  "$ROOT/tools/drlink"
  "$ROOT/tools/frpctl"
  "$ROOT/lib/frp-client-common.sh"
  "$ROOT/lib/frp-macos.sh"
  "$ROOT/lib/frp-common.sh"
  "$ROOT/lib/frp-doctor-common.sh"
  "$ROOT/install-client.sh"
  "$ROOT/uninstall-client.sh"
)

missing=0
for f in "${files[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "MISSING $f" >&2
    missing=1
  fi
done
[[ "$missing" -eq 0 ]] || fail "expected client shell files missing"

# Bash 4+/5 constructs that break on macOS /bin/bash 3.2.
# Includes nameref (local -n / declare -n), associative arrays, mapfile,
# and case-folding expansions.
hits="$(
  grep -nE \
    '[[:space:]](mapfile|readarray)[[:space:]]|declare -A |local -n |declare -n |\$\{[A-Za-z_][A-Za-z0-9_]*,,\}|\$\{[A-Za-z_][A-Za-z0-9_]*\^\^\}' \
    "${files[@]}" \
    || true
)"
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits" >&2
  fail "client-side scripts contain Bash 4+-only features (nameref/mapfile/assoc/casefold)"
fi

echo "MACOS_BASH32_CLIENT_TEST=PASS"
echo "MACOS_BASH32_STATIC_COMPAT=PASS"
