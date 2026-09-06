#!/usr/bin/env bash
# macOS ships Bash 3.2. Client-side scripts must not use Bash 4-only builtins.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL $*" >&2; exit 1; }
hits="$(grep -nE '[[:space:]](mapfile|readarray)[[:space:]]|declare -A ' \
  "$ROOT/tools/frp-client" \
  "$ROOT/lib/frp-client-common.sh" \
  "$ROOT/lib/frp-macos.sh" \
  "$ROOT/tools/frpctl" \
  || true)"
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits" >&2
  fail "client-side scripts contain Bash 4-only features (mapfile/readarray/declare -A)"
fi
echo "MACOS_BASH32_CLIENT_TEST=PASS"
