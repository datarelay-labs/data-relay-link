#!/usr/bin/env bash
# F13: typo suggestion must work without /dev/fd/N (macOS-safe module entrypoint).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Direct grammar entrypoint (what frpctl_suggest now uses).
out="$(printf '%s\n' client group status help | python3 "$ROOT/lib/frp_ctl_grammar.py" suggest clints)"
grep -qx 'client' <<<"$out" || fail "suggest_commands missing client for clints: $out"

# Ensure frpctl no longer depends on /dev/fd for suggestions.
if grep -n 'python3 /dev/fd/' "$ROOT/tools/frpctl" | grep -v '^#' >/dev/null 2>&1; then
  fail "frpctl still uses python3 /dev/fd/ for suggestions"
fi

# Smoke: grammar suggest via installed-style path resolution in a temp root.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/usr/local/lib/drlink" "$tmp/usr/local/sbin"
cp "$ROOT/lib/frp_ctl_grammar.py" "$tmp/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_cli_catalog.py" "$tmp/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_cli_final_commands.json" "$tmp/usr/local/lib/drlink/"
# Minimal frpctl fragment: call suggest helper if present by sourcing is heavy;
# instead verify module path used by frpctl_grammar_py pattern.
python3 "$tmp/usr/local/lib/drlink/frp_ctl_grammar.py" suggest statu <<EOF | grep -qx status
status
stat
client
EOF

echo "PASS test-frpctl-suggest-portable.sh"
