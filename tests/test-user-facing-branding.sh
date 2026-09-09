#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_not_contains() {
  local path="$1" pattern="$2"
  if rg -n "$pattern" "$path" >/dev/null 2>&1; then
    fail "$path contains forbidden branding pattern: $pattern"
  fi
}

assert_contains() {
  local text="$1" pattern="$2"
  if ! grep -qE "$pattern" <<<"$text"; then
    fail "expected pattern not found: $pattern"
  fi
}

# User-facing docs and install flows must not expose legacy product/CLI terms.
assert_not_contains "$ROOT/README.md" 'FRP Auto Deploy|frpctl|frp>'
assert_not_contains "$ROOT/docs/CLI_REFERENCE.md" 'FRP Auto Deploy|frpctl|frp>'
assert_not_contains "$ROOT/docs/CONTROLLED_EGRESS.md" 'FRP Auto Deploy|frpctl|frp>'
assert_not_contains "$ROOT/docs/SECURITY.md" 'FRP Auto Deploy|frpctl|frp>'

mkdir -p "$WORK/root/etc/frp-auto-deploy" "$WORK/root/var/lib/frp-auto-deploy"
cat >"$WORK/root/etc/frp-auto-deploy/config.json" <<'JSON'
{"registry_file":"/var/lib/frp-auto-deploy/registry.json"}
JSON
cat >"$WORK/root/var/lib/frp-auto-deploy/registry.json" <<'JSON'
{"schema_version":2,"clients":{},"used_ports":{}}
JSON

help_out="$(FRP_CTL_TEST_ROOT="$WORK/root" "$ROOT/tools/drlink" --help)"
assert_contains "$help_out" 'Usage: drlink'
assert_contains "$help_out" 'Data Relay Link'
if grep -qE 'frpctl|FRP Auto Deploy|frp>' <<<"$help_out"; then
  fail "drlink --help leaked legacy branding"
fi

repl_out="$(printf 'exit\n' | FRP_CTL_TEST_ROOT="$WORK/root" FRP_CTL_TEST_INPUT=$'exit\n' "$ROOT/tools/drlink" 2>&1 || true)"
assert_contains "$repl_out" 'drlink>'
assert_contains "$repl_out" 'Data Relay Link'
if grep -qE 'frpctl>|FRP Auto Deploy' <<<"$repl_out"; then
  fail "interactive drlink output leaked legacy branding"
fi

echo "USER_FACING_BRANDING_TEST=PASS"
