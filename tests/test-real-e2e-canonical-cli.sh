#!/usr/bin/env bash
# Static contract: Real E2E operator workflows must use canonical drlink.
# Fixture/evidence reads may still mention internal paths; this gate only
# rejects direct management/dispatch of backend tools in run-real-e2e.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E="$ROOT/tests/run-real-e2e.sh"
fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }

[[ -f "$E2E" ]] || fail "missing run-real-e2e.sh"

# Forbidden: direct backend management used as the operator path.
if grep -nE \
  '/usr/local/lib/drlink/frp-create-client|/usr/local/bin/frp-client |/usr/local/lib/drlink/frp-server-set|frp-client add-service|frp-client set-service|frp-client enable-service|frp-client disable-service|frp-client apply-pending|frp-client sync' \
  "$E2E" | grep -v '^#' >/dev/null; then
  grep -nE \
    '/usr/local/lib/drlink/frp-create-client|/usr/local/bin/frp-client |/usr/local/lib/drlink/frp-server-set|frp-client add-service|frp-client set-service|frp-client enable-service|frp-client disable-service|frp-client apply-pending|frp-client sync' \
    "$E2E" >&2 || true
  fail "Real E2E still invokes backend tools for operator workflows"
fi
pass "NO_DIRECT_BACKEND_OPERATOR_CALLS"

# Forbidden: drlink failure falling through to backend still counts as PASS.
if grep -nE \
  'drlink[^|]*\|\|[[:space:]]*(sudo[[:space:]]+)?(/usr/local/(bin|lib/drlink)/)?frp-(create-client|client|server-set|release|set-)' \
  "$E2E" >/dev/null; then
  grep -nE \
    'drlink[^|]*\|\|[[:space:]]*(sudo[[:space:]]+)?(/usr/local/(bin|lib/drlink)/)?frp-(create-client|client|server-set|release|set-)' \
    "$E2E" >&2 || true
  fail "Real E2E still has drlink||backend escape hatch"
fi
pass "NO_DRLINK_BACKEND_FALLBACK"

# Forbidden: direct config.json mutation for installer URL pinning.
if grep -nE "config\.json.*client_installer_url|c\['client_installer_url'\]|c\['windows_client_installer_url'\]" "$E2E" >/dev/null; then
  grep -nE "config\.json.*client_installer_url|c\['client_installer_url'\]|c\['windows_client_installer_url'\]" "$E2E" >&2 || true
  fail "Real E2E still patches config.json for installer URLs"
fi
pass "NO_DIRECT_INSTALLER_JSON_PATCH"

# Required: canonical installer pin + guided zero-touch.
grep -q "set installer-url" "$E2E" || fail "missing set installer-url pin"
grep -q "set windows-installer-url" "$E2E" || fail "missing set windows-installer-url pin"
grep -q "drlink create zero-touch" "$E2E" || fail "missing create zero-touch"
pass "CANONICAL_INSTALLER_AND_ZERO_TOUCH"

echo "REAL_E2E_CANONICAL_CLI_CONTRACT=PASS"
