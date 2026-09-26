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

# Required: canonical installer pin + guided zero-touch via public set client.
grep -q "set installer-url" "$E2E" || fail "missing set installer-url pin"
grep -q "set windows-installer-url" "$E2E" || fail "missing set windows-installer-url pin"
grep -q 'drlink set client"' "$E2E" || fail "missing public set client onboarding"
grep -q "FRP_CTL_TEST_INPUT" "$E2E" || fail "zero-touch must use FRP_CTL_TEST_INPUT under sudo use_pty"
grep -q "base64" "$E2E" || fail "zero-touch TEST_INPUT must be base64-safe across remote shells"
# Guided answers must include the post-identity service-mode choice (SSH only).
grep -Fq '\"$note_text\" '\''1'\'' \"$TUNNEL_SSH_USER\"' "$E2E" \
  || grep -Fq "\"\$note_text\" '1' \"\$TUNNEL_SSH_USER\"" "$E2E" \
  || fail "zero-touch guided answers missing SSH-only step"
pass "CANONICAL_INSTALLER_AND_ZERO_TOUCH"

# set installer-url must not resolve through set server (URL-as-setting bug).
python3 - "$ROOT" <<'PY' || fail "set installer-url catalog resolve regression"
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "lib"))
import frp_cli_catalog as c
import frp_ctl_grammar as g
tokens = ["set", "installer-url", "https://example.com/install-client.sh"]
resolved = c.resolve_tokens(tokens, role="server")
if resolved != tokens:
    raise SystemExit("resolve mutated set installer-url: %r" % resolved)
matched = g.match(tokens, "server")
if matched.get("status") != "ok" or matched.get("action") != "set_installer_url":
    raise SystemExit("match failed: %r" % matched)
print("ok")
PY
pass "SET_INSTALLER_URL_NOT_ALIASED_TO_SET_SERVER"

echo "REAL_E2E_CANONICAL_CLI_CONTRACT=PASS"
