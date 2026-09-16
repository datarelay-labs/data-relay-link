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
  if ! command -v grep >/dev/null 2>&1; then
    fail "grep is required for branding assertions"
  fi
  if grep -nE "$pattern" "$path" >/dev/null 2>&1; then
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
USER_DOCS=(
  "$ROOT/README.md"
  "$ROOT/docs/CLI_REFERENCE.md"
  "$ROOT/docs/CONTROLLED_EGRESS.md"
  "$ROOT/docs/SECURITY.md"
  "$ROOT/docs/PRODUCT_MASTER.md"
  "$ROOT/docs/DEPLOYMENT_MODES.md"
  "$ROOT/docs/WINDOWS_CLIENT.md"
  "$ROOT/docs/MACOS_CLIENT.md"
)
for doc in "${USER_DOCS[@]}"; do
  [[ -f "$doc" ]] || continue
  assert_not_contains "$doc" 'FRP Auto Deploy|FRP Auto-Deploy|frpctl>|sudo frpctl|frp>'
done

# Runtime surfaces that operators see.
RUNTIME=(
  "$ROOT/lib/frp_ctl_grammar.py"
  "$ROOT/lib/frp_doctor.py"
  "$ROOT/lib/frp_pki.py"
  "$ROOT/lib/frp_zero_touch.py"
  "$ROOT/lib/frp-doctor-common.sh"
  "$ROOT/tools/frp-server-status"
  "$ROOT/tools/frp-client"
  "$ROOT/server/drlink-server.service"
  "$ROOT/server/drlink-egress.service"
  "$ROOT/server/drlink-allocator.service"
  "$ROOT/server/drlink-access.service"
  "$ROOT/client/drlink-client.service"
)
for f in "${RUNTIME[@]}"; do
  [[ -f "$f" ]] || continue
  assert_not_contains "$f" 'FRP Auto Deploy|FRP Auto-Deploy|sudo frpctl|frpctl>'
done

# Product unit names must be drlink-*; legacy names must not be the installed sources.
[[ -f "$ROOT/server/drlink-server.service" ]] || fail "missing drlink-server.service"
[[ -f "$ROOT/client/drlink-client.service" ]] || fail "missing drlink-client.service"
[[ -f "$ROOT/server/drlink-egress.service" ]] || fail "missing drlink-egress.service"
grep -q 'Description=Data Relay Link Server' "$ROOT/server/drlink-server.service" || fail "server unit description"
grep -q 'Description=Data Relay Link Client' "$ROOT/client/drlink-client.service" || fail "client unit description"

# Manifest installs drlink on PATH and keeps frpctl internal.
grep -q 'usr/local/bin/drlink' "$ROOT/lib/server-project-files.manifest" || fail "manifest missing drlink"
grep -q 'usr/local/lib/drlink/frpctl' "$ROOT/lib/server-project-files.manifest" || fail "manifest missing internal frpctl"
if grep -qE 'usr/local/(bin|sbin)/frpctl' "$ROOT/lib/server-project-files.manifest"; then
  fail "manifest still installs frpctl on PATH"
fi

mkdir -p "$WORK/root/etc/drlink" "$WORK/root/var/lib/drlink"
cat >"$WORK/root/etc/drlink/config.json" <<'JSON'
{"registry_file":"/var/lib/drlink/registry.json"}
JSON
cat >"$WORK/root/var/lib/drlink/registry.json" <<'JSON'
{"schema_version":2,"clients":{},"used_ports":{}}
JSON

help_out="$(FRP_CTL_TEST_ROOT="$WORK/root" "$ROOT/tools/drlink" --help)"
assert_contains "$help_out" 'Usage: drlink'
assert_contains "$help_out" 'Data Relay Link'
if grep -qE 'frpctl>|FRP Auto Deploy|Usage: frpctl' <<<"$help_out"; then
  fail "drlink --help leaked legacy branding"
fi

repl_out="$(printf 'exit\n' | FRP_CTL_TEST_ROOT="$WORK/root" FRP_CTL_TEST_INPUT=$'exit\n' "$ROOT/tools/drlink" 2>&1 || true)"
assert_contains "$repl_out" 'drlink>'
assert_contains "$repl_out" 'Data Relay Link'
if grep -qE 'frpctl>|FRP Auto Deploy' <<<"$repl_out"; then
  fail "interactive drlink output leaked legacy branding"
fi


# Expanded surfaces: installers, zero-touch helpers, enrollment CLI text.
EXTRA_RUNTIME=(
  "$ROOT/install-client.sh"
  "$ROOT/install-server.sh"
  "$ROOT/lib/frp-client-common.sh"
  "$ROOT/tools/frp-create-client"
  "$ROOT/tools/drlink"
  "$ROOT/tools/frpctl"
  "$ROOT/docs/DATA_RELAY_ROADMAP.md"
  "$ROOT/docs/OCI_ACCEPTANCE.md"
  "$ROOT/docs/RELEASE_VALIDATION.md"
  "$ROOT/docs/SCHEMA_V2_DEPLOYMENT.md"
  "$ROOT/docs/FRP_UPGRADE.md"
)
for f in "${EXTRA_RUNTIME[@]}"; do
  [[ -f "$f" ]] || continue
  # "Usage: frpctl " (with space) catches CLI help; allow internal function names like frpctl_zt_*.
  assert_not_contains "$f" 'FRP Auto Deploy|FRP Auto-Deploy|frpctl>|sudo frpctl|Usage: frpctl '
done

# Manifest must not install management helpers onto PATH under legacy names.
if grep -qE 'usr/local/(bin|sbin)/frp-(create-client|clients|server-status|backup|restore)\b' "$ROOT/lib/server-project-files.manifest"; then
  fail "manifest still installs legacy management tools on PATH"
fi

# Installer completion / info labels
assert_not_contains "$ROOT/install-client.sh" 'FRP client setup complete|Your FRP client is running|FRP Installation Complete'
assert_not_contains "$ROOT/lib/frp-client-common.sh" "FRP Server:"
assert_not_contains "$ROOT/tools/frp-create-client" "FRP Server:"


# Explicit allowlist: internal backend filename and historical migration helpers may mention frpctl.
# This test fails closed on operator-facing docs/runtime above.

# Repository / docs identity regression after GitHub transfer+rename.
for f in "$ROOT/README.md" "$ROOT/GITHUB_SETUP.md" "$ROOT/release-manifest.json" "$ROOT/lib/frp-common.sh"; do
  [[ -f "$f" ]] || fail "missing identity file: $f"
  grep -q 'datarelay-labs' "$f" || fail "$f missing datarelay-labs"
  grep -q 'data-relay-link' "$f" || fail "$f missing data-relay-link"
done
grep -q 'Data Relay Link' "$ROOT/README.md" || fail "README missing Data Relay Link"
grep -q 'drlink' "$ROOT/README.md" || fail "README missing drlink"
grep -q 'link.datarelay.run' "$ROOT/README.md" || fail "README missing public docs URL"
assert_not_contains "$ROOT/README.md" 'xdr-labs/frp-auto-deploy|frp\.xdr\.ooo|FRP Auto Deploy'
assert_not_contains "$ROOT/GITHUB_SETUP.md" 'xdr-labs/frp-auto-deploy|frp\.xdr\.ooo'
assert_not_contains "$ROOT/release-manifest.json" 'xdr-labs|"frp-auto-deploy"'
# Defaults must not point at the former product repository.
if grep -nE 'FRP_GITHUB_OWNER=.*xdr-labs|DRLINK_GITHUB_OWNER=.*xdr-labs|:-xdr-labs' "$ROOT/lib/frp-common.sh"; then
  fail "frp-common still defaults GitHub owner to xdr-labs"
fi
if grep -nE 'FRP_GITHUB_REPO=.*frp-auto-deploy|DRLINK_GITHUB_REPO=.*frp-auto-deploy|:-frp-auto-deploy' "$ROOT/lib/frp-common.sh"; then
  fail "frp-common still defaults GitHub repo to frp-auto-deploy"
fi

echo "USER_FACING_BRANDING_TEST=PASS"
echo "USER_FACING_LEGACY_PRODUCT_REFERENCES=0"
echo "REPOSITORY_IDENTITY=datarelay-labs/data-relay-link"
