#!/usr/bin/env bash
# Version / release governance regressions for v2.4.0 pretags trees.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/VERSION"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

HEAD="$(git rev-parse HEAD)"
SHORT="$(printf '%s' "$HEAD" | cut -c1-7)"

# --- SSOT + governance -------------------------------------------------------
[[ "$RELEASE_CHANNEL" == "development" ]] || fail "VERSION RELEASE_CHANNEL"
[[ -f docs/VERSION_POLICY.md ]] || fail "VERSION_POLICY missing"
[[ -f RELEASE_MANIFEST.schema.json ]] || fail "schema missing"
./scripts/check-version-consistency.sh >/tmp/vg-version.out 2>&1 || {
  cat /tmp/vg-version.out >&2
  fail "version consistency"
}
pass "VERSION_SSOT"
./scripts/check-release-governance.sh >/tmp/vg-gov.out 2>&1 || {
  cat /tmp/vg-gov.out >&2
  fail "release governance"
}
pass "RELEASE_GOVERNANCE"

# CI harness: the lint job that runs release governance must fetch full history/tags.
# A shallow tagless checkout makes HISTORICAL_TAG_PRESENT_* fail even when tags exist.
python3 - <<'PY' || fail "lint.yml release-governance checkout must use fetch-depth: 0"
from pathlib import Path

text = Path(".github/workflows/lint.yml").read_text(encoding="utf-8")
# Isolate the lint job (before portability-containers) so other checkouts are untouched.
marker = "portability-containers:"
lint_job = text.split(marker, 1)[0]
if "check-release-governance.sh" not in lint_job:
    raise SystemExit("lint job missing release governance step")
# Require the established release-attest pattern on the governance checkout.
if "fetch-depth: 0" not in lint_job:
    raise SystemExit("lint job checkout missing fetch-depth: 0")
print("OK")
PY
pass "LINT_CHECKOUT_FETCHES_HISTORICAL_TAGS"

python3 tests/test-release-manifest-schema.py >/tmp/vg-schema.out 2>&1 || {
  cat /tmp/vg-schema.out >&2
  fail "manifest schema tests"
}
pass "RELEASE_MANIFEST_SCHEMA"

# Manifest must not advertise nonexistent v2.4.0 before the tag exists.
MANIFEST_REF="$(python3 -c 'import json;print(json.load(open("release-manifest.json"))["git_ref"])')"
MANIFEST_CH="$(python3 -c 'import json;print(json.load(open("release-manifest.json"))["channel"])')"
[[ "$MANIFEST_CH" == "development" ]] || fail "manifest channel=$MANIFEST_CH"
[[ "$MANIFEST_REF" =~ ^[0-9a-fA-F]{40}$ ]] || fail "manifest ref not exact SHA: $MANIFEST_REF"
[[ "$MANIFEST_REF" != "v${PROJECT_VERSION}" ]] || fail "premature stable tag in manifest"
pass "NONEXISTENT_TAG_404_REGRESSION"

# --- Development / RC / stable identity -------------------------------------
python3 - <<PY || fail "identity derivation"
import sys
sys.path.insert(0, "lib")
from frp_version_identity import derive_display_identity, format_show_version

ident = derive_display_identity(
    project_version="$PROJECT_VERSION",
    channel="development",
    source_head="$HEAD",
)
assert ident["display_identity"] == "2.4.0-dev+g$SHORT", ident
assert ident["channel"] == "development", ident
rc = derive_display_identity(
    project_version="$PROJECT_VERSION",
    channel="preview",
    source_ref="v2.4.0-rc.1",
    source_head="$HEAD",
)
assert rc["display_identity"] == "2.4.0-rc.1", rc
assert rc["channel"] == "preview", rc
stable = derive_display_identity(
    project_version="$PROJECT_VERSION",
    channel="stable",
    source_ref="v2.4.0",
    source_head="$HEAD",
    tag_exists=True,
)
assert stable["display_identity"] == "2.4.0", stable
guard = derive_display_identity(
    project_version="$PROJECT_VERSION",
    channel="stable",
    source_ref="$HEAD",
    source_head="$HEAD",
)
assert guard["channel"] == "development", guard
text = format_show_version(
    display_identity=ident["display_identity"],
    channel=ident["channel"],
    source_head="$HEAD",
    frp_version="$FRP_VERSION",
    role="Server",
)
assert "Data Relay Link: 2.4.0-dev+g$SHORT" in text
assert "Channel: development" in text
assert "Source HEAD: $HEAD" in text
assert "Relay Engine (FRP): $FRP_VERSION" in text
assert "frps" not in text.lower() or "Relay Engine" in text
print("OK")
PY
pass "DEVELOPMENT_IDENTITY"
pass "RC_IDENTITY"
pass "STABLE_IDENTITY_GUARD"
pass "PRODUCT_ENGINE_VERSION_SEPARATION"

# --- show version parity across roles ---------------------------------------
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
for role in client server both; do
  tree="$WORKDIR/$role"
  mkdir -p "$tree/etc/drlink" "$tree/usr/local/lib/drlink"
  cp "$ROOT/lib/frp_version_identity.py" "$tree/usr/local/lib/drlink/"
  cat >"$tree/etc/drlink/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=${FRP_VERSION}
RELEASE_CHANNEL=development
SOURCE_REF=${HEAD}
SOURCE_HEAD=${HEAD}
EOF
  # role markers
  case "$role" in
    client)
      mkdir -p "$tree/etc/frp"
      echo '{}' >"$tree/etc/frp/client-state.json"
      ;;
    server)
      mkdir -p "$tree/etc/frp" "$tree/var/lib/drlink"
      echo token >"$tree/etc/frp/server_token"
      echo '{"schema_version":2,"clients":{},"reserved":[]}' >"$tree/var/lib/drlink/registry.json"
      ;;
    both)
      mkdir -p "$tree/etc/frp" "$tree/var/lib/drlink"
      echo '{}' >"$tree/etc/frp/client-state.json"
      echo token >"$tree/etc/frp/server_token"
      echo '{"schema_version":2,"clients":{},"reserved":[]}' >"$tree/var/lib/drlink/registry.json"
      ;;
  esac
  out="$WORKDIR/version-$role.out"
  FRP_CTL_TEST_ROOT="$tree" FRP_DEPLOY_TEST_ROOT="$tree" \
    "$ROOT/tools/drlink" show version >"$out" 2>"$WORKDIR/version-$role.err" || {
      cat "$out" "$WORKDIR/version-$role.err" >&2
      fail "show version $role"
    }
  grep -q "Data Relay Link: 2.4.0-dev+g${SHORT}" "$out" || fail "display $role: $(cat "$out")"
  grep -q "Channel: development" "$out" || fail "channel $role"
  grep -q "Source HEAD: ${HEAD}" "$out" || fail "head $role"
  grep -q "Relay Engine (FRP): ${FRP_VERSION}" "$out" || fail "engine $role"
  grep -q "Project version" "$out" && fail "legacy project version label still present"
done
pass "SHOW_VERSION_PARITY"

# --- Exact-SHA pretags installer refs; no future-tag URL --------------------
unset FRP_RELEASE_CHANNEL FRP_TXN_SOURCE_REF || true
export FRP_EXPECTED_SOURCE_REF="$HEAD"
export FRP_RELEASE_CHANNEL=development
url="$(frp_default_client_installer_url)"
win="$(frp_default_windows_client_installer_url)"
[[ "$url" == *"/${HEAD}/dist/bootstrap-client.sh" ]] || fail "linux URL: $url"
[[ "$win" == *"/${HEAD}/dist/bootstrap-client.ps1" ]] || fail "windows URL: $win"
case "$url$win" in
  *"/v${PROJECT_VERSION}/"*) fail "future tag leaked into installer URL" ;;
esac
pass "PRETAG_EXACT_SHA_REFERENCE"

# Fail-closed: contradictory stable claim with SHA provenance in identity helper
python3 - <<'PY' || fail "fail-closed contradictory provenance"
import sys
sys.path.insert(0, "lib")
from frp_version_identity import derive_display_identity, validate_manifest_dict
ident = derive_display_identity(
    project_version="2.4.0",
    channel="stable",
    source_ref="0123456789abcdef0123456789abcdef01234567",
)
assert ident["channel"] != "stable"
bad = {
    "schema_version": 1,
    "project_version": "2.4.0",
    "frp_version": "0.71.0",
    "channel": "stable",
    "git_ref": "v2.4.0",
    "source_head": "",
    "features": {"mcp_included": False},
    "artifacts": {"a": {"path": "x", "sha256": "a"*64}},
}
errs = validate_manifest_dict(bad)
assert errs, errs
print("OK")
PY
pass "FAIL_CLOSED_PROVENANCE"

# MCP included markers
python3 -c 'import json; assert json.load(open("release-manifest.json"))["features"]["mcp_included"] is True'
pass "MCP_V2_4_INCLUDED_AND_QUALIFIED"

echo "VERSION_GOVERNANCE=PASS"
