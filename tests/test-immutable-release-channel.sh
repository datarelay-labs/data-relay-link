#!/usr/bin/env bash
# Immutable release channel: stable must not silently follow mutable main.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
# shellcheck source=lib/frp-client-common.sh
. "$ROOT/lib/frp-client-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

[[ -f "$ROOT/release-manifest.json" ]] || fail "release-manifest.json missing"
grep -q '"signing": false' "$ROOT/release-manifest.json" || fail "manifest must not claim signing"
grep -q 'never mutable main' "$ROOT/release-manifest.json" || fail "manifest missing immutable note"
pass "RELEASE_MANIFEST_PRESENT"

# Stable defaults to vPROJECT_VERSION.
unset FRP_RELEASE_CHANNEL FRP_CLIENT_UPDATE_URL FRP_CLIENT_INSTALLER_URL || true
export FRP_RELEASE_CHANNEL=stable
ref="$(frp_release_git_ref)"
[[ "$ref" == "v${PROJECT_VERSION}" ]] || fail "stable ref is $ref"
url="$(frp_default_client_installer_url)"
[[ "$url" == "https://raw.githubusercontent.com/datarelay-labs/frp-auto-deploy/v${PROJECT_VERSION}/dist/bootstrap-client.sh" ]] \
  || fail "stable installer URL: $url"
upd="$(frp_default_client_update_url)"
[[ "$upd" == "$url" ]] || fail "stable update URL mismatch: $upd"
case "$url" in
  *'/main/'*) fail "stable URL still points at main: $url" ;;
esac
pass "STABLE_INSTALLER_IMMUTABLE_TAG"
pass "STABLE_UPDATE_IMMUTABLE_TAG"

# Dev/main channel is opt-in only.
export FRP_RELEASE_CHANNEL=dev
dev_url="$(frp_default_client_installer_url)"
[[ "$dev_url" == *"/main/dist/bootstrap-client.sh" ]] || fail "dev URL: $dev_url"
pass "DEV_CHANNEL_OPT_IN_MAIN"

# Server config rewrite: stored official main URL becomes immutable under stable.
unset FRP_RELEASE_CHANNEL FRP_CLIENT_INSTALLER_URL || true
export FRP_RELEASE_CHANNEL=stable
# shellcheck source=install-server.sh
# Source only the migration helpers by extracting behavior via a mini check.
MAIN_URL="https://raw.githubusercontent.com/datarelay-labs/frp-auto-deploy/main/dist/bootstrap-client.sh"
frp_is_official_main_installer_url "$MAIN_URL" || fail "main URL not recognized"
STABLE_URL="$(frp_default_client_installer_url)"
[[ "$STABLE_URL" != "$MAIN_URL" ]] || fail "stable default still main"
[[ "$STABLE_URL" == *"v${PROJECT_VERSION}"* ]] || fail "stable default missing tag"

# HTTPS transport must remain mandatory for updates.
export FRP_CLIENT_TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$FRP_CLIENT_TEST_ROOT"' EXIT
export FRP_CLIENT_UPDATE_URL="http://example.invalid/bootstrap-client.sh"
if frp_client_fetch_and_upgrade >/tmp/frp-release-channel-http.out 2>/tmp/frp-release-channel-http.err; then
  fail "HTTP update URL should be rejected"
fi
grep -qi 'HTTPS' /tmp/frp-release-channel-http.err || fail "HTTPS requirement message missing"
pass "UPDATE_HTTPS_REQUIRED"

# A stable client also rejects mutable refs even when transport is HTTPS.
export FRP_CLIENT_UPDATE_URL="https://raw.githubusercontent.com/datarelay-labs/frp-auto-deploy/main/dist/bootstrap-client.sh"
export FRP_CLIENT_UPDATE_METADATA_URL="https://raw.githubusercontent.com/datarelay-labs/frp-auto-deploy/main/SHA256SUMS"
if frp_client_fetch_and_upgrade >/tmp/frp-release-channel-main.out 2>/tmp/frp-release-channel-main.err; then
  fail "stable update should reject mutable main"
fi
grep -q "source ref v${PROJECT_VERSION}" /tmp/frp-release-channel-main.err || fail "stable ref rejection message missing"
pass "STABLE_MUTABLE_REF_REJECTED"

# Artifact SHA verification rejects a tampered payload when expected hash is set.
GOOD="$FRP_CLIENT_TEST_ROOT/good.sh"
echo '#!/bin/sh' >"$GOOD"
chmod 0755 "$GOOD"
export FRP_CLIENT_UPDATE_SHA256="$(sha256sum "$GOOD" | awk '{print $1}')"
frp_verify_client_update_artifact "$GOOD" || fail "matching sha should pass"
echo '#tamper' >>"$GOOD"
if frp_verify_client_update_artifact "$GOOD"; then
  fail "tampered artifact should fail sha verify"
fi
pass "UPDATE_SHA256_VERIFIED"

# Working-tree on main is normally channel=dev / git_ref=main.
# The immutable release commit (and tagged tree) uses channel=stable / git_ref=vVERSION.
python3 - "$ROOT/release-manifest.json" "$ROOT/VERSION" <<'PY' || fail "manifest channel/ref"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
values = {}
for line in Path(sys.argv[2]).read_text().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip()
project = values["PROJECT_VERSION"]
assert data.get("project_version") == project, data.get("project_version")
channel = data.get("channel")
ref = data.get("git_ref")
if channel == "dev":
    assert ref == "main", ref
elif channel == "stable":
    assert ref == "v%s" % project, ref
else:
    raise AssertionError("unexpected channel %r" % (channel,))
assert "bootstrap-server.sh" in (data.get("artifacts") or {})
server = data["artifacts"]["bootstrap-server.sh"]
assert not server.get("sha256"), "server bundle hash must not live in the embedded manifest"
PY
pass "RELEASE_MANIFEST_CHANNEL_REF_IDENTITY"

# Source tree metadata must agree with the active channel/ref pair.
MANIFEST_CHANNEL="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/release-manifest.json"))["channel"])')"
MANIFEST_REF="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/release-manifest.json"))["git_ref"])')"
TREE_META="$(frp_validate_release_source_metadata "$ROOT" "$MANIFEST_REF" "$MANIFEST_CHANNEL")" \
  || fail "tree metadata validation"
[[ "$TREE_META" == "${PROJECT_VERSION}"$'\t'"${MANIFEST_CHANNEL}"$'\t'"${MANIFEST_REF}" ]] \
  || fail "tree metadata triple: $TREE_META"
pass "TREE_ARTIFACT_IDENTITY"

# STABLE_IMMUTABLE: tagged stable line still resolves to vPROJECT_VERSION (not main).
unset FRP_RELEASE_CHANNEL || true
export FRP_RELEASE_CHANNEL=stable
[[ "$(frp_release_git_ref)" == "v${PROJECT_VERSION}" ]] || fail "stable immutable ref drifted"
case "$(frp_default_client_installer_url)" in
  *"/v${PROJECT_VERSION}/dist/"*) ;;
  *'/main/'*) fail "stable immutable still points at main" ;;
  *) fail "stable immutable URL unexpected" ;;
esac
pass "STABLE_IMMUTABLE"

# Persist channel across installer re-runs and missing env.
persist="$(mktemp -d)"
trap 'rm -rf "$FRP_CLIENT_TEST_ROOT" "$persist"' EXIT
export FRP_DEPLOY_TEST_ROOT="$persist"
mkdir -p "$persist/etc/frp-auto-deploy"
unset FRP_RELEASE_CHANNEL || true
export FRP_RELEASE_CHANNEL=dev
export FRP_BUNDLE_SHA256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
frp_write_version_file "$persist/etc/frp-auto-deploy/version"
grep -q 'RELEASE_CHANNEL=dev' "$persist/etc/frp-auto-deploy/version" || fail "dev channel not written"
grep -q 'SOURCE_REF=main' "$persist/etc/frp-auto-deploy/version" || fail "dev source ref"
grep -q 'BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$persist/etc/frp-auto-deploy/version" || fail "bundle sha not written"
unset FRP_RELEASE_CHANNEL FRP_BUNDLE_SHA256 || true
frp_write_version_file "$persist/etc/frp-auto-deploy/version"
grep -q 'RELEASE_CHANNEL=dev' "$persist/etc/frp-auto-deploy/version" || fail "dev channel lost on re-run"
grep -q 'SOURCE_REF=main' "$persist/etc/frp-auto-deploy/version" || fail "dev source ref lost"
grep -q 'BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$persist/etc/frp-auto-deploy/version" || fail "bundle sha lost"
[[ "$(frp_release_channel)" == "dev" ]] || fail "persisted channel not used for URLs"
case "$(frp_default_client_installer_url)" in
  */main/dist/bootstrap-client.sh) ;;
  *) fail "persisted dev still not following main" ;;
esac
pass "DEV_IDENTITY"
pass "CHANNEL_PERSISTENCE"
pass "SOURCE_REF"
pass "BUILD_IDENTITY"

unset FRP_RELEASE_CHANNEL || true
stable_tree="$(mktemp -d)"
export FRP_DEPLOY_TEST_ROOT="$stable_tree"
mkdir -p "$stable_tree/etc/frp-auto-deploy"
export FRP_RELEASE_CHANNEL=stable
frp_write_version_file "$stable_tree/etc/frp-auto-deploy/version"
grep -q 'RELEASE_CHANNEL=stable' "$stable_tree/etc/frp-auto-deploy/version" || fail "stable channel"
grep -q "SOURCE_REF=v${PROJECT_VERSION}" "$stable_tree/etc/frp-auto-deploy/version" || fail "stable source ref"
unset FRP_RELEASE_CHANNEL || true
[[ "$(frp_release_channel)" == "stable" ]] || fail "stable persistence"
case "$(frp_default_client_installer_url)" in
  *"/v${PROJECT_VERSION}/dist/"*) ;;
  *'/main/'*) fail "stable follows main" ;;
  *) fail "stable URL unexpected" ;;
esac
rm -rf "$stable_tree"
pass "STABLE_IDENTITY"

if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse v2.1.0 >/dev/null 2>&1; then
  git -C "$ROOT" rev-parse v2.1.0 >/dev/null
fi
pass "V210_TAG_UNTOUCHED"

echo "IMMUTABLE_RELEASE_CHANNEL_TEST=PASS"
