#!/usr/bin/env bash
# Exact-SHA RC installs must preserve SOURCE_REF and Zero-Touch installer URLs.
# Tagged installs must keep vX.Y.Z defaults. Explicit URL overrides win.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

FAKE_SHA='0123456789abcdef0123456789abcdef01234567'
# shellcheck source=../VERSION
. "$ROOT/VERSION"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

reset_provenance_env() {
  unset FRP_EXPECTED_SOURCE_REF FRP_TXN_SOURCE_REF FRP_BOOTSTRAP_URL \
    FRP_CLIENT_INSTALLER_URL FRP_WINDOWS_CLIENT_INSTALLER_URL \
    FRP_RELEASE_CHANNEL FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
    FRP_CTL_TEST_ROOT || true
}

# --- tagged / channel default preserved ---
reset_provenance_env
export FRP_RELEASE_CHANNEL=stable
[[ "$(frp_release_git_ref)" == "v${PROJECT_VERSION}" ]] || fail "stable default ref"
case "$(frp_default_client_installer_url)" in
  *"/v${PROJECT_VERSION}/dist/bootstrap-client.sh") ;;
  *) fail "stable linux default URL: $(frp_default_client_installer_url)" ;;
esac
case "$(frp_default_windows_client_installer_url)" in
  *"/v${PROJECT_VERSION}/dist/bootstrap-client.ps1") ;;
  *) fail "stable windows default URL" ;;
esac
pass "FINAL_TAG_DEFAULT_PRESERVED"

# --- exact SHA via FRP_EXPECTED_SOURCE_REF ---
reset_provenance_env
export FRP_EXPECTED_SOURCE_REF="$FAKE_SHA"
export FRP_RELEASE_CHANNEL=stable
export FRP_DEPLOY_TEST_ROOT="$WORKDIR/sha-tree"
mkdir -p "$FRP_DEPLOY_TEST_ROOT/etc/drlink"
frp_write_version_file "$FRP_DEPLOY_TEST_ROOT/etc/drlink/version"
grep -q "SOURCE_REF=${FAKE_SHA}" "$FRP_DEPLOY_TEST_ROOT/etc/drlink/version" \
  || fail "SOURCE_REF not preserved for exact SHA"
[[ "$(frp_release_git_ref)" == "$FAKE_SHA" ]] || fail "release_git_ref ignored EXPECTED"
linux_url="$(frp_default_client_installer_url)"
win_url="$(frp_default_windows_client_installer_url)"
[[ "$linux_url" == *"/${FAKE_SHA}/dist/bootstrap-client.sh" ]] \
  || fail "linux default used premature tag: $linux_url"
[[ "$win_url" == *"/${FAKE_SHA}/dist/bootstrap-client.ps1" ]] \
  || fail "windows default used premature tag: $win_url"
grep -q "v${PROJECT_VERSION}" <<<"$linux_url$win_url" && \
  fail "premature v${PROJECT_VERSION} tag substitution in defaults"
pass "RC_EXACT_SHA_SOURCE_REF_PRESERVED"

# Persist SOURCE_REF alone (no EXPECTED env) still drives defaults.
reset_provenance_env
export FRP_DEPLOY_TEST_ROOT="$WORKDIR/sha-tree"
export FRP_RELEASE_CHANNEL=stable
[[ "$(frp_release_git_ref)" == "$FAKE_SHA" ]] || fail "persisted SOURCE_REF ignored"
case "$(frp_default_client_installer_url)" in
  *"/${FAKE_SHA}/dist/bootstrap-client.sh") ;;
  *) fail "persisted SOURCE_REF linux URL" ;;
esac
pass "PERSISTED_SOURCE_REF_DRIVES_DEFAULTS"

# --- infer from bootstrap / installer URL ---
reset_provenance_env
export FRP_BOOTSTRAP_URL="https://raw.githubusercontent.com/datarelay-labs/datarelay-link/${FAKE_SHA}/dist/bootstrap-server.sh"
frp_infer_expected_source_ref
[[ "${FRP_EXPECTED_SOURCE_REF:-}" == "$FAKE_SHA" ]] || fail "infer from FRP_BOOTSTRAP_URL"
pass "INFER_FROM_BOOTSTRAP_URL"

reset_provenance_env
export FRP_CLIENT_INSTALLER_URL="https://raw.githubusercontent.com/datarelay-labs/datarelay-link/${FAKE_SHA}/dist/bootstrap-client.sh"
frp_infer_expected_source_ref
[[ "${FRP_EXPECTED_SOURCE_REF:-}" == "$FAKE_SHA" ]] || fail "infer from client installer URL"
pass "INFER_FROM_CLIENT_INSTALLER_URL"

# Pre-rename raw repository URLs must still yield SOURCE_REF for upgrade/provenance.
reset_provenance_env
export FRP_BOOTSTRAP_URL="https://raw.githubusercontent.com/datarelay-labs/data-relay-link/${FAKE_SHA}/dist/bootstrap-server.sh"
frp_infer_expected_source_ref
[[ "${FRP_EXPECTED_SOURCE_REF:-}" == "$FAKE_SHA" ]] || fail "infer from pre-rename FRP_BOOTSTRAP_URL"
pass "INFER_FROM_FORMER_BOOTSTRAP_URL"

# --- install-server resolve uses exact SHA defaults ---
reset_provenance_env
export FRP_SERVER_SOURCED=1
export FRP_SERVER_TEST_ROOT="$WORKDIR/install-root"
mkdir -p "$FRP_SERVER_TEST_ROOT/etc/drlink"
export FRP_PUBLIC_HOST='203.0.113.50'
export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
export FRP_CLIENT_INSTALLER_URL="https://raw.githubusercontent.com/datarelay-labs/datarelay-link/${FAKE_SHA}/dist/bootstrap-client.sh"
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"
load_existing_server_config
resolve_server_settings
[[ "${FRP_EXPECTED_SOURCE_REF:-}" == "$FAKE_SHA" ]] || fail "install did not infer SOURCE_REF"
[[ "$CLIENT_INSTALLER_URL" == *"/${FAKE_SHA}/dist/bootstrap-client.sh" ]] \
  || fail "install linux installer URL: $CLIENT_INSTALLER_URL"
[[ "$WINDOWS_CLIENT_INSTALLER_URL" == *"/artifacts/"*"bootstrap-client.ps1" ]] \
  || fail "install windows installer URL: $WINDOWS_CLIENT_INSTALLER_URL"
[[ "$CLIENT_INSTALLER_URL" != *"/v${PROJECT_VERSION}/"* ]] \
  || fail "premature tag in install linux URL"
pass "INSTALL_RESOLVE_EXACT_SHA"

# --- create-client defaults / Zero-Touch installer refs use SOURCE_REF ---
load_create_client() {
  python3 - "$ROOT/tools/frp-create-client" "$1" "$2" "${3:-}" <<'PY' || return 1
import importlib.machinery
import importlib.util
import os
import sys

path, tree = sys.argv[1], sys.argv[2]
os.environ["FRP_CTL_TEST_ROOT"] = tree
os.environ["FRP_DEPLOY_TEST_ROOT"] = tree
os.environ.pop("FRP_EXPECTED_SOURCE_REF", None)
loader = importlib.machinery.SourceFileLoader("frp_create_client", path)
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
sha_or_tag = sys.argv[3]
cfg = {
    "allocator_public_url": "https://203.0.113.10:6099/enroll",
    "client_installer_url": "",
    "windows_client_installer_url": "",
}
linux = mod.resolve_configured_installer_url(cfg, windows=False)
windows = mod.resolve_configured_installer_url(cfg, windows=True)
assert linux.endswith("/artifacts/agent/bootstrap-client.sh"), linux
assert windows.endswith("/artifacts/agent/bootstrap-client.ps1"), windows
for url in (linux, windows):
    assert "raw.githubusercontent.com" not in url, url
    assert "github.com/datarelay-labs" not in url, url
    assert "github.com/fatedier" not in url, url
if sha_or_tag.startswith("v") and sha_or_tag.count(".") >= 1 and len(sha_or_tag) < 20:
    assert mod.installed_source_ref() == sha_or_tag, mod.installed_source_ref()
    print("TAGGED_DEFAULTS_OK")
else:
    sha = sha_or_tag
    assert mod.installed_source_ref() == sha, mod.installed_source_ref()
    ver = mod.installed_project_version()
    assert f"/v{ver}/" not in linux, linux
    assert f"/v{ver}/" not in windows, windows
    print("LINUX_ZERO_TOUCH_INSTALLER_REF=SERVER_LOCAL")
    print("WINDOWS_ZERO_TOUCH_INSTALLER_REF=SERVER_LOCAL")
PY
}

ZT_ROOT="$WORKDIR/zt"
mkdir -p "$ZT_ROOT/etc/drlink"
cat >"$ZT_ROOT/etc/drlink/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=${FRP_VERSION}
RELEASE_CHANNEL=stable
SOURCE_REF=${FAKE_SHA}
EOF
load_create_client "$ZT_ROOT" "$FAKE_SHA" || fail "create-client exact-SHA defaults"
pass "ZERO_TOUCH_INSTALLER_REF_MATCHES_SOURCE_REF"

# --- tagged SOURCE_REF path still emits tag URLs ---
TAG_ROOT="$WORKDIR/tag"
mkdir -p "$TAG_ROOT/etc/drlink"
cat >"$TAG_ROOT/etc/drlink/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=${FRP_VERSION}
RELEASE_CHANNEL=stable
SOURCE_REF=v${PROJECT_VERSION}
EOF
load_create_client "$TAG_ROOT" "v${PROJECT_VERSION}" || fail "tagged defaults"
pass "FINAL_TAG_PATH_PRESERVED"

# --- explicit override preserved ---
reset_provenance_env
export FRP_SERVER_SOURCED=1
export FRP_SERVER_TEST_ROOT="$WORKDIR/override-root"
mkdir -p "$FRP_SERVER_TEST_ROOT/etc/drlink"
export FRP_PUBLIC_HOST='203.0.113.60'
export FRP_SERVER_CONFIG="$WORKDIR/missing-config-2.json"
export FRP_CLIENT_INSTALLER_URL='https://example.test/custom-bootstrap-client.sh'
export FRP_WINDOWS_CLIENT_INSTALLER_URL='https://example.test/custom-bootstrap-client.ps1'
# Re-source in a subshell to avoid polluted installer state from earlier.
(
  # shellcheck source=../install-server.sh
  . "$ROOT/install-server.sh"
  load_existing_server_config
  resolve_server_settings
  [[ "$CLIENT_INSTALLER_URL" == 'https://example.test/custom-bootstrap-client.sh' ]] \
    || fail "explicit linux override lost"
  [[ "$WINDOWS_CLIENT_INSTALLER_URL" == 'https://example.test/custom-bootstrap-client.ps1' ]] \
    || fail "explicit windows override lost"
)
pass "EXPLICIT_INSTALLER_URL_OVERRIDE_PRESERVED"

# --- exact SHA expected_ref accepted against development manifest git_ref ---
reset_provenance_env
meta="$(frp_validate_release_source_metadata "$ROOT" "$FAKE_SHA" development)" \
  || fail "exact SHA expected_ref rejected by metadata validate"
got_ref="$(printf '%s' "$meta" | awk -F'\t' '{print $3}')"
[[ "$got_ref" == "$FAKE_SHA" ]] || fail "validate did not return exact SHA provenance: $got_ref"
pass "VALIDATE_ACCEPTS_EXACT_SHA_PROVENANCE"

# --- local git source inference ---
reset_provenance_env
frp_infer_expected_source_ref_from_git_source "$ROOT"
[[ "${FRP_EXPECTED_SOURCE_REF:-}" =~ ^[0-9a-fA-F]{40}$ ]] \
  || fail "git source did not set exact SHA: ${FRP_EXPECTED_SOURCE_REF:-}"
case "$(frp_default_client_installer_url)" in
  *"/${FRP_EXPECTED_SOURCE_REF}/dist/bootstrap-client.sh") ;;
  *) fail "git HEAD default URL: $(frp_default_client_installer_url)" ;;
esac
grep -q "/v${PROJECT_VERSION}/" <<<"$(frp_default_client_installer_url)" && \
  fail "git HEAD path still used premature tag"
pass "LOCAL_GIT_SOURCE_REF_EXACT_SHA"

# --- missing version provenance must not fabricate a project version ---
reset_provenance_env
unset PROJECT_VERSION || true
FABRICATED="$WORKDIR/no-version-tool"
mkdir -p "$FABRICATED/tools" "$FABRICATED/empty-root"
cp "$ROOT/tools/frp-create-client" "$FABRICATED/tools/frp-create-client"
if PROJECT_VERSION= FRP_DEPLOY_TEST_ROOT="$FABRICATED/empty-root" FRP_CTL_TEST_ROOT="$FABRICATED/empty-root" \
  python3 - "$FABRICATED/tools/frp-create-client" <<'PY'
import importlib.machinery
import importlib.util
import os
import sys

os.environ.pop("PROJECT_VERSION", None)
path = sys.argv[1]
loader = importlib.machinery.SourceFileLoader("frp_create_client_no_version", path)
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
try:
    value = mod.installed_project_version()
except SystemExit as exc:
    message = str(exc)
    if "2.3.1" in message:
        raise SystemExit("fabricated version leaked in error: %s" % message)
    if "unavailable" not in message.lower():
        raise SystemExit("fail-closed message missing: %s" % message)
    raise SystemExit(0)
raise SystemExit("fabricated project version emitted: %r" % value)
PY
then
  pass "NO_FABRICATED_PROJECT_VERSION"
else
  fail "installed_project_version fabricated a version or failed closed incorrectly"
fi

echo "PREMATURE_V240_TAG_SUBSTITUTION=NO"
echo "SOURCE_REF_PRESERVED=YES"
echo "EXACT_SHA_INSTALLER_PROVENANCE_TEST=PASS"
