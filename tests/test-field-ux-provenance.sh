#!/usr/bin/env bash
# Field UX: provenance + source-ref propagation (no network).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

unset FRP_RELEASE_CHANNEL FRP_SOURCE_REF FRP_BUNDLE_SHA256 FRP_DEPLOY_TEST_ROOT || true

# Stable tag line still resolves to vPROJECT_VERSION when channel is explicit.
export FRP_RELEASE_CHANNEL=stable
[[ "$(frp_release_git_ref)" == "v${PROJECT_VERSION}" ]] || fail "stable ref"
case "$(frp_default_client_installer_url)" in
  *"/v${PROJECT_VERSION}/dist/bootstrap-client.sh") ;;
  *) fail "stable installer URL" ;;
esac
pass "STABLE_TAG_INSTALLER"

# Explicit commit pin wins for installer URL generation.
unset FRP_RELEASE_CHANNEL || true
export FRP_SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53
[[ "$(frp_release_git_ref)" == "6d1c12795e2ca56c173223b95c80959ff0fc0a53" ]] || fail "sha ref"
case "$(frp_default_client_installer_url)" in
  *"/6d1c12795e2ca56c173223b95c80959ff0fc0a53/dist/bootstrap-client.sh") ;;
  *) fail "sha installer URL: $(frp_default_client_installer_url)" ;;
esac
pass "SHA_SOURCE_REF_INSTALLER"

# Version file from commit pin must not claim stable/vX.Y.Z.
TREE="$WORKDIR/sha-install"
mkdir -p "$TREE/etc/frp-auto-deploy"
export FRP_DEPLOY_TEST_ROOT="$TREE"
unset FRP_RELEASE_CHANNEL FRP_BUNDLE_SHA256 || true
export FRP_SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53
export FRP_BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
frp_write_version_file "$TREE/etc/frp-auto-deploy/version"
grep -q 'RELEASE_CHANNEL=dev' "$TREE/etc/frp-auto-deploy/version" || fail "sha channel"
grep -q 'SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53' "$TREE/etc/frp-auto-deploy/version" || fail "sha source"
grep -q 'BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$TREE/etc/frp-auto-deploy/version" || fail "sha bundle"
# Persisted SHA drives default installer without env.
unset FRP_SOURCE_REF FRP_RELEASE_CHANNEL FRP_BUNDLE_SHA256 || true
case "$(frp_default_client_installer_url)" in
  *"/6d1c12795e2ca56c173223b95c80959ff0fc0a53/dist/bootstrap-client.sh") ;;
  *) fail "persisted sha installer" ;;
esac
pass "SHA_VERSION_FILE_AND_PERSIST"

# Explicit administrator installer override must win over official auto-default.
frp_is_official_client_installer_url \
  "https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/v${PROJECT_VERSION}/dist/bootstrap-client.sh" \
  || fail "official tag URL not recognized"
frp_is_official_client_installer_url \
  "https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/deadbeef/dist/bootstrap-client.sh" \
  || fail "official sha URL not recognized"
if frp_is_official_client_installer_url "https://mirror.example/bootstrap-client.sh"; then
  fail "custom URL treated as official"
fi
pass "OFFICIAL_INSTALLER_URL_HELPER"

# build-bundles stamps commit provenance when not on exact release tag.
python3 - "$ROOT" <<'PY' || fail "bundle provenance stamp"
import os, sys
from pathlib import Path
root = Path(sys.argv[1])
# Import by running the module as a file so __file__ works.
import importlib.util
spec = importlib.util.spec_from_file_location("build_bundles", root / "scripts" / "build-bundles.py")
# Avoid executing the full bundle write; load only helper defs by compiling a slice.
src = (root / "scripts" / "build-bundles.py").read_text(encoding="utf-8")
helper = src.split("BUILD_CHANNEL, BUILD_SOURCE_REF = detect_build_provenance()")[0]
ns = {"__file__": str(root / "scripts" / "build-bundles.py"), "__name__": "build_bundles_helpers"}
exec(compile(helper, "build-bundles.py", "exec"), ns)
os.environ["FRP_BUILD_SOURCE_REF"] = "abc1234deadbeef"
os.environ["FRP_BUILD_RELEASE_CHANNEL"] = "dev"
ch, ref = ns["detect_build_provenance"]()
assert ch == "dev", ch
assert ref == "abc1234deadbeef", ref
pre = "\n".join(ns["provenance_preamble"](ch, ref))
assert "FRP_SOURCE_REF='abc1234deadbeef'" in pre
assert "FRP_RELEASE_CHANNEL='dev'" in pre
tag = "v%s" % ns["read_project_version"]()
os.environ["FRP_BUILD_SOURCE_REF"] = tag
os.environ["FRP_BUILD_RELEASE_CHANNEL"] = "stable"
ch, ref = ns["detect_build_provenance"]()
assert ch == "stable", ch
assert ref == tag, ref
print("ok")
PY
pass "BUILD_BUNDLE_PROVENANCE_HELPER"

echo "FIELD_UX_PROVENANCE_TEST=PASS"
