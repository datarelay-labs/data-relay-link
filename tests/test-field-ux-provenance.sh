#!/usr/bin/env bash
# Field UX: provenance + distribution-ref propagation (no network).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

unset FRP_RELEASE_CHANNEL FRP_SOURCE_REF FRP_DISTRIBUTION_REF FRP_BUNDLE_SHA256 FRP_DEPLOY_TEST_ROOT || true

# Stable tag line still resolves to vPROJECT_VERSION when channel is explicit.
export FRP_RELEASE_CHANNEL=stable
[[ "$(frp_release_git_ref)" == "v${PROJECT_VERSION}" ]] || fail "stable ref"
case "$(frp_default_client_installer_url)" in
  *"/v${PROJECT_VERSION}/dist/bootstrap-client.sh") ;;
  *) fail "stable installer URL" ;;
esac
pass "STABLE_TAG_INSTALLER"

# Commit SOURCE_REF is content identity only — must NOT become the download ref.
unset FRP_RELEASE_CHANNEL FRP_DISTRIBUTION_REF || true
export FRP_SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53
export FRP_RELEASE_CHANNEL=dev
case "$(frp_default_client_installer_url)" in
  *"/6d1c12795e2ca56c173223b95c80959ff0fc0a53/"*) fail "commit SHA used as distribution ref" ;;
  *"/main/dist/bootstrap-client.sh") ;;
  *) fail "dev+sha installer URL: $(frp_default_client_installer_url)" ;;
esac
pass "COMMIT_SOURCE_REF_NOT_DISTRIBUTION"

# Explicit DISTRIBUTION_REF wins for installer URL generation.
unset FRP_RELEASE_CHANNEL || true
export FRP_SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53
export FRP_DISTRIBUTION_REF=fix/client-resource-cli-ux
case "$(frp_default_client_installer_url)" in
  *"/fix/client-resource-cli-ux/dist/bootstrap-client.sh") ;;
  *) fail "distribution installer URL: $(frp_default_client_installer_url)" ;;
esac
pass "DISTRIBUTION_REF_INSTALLER"

# Version file persists both content and distribution identity.
TREE="$WORKDIR/sha-install"
mkdir -p "$TREE/etc/frp-auto-deploy"
export FRP_DEPLOY_TEST_ROOT="$TREE"
unset FRP_RELEASE_CHANNEL FRP_BUNDLE_SHA256 || true
export FRP_SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53
export FRP_DISTRIBUTION_REF=fix/client-resource-cli-ux
export FRP_RELEASE_CHANNEL=dev
export FRP_BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
frp_write_version_file "$TREE/etc/frp-auto-deploy/version"
grep -q 'RELEASE_CHANNEL=dev' "$TREE/etc/frp-auto-deploy/version" || fail "sha channel"
grep -q 'SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53' "$TREE/etc/frp-auto-deploy/version" || fail "sha source"
grep -q 'DISTRIBUTION_REF=fix/client-resource-cli-ux' "$TREE/etc/frp-auto-deploy/version" || fail "dist ref"
grep -q 'BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$TREE/etc/frp-auto-deploy/version" || fail "sha bundle"
# Persisted DISTRIBUTION_REF drives default installer without env.
unset FRP_SOURCE_REF FRP_RELEASE_CHANNEL FRP_DISTRIBUTION_REF FRP_BUNDLE_SHA256 || true
case "$(frp_default_client_installer_url)" in
  *"/fix/client-resource-cli-ux/dist/bootstrap-client.sh") ;;
  *) fail "persisted distribution installer: $(frp_default_client_installer_url)" ;;
esac
pass "VERSION_FILE_DISTRIBUTION_PERSIST"

# Commit-only install (no DISTRIBUTION_REF) falls back to release-line main.
TREE2="$WORKDIR/commit-only"
mkdir -p "$TREE2/etc/frp-auto-deploy"
export FRP_DEPLOY_TEST_ROOT="$TREE2"
export FRP_SOURCE_REF=6d1c12795e2ca56c173223b95c80959ff0fc0a53
export FRP_RELEASE_CHANNEL=dev
unset FRP_DISTRIBUTION_REF || true
frp_write_version_file "$TREE2/etc/frp-auto-deploy/version"
grep -q 'DISTRIBUTION_REF=main' "$TREE2/etc/frp-auto-deploy/version" || fail "commit-only dist default"
unset FRP_SOURCE_REF FRP_RELEASE_CHANNEL || true
case "$(frp_default_client_installer_url)" in
  *"/main/dist/bootstrap-client.sh") ;;
  *"/6d1c127"*) fail "stale commit used as installer URL" ;;
  *) fail "commit-only installer: $(frp_default_client_installer_url)" ;;
esac
pass "COMMIT_ONLY_FALLBACK_MAIN"

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

# build-bundles stamps channel + content + distribution provenance.
python3 - "$ROOT" <<'PY' || fail "bundle provenance stamp"
import os, sys
from pathlib import Path
root = Path(sys.argv[1])
src = (root / "scripts" / "build-bundles.py").read_text(encoding="utf-8")
helper = src.split("BUILD_CHANNEL, BUILD_SOURCE_REF, BUILD_DISTRIBUTION_REF = detect_build_provenance()")[0]
ns = {"__file__": str(root / "scripts" / "build-bundles.py"), "__name__": "build_bundles_helpers"}
exec(compile(helper, "build-bundles.py", "exec"), ns)
os.environ["FRP_BUILD_SOURCE_REF"] = "abc1234deadbeef"
os.environ["FRP_BUILD_RELEASE_CHANNEL"] = "dev"
os.environ["FRP_BUILD_DISTRIBUTION_REF"] = "fix/example"
ch, ref, dist = ns["detect_build_provenance"]()
assert ch == "dev", ch
assert ref == "abc1234deadbeef", ref
assert dist == "fix/example", dist
pre = "\n".join(ns["provenance_preamble"](ch, ref, dist))
assert "FRP_SOURCE_REF='abc1234deadbeef'" in pre
assert "FRP_RELEASE_CHANNEL='dev'" in pre
assert "FRP_DISTRIBUTION_REF='fix/example'" in pre
# Dev embed rewrites release-line identity without touching the tree manifest.
payload = ns["bundle_payload"]("release-manifest.json", "dev")
import json
embedded = json.loads(payload.decode("utf-8"))
assert embedded["channel"] == "dev", embedded
assert embedded["git_ref"] == "main", embedded
tree = json.loads((root / "release-manifest.json").read_text(encoding="utf-8"))
assert tree["channel"] == "stable", tree
assert tree["git_ref"] == "v%s" % ns["read_project_version"](), tree
# Stable embed keeps canonical identity.
stable_payload = ns["bundle_payload"]("release-manifest.json", "stable")
stable_emb = json.loads(stable_payload.decode("utf-8"))
assert stable_emb["channel"] == "stable"
assert stable_emb["git_ref"] == "v%s" % ns["read_project_version"]()
tag = "v%s" % ns["read_project_version"]()
os.environ["FRP_BUILD_SOURCE_REF"] = tag
os.environ["FRP_BUILD_RELEASE_CHANNEL"] = "stable"
os.environ.pop("FRP_BUILD_DISTRIBUTION_REF", None)
ch, ref, dist = ns["detect_build_provenance"]()
assert ch == "stable", ch
assert ref == tag, ref
assert dist == tag, dist
print("ok")
PY
pass "BUILD_BUNDLE_PROVENANCE_HELPER"

echo "FIELD_UX_PROVENANCE_TEST=PASS"
