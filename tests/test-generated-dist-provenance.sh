#!/usr/bin/env bash
# Regression: generated dist bootstrap channel must agree with embedded
# release-manifest.json, and Zero-Touch installer URLs must use DISTRIBUTION_REF
# (not a stale content SHA / not stable vX.Y.Z for a dev bundle).
# Isolated fixtures only — no host/network contact.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BUNDLE="$ROOT/dist/bootstrap-server.sh"
[[ -f "$BUNDLE" ]] || fail "missing dist/bootstrap-server.sh"

# --- Extract stamped provenance from the *generated* bootstrap ---
STAMP_CHANNEL="$(awk -F= '/export FRP_RELEASE_CHANNEL=/{gsub(/'\''/,"",$2); print $2; exit}' "$BUNDLE")"
STAMP_SOURCE="$(awk -F= '/export FRP_SOURCE_REF=/{gsub(/'\''/,"",$2); print $2; exit}' "$BUNDLE")"
STAMP_DIST="$(awk -F= '/export FRP_DISTRIBUTION_REF=/{gsub(/'\''/,"",$2); print $2; exit}' "$BUNDLE")"
[[ -n "$STAMP_CHANNEL" ]] || fail "missing FRP_RELEASE_CHANNEL stamp"
[[ -n "$STAMP_SOURCE" ]] || fail "missing FRP_SOURCE_REF stamp"
[[ -n "$STAMP_DIST" ]] || fail "missing FRP_DISTRIBUTION_REF stamp"

EMBEDDED_JSON="$WORKDIR/embedded-release-manifest.json"
python3 - "$BUNDLE" "$EMBEDDED_JSON" <<'PY' || fail "extract embedded manifest"
import base64, json, re, sys
from pathlib import Path
bundle = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
match = re.search(
    r"base64 -d >\"\$TMP/release-manifest\.json\" <<'B64'\n(.*?)\nB64",
    bundle,
    re.S,
)
assert match, "embedded release-manifest.json missing"
data = json.loads(base64.b64decode(match.group(1)).decode("utf-8"))
Path(sys.argv[2]).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(data.get("channel", ""), data.get("git_ref", ""))
PY
read -r EMBED_CHANNEL EMBED_REF < <(
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["channel"], d["git_ref"])' \
    "$EMBEDDED_JSON"
)

# Tree canonical stable identity must remain untouched.
TREE_CHANNEL="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/release-manifest.json"))["channel"])')"
TREE_REF="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/release-manifest.json"))["git_ref"])')"
[[ "$TREE_CHANNEL" == "stable" ]] || fail "tree manifest channel rewritten: $TREE_CHANNEL"
[[ "$TREE_REF" == "v${PROJECT_VERSION}" ]] || fail "tree manifest ref rewritten: $TREE_REF"
pass "TREE_STABLE_IDENTITY_INTACT"

# Current branch is not the exact release tag → generated bundle must be dev-consistent.
if git -C "$ROOT" describe --tags --exact-match HEAD >/dev/null 2>&1; then
  EXACT="$(git -C "$ROOT" describe --tags --exact-match HEAD)"
else
  EXACT=""
fi

if [[ "$EXACT" == "v${PROJECT_VERSION}" ]]; then
  [[ "$STAMP_CHANNEL" == "stable" ]] || fail "stable stamp channel: $STAMP_CHANNEL"
  [[ "$EMBED_CHANNEL" == "stable" ]] || fail "stable embed channel: $EMBED_CHANNEL"
  [[ "$EMBED_REF" == "v${PROJECT_VERSION}" ]] || fail "stable embed ref: $EMBED_REF"
  [[ "$STAMP_DIST" == "v${PROJECT_VERSION}" ]] || fail "stable distribution: $STAMP_DIST"
  pass "STABLE_GENERATED_BUNDLE_IDENTITY"
else
  [[ "$STAMP_CHANNEL" == "dev" ]] || fail "dev stamp channel: $STAMP_CHANNEL"
  [[ "$EMBED_CHANNEL" == "dev" ]] || fail "dev embed channel: $EMBED_CHANNEL (regression: channel mismatch)"
  [[ "$EMBED_REF" == "main" ]] || fail "dev embed ref: $EMBED_REF"
  # Distribution must not be a bare content SHA (self-referential dist problem).
  if frp_is_commit_source_ref "$STAMP_DIST"; then
    fail "DISTRIBUTION_REF is a commit SHA ($STAMP_DIST); use branch/main/tag"
  fi
  [[ "$STAMP_DIST" != "v${PROJECT_VERSION}" ]] || fail "dev distribution fell back to stable tag"
  pass "DEV_GENERATED_BUNDLE_IDENTITY"
fi

# Metadata validation must PASS against the extracted payload (the real failure mode).
EXTRACT_ROOT="$WORKDIR/extract"
mkdir -p "$EXTRACT_ROOT"
cp "$EMBEDDED_JSON" "$EXTRACT_ROOT/release-manifest.json"
cp "$ROOT/VERSION" "$EXTRACT_ROOT/VERSION"
META="$(frp_validate_release_source_metadata "$EXTRACT_ROOT" "$STAMP_SOURCE" "$STAMP_CHANNEL")" \
  || fail "generated bundle metadata validation failed (channel mismatch regression)"
[[ "$META" == "${PROJECT_VERSION}"$'\t'"${EMBED_CHANNEL}"$'\t'"${EMBED_REF}" ]] \
  || fail "metadata triple: $META"
pass "GENERATED_DEV_METADATA_VALIDATION"

# Simulate installed server provenance → Zero-Touch client installer URL.
unset FRP_RELEASE_CHANNEL FRP_SOURCE_REF FRP_DISTRIBUTION_REF FRP_BUNDLE_SHA256 || true
export FRP_DEPLOY_TEST_ROOT="$WORKDIR/server"
mkdir -p "$FRP_DEPLOY_TEST_ROOT/etc/frp-auto-deploy"
export FRP_RELEASE_CHANNEL="$STAMP_CHANNEL"
export FRP_SOURCE_REF="$STAMP_SOURCE"
export FRP_DISTRIBUTION_REF="$STAMP_DIST"
frp_write_version_file "$FRP_DEPLOY_TEST_ROOT/etc/frp-auto-deploy/version"
# Clear env so only persisted state drives URL (post-install Zero-Touch path).
unset FRP_RELEASE_CHANNEL FRP_SOURCE_REF FRP_DISTRIBUTION_REF || true
CLIENT_URL="$(frp_default_client_installer_url)"
case "$CLIENT_URL" in
  *"/${STAMP_DIST}/dist/bootstrap-client.sh") ;;
  *) fail "Zero-Touch client URL not current distribution artifact: $CLIENT_URL" ;;
esac
case "$CLIENT_URL" in
  *"/v${PROJECT_VERSION}/"*) 
    if [[ "$STAMP_CHANNEL" == "dev" ]]; then
      fail "dev Zero-Touch silently fell back to stable tag: $CLIENT_URL"
    fi
    ;;
esac
if frp_is_commit_source_ref "$STAMP_SOURCE"; then
  case "$CLIENT_URL" in
    *"/${STAMP_SOURCE}/"*) fail "Zero-Touch used content SHA (stale self-ref risk): $CLIENT_URL" ;;
  esac
fi
pass "DEV_ZERO_TOUCH_CLIENT_URL_CURRENT"

# Stable URL behavior remains pin-to-tag when channel/distribution are stable.
unset FRP_DEPLOY_TEST_ROOT FRP_RELEASE_CHANNEL FRP_SOURCE_REF FRP_DISTRIBUTION_REF || true
export FRP_RELEASE_CHANNEL=stable
export FRP_DISTRIBUTION_REF="v${PROJECT_VERSION}"
STABLE_URL="$(frp_default_client_installer_url)"
[[ "$STABLE_URL" == "https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/v${PROJECT_VERSION}/dist/bootstrap-client.sh" ]] \
  || fail "stable Zero-Touch URL: $STABLE_URL"
pass "STABLE_ZERO_TOUCH_CLIENT_URL"

echo "GENERATED_DIST_PROVENANCE_TEST=PASS"
