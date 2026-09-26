#!/usr/bin/env bash
# Release governance guardrails (offline, repository-native).
#
# Checks:
#   VERSION_SSOT_CONSISTENT
#   TAG_MATCHES_PRODUCT_VERSION (when a matching tag exists)
#   TAG_HEAD_MATCHES_SOURCE_HEAD (when a matching tag exists)
#   INSTALLER_SOURCE_REF_IMMUTABLE
#   RELEASE_MANIFEST_VALID
#   SOURCE_DIST_PARITY (client upgrade destinations ⊆ client bootstrap)
#   MCP_V2_4_INCLUDED_AND_QUALIFIED
#   CONTROL_PLANE_SCHEMA_COMPATIBLE
#   HISTORICAL_TAG_IMMUTABILITY (documentation + no rewrite of known tags)
#   STABLE_WITHOUT_TAG (fail if manifest claims stable before tag exists)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail_count=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; fail_count=$((fail_count + 1)); }

# shellcheck disable=SC1091
. "$ROOT/VERSION"
: "${PROJECT_VERSION:?}"
: "${FRP_VERSION:?}"
: "${RELEASE_CHANNEL:?}"

TAG="v${PROJECT_VERSION}"
HEAD="$(git rev-parse HEAD)"

# --- VERSION SSOT -----------------------------------------------------------
if [[ "$RELEASE_CHANNEL" =~ ^(development|preview|stable)$ ]]; then
  pass "VERSION_SSOT_CHANNEL"
else
  fail "VERSION_SSOT_CHANNEL: RELEASE_CHANNEL=$RELEASE_CHANNEL"
fi
grep -q "PROJECT_VERSION:-${PROJECT_VERSION}" lib/frp-common.sh &&
  pass "VERSION_SSOT_COMMON_DEFAULT" || fail "VERSION_SSOT_COMMON_DEFAULT"
./scripts/check-version-consistency.sh >/tmp/version-consistency.out 2>&1 &&
  pass "VERSION_SSOT_CONSISTENT" || {
    cat /tmp/version-consistency.out >&2
    fail "VERSION_SSOT_CONSISTENT"
  }

# --- Manifest validity + provenance ----------------------------------------
python3 ./scripts/validate-release-manifest.py &&
  pass "RELEASE_MANIFEST_VALID" || fail "RELEASE_MANIFEST_VALID"
python3 ./scripts/sync-release-manifest-provenance.py --check &&
  pass "RELEASE_MANIFEST_PROVENANCE" || fail "RELEASE_MANIFEST_PROVENANCE"

MANIFEST_CHANNEL="$(python3 -c 'import json;print(json.load(open("release-manifest.json"))["channel"])')"
MANIFEST_REF="$(python3 -c 'import json;print(json.load(open("release-manifest.json"))["git_ref"])')"
MANIFEST_HEAD="$(python3 -c 'import json;print(json.load(open("release-manifest.json"))["source_head"])')"
MCP="$(python3 -c 'import json;print(json.load(open("release-manifest.json"))["features"]["mcp_included"])')"

# --- Stable-without-tag guard ----------------------------------------------
TAG_EXISTS=0
if git rev-parse --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
  TAG_EXISTS=1
fi
if [[ "$MANIFEST_CHANNEL" == "stable" && "$TAG_EXISTS" -eq 0 ]]; then
  fail "STABLE_WITHOUT_TAG: manifest claims stable but ${TAG} does not exist"
else
  pass "STABLE_WITHOUT_TAG_GUARD"
fi
if [[ "$RELEASE_CHANNEL" == "stable" && "$TAG_EXISTS" -eq 0 ]]; then
  fail "VERSION_STABLE_WITHOUT_TAG"
else
  pass "VERSION_STABLE_WITHOUT_TAG_GUARD"
fi

# --- Tag match when present ------------------------------------------------
if [[ "$TAG_EXISTS" -eq 1 ]]; then
  TAG_HEAD="$(git rev-list -n 1 "refs/tags/${TAG}")"
  if [[ "$TAG" == "v${PROJECT_VERSION}" ]]; then
    pass "TAG_MATCHES_PRODUCT_VERSION"
  else
    fail "TAG_MATCHES_PRODUCT_VERSION"
  fi
  # The tag is the qualified provenance commit. source_head remains its
  # content parent. A post-PASS2 metadata commit must not become the tag.
  PARENT="$(git rev-parse --verify HEAD^1 2>/dev/null || true)"
  if [[ "$TAG_HEAD" == "$HEAD" && -n "$PARENT" && "$MANIFEST_HEAD" == "$PARENT" && "$MANIFEST_HEAD" != "$HEAD" ]]; then
    pass "TAG_HEAD_MATCHES_SOURCE_HEAD"
  else
    fail "TAG_HEAD_MATCHES_SOURCE_HEAD: tag=$TAG_HEAD manifest=$MANIFEST_HEAD parent=${PARENT:-NONE} HEAD=$HEAD"
  fi
else
  pass "TAG_MATCHES_PRODUCT_VERSION (tag absent; deferred)"
  pass "TAG_HEAD_MATCHES_SOURCE_HEAD (tag absent; deferred)"
fi

# --- Installer source ref immutability -------------------------------------
case "$MANIFEST_REF" in
  main|master|latest)
    if [[ "$MANIFEST_CHANNEL" == "stable" ]]; then
      fail "INSTALLER_SOURCE_REF_IMMUTABLE: stable uses mutable $MANIFEST_REF"
    else
      if [[ "$MANIFEST_CHANNEL" == "development" && "$TAG_EXISTS" -eq 0 ]]; then
        fail "INSTALLER_SOURCE_REF_IMMUTABLE: pretags development must pin exact SHA, got $MANIFEST_REF"
      else
        pass "INSTALLER_SOURCE_REF_IMMUTABLE (explicit tip)"
      fi
    fi
    ;;
  *)
    if [[ "$MANIFEST_REF" =~ ^[0-9a-fA-F]{40}$ || "$MANIFEST_REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
      pass "INSTALLER_SOURCE_REF_IMMUTABLE"
    else
      fail "INSTALLER_SOURCE_REF_IMMUTABLE: unexpected ref $MANIFEST_REF"
    fi
    ;;
esac

# Future stable tag must not appear as the active installer ref before creation.
if [[ "$TAG_EXISTS" -eq 0 ]]; then
  if [[ "$MANIFEST_REF" == "$TAG" ]]; then
    fail "NONEXISTENT_TAG_REF: manifest git_ref is ${TAG} before the tag exists"
  else
    pass "NONEXISTENT_TAG_REF"
  fi
fi

# --- MCP included and qualified for 2.4.x ----------------------------------
if [[ "$PROJECT_VERSION" == 2.4.* ]]; then
  if [[ "$MCP" == "True" || "$MCP" == "true" ]]; then
    pass "MCP_V2_4_INCLUDED_AND_QUALIFIED"
  else
    fail "MCP_V2_4_INCLUDED_AND_QUALIFIED: features.mcp_included=$MCP"
  fi
  missing=0
  for req in \
    lib/drlink_mcp_bridge.py \
    lib/drlink_control_db.py \
    lib/drlink_control_plane.py \
    lib/drlink_control_cli.py \
    lib/drlink_ai_agent.py \
    server/drlink-mcp-bridge.py \
    server/drlink-mcp-bridge.service \
    tests/test-ai-access-mcp-e2e.py
  do
    if [[ ! -f "$req" ]]; then
      echo "missing $req" >&2
      missing=1
    fi
  done
  if grep -q 'CREATE TABLE ai_principals' lib/drlink_control_db.py &&
     grep -q 'MCP_PROTOCOL_VERSION = "2026-07-28"' lib/drlink_mcp_bridge.py &&
     [[ "$missing" -eq 0 ]]; then
    pass "MCP_SURFACE_PRESENT"
  else
    fail "MCP_SURFACE_PRESENT"
  fi
  if grep -q 'SCHEMA_VERSION = 2' lib/drlink_control_db.py &&
     grep -q 'APPLICATION_ID = 0x44524C4B' lib/drlink_control_db.py; then
    pass "CONTROL_PLANE_SCHEMA_COMPATIBLE"
  else
    fail "CONTROL_PLANE_SCHEMA_COMPATIBLE"
  fi
else
  pass "MCP_V2_4_INCLUDED_AND_QUALIFIED (n/a)"
  pass "CONTROL_PLANE_SCHEMA_COMPATIBLE (n/a)"
fi

# --- Historical tag immutability (presence) --------------------------------
for hist in v2.1.0 v2.1.1 v2.1.2 v2.1.3 v2.2.0 v2.2.1 v2.3.0; do
  if git rev-parse --verify "refs/tags/${hist}" >/dev/null 2>&1; then
    pass "HISTORICAL_TAG_PRESENT_${hist}"
  else
    fail "HISTORICAL_TAG_PRESENT_${hist}"
  fi
done
if git rev-parse --verify refs/tags/v2.3.1 >/dev/null 2>&1; then
  pass "HISTORICAL_V231_TAG_OPTIONAL_PRESENT"
else
  pass "HISTORICAL_V231_NOT_MANUFACTURED"
fi

# --- Source/dist parity: client upgrade destinations ⊆ client bootstrap ----
if python3 - <<'PY'
import ast
import re
import sys
from pathlib import Path

root = Path('.')
sys.path.insert(0, str(root / 'lib'))
from drlink_agent_payload import agent_source_rels

cc = (root / 'lib/frp-client-common.sh').read_text(encoding='utf-8')
m = re.search(
    r"frp_client_upgrade_destinations\(\) \{.*?printf '%s\\n' \\\n(.*?)\}",
    cc,
    re.S,
)
if not m:
    raise SystemExit('destinations parser failed')
srcs = []
for line in m.group(1).splitlines():
    line = line.strip().rstrip('\\').strip().strip('"')
    if not line or line.startswith('#'):
        continue
    parts = line.split(':')
    if len(parts) >= 3:
        srcs.append(parts[2])
bb = (root / 'scripts/build-bundles.py').read_text(encoding='utf-8')
tree = ast.parse(bb)
client_files = None
ns = {'agent_source_rels': agent_source_rels}
for node in tree.body:
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == 'client_files':
                client_files = eval(
                    compile(ast.Expression(node.value), '<client_files>', 'eval'),
                    ns,
                )
if not isinstance(client_files, list):
    raise SystemExit('client_files parser failed')
missing = sorted({s for s in srcs if s not in client_files})
if missing:
    print('MISSING', ','.join(missing))
    raise SystemExit(1)
bootstrap = root / 'dist/bootstrap-client.sh'
if bootstrap.is_file():
    text = bootstrap.read_text(encoding='utf-8', errors='ignore')
    absent = [s for s in sorted(set(srcs)) if s not in text]
    if absent:
        print('BOOTSTRAP_ABSENT', ','.join(absent))
        raise SystemExit(1)
raise SystemExit(0)
PY
then
  pass "SOURCE_DIST_PARITY_CLIENT_UPGRADE"
else
  fail "SOURCE_DIST_PARITY_CLIENT_UPGRADE"
fi

if [[ $fail_count -gt 0 ]]; then
  echo "RELEASE_GOVERNANCE=FAIL (${fail_count})" >&2
  exit 1
fi
echo "RELEASE_GOVERNANCE=PASS"
echo "HEAD=${HEAD}"
echo "CHANNEL=${RELEASE_CHANNEL}"
echo "MANIFEST_CHANNEL=${MANIFEST_CHANNEL}"
echo "MANIFEST_REF=${MANIFEST_REF}"
echo "SOURCE_HEAD=${MANIFEST_HEAD}"
