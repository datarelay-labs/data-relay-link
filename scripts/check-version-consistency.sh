#!/usr/bin/env bash
# Version-consistency gate. VERSION is the single source of truth; every
# assertion below is derived from it rather than hard-coded, so a version bump
# only requires editing VERSION and the documents themselves.
#
# Also enforces the historical-tag immutability policy: no release document may
# instruct an operator to move, recreate, retarget, or delete a published tag.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail_count=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; fail_count=$((fail_count + 1)); }

# shellcheck disable=SC1091
. "$ROOT/VERSION"
: "${PROJECT_VERSION:?VERSION must define PROJECT_VERSION}"
: "${FRP_VERSION:?VERSION must define FRP_VERSION}"
[[ "$PROJECT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "PROJECT_VERSION not X.Y.Z: $PROJECT_VERSION"
[[ "$FRP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "FRP_VERSION not X.Y.Z: $FRP_VERSION"
TAG="v${PROJECT_VERSION}"
echo "VERSION_SOURCE PROJECT_VERSION=${PROJECT_VERSION} FRP_VERSION=${FRP_VERSION} TAG=${TAG}"

want() { # want <label> <file> <literal>
  grep -qF -- "$3" "$2" && pass "$1" || fail "$1: $2 missing '$3'"
}

# --- Code defaults -----------------------------------------------------------
want "COMMON_SH_PROJECT_VERSION" lib/frp-common.sh "PROJECT_VERSION:-${PROJECT_VERSION}"

# --- release-manifest.json ---------------------------------------------------
if PROJECT_VERSION="$PROJECT_VERSION" FRP_VERSION="$FRP_VERSION" TAG="$TAG" \
  RELEASE_CHANNEL="${RELEASE_CHANNEL:-}" python3 - <<'PY'
import json
import os
import re
import sys
from pathlib import Path

m = json.loads(Path('release-manifest.json').read_text(encoding='utf-8'))
project, frp, tag = os.environ['PROJECT_VERSION'], os.environ['FRP_VERSION'], os.environ['TAG']
want_channel = (os.environ.get('RELEASE_CHANNEL') or '').strip().lower()
errs = []
if str(m.get('project_version') or '') != project:
    errs.append('project_version %r != VERSION %r' % (m.get('project_version'), project))
if str(m.get('frp_version') or '') != frp:
    errs.append('frp_version %r != VERSION %r' % (m.get('frp_version'), frp))
if frp not in (m.get('supported_frp_versions') or {}):
    errs.append('supported_frp_versions has no entry for %s' % frp)
channel = str(m.get('channel') or '')
ref = str(m.get('git_ref') or '')
source_head = str(m.get('source_head') or '')
if want_channel and channel != want_channel:
    errs.append('channel %r != VERSION RELEASE_CHANNEL %r' % (channel, want_channel))
if channel == 'stable' and ref != tag:
    errs.append('stable git_ref %r != %r' % (ref, tag))
if channel == 'stable' and ref == 'main':
    errs.append('stable release must not use mutable main')
if channel == 'development':
    if not (re.fullmatch(r'[0-9a-fA-F]{40}', ref) or ref == 'main'):
        errs.append('development git_ref must be SHA or main')
    if source_head and not re.fullmatch(r'[0-9a-fA-F]{40}', source_head):
        errs.append('source_head malformed')
features = m.get('features') or {}
if 'mcp_included' not in features or features.get('mcp_included') not in (True, False):
    errs.append('features.mcp_included must be boolean')
for e in errs:
    print('ERROR: release-manifest.json: %s' % e, file=sys.stderr)
sys.exit(1 if errs else 0)
PY
then
  pass "RELEASE_MANIFEST_VERSION"
else
  fail "RELEASE_MANIFEST_VERSION"
fi

# --- User-facing docs --------------------------------------------------------
want "README_PROJECT_VERSION" README.md "Current project version: **${PROJECT_VERSION}**"
want "README_FRP_VERSION" README.md "Current pinned FRP version: **v${FRP_VERSION}**"
want "SECURITY_PROJECT_VERSION" docs/SECURITY.md "\`Data Relay Link\` **${PROJECT_VERSION}**"
want "SECURITY_FRP_VERSION" docs/SECURITY.md "Pinned FRP version: **${FRP_VERSION}**"
want "VALIDATION_PROJECT_VERSION" docs/RELEASE_VALIDATION.md "Current project version **${PROJECT_VERSION}** / FRP **${FRP_VERSION}**"
want "CHECKLIST_FRP_VERSION" docs/RELEASE_CHECKLIST.md "FRP_VERSION=${FRP_VERSION}"
want "CHECKLIST_TAG_SECTION" docs/RELEASE_CHECKLIST.md "Preparing the ${PROJECT_VERSION} immutable tag"
want "PRODUCT_MASTER_PROJECT_VERSION" docs/PRODUCT_MASTER.md "Current project version: **${PROJECT_VERSION}**"
want "PRODUCT_MASTER_FRP_VERSION" docs/PRODUCT_MASTER.md "Current pinned Relay Engine (FRP): **v${FRP_VERSION}**"
want "VERSION_POLICY_PRESENT" docs/VERSION_POLICY.md "Single source of truth"
want "VERSION_POLICY_CHANNELS" docs/VERSION_POLICY.md "development | preview | stable"
want "MANIFEST_SCHEMA_PRESENT" RELEASE_MANIFEST.schema.json '"mcp_included"'
grep -qE "^## ${PROJECT_VERSION//./\\.} — " CHANGELOG.md &&
  pass "CHANGELOG_HEADING" || fail "CHANGELOG_HEADING: no '## ${PROJECT_VERSION} — ' section"

# --- Historical tag immutability --------------------------------------------
# Published tags are immutable. Documentation must never tell an operator to
# move, recreate, retarget, or delete one.
RELEASE_DOCS=(README.md CHANGELOG.md docs/RELEASE_CHECKLIST.md docs/RELEASE_VALIDATION.md
  docs/SECURITY.md docs/PRODUCT_MASTER.md docs/FRP_UPGRADE.md docs/VERSION_POLICY.md GITHUB_SETUP.md)
if python3 - "${RELEASE_DOCS[@]}" <<'PY'
import re
import sys

# A tag-mutation verb co-occurring with a tag token, judged per paragraph so a
# prohibition that wraps across lines still counts. Markdown emphasis is
# stripped first: "Do **not** move" must read as "do not move".
VERB = re.compile(
    r'\b(re-?creates?|re-?created|re-?creating|re-?tags?|re-?tagged|'
    r'retargets?|retargeted|rewrites?|rewritten|force-pushe?[sd]?|'
    r'moves?|moved|moving|deletes?|deleted)\b',
    re.IGNORECASE,
)
NOUN = re.compile(r'(\btags?\b|\bv[0-9]+\.[0-9]+\.[0-9]+\b|\bTAG_[A-Z0-9_]+)')
NEGATION = re.compile(
    r'(do not|does not|must not|will not|cannot|never|untouched|immutable|'
    r'않는|않고|말아야|금지)',
    re.IGNORECASE,
)

bad = []
for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as fh:
        lines = fh.read().splitlines()
    start = 0
    paragraphs = []
    for idx, line in enumerate(lines + ['']):
        if not line.strip():
            if idx > start:
                paragraphs.append((start + 1, lines[start:idx]))
            start = idx + 1
    for lineno, block in paragraphs:
        text = re.sub(r'[*`_]+', '', ' '.join(block))
        if VERB.search(text) and NOUN.search(text) and not NEGATION.search(text):
            bad.append('%s:%d: %s' % (path, lineno, block[0].strip()[:110]))

for entry in bad:
    print('ERROR: tag-mutation instruction: %s' % entry, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
then
  pass "TAG_IMMUTABILITY"
else
  fail "TAG_IMMUTABILITY: release docs still instruct moving/recreating a published tag"
fi
want "TAG_IMMUTABILITY_STATED" docs/RELEASE_CHECKLIST.md "Published tags are immutable"
want "TAG_IMMUTABILITY_VALIDATION" docs/RELEASE_VALIDATION.md "Published tags are immutable"

# --- Tag validator agrees with VERSION ---------------------------------------
./scripts/validate-release-tag.sh "$TAG" >/dev/null &&
  pass "VALIDATE_RELEASE_TAG" || fail "VALIDATE_RELEASE_TAG: ${TAG} rejected by validator"

if [[ $fail_count -gt 0 ]]; then
  echo "VERSION_CONSISTENCY=FAIL (${fail_count})" >&2
  exit 1
fi
echo "VERSION_CONSISTENCY=PASS"
