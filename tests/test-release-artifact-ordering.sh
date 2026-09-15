#!/usr/bin/env bash
# Regression: the release artifact chain is acyclic and converges.
#
# The bug this guards against: dist/sbom.spdx.json used to be checksummed into
# SHA256SUMS, while generate-sbom.py builds its inventory *from* SHA256SUMS. The
# SBOM therefore embedded a stale hash of itself, and no number of rebuilds
# could make the two agree.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

HEAD_COMMIT="$(git rev-parse HEAD)"

# --- Derived metadata must stay out of SHA256SUMS ----------------------------
for meta in SHA256SUMS release-manifest.json dist/sbom.spdx.json; do
  if grep -qE "(^| )${meta//\//\\/}\$" SHA256SUMS; then
    fail "SHA256SUMS_EXCLUDES_METADATA: SHA256SUMS still checksums ${meta}"
  fi
done
pass "SHA256SUMS_EXCLUDES_METADATA"

# The SBOM cannot be tracked: a committed file cannot record the hash of the
# commit that contains it, so a tracked SBOM can never bind to its own release.
if git ls-files --error-unmatch dist/sbom.spdx.json >/dev/null 2>&1; then
  fail "SBOM_NOT_TRACKED: dist/sbom.spdx.json must be generated, not committed"
fi
pass "SBOM_NOT_TRACKED"

# --- SBOM generation is deterministic for a fixed commit ---------------------
TMPDIR_SBOM="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SBOM"' EXIT

python3 ./scripts/generate-sbom.py -o "$TMPDIR_SBOM/a.json" --source-commit "$HEAD_COMMIT" >/dev/null
python3 ./scripts/generate-sbom.py -o "$TMPDIR_SBOM/b.json" --source-commit "$HEAD_COMMIT" >/dev/null
cmp -s "$TMPDIR_SBOM/a.json" "$TMPDIR_SBOM/b.json" ||
  fail "SBOM_DETERMINISTIC: two runs on the same commit differ"
pass "SBOM_DETERMINISTIC"

# --- SBOM binds to the source commit and refuses a wrong one -----------------
python3 - "$TMPDIR_SBOM/a.json" "$HEAD_COMMIT" <<'PY' || exit 1
import json
import sys

doc = json.loads(open(sys.argv[1], encoding='utf-8').read())
want = sys.argv[2]
root = next(
    p for p in doc['packages'] if p['SPDXID'] == 'SPDXRef-Package-DataRelayLink'
)
refs = {r['referenceType']: r['referenceLocator'] for r in root['externalRefs']}
if refs.get('gitCommit') != want:
    print('FAIL SBOM_COMMIT_BINDING: %r != %r' % (refs.get('gitCommit'), want))
    raise SystemExit(1)

names = {p.get('name') for p in doc['packages']}
for meta in ('SHA256SUMS', 'release-manifest.json', 'dist/sbom.spdx.json'):
    if meta in names:
        print('FAIL SBOM_SELF_REFERENCE: inventory lists %s' % meta)
        raise SystemExit(1)
PY
pass "SBOM_COMMIT_BINDING"
pass "SBOM_SELF_REFERENCE"

WRONG_COMMIT="0000000000000000000000000000000000000000"
if python3 ./scripts/generate-sbom.py -o "$TMPDIR_SBOM/c.json" \
  --source-commit "$WRONG_COMMIT" >/dev/null 2>&1; then
  fail "SBOM_REJECTS_FOREIGN_COMMIT: generator accepted a commit that is not HEAD"
fi
pass "SBOM_REJECTS_FOREIGN_COMMIT"

# --- The gate rejects an SBOM bound to the wrong commit ----------------------
if SBOM_PATH="$TMPDIR_SBOM/a.json" SBOM_EXPECTED_COMMIT="$WRONG_COMMIT" \
  ./scripts/verify-sbom.sh >/dev/null 2>&1; then
  fail "VERIFY_SBOM_REJECTS_MISMATCH: gate passed a mismatched commit"
fi
pass "VERIFY_SBOM_REJECTS_MISMATCH"

# --- Convergence: only a clean tree can assert the full chain ----------------
if [[ -n "$(git status --porcelain)" ]]; then
  echo "SKIP RELEASE_CHAIN_CONVERGES (working tree dirty; run on a clean tree)"
else
  SBOM_PATH="$TMPDIR_SBOM/a.json" SBOM_EXPECTED_COMMIT="$HEAD_COMMIT" \
    ./scripts/verify-sbom.sh >/dev/null ||
    fail "RELEASE_CHAIN_CONVERGES: verify-sbom.sh failed on a clean tree"
  ./scripts/verify-sha256sums.sh >/dev/null ||
    fail "RELEASE_CHAIN_CONVERGES: SHA256SUMS stale on a clean tree"
  pass "RELEASE_CHAIN_CONVERGES"
fi

echo "RELEASE_ARTIFACT_ORDERING=PASS"
