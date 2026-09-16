#!/usr/bin/env bash
# Authoritative release artifact ordering.
#
#   0. sync manifest provenance   VERSION + HEAD -> release-manifest.json
#   1. build bundles              sources          -> dist/bootstrap-*, dist/uninstall-*
#   2. update SHA256SUMS          tracked sources  -> SHA256SUMS, release-manifest hashes
#   3. generate SBOM              SHA256SUMS       -> dist/sbom.spdx.json
#   4. verify                     gates 0-3
#
# Each stage consumes only the output of earlier stages, so the relation is a
# DAG and a rebuild converges in one pass. The three derived metadata files
# (SHA256SUMS, release-manifest.json, dist/sbom.spdx.json) are deliberately
# absent from SHA256SUMS: checksumming them there is what previously made the
# SBOM embed a stale hash of itself.
#
# Determinism: for a fixed source commit this script is idempotent. Run it
# twice and stages 1-3 produce byte-identical output.
set -euo pipefail
cd "$(dirname "$0")/.."

SOURCE_COMMIT="${SBOM_SOURCE_COMMIT:-$(git rev-parse HEAD)}"
export SBOM_EXPECTED_COMMIT="$SOURCE_COMMIT"

echo "== 0/4 sync release-manifest provenance =="
python3 ./scripts/sync-release-manifest-provenance.py

echo "== 1/4 build bundles =="
./scripts/build-bundles.sh

echo "== 2/4 update SHA256SUMS =="
./scripts/update-sha256sums.sh

echo "== 3/4 generate SBOM =="
python3 ./scripts/generate-sbom.py -o dist/sbom.spdx.json --source-commit "$SOURCE_COMMIT"

echo "== 4/4 verify =="
./scripts/verify-sha256sums.sh
./scripts/verify-sbom.sh
./scripts/validate-release-manifest.py
./scripts/check-release-governance.sh

echo "RELEASE_ARTIFACTS=PASS"
