#!/usr/bin/env bash
# Verify SHA256SUMS matches tracked files (excluding self-referential metadata).
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f SHA256SUMS ]]; then
  echo "ERROR: SHA256SUMS missing" >&2
  exit 1
fi
if grep -qE '(^| )(SHA256SUMS|release-manifest\.json)$' SHA256SUMS; then
  echo "ERROR: SHA256SUMS must not checksum metadata files" >&2
  exit 1
fi
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
git ls-files -z | grep -zvE '^(SHA256SUMS|release-manifest\.json)$' | sort -z | xargs -0 sha256sum | LC_ALL=C sort -k2 >"$tmp"
if ! diff -u SHA256SUMS "$tmp"; then
  echo "ERROR: SHA256SUMS is stale; run ./scripts/update-sha256sums.sh" >&2
  exit 1
fi
echo "SHA256SUMS=PASS"
# Cross-check release-manifest artifact hashes against SHA256SUMS and file bytes.
./scripts/verify-release-manifest-artifacts.sh
