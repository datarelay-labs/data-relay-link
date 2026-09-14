#!/usr/bin/env bash
# Write SHA256SUMS for every tracked file except derived release metadata.
# The release manifest carries artifact hashes independently, and the SBOM is
# generated *from* SHA256SUMS, so neither may be checksummed here — that is
# what would make the integrity relation self-referential.
# Keep RELEASE_METADATA_RE in sync with scripts/verify-sha256sums.sh and the
# METADATA_PATHS set in scripts/generate-sbom.py.
set -euo pipefail
cd "$(dirname "$0")/.."
RELEASE_METADATA_RE='^(SHA256SUMS|release-manifest\.json|dist/sbom\.spdx\.json)$'
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
git ls-files -z | grep -zvE "$RELEASE_METADATA_RE" | sort -z | xargs -0 sha256sum | LC_ALL=C sort -k2 >"$tmp"
mv "$tmp" SHA256SUMS
echo "Updated SHA256SUMS ($(wc -l <SHA256SUMS) files)"

if [[ -f release-manifest.json ]]; then
  python3 - <<'PY'
import json
from pathlib import Path

sums = {}
for line in Path('SHA256SUMS').read_text(encoding='utf-8').splitlines():
    parts = line.split(None, 1)
    if len(parts) == 2:
        sums[parts[1]] = parts[0]
manifest_path = Path('release-manifest.json')
manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
artifacts = manifest.setdefault('artifacts', {})
synced = 0
for _name, meta in artifacts.items():
    if not isinstance(meta, dict):
        continue
    path = str(meta.get('path') or '').strip()
    if not path:
        continue
    # Never self-reference derived release metadata.
    if path in ('SHA256SUMS', 'release-manifest.json', 'dist/sbom.spdx.json'):
        continue
    if path not in sums:
        raise SystemExit('ERROR: artifact path missing from SHA256SUMS: %s' % path)
    meta['sha256'] = sums[path]
    synced += 1
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=False) + '\n', encoding='utf-8'
)
print('Synced release-manifest.json artifact hashes (%d)' % synced)
PY
fi
