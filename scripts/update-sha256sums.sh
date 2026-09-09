#!/usr/bin/env bash
# Write SHA256SUMS for every tracked file except the self-referential metadata
# files. The release manifest carries artifact hashes independently.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
git ls-files -z | grep -zvE '^(SHA256SUMS|release-manifest\.json)$' | sort -z | xargs -0 sha256sum | LC_ALL=C sort -k2 >"$tmp"
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
    # Never self-reference metadata checksum files.
    if path in ('SHA256SUMS', 'release-manifest.json'):
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
