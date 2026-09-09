#!/usr/bin/env bash
# Assert release-manifest.artifacts[*].sha256 == SHA256SUMS[path] == file SHA256.
# Excludes self-referential metadata (SHA256SUMS / release-manifest.json).
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f SHA256SUMS ]]; then
  echo "ERROR: SHA256SUMS missing" >&2
  exit 1
fi
if [[ ! -f release-manifest.json ]]; then
  echo "ERROR: release-manifest.json missing" >&2
  exit 1
fi

python3 - <<'PY'
import hashlib
import json
import sys
from pathlib import Path

sums = {}
for line in Path('SHA256SUMS').read_text(encoding='utf-8').splitlines():
    parts = line.split(None, 1)
    if len(parts) == 2:
        sums[parts[1].lstrip('*')] = parts[0]

manifest = json.loads(Path('release-manifest.json').read_text(encoding='utf-8'))
artifacts = manifest.get('artifacts') or {}
errors = []
checked = 0
for name, meta in artifacts.items():
    if not isinstance(meta, dict):
        continue
    path = str(meta.get('path') or '').strip()
    if not path:
        continue
    if path in ('SHA256SUMS', 'release-manifest.json'):
        continue
    want = str(meta.get('sha256') or '').strip().lower()
    if not want:
        errors.append('%s: missing sha256 in release-manifest.json' % name)
        continue
    listed = sums.get(path)
    if not listed:
        errors.append('%s: path %s missing from SHA256SUMS' % (name, path))
        continue
    if listed.lower() != want:
        errors.append(
            '%s: release-manifest sha256 != SHA256SUMS (%s vs %s)'
            % (name, want, listed.lower())
        )
        continue
    file_path = Path(path)
    if not file_path.is_file():
        errors.append('%s: artifact file missing: %s' % (name, path))
        continue
    actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
    if actual != want:
        errors.append(
            '%s: release-manifest/SHA256SUMS sha256 != file (%s vs %s)'
            % (name, want, actual)
        )
        continue
    checked += 1

if errors:
    for err in errors:
        print('ERROR: %s' % err, file=sys.stderr)
    raise SystemExit(1)
print('RELEASE_MANIFEST_ARTIFACTS=PASS (%d)' % checked)
PY
