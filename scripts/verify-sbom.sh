#!/usr/bin/env bash
# Gate: the SBOM must bind to the actual release source commit and must agree
# with SHA256SUMS entry-for-entry.
#
# The expected commit defaults to the checked-out HEAD. A release workflow that
# has already resolved an immutable ref should pass that commit explicitly:
#
#   SBOM_EXPECTED_COMMIT=<40-hex> ./scripts/verify-sbom.sh
#
# This is why dist/sbom.spdx.json is generated rather than committed: a file
# stored in a commit cannot record that commit's own hash, so a committed SBOM
# can only ever bind to some earlier tree.
set -euo pipefail
cd "$(dirname "$0")/.."

SBOM_PATH="${SBOM_PATH:-dist/sbom.spdx.json}"
if [[ ! -s "$SBOM_PATH" ]]; then
  echo "ERROR: $SBOM_PATH missing or empty; run ./scripts/generate-sbom.py" >&2
  exit 1
fi

expected="${SBOM_EXPECTED_COMMIT:-}"
if [[ -z "$expected" ]]; then
  expected="$(git rev-parse HEAD)"
fi

SBOM_PATH="$SBOM_PATH" SBOM_EXPECTED_COMMIT="$expected" python3 - <<'PY'
import json
import os
import sys
from pathlib import Path

import importlib.util

# Single source of truth for the excluded-metadata set.
_spec = importlib.util.spec_from_file_location(
    'generate_sbom', 'scripts/generate-sbom.py'
)
_gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gen)
METADATA_PATHS = _gen.METADATA_PATHS

sbom_path = Path(os.environ['SBOM_PATH'])
expected_commit = os.environ['SBOM_EXPECTED_COMMIT'].strip().lower()
errors = []

doc = json.loads(sbom_path.read_text(encoding='utf-8'))
packages = doc.get('packages') or []

version = {}
for line in Path('VERSION').read_text(encoding='utf-8').splitlines():
    if '=' in line:
        k, v = line.split('=', 1)
        version[k.strip()] = v.strip()
project_version = version.get('PROJECT_VERSION', '')
frp_version = version.get('FRP_VERSION', '')
manifest = json.loads(Path('release-manifest.json').read_text(encoding='utf-8'))
expected_ref = str(manifest.get('git_ref') or '')

root_pkg = next(
    (p for p in packages if p.get('SPDXID') == 'SPDXRef-Package-DataRelayLink'),
    None,
)
if root_pkg is None:
    errors.append('SBOM has no SPDXRef-Package-DataRelayLink root package')
else:
    refs = {
        r.get('referenceType'): str(r.get('referenceLocator') or '')
        for r in (root_pkg.get('externalRefs') or [])
    }
    got_commit = refs.get('gitCommit', '').strip().lower()
    if not got_commit or got_commit == 'unknown':
        errors.append('SBOM records no source commit')
    elif got_commit != expected_commit:
        errors.append(
            'SBOM source commit %s != expected release commit %s'
            % (got_commit, expected_commit)
        )
    got_ref = refs.get('gitRef', '')
    if got_ref != expected_ref:
        errors.append(
            'SBOM release ref %r != release-manifest git_ref %r'
            % (got_ref, expected_ref)
        )
    if str(root_pkg.get('versionInfo') or '') != project_version:
        errors.append(
            'SBOM root versionInfo %r != VERSION PROJECT_VERSION %r'
            % (root_pkg.get('versionInfo'), project_version)
        )

frp_pkg = next((p for p in packages if p.get('name') == 'frp'), None)
if frp_pkg is None:
    errors.append('SBOM has no pinned frp package')
elif str(frp_pkg.get('versionInfo') or '') != frp_version:
    errors.append(
        'SBOM frp versionInfo %r != VERSION FRP_VERSION %r'
        % (frp_pkg.get('versionInfo'), frp_version)
    )

# Inventory must equal SHA256SUMS exactly, and must not list derived metadata.
listed = {}
for pkg in packages:
    name = str(pkg.get('name') or '')
    checksums = pkg.get('checksums') or []
    digest = next(
        (
            str(c.get('checksumValue') or '').lower()
            for c in checksums
            if c.get('algorithm') == 'SHA256'
        ),
        '',
    )
    if name in METADATA_PATHS:
        errors.append('SBOM must not inventory derived release metadata: %s' % name)
        continue
    if str(pkg.get('comment') or '').startswith('Repository-owned path'):
        listed[name] = digest

sums = {}
for line in Path('SHA256SUMS').read_text(encoding='utf-8').splitlines():
    parts = line.split(None, 1)
    if len(parts) == 2:
        sums[parts[1].strip().lstrip('*')] = parts[0].strip().lower()

for path, digest in sorted(sums.items()):
    if path not in listed:
        errors.append('SHA256SUMS path absent from SBOM: %s' % path)
    elif listed[path] != digest:
        errors.append(
            '%s: SBOM digest %s != SHA256SUMS %s' % (path, listed[path], digest)
        )
for path in sorted(set(listed) - set(sums)):
    errors.append('SBOM inventories a path absent from SHA256SUMS: %s' % path)

if errors:
    for err in errors:
        print('ERROR: %s' % err, file=sys.stderr)
    raise SystemExit(1)

print('SBOM_SOURCE_COMMIT=%s' % expected_commit)
print('SBOM_RELEASE_REF=%s' % expected_ref)
print('SBOM_INVENTORY=%d' % len(listed))
print('SBOM=PASS')
PY
