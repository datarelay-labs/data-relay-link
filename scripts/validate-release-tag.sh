#!/usr/bin/env bash
# Reject a proposed git tag that does not match PROJECT_VERSION.
# Usage: ./scripts/validate-release-tag.sh [vX.Y.Z]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/VERSION"

tag="${1:-}"
if [[ -z "$tag" ]]; then
  echo "Usage: $0 vX.Y.Z" >&2
  exit 2
fi
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: tag must look like vX.Y.Z: $tag" >&2
  exit 1
fi
want="v${PROJECT_VERSION}"
if [[ "$tag" != "$want" ]]; then
  echo "ERROR: refusing to tag ${tag} while PROJECT_VERSION=${PROJECT_VERSION} (expected ${want})" >&2
  echo "A dedicated release commit must bump VERSION before the immutable tag is created." >&2
  exit 1
fi

if [[ -f "$ROOT/release-manifest.json" ]]; then
  python3 - "$ROOT/release-manifest.json" "$PROJECT_VERSION" "$tag" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
project, tag = sys.argv[2], sys.argv[3]
if str(data.get("project_version") or "") != project:
    sys.stderr.write("ERROR: release-manifest project_version does not match VERSION\n")
    raise SystemExit(1)
channel = str(data.get("channel") or "")
ref = str(data.get("git_ref") or "")
if channel == "stable" and ref != tag:
    sys.stderr.write("ERROR: stable release-manifest git_ref must equal %s\n" % tag)
    raise SystemExit(1)
if channel == "stable" and ref == "main":
    sys.stderr.write("ERROR: stable release must not use mutable main\n")
    raise SystemExit(1)
if channel not in ("development", "preview", "stable"):
    sys.stderr.write("ERROR: release-manifest channel must be development|preview|stable\n")
    raise SystemExit(1)
print("RELEASE_TAG_VALID=%s" % tag)
PY
fi
