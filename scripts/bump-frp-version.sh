#!/usr/bin/env bash
# Explicit maintainer bump of the pinned FRP version after compatibility PASS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-}"
APPLY=0
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    *) echo "ERROR: unknown option $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  cat <<'EOF'
Usage: ./scripts/bump-frp-version.sh <frp-version> --apply

Refuses to run unless:
  1) ./scripts/check-frp-compatibility.sh <version> produced a PASS report
     whose content matches the requested version and verified digests, or
     FRP_COMPAT_REPORT points at such a report.json
  2) --apply is passed

This never installs GitHub "latest" automatically.
EOF
  exit 2
fi

if [[ "$APPLY" != "1" ]]; then
  echo "ERROR: refusing to bump VERSION without --apply" >&2
  echo "Run ./scripts/check-frp-compatibility.sh ${VERSION} first." >&2
  exit 2
fi

REPORT_JSON="${FRP_COMPAT_REPORT:-$ROOT/.frp-compat-stage/$VERSION/report.json}"
if [[ "$REPORT_JSON" == *.status ]]; then
  REPORT_JSON="${REPORT_JSON%.status}.json"
fi

if [[ "${FRP_COMPAT_FORCE:-}" == "1" ]]; then
  echo "WARNING: FRP_COMPAT_FORCE=1 bypasses report content validation" >&2
else
  if [[ ! -f "$REPORT_JSON" ]]; then
    echo "ERROR: no compatibility report.json at $REPORT_JSON" >&2
    echo "Run ./scripts/check-frp-compatibility.sh ${VERSION} first." >&2
    exit 2
  fi
  python3 - "$REPORT_JSON" "$VERSION" "${FRP_NEW_SHA256_AMD64:-}" "${FRP_NEW_SHA256_ARM64:-}" <<'PY'
import json, sys
from pathlib import Path

path, want_version, env_amd, env_arm = sys.argv[1:]
try:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
except Exception as exc:
    sys.stderr.write("ERROR: invalid compatibility report JSON: %s\n" % exc)
    raise SystemExit(2)
if str(data.get("result") or "") != "PASS":
    sys.stderr.write("ERROR: compatibility report result is not PASS\n")
    raise SystemExit(2)
if str(data.get("target_frp_version") or "") != want_version:
    sys.stderr.write(
        "ERROR: report target_frp_version=%r does not match requested %r\n"
        % (data.get("target_frp_version"), want_version)
    )
    raise SystemExit(2)
arts = {a.get("architecture"): a for a in (data.get("artifacts") or []) if isinstance(a, dict)}
for arch in ("amd64", "arm64"):
    art = arts.get(arch)
    if not art:
        sys.stderr.write("ERROR: report missing %s artifact\n" % arch)
        raise SystemExit(2)
    if art.get("result") != "PASS":
        sys.stderr.write("ERROR: report %s artifact is not PASS\n" % arch)
        raise SystemExit(2)
    expected = str(art.get("expected_sha256") or "")
    actual = str(art.get("actual_sha256") or "")
    if not expected or not actual or expected != actual:
        sys.stderr.write("ERROR: report %s digest mismatch or missing\n" % arch)
        raise SystemExit(2)
    env_val = env_amd if arch == "amd64" else env_arm
    if env_val and env_val != actual:
        sys.stderr.write(
            "ERROR: FRP_NEW_SHA256_%s does not match verified report digest\n"
            % arch.upper()
        )
        raise SystemExit(2)
print("COMPAT_REPORT_VALID=%s" % want_version)
PY
fi

AMD="${FRP_NEW_SHA256_AMD64:-}"
ARM="${FRP_NEW_SHA256_ARM64:-}"
if [[ -z "$AMD" || -z "$ARM" ]]; then
  if [[ -f "$REPORT_JSON" ]]; then
    eval "$(python3 - "$REPORT_JSON" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
arts = {a.get("architecture"): a for a in (data.get("artifacts") or [])}
print("AMD=%s" % arts["amd64"]["actual_sha256"])
print("ARM=%s" % arts["arm64"]["actual_sha256"])
PY
)"
  fi
fi
if [[ -z "$AMD" || -z "$ARM" ]]; then
  echo "ERROR: set FRP_NEW_SHA256_AMD64 and FRP_NEW_SHA256_ARM64 from the compatibility report" >&2
  exit 2
fi

python3 - "$ROOT" "$VERSION" "$AMD" "$ARM" <<'PY'
from pathlib import Path
import re, sys
root, version, amd, arm = sys.argv[1:]
ver = Path(root) / "VERSION"
text = ver.read_text()
text = re.sub(r"^FRP_VERSION=.*$", f"FRP_VERSION={version}", text, flags=re.M)
ver.write_text(text)
common = Path(root) / "lib" / "frp-common.sh"
ct = common.read_text()
ct = re.sub(r'FRP_VERSION="\$\{FRP_VERSION:-[^}]+\}"', f'FRP_VERSION="${{FRP_VERSION:-{version}}}"', ct, count=1)
ct = re.sub(r'FRP_SHA256_AMD64="\$\{FRP_SHA256_AMD64:-[^}]+\}"', f'FRP_SHA256_AMD64="${{FRP_SHA256_AMD64:-{amd}}}"', ct, count=1)
ct = re.sub(r'FRP_SHA256_ARM64="\$\{FRP_SHA256_ARM64:-[^}]+\}"', f'FRP_SHA256_ARM64="${{FRP_SHA256_ARM64:-{arm}}}"', ct, count=1)
common.write_text(ct)
print(f"Updated VERSION and lib/frp-common.sh to FRP {version}")
print("Now run tests, ./scripts/build-bundles.sh, ./scripts/update-sha256sums.sh")
print("Do not tag until OCI acceptance.")
PY
