#!/usr/bin/env bash
# Stage and inspect a candidate upstream FRP release. Does not bump VERSION.
# Fail-closed: never extract or execute an archive whose digest does not match
# a trusted expected SHA256. PASS reports are written atomically only after
# every required check succeeds.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

CANDIDATE="${1:-}"
if [[ -z "$CANDIDATE" || "$CANDIDATE" == "-h" || "$CANDIDATE" == "--help" ]]; then
  cat <<'EOF'
Usage: ./scripts/check-frp-compatibility.sh <frp-version>

Downloads linux amd64/arm64 candidate archives from GitHub, verifies
checksums BEFORE extract/execute, inspects websocket path defaults, and runs
local config verify when binaries can be extracted.

This does NOT change VERSION, SHA256 constants, or production installs.
Use ./scripts/bump-frp-version.sh only after this report is PASS and after
full project tests.
EOF
  exit 2
fi

RUN_ID="${FRP_COMPAT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
STAGE_ROOT="${FRP_COMPAT_STAGE_ROOT:-$ROOT/.frp-compat-stage}"
STAGE="${FRP_COMPAT_STAGE:-$STAGE_ROOT/$CANDIDATE/$RUN_ID}"
mkdir -p "$STAGE"
# Never reuse a prior PASS for a different run.
rm -f "$STAGE/report.status" "$STAGE/report.json" "$STAGE_ROOT/$CANDIDATE/report.status" \
  "$STAGE_ROOT/$CANDIDATE/report.json" 2>/dev/null || true

BASE_URL="https://github.com/fatedier/frp/releases/download/v${CANDIDATE}"
EXPECTED_AMD64="${FRP_COMPAT_EXPECTED_AMD64_SHA256:-}"
EXPECTED_ARM64="${FRP_COMPAT_EXPECTED_ARM64_SHA256:-}"

fail_closed() {
  local msg="$1"
  echo "ERROR: $msg" >&2
  echo "FRP_COMPAT=FAIL" >&2
  rm -f "$STAGE/report.status" "$STAGE/report.json" 2>/dev/null || true
  # Best-effort: drop unverified archives/extracts from this run.
  find "$STAGE" -maxdepth 1 \( -name '*.tar.gz' -o -name '*_extract' \) -exec rm -rf {} + 2>/dev/null || true
  exit 1
}

download() {
  local name="$1"
  curl -fL --retry 3 --connect-timeout 10 --max-time 180 \
    -o "$STAGE/$name" "$BASE_URL/$name" \
    || fail_closed "download failed for $name"
}

trusted_digest_for() {
  # Prefer explicit env, then GitHub release checksums asset, then pinned
  # project constants only when the candidate equals the currently pinned FRP.
  local arch="$1"
  local name="frp_${CANDIDATE}_linux_${arch}.tar.gz"
  case "$arch" in
    amd64)
      if [[ -n "$EXPECTED_AMD64" ]]; then
        printf '%s\n' "$EXPECTED_AMD64"
        return 0
      fi
      ;;
    arm64)
      if [[ -n "$EXPECTED_ARM64" ]]; then
        printf '%s\n' "$EXPECTED_ARM64"
        return 0
      fi
      ;;
  esac
  if [[ -f "$STAGE/frp_sha256_checksums" ]]; then
    awk -v n="$name" '$2 == n { print $1; found=1 } END { exit found ? 0 : 1 }' \
      "$STAGE/frp_sha256_checksums" && return 0
  fi
  if [[ "$CANDIDATE" == "$FRP_VERSION" ]]; then
    case "$arch" in
      amd64) printf '%s\n' "$FRP_SHA256_AMD64"; return 0 ;;
      arm64) printf '%s\n' "$FRP_SHA256_ARM64"; return 0 ;;
    esac
  fi
  return 1
}

ws_src="$STAGE/websocket.go"
if [[ "${FRP_COMPAT_OFFLINE:-}" != "1" ]]; then
  curl -fL --retry 3 --connect-timeout 10 --max-time 60 \
    -o "$ws_src" \
    "https://raw.githubusercontent.com/fatedier/frp/v${CANDIDATE}/pkg/util/net/websocket.go" \
    || fail_closed "websocket.go download failed"
fi
if [[ ! -f "$ws_src" ]] || ! grep -F "$FRP_WEBSOCKET_PATH" "$ws_src" >/dev/null 2>&1; then
  echo "BREAKING_WEBSOCKET_PATH=FAIL" >&2
  fail_closed "candidate websocket.go does not contain ${FRP_WEBSOCKET_PATH}"
fi
echo "WEBSOCKET_PATH_UNCHANGED=PASS"

echo "Candidate FRP : $CANDIDATE"
echo "Pinned FRP    : $FRP_VERSION"
echo "WebSocket path (project): $FRP_WEBSOCKET_PATH"
echo "Stage         : $STAGE"
echo "Run ID        : $RUN_ID"
echo

if [[ "${FRP_COMPAT_SKIP_ARCHIVES:-}" == "1" ]]; then
  fail_closed "FRP_COMPAT_SKIP_ARCHIVES is no longer allowed (fail-closed gate)"
fi

if [[ "${FRP_COMPAT_OFFLINE:-}" == "1" ]]; then
  echo "OFFLINE=1; expecting pre-staged archives in $STAGE"
else
  # Official checksum file is the preferred trusted digest source for a new
  # candidate (not yet pinned in VERSION).
  curl -fL --retry 3 --connect-timeout 10 --max-time 60 \
    -o "$STAGE/frp_sha256_checksums" \
    "$BASE_URL/frp_sha256_checksums" \
    || fail_closed "official frp_sha256_checksums download failed"
  download "frp_${CANDIDATE}_linux_amd64.tar.gz"
  download "frp_${CANDIDATE}_linux_arm64.tar.gz"
fi

AMD_EXPECT="$(trusted_digest_for amd64)" || fail_closed "trusted amd64 digest unavailable"
ARM_EXPECT="$(trusted_digest_for arm64)" || fail_closed "trusted arm64 digest unavailable"

python3 - "$STAGE" "$CANDIDATE" "$AMD_EXPECT" "$ARM_EXPECT" <<'PY' || fail_closed "archive digest/extract verification failed"
import hashlib, os, sys, tarfile
from pathlib import Path

stage, version, expect_amd, expect_arm = sys.argv[1:]

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_then_extract(archive: Path, expected: str) -> str:
    if not archive.is_file():
        raise SystemExit(f"MISSING {archive.name}")
    digest = sha256(archive)
    print(f"{archive.name} expected={expected}")
    print(f"{archive.name} actual={digest}")
    if digest != expected:
        try:
            archive.unlink()
        except OSError:
            pass
        raise SystemExit(f"DIGEST_MISMATCH {archive.name}")
    extract = archive.parent / (archive.name.replace(".tar.gz", "") + "_extract")
    if extract.exists():
        import shutil
        shutil.rmtree(extract)
    extract.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as tar:
        # Refuse path traversal before extract.
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or ".." in Path(name).parts:
                raise SystemExit(f"UNSAFE_ARCHIVE_MEMBER {archive.name}: {name}")
        tar.extractall(extract)
    print(f"DIGEST_OK_EXTRACTED {archive.name}")
    return digest

amd = verify_then_extract(Path(stage) / f"frp_{version}_linux_amd64.tar.gz", expect_amd)
arm = verify_then_extract(Path(stage) / f"frp_{version}_linux_arm64.tar.gz", expect_arm)
Path(stage, "verified.amd64.sha256").write_text(amd + "\n")
Path(stage, "verified.arm64.sha256").write_text(arm + "\n")
print("FRP_COMPAT_ARCHIVES=PASS")
PY

# Config verify against current project templates if binaries extracted.
amd_bin="$(find "$STAGE" -path '*linux_amd64*' -name frps -type f | head -n1 || true)"
frpc_bin="$(find "$STAGE" -path '*linux_amd64*' -name frpc -type f | head -n1 || true)"
[[ -n "$amd_bin" && -x "$amd_bin" ]] || fail_closed "verified amd64 frps binary missing"
[[ -n "$frpc_bin" && -x "$frpc_bin" ]] || fail_closed "verified amd64 frpc binary missing"

frps_ver="$("$amd_bin" --version 2>/dev/null | head -n1 || true)"
frpc_ver="$("$frpc_bin" --version 2>/dev/null | head -n1 || true)"
echo "FRPS_VERSION_OUTPUT=$frps_ver"
echo "FRPC_VERSION_OUTPUT=$frpc_ver"
printf '%s\n' "$frps_ver" | grep -F "$CANDIDATE" >/dev/null \
  || fail_closed "frps --version does not contain $CANDIDATE"
printf '%s\n' "$frpc_ver" | grep -F "$CANDIDATE" >/dev/null \
  || fail_closed "frpc --version does not contain $CANDIDATE"

tmp="$(mktemp)"
cat >"$tmp" <<EOF
bindPort = 7000
auth.method = "token"
auth.token = "compat-check-not-a-secret"
allowPorts = [{ start = 6000, end = 6098 }]
EOF
if ! "$amd_bin" verify -c "$tmp"; then
  rm -f "$tmp"
  fail_closed "frps verify failed"
fi
echo "FRPS_VERIFY=PASS"
rm -f "$tmp"

# Atomic PASS report only after every required check.
python3 - "$STAGE" "$CANDIDATE" "$RUN_ID" "$BASE_URL" "$AMD_EXPECT" "$ARM_EXPECT" <<'PY'
import json, sys, time
from pathlib import Path

stage, version, run_id, source, expect_amd, expect_arm = sys.argv[1:]
stage_p = Path(stage)
actual_amd = (stage_p / "verified.amd64.sha256").read_text().strip()
actual_arm = (stage_p / "verified.arm64.sha256").read_text().strip()
report = {
    "schema_version": 1,
    "result": "PASS",
    "target_frp_version": version,
    "source_release": source,
    "release_tag": "v%s" % version,
    "run_id": run_id,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "platform": "linux",
    "artifacts": [
        {
            "name": "frp_%s_linux_amd64.tar.gz" % version,
            "architecture": "amd64",
            "expected_sha256": expect_amd,
            "actual_sha256": actual_amd,
            "result": "PASS",
        },
        {
            "name": "frp_%s_linux_arm64.tar.gz" % version,
            "architecture": "arm64",
            "expected_sha256": expect_arm,
            "actual_sha256": actual_arm,
            "result": "PASS",
        },
    ],
}
tmp = stage_p / "report.json.tmp"
tmp.write_text(json.dumps(report, indent=2) + "\n")
tmp.replace(stage_p / "report.json")
status_tmp = stage_p / "report.status.tmp"
status_tmp.write_text("PASS\n")
status_tmp.replace(stage_p / "report.status")
# Convenience symlink/copy at version root for bump script discovery.
root = stage_p.parent
(root / "report.json").write_text((stage_p / "report.json").read_text())
(root / "report.status").write_text("PASS\n")
(root / "latest_run_id").write_text(run_id + "\n")
print("FRP_COMPAT=PASS")
print("REPORT=%s" % (stage_p / "report.json"))
PY

echo
echo "Next: run project tests, then ./scripts/bump-frp-version.sh ${CANDIDATE} --apply"
echo "Never install upstream latest automatically."
