#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/lib/frp-common.sh"

EXPECTED=45be02b186860d375ed49a8941ae9569628a54bf14e67fc36b29c98c99dabcc6
[[ "$FRP_VERSION" == 0.71.0 ]]
[[ "$FRP_SHA256_DARWIN_ARM64" == "$EXPECTED" ]]
[[ "$(frp_checksum_for 0.71.0 arm64 darwin)" == "$EXPECTED" ]]
[[ "$(frp_release_url 0.71.0 arm64 darwin)" == \
  https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_darwin_arm64.tar.gz ]]
if frp_checksum_for 0.71.0 amd64 darwin >/dev/null 2>&1; then
  echo "FAIL: Darwin amd64 checksum resolved" >&2
  exit 1
fi
python3 - "$ROOT/release-manifest.json" "$EXPECTED" <<'PY'
import json,sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
assert data["supported_frp_versions"]["0.71.0"]["darwin_arm64_sha256"] == sys.argv[2]
PY
grep -q 'shasum -a 256 -c -' "$ROOT/lib/frp-macos.sh"
echo "MACOS_FRP_PIN_TEST=PASS"
