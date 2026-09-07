#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/lib/frp-common.sh"

export FRP_TEST_UNAME_S=Darwin FRP_TEST_UNAME_M=arm64
[[ "$(frp_os)" == darwin ]]
frp_is_darwin
frp_detect_arch
[[ "$FRP_ARCH" == arm64 ]]
[[ "$EXPECTED_SHA" == "$FRP_SHA256_DARWIN_ARM64" ]]

export FRP_TEST_UNAME_M=x86_64
if frp_detect_arch >/dev/null 2>&1; then
  echo "FAIL: Intel Darwin accepted" >&2
  exit 1
fi

export FRP_TEST_UNAME_S=Linux FRP_TEST_UNAME_M=x86_64
frp_detect_arch
[[ "$FRP_ARCH" == amd64 ]]
[[ "$(frp_platform_map_path /etc/frp/frpc.toml)" == /etc/frp/frpc.toml ]]

echo "MACOS_DETECTION_TEST=PASS"
