#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export FRP_TEST_UNAME_S=Darwin FRP_TEST_UNAME_M=arm64
export FRP_CLIENT_SOURCED=1
. "$ROOT/install-client.sh"

pkg="$(python3 - <<'PY'
import base64,json
p={"v":1,"u":"https://example.test/enroll","c":"a"*64,"t":"ticket.value"}
print("zt1."+base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("="))
PY
)"
frp_zero_touch_apply_package "$pkg"
[[ "$FRP_ZERO_TOUCH" == 1 ]]
[[ "$FRP_ALLOCATOR_URL" == https://example.test/enroll ]]
frp_detect_arch
[[ "$FRP_ARCH" == arm64 ]]
echo "MACOS_ZERO_TOUCH_COMMAND_TEST=PASS"
