#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export FRP_TEST_UNAME_S=Darwin
export FRP_CLIENT_TEST_ROOT="$TMP/root"
export FRP_MACOS_STATE_ROOT="$TMP/state"
. "$ROOT/lib/frp-common.sh"

out="$TMP/rendered.plist"
frp_macos_render_plist "$out"
python3 - "$out" "$TMP/root$TMP/state" <<'PY'
import plistlib,sys
with open(sys.argv[1],"rb") as f: p=plistlib.load(f)
state=sys.argv[2]
assert p["Label"] == "com.datarelay.frp-auto-deploy.frpc"
assert p["ProgramArguments"] == [state+"/bin/frpc", "-c", state+"/frpc.toml"]
assert p["RunAtLoad"] is True
assert p["KeepAlive"]["SuccessfulExit"] is False
assert p["KeepAlive"]["NetworkState"] is True
assert p["StandardOutPath"] == state+"/logs/frpc.out.log"
assert "@" not in repr(p)
PY
echo "MACOS_LAUNCHD_PLIST_TEST=PASS"
