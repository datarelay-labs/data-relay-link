#!/usr/bin/env bash
# Persistent launchctl enable/disable must not be swallowed with || true.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export FRP_TEST_UNAME_S=Darwin
export FRP_TEST_UNAME_M=arm64
export FRP_CLIENT_TEST_ROOT="$TMP/root"
export FRP_MACOS_STATE_ROOT="$TMP/state"
export FRP_TEST_CMD_PATH="$TMP/bin"
export FRP_TEST_LAUNCHCTL_LOG="$TMP/launchctl.log"
mkdir -p "$FRP_TEST_CMD_PATH"

cat >"$FRP_TEST_CMD_PATH/launchctl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "${FRP_TEST_LAUNCHCTL_LOG:-/dev/null}"
cmd="${1:-}"
case "$cmd" in
  enable)
    [[ "${FRP_TEST_LAUNCHCTL_ENABLE_FAIL:-}" == "1" ]] && exit 1
    exit 0
    ;;
  disable)
    [[ "${FRP_TEST_LAUNCHCTL_DISABLE_FAIL:-}" == "1" ]] && exit 1
    exit 0
    ;;
  bootstrap|load)
    [[ "${FRP_TEST_LAUNCHCTL_BOOTSTRAP_FAIL:-}" == "1" ]] && exit 1
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
chmod +x "$FRP_TEST_CMD_PATH/launchctl"

# shellcheck disable=SC1091
. "$ROOT/lib/frp-common.sh"
# shellcheck disable=SC1091
. "$ROOT/lib/frp-macos.sh"

frp_is_darwin
frp_launchd_usable

: >"$FRP_TEST_LAUNCHCTL_LOG"
frp_macos_launchd_set_enabled enable
grep -q 'enable system/com.datarelay.drlink.frpc' "$FRP_TEST_LAUNCHCTL_LOG"

export FRP_TEST_LAUNCHCTL_ENABLE_FAIL=1
if frp_macos_launchd_set_enabled enable >/dev/null 2>"$TMP/enable.err"; then
  echo "FAIL: enable failure was swallowed" >&2
  exit 1
fi
grep -q 'launchctl enable' "$TMP/enable.err"
unset FRP_TEST_LAUNCHCTL_ENABLE_FAIL

export FRP_TEST_LAUNCHCTL_DISABLE_FAIL=1
if frp_macos_launchd_set_enabled disable >/dev/null 2>"$TMP/disable.err"; then
  echo "FAIL: disable failure was swallowed" >&2
  exit 1
fi
grep -q 'launchctl disable' "$TMP/disable.err"
unset FRP_TEST_LAUNCHCTL_DISABLE_FAIL

export FRP_TEST_LAUNCHCTL_BOOTSTRAP_FAIL=1
if frp_macos_launchd_bootstrap >/dev/null 2>"$TMP/boot.err"; then
  echo "FAIL: bootstrap failure was swallowed" >&2
  exit 1
fi
grep -q 'launchctl bootstrap/load' "$TMP/boot.err"
unset FRP_TEST_LAUNCHCTL_BOOTSTRAP_FAIL

if grep -E 'launchctl (enable|disable).*\|[[:space:]]*true' "$ROOT/lib/frp-macos.sh"; then
  echo "FAIL: launchctl enable/disable still fail-open" >&2
  exit 1
fi

echo "MACOS_LAUNCHCTL_ENABLE_TEST=PASS"
