#!/usr/bin/env bash
# Cross-distro portability: package mappings, Bash/Python mins, systemd unit
# compatibility, layout, uninstall safety, and frpctl readline fallback.
# Uses PATH / file injection only — never the host package manager or systemd.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

FRP_CTL_SOURCED=1
# shellcheck source=../tools/frpctl
. "$ROOT/tools/frpctl"

# ---------------------------------------------------------------------------
# Distro metadata fixtures (detection only — not a full distro install)
# ---------------------------------------------------------------------------

expect_id() {
  local fixture="$1" id="$2"
  export FRP_OS_RELEASE_FILE="$ROOT/tests/fixtures/os-release/$fixture"
  frp_detect_platform
  [[ "$DISTRO_ID" == "$id" ]] || fail "$fixture ID $DISTRO_ID != $id"
}

expect_id ubuntu ubuntu
expect_id ubuntu24 ubuntu
expect_id rocky rocky
expect_id rocky8 rocky
expect_id almalinux almalinux
expect_id amazonlinux amzn
expect_id amazonlinux2 amzn
pass "DISTRO_UBUNTU"
pass "DISTRO_ROCKY"
pass "DISTRO_ROCKY8"
pass "DISTRO_ALMA"
pass "DISTRO_AMAZON_2023"
pass "DISTRO_AMAZON_2"

# ---------------------------------------------------------------------------
# Package mappings
# ---------------------------------------------------------------------------

[[ "$(frp_package_for_command curl apt)" == curl ]] || fail "curl apt"
[[ "$(frp_package_for_command python3 dnf)" == python3 ]] || fail "python3 dnf"
[[ "$(frp_package_for_command hostname yum)" == hostname ]] || fail "hostname yum"
[[ "$(frp_package_for_command ss apt)" == iproute2 ]] || fail "ss apt"
[[ "$(frp_package_for_command ss dnf)" == iproute ]] || fail "ss dnf"
[[ "$(frp_package_for_command ip yum)" == iproute ]] || fail "ip yum"
[[ "$(frp_package_for_command nginx apt)" == nginx ]] || fail "nginx apt"
[[ "$(frp_package_for_command nginx dnf)" == nginx ]] || fail "nginx dnf"
PACKAGES=()
MISSING_COMMANDS=(curl openssl)
frp_packages_for_missing apt
printf '%s\n' "${PACKAGES[@]}" | grep -qx ca-certificates || fail "always ca-certificates"
printf '%s\n' "${PACKAGES[@]}" | grep -qx curl || fail "missing curl mapped"
pass "APT_DEPENDENCY_MAPPING"
pass "DNF_DEPENDENCY_MAPPING"
pass "YUM_DEPENDENCY_MAPPING"

# ---------------------------------------------------------------------------
# systemd required / unsupported init
# ---------------------------------------------------------------------------

export FRP_TEST_CMD_PATH="$WORKDIR/sys-ok"
export FRP_TEST_SYSTEMD_RUNTIME_DIR="$WORKDIR/run-ok"
mkdir -p "$FRP_TEST_CMD_PATH" "$FRP_TEST_SYSTEMD_RUNTIME_DIR"
cat >"$FRP_TEST_CMD_PATH/systemctl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$FRP_TEST_CMD_PATH/systemctl"
frp_require_systemd || fail "usable systemd should pass"
pass "SYSTEMD_REQUIRED_CHECK"

unset FRP_TEST_CMD_PATH
export FRP_TEST_CMD_PATH="$WORKDIR/sys-none"
export FRP_TEST_SYSTEMD_RUNTIME_DIR="$WORKDIR/run-missing"
mkdir -p "$FRP_TEST_CMD_PATH"
rm -rf "$FRP_TEST_SYSTEMD_RUNTIME_DIR"
if frp_require_systemd 2>"$WORKDIR/no-sys.err"; then
  fail "missing systemd should fail"
fi
grep -q 'ERROR: this release requires a systemd-based Linux distribution.' "$WORKDIR/no-sys.err" \
  || fail "unsupported init message"
pass "UNSUPPORTED_INIT_FAILS_CLEANLY"
unset FRP_TEST_CMD_PATH FRP_TEST_SYSTEMD_RUNTIME_DIR

# Amazon Linux 2 systemd 219 cannot load ProtectSystem=strict.
export FRP_TEST_SYSTEMD_VERSION=219
frp_systemd_supports_service_hardening && fail "219 should not keep strict hardening"
frp_write_compatible_systemd_unit \
  "$ROOT/server/drlink-allocator.service" \
  "$WORKDIR/allocator-219.service"
if grep -q '^ProtectSystem=' "$WORKDIR/allocator-219.service"; then
  fail "old systemd unit still has ProtectSystem"
fi
if grep -q '^ReadWritePaths=' "$WORKDIR/allocator-219.service"; then
  fail "old systemd unit still has ReadWritePaths"
fi
if grep -q '^NoNewPrivileges=' "$WORKDIR/allocator-219.service"; then
  fail "old systemd unit still has NoNewPrivileges"
fi
grep -q '^PrivateTmp=' "$WORKDIR/allocator-219.service" || fail "PrivateTmp should remain"
grep -q 'ExecStart=/usr/bin/python3' "$WORKDIR/allocator-219.service" || fail "allocator exec"
unset FRP_TEST_SYSTEMD_VERSION
export FRP_TEST_SYSTEMD_VERSION=252
frp_systemd_supports_service_hardening || fail "252 should keep hardening"
frp_write_compatible_systemd_unit \
  "$ROOT/server/drlink-allocator.service" \
  "$WORKDIR/allocator-252.service"
grep -q '^RuntimeDirectory=drlink/allocator$' "$WORKDIR/allocator-252.service" \
  || fail "allocator runtime directory missing"
grep -q '^RuntimeDirectoryMode=0700$' "$WORKDIR/allocator-252.service" \
  || fail "allocator runtime directory mode missing"
grep -q '^ProtectSystem=strict' "$WORKDIR/allocator-252.service" || fail "modern unit lost strict"
grep -q '^ReadWritePaths=/var/lib/drlink /var/log/drlink /etc/drlink /etc/frp$' \
  "$WORKDIR/allocator-252.service" || fail "allocator writable paths incomplete"
frp_write_compatible_systemd_unit \
  "$ROOT/server/drlink-frontend.service" \
  "$WORKDIR/frontend-252.service"
grep -q '^ProtectSystem=strict' "$WORKDIR/frontend-252.service" || fail "frontend modern unit lost strict"
export FRP_TEST_SYSTEMD_VERSION=219
frp_write_compatible_systemd_unit \
  "$ROOT/server/drlink-frontend.service" \
  "$WORKDIR/frontend-219.service"
if grep -q '^ProtectSystem=' "$WORKDIR/frontend-219.service"; then
  fail "old systemd frontend unit still has ProtectSystem"
fi
grep -q '^RuntimeDirectory=drlink/frontend' "$WORKDIR/frontend-219.service" \
  || fail "frontend unit lost RuntimeDirectory on old systemd"
unset FRP_TEST_SYSTEMD_VERSION
pass "SYSTEMD_OLD_UNIT_COMPAT"

# ---------------------------------------------------------------------------
# Python / Bash
# ---------------------------------------------------------------------------

python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 7) else 1)" \
  || fail "host python is older than the documented minimum"
frp_require_python || fail "frp_require_python on this host"
grep -q 'python 3.7 or newer is required' "$ROOT/server/frp-port-allocator.py" \
  || fail "allocator min python guard"
grep -q 'python 3.7 or newer is required' "$ROOT/server/migrate_token.py" \
  || fail "migrate_token min python guard"
grep -q 'python 3.7 or newer is required' "$ROOT/lib/frp_pki.py" \
  || fail "pki min python guard"
python3 -m py_compile \
  "$ROOT/server/frp-port-allocator.py" \
  "$ROOT/server/migrate_token.py" \
  "$ROOT/lib/frp_mgmt_auth.py" \
  "$ROOT/lib/frp_pki.py" \
  "$ROOT/lib/frp_frontend.py" \
  "$ROOT/lib/frp_doctor.py" \
  "$ROOT/scripts/build-bundles.py"
pass "PYTHON_MIN_VERSION"

frp_require_bash || fail "frp_require_bash on this host"
# Features used by installers / frpctl that Amazon Linux 2 Bash 4.2 provides.
mapfile -t _frp_compat_arr < <(printf '%s\n' a b)
[[ ${#_frp_compat_arr[@]} -eq 2 ]] || fail "mapfile"
_frp_compat_s='ab'
[[ "${_frp_compat_s: -1}" == b ]] || fail "negative offset substring"
declare -a _frp_compat_words=(one two)
[[ "${_frp_compat_words[1]}" == two ]] || fail "arrays"
# Bash 4.2 + set -u: empty array [@] expansion is unbound; length is safe.
_frp_empty=()
((${#_frp_empty[@]} == 0)) || fail "empty array length"
pass "BASH_COMPATIBILITY"

# ---------------------------------------------------------------------------
# ss / hostname capability helpers
# ---------------------------------------------------------------------------

export FRP_TEST_CMD_PATH="$WORKDIR/ss-no-header"
mkdir -p "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/ss" <<'EOF'
#!/bin/sh
if [ "$1" = "-H" ]; then
  echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port" >&2
  exit 1
fi
cat <<'OUT'
State Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0 128 0.0.0.0:6000 0.0.0.0:*
LISTEN 0 128 127.0.0.1:22 0.0.0.0:*
LISTEN 0 128 *:6099 *:*
OUT
EOF
chmod +x "$FRP_TEST_CMD_PATH/ss"
ports="$(frp_listening_tcp_ports_in_range 6000 6098)"
[[ "$ports" == "6000" ]] || fail "ss without -H parsed $ports"
unset FRP_TEST_CMD_PATH

export FRP_TEST_CMD_PATH="$WORKDIR/ss-with-header-flag"
mkdir -p "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/ss" <<'EOF'
#!/bin/sh
if [ "$1" = "-H" ]; then
  echo "LISTEN 0 128 0.0.0.0:6001 0.0.0.0:*"
  echo "LISTEN 0 128 [::]:6002 [::]:*"
  exit 0
fi
exit 1
EOF
chmod +x "$FRP_TEST_CMD_PATH/ss"
ports="$(frp_listening_tcp_ports_in_range 6000 6098)"
[[ "$ports" == "6001,6002" ]] || fail "ss -H parsed $ports"
unset FRP_TEST_CMD_PATH

export FRP_TEST_CMD_PATH="$WORKDIR/host-ip"
mkdir -p "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/hostname" <<'EOF'
#!/bin/sh
exit 1
EOF
cat >"$FRP_TEST_CMD_PATH/ip" <<'EOF'
#!/bin/sh
echo "2: eth0    inet 192.0.2.50/24 brd 192.0.2.255 scope global eth0"
EOF
chmod +x "$FRP_TEST_CMD_PATH/hostname" "$FRP_TEST_CMD_PATH/ip"
ip="$(frp_detect_internal_ip)"
[[ "$ip" == "192.0.2.50" ]] || fail "ip fallback $ip"
unset FRP_TEST_CMD_PATH
pass "SS_AND_IP_FALLBACKS"

# ---------------------------------------------------------------------------
# frpctl readline capability / safe fallback
# ---------------------------------------------------------------------------

grep -q 'bind -x' "$ROOT/tools/frpctl" || fail "bind -x custom completion"
grep -q 'set disable-completion on' "$ROOT/tools/frpctl" || fail "disable default completion"
if grep -q "disable-completion off" "$ROOT/tools/frpctl"; then
  fail "filename completion re-enabled"
fi
# read -e is only used after a successful custom bind.
python3 - "$ROOT/tools/frpctl" <<'PY' || fail "read -e not gated on bound tab"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding='utf-8')
idx_bound = text.find('_FRP_CTL_BOUND_TAB:-')
idx_reade = text.find('read -e')
if idx_bound < 0 or idx_reade < 0 or idx_reade < idx_bound:
    raise SystemExit(1)
PY
_FRP_CTL_BOUND_TAB=""
FRP_CTL_DISABLE_TAB=1
frpctl_repl_enable_completion
[[ -z "${_FRP_CTL_BOUND_TAB:-}" ]] || fail "DISABLE_TAB still bound"
unset FRP_CTL_DISABLE_TAB
pass "FRPCTL_READLINE_CAPABILITY"
pass "FRPCTL_NO_READLINE_FALLBACK_SAFE"

# ---------------------------------------------------------------------------
# Install / uninstall layout (documented paths)
# ---------------------------------------------------------------------------

grep -q '/usr/local/bin/frps' "$ROOT/install-server.sh" || fail "server frps path"
grep -q 'sbin_dir' "$ROOT/install-server.sh" || fail "server tools in sbin"
grep -q '/usr/local/bin/frpc' "$ROOT/install-client.sh" || fail "client frpc path"
grep -q 'frp_client_path /usr/local/bin' "$ROOT/lib/frp-client-common.sh" || fail "client tools in bin"
grep -q 'lib/frp-common.sh' "$ROOT/scripts/build-bundles.py" || fail "client bundle missing common lib"
grep -q "'release-manifest.json'" "$ROOT/scripts/build-bundles.py" || fail "client bundle missing release-manifest"
grep -q 'lib/frp_doctor.py' "$ROOT/scripts/build-bundles.py" || fail "bundle missing doctor engine"
grep -q 'lib/frp-doctor-common.sh' "$ROOT/scripts/build-bundles.py" || fail "bundle missing doctor lib"
grep -q 'lib/frp_support_bundle.py' "$ROOT/scripts/build-bundles.py" || fail "bundle missing support-bundle lib"
grep -q 'tools/frp-support-bundle' "$ROOT/scripts/build-bundles.py" || fail "bundle missing support-bundle tool"
if grep -q 'Debian/Ubuntu only' "$ROOT/install-server.sh"; then
  fail "server installer still apt-only"
fi
grep -q 'ensure_dependencies' "$ROOT/install-server.sh" || fail "server uses shared deps"
grep -q 'frp_write_compatible_systemd_unit' "$ROOT/install-server.sh" || fail "server unit compat"
pass "SERVER_INSTALL_LAYOUT"
pass "CLIENT_INSTALL_LAYOUT"

grep -q 'bootstrap-client.sh | sudo bash -s -- --upgrade' "$ROOT/install-client.sh" \
  || fail "upgrade path documented"
grep -q 'Enrollment Code : NOT REQUIRED' "$ROOT/tests/test-client-upgrade.sh" \
  || fail "upgrade tests"
pass "CLIENT_SAFE_UPGRADE_PORTABILITY"

# Uninstall must not purge server registry/token unless --purge.
python3 - "$ROOT/uninstall-server.sh" <<'PY' || fail "default uninstall deletes state"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding='utf-8')
idx_purge = text.find('if [[ "$PURGE" == true ]]; then')
if idx_purge < 0:
    raise SystemExit(1)
before = text[:idx_purge]
if 'try_rm_rf "$(frp_u_path /etc/frp)"' in before or 'frp_u_safe_rm_rf "$(frp_u_path /etc/frp)"' in before:
    raise SystemExit(1)
if '--purge' not in text or 'PURGE_CONFIRMATION_REQUIRED' not in text:
    raise SystemExit(1)
PY
grep -q "Configuration, token, and registry were preserved" "$ROOT/uninstall-server.sh" \
  || fail "server preserve message"
grep -qF 'if [[ ! -f /etc/drlink/config.json ]]' "$ROOT/uninstall-client.sh" \
  || fail "client uninstall dual-role guard"
grep -q 'command -v systemctl' "$ROOT/uninstall-server.sh" || fail "server uninstall systemd guard"
if grep -nE 'systemctl[[:space:]]+(enable|start|unmask)[[:space:]].*nginx' "$ROOT/uninstall-server.sh"; then
  fail "server uninstall starts distro nginx"
fi
pass "UNINSTALL_CLIENT_PORTABILITY"
pass "UNINSTALL_SERVER_PORTABILITY"

# Architecture detection
export FRP_TEST_UNAME_M=aarch64
frp_detect_architecture || fail "aarch64"
[[ "$FRP_ARCH" == arm64 ]] || fail "arm64 mapping"
unset FRP_TEST_UNAME_M
pass "ARM64_STATIC_COMPATIBILITY"

# live-distro-smoke.sh is a read-only collector; keep it non-destructive.
SMOKE="$ROOT/tests/live-distro-smoke.sh"
[[ -f "$SMOKE" ]] || fail "live-distro-smoke.sh missing"
bash -n "$SMOKE" || fail "live-distro-smoke.sh syntax"
if grep -nE -- '--insecure|(^|[[:space:]])-k([[:space:]]|$)' "$SMOKE"; then
  fail "live-distro-smoke.sh uses insecure curl"
fi
if grep -nE 'frp-create-client|frp-release-|frp-revoke|systemctl (restart|enable|disable|stop)|setenforce|iptables|firewall-cmd|semanage' "$SMOKE"; then
  fail "live-distro-smoke.sh looks destructive"
fi
if grep -nE 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|--insecure' "$SMOKE"; then
  fail "live-distro-smoke.sh secret/insecure pattern"
fi
grep -q 'NOT_INSTALLED\|NOT_APPLICABLE\|NOT_TESTED' "$SMOKE" || fail "live-distro-smoke.sh role states"
pass "LIVE_DISTRO_SMOKE_STATIC"

echo
echo "PORTABILITY_TEST=PASS"
echo "Note: this file does not start systemd or install packages on a live distro."
echo "Container/CI jobs report per-distro package installs separately."
echo "SYSTEMD_SMOKE is not claimed here."
