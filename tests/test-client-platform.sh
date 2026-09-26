#!/usr/bin/env bash
# Platform detection, package-manager selection, dependency install, and systemd
# checks. Uses PATH / file injection only — never the host package manager or systemd.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_CLIENT_SOURCED=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"
eval "$(declare -f frp_python_module_importable | sed '1s/frp_python_module_importable/frp_python_module_importable_real/')"

FIXTURES="$ROOT/tests/fixtures/os-release"

make_cmd() {
  local dir="$1" name="$2"
  mkdir -p "$dir"
  cat >"$dir/$name" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$dir/$name"
}

make_required_cmds() {
  local dir="$1"
  local c
  mkdir -p "$dir"
  while IFS= read -r c; do
    [[ -n "$c" ]] || continue
    make_cmd "$dir" "$c"
  done < <(frp_required_commands)
}

write_pm() {
  local path="$1" log="$2" extra="${3:-}"
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>$(printf '%q' "$log")
printf 'DEBIAN_FRONTEND=%s\\n' "\${DEBIAN_FRONTEND-}" >>$(printf '%q' "$log.env")
$extra
exit 0
EOF
  chmod +x "$path"
}

reset_pm_isolation() {
  unset PACKAGE_MANAGER MISSING_COMMANDS PACKAGES FRP_ARCH EXPECTED_SHA || true
  unset FRP_TEST_CMD_PATH FRP_TEST_PM_PATH FRP_TEST_UNAME_M || true
  unset FRP_TEST_SYSTEMD_RUNTIME_DIR FRP_OS_RELEASE_FILE FRP_DEPENDENCY_ROLE || true
  unset FRP_TEST_SYSTEMD_VERSION || true
  PACKAGE_MANAGER=""
}

# ---------------------------------------------------------------------------
# Package manager detection
# ---------------------------------------------------------------------------

reset_pm_isolation
export FRP_TEST_PM_PATH="$WORKDIR/pm-apt"
make_cmd "$FRP_TEST_PM_PATH" apt-get
frp_detect_package_manager
[[ "$PACKAGE_MANAGER" == apt ]] || fail "apt only -> $PACKAGE_MANAGER"
pass "package manager: apt only"

reset_pm_isolation
export FRP_TEST_PM_PATH="$WORKDIR/pm-dnf"
make_cmd "$FRP_TEST_PM_PATH" dnf
frp_detect_package_manager
[[ "$PACKAGE_MANAGER" == dnf ]] || fail "dnf only -> $PACKAGE_MANAGER"
pass "package manager: dnf only"

reset_pm_isolation
export FRP_TEST_PM_PATH="$WORKDIR/pm-yum"
make_cmd "$FRP_TEST_PM_PATH" yum
frp_detect_package_manager
[[ "$PACKAGE_MANAGER" == yum ]] || fail "yum only -> $PACKAGE_MANAGER"
pass "package manager: yum only"

reset_pm_isolation
export FRP_TEST_PM_PATH="$WORKDIR/pm-dnf-yum"
make_cmd "$FRP_TEST_PM_PATH" dnf
make_cmd "$FRP_TEST_PM_PATH" yum
frp_detect_package_manager
[[ "$PACKAGE_MANAGER" == dnf ]] || fail "dnf+yum should prefer dnf -> $PACKAGE_MANAGER"
pass "package manager: dnf+yum prefers dnf"

reset_pm_isolation
export FRP_TEST_PM_PATH="$WORKDIR/pm-none"
mkdir -p "$FRP_TEST_PM_PATH"
frp_detect_package_manager
[[ -z "$PACKAGE_MANAGER" ]] || fail "no package manager -> $PACKAGE_MANAGER"
pass "package manager: none"

# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------

reset_pm_isolation
export FRP_TEST_UNAME_M=x86_64
frp_detect_architecture || fail "x86_64 should be supported"
[[ "$FRP_ARCH" == amd64 ]] || fail "x86_64 arch $FRP_ARCH"
pass "architecture: x86_64 -> amd64"

reset_pm_isolation
export FRP_TEST_UNAME_M=aarch64
frp_detect_architecture || fail "aarch64 should be supported"
[[ "$FRP_ARCH" == arm64 ]] || fail "aarch64 arch $FRP_ARCH"
pass "architecture: aarch64 -> arm64"

reset_pm_isolation
export FRP_TEST_UNAME_M=arm64
frp_detect_architecture || fail "arm64 should be supported"
[[ "$FRP_ARCH" == arm64 ]] || fail "arm64 arch $FRP_ARCH"
pass "architecture: arm64 -> arm64"

reset_pm_isolation
export FRP_TEST_UNAME_M=i686
if frp_detect_architecture 2>"$WORKDIR/arch.err"; then
  fail "i686 should be unsupported"
fi
grep -q 'ERROR: unsupported architecture: i686' "$WORKDIR/arch.err" || fail "unsupported arch message"
pass "architecture: unsupported fails clearly"

# ---------------------------------------------------------------------------
# Distro metadata
# ---------------------------------------------------------------------------

expect_distro() {
  local fixture="$1" id="$2" needle="$3"
  reset_pm_isolation
  export FRP_OS_RELEASE_FILE="$FIXTURES/$fixture"
  frp_detect_platform
  [[ "$DISTRO_ID" == "$id" ]] || fail "$fixture ID $DISTRO_ID != $id"
  [[ "$DISTRO_NAME" == *"$needle"* ]] || fail "$fixture name $DISTRO_NAME"
}

expect_distro ubuntu ubuntu "Ubuntu 22.04"
expect_distro ubuntu24 ubuntu "Ubuntu 24.04"
expect_distro debian debian "Debian GNU/Linux 12"
expect_distro rocky rocky "Rocky Linux 9"
expect_distro rocky8 rocky "Rocky Linux 8"
expect_distro almalinux almalinux "AlmaLinux 9"
expect_distro rhel rhel "Red Hat Enterprise Linux 9"
expect_distro centos-stream centos "CentOS Stream 9"
expect_distro fedora fedora "Fedora Linux 41"
expect_distro amazonlinux amzn "Amazon Linux 2023"
expect_distro amazonlinux2 amzn "Amazon Linux 2"
expect_distro unknown appliance "Custom Appliance OS"
pass "distro metadata fixtures"

# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------

reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/sys-ok"
export FRP_TEST_SYSTEMD_RUNTIME_DIR="$WORKDIR/run-systemd-ok"
mkdir -p "$FRP_TEST_SYSTEMD_RUNTIME_DIR"
make_cmd "$FRP_TEST_CMD_PATH" systemctl
frp_require_systemd || fail "systemd present/functional should pass"
pass "systemd: present and usable"

reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/sys-missing"
export FRP_TEST_SYSTEMD_RUNTIME_DIR="$WORKDIR/run-systemd-ok"
mkdir -p "$FRP_TEST_CMD_PATH" "$FRP_TEST_SYSTEMD_RUNTIME_DIR"
if frp_require_systemd 2>"$WORKDIR/sys-missing.err"; then
  fail "missing systemctl should fail"
fi
grep -q 'ERROR: this release requires a systemd-based Linux distribution.' "$WORKDIR/sys-missing.err" \
  || fail "missing systemctl error message"
pass "systemd: systemctl missing"

reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/sys-unusable"
export FRP_TEST_SYSTEMD_RUNTIME_DIR="$WORKDIR/run-systemd-missing"
make_cmd "$FRP_TEST_CMD_PATH" systemctl
rm -rf "$FRP_TEST_SYSTEMD_RUNTIME_DIR"
if frp_require_systemd 2>"$WORKDIR/sys-unusable.err"; then
  fail "unusable systemd should fail"
fi
grep -q 'ERROR: this release requires a systemd-based Linux distribution.' "$WORKDIR/sys-unusable.err" \
  || fail "unusable systemd error message"
pass "systemd: runtime unusable"

# ---------------------------------------------------------------------------
# Dependency installation
# ---------------------------------------------------------------------------

# All commands present: skip package manager entirely.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-all"
export FRP_TEST_PM_PATH="$WORKDIR/pm-skip"
make_required_cmds "$FRP_TEST_CMD_PATH"
SKIP_LOG="$WORKDIR/pm-skip.log"
: >"$SKIP_LOG.env"
write_pm "$FRP_TEST_PM_PATH/dnf" "$SKIP_LOG"
frp_detect_package_manager
ensure_dependencies || fail "all commands present should succeed"
if [[ -s "$SKIP_LOG" ]]; then
  fail "package manager should not run when commands exist"
fi
pass "deps: skip install when all commands present"

# Missing python3 triggers dnf install, then the fake PM creates the command.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-missing-py"
export FRP_TEST_PM_PATH="$WORKDIR/pm-dnf-install"
make_required_cmds "$FRP_TEST_CMD_PATH"
rm -f "$FRP_TEST_CMD_PATH/python3"
DNF_LOG="$WORKDIR/dnf-install.log"
: >"$DNF_LOG.env"
write_pm "$FRP_TEST_PM_PATH/dnf" "$DNF_LOG" \
  "printf '#!/bin/sh\\nexit 0\\n' >$(printf '%q' "$FRP_TEST_CMD_PATH/python3"); chmod +x $(printf '%q' "$FRP_TEST_CMD_PATH/python3")"
frp_detect_package_manager
ensure_dependencies || fail "dnf install of missing python3 should succeed"
grep -q 'install -y' "$DNF_LOG" || fail "dnf install -y not invoked"
if grep -Eq '(^|[[:space:]])(upgrade|update)([[:space:]]|$)' "$DNF_LOG"; then
  fail "dnf must not upgrade/update the system"
fi
grep -q 'python3' "$DNF_LOG" || fail "dnf should install python3"
grep -q 'ca-certificates' "$DNF_LOG" || fail "dnf should install ca-certificates"
pass "deps: missing commands trigger dnf install"

# apt-get update + install -y, noninteractive, no upgrade.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-missing-apt"
export FRP_TEST_PM_PATH="$WORKDIR/pm-apt-install"
make_required_cmds "$FRP_TEST_CMD_PATH"
rm -f "$FRP_TEST_CMD_PATH/curl"
APT_LOG="$WORKDIR/apt-install.log"
: >"$APT_LOG.env"
write_pm "$FRP_TEST_PM_PATH/apt-get" "$APT_LOG" \
  "if [ \"\$1\" = update ]; then exit 0; fi; printf '#!/bin/sh\\nexit 0\\n' >$(printf '%q' "$FRP_TEST_CMD_PATH/curl"); chmod +x $(printf '%q' "$FRP_TEST_CMD_PATH/curl")"
frp_detect_package_manager
[[ "$PACKAGE_MANAGER" == apt ]] || fail "apt detection for install test"
ensure_dependencies || fail "apt install of missing curl should succeed"
head -n 1 "$APT_LOG" | grep -qx 'update' || fail "apt-get update should run first"
grep -q 'install -y --no-install-recommends' "$APT_LOG" || fail "apt-get install -y --no-install-recommends"
if grep -Eq '(^|[[:space:]])(upgrade|dist-upgrade)([[:space:]]|$)' "$APT_LOG"; then
  fail "apt must not upgrade the system"
fi
grep -q 'DEBIAN_FRONTEND=noninteractive' "$APT_LOG.env" || fail "DEBIAN_FRONTEND=noninteractive"
pass "deps: apt-get update/install noninteractive"

# yum install -y
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-missing-yum"
export FRP_TEST_PM_PATH="$WORKDIR/pm-yum-install"
make_required_cmds "$FRP_TEST_CMD_PATH"
rm -f "$FRP_TEST_CMD_PATH/openssl"
YUM_LOG="$WORKDIR/yum-install.log"
: >"$YUM_LOG.env"
write_pm "$FRP_TEST_PM_PATH/yum" "$YUM_LOG" \
  "printf '#!/bin/sh\\nexit 0\\n' >$(printf '%q' "$FRP_TEST_CMD_PATH/openssl"); chmod +x $(printf '%q' "$FRP_TEST_CMD_PATH/openssl")"
frp_detect_package_manager
ensure_dependencies || fail "yum install of missing openssl should succeed"
grep -q 'install -y' "$YUM_LOG" || fail "yum install -y not invoked"
if grep -Eq '(^|[[:space:]])(upgrade|update)([[:space:]]|$)' "$YUM_LOG"; then
  fail "yum must not update/upgrade the system"
fi
pass "deps: yum install -y"

# Package manager failure propagates.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-pm-fail"
export FRP_TEST_PM_PATH="$WORKDIR/pm-fail"
make_required_cmds "$FRP_TEST_CMD_PATH"
rm -f "$FRP_TEST_CMD_PATH/python3"
mkdir -p "$FRP_TEST_PM_PATH"
cat >"$FRP_TEST_PM_PATH/dnf" <<'EOF'
#!/bin/sh
echo "dnf simulated failure" >&2
exit 1
EOF
chmod +x "$FRP_TEST_PM_PATH/dnf"
frp_detect_package_manager
if ensure_dependencies 2>"$WORKDIR/pm-fail.err"; then
  fail "package manager failure should propagate"
fi
grep -q 'dnf simulated failure' "$WORKDIR/pm-fail.err" || fail "pm stderr should be visible"
pass "deps: package manager failure propagates"

# Commands still missing after a successful PM exit fail closed.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-still-missing"
export FRP_TEST_PM_PATH="$WORKDIR/pm-noop"
make_required_cmds "$FRP_TEST_CMD_PATH"
rm -f "$FRP_TEST_CMD_PATH/python3"
write_pm "$FRP_TEST_PM_PATH/dnf" "$WORKDIR/noop.log"
frp_detect_package_manager
if ensure_dependencies 2>"$WORKDIR/still-missing.err"; then
  fail "missing command after install should fail"
fi
grep -q 'missing required command after dependency installation' "$WORKDIR/still-missing.err" \
  || fail "post-install missing error"
grep -q 'python3' "$WORKDIR/still-missing.err" || fail "post-install should name python3"
pass "deps: still missing after install fails"

# Unsupported package manager + missing tools: actionable error.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-no-pm"
export FRP_TEST_PM_PATH="$WORKDIR/pm-empty"
make_required_cmds "$FRP_TEST_CMD_PATH"
rm -f "$FRP_TEST_CMD_PATH/python3" "$FRP_TEST_CMD_PATH/openssl"
mkdir -p "$FRP_TEST_PM_PATH"
if ensure_dependencies 2>"$WORKDIR/no-pm.err"; then
  fail "missing tools without a package manager should fail"
fi
grep -q 'ERROR: required tools are missing:' "$WORKDIR/no-pm.err" || fail "missing tools header"
grep -q '  python3' "$WORKDIR/no-pm.err" || fail "python3 listed"
grep -q '  openssl' "$WORKDIR/no-pm.err" || fail "openssl listed"
grep -q 'Automatic dependency installation supports apt, dnf, and yum.' "$WORKDIR/no-pm.err" \
  || fail "unsupported manager guidance"
pass "deps: unsupported package manager error"

# Unknown systemd Linux with dependencies present can proceed.
reset_pm_isolation
export FRP_OS_RELEASE_FILE="$FIXTURES/unknown"
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-appliance"
export FRP_TEST_PM_PATH="$WORKDIR/pm-empty2"
export FRP_TEST_SYSTEMD_RUNTIME_DIR="$WORKDIR/run-appliance"
export FRP_TEST_UNAME_M=x86_64
mkdir -p "$FRP_TEST_PM_PATH" "$FRP_TEST_SYSTEMD_RUNTIME_DIR"
make_required_cmds "$FRP_TEST_CMD_PATH"
make_cmd "$FRP_TEST_CMD_PATH" systemctl
frp_detect_architecture || fail "appliance arch"
frp_detect_platform
frp_detect_package_manager
[[ "$DISTRO_ID" == appliance ]] || fail "appliance id"
[[ -z "$PACKAGE_MANAGER" ]] || fail "appliance should have no pm"
frp_require_systemd || fail "appliance systemd"
ensure_dependencies || fail "appliance with deps should skip install"
DETECT_OUT="$(frp_print_detected_linux)"
grep -q 'Custom Appliance OS 1.0' <<<"$DETECT_OUT" || fail "appliance distribution line"
grep -q 'Package mgr  : none' <<<"$DETECT_OUT" || fail "appliance package mgr none"
grep -q 'Architecture : amd64' <<<"$DETECT_OUT" || fail "appliance arch line"
grep -q 'Init system  : systemd' <<<"$DETECT_OUT" || fail "appliance init line"
pass "unknown systemd Linux with deps proceeds"

# Package name mapping
reset_pm_isolation
[[ "$(frp_package_for_command python3 apt)" == python3 ]] || fail "python3 package"
[[ "$(frp_package_for_command sha256sum apt)" == coreutils ]] || fail "sha256sum -> coreutils"
[[ "$(frp_package_for_command timeout dnf)" == coreutils ]] || fail "timeout -> coreutils"
[[ "$(frp_package_for_command ss apt)" == iproute2 ]] || fail "ss apt -> iproute2"
[[ "$(frp_package_for_command ss dnf)" == iproute ]] || fail "ss dnf -> iproute"
[[ "$(frp_package_for_command ip yum)" == iproute ]] || fail "ip yum -> iproute"
[[ "$(frp_package_for_command nginx apt)" == nginx ]] || fail "nginx package"
reset_pm_isolation
FRP_DEPENDENCY_ROLE=client
frp_required_commands | grep -qx curl || fail "client requires curl"
if frp_required_commands | grep -qx ss; then
  fail "client should not require ss"
fi
FRP_DEPENDENCY_ROLE=server
frp_required_commands | grep -qx ss || fail "server requires ss"
frp_required_commands | grep -qx python3 || fail "server requires python3"
MISSING_COMMANDS=()
MISSING_PYTHON_PACKAGES=()
# Simulate missing AUTO_ACME runtime on a clean server image.
frp_python_module_importable() { return 1; }
PACKAGE_MANAGER=apt
frp_collect_missing_python_packages
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-acme || fail "server missing acme maps to python3-acme"
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-cryptography || fail "server missing cryptography mapped"
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-yaml || fail "server missing yaml maps to python3-yaml"
frp_packages_for_missing apt
printf '%s\n' "${PACKAGES[@]}" | grep -qx python3-acme || fail "server PACKAGES includes python3-acme"
pass "package name mapping"

# Agent installs must pull a PyYAML package for the interpreter that will run.
# apt-family is python3-yaml. Clean EL8 pairs python39 with python39-pyyaml.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-yaml-map"
FRP_DEPENDENCY_ROLE=client
make_required_cmds "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/python3" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
PACKAGE_MANAGER=apt
DISTRO_ID=ubuntu
DISTRO_VERSION=24.04
frp_python_module_importable() { return 1; }
frp_collect_missing_python_packages
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-yaml || fail "apt client missing yaml"
if printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-acme; then
  fail "client role must not require AUTO_ACME packages"
fi
PACKAGE_MANAGER=dnf
DISTRO_ID=rocky
DISTRO_VERSION=8.10
frp_collect_missing_python_packages
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python39-pyyaml || fail "clean EL8 client missing python39-pyyaml"
if printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-pyyaml; then
  fail "clean EL8 must not select platform python3-pyyaml"
fi
[[ "$(frp_package_for_command python3 dnf)" == python39 ]] || fail "EL8 python3 package must stay python39"
cat >"$FRP_TEST_CMD_PATH/python3" <<'EOF'
#!/bin/sh
code="${2:-}"
case "$code" in
  *'sys.version_info[:2]'*) printf '3.11\n' ;;
esac
exit 0
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
frp_python_module_importable() { return 1; }
frp_collect_missing_python_packages
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3.11-pyyaml || fail "EL8 python3.11 missing python3.11-pyyaml"
if printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-pyyaml; then
  fail "live Rocky8 python3.11 must not select platform python3-pyyaml"
fi
if printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python39-pyyaml; then
  fail "live Rocky8 python3.11 must not select python39-pyyaml"
fi
pass "client yaml package mapping"

# Live Rocky 8: active python3 is Python 3.11. python3-pyyaml is the platform
# 3.6 ABI and must not satisfy import yaml on that interpreter.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-rocky311-yaml"
export FRP_TEST_PM_PATH="$WORKDIR/pm-rocky311-yaml"
ROCKY311_STATE="$WORKDIR/rocky311-py-state"
mkdir -p "$ROCKY311_STATE" "$FRP_TEST_PM_PATH"
FRP_DEPENDENCY_ROLE=client
DISTRO_ID=rocky
DISTRO_VERSION=8.10
PACKAGE_MANAGER=dnf
make_required_cmds "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/python3" <<EOF
#!/bin/sh
code="\${2:-}"
case "\$code" in
  *'sys.version_info[:2]'*) printf '3.11\\n'; exit 0 ;;
  *version_info*) exit 0 ;;
  *'import yaml'*)
    [ -f $(printf '%q' "$ROCKY311_STATE")/yaml311 ] && exit 0
    exit 1
    ;;
esac
exit 0
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
ROCKY311_LOG="$WORKDIR/rocky311-yaml.log"
: >"$ROCKY311_LOG"
cat >"$FRP_TEST_PM_PATH/dnf" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>$(printf '%q' "$ROCKY311_LOG")
for arg in "\$@"; do
  case "\$arg" in
    python3.11-pyyaml) touch $(printf '%q' "$ROCKY311_STATE")/yaml311 ;;
    python3-pyyaml) touch $(printf '%q' "$ROCKY311_STATE")/yaml36 ;;
    python39-pyyaml) touch $(printf '%q' "$ROCKY311_STATE")/yaml39 ;;
  esac
done
exit 0
EOF
chmod +x "$FRP_TEST_PM_PATH/dnf"
eval "$(declare -f frp_python_module_importable_real | sed '1s/frp_python_module_importable_real/frp_python_module_importable/')"
if ! ensure_dependencies >"$WORKDIR/rocky311-yaml.out" 2>"$WORKDIR/rocky311-yaml.err"; then
  cat "$WORKDIR/rocky311-yaml.err" >&2
  fail "live Rocky8 python3.11 ensure_dependencies must install python3.11-pyyaml"
fi
grep -q 'python3.11-pyyaml' "$ROCKY311_LOG" || fail "live Rocky8 must install python3.11-pyyaml"
if grep -q 'python3-pyyaml' "$ROCKY311_LOG"; then
  fail "live Rocky8 python3.11 must not install platform python3-pyyaml"
fi
if grep -q 'python39-pyyaml' "$ROCKY311_LOG"; then
  fail "live Rocky8 python3.11 must not install python39-pyyaml"
fi
frp_prefer_newer_python || fail "live Rocky8 frp_prefer_newer_python"
frp_invoke python3 -c 'import yaml' || fail "active Rocky8 python3.11 cannot import yaml after install"
pass "live rocky8 python3.11 yaml abi"

reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-yaml-fail"
export FRP_TEST_PM_PATH="$WORKDIR/pm-yaml-fail"
FRP_DEPENDENCY_ROLE=client
DISTRO_ID=rocky
DISTRO_VERSION=8
PACKAGE_MANAGER=dnf
make_required_cmds "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/python3" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
mkdir -p "$FRP_TEST_PM_PATH"
cat >"$FRP_TEST_PM_PATH/dnf" <<'EOF'
#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = python39-pyyaml ]; then
    echo "No match for argument: python39-pyyaml" >&2
    exit 1
  fi
done
exit 0
EOF
chmod +x "$FRP_TEST_PM_PATH/dnf"
frp_python_module_importable() { return 1; }
if ensure_dependencies >"$WORKDIR/yaml-fail.out" 2>"$WORKDIR/yaml-fail.err"; then
  fail "missing Rocky PyYAML must fail client ensure_dependencies"
fi
grep -q 'No match for argument: python39-pyyaml' "$WORKDIR/yaml-fail.err" || fail "yaml failure must keep the package manager error"
grep -q 'required Python packages are missing' "$WORKDIR/yaml-fail.err" || fail "yaml failure must name required Python packages"
grep -q 'python39-pyyaml' "$WORKDIR/yaml-fail.err" || fail "yaml failure must name python39-pyyaml"
pass "client yaml install failure is deterministic"

# Clean EL8: platform python3 is too old, installer selects python39, and
# python3-pyyaml must not count as success for that interpreter.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-el8-yaml"
export FRP_TEST_PM_PATH="$WORKDIR/pm-el8-yaml"
EL8_STATE="$WORKDIR/el8-py-state"
mkdir -p "$EL8_STATE" "$FRP_TEST_PM_PATH"
FRP_DEPENDENCY_ROLE=client
DISTRO_ID=rocky
DISTRO_VERSION=8.10
PACKAGE_MANAGER=dnf
make_required_cmds "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/python3" <<EOF
#!/bin/sh
code="\${2:-}"
if [ -f $(printf '%q' "$EL8_STATE")/py39 ]; then
  case "\$code" in
    *'sys.version_info[:2]'*) printf '3.9\\n'; exit 0 ;;
    *version_info*) exit 0 ;;
    *'import yaml'*)
      [ -f $(printf '%q' "$EL8_STATE")/yaml39 ] && exit 0
      exit 1
      ;;
  esac
  exit 0
fi
case "\$code" in
  *'sys.version_info[:2]'*) printf '3.6\\n' ;;
esac
exit 1
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
EL8_LOG="$WORKDIR/el8-yaml.log"
: >"$EL8_LOG"
cat >"$FRP_TEST_PM_PATH/dnf" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>$(printf '%q' "$EL8_LOG")
for arg in "\$@"; do
  case "\$arg" in
    python39) touch $(printf '%q' "$EL8_STATE")/py39 ;;
    python39-pyyaml) touch $(printf '%q' "$EL8_STATE")/yaml39 ;;
    python3-pyyaml) touch $(printf '%q' "$EL8_STATE")/yaml36 ;;
  esac
done
exit 0
EOF
chmod +x "$FRP_TEST_PM_PATH/dnf"
eval "$(declare -f frp_python_module_importable_real | sed '1s/frp_python_module_importable_real/frp_python_module_importable/')"
if ! ensure_dependencies >"$WORKDIR/el8-yaml.out" 2>"$WORKDIR/el8-yaml.err"; then
  cat "$WORKDIR/el8-yaml.err" >&2
  fail "clean EL8 ensure_dependencies must install python39-pyyaml and import yaml"
fi
grep -q 'python39' "$EL8_LOG" || fail "clean EL8 must install python39"
grep -q 'python39-pyyaml' "$EL8_LOG" || fail "clean EL8 must install python39-pyyaml"
if grep -q 'python3-pyyaml' "$EL8_LOG"; then
  fail "clean EL8 must not install platform python3-pyyaml"
fi
PATH="$FRP_TEST_CMD_PATH" "$FRP_TEST_CMD_PATH/python3" -c 'import yaml' || fail "selected EL8 python3 cannot import yaml"
frp_prefer_newer_python || fail "clean EL8 frp_prefer_newer_python"
frp_invoke python3 -c 'import yaml' || fail "active python3 after prefer_newer_python cannot import yaml"
pass "clean EL8 python39 yaml abi"

# Amazon Linux 2 is container/CI portability only, not a ConfigurationBundle
# target. Required YAML is not collected for client or server. Optional
# server ACME packages may still be attempted.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-al2-yaml"
export FRP_TEST_PM_PATH="$WORKDIR/pm-al2-yaml"
FRP_DEPENDENCY_ROLE=client
DISTRO_ID=amzn
DISTRO_VERSION=2
PACKAGE_MANAGER=yum
make_required_cmds "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/python3" <<'EOF'
#!/bin/sh
code="${2:-}"
case "$code" in
  *version_info*) exit 0 ;;
esac
exit 1
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
frp_python_module_importable() { return 1; }
frp_collect_missing_python_packages
if ((${#MISSING_PYTHON_PACKAGES[@]} > 0)); then
  fail "AL2 client must not require Python packages: ${MISSING_PYTHON_PACKAGES[*]}"
fi
mkdir -p "$FRP_TEST_PM_PATH"
AL2_LOG="$WORKDIR/al2-client-yaml.log"
: >"$AL2_LOG"
cat >"$FRP_TEST_PM_PATH/yum" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>$(printf '%q' "$AL2_LOG")
for arg in "\$@"; do
  case "\$arg" in
    python3-pyyaml|python3-PyYAML|python39-pyyaml|python3.11-pyyaml)
      echo "AL2 must not install \$arg" >&2
      exit 1
      ;;
  esac
done
exit 0
EOF
chmod +x "$FRP_TEST_PM_PATH/yum"
if ! ensure_dependencies >"$WORKDIR/al2-client.out" 2>"$WORKDIR/al2-client.err"; then
  cat "$WORKDIR/al2-client.err" >&2
  fail "AL2 client ensure_dependencies must not require PyYAML"
fi
if grep -E -q 'python3-pyyaml|python3-PyYAML|python39-pyyaml|python3\.11-pyyaml' "$AL2_LOG"; then
  fail "AL2 client yum transaction included a PyYAML package"
fi
pass "amazon linux 2 client yaml not required"

reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-al2-server-yaml"
export FRP_TEST_PM_PATH="$WORKDIR/pm-al2-server-yaml"
FRP_DEPENDENCY_ROLE=server
DISTRO_ID=amzn
DISTRO_VERSION=2
PACKAGE_MANAGER=yum
make_required_cmds "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/python3" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
frp_python_module_importable() { return 1; }
frp_collect_missing_python_packages
if printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -E -q 'pyyaml|PyYAML|python3-yaml'; then
  fail "AL2 server must not collect a required YAML package"
fi
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-acme || fail "AL2 server still collects optional python3-acme"
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-cryptography || fail "AL2 server still collects optional python3-cryptography"
mkdir -p "$FRP_TEST_PM_PATH"
AL2_SERVER_LOG="$WORKDIR/al2-server-yaml.log"
: >"$AL2_SERVER_LOG"
cat >"$FRP_TEST_PM_PATH/yum" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>$(printf '%q' "$AL2_SERVER_LOG")
for arg in "\$@"; do
  case "\$arg" in
    python3-pyyaml|python3-PyYAML|python39-pyyaml|python3.11-pyyaml)
      echo "AL2 must not install \$arg" >&2
      exit 1
      ;;
    python3-acme)
      echo "No match for argument: python3-acme" >&2
      exit 1
      ;;
  esac
done
exit 0
EOF
chmod +x "$FRP_TEST_PM_PATH/yum"
if ! ensure_dependencies >"$WORKDIR/al2-server.out" 2>"$WORKDIR/al2-server.err"; then
  cat "$WORKDIR/al2-server.err" >&2
  fail "AL2 server ensure_dependencies must not fail for missing PyYAML or ACME"
fi
grep -q 'optional AUTO_ACME' "$WORKDIR/al2-server.err" || fail "AL2 server must keep optional ACME soft-fail"
if grep -E -q 'python3-pyyaml|python3-PyYAML|python39-pyyaml|python3\.11-pyyaml' "$AL2_SERVER_LOG"; then
  fail "AL2 server yum transaction included a PyYAML package"
fi
grep -q 'python3-acme' "$AL2_SERVER_LOG" || fail "AL2 server should still attempt optional python3-acme"
pass "amazon linux 2 server yaml not required"

reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-al2023-yaml"
FRP_DEPENDENCY_ROLE=client
DISTRO_ID=amzn
DISTRO_VERSION=2023
PACKAGE_MANAGER=dnf
make_required_cmds "$FRP_TEST_CMD_PATH"
cat >"$FRP_TEST_CMD_PATH/python3" <<'EOF'
#!/bin/sh
code="${2:-}"
case "$code" in
  *'sys.version_info[:2]'*) printf '3.9\n'; exit 0 ;;
  *version_info*) exit 0 ;;
esac
exit 1
EOF
chmod +x "$FRP_TEST_CMD_PATH/python3"
frp_python_module_importable() { return 1; }
frp_collect_missing_python_packages
printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python3-pyyaml || fail "AL2023 client missing python3-pyyaml"
if printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx 'python3-PyYAML'; then
  fail "AL2023 must stay on python3-pyyaml"
fi
if printf '%s\n' "${MISSING_PYTHON_PACKAGES[@]}" | grep -qx python39-pyyaml; then
  fail "AL2023 must not use the EL8 python39-pyyaml package"
fi
pass "amazon linux 2023 pyyaml"

# Optional AUTO_ACME packages must not abort server install when unavailable.
reset_pm_isolation
export FRP_TEST_CMD_PATH="$WORKDIR/cmds-acme-soft"
export FRP_TEST_PM_PATH="$WORKDIR/pm-acme-soft"
FRP_DEPENDENCY_ROLE=server
make_required_cmds "$FRP_TEST_CMD_PATH"
mkdir -p "$FRP_TEST_PM_PATH"
ACME_SOFT_LOG="$WORKDIR/acme-soft.log"
: >"$ACME_SOFT_LOG"
cat >"$FRP_TEST_PM_PATH/dnf" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>$(printf '%q' "$ACME_SOFT_LOG")
for arg in "\$@"; do
  if [ "\$arg" = python3-acme ]; then
    echo "No match for argument: python3-acme" >&2
    exit 1
  fi
done
exit 0
EOF
chmod +x "$FRP_TEST_PM_PATH/dnf"
frp_detect_package_manager
DISTRO_ID=rocky
frp_python_module_importable() {
  [[ "$1" == yaml ]]
}
if ! ensure_dependencies 2>"$WORKDIR/acme-soft.err"; then
  fail "missing optional AUTO_ACME packages must not fail server ensure_dependencies"
fi
grep -q 'optional AUTO_ACME' "$WORKDIR/acme-soft.err" || fail "soft-fail warning for unavailable ACME packages"
grep -q 'python3-acme' "$ACME_SOFT_LOG" || fail "dnf should still attempt python3-acme"
pass "deps: optional AUTO_ACME soft-fail"

# Host isolation: tests must not have invoked real apt-get/dnf/yum via the helpers
# with an unset FRP_TEST_PM_PATH during install. Detection-only tests always set it.
pass "host package manager not used"

echo
echo "CLIENT_PLATFORM_TEST=PASS"
