#!/usr/bin/env bash
# Run inside a distro container. Installs mapped packages with the project's
# helpers, then runs a systemd-free portability subset.
# This is NOT a systemd smoke test.
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
export DEBIAN_FRONTEND=noninteractive

SRC="${FRP_PORTABILITY_SRC:-/src}"
if [[ ! -f "$SRC/lib/frp-common.sh" ]]; then
  echo "ERROR: expected $SRC/lib/frp-common.sh (mount the repository at /src)" >&2
  exit 1
fi
cp -a "$SRC" /tmp/frp-src
ROOT=/tmp/frp-src
cd "$ROOT"
chmod +x tests/*.sh scripts/*.sh tools/* install-*.sh uninstall-*.sh 2>/dev/null || true

# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

frp_require_bash || exit 1
frp_detect_architecture || exit 1
frp_detect_platform
frp_detect_package_manager
frp_print_detected_linux
echo

echo "CONTAINER_DISTRO_ID=${DISTRO_ID}"
echo "CONTAINER_DISTRO_NAME=${DISTRO_NAME}"
echo "CONTAINER_DISTRO_VERSION=${DISTRO_VERSION}"
echo "CONTAINER_PACKAGE_MANAGER=${PACKAGE_MANAGER:-none}"
echo "CONTAINER_ARCH=${FRP_ARCH}"
echo "CONTAINER_BASH=${BASH_VERSION}"

if [[ -z "${PACKAGE_MANAGER:-}" ]]; then
  echo "ERROR: no apt/dnf/yum in this image" >&2
  exit 1
fi

FRP_DEPENDENCY_ROLE=server
ensure_dependencies
frp_prefer_newer_python || true
frp_require_python
echo "CONTAINER_PYTHON=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
if command -v openssl >/dev/null 2>&1; then
  echo "CONTAINER_OPENSSL=$(openssl version 2>/dev/null | tr '\n' ' ')"
else
  echo "CONTAINER_OPENSSL=missing"
fi
echo "DEPENDENCY_INSTALL=PASS"

if frp_command_exists systemctl && frp_systemd_usable; then
  echo "CONTAINER_SYSTEMD_USABLE=yes"
else
  echo "CONTAINER_SYSTEMD_USABLE=no"
fi
echo "CONTAINER_SYSTEMD_VERSION=$(frp_systemd_version || true)"
echo "Note: container systemd usability is not a host smoke test."

echo
echo "Running portable tests..."
export PYTHONDONTWRITEBYTECODE=1
python3 -m py_compile \
  server/frp-port-allocator.py \
  server/migrate_token.py \
  lib/frp_mgmt_auth.py \
  lib/frp_pki.py \
  lib/frp_doctor.py \
  scripts/build-bundles.py
while IFS= read -r -d '' f; do
  bash -n "$f"
done < <(find . -name '*.sh' -not -path './.git/*' -print0)
bash -n tools/frp-server-status tools/frp-update tools/frp-client tools/frpctl

./tests/test-portability.sh
./tests/test-client-platform.sh
./tests/test-server-install-config.sh
./tests/test-client-allocator-url.sh
./tests/test-create-client.sh
./tests/test-zero-touch-bootstrap.sh
./tests/test-client-upgrade.sh
./tests/test-install-lifecycle.sh
./tests/test-frpctl.sh
./tests/test-frpctl-completion.sh
./tests/test-frpctl-doctor.sh
python3 tests/test-allocator.py
python3 tests/test-bootstrap-ticket.py
python3 tests/test-mgmt-identity.py
python3 tests/test-enrollment-security.py
python3 tests/test-pki-https.py
./tests/test-port-architecture.sh
./tests/test-ca-bootstrap.sh
./tests/test-allocator-process-cleanup.sh
./tests/test-lifecycle.sh
./tests/test-release-docs.sh

echo
echo "CONTAINER_PORTABILITY=PASS"
echo "SYSTEMD_SMOKE=NOT_TESTED"
echo "REAL_ARM_SYSTEMD_SMOKE=NOT_TESTED"
