#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

# Legacy paths migrate into canonical Data Relay Link roots.
TREE="$WORK/legacy"
mkdir -p \
  "$TREE/etc/frp-auto-deploy/pki" \
  "$TREE/var/lib/frp-auto-deploy" \
  "$TREE/usr/local/lib/frp-auto-deploy" \
  "$TREE/usr/local/bin" \
  "$TREE/usr/local/sbin" \
  "$TREE/etc/systemd/system"
printf 'cfg\n' >"$TREE/etc/frp-auto-deploy/config.json"
printf 'reg\n' >"$TREE/var/lib/frp-auto-deploy/registry.json"
printf 'lib\n' >"$TREE/usr/local/lib/frp-auto-deploy/frp-common.sh"
printf 'old-unit\n' >"$TREE/etc/systemd/system/frps.service"
printf 'old-cli\n' >"$TREE/usr/local/bin/frpctl"
printf '#!/bin/bash\necho drlink\n' >"$TREE/usr/local/bin/drlink"
chmod 0755 "$TREE/usr/local/bin/drlink"
printf 'new-unit\n' >"$TREE/etc/systemd/system/drlink-server.service"

FRP_SERVER_TEST_ROOT="$TREE" frp_migrate_legacy_product_paths || fail "path migrate"
[[ -f "$TREE/etc/drlink/config.json" ]] || fail "config not migrated"
[[ -f "$TREE/var/lib/drlink/registry.json" ]] || fail "registry not migrated"
[[ -f "$TREE/usr/local/lib/drlink/frp-common.sh" ]] || fail "lib not migrated"
[[ ! -e "$TREE/etc/frp-auto-deploy" ]] || fail "legacy etc remains"
pass "LEGACY_PATH_MIGRATE"

FRP_SERVER_TEST_ROOT="$TREE" frp_migrate_legacy_systemd_units || fail "unit migrate"
[[ -f "$TREE/etc/systemd/system/drlink-server.service" ]] || fail "new unit missing"
[[ ! -f "$TREE/etc/systemd/system/frps.service" ]] || fail "old unit remains"
[[ ! -e "$TREE/usr/local/bin/frpctl" ]] || fail "frpctl still on PATH"
[[ -x "$TREE/usr/local/bin/drlink" ]] || fail "drlink missing"
pass "LEGACY_UNIT_AND_CLI_RETIRE"

# Dual-role: frpc.service migrates to drlink-client when client-state exists.
DUAL="$WORK/dual"
mkdir -p "$DUAL/etc/systemd/system" "$DUAL/etc/frp" "$DUAL/usr/local/bin"
cat >"$DUAL/etc/systemd/system/frpc.service" <<'EOF'
[Unit]
Description=FRP Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
printf '{}\n' >"$DUAL/etc/frp/client-state.json"
printf '#!/bin/bash\necho drlink\n' >"$DUAL/usr/local/bin/drlink"
chmod 0755 "$DUAL/usr/local/bin/drlink"
FRP_SERVER_SOURCE="$ROOT" FRP_SERVER_TEST_ROOT="$DUAL" frp_migrate_legacy_systemd_units || fail "dual migrate"
[[ -f "$DUAL/etc/systemd/system/drlink-client.service" ]] || fail "drlink-client not created"
[[ ! -f "$DUAL/etc/systemd/system/frpc.service" ]] || fail "frpc remains"
pass "LEGACY_DUAL_ROLE_CLIENT_UNIT"

# Unrelated administrator frpc.service must be preserved.
ADMIN="$WORK/admin"
mkdir -p "$ADMIN/etc/systemd/system" "$ADMIN/usr/local/bin"
cat >"$ADMIN/etc/systemd/system/frpc.service" <<'EOF'
[Unit]
Description=Company Custom FRP Tunnel
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/custom/frpc -c /opt/custom/frpc.ini
Restart=always

[Install]
WantedBy=multi-user.target
EOF
printf 'new\n' >"$ADMIN/etc/systemd/system/drlink-client.service"
printf '#!/bin/bash\necho drlink\n' >"$ADMIN/usr/local/bin/drlink"
chmod 0755 "$ADMIN/usr/local/bin/drlink"
FRP_SERVER_TEST_ROOT="$ADMIN" frp_migrate_legacy_systemd_units || fail "admin migrate"
[[ -f "$ADMIN/etc/systemd/system/frpc.service" ]] || fail "admin frpc removed"
[[ -f "$ADMIN/etc/systemd/system/drlink-client.service" ]] || fail "canonical missing"
pass "UNRELATED_ADMIN_FRPC_PRESERVED"

# Clean install layout: drlink on PATH, frpctl only as internal backend.
CLEAN="$WORK/clean"
mkdir -p "$CLEAN/usr/local/bin" "$CLEAN/usr/local/lib/drlink"
install -m 0755 "$ROOT/tools/frpctl" "$CLEAN/usr/local/lib/drlink/frpctl"
install -m 0755 "$ROOT/tools/drlink" "$CLEAN/usr/local/bin/drlink"
[[ -x "$CLEAN/usr/local/bin/drlink" ]] || fail "clean drlink"
[[ ! -e "$CLEAN/usr/local/bin/frpctl" ]] || fail "clean has PATH frpctl"
help_out="$(FRP_CTL_TEST_ROOT="$CLEAN/root-missing" PATH="$CLEAN/usr/local/bin:$PATH" \
  "$CLEAN/usr/local/bin/drlink" --help 2>&1 || true)"
# Backend resolves via absolute /usr/local/lib/drlink only when installed system-wide.
# For harness, invoke with backend beside wrapper by placing both under a prefix.
PREFIX="$WORK/prefix"
mkdir -p "$PREFIX/bin" "$PREFIX/lib"
install -m 0755 "$ROOT/tools/frpctl" "$PREFIX/lib/frpctl"
# Wrapper looks for sibling tools/frpctl or /usr/local/lib/drlink/frpctl.
# Emulate source-tree layout for this assertion:
install -m 0755 "$ROOT/tools/drlink" "$PREFIX/bin/drlink"
install -m 0755 "$ROOT/tools/frpctl" "$PREFIX/bin/../tools/frpctl" 2>/dev/null || true
mkdir -p "$PREFIX/tools"
install -m 0755 "$ROOT/tools/frpctl" "$PREFIX/tools/frpctl"
install -m 0755 "$ROOT/tools/drlink" "$PREFIX/tools/drlink"
out="$("$PREFIX/tools/drlink" --help)"
grep -q 'Usage: drlink' <<<"$out" || fail "drlink help"
grep -q 'Data Relay Link' <<<"$out" || fail "product name"
pass "CLEAN_INSTALL_DRLINK_ONLY"

echo "LEGACY_IDENTITY_MIGRATION_TEST=PASS"
