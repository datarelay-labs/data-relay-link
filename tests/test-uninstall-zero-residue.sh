#!/usr/bin/env bash
# Complete uninstall must leave zero product-owned local residue, including
# empty directory trees. Default uninstall equals --purge --yes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

assert_absent() {
  local path="$1" label="$2"
  if [[ -e "$path" || -L "$path" ]]; then
    fail "$label still present: $path"
  fi
}

assert_server_zero_residue() {
  local tree="$1" label="$2"
  local p
  for p in \
    /usr/local/bin/drlink \
    /usr/local/bin/frps \
    /usr/local/bin/frpctl \
    /usr/local/sbin/frpctl \
    /usr/local/lib/drlink \
    /etc/frp \
    /etc/drlink \
    /var/lib/drlink \
    /var/log/drlink \
    /etc/systemd/system/drlink-server.service \
    /etc/systemd/system/drlink-allocator.service \
    /etc/systemd/system/drlink-access.service \
    /etc/systemd/system/drlink-egress.service \
    /etc/systemd/system/drlink-tcp-egress.service \
    /etc/systemd/system/drlink-mcp-bridge.service \
    /etc/systemd/system/drlink-frontend.service \
    /etc/systemd/system/frp-port-allocator.service \
    /etc/systemd/system/frp-access-plugin.service \
    /etc/systemd/system/frp-egress-gateway.service \
    /etc/systemd/system/frp-frontend.service
  do
    assert_absent "${tree}${p}" "$label $p"
  done
  # Empty nested trees must not survive; checking files alone is insufficient.
  if [[ -d "${tree}/usr/local/lib/drlink" ]]; then
    fail "$label leftover library directory"
  fi
}

assert_client_zero_residue() {
  local tree="$1" label="$2"
  local p
  for p in \
    /usr/local/bin/drlink \
    /usr/bin/drlink \
    /usr/local/bin/frpc \
    /usr/local/bin/frp-client \
    /usr/local/bin/frpctl \
    /usr/local/lib/drlink \
    /etc/frp \
    /etc/drlink \
    /var/lib/drlink \
    /etc/systemd/system/drlink-client.service \
    /etc/systemd/system/frpc.service
  do
    assert_absent "${tree}${p}" "$label $p"
  done
}

seed_server() {
  local tree="$1"
  mkdir -p \
    "$tree/etc/drlink/pki" \
    "$tree/etc/frp" \
    "$tree/var/lib/drlink/enrollments" \
    "$tree/var/lib/drlink/bootstrap" \
    "$tree/var/lib/drlink/backups" \
    "$tree/var/log/drlink/egress" \
    "$tree/usr/local/bin" \
    "$tree/usr/local/sbin" \
    "$tree/usr/local/lib/drlink/data/egress-recipes" \
    "$tree/etc/systemd/system"
  printf '{"deployment_mode":"direct"}\n' >"$tree/etc/drlink/config.json"
  printf 'token-secret\n' >"$tree/etc/frp/server_token"
  printf 'bindPort = 443\n' >"$tree/etc/frp/frps.toml"
  printf '{"schema_version":2,"clients":{},"reserved":[6001]}\n' \
    >"$tree/var/lib/drlink/registry.json"
  printf '{}\n' >"$tree/var/lib/drlink/access-control.json"
  printf '{}\n' >"$tree/var/lib/drlink/egress-control.json"
  printf '{}\n' >"$tree/var/lib/drlink/service-profiles.json"
  printf 'ca-key\n' >"$tree/etc/drlink/pki/ca.key"
  printf 'ca-crt\n' >"$tree/etc/drlink/pki/ca.crt"
  printf 'PROJECT_VERSION=2.4.0\n' >"$tree/etc/drlink/version"
  printf '{}\n' >"$tree/usr/local/lib/drlink/data/egress-recipes/https-api.json"
  printf 'suffix\n' >"$tree/usr/local/lib/drlink/data/public_suffix_list.dat"
  printf '#!/bin/true\n' >"$tree/usr/local/bin/frps"
  printf '#!/bin/true\n' >"$tree/usr/local/bin/drlink"
  printf '#!/bin/true\n' >"$tree/usr/local/sbin/frpctl"
  printf '#!/bin/true\n' >"$tree/usr/local/bin/frpctl"
  chmod +x "$tree/usr/local/bin/frps" "$tree/usr/local/bin/drlink" \
    "$tree/usr/local/sbin/frpctl" "$tree/usr/local/bin/frpctl"
  cp "$ROOT/lib/frp_project_files.py" "$tree/usr/local/lib/drlink/"
  cp "$ROOT/lib/server-project-files.manifest" "$tree/usr/local/lib/drlink/"
  cp "$ROOT/lib/frp-role-ownership.sh" "$tree/usr/local/lib/drlink/"
  for unit in drlink-server drlink-allocator drlink-access drlink-egress \
    drlink-tcp-egress drlink-frontend; do
    printf '[Unit]\nDescription=%s\n' "$unit" >"$tree/etc/systemd/system/${unit}.service"
  done
}

seed_client() {
  local tree="$1"
  mkdir -p \
    "$tree/etc/frp/backups" \
    "$tree/etc/drlink" \
    "$tree/var/lib/drlink/client-upgrades/x" \
    "$tree/usr/local/bin" \
    "$tree/usr/bin" \
    "$tree/usr/local/sbin" \
    "$tree/usr/local/lib/drlink/data/empty-nested" \
    "$tree/etc/systemd/system"
  printf '{"schema_version":1,"machine_id":"aabbccddeeff00112233445566778899"}\n' \
    >"$tree/etc/frp/client-state.json"
  printf 'serverAddr = "203.0.113.10"\n' >"$tree/etc/frp/frpc.toml"
  printf 'key\n' >"$tree/etc/frp/client-identity.key"
  printf 'pub\n' >"$tree/etc/frp/client-identity.pub"
  printf 'mac\n' >"$tree/etc/frp/client-identity.mac"
  printf '{}\n' >"$tree/etc/frp/apply-pending.json"
  printf '{}\n' >"$tree/etc/frp/enroll-pending.json"
  printf 'ca\n' >"$tree/etc/drlink/allocator-ca.crt"
  printf 'PROJECT_VERSION=2.4.0\n' >"$tree/etc/drlink/version"
  printf 'draft\n' >"$tree/var/lib/drlink/client-draft.json"
  printf '{}\n' >"$tree/var/lib/drlink/client-update-pending.json"
  printf 'log\n' >"$tree/var/lib/drlink/update-actions.log"
  printf '#!/bin/true\n' >"$tree/usr/local/bin/frpc"
  printf '#!/bin/true\n' >"$tree/usr/local/bin/frp-client"
  printf '#!/bin/true\n' >"$tree/usr/local/sbin/frp-client"
  printf '#!/bin/true\n' >"$tree/usr/local/bin/drlink"
  printf '#!/bin/true\n' >"$tree/usr/bin/drlink"
  printf '#!/bin/true\n' >"$tree/usr/local/bin/frpctl"
  chmod +x "$tree/usr/local/bin/frpc" "$tree/usr/local/bin/frp-client" \
    "$tree/usr/local/sbin/frp-client" "$tree/usr/local/bin/drlink" \
    "$tree/usr/bin/drlink" "$tree/usr/local/bin/frpctl"
  echo 'common' >"$tree/usr/local/lib/drlink/frp-client-common.sh"
  echo 'shared' >"$tree/usr/local/lib/drlink/frp_doctor.py"
  cp "$ROOT/lib/frp-role-ownership.sh" "$tree/usr/local/lib/drlink/"
  cat >"$tree/etc/systemd/system/drlink-client.service" <<'EOF'
[Unit]
Description=Data Relay Link Client
[Service]
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
EOF
  cat >"$tree/etc/systemd/system/frpc.service" <<'EOF'
[Unit]
Description=Data Relay Link Client (legacy unit name; use drlink-client)
[Service]
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
EOF
}

export FRP_CLIENT_SOURCED=1
export FRP_SKIP_SYSTEMD=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"

# ---------------------------------------------------------------------------
# Dedicated server: default uninstall removes empty recipe dirs
# ---------------------------------------------------------------------------
TREE="$WORKDIR/server-default"
seed_server "$TREE"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/s-def.out" 2>"$WORKDIR/s-def.err"; then
  cat "$WORKDIR/s-def.out" "$WORKDIR/s-def.err" >&2
  fail "default server uninstall"
fi
assert_server_zero_residue "$TREE" "default server"
assert_absent "$TREE/usr/local/lib/drlink/data/egress-recipes" "empty egress-recipes"
pass "SERVER_UNINSTALL_ZERO_RESIDUE"

if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/s-def2.out" 2>"$WORKDIR/s-def2.err"; then
  fail "second server uninstall: $(cat "$WORKDIR/s-def2.err")"
fi
assert_server_zero_residue "$TREE" "second server"
pass "UNINSTALL_IDEMPOTENT"

# Compatibility alias
TREE="$WORKDIR/server-purge"
seed_server "$TREE"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
if ! "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/s-purge.out" 2>"$WORKDIR/s-purge.err"; then
  fail "purge alias: $(cat "$WORKDIR/s-purge.err")"
fi
assert_server_zero_residue "$TREE" "purge alias"
pass "LEGACY_PURGE_COMPATIBILITY"

# Empty leftover tree only (the Manual E2E residue shape)
TREE="$WORKDIR/empty-libdir"
mkdir -p "$TREE/usr/local/lib/drlink/data/egress-recipes"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
if ! "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/s-empty.out" 2>"$WORKDIR/s-empty.err"; then
  fail "empty-libdir uninstall: $(cat "$WORKDIR/s-empty.err")"
fi
assert_absent "$TREE/usr/local/lib/drlink" "empty leftover library tree"
assert_absent "$TREE/var/lib/drlink" "empty leftover var/lib"
pass "SERVER_EMPTY_DIRECTORY_RESIDUE_FIXED"

# ---------------------------------------------------------------------------
# Dedicated client
# ---------------------------------------------------------------------------
TREE="$WORKDIR/client"
seed_client "$TREE"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_CLIENT_TEST_ROOT="$TREE"
if ! "$ROOT/uninstall-client.sh" >"$WORKDIR/c.out" 2>"$WORKDIR/c.err"; then
  fail "client uninstall: $(cat "$WORKDIR/c.err")"
fi
assert_client_zero_residue "$TREE" "client"
[[ "$(frp_client_install_class)" == "none" ]] || fail "post-uninstall class=$(frp_client_install_class)"
pass "CLIENT_UNINSTALL_ZERO_RESIDUE"
pass "POST_UNINSTALL_CLASSIFICATION"

if ! "$ROOT/uninstall-client.sh" >"$WORKDIR/c2.out" 2>"$WORKDIR/c2.err"; then
  fail "second client uninstall: $(cat "$WORKDIR/c2.err")"
fi
assert_client_zero_residue "$TREE" "second client"
[[ "$(frp_client_install_class)" == "none" ]] || fail "second uninstall class=$(frp_client_install_class)"

# ---------------------------------------------------------------------------
# Dual-role: server-only removal
# ---------------------------------------------------------------------------
TREE="$WORKDIR/dual-server"
seed_server "$TREE"
seed_client "$TREE"
# seed_client overwrites shared binaries; restore client+server overlap
printf '#!/bin/true\n' >"$TREE/usr/local/bin/drlink"
chmod +x "$TREE/usr/local/bin/drlink"
echo 'shared' >"$TREE/usr/local/lib/drlink/frp_doctor.py"
echo 'client-only' >"$TREE/usr/local/lib/drlink/frp-client-common.sh"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/ds.out" 2>"$WORKDIR/ds.err"; then
  fail "dual-role server uninstall: $(cat "$WORKDIR/ds.err")"
fi
[[ -f "$TREE/etc/frp/client-state.json" ]] || fail "dual server-uninstall removed client state"
[[ -f "$TREE/etc/frp/client-identity.key" ]] || fail "dual server-uninstall removed identity"
[[ -x "$TREE/usr/local/bin/frpc" ]] || fail "dual server-uninstall removed frpc"
[[ -x "$TREE/usr/local/bin/drlink" ]] || fail "dual server-uninstall removed drlink"
[[ -f "$TREE/usr/local/lib/drlink/frp-client-common.sh" ]] || fail "dual server-uninstall removed client lib"
[[ -f "$TREE/usr/local/lib/drlink/frp_doctor.py" ]] || fail "dual server-uninstall removed shared lib"
[[ ! -f "$TREE/etc/frp/server_token" ]] || fail "dual server-uninstall left token"
[[ ! -f "$TREE/etc/drlink/config.json" ]] || fail "dual server-uninstall left config"
[[ ! -f "$TREE/var/lib/drlink/registry.json" ]] || fail "dual server-uninstall left registry"
[[ ! -e "$TREE/usr/local/lib/drlink/data/egress-recipes" ]] || fail "dual server-uninstall left empty recipes"
[[ ! -x "$TREE/usr/local/bin/frps" ]] || fail "dual server-uninstall left frps"
pass "DUAL_ROLE_SERVER_UNINSTALL"

# ---------------------------------------------------------------------------
# Dual-role: client-only removal
# ---------------------------------------------------------------------------
TREE="$WORKDIR/dual-client"
seed_server "$TREE"
seed_client "$TREE"
printf '#!/bin/true\n' >"$TREE/usr/local/bin/drlink"
chmod +x "$TREE/usr/local/bin/drlink"
echo 'shared' >"$TREE/usr/local/lib/drlink/frp_doctor.py"
echo 'client-only' >"$TREE/usr/local/lib/drlink/frp-client-common.sh"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
if ! "$ROOT/uninstall-client.sh" >"$WORKDIR/dc.out" 2>"$WORKDIR/dc.err"; then
  fail "dual-role client uninstall: $(cat "$WORKDIR/dc.err")"
fi
[[ -f "$TREE/etc/frp/server_token" ]] || fail "dual client-uninstall removed server token"
[[ -f "$TREE/etc/drlink/config.json" ]] || fail "dual client-uninstall removed server config"
[[ -f "$TREE/var/lib/drlink/registry.json" ]] || fail "dual client-uninstall removed registry"
[[ -x "$TREE/usr/local/bin/drlink" ]] || fail "dual client-uninstall removed shared drlink"
[[ -f "$TREE/usr/local/lib/drlink/frp_doctor.py" ]] || fail "dual client-uninstall removed shared lib"
[[ ! -f "$TREE/etc/frp/client-state.json" ]] || fail "dual client-uninstall left client state"
[[ ! -f "$TREE/etc/frp/enroll-pending.json" ]] || fail "dual client-uninstall left enroll-pending"
[[ ! -f "$TREE/usr/local/lib/drlink/frp-client-common.sh" ]] || fail "dual client-uninstall left client-only lib"
[[ ! -x "$TREE/usr/local/bin/frpc" ]] || fail "dual client-uninstall left frpc"
pass "DUAL_ROLE_CLIENT_UNINSTALL"
pass "DUAL_ROLE_SHARED_OWNERSHIP"

# ---------------------------------------------------------------------------
# macOS dedicated client zero-residue
# ---------------------------------------------------------------------------
TREE="$WORKDIR/macos"
export FRP_TEST_UNAME_S=Darwin
export FRP_MACOS_STATE_ROOT='/Library/Application Support/drlink'
export FRP_MACOS_PREFIX='/opt/homebrew'
STATE="$TREE/Library/Application Support/drlink"
mkdir -p \
  "$STATE/bin" \
  "$STATE/lib" \
  "$STATE/state/client-upgrades" \
  "$STATE/logs" \
  "$TREE/opt/homebrew/bin" \
  "$TREE/Library/LaunchDaemons"
printf '{"schema_version":1,"machine_id":"macidmacidmacidmacidmacidmacid"}\n' \
  >"$STATE/client-state.json"
printf 'serverAddr = "203.0.113.10"\n' >"$STATE/frpc.toml"
printf 'key\n' >"$STATE/client-identity.key"
printf 'pub\n' >"$STATE/client-identity.pub"
printf 'mac\n' >"$STATE/client-identity.mac"
printf '{}\n' >"$STATE/enroll-pending.json"
printf 'ca\n' >"$STATE/allocator-ca.crt"
printf 'draft\n' >"$STATE/state/client-draft.json"
printf '#!/bin/true\n' >"$STATE/bin/frpc"
printf '#!/bin/true\n' >"$TREE/opt/homebrew/bin/drlink"
printf '#!/bin/true\n' >"$TREE/opt/homebrew/bin/frp-client"
printf '#!/bin/true\n' >"$TREE/opt/homebrew/bin/frpctl"
chmod +x "$STATE/bin/frpc" "$TREE/opt/homebrew/bin/drlink" \
  "$TREE/opt/homebrew/bin/frp-client" "$TREE/opt/homebrew/bin/frpctl"
echo 'common' >"$STATE/lib/frp-client-common.sh"
echo 'plist' >"$TREE/Library/LaunchDaemons/com.datarelay.drlink.frpc.plist"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_CLIENT_TEST_ROOT="$TREE"
if ! "$ROOT/uninstall-client.sh" >"$WORKDIR/mac.out" 2>"$WORKDIR/mac.err"; then
  fail "macos uninstall: $(cat "$WORKDIR/mac.err")"
fi
assert_absent "$STATE" "macos Application Support payload"
assert_absent "$STATE/client-state.json" "macos client state"
assert_absent "$STATE/client-identity.key" "macos identity"
assert_absent "$TREE/Library/LaunchDaemons/com.datarelay.drlink.frpc.plist" "macos plist"
assert_absent "$TREE/opt/homebrew/bin/drlink" "macos drlink"
assert_absent "$TREE/opt/homebrew/bin/frp-client" "macos frp-client"
assert_absent "$TREE/opt/homebrew/bin/frpctl" "macos frpctl"
assert_absent "$STATE/bin/frpc" "macos frpc"
pass "MACOS_UNINSTALL"

unset FRP_TEST_UNAME_S FRP_MACOS_STATE_ROOT FRP_MACOS_PREFIX
unset FRP_UNINSTALL_TEST_ROOT FRP_CLIENT_TEST_ROOT

echo
echo "SERVER_UNINSTALL_ZERO_RESIDUE=PASS"
echo "CLIENT_UNINSTALL_ZERO_RESIDUE=PASS"
echo "UNINSTALL_ZERO_RESIDUE_TEST=PASS"
