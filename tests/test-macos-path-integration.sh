#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export FRP_TEST_UNAME_S=Darwin
export FRP_MACOS_STATE_ROOT="$TMP/state"
export FRP_MACOS_PREFIX="$TMP/prefix"
export FRP_CLIENT_TEST_ROOT="$TMP/root"
. "$ROOT/lib/frp-client-common.sh"

[[ "$(frp_client_state_path)" == "$TMP/root$TMP/state/client-state.json" ]]
[[ "$(frp_client_path /usr/local/bin/frpc)" == "$TMP/root$TMP/state/bin/frpc" ]]
[[ "$(frp_client_path /usr/local/bin/frpctl)" == "$TMP/root$TMP/prefix/bin/frpctl" ]]
[[ "$(frp_txn_marker_path client)" == "$TMP/root$TMP/state/state/client-update-pending.json" ]]
[[ "$(frp_txn_marker_path server)" == "$TMP/root$TMP/state/state/server-update-pending.json" ]]

FRP_TEST_UNAME_S=Linux
[[ "$(frp_platform_map_path /etc/frp/frpc.toml)" == /etc/frp/frpc.toml ]]
echo "MACOS_PATH_INTEGRATION_TEST=PASS"
