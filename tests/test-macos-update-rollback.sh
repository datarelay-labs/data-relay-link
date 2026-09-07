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

while IFS=: read -r rel mode src; do
  live="$(frp_client_path "/$rel")"
  mkdir -p "$(dirname "$live")"
  printf 'original:%s\n' "$rel" >"$live"
  chmod "$mode" "$live"
done < <(frp_client_upgrade_destinations)
version="$(frp_client_version_file)"
mkdir -p "$(dirname "$version")"
printf 'PROJECT_VERSION=2.2.1\nFRP_VERSION=0.71.0\n' >"$version"

backup="$(frp_client_upgrade_backup_tools "$ROOT")"
while IFS=: read -r rel mode src; do
  printf 'mutated\n' >"$(frp_client_path "/$rel")"
done < <(frp_client_upgrade_destinations)
printf 'mutated\n' >"$version"

frp_client_upgrade_restore_tools "$backup"
frp_client_upgrade_verify_restored "$backup"
grep -q '^original:' "$(frp_client_path /usr/local/bin/frpctl)"
grep -q '^PROJECT_VERSION=2.2.1' "$version"
echo "MACOS_UPDATE_ROLLBACK_TEST=PASS"
