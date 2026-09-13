#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 && -z "${FRP_UNINSTALL_TEST_ROOT:-}" && -z "${FRP_CLIENT_TEST_ROOT:-}" ]]; then
  echo 'Run as root' >&2
  exit 1
fi

_frp_u_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for _frp_u_macos in \
  "${_frp_u_here}/lib/frp-macos.sh" \
  "${_frp_u_here}/frp-macos.sh" \
  '/Library/Application Support/drlink/lib/frp-macos.sh'; do
  if [[ -f "$_frp_u_macos" ]]; then
    frp_is_darwin() { [[ "${FRP_TEST_UNAME_S:-$(uname -s)}" == Darwin ]]; }
    frp_command_exists() { command -v "$1" >/dev/null 2>&1; }
    frp_invoke() { local cmd="$1"; shift; command "$cmd" "$@"; }
    # shellcheck disable=SC1090
    . "$_frp_u_macos"
    break
  fi
done
unset _frp_u_macos

frp_u_is_darwin() {
  declare -F frp_is_darwin >/dev/null 2>&1 && frp_is_darwin
}

frp_u_path() {
  local p="$1"
  local root="${FRP_UNINSTALL_TEST_ROOT:-${FRP_CLIENT_TEST_ROOT:-}}"
  if frp_u_is_darwin && declare -F frp_macos_map_path >/dev/null 2>&1; then
    p="$(frp_macos_map_path "$p")"
  fi
  if [[ -n "$root" ]]; then
    printf '%s' "${root}${p}"
  else
    printf '%s' "$p"
  fi
}

frp_u_unsafe_path() {
  local path="${1:-}"
  if [[ -z "$path" || "$path" == "/" || "$path" == "." || "$path" == ".." || "$path" == "//" ]]; then
    return 0
  fi
  case "$path" in
    /*) ;;
    *) return 0 ;;
  esac
  return 1
}

frp_u_safe_rm_rf() {
  local path="${1:-}"
  if frp_u_unsafe_path "$path"; then
    echo "ERROR: refusing unsafe recursive deletion" >&2
    echo "FAILURE_CLASS=PATH_DELETION_REFUSED" >&2
    return 1
  fi
  if [[ -L "$path" ]]; then
    echo "ERROR: refusing to recursively delete through a symlink" >&2
    echo "FAILURE_CLASS=SYMLINK_REFUSED" >&2
    return 1
  fi
  if [[ ! -e "$path" ]]; then
    return 0
  fi
  if [[ ! -d "$path" ]]; then
    echo "ERROR: refusing recursive deletion of a non-directory" >&2
    echo "FAILURE_CLASS=PATH_DELETION_REFUSED" >&2
    return 1
  fi
  rm -rf "$path"
}

frp_u_rm_file() {
  local path="${1:-}"
  if frp_u_unsafe_path "$path"; then
    echo "ERROR: refusing unsafe file deletion" >&2
    echo "FAILURE_CLASS=PATH_DELETION_REFUSED" >&2
    return 1
  fi
  rm -f "$path"
}

frp_u_pid_executable() {
  local pid="$1"
  if [[ -e "/proc/${pid}/exe" ]]; then
    readlink -f "/proc/${pid}/exe" 2>/dev/null || true
    return 0
  fi
  ps -p "$pid" -ww -o command= 2>/dev/null | awk '{print $1}'
}

frp_u_stop_owned_frpc() {
  local canonical pid exe still
  canonical="$(frp_u_path /usr/local/bin/frpc)"
  [[ -n "$canonical" ]] || return 0
  still=0
  if [[ -d /proc ]]; then
    for pid in /proc/[0-9]*; do
      pid="${pid#/proc/}"
      [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
      exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
      if [[ "$exe" == "$canonical" || "$exe" == "${canonical} (deleted)" ]]; then
        kill "$pid" 2>/dev/null || true
        still=1
      fi
    done
  else
    while read -r pid cmd; do
      [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
      exe="${cmd%% *}"
      if [[ "$exe" == "$canonical" ]]; then
        kill "$pid" 2>/dev/null || true
        still=1
      fi
    done < <(ps -axo pid=,command= 2>/dev/null || true)
  fi
  if [[ "$still" == "1" ]]; then
    sleep 1
    still=0
    if [[ -d /proc ]]; then
      for pid in /proc/[0-9]*; do
        pid="${pid#/proc/}"
        exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        if [[ "$exe" == "$canonical" || "$exe" == "${canonical} (deleted)" ]]; then
          kill -9 "$pid" 2>/dev/null || true
          if kill -0 "$pid" 2>/dev/null; then
            echo "ERROR: failed to stop project-owned frpc pid ${pid}" >&2
            echo "FAILURE_CLASS=OWNED_PROCESS_STOP_FAILED" >&2
            return 1
          fi
        fi
      done
    fi
  fi
  return 0
}

SKIP_SYSTEMD=0
if [[ "${FRP_UNINSTALL_HOOK_SKIP_SYSTEMD:-}" == "1" ]]; then
  SKIP_SYSTEMD=1
elif [[ -n "${FRP_UNINSTALL_TEST_ROOT:-}${FRP_CLIENT_TEST_ROOT:-}" && -z "${FRP_UNINSTALL_HOOK_SYSTEMCTL:-}" ]]; then
  SKIP_SYSTEMD=1
fi

echo 'Local software will be removed.'
echo 'Server-side reservations remain.'
echo 'Use an explicit server release command if ports should be freed.'
echo

frp_u_legacy_client_unit_is_product_owned() {
  local unit_file="${1:-}"
  local desc="" exec_line="" line
  [[ -n "$unit_file" && -f "$unit_file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      Description=*) desc="${line#Description=}" ;;
      ExecStart=*) exec_line="${line#ExecStart=}" ;;
    esac
  done <"$unit_file"
  case "$exec_line" in
    */usr/local/bin/frpc\ -c\ /etc/frp/frpc.toml|*/usr/local/bin/frpc\ -c\ /etc/frp/frpc.toml\ *) ;;
    /usr/local/bin/frpc\ -c\ /etc/frp/frpc.toml|/usr/local/bin/frpc\ -c\ /etc/frp/frpc.toml\ *) ;;
    *) return 1 ;;
  esac
  case "$desc" in
    'FRP Client'|'Data Relay Link Client'|'Data Relay Link Client (legacy unit name; use drlink-client)')
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

frp_u_legacy_systemctl() {
  if [[ -n "${FRP_UNINSTALL_HOOK_SYSTEMCTL:-}" ]]; then
    "${FRP_UNINSTALL_HOOK_SYSTEMCTL}" "$@"
    return $?
  fi
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl "$@"
}

frp_u_use_systemd() {
  [[ "$SKIP_SYSTEMD" != "1" ]] && ! frp_u_is_darwin \
    && { [[ -n "${FRP_UNINSTALL_HOOK_SYSTEMCTL:-}" ]] || command -v systemctl >/dev/null 2>&1; }
}

frp_u_unit_is_active() {
  local unit="$1" st
  st="$(frp_u_legacy_systemctl is-active "$unit" 2>/dev/null || true)"
  [[ "$st" == "active" || "$st" == "activating" || "$st" == "reloading" ]]
}

frp_u_legacy_unit_is_active() {
  frp_u_unit_is_active frpc.service
}

frp_u_unit_owns_product_frpc() {
  local unit="$1"
  local main_pid="" exe=""
  if [[ -n "${FRP_LEGACY_RETIRE_HOOK_OWNS_FRPC:-}" ]]; then
    "${FRP_LEGACY_RETIRE_HOOK_OWNS_FRPC}"
    return $?
  fi
  main_pid="$(frp_u_legacy_systemctl show -p MainPID --value "$unit" 2>/dev/null || true)"
  [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  if ! kill -0 "$main_pid" 2>/dev/null; then
    return 1
  fi
  if [[ -e "/proc/${main_pid}/exe" ]]; then
    exe="$(readlink -f "/proc/${main_pid}/exe" 2>/dev/null || true)"
    case "$exe" in
      /usr/local/bin/frpc|/usr/local/bin/frpc\ \(deleted\)) return 0 ;;
    esac
    return 1
  fi
  return 0
}

frp_u_legacy_unit_owns_product_frpc() {
  frp_u_unit_owns_product_frpc frpc.service
}

frp_u_retire_unit_fail_closed() {
  local unit="$1"
  local unit_file="$2"
  local label="$3"
  local class_prefix="${4:-CLIENT_UNIT}"
  local attempt max_attempts=3 enabled=""
  [[ -f "$unit_file" ]] || return 0
  if frp_u_use_systemd; then
    if frp_u_unit_is_active "$unit" || frp_u_unit_owns_product_frpc "$unit"; then
      attempt=1
      while (( attempt <= max_attempts )); do
        if frp_u_legacy_systemctl stop "$unit" >/dev/null 2>&1; then
          break
        fi
        if (( attempt == max_attempts )); then
          echo "ERROR: failed to stop ${label}" >&2
          echo "FAILURE_CLASS=${class_prefix}_STOP_FAILED" >&2
          return 1
        fi
        sleep 0.2
        attempt=$((attempt + 1))
      done
      if frp_u_unit_is_active "$unit"; then
        echo "ERROR: ${label} remains active after stop" >&2
        echo "FAILURE_CLASS=${class_prefix}_STILL_ACTIVE" >&2
        return 1
      fi
      if frp_u_unit_owns_product_frpc "$unit"; then
        echo "ERROR: ${label} MainPID still owns frpc after stop" >&2
        echo "FAILURE_CLASS=${class_prefix}_PROCESS_REMAINS" >&2
        return 1
      fi
    fi
    if ! frp_u_legacy_systemctl disable "$unit" >/dev/null 2>&1; then
      enabled="$(frp_u_legacy_systemctl is-enabled "$unit" 2>/dev/null || true)"
      case "$enabled" in
        enabled|enabled-runtime|linked|linked-runtime)
          echo "ERROR: failed to disable ${label}" >&2
          echo "FAILURE_CLASS=${class_prefix}_DISABLE_FAILED" >&2
          return 1
          ;;
      esac
    fi
  fi
  frp_u_rm_file "$unit_file"
  if frp_u_use_systemd; then
    if ! frp_u_legacy_systemctl daemon-reload >/dev/null 2>&1; then
      echo "ERROR: daemon-reload failed after removing ${label}" >&2
      echo "FAILURE_CLASS=${class_prefix}_RELOAD_FAILED" >&2
      return 1
    fi
    frp_u_legacy_systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  fi
  return 0
}

frp_u_retire_canonical_client_unit() {
  local unit unit_file
  unit=drlink-client.service
  unit_file="$(frp_u_path /etc/systemd/system/drlink-client.service)"
  frp_u_retire_unit_fail_closed "$unit" "$unit_file" "product-owned drlink-client.service" "CLIENT_UNIT"
}

frp_u_retire_legacy_client_unit() {
  local unit unit_file
  unit=frpc.service
  unit_file="$(frp_u_path /etc/systemd/system/frpc.service)"
  [[ -f "$unit_file" ]] || return 0
  if ! frp_u_legacy_client_unit_is_product_owned "$unit_file"; then
    echo "WARNING: leaving non-product frpc.service in place at ${unit_file}" >&2
    return 0
  fi
  frp_u_retire_unit_fail_closed "$unit" "$unit_file" "product-owned legacy frpc.service" "LEGACY_UNIT"
}

if [[ "$SKIP_SYSTEMD" != "1" ]]; then
  if frp_u_is_darwin; then
    if ! frp_macos_launchd_set_enabled disable; then
      echo 'ERROR: failed to persist launchd disable; leaving files for recovery.' >&2
      echo 'FAILURE_CLASS=LAUNCHD_DISABLE_FAILED' >&2
      exit 1
    fi
    frp_macos_launchd_bootout
  fi
fi
# Canonical supervisor must stop fail-closed before binary/config removal.
if ! frp_u_retire_canonical_client_unit; then
  exit 1
fi
# Historical product supervisor must not survive uninstall and respawn on reboot.
if ! frp_u_retire_legacy_client_unit; then
  exit 1
fi
frp_u_stop_owned_frpc

frp_u_rm_file "$(frp_u_path /usr/local/bin/frpc)"
frp_u_rm_file "$(frp_u_path /usr/local/bin/frp-client)"

libdir="$(frp_u_path /usr/local/lib/drlink)"
SERVER_PRESENT=0
if [[ -f "$(frp_u_path /etc/drlink/config.json)" ]]; then
  SERVER_PRESENT=1
fi

# Shared management entrypoints are owned symmetrically with shared libraries:
# preserve them when the server role remains on this host.
if [[ "$SERVER_PRESENT" != "1" ]]; then
  frp_u_rm_file "$(frp_u_path /usr/local/bin/drlink)"
  frp_u_rm_file "$(frp_u_path /usr/local/bin/frpctl)"
  frp_u_rm_file "$(frp_u_path /usr/local/bin/frp-support-bundle)"
fi

# Load canonical ownership (CLIENT_ONLY / SHARED).
for _frp_own in \
  "${libdir}/frp-role-ownership.sh" \
  "${_frp_u_here}/lib/frp-role-ownership.sh" \
  "${_frp_u_here}/../lib/frp-role-ownership.sh"; do
  if [[ -f "$_frp_own" ]]; then
    # shellcheck disable=SC1090
    . "$_frp_own"
    break
  fi
done
unset _frp_own

if [[ -d "$libdir" && ! -L "$libdir" ]]; then
  # CLIENT_ONLY: always remove on client uninstall.
  for f in frp-client-common.sh frp-macos.sh com.datarelay.drlink.frpc.plist; do
    frp_u_rm_file "${libdir}/${f}"
  done
  # SHARED with server: remove only when server role is absent.
  if [[ "$SERVER_PRESENT" != "1" ]]; then
    for f in frp-common.sh frp_mgmt_auth.py frp_health_check.py \
      frp-doctor-common.sh frp_doctor.py frp_support_bundle.py frp_ctl_grammar.py frp_ctl_repl.py \
      frp-role-ownership.sh frpctl; do
      frp_u_rm_file "${libdir}/${f}"
    done
  fi
  rmdir "$libdir" 2>/dev/null || true
elif [[ -L "$libdir" ]]; then
  echo "ERROR: refusing to delete symlink library directory" >&2
  echo "FAILURE_CLASS=SYMLINK_REFUSED" >&2
  echo "FAILURE_CLASS=UNINSTALL_PARTIAL" >&2
  exit 1
fi

etc_frp="$(frp_u_path /etc/frp)"
if [[ -L "$etc_frp" ]]; then
  echo "ERROR: refusing to delete through a symlink at ${etc_frp}" >&2
  echo "FAILURE_CLASS=SYMLINK_REFUSED" >&2
  echo "FAILURE_CLASS=UNINSTALL_PARTIAL" >&2
  exit 1
fi

if [[ -d "$etc_frp" ]]; then
  for f in client-state.json frpc.toml access-info.txt client-id \
    client-identity.key client-identity.pub client-identity.mac \
    apply-pending.json; do
    frp_u_rm_file "${etc_frp}/${f}"
  done
  frp_u_safe_rm_rf "${etc_frp}/backups"
  frp_u_rm_file "${etc_frp}/client-manage.lock"
  if [[ -f "${etc_frp}/server_token" || -f "${etc_frp}/frps.toml" ]]; then
    :
  else
    frp_u_safe_rm_rf "$etc_frp"
  fi
fi

frp_u_rm_file "$(frp_u_path /etc/drlink/allocator-ca.crt)"
# Client role owns client-update-pending.json only. Never remove the server marker.
frp_u_rm_file "$(frp_u_path /var/lib/drlink/client-update-pending.json)"
legacy_marker="$(frp_u_path /var/lib/drlink/update-pending.json)"
if [[ -f "$legacy_marker" ]]; then
  legacy_op="$(python3 - "$legacy_marker" <<'PY'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
print(str(data.get("operation") or "").strip())
PY
)"
  if [[ "$legacy_op" == "client-update" ]]; then
    frp_u_rm_file "$legacy_marker"
  fi
fi
frp_u_rm_file "$(frp_u_path /var/lib/drlink/client-draft.json)"
frp_u_safe_rm_rf "$(frp_u_path /var/lib/drlink/client-upgrades)"

# Dual-role guard: if [[ ! -f /etc/drlink/config.json ]]
if [[ ! -f "$(frp_u_path /etc/drlink/config.json)" ]]; then
  frp_u_rm_file "$(frp_u_path /etc/drlink/version)"
  rmdir "$(frp_u_path /etc/drlink)" 2>/dev/null || true
fi

if frp_u_use_systemd; then
  if ! frp_u_legacy_systemctl daemon-reload >/dev/null 2>&1; then
    echo "ERROR: daemon-reload failed after client uninstall" >&2
    echo "FAILURE_CLASS=CLIENT_UNIT_RELOAD_FAILED" >&2
    exit 1
  fi
  frp_u_legacy_systemctl reset-failed >/dev/null 2>&1 || true
fi

echo 'FRP client removed locally. The central port reservation is intentionally preserved.'
echo 'This uninstall does not contact the server and does not release ports.'
