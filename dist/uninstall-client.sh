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
  '/Library/Application Support/frp-auto-deploy/lib/frp-macos.sh'; do
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
if [[ -n "${FRP_UNINSTALL_TEST_ROOT:-}" || -n "${FRP_CLIENT_TEST_ROOT:-}" || "${FRP_UNINSTALL_HOOK_SKIP_SYSTEMD:-}" == "1" ]]; then
  SKIP_SYSTEMD=1
fi

echo 'Local software will be removed.'
echo 'Server-side reservations remain.'
echo 'Use an explicit server release command if ports should be freed.'
echo

if [[ "$SKIP_SYSTEMD" != "1" ]]; then
  if frp_u_is_darwin; then
    if ! frp_macos_launchd_set_enabled disable; then
      echo 'ERROR: failed to persist launchd disable; leaving files for recovery.' >&2
      echo 'FAILURE_CLASS=LAUNCHD_DISABLE_FAILED' >&2
      exit 1
    fi
    frp_macos_launchd_bootout
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl stop frpc 2>/dev/null || true
    systemctl disable frpc 2>/dev/null || true
  fi
fi
frp_u_stop_owned_frpc

frp_u_rm_file "$(frp_u_path /etc/systemd/system/frpc.service)"
frp_u_rm_file "$(frp_u_path /usr/local/bin/frpc)"
frp_u_rm_file "$(frp_u_path /usr/local/bin/frp-client)"
frp_u_rm_file "$(frp_u_path /usr/local/bin/frpctl)"
frp_u_rm_file "$(frp_u_path /usr/local/bin/frp-support-bundle)"

libdir="$(frp_u_path /usr/local/lib/frp-auto-deploy)"
SERVER_PRESENT=0
if [[ -f "$(frp_u_path /etc/frp-auto-deploy/config.json)" ]]; then
  SERVER_PRESENT=1
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
  for f in frp-client-common.sh frp-macos.sh com.datarelay.frp-auto-deploy.frpc.plist; do
    frp_u_rm_file "${libdir}/${f}"
  done
  # SHARED with server: remove only when server role is absent.
  if [[ "$SERVER_PRESENT" != "1" ]]; then
<<<<<<< HEAD
    for f in frp-common.sh frp_mgmt_auth.py frp_health_check.py \
      frp-doctor-common.sh frp_doctor.py frp_ctl_grammar.py frp_ctl_repl.py \
=======
    for f in frp-common.sh frp_mgmt_auth.py \
      frp-doctor-common.sh frp_doctor.py frp_support_bundle.py frp_ctl_grammar.py frp_ctl_repl.py \
>>>>>>> 4049f6d (feat: add Support Bundle diagnostic archive)
      frp-role-ownership.sh; do
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

frp_u_rm_file "$(frp_u_path /etc/frp-auto-deploy/allocator-ca.crt)"
# Client role owns client-update-pending.json only. Never remove the server marker.
frp_u_rm_file "$(frp_u_path /var/lib/frp-auto-deploy/client-update-pending.json)"
legacy_marker="$(frp_u_path /var/lib/frp-auto-deploy/update-pending.json)"
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
frp_u_rm_file "$(frp_u_path /var/lib/frp-auto-deploy/client-draft.json)"
frp_u_safe_rm_rf "$(frp_u_path /var/lib/frp-auto-deploy/client-upgrades)"

# Dual-role guard: if [[ ! -f /etc/frp-auto-deploy/config.json ]]
if [[ ! -f "$(frp_u_path /etc/frp-auto-deploy/config.json)" ]]; then
  frp_u_rm_file "$(frp_u_path /etc/frp-auto-deploy/version)"
  rmdir "$(frp_u_path /etc/frp-auto-deploy)" 2>/dev/null || true
fi

if [[ "$SKIP_SYSTEMD" != "1" ]] && ! frp_u_is_darwin && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true
fi

echo 'FRP client removed locally. The central port reservation is intentionally preserved.'
echo 'This uninstall does not contact the server and does not release ports.'
