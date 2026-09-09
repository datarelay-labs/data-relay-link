#!/usr/bin/env bash
set -euo pipefail

PURGE=false
PURGE_YES=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=true; shift ;;
    --yes|-y) PURGE_YES=true; shift ;;
    -h|--help)
      cat <<'EOF'
Usage: uninstall-server.sh [--purge] [--yes]

Default uninstall removes FRP server software and runtime units.
Token, private CA, registry, and reservations are preserved.

  --purge   Permanently delete preserved state (token, CA, registry, config)
  --yes     Required with --purge for noninteractive confirmation
EOF
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ${EUID} -ne 0 && -z "${FRP_UNINSTALL_TEST_ROOT:-}" ]]; then
  echo 'Run as root' >&2
  exit 1
fi

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

frp_u_path() {
  local p="$1"
  if [[ -n "${FRP_UNINSTALL_TEST_ROOT:-}" ]]; then
    printf '%s' "${FRP_UNINSTALL_TEST_ROOT}${p}"
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

frp_u_client_present() {
  [[ -f "$(frp_u_path /etc/frp/client-state.json)" || -x "$(frp_u_path /usr/local/bin/frp-client)" ]]
}

frp_u_project_files_py() {
  local cand
  for cand in \
    "$(frp_u_path /usr/local/lib/frp-auto-deploy/frp_project_files.py)" \
    "${_HERE}/lib/frp_project_files.py" \
    "${_HERE}/../lib/frp_project_files.py"; do
    if [[ -f "$cand" ]]; then
      printf '%s' "$cand"
      return 0
    fi
  done
  return 1
}

# Canonical SERVER_ONLY / CLIENT_ONLY / SHARED ownership for dual-role uninstall.
for _frp_own in \
  "$(frp_u_path /usr/local/lib/frp-auto-deploy/frp-role-ownership.sh)" \
  "${_HERE}/lib/frp-role-ownership.sh" \
  "${_HERE}/../lib/frp-role-ownership.sh"; do
  if [[ -f "$_frp_own" ]]; then
    # shellcheck disable=SC1090
    . "$_frp_own"
    break
  fi
done
unset _frp_own
if ! declare -F frp_role_is_shared_lib >/dev/null 2>&1; then
  FRP_ROLE_SHARED_LIB_BASENAMES=' frp-common.sh frp_mgmt_auth.py frp_health_check.py frp-client-common.sh frp-doctor-common.sh frp_doctor.py frp_support_bundle.py frp_ctl_grammar.py frp_ctl_repl.py '
  frp_role_is_shared_lib() {
    local base="$1"
    [[ "$FRP_ROLE_SHARED_LIB_BASENAMES" == *" ${base} "* ]]
  }
fi


frp_u_legacy_marker_is_server() {
  local legacy="$1" op
  [[ -f "$legacy" ]] || return 1
  op="$(python3 - "$legacy" <<'PY'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
print(str(data.get("operation") or "").strip())
PY
)"
  case "$op" in
    install|project-update|frp-update) return 0 ;;
    *) return 1 ;;
  esac
}

frp_u_purge_confirm_ok() {
  local confirm
  if [[ "$PURGE_YES" == true ]]; then
    return 0
  fi
  confirm="$(printf '%s' "${FRP_PURGE_CONFIRM:-}" | tr '[:upper:]' '[:lower:]')"
  confirm="${confirm#"${confirm%%[![:space:]]*}"}"
  confirm="${confirm%"${confirm##*[![:space:]]}"}"
  [[ "$confirm" == "yes" ]]
}

frp_u_release_control_locks() {
  if [[ -n "${FRP_UNINSTALL_LOCK_HOLD:-}" ]]; then
    rm -f "$FRP_UNINSTALL_LOCK_HOLD"
  fi
  if [[ -n "${FRP_UNINSTALL_LOCKER_PID:-}" ]]; then
    wait "$FRP_UNINSTALL_LOCKER_PID" 2>/dev/null || true
    unset FRP_UNINSTALL_LOCKER_PID
  fi
  if [[ -n "${FRP_UNINSTALL_LOCK_STATUS:-}" ]]; then
    rm -f "$FRP_UNINSTALL_LOCK_STATUS"
  fi
  unset FRP_UNINSTALL_LOCK_HOLD FRP_UNINSTALL_LOCK_STATUS
}

frp_u_acquire_control_locks() {
  local timeout life_lock reg_lock status deadline
  timeout="${FRP_UNINSTALL_LOCK_TIMEOUT:-30}"
  life_lock="$(frp_u_path /var/lib/frp-auto-deploy/server-lifecycle.lock)"
  reg_lock="$(frp_u_path /var/lib/frp-auto-deploy/registry.lock)"
  mkdir -p "$(dirname "$life_lock")" "$(dirname "$reg_lock")"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to serialize server uninstall." >&2
    echo "FAILURE_CLASS=LOCK_CONTENTION" >&2
    exit 1
  fi
  # Hold canonical fcntl locks (same as backup/restore) without depending on
  # the util-linux flock CLI, which Amazon Linux containers may omit.
  FRP_UNINSTALL_LOCK_HOLD="$(mktemp "${TMPDIR:-/tmp}/frp-uninstall-hold.XXXXXX")"
  FRP_UNINSTALL_LOCK_STATUS="$(mktemp "${TMPDIR:-/tmp}/frp-uninstall-status.XXXXXX")"
  python3 - "$life_lock" "$reg_lock" "$timeout" "$FRP_UNINSTALL_LOCK_HOLD" "$FRP_UNINSTALL_LOCK_STATUS" <<'PY' &
import fcntl
import os
import sys
import time

life_path, reg_path, timeout_s, hold_path, status_path = (
    sys.argv[1],
    sys.argv[2],
    float(sys.argv[3]),
    sys.argv[4],
    sys.argv[5],
)
deadline = time.monotonic() + timeout_s


def write_status(msg):
    tmp = status_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(msg)
    os.replace(tmp, status_path)


def lock_nb(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                raise TimeoutError
            time.sleep(0.05)


try:
    parent = os.path.dirname(life_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    parent = os.path.dirname(reg_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    life_fd = lock_nb(life_path)
    reg_fd = lock_nb(reg_path)
    write_status("LOCKED")
    while os.path.exists(hold_path):
        time.sleep(0.05)
    os.close(reg_fd)
    os.close(life_fd)
except TimeoutError:
    write_status("TIMEOUT")
    raise SystemExit(2)
except Exception:
    write_status("ERROR")
    raise
PY
  FRP_UNINSTALL_LOCKER_PID=$!
  status=""
  deadline=$((SECONDS + timeout + 2))
  while (( SECONDS < deadline )); do
    if [[ -s "$FRP_UNINSTALL_LOCK_STATUS" ]]; then
      status="$(tr -d '\n' <"$FRP_UNINSTALL_LOCK_STATUS" || true)"
      break
    fi
    if ! kill -0 "$FRP_UNINSTALL_LOCKER_PID" 2>/dev/null; then
      status="$(tr -d '\n' <"$FRP_UNINSTALL_LOCK_STATUS" 2>/dev/null || true)"
      break
    fi
    sleep 0.05
  done
  if [[ "$status" != "LOCKED" ]]; then
    echo "ERROR: timed out waiting for the server lifecycle lock." >&2
    echo "FAILURE_CLASS=LOCK_CONTENTION" >&2
    frp_u_release_control_locks
    exit 1
  fi
  trap 'frp_u_release_control_locks' EXIT
}

frp_u_systemctl() {
  if [[ -n "${FRP_UNINSTALL_HOOK_SYSTEMCTL:-}" ]]; then
    "${FRP_UNINSTALL_HOOK_SYSTEMCTL}" "$@"
    return $?
  fi
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl "$@"
}

frp_u_unit_load_state() {
  local unit="$1" st
  st="$(frp_u_systemctl show -p LoadState --value "$unit" 2>/dev/null || true)"
  printf '%s' "$st"
}

frp_u_unit_exists() {
  local st
  st="$(frp_u_unit_load_state "$1")"
  [[ "$st" == "loaded" || "$st" == "masked" || "$st" == "stub" ]]
}

frp_u_unit_active() {
  local st
  st="$(frp_u_systemctl is-active "$1" 2>/dev/null || true)"
  [[ "$st" == "active" || "$st" == "activating" || "$st" == "reloading" ]]
}

frp_u_stop_product_units() {
  local unit
  for unit in frp-frontend frp-egress-gateway frp-access-plugin frp-port-allocator frps; do
    if ! frp_u_unit_exists "$unit" && ! frp_u_unit_active "$unit"; then
      continue
    fi
    if frp_u_unit_active "$unit"; then
      if ! frp_u_systemctl stop "$unit"; then
        echo "ERROR: failed to stop ${unit}." >&2
        echo "FAILURE_CLASS=SERVICE_STOP_FAILED" >&2
        return 1
      fi
    fi
    if frp_u_unit_active "$unit"; then
      echo "ERROR: ${unit} remains active after stop." >&2
      echo "FAILURE_CLASS=SERVICE_STILL_ACTIVE" >&2
      return 1
    fi
  done
  return 0
}

frp_u_disable_product_units() {
  local unit enabled
  for unit in frp-frontend frp-egress-gateway frp-access-plugin frp-port-allocator frps; do
    if ! frp_u_unit_exists "$unit"; then
      continue
    fi
    if frp_u_systemctl disable "$unit" >/dev/null 2>&1; then
      continue
    fi
    enabled="$(frp_u_systemctl is-enabled "$unit" 2>/dev/null || true)"
    case "$enabled" in
      enabled|enabled-runtime|linked|linked-runtime)
        echo "ERROR: failed to disable ${unit}." >&2
        echo "FAILURE_CLASS=SERVICE_DISABLE_FAILED" >&2
        return 1
        ;;
    esac
  done
  return 0
}

frp_u_acquire_control_locks

SKIP_SYSTEMD=0
if [[ "${FRP_UNINSTALL_HOOK_SKIP_SYSTEMD:-}" == "1" ]]; then
  SKIP_SYSTEMD=1
elif [[ -n "${FRP_UNINSTALL_TEST_ROOT:-}" && -z "${FRP_UNINSTALL_HOOK_SYSTEMCTL:-}" ]]; then
  SKIP_SYSTEMD=1
elif [[ -z "${FRP_UNINSTALL_HOOK_SYSTEMCTL:-}" ]] && ! command -v systemctl >/dev/null 2>&1; then
  if [[ -z "${FRP_UNINSTALL_TEST_ROOT:-}" ]]; then
    echo "ERROR: cannot prove product services are stopped (systemctl is unavailable)." >&2
    echo "FAILURE_CLASS=SERVICE_STOP_FAILED" >&2
    exit 1
  fi
  SKIP_SYSTEMD=1
fi

if [[ "$SKIP_SYSTEMD" != "1" ]]; then
  if ! frp_u_stop_product_units; then
    exit 1
  fi
  if ! frp_u_disable_product_units; then
    exit 1
  fi
fi
# Never enable, start, or unmask distro nginx.service. Uninstall removes
# frp-frontend.service only. If this project installed nginx and disabled
# the distro unit, leave nginx.service disabled. Do not restore unknown
# external nginx configuration.

# Shared libs must remain when a client role is still installed.
CLIENT_PRESENT=0
if frp_u_client_present; then
  CLIENT_PRESENT=1
fi

# Remove managed project files from the canonical server manifest.
if py="$(frp_u_project_files_py)"; then
  mapfile -t _managed_rels < <(python3 "$py" managed-rels --single443 2>/dev/null || python3 "$py" managed-rels)
  for rel in "${_managed_rels[@]}"; do
    [[ -n "$rel" ]] || continue
    base="$(basename "$rel")"
    if [[ "$CLIENT_PRESENT" == "1" ]] && frp_role_is_shared_lib "$base"; then
      continue
    fi
    frp_u_rm_file "$(frp_u_path "/${rel}")"
  done
else
  # Fallback when the helper is already gone (partial uninstall / exotic layout).
  frp_u_rm_file "$(frp_u_path /etc/systemd/system/frps.service)"
  frp_u_rm_file "$(frp_u_path /etc/systemd/system/frp-port-allocator.service)"
  frp_u_rm_file "$(frp_u_path /etc/systemd/system/frp-access-plugin.service)"
  frp_u_rm_file "$(frp_u_path /etc/systemd/system/frp-egress-gateway.service)"
  frp_u_rm_file "$(frp_u_path /etc/systemd/system/frp-frontend.service)"
  frp_u_rm_file "$(frp_u_path /etc/frp-auto-deploy/frontend.conf)"
  frp_u_rm_file "$(frp_u_path /usr/local/bin/frps)"
  for tool in frp-create-client frp-enrollments frp-enrollment-revoke frp-enrollment-purge frp-enroll-bulk \
    frp-clients frp-client-info frp-client-set frp-release-client \
    frp-release-service frp-access frp-egress frp-profile frp-revoke-client frp-set-client-installer-url \
    frp-server-set frp-server-status frp-update frp-upstream frp-project-update frp-backup frp-restore frp-support-bundle; do
    frp_u_rm_file "$(frp_u_path /usr/local/sbin/${tool})"
  done
  frp_u_rm_file "$(frp_u_path /usr/local/sbin/frpctl)"
  libdir="$(frp_u_path /usr/local/lib/frp-auto-deploy)"
  if [[ -d "$libdir" && ! -L "$libdir" ]]; then
    for f in frp-port-allocator.py frp-access-plugin.py frp-egress-gateway.py frp_access_control.py frp_egress_control.py frp_pki.py frp_frontend.py frp_client_registry.py \
      frp_enrollment_lifecycle.py frp_audit.py frp_zero_touch.py \
      frp_install_txn.py frp_health_check.py frp_service_profiles.py \
      frp-server-upgrade.sh frp_project_files.py frp_control_locks.py frp_server_config.py \
      frp-role-ownership.sh \
      server-project-files.manifest release-manifest.json SHA256SUMS; do
      frp_u_rm_file "${libdir}/${f}"
    done
    # SHARED libs: only remove when client role is absent.
    if [[ "$CLIENT_PRESENT" != "1" ]]; then
      for f in frp-common.sh frp_mgmt_auth.py frp_health_check.py frp-client-common.sh \
        frp-doctor-common.sh frp_doctor.py frp_support_bundle.py frp_ctl_grammar.py frp_ctl_repl.py; do
        frp_u_rm_file "${libdir}/${f}"
      done
    fi
  fi
fi
# Dual-role: keep /usr/local/bin/frpctl (client). Manifest only lists sbin.
frp_u_rm_file "$(frp_u_path /usr/local/bin/frps)"
frp_u_rm_file "$(frp_u_path /etc/frp-auto-deploy/frontend.conf)"

libdir="$(frp_u_path /usr/local/lib/frp-auto-deploy)"
if [[ -d "$libdir" && ! -L "$libdir" ]]; then
  rmdir "$libdir" 2>/dev/null || true
elif [[ -L "$libdir" ]]; then
  echo "ERROR: refusing to delete symlink library directory" >&2
  echo "FAILURE_CLASS=SYMLINK_REFUSED" >&2
  echo "FAILURE_CLASS=UNINSTALL_PARTIAL" >&2
  exit 1
fi

if [[ "$SKIP_SYSTEMD" != "1" ]]; then
  frp_u_systemctl daemon-reload || {
    echo "ERROR: systemd daemon-reload failed." >&2
    echo "FAILURE_CLASS=SERVICE_STOP_FAILED" >&2
    exit 1
  }
  frp_u_systemctl reset-failed >/dev/null 2>&1 || true
fi

if [[ "$PURGE" == true ]]; then
  if ! frp_u_purge_confirm_ok; then
    echo "ERROR: --purge permanently deletes the CA, token, registry, and reservations." >&2
    echo "Re-run with --purge --yes, or set FRP_PURGE_CONFIRM=yes exactly." >&2
    echo "FAILURE_CLASS=PURGE_CONFIRMATION_REQUIRED" >&2
    exit 1
  fi

  PURGE_FAILED=0
  PURGE_REMAINING=""
  record_remaining() {
    local p="$1"
    PURGE_FAILED=1
    if [[ -n "$PURGE_REMAINING" ]]; then
      PURGE_REMAINING="${PURGE_REMAINING}
${p}"
    else
      PURGE_REMAINING="$p"
    fi
  }

  try_rm_file() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
      if [[ "${FRP_UNINSTALL_HOOK_PURGE_FAIL_PATH:-}" == "$path" ]]; then
        record_remaining "$path"
        return 0
      fi
      frp_u_rm_file "$path" || record_remaining "$path"
    fi
  }

  try_rm_rf() {
    local path="$1"
    if [[ "${FRP_UNINSTALL_HOOK_PURGE_FAIL_PATH:-}" == "$path" ]]; then
      record_remaining "$path"
      return 0
    fi
    if [[ -L "$path" ]]; then
      frp_u_rm_file "$path" || record_remaining "$path"
      return 0
    fi
    if [[ -e "$path" ]]; then
      frp_u_safe_rm_rf "$path" || record_remaining "$path"
    fi
  }

  var_lib="$(frp_u_path /var/lib/frp-auto-deploy)"
  # Server-owned pending marker only; never clear client-update-pending.json.
  try_rm_file "${var_lib}/server-update-pending.json"
  legacy_marker="${var_lib}/update-pending.json"
  if frp_u_legacy_marker_is_server "$legacy_marker"; then
    try_rm_file "$legacy_marker"
  fi
  try_rm_rf "${var_lib}/enrollments"
  try_rm_rf "${var_lib}/bootstrap"
  try_rm_rf "${var_lib}/backups"
  try_rm_file "${var_lib}/registry.json"
  try_rm_file "${var_lib}/access-control.json"
  try_rm_file "${var_lib}/egress-control.json"
  try_rm_file "${var_lib}/service-profiles.json"
  try_rm_file "${var_lib}/service-profiles.json.lock"
  try_rm_file "${var_lib}/mgmt-nonces.json"
  try_rm_file "${var_lib}/registry.lock"

  if [[ "$CLIENT_PRESENT" == "1" ]]; then
    # Dual-role: never wipe the whole var/lib tree. Preserve client-upgrades/,
    # client-draft.json, client-update-pending.json, and client identity under /etc/frp.
    try_rm_file "$(frp_u_path /etc/frp/server_token)"
    try_rm_file "$(frp_u_path /etc/frp/frps.toml)"
  else
    try_rm_rf "$(frp_u_path /etc/frp)"
  fi
  try_rm_rf "$(frp_u_path /etc/frp-auto-deploy/pki)"
  try_rm_file "$(frp_u_path /etc/frp-auto-deploy/config.json)"
  if [[ "$CLIENT_PRESENT" != "1" && ! -f "$(frp_u_path /etc/frp-auto-deploy/allocator-ca.crt)" ]]; then
    try_rm_file "$(frp_u_path /etc/frp-auto-deploy/version)"
    try_rm_rf "$(frp_u_path /etc/frp-auto-deploy)"
  fi
  if [[ "$CLIENT_PRESENT" == "1" ]]; then
    rmdir "$var_lib" 2>/dev/null || true
  else
    try_rm_rf "$var_lib"
  fi

  if [[ "$PURGE_FAILED" == "1" ]]; then
    echo "ERROR: server purge did not complete." >&2
    echo "FAILURE_CLASS=PURGE_PARTIAL" >&2
    echo "Remaining paths:" >&2
    printf '%s\n' "$PURGE_REMAINING" >&2
    exit 1
  fi
  echo 'FRP server removed and state/secrets purged.'
else
  echo 'FRP server binaries/services removed. Configuration, token, and registry were preserved.'
  echo 'Use --purge only if you intentionally want to delete all reservations and secrets.'
  echo 'Reinstalling the server later reuses the same CA, token, and port reservations.'
fi
