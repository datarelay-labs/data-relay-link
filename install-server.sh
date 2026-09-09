#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ -f "$BASE_DIR/lib/frp-common.sh" ]] || { echo "ERROR: missing project file: $BASE_DIR/lib/frp-common.sh" >&2; exit 1; }
# shellcheck source=lib/frp-common.sh
. "$BASE_DIR/lib/frp-common.sh"

for f in \
  "$BASE_DIR/VERSION" \
  "$BASE_DIR/server/frp-port-allocator.py" \
  "$BASE_DIR/server/frp-access-plugin.py" \
  "$BASE_DIR/server/frp-egress-gateway.py" \
  "$BASE_DIR/server/migrate_token.py" \
  "$BASE_DIR/server/frps.service" \
  "$BASE_DIR/server/frp-port-allocator.service" \
  "$BASE_DIR/server/frp-access-plugin.service" \
  "$BASE_DIR/server/frp-egress-gateway.service" \
  "$BASE_DIR/server/frp-frontend.service" \
  "$BASE_DIR/lib/frp_access_control.py" \
  "$BASE_DIR/lib/frp_egress_control.py" \
  "$BASE_DIR/lib/frp_service_profiles.py" \
  "$BASE_DIR/lib/frp_mgmt_auth.py" \
  "$BASE_DIR/lib/frp_pki.py" \
  "$BASE_DIR/lib/frp_frontend.py" \
  "$BASE_DIR/lib/frp_install_txn.py" \
  "$BASE_DIR/lib/frp-server-upgrade.sh" \
  "$BASE_DIR/lib/frp_client_registry.py" \
  "$BASE_DIR/lib/frp_audit.py" \
  "$BASE_DIR/lib/frp_project_files.py" \
  "$BASE_DIR/lib/frp_control_locks.py" \
  "$BASE_DIR/lib/frp_server_config.py" \
  "$BASE_DIR/lib/server-project-files.manifest" \
  "$BASE_DIR/lib/frp-doctor-common.sh" \
  "$BASE_DIR/lib/frp_doctor.py" \
  "$BASE_DIR/lib/frp_support_bundle.py" \
  "$BASE_DIR/lib/frp_ctl_grammar.py" \
  "$BASE_DIR/lib/frp_ctl_repl.py" \
  "$BASE_DIR/release-manifest.json" \
  "$BASE_DIR/tools/frp-create-client" \
  "$BASE_DIR/tools/frp-enrollments" \
  "$BASE_DIR/tools/frp-enrollment-revoke" \
  "$BASE_DIR/tools/frp-enrollment-purge" \
  "$BASE_DIR/tools/frp-enroll-bulk" \
  "$BASE_DIR/tools/frp-clients" \
  "$BASE_DIR/tools/frp-client-info" \
  "$BASE_DIR/tools/frp-groups" \
  "$BASE_DIR/tools/frp-group-set" \
  "$BASE_DIR/tools/frp-release-client" \
  "$BASE_DIR/tools/frp-release-service" \
  "$BASE_DIR/tools/frp-access" \
  "$BASE_DIR/tools/frp-egress" \
  "$BASE_DIR/tools/frp-profile" \
  "$BASE_DIR/tools/frp-revoke-client" \
  "$BASE_DIR/tools/frp-client-set" \
  "$BASE_DIR/tools/frp-set-client-installer-url" \
  "$BASE_DIR/tools/frp-server-set" \
  "$BASE_DIR/tools/frp-server-status" \
  "$BASE_DIR/tools/frp-project-update" \
  "$BASE_DIR/tools/frp-backup" \
  "$BASE_DIR/tools/frp-restore" \
  "$BASE_DIR/tools/frp-support-bundle" \
  "$BASE_DIR/tools/frp-update" \
  "$BASE_DIR/tools/frp-upstream" \
  "$BASE_DIR/tools/frpctl"; do
  [[ -f "$f" ]] || { echo "ERROR: missing project file: $f" >&2; exit 1; }
done

# shellcheck source=lib/frp-server-upgrade.sh
. "$BASE_DIR/lib/frp-server-upgrade.sh"

DEFAULT_CLIENT_INSTALLER_URL="$(frp_default_client_installer_url)"
DEFAULT_WINDOWS_CLIENT_INSTALLER_URL="$(frp_default_windows_client_installer_url)"
# Historical owner/repo, concatenated only to recognize the obsolete project URL.
LEGACY_CLIENT_INSTALLER_OWNER='RickLee-kr'
LEGACY_CLIENT_INSTALLER_REPO='frp-auto-deploy'

frp_legacy_client_installer_url() {
  printf 'https://raw.githubusercontent.com/%s/%s/main/dist/bootstrap-client.sh' \
    "$LEGACY_CLIENT_INSTALLER_OWNER" "$LEGACY_CLIENT_INSTALLER_REPO"
}

frp_migrate_legacy_client_installer_url() {
  local legacy
  legacy="$(frp_legacy_client_installer_url)"
  if [[ "${CLIENT_INSTALLER_URL:-}" == "$legacy" ]]; then
    CLIENT_INSTALLER_URL="$(frp_default_client_installer_url)"
  fi
  if [[ -z "${FRP_CLIENT_INSTALLER_URL:-}" ]] && \
     [[ "$(frp_release_channel)" == "stable" ]] && \
     frp_is_official_main_installer_url "${CLIENT_INSTALLER_URL:-}"; then
    CLIENT_INSTALLER_URL="$(frp_default_client_installer_url)"
  fi
}

frp_server_fs() {
  local p="$1"
  if [[ -n "${FRP_SERVER_TEST_ROOT:-}" ]]; then
    printf '%s' "${FRP_SERVER_TEST_ROOT}${p}"
  else
    printf '%s' "$p"
  fi
}

frp_server_test_mode() {
  [[ -n "${FRP_SERVER_TEST_ROOT:-}" ]]
}

frp_server_config_path() {
  if [[ -n "${FRP_SERVER_CONFIG:-}" ]]; then
    printf '%s' "$FRP_SERVER_CONFIG"
  else
    frp_server_fs /etc/frp-auto-deploy/config.json
  fi
}

frp_valid_https_url() {
  local url="${1:-}"
  case "$url" in
    https://?*) ;;
    *) return 1 ;;
  esac
  if [[ "$url" == *$'\n'* || "$url" == *$'\r'* || "$url" == *$'\t'* || "$url" == *' '* ]]; then
    return 1
  fi
  local rest="${url#https://}"
  local hostport="${rest%%/*}"
  [[ -n "$hostport" ]]
}

frp_valid_http_url() {
  # Historical name kept for sourced tests; allocator URLs must be HTTPS.
  frp_valid_https_url "$@"
}

frp_valid_tcp_port() {
  local port="${1:-}"
  [[ "$port" =~ ^[1-9][0-9]*$ ]] || return 1
  (( 10#$port >= 1 && 10#$port <= 65535 ))
}

frp_format_https_url() {
  local host="$1" port="$2" path="${3:-/enroll}"
  if [[ "$port" == "443" ]]; then
    printf 'https://%s%s' "$host" "$path"
  else
    printf 'https://%s:%s%s' "$host" "$port" "$path"
  fi
}

frp_pki_dir() {
  if [[ -n "${FRP_PKI_DIR:-}" ]]; then
    printf '%s' "$FRP_PKI_DIR"
  else
    frp_server_fs /etc/frp-auto-deploy/pki
  fi
}

frp_server_install_manifest_files() {
  local lib_dir="$1" sbin_dir="$2" rel mode src
  while IFS=: read -r rel mode src; do
    case "$rel" in
      usr/local/lib/frp-auto-deploy/*)
        install -m "$mode" "$BASE_DIR/$src" "${lib_dir}/$(basename "$rel")"
        ;;
      usr/local/sbin/*)
        install -m "$mode" "$BASE_DIR/$src" "${sbin_dir}/$(basename "$rel")"
        ;;
    esac
  done < <(frp_server_upgrade_destinations "$BASE_DIR")
}

frp_normalize_deployment_mode() {
  local raw="${1:-direct}"
  raw="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  raw="${raw//-/}"
  raw="${raw//_/}"
  case "$raw" in
    single443|enterprise|enterprisesingle443)
      printf '%s' 'single443'
      ;;
    direct|'')
      printf '%s' 'direct'
      ;;
    *)
      echo "ERROR: FRP_DEPLOYMENT_MODE must be direct or single443" >&2
      return 1
      ;;
  esac
}

frp_mode_is_single443() {
  [[ "${FRP_DEPLOYMENT_MODE:-direct}" == "single443" ]]
}

frp_confirm_mode_switch() {
  local from_mode="$1" to_mode="$2"
  echo
  echo "WARNING: switching deployment mode from ${from_mode} to ${to_mode} is a cutover." >&2
  echo "WARNING: existing clients using the previous FRP control transport will disconnect" >&2
  echo "WARNING: until they run a 2.1.0+ client apply against the new server." >&2
  echo "WARNING: this is not a zero-downtime migration." >&2
  if frp_has_tty; then
    local answer=""
    read -r -p "Type SWITCH to confirm this maintenance-window cutover: " answer </dev/tty || true
    if [[ "$answer" != "SWITCH" ]]; then
      echo "ERROR: mode switch was not confirmed" >&2
      return 1
    fi
    return 0
  fi
  case "${FRP_CONFIRM_MODE_SWITCH:-}" in
    1|yes|YES|true|TRUE) return 0 ;;
  esac
  echo "ERROR: set FRP_CONFIRM_MODE_SWITCH=yes for a non-interactive mode switch" >&2
  return 1
}

frp_nginx_bin() {
  if [[ -n "${FRP_NGINX_BIN:-}" && -x "${FRP_NGINX_BIN}" ]]; then
    printf '%s' "$FRP_NGINX_BIN"
    return 0
  fi
  if [[ -x /usr/sbin/nginx ]]; then
    printf '%s' /usr/sbin/nginx
    return 0
  fi
  command -v nginx 2>/dev/null || true
}

frp_nginx_ownership_path() {
  frp_server_fs /var/lib/frp-auto-deploy/nginx-ownership
}

frp_nginx_package_is_installed() {
  local status=""
  if [[ -n "${FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED:-}" ]]; then
    [[ "${FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED}" == "1" ]]
    return
  fi
  if frp_server_test_mode; then
    return 1
  fi
  case "${PACKAGE_MANAGER:-}" in
    apt)
      status="$(dpkg-query -W -f '${Status}' nginx 2>/dev/null || true)"
      [[ "$status" == *'install ok installed'* ]]
      return
      ;;
    dnf|yum)
      rpm -q nginx >/dev/null 2>&1
      return
      ;;
  esac
  if command -v dpkg-query >/dev/null 2>&1; then
    status="$(dpkg-query -W -f '${Status}' nginx 2>/dev/null || true)"
    [[ "$status" == *'install ok installed'* ]]
    return
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -q nginx >/dev/null 2>&1
    return
  fi
  return 1
}

frp_distro_nginx_is_active() {
  if [[ -n "${FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE:-}" ]]; then
    [[ "${FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE}" == "1" ]]
    return
  fi
  if frp_server_skip_systemd; then
    return 1
  fi
  command -v systemctl >/dev/null 2>&1 || return 1
  frp_server_systemctl is-active --quiet nginx.service
}

frp_distro_nginx_is_enabled() {
  if [[ -n "${FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED:-}" ]]; then
    [[ "${FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED}" == "1" ]]
    return
  fi
  if frp_server_skip_systemd; then
    return 1
  fi
  command -v systemctl >/dev/null 2>&1 || return 1
  frp_server_systemctl is-enabled --quiet nginx.service
}

frp_nginx_is_single443_reinstall() {
  local existing
  existing="$(frp_normalize_deployment_mode "${EXISTING_DEPLOYMENT_MODE:-direct}")" || existing=direct
  [[ "$existing" == "single443" ]]
}

frp_nginx_snapshot_state() {
  FRP_NGINX_PACKAGE_WAS_INSTALLED=0
  FRP_NGINX_SERVICE_WAS_ACTIVE=0
  FRP_NGINX_SERVICE_WAS_ENABLED=0
  if frp_nginx_package_is_installed; then
    FRP_NGINX_PACKAGE_WAS_INSTALLED=1
  fi
  if frp_distro_nginx_is_active; then
    FRP_NGINX_SERVICE_WAS_ACTIVE=1
  fi
  if frp_distro_nginx_is_enabled; then
    FRP_NGINX_SERVICE_WAS_ENABLED=1
  fi
}

frp_nginx_emit_preexisting_conflict() {
  echo "ERROR: pre-existing nginx.service is active/enabled." >&2
  echo "ERROR: Enterprise single-443 uses a project-owned nginx instance." >&2
  echo "ERROR: stop/reconfigure the existing nginx service before switching modes." >&2
  if [[ "$(frp_normalize_deployment_mode "${EXISTING_DEPLOYMENT_MODE:-direct}")" == "direct" ]]; then
    echo "ERROR: existing Direct deployment was not modified." >&2
  fi
}

frp_nginx_preflight() {
  frp_mode_is_single443 || return 0
  frp_nginx_snapshot_state
  # Reinstall of project-owned single-443: distro nginx.service is not
  # frp-frontend.service. Leftover package autostart is cleaned up later.
  if frp_nginx_is_single443_reinstall; then
    return 0
  fi
  if [[ "$FRP_NGINX_PACKAGE_WAS_INSTALLED" == "1" ]] && \
     { [[ "$FRP_NGINX_SERVICE_WAS_ACTIVE" == "1" ]] || [[ "$FRP_NGINX_SERVICE_WAS_ENABLED" == "1" ]]; }; then
    frp_nginx_emit_preexisting_conflict
    return 1
  fi
  return 0
}

frp_nginx_stop_disable_distro() {
  if frp_server_skip_systemd; then
    frp_server_record_action "stop nginx.service"
    frp_server_record_action "disable nginx.service"
    return 0
  fi
  frp_server_systemctl stop nginx.service >/dev/null 2>&1 || true
  frp_server_systemctl disable nginx.service >/dev/null 2>&1 || true
}

frp_nginx_write_ownership() {
  local path installed_by=0 disabled_by=0
  path="$(frp_nginx_ownership_path)"
  mkdir -p "$(dirname "$path")"
  installed_by="${FRP_NGINX_PACKAGE_INSTALLED_BY_PROJECT:-0}"
  disabled_by="${FRP_NGINX_DISTRO_DISABLED_BY_PROJECT:-0}"
  cat >"$path" <<EOF
NGINX_PACKAGE_PREEXISTING=${FRP_NGINX_PACKAGE_WAS_INSTALLED:-0}
NGINX_SERVICE_WAS_ACTIVE=${FRP_NGINX_SERVICE_WAS_ACTIVE:-0}
NGINX_SERVICE_WAS_ENABLED=${FRP_NGINX_SERVICE_WAS_ENABLED:-0}
NGINX_PACKAGE_INSTALLED_BY_PROJECT=${installed_by}
NGINX_DISTRO_DISABLED_BY_PROJECT=${disabled_by}
EOF
  chmod 600 "$path"
}

frp_nginx_reconcile_distro_unit() {
  frp_mode_is_single443 || return 0
  FRP_NGINX_PACKAGE_INSTALLED_BY_PROJECT=0
  FRP_NGINX_DISTRO_DISABLED_BY_PROJECT=0
  if [[ "${FRP_NGINX_PACKAGE_WAS_INSTALLED:-0}" != "1" ]]; then
    # Case A: this install brought in the nginx package. Distro nginx.service
    # often auto-starts on TCP/80; stop and disable it. Use frp-frontend only.
    frp_nginx_stop_disable_distro
    FRP_NGINX_PACKAGE_INSTALLED_BY_PROJECT=1
    FRP_NGINX_DISTRO_DISABLED_BY_PROJECT=1
  elif frp_nginx_is_single443_reinstall; then
    # Case D: leftover distro nginx.service from a previous package autostart
    # must not keep TCP/80. Do not confuse this unit with frp-frontend.service.
    if frp_distro_nginx_is_active || frp_distro_nginx_is_enabled; then
      frp_nginx_stop_disable_distro
      FRP_NGINX_DISTRO_DISABLED_BY_PROJECT=1
    fi
  fi
  # Case B: package already installed and nginx.service was inactive/disabled.
  # Leave it that way. Do not enable or start distro nginx.service.
  frp_nginx_write_ownership
}

frp_tcp_port_is_listening() {
  local port="$1" raw=""
  [[ "$port" =~ ^[1-9][0-9]*$ ]] || return 1
  if ! command -v ss >/dev/null 2>&1; then
    return 1
  fi
  raw="$(ss -H -lnt 2>/dev/null || ss -lnt 2>/dev/null || true)"
  printf '%s\n' "$raw" | awk -v p="$port" '
    $1 ~ /^(State|Netid)$/ { next }
    {
      addr=$4
      gsub(/\]$/, "", addr)
      sub(/^.*:/, "", addr)
      if (addr == p) found=1
    }
    END { exit found ? 0 : 1 }
  '
}

frp_frontend_port_preflight() {
  local port occupant_ok=0
  frp_mode_is_single443 || return 0
  port="${FRP_CONTROL_PUBLIC_PORT:-}"
  if [[ "${FRP_INSTALL_HOOK_FRONTEND_PORT_BUSY:-}" == "1" ]]; then
    echo "ERROR: TCP/${port} is already in use by another service." >&2
    echo "ERROR: Enterprise single-443 needs this public port for the HTTPS/WSS frontend." >&2
    echo "ERROR: existing Direct deployment was not modified." >&2
    return 1
  fi
  if frp_server_skip_systemd; then
    return 0
  fi
  if ! frp_tcp_port_is_listening "$port"; then
    return 0
  fi
  # Direct frps already bound on this local port: cutover will restart it onto the backend port.
  if [[ "$(frp_normalize_deployment_mode "${EXISTING_DEPLOYMENT_MODE:-direct}")" == "direct" && \
        "${EXISTING_CONTROL_LISTEN_PORT:-}" == "$port" ]]; then
    occupant_ok=1
  fi
  # Reinstall of an existing single-443 frontend that already owns the port.
  if [[ "$(frp_normalize_deployment_mode "${EXISTING_DEPLOYMENT_MODE:-direct}")" == "single443" ]]; then
    occupant_ok=1
  fi
  if [[ "$occupant_ok" == "1" ]]; then
    return 0
  fi
  echo "ERROR: TCP/${port} is already in use by another service." >&2
  echo "ERROR: Enterprise single-443 needs this public port for the HTTPS/WSS frontend." >&2
  if [[ -n "${EXISTING_DEPLOYMENT_MODE:-}" ]]; then
    echo "ERROR: existing Direct deployment was not modified." >&2
  fi
  if command -v systemctl >/dev/null 2>&1 && frp_server_systemctl is-active --quiet nginx 2>/dev/null; then
    echo "ERROR: distro nginx.service is active; stop or rebind it before using frp-frontend.service." >&2
  fi
  return 1
}

frp_ensure_nginx() {
  local bin
  bin="$(frp_nginx_bin)"
  if [[ -n "$bin" && -x "$bin" ]]; then
    FRP_NGINX_BIN="$bin"
    return 0
  fi
  if frp_server_test_mode; then
    FRP_NGINX_BIN="${FRP_NGINX_BIN:-/usr/sbin/nginx}"
    return 0
  fi
  MISSING_COMMANDS=(nginx)
  if [[ -z "${PACKAGE_MANAGER:-}" ]]; then
    frp_detect_package_manager
  fi
  if [[ -z "${PACKAGE_MANAGER:-}" ]]; then
    echo "ERROR: nginx is required for Enterprise single-443 mode" >&2
    return 1
  fi
  frp_packages_for_missing "$PACKAGE_MANAGER"
  case "$PACKAGE_MANAGER" in
    apt) install_dependencies_apt "${PACKAGES[@]}" ;;
    dnf) install_dependencies_dnf "${PACKAGES[@]}" ;;
    yum) install_dependencies_yum "${PACKAGES[@]}" ;;
    *)
      echo "ERROR: unsupported package manager: ${PACKAGE_MANAGER}" >&2
      return 1
      ;;
  esac
  bin="$(frp_nginx_bin)"
  if [[ -z "$bin" || ! -x "$bin" ]]; then
    echo "ERROR: nginx was installed but the nginx binary was not found" >&2
    return 1
  fi
  FRP_NGINX_BIN="$bin"
}

frp_valid_public_host() {
  local host="${1:-}"
  [[ -n "$host" ]] || return 1
  if [[ "$host" == *$'\n'* || "$host" == *$'\r'* || "$host" == *$'\t'* || "$host" == *' '* ]]; then
    return 1
  fi
  if [[ "$host" == *';'* || "$host" == *'|'* || "$host" == *'&'* || "$host" == *'$'* || "$host" == *'`'* || "$host" == *'<'* || "$host" == *'>'* || "$host" == *"'"* || "$host" == *'"'* || "$host" == *'\\'* || "$host" == *'/'* ]]; then
    return 1
  fi
  return 0
}

frp_valid_public_ip_literal() {
  local value="${1:-}"
  python3 - "$value" <<'PY'
import ipaddress, sys
text = (sys.argv[1] or '').strip()
if text.startswith('[') and text.endswith(']'):
    text = text[1:-1]
try:
    ipaddress.ip_address(text)
except ValueError:
    raise SystemExit(1)
raise SystemExit(0)
PY
}

frp_valid_public_hostname() {
  local value="${1:-}"
  [[ -n "$value" ]] || return 0
  python3 - "$BASE_DIR/lib/frp_server_config.py" "$value" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('frp_server_config', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
try:
    mod.validate_public_hostname(sys.argv[2], required=True)
except Exception:
    raise SystemExit(1)
raise SystemExit(0)
PY
}

frp_has_tty() {
  [[ -e /dev/tty && -r /dev/tty && -w /dev/tty ]] || return 1
  { true </dev/tty >/dev/tty; } 2>/dev/null || return 1
  return 0
}

prompt() {
  local label="$1" default="$2" var="$3"
  local current="${!var:-}"
  if [[ -n "$current" ]]; then return 0; fi
  local value=""
  if frp_has_tty; then
    if [[ -n "$default" ]]; then
      read -r -p "$label [$default]: " value </dev/tty || true
    else
      read -r -p "$label: " value </dev/tty || true
    fi
  fi
  printf -v "$var" '%s' "${value:-$default}"
}

require_value() {
  local var="$1" label="$2"
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: ${label} is required." >&2
    echo "Set ${var} for non-interactive install, or enter it when prompted." >&2
    exit 1
  fi
}

# Overridable wrappers so installer tests can mock systemd/curl/sleep.
frp_server_systemctl() {
  systemctl "$@"
}

frp_server_curl() {
  curl "$@"
}

frp_server_journalctl() {
  journalctl "$@"
}

frp_server_sleep() {
  sleep "$@"
}

frp_allocator_ready_timeout_sec() {
  local timeout="${FRP_ALLOCATOR_READY_TIMEOUT_SEC:-30}"
  if [[ ! "$timeout" =~ ^[1-9][0-9]*$ ]]; then
    timeout=30
  fi
  printf '%s' "$timeout"
}

frp_allocator_ready_interval_sec() {
  local interval="${FRP_ALLOCATOR_READY_INTERVAL_SEC:-1}"
  if [[ ! "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]] || [[ "$interval" == "0" || "$interval" == "0.0" ]]; then
    interval=1
  fi
  printf '%s' "$interval"
}

frp_print_unit_diagnostics() {
  local unit="$1"
  echo >&2
  echo "----- systemctl status ${unit} -----" >&2
  frp_server_systemctl status "$unit" --no-pager -l >&2 || true
  echo >&2
  echo "----- journalctl -u ${unit} -----" >&2
  frp_server_journalctl -u "$unit" -n 50 --no-pager >&2 || true
}

frp_wait_unit_active() {
  local unit="$1"
  local timeout interval start now
  timeout="$(frp_allocator_ready_timeout_sec)"
  interval="$(frp_allocator_ready_interval_sec)"
  start="$(date +%s)"
  while true; do
    if frp_server_systemctl is-active --quiet "$unit"; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout )); then
      echo "ERROR: ${unit} did not become active within ${timeout} seconds" >&2
      frp_print_unit_diagnostics "$unit"
      return 1
    fi
    frp_server_sleep "$interval"
  done
}

frp_wait_allocator_ready() {
  local port="${1:-${FRP_ALLOCATOR_LISTEN_PORT:-${FRP_ALLOCATOR_PORT:-6099}}}"
  local timeout interval start now url announced=0 ca
  timeout="$(frp_allocator_ready_timeout_sec)"
  interval="$(frp_allocator_ready_interval_sec)"
  url="https://127.0.0.1:${port}/healthz"
  ca="${FRP_ALLOCATOR_READY_CA:-$(frp_pki_dir)/ca.crt}"
  start="$(date +%s)"

  while true; do
    if ! frp_server_systemctl is-active --quiet frp-port-allocator; then
      echo "ERROR: frp-port-allocator.service stopped before becoming ready" >&2
      frp_print_unit_diagnostics frp-port-allocator
      return 1
    fi
    if frp_server_curl -fsS --cacert "$ca" "$url" >/dev/null 2>&1; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout )); then
      echo "ERROR: FRP allocator did not become ready within ${timeout} seconds" >&2
      frp_print_unit_diagnostics frp-port-allocator
      return 1
    fi
    if [[ "$announced" == "0" ]]; then
      echo "Waiting for FRP allocator HTTPS listener on ${url} ..."
      announced=1
    fi
    frp_server_sleep "$interval"
  done
}

frp_server_prepare_host() {
  frp_require_bash || exit 1
  frp_detect_architecture || exit 1
  if frp_server_test_mode; then
    return 0
  fi
  frp_detect_platform
  frp_detect_package_manager
  frp_print_detected_linux
  echo
  frp_require_systemd || {
    frp_emit_failure_class INSTALL_PRECHECK_FAILED
    exit 1
  }
  FRP_DEPENDENCY_ROLE=server
  if [[ "${FRP_INSTALL_HOOK_DEP_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated package manager failure" >&2
    frp_emit_failure_class DEPENDENCY_INSTALL_FAILED
    exit 1
  fi
  if ! ensure_dependencies; then
    frp_emit_failure_class DEPENDENCY_INSTALL_FAILED
    exit 1
  fi
  frp_require_python || {
    frp_emit_failure_class INSTALL_PRECHECK_FAILED
    exit 1
  }
}

load_existing_server_config() {
  local path
  path="$(frp_server_config_path)"
  EXISTING_PUBLIC_IP=""
  EXISTING_CONTROL_PORT=""
  EXISTING_CONTROL_PUBLIC_PORT=""
  EXISTING_CONTROL_LISTEN_PORT=""
  EXISTING_PORT_START=""
  EXISTING_PORT_END=""
  EXISTING_ALLOCATOR_PORT=""
  EXISTING_ALLOCATOR_PUBLIC_PORT=""
  EXISTING_ALLOCATOR_LISTEN_PORT=""
  EXISTING_ALLOCATOR_URL=""
  EXISTING_CLIENT_INSTALLER_URL=""
  EXISTING_WINDOWS_CLIENT_INSTALLER_URL=""
  EXISTING_DEPLOYMENT_MODE=""
  EXISTING_SERVER_CONFIG=""
  [[ -r "$path" ]] || return 0
  eval "$(python3 - "$path" <<'PY'
import json, shlex, sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    cfg = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(0)
if not isinstance(cfg, dict):
    raise SystemExit(0)
print('EXISTING_SERVER_CONFIG=1')
mapping = {
    'public_host': 'EXISTING_PUBLIC_IP',
    'public_ip': 'EXISTING_PUBLIC_IP',
    'public_hostname': 'EXISTING_PUBLIC_HOSTNAME',
    'bootstrap_hostname': 'EXISTING_BOOTSTRAP_HOSTNAME',
    'control_port': 'EXISTING_CONTROL_PORT',
    'frp_control_public_port': 'EXISTING_CONTROL_PUBLIC_PORT',
    'frp_control_listen_port': 'EXISTING_CONTROL_LISTEN_PORT',
    'port_start': 'EXISTING_PORT_START',
    'port_end': 'EXISTING_PORT_END',
    'listen_port': 'EXISTING_ALLOCATOR_LISTEN_PORT',
    'allocator_listen_port': 'EXISTING_ALLOCATOR_LISTEN_PORT',
    'allocator_public_port': 'EXISTING_ALLOCATOR_PUBLIC_PORT',
    'client_installer_url': 'EXISTING_CLIENT_INSTALLER_URL',
    'windows_client_installer_url': 'EXISTING_WINDOWS_CLIENT_INSTALLER_URL',
    'deployment_mode': 'EXISTING_DEPLOYMENT_MODE',
}
# public_ip is the control endpoint; public_host is a legacy synonym.
# Prefer public_ip when both exist so a stale public_host cannot override IP.
order = [
    'public_host', 'public_ip', 'public_hostname', 'bootstrap_hostname',
    'control_port', 'frp_control_public_port', 'frp_control_listen_port',
    'port_start', 'port_end',
    'listen_port', 'allocator_listen_port', 'allocator_public_port',
    'client_installer_url', 'windows_client_installer_url',
    'deployment_mode',
]
seen = {}
for key in order:
    envname = mapping[key]
    value = cfg.get(key)
    if value is None or value == '':
        continue
    seen[envname] = str(value)
if 'EXISTING_DEPLOYMENT_MODE' not in seen:
    # Pre-2.1 configs omit deployment_mode. An existing server is Direct.
    seen['EXISTING_DEPLOYMENT_MODE'] = 'direct'
for envname, value in seen.items():
    print(f'{envname}={shlex.quote(value)}')
url = str(cfg.get('allocator_public_url') or '').strip()
if url.lower().startswith('https://'):
    print('EXISTING_ALLOCATOR_URL=' + shlex.quote(url))
PY
)"
}

resolve_server_settings() {
  local user_set_mode=0 user_control_public=0 user_control_listen=0
  local user_alloc_public=0 user_alloc_listen=0 user_alloc_url=0
  local existing_mode="" choice=""

  if [[ -n "${FRP_DEPLOYMENT_MODE:-}" ]]; then
    user_set_mode=1
  fi
  if [[ -n "${FRP_CONTROL_PUBLIC_PORT:-}" || -n "${FRP_CONTROL_PORT:-}" ]]; then
    user_control_public=1
  fi
  if [[ -n "${FRP_CONTROL_LISTEN_PORT:-}" ]]; then
    user_control_listen=1
  fi
  # A single FRP_CONTROL_PORT sets both public and listen (legacy).
  if [[ -n "${FRP_CONTROL_PORT:-}" && -z "${FRP_CONTROL_LISTEN_PORT:-}" && -z "${FRP_CONTROL_PUBLIC_PORT:-}" ]]; then
    user_control_listen=1
  fi
  if [[ -n "${FRP_ALLOCATOR_PUBLIC_PORT:-}" ]]; then
    user_alloc_public=1
  fi
  if [[ -n "${FRP_ALLOCATOR_LISTEN_PORT:-}" || -n "${FRP_ALLOCATOR_PORT:-}" ]]; then
    user_alloc_listen=1
  fi
  if [[ -n "${FRP_ALLOCATOR_PUBLIC_URL:-}" || -n "${FRP_ALLOCATOR_URL:-}" ]]; then
    user_alloc_url=1
  fi

  if [[ -z "${FRP_PUBLIC_IP:-}" && -n "${FRP_PUBLIC_HOST:-}" ]]; then
    FRP_PUBLIC_IP="$FRP_PUBLIC_HOST"
  fi
  if [[ -z "${FRP_ALLOCATOR_PUBLIC_URL:-}" && -n "${FRP_ALLOCATOR_URL:-}" ]]; then
    FRP_ALLOCATOR_PUBLIC_URL="$FRP_ALLOCATOR_URL"
  fi

  FRP_PUBLIC_IP="${FRP_PUBLIC_IP:-${EXISTING_PUBLIC_IP:-}}"
  FRP_PUBLIC_HOST="${FRP_PUBLIC_HOST:-$FRP_PUBLIC_IP}"
  FRP_PUBLIC_HOSTNAME="${FRP_PUBLIC_HOSTNAME:-${EXISTING_PUBLIC_HOSTNAME:-}}"
  FRP_BOOTSTRAP_HOSTNAME="${FRP_BOOTSTRAP_HOSTNAME:-${EXISTING_BOOTSTRAP_HOSTNAME:-}}"
  FRP_INTERNAL_IP="${FRP_INTERNAL_IP:-}"
  FRP_PORT_START="${FRP_PORT_START:-${EXISTING_PORT_START:-}}"
  FRP_PORT_END="${FRP_PORT_END:-${EXISTING_PORT_END:-}}"
  CLIENT_INSTALLER_URL="${FRP_CLIENT_INSTALLER_URL:-${EXISTING_CLIENT_INSTALLER_URL:-$DEFAULT_CLIENT_INSTALLER_URL}}"
  frp_migrate_legacy_client_installer_url
  WINDOWS_CLIENT_INSTALLER_URL="${FRP_WINDOWS_CLIENT_INSTALLER_URL:-${EXISTING_WINDOWS_CLIENT_INSTALLER_URL:-$DEFAULT_WINDOWS_CLIENT_INSTALLER_URL}}"
  if ! frp_validate_https_url "$CLIENT_INSTALLER_URL"; then
    echo "ERROR: client_installer_url must be a valid https:// URL" >&2
    exit 1
  fi
  if ! frp_validate_https_url "$WINDOWS_CLIENT_INSTALLER_URL"; then
    echo "ERROR: windows_client_installer_url must be a valid https:// URL" >&2
    exit 1
  fi
  FRP_MODE_SWITCH=0

  # Public vs listen: dedicated vars win; a single legacy FRP_CONTROL_PORT or
  # existing control_port is used for both only when the split was never set
  # (pre-P2.8 they were always equal).
  if [[ -z "${FRP_CONTROL_PUBLIC_PORT:-}" ]]; then
    FRP_CONTROL_PUBLIC_PORT="${EXISTING_CONTROL_PUBLIC_PORT:-}"
  fi
  if [[ -z "${FRP_CONTROL_LISTEN_PORT:-}" ]]; then
    FRP_CONTROL_LISTEN_PORT="${EXISTING_CONTROL_LISTEN_PORT:-}"
  fi
  if [[ -z "${FRP_CONTROL_PUBLIC_PORT:-}" && -z "${FRP_CONTROL_LISTEN_PORT:-}" ]]; then
    FRP_CONTROL_PUBLIC_PORT="${FRP_CONTROL_PORT:-${EXISTING_CONTROL_PORT:-}}"
    FRP_CONTROL_LISTEN_PORT="${FRP_CONTROL_PORT:-${EXISTING_CONTROL_PORT:-}}"
  fi
  if [[ -z "${FRP_CONTROL_PUBLIC_PORT:-}" && -n "${FRP_CONTROL_LISTEN_PORT:-}" ]]; then
    FRP_CONTROL_PUBLIC_PORT="$FRP_CONTROL_LISTEN_PORT"
  fi
  if [[ -z "${FRP_CONTROL_LISTEN_PORT:-}" && -n "${FRP_CONTROL_PUBLIC_PORT:-}" ]]; then
    FRP_CONTROL_LISTEN_PORT="$FRP_CONTROL_PUBLIC_PORT"
  fi

  if [[ -z "${FRP_ALLOCATOR_LISTEN_PORT:-}" ]]; then
    FRP_ALLOCATOR_LISTEN_PORT="${FRP_ALLOCATOR_PORT:-${EXISTING_ALLOCATOR_LISTEN_PORT:-${EXISTING_ALLOCATOR_PORT:-}}}"
  fi
  if [[ -z "${FRP_ALLOCATOR_PUBLIC_PORT:-}" ]]; then
    FRP_ALLOCATOR_PUBLIC_PORT="${EXISTING_ALLOCATOR_PUBLIC_PORT:-}"
  fi

  local detected_public="${DETECTED_PUBLIC_IP:-}"
  local detected_internal="${DETECTED_INTERNAL_IP:-}"

  echo
  echo "FRP Auto Deploy Server Setup"
  echo "============================"
  echo

  if [[ -z "$FRP_PUBLIC_IP" ]]; then
    if frp_has_tty; then
      prompt "Public IP" "$detected_public" FRP_PUBLIC_IP
    fi
  fi
  require_value FRP_PUBLIC_IP "Public IP (FRP_PUBLIC_IP or FRP_PUBLIC_HOST)"
  if ! frp_valid_public_host "$FRP_PUBLIC_IP"; then
    echo "ERROR: Public IP contains invalid characters" >&2
    exit 1
  fi
  # Fresh installs require an IP literal. Existing deployments may still use a
  # legacy hostname as the control endpoint; do not break reinstall/upgrade.
  if [[ "${EXISTING_SERVER_CONFIG:-}" != "1" ]]; then
    if ! frp_valid_public_ip_literal "$FRP_PUBLIC_IP"; then
      echo "ERROR: Public IP must be an IPv4 or IPv6 address" >&2
      echo "Optional DNS aliases are configured separately as Public DNS hostname." >&2
      exit 1
    fi
  fi
  FRP_PUBLIC_HOST="$FRP_PUBLIC_IP"

  if [[ -z "${FRP_PUBLIC_HOSTNAME}" ]]; then
    if frp_has_tty && [[ "${EXISTING_SERVER_CONFIG:-}" != "1" ]]; then
      echo
      echo "Optional DNS name pointing to this server's public IP."
      echo
      echo "Example:"
      echo "  frp.example.com"
      echo
      echo "Press Enter to use the public IP only."
      echo
      echo "FRP Auto Deploy does not create or manage DNS records."
      prompt "Public DNS hostname [optional]" "" FRP_PUBLIC_HOSTNAME
    fi
  fi
  if [[ -n "${FRP_PUBLIC_HOSTNAME}" ]]; then
    if ! frp_valid_public_hostname "$FRP_PUBLIC_HOSTNAME"; then
      echo "ERROR: Public DNS hostname is invalid" >&2
      echo "Use a bare DNS name such as frp.example.com (no scheme, port, or path)." >&2
      exit 1
    fi
  fi

  local internal_default="${FRP_INTERNAL_IP:-${detected_internal:-}}"
  prompt "Internal FRP server IP (display only)" "$internal_default" FRP_INTERNAL_IP

  existing_mode="$(frp_normalize_deployment_mode "${EXISTING_DEPLOYMENT_MODE:-direct}")" || exit 1
  if [[ "$user_set_mode" != "1" ]]; then
    FRP_DEPLOYMENT_MODE="$existing_mode"
    # Mode prompt is for a genuine fresh install only. A pre-2.1 config.json
    # without deployment_mode is an existing Direct server, not a first install.
    if frp_has_tty && [[ "${EXISTING_SERVER_CONFIG:-}" != "1" ]]; then
      echo
      echo "Deployment mode"
      echo "---------------"
      echo "  1) Direct — FRP control and allocator HTTPS on separate public ports [default]"
      echo "  2) Enterprise single-443 — HTTPS allocator + FRP control over WSS on one public TCP port"
      choice=""
      prompt "Select 1 or 2" "1" choice
      case "$choice" in
        2|single443|SINGLE443) FRP_DEPLOYMENT_MODE=single443 ;;
        *) FRP_DEPLOYMENT_MODE=direct ;;
      esac
    fi
  fi
  FRP_DEPLOYMENT_MODE="$(frp_normalize_deployment_mode "$FRP_DEPLOYMENT_MODE")" || exit 1
  if [[ "${EXISTING_SERVER_CONFIG:-}" == "1" && "$existing_mode" != "$FRP_DEPLOYMENT_MODE" ]]; then
    frp_confirm_mode_switch "$existing_mode" "$FRP_DEPLOYMENT_MODE" || exit 1
    FRP_MODE_SWITCH=1
  fi

  if [[ "$FRP_MODE_SWITCH" == "1" && "$user_alloc_url" != "1" ]]; then
    FRP_ALLOCATOR_PUBLIC_URL=""
    EXISTING_ALLOCATOR_URL=""
  fi

  if frp_mode_is_single443; then
    if [[ "$user_control_public" != "1" && -z "${FRP_CONTROL_PUBLIC_PORT:-}" ]]; then
      FRP_CONTROL_PUBLIC_PORT=443
    fi
    if [[ "$user_alloc_public" != "1" ]]; then
      if [[ -z "${FRP_ALLOCATOR_PUBLIC_PORT:-}" || "$FRP_MODE_SWITCH" == "1" ]]; then
        FRP_ALLOCATOR_PUBLIC_PORT="${FRP_CONTROL_PUBLIC_PORT:-443}"
      fi
    fi
    if [[ "$user_control_listen" != "1" ]]; then
      if [[ -z "${FRP_CONTROL_LISTEN_PORT:-}" || "$FRP_MODE_SWITCH" == "1" || \
            "${FRP_CONTROL_LISTEN_PORT}" == "${FRP_CONTROL_PUBLIC_PORT:-443}" ]]; then
        FRP_CONTROL_LISTEN_PORT="${FRP_SINGLE443_BACKEND_PORT}"
      fi
    fi
    if [[ "$user_alloc_listen" != "1" && -z "${FRP_ALLOCATOR_LISTEN_PORT:-}" ]]; then
      FRP_ALLOCATOR_LISTEN_PORT=6099
    fi
  elif [[ "$FRP_MODE_SWITCH" == "1" ]]; then
    if [[ "$user_control_public" != "1" ]]; then
      FRP_CONTROL_PUBLIC_PORT=443
    fi
    if [[ "$user_control_listen" != "1" ]]; then
      FRP_CONTROL_LISTEN_PORT="${FRP_CONTROL_PUBLIC_PORT:-443}"
    fi
    if [[ "$user_alloc_public" != "1" ]]; then
      FRP_ALLOCATOR_PUBLIC_PORT=6099
    fi
    if [[ "$user_alloc_listen" != "1" ]]; then
      FRP_ALLOCATOR_LISTEN_PORT=6099
    fi
  fi

  echo
  echo "FRP Control"
  echo "-----------"
  prompt "Public control port" "${FRP_CONTROL_PUBLIC_PORT:-443}" FRP_CONTROL_PUBLIC_PORT
  if frp_mode_is_single443; then
    prompt "Internal FRP backend port" "${FRP_CONTROL_LISTEN_PORT:-${FRP_SINGLE443_BACKEND_PORT}}" FRP_CONTROL_LISTEN_PORT
  else
    prompt "Internal listen port" "${FRP_CONTROL_LISTEN_PORT:-${FRP_CONTROL_PUBLIC_PORT:-443}}" FRP_CONTROL_LISTEN_PORT
  fi

  echo
  echo "Enrollment / Management HTTPS"
  echo "-----------------------------"
  if frp_mode_is_single443; then
    prompt "Public HTTPS port" "${FRP_ALLOCATOR_PUBLIC_PORT:-${FRP_CONTROL_PUBLIC_PORT:-443}}" FRP_ALLOCATOR_PUBLIC_PORT
    prompt "Internal allocator backend port" "${FRP_ALLOCATOR_LISTEN_PORT:-6099}" FRP_ALLOCATOR_LISTEN_PORT
  else
    prompt "Public HTTPS port" "${FRP_ALLOCATOR_PUBLIC_PORT:-${FRP_ALLOCATOR_LISTEN_PORT:-6099}}" FRP_ALLOCATOR_PUBLIC_PORT
    prompt "Internal listen port" "${FRP_ALLOCATOR_LISTEN_PORT:-${FRP_ALLOCATOR_PUBLIC_PORT:-6099}}" FRP_ALLOCATOR_LISTEN_PORT
  fi

  echo
  echo "Published Service Ports"
  echo "-----------------------"
  prompt "Range start" "${FRP_PORT_START:-6000}" FRP_PORT_START
  prompt "Range end" "${FRP_PORT_END:-6098}" FRP_PORT_END

  FRP_CONTROL_PORT="$FRP_CONTROL_LISTEN_PORT"
  FRP_ALLOCATOR_PORT="$FRP_ALLOCATOR_LISTEN_PORT"
  if [[ -z "${FRP_ALLOCATOR_PUBLIC_PORT:-}" ]]; then
    FRP_ALLOCATOR_PUBLIC_PORT="$FRP_ALLOCATOR_LISTEN_PORT"
  fi
  if [[ -z "${FRP_ALLOCATOR_LISTEN_PORT:-}" ]]; then
    FRP_ALLOCATOR_LISTEN_PORT="$FRP_ALLOCATOR_PUBLIC_PORT"
  fi

  if frp_mode_is_single443; then
    FRP_LISTEN_HOST=127.0.0.1
    FRP_CONTROL_BIND_ADDR=127.0.0.1
    FRP_TRANSPORT=wss
    if [[ "$FRP_CONTROL_PUBLIC_PORT" != "$FRP_ALLOCATOR_PUBLIC_PORT" ]]; then
      echo "ERROR: Enterprise single-443 mode requires FRP control and allocator to share the same public TCP port" >&2
      exit 1
    fi
    if [[ "$FRP_CONTROL_PUBLIC_PORT" != "443" ]]; then
      echo "WARNING: Enterprise firewalls that allow TLS only on TCP/443 may still reset TLS on ${FRP_CONTROL_PUBLIC_PORT}." >&2
    fi
  else
    FRP_LISTEN_HOST=0.0.0.0
    FRP_CONTROL_BIND_ADDR=0.0.0.0
    FRP_TRANSPORT=tcp
  fi

  local derived_url
  derived_url="$(frp_format_https_url "$FRP_PUBLIC_HOST" "$FRP_ALLOCATOR_PUBLIC_PORT" /enroll)"
  if [[ -n "${FRP_ALLOCATOR_PUBLIC_URL:-}" ]]; then
    if [[ "${FRP_ALLOCATOR_PUBLIC_URL,,}" == http://* ]]; then
      echo "ERROR: allocator public URL must be HTTPS; plain HTTP is not supported" >&2
      exit 1
    fi
  elif [[ -n "${EXISTING_ALLOCATOR_URL:-}" ]]; then
    FRP_ALLOCATOR_PUBLIC_URL="$EXISTING_ALLOCATOR_URL"
  else
    if frp_has_tty; then
      prompt "Allocator public URL" "$derived_url" FRP_ALLOCATOR_PUBLIC_URL
    else
      FRP_ALLOCATOR_PUBLIC_URL="$derived_url"
    fi
  fi
  require_value FRP_ALLOCATOR_PUBLIC_URL "Allocator public URL (FRP_ALLOCATOR_PUBLIC_URL or FRP_ALLOCATOR_URL)"
  if [[ "${FRP_ALLOCATOR_PUBLIC_URL,,}" == http://* ]]; then
    echo "ERROR: allocator public URL must be HTTPS; plain HTTP is not supported" >&2
    exit 1
  fi
  if ! frp_valid_https_url "$FRP_ALLOCATOR_PUBLIC_URL"; then
    echo "ERROR: Allocator public URL must be an https:// URL with a host" >&2
    exit 1
  fi
  if frp_mode_is_single443; then
    local url_port
    url_port="$(python3 - "$FRP_ALLOCATOR_PUBLIC_URL" <<'PY'
from urllib.parse import urlparse
import sys
parsed = urlparse(sys.argv[1])
print(parsed.port or (443 if parsed.scheme == 'https' else 80))
PY
)"
    if [[ "$url_port" != "$FRP_ALLOCATOR_PUBLIC_PORT" ]]; then
      echo "ERROR: single-443 allocator public URL port (${url_port}) must match public port ${FRP_ALLOCATOR_PUBLIC_PORT}" >&2
      exit 1
    fi
  fi

  local port_name
  for port_name in FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
    FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_PORT_START FRP_PORT_END; do
    if ! frp_valid_tcp_port "${!port_name}"; then
      echo "ERROR: ${port_name} must be an integer TCP port between 1 and 65535" >&2
      exit 1
    fi
  done
  if (( 10#$FRP_PORT_START > 10#$FRP_PORT_END )); then
    echo "ERROR: invalid service port range" >&2
    exit 1
  fi
  if (( 10#$FRP_CONTROL_LISTEN_PORT == 10#$FRP_ALLOCATOR_LISTEN_PORT )); then
    echo "ERROR: local port collision: FRP control listen port and allocator listen port cannot share ${FRP_CONTROL_LISTEN_PORT}" >&2
    exit 1
  fi
  if (( 10#$FRP_ALLOCATOR_LISTEN_PORT >= 10#$FRP_PORT_START && 10#$FRP_ALLOCATOR_LISTEN_PORT <= 10#$FRP_PORT_END )); then
    echo "ERROR: allocator listen port must be outside the FRP service port range" >&2
    exit 1
  fi
  if (( 10#$FRP_CONTROL_LISTEN_PORT >= 10#$FRP_PORT_START && 10#$FRP_CONTROL_LISTEN_PORT <= 10#$FRP_PORT_END )); then
    echo "ERROR: FRP control listen port must be outside the FRP service port range" >&2
    exit 1
  fi
  if frp_mode_is_single443; then
    if (( 10#$FRP_CONTROL_LISTEN_PORT == 10#$FRP_CONTROL_PUBLIC_PORT )); then
      echo "ERROR: FRP control backend port cannot be the public frontend port ${FRP_CONTROL_PUBLIC_PORT}" >&2
      exit 1
    fi
    if (( 10#$FRP_ALLOCATOR_LISTEN_PORT == 10#$FRP_ALLOCATOR_PUBLIC_PORT )); then
      echo "ERROR: allocator backend port cannot be the public frontend port ${FRP_ALLOCATOR_PUBLIC_PORT}" >&2
      exit 1
    fi
  elif [[ "$FRP_CONTROL_PUBLIC_PORT" == "$FRP_ALLOCATOR_PUBLIC_PORT" ]]; then
    echo "WARNING: FRP control and allocator public ports are both ${FRP_CONTROL_PUBLIC_PORT}." >&2
    echo "WARNING: two distinct raw TCP services cannot normally share the same public IP:port without an external proxy." >&2
  fi
}

write_server_config() {
  local path pki
  path="$(frp_server_config_path)"
  pki="$(frp_pki_dir)"
  mkdir -p "$(dirname "$path")"
  FRP_DEPLOYMENT_MODE="${FRP_DEPLOYMENT_MODE:-direct}"
  FRP_LISTEN_HOST="${FRP_LISTEN_HOST:-0.0.0.0}"
  FRP_CONTROL_BIND_ADDR="${FRP_CONTROL_BIND_ADDR:-0.0.0.0}"
  FRP_TRANSPORT="${FRP_TRANSPORT:-tcp}"
  export FRP_DEPLOYMENT_MODE FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR FRP_TRANSPORT
  python3 - "$path" \
    "$FRP_PUBLIC_HOST" \
    "$FRP_CONTROL_PUBLIC_PORT" \
    "$FRP_CONTROL_LISTEN_PORT" \
    "$FRP_PORT_START" \
    "$FRP_PORT_END" \
    "$FRP_ALLOCATOR_PUBLIC_PORT" \
    "$FRP_ALLOCATOR_LISTEN_PORT" \
    "$FRP_ALLOCATOR_PUBLIC_URL" \
    "$CLIENT_INSTALLER_URL" \
    "$WINDOWS_CLIENT_INSTALLER_URL" \
    "$pki" \
    "${FRP_PUBLIC_HOSTNAME:-}" \
    "${FRP_BOOTSTRAP_HOSTNAME:-}" <<'PY'
import json, os, sys, tempfile
from pathlib import Path
path = Path(sys.argv[1])
pki = sys.argv[12]
host = sys.argv[2]
hostname = (sys.argv[13] if len(sys.argv) > 13 else '').strip()
bootstrap_hostname = (sys.argv[14] if len(sys.argv) > 14 else '').strip()
cfg = {
    'public_host': host,
    'public_ip': host,
    'frp_control_public_port': int(sys.argv[3]),
    'frp_control_listen_port': int(sys.argv[4]),
    'port_start': int(sys.argv[5]),
    'port_end': int(sys.argv[6]),
    'listen_host': os.environ.get('FRP_LISTEN_HOST') or '0.0.0.0',
    'frp_control_bind_addr': os.environ.get('FRP_CONTROL_BIND_ADDR') or '0.0.0.0',
    'frp_proxy_bind_addr': '0.0.0.0',
    'deployment_mode': os.environ.get('FRP_DEPLOYMENT_MODE') or 'direct',
    'frp_transport': os.environ.get('FRP_TRANSPORT') or 'tcp',
    'allocator_public_port': int(sys.argv[7]),
    'allocator_listen_port': int(sys.argv[8]),
    'listen_port': int(sys.argv[8]),
    'allocator_public_url': sys.argv[9],
    'registry_file': '/var/lib/frp-auto-deploy/registry.json',
    'enrollments_dir': '/var/lib/frp-auto-deploy/enrollments',
    'bootstrap_dir': '/var/lib/frp-auto-deploy/bootstrap',
    'enrollment_retention_days': 30,
    'token_file': '/etc/frp/server_token',
    'access_control_file': '/var/lib/frp-auto-deploy/access-control.json',
    'service_profiles_file': '/var/lib/frp-auto-deploy/service-profiles.json',
    'egress_control_file': '/var/lib/frp-auto-deploy/egress-control.json',
    'access_conn_log_file': '/var/log/frp-auto-deploy/access-conn.jsonl',
    'egress_conn_log_file': '/var/log/frp-auto-deploy/egress-conn.jsonl',
    'egress_listen_addr': '0.0.0.0',
    'egress_listen_port': 6080,
    'access_plugin_addr': '127.0.0.1:6101',
    'access_plugin_path': '/access-auth',
    'client_installer_url': sys.argv[10],
    'windows_client_installer_url': sys.argv[11],
    'tls_ca_cert': pki.rstrip('/') + '/ca.crt',
    'tls_server_cert': pki.rstrip('/') + '/server.crt',
    'tls_server_key': pki.rstrip('/') + '/server.key',
}
if hostname:
    cfg['public_hostname'] = hostname
if bootstrap_hostname:
    cfg['bootstrap_hostname'] = bootstrap_hostname.lower()
payload = json.dumps(cfg, indent=2, sort_keys=True) + '\n'
path.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        try:
            os.unlink(tmp)
        except OSError:
            pass
PY
  chmod 600 "$path"
}

write_frps_toml() {
  local dest="$1"
  if frp_mode_is_single443; then
    frp_atomic_write "$dest" 0600 <<EOF2
bindAddr = "${FRP_CONTROL_BIND_ADDR:-127.0.0.1}"
bindPort = ${FRP_CONTROL_LISTEN_PORT}
proxyBindAddr = "0.0.0.0"

auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/server_token"

transport.tls.force = false

allowPorts = [
  { start = ${FRP_PORT_START}, end = ${FRP_PORT_END} }
]

[[httpPlugins]]
name = "frp-access"
addr = "127.0.0.1:6101"
path = "/access-auth"
ops = ["NewUserConn"]
EOF2
  else
    frp_atomic_write "$dest" 0600 <<EOF2
bindPort = ${FRP_CONTROL_LISTEN_PORT}

auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/server_token"

transport.tls.force = true

allowPorts = [
  { start = ${FRP_PORT_START}, end = ${FRP_PORT_END} }
]

[[httpPlugins]]
name = "frp-access"
addr = "127.0.0.1:6101"
path = "/access-auth"
ops = ["NewUserConn"]
EOF2
  fi
}

write_frontend_config() {
  local dest="$1" pki run_dir log_dir temp_root
  pki="$(frp_pki_dir)"
  run_dir="$(frp_server_fs /run/frp-auto-deploy)"
  log_dir="$(frp_server_fs /var/log/frp-auto-deploy)"
  temp_root="$(frp_server_fs /var/lib/frp-auto-deploy/nginx)"
  mkdir -p "$run_dir" "$log_dir" "$temp_root/body" "$temp_root/proxy" \
    "$temp_root/fastcgi" "$temp_root/uwsgi" "$temp_root/scgi"
  chmod 700 "$run_dir" "$log_dir" "$temp_root"
  python3 "$BASE_DIR/lib/frp_frontend.py" \
    --dest "$dest" \
    --public-host "$FRP_PUBLIC_HOST" \
    --frontend-port "$FRP_CONTROL_PUBLIC_PORT" \
    --allocator-listen-port "$FRP_ALLOCATOR_LISTEN_PORT" \
    --control-listen-port "$FRP_CONTROL_LISTEN_PORT" \
    --ca-cert "${pki}/ca.crt" \
    --server-cert "${pki}/server.crt" \
    --server-key "${pki}/server.key" \
    --pid-path "${run_dir}/nginx.pid" \
    --error-log stderr \
    --temp-root "$temp_root"
}

write_frontend_unit() {
  local dest="$1" src bin unit
  src="$BASE_DIR/server/frp-frontend.service"
  bin="$(frp_nginx_bin)"
  [[ -n "$bin" ]] || bin=/usr/sbin/nginx
  unit="$(mktemp)"
  python3 - "$src" "$unit" "$bin" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding='utf-8')
bin_path = sys.argv[3]
text = text.replace('ExecStart=/usr/sbin/nginx', 'ExecStart=' + bin_path)
Path(sys.argv[2]).write_text(text, encoding='utf-8')
PY
  frp_write_compatible_systemd_unit "$unit" "$dest"
  rm -f "$unit"
}

frp_frontend_validate_config() {
  local conf bin check port py
  conf="$(frp_server_fs /etc/frp-auto-deploy/frontend.conf)"
  if [[ ! -f "$conf" ]]; then
    echo "ERROR: nginx frontend configuration is missing" >&2
    return 1
  fi
  py="$BASE_DIR/lib/frp_frontend.py"
  if [[ ! -f "$py" ]]; then
    py="$(frp_server_fs /usr/local/lib/frp-auto-deploy/frp_frontend.py)"
  fi
  bin="$(frp_nginx_bin)"
  if [[ -z "$bin" || ! -x "$bin" ]]; then
    if frp_server_skip_systemd; then
      return 0
    fi
    echo "ERROR: nginx is required to validate the single-443 frontend" >&2
    return 1
  fi
  # nginx -t binds listen sockets. Never target production TCP/443: isolated
  # tests get EACCES, and live reinstall/migration hit EADDRINUSE while frps
  # or the running frontend still owns the public port.
  check="$(mktemp)"
  port=$((49152 + RANDOM % 14000))
  if ! python3 "$py" --syntax-check-from "$conf" --dest "$check" --syntax-check-port "$port"; then
    rm -f "$check"
    echo "ERROR: nginx frontend configuration could not be prepared for validation" >&2
    return 1
  fi
  chmod 600 "$check"
  if ! "$bin" -t -c "$check" >/dev/null 2>&1; then
    echo "ERROR: nginx frontend configuration is invalid" >&2
    "$bin" -t -c "$check" >&2 || true
    rm -f "$check"
    return 1
  fi
  rm -f "$check"
  return 0
}

frp_server_restore_frps_backup() {
  local backup="$1" dest="$2"
  if [[ -z "$backup" || ! -f "$backup" || -z "$dest" ]]; then
    return 0
  fi
  cp "$backup" "$dest"
  chmod 600 "$dest"
}

frp_server_lock_path() {
  frp_server_fs /var/lib/frp-auto-deploy/server-lifecycle.lock
}

frp_acquire_server_lock() {
  local lock pid
  # Fixture installs run sequentially in one shell; skip host flock there.
  if frp_server_test_mode; then
    return 0
  fi
  lock="$(frp_server_lock_path)"
  mkdir -p "$(dirname "$lock")"
  if command -v flock >/dev/null 2>&1; then
    if [[ -z "${FRP_SERVER_LOCK_FD:-}" ]]; then
      exec {FRP_SERVER_LOCK_FD}>>"$lock"
    fi
    if ! flock -n "$FRP_SERVER_LOCK_FD"; then
      echo "ERROR: another server install or lifecycle operation is already running." >&2
      exec {FRP_SERVER_LOCK_FD}>&-
      unset FRP_SERVER_LOCK_FD
      return 1
    fi
    printf '%s\n' "$$" >"${lock}.pid"
    chmod 600 "$lock" 2>/dev/null || true
    return 0
  fi
  # Stale mkdir lock from a dead PID must not block forever.
  if [[ -d "${lock}.dir" ]]; then
    pid="$(cat "${lock}.dir/pid" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      rm -rf "${lock}.dir"
    fi
  fi
  if ! mkdir "${lock}.dir" 2>/dev/null; then
    echo "ERROR: another server install or lifecycle operation is already running." >&2
    return 1
  fi
  printf '%s\n' "$$" >"${lock}.dir/pid"
  return 0
}

frp_release_server_lock() {
  local lock
  if frp_server_test_mode; then
    return 0
  fi
  lock="$(frp_server_lock_path)"
  if [[ -n "${FRP_SERVER_LOCK_FD:-}" ]]; then
    flock -u "$FRP_SERVER_LOCK_FD" 2>/dev/null || true
    exec {FRP_SERVER_LOCK_FD}>&- 2>/dev/null || true
    unset FRP_SERVER_LOCK_FD
    rm -f "${lock}.pid"
  fi
  rm -rf "${lock}.dir"
}

frp_server_lock_return_trap() {
  # bash RETURN traps fire for every nested function; only unlock when
  # frp_server_main itself is returning.
  if [[ "${FUNCNAME[0]:-}" == "frp_server_main" ]]; then
    frp_release_server_lock
  fi
}

frp_server_snapshot_root() {
  printf '%s' "${FRP_SERVER_TEST_ROOT:-/}"
}

frp_server_create_snapshot() {
  local dest="$1" py
  py="$BASE_DIR/lib/frp_install_txn.py"
  mkdir -p "$dest"
  chmod 700 "$dest"
  python3 "$py" snapshot --root "$(frp_server_snapshot_root)" --dest "$dest"
}

frp_server_rollback_snapshot() {
  local dest="${FRP_INSTALL_SNAPSHOT:-}" py
  [[ -n "$dest" && -d "$dest" ]] || return 0
  if [[ "${FRP_SERVER_UPGRADE_HOOK_ROLLBACK_SYSTEMD:-}" == "1" ]]; then
    echo "ERROR: simulated systemd service-state restoration failure" >&2
    return 1
  fi
  py="$BASE_DIR/lib/frp_install_txn.py"
  if [[ ! -f "$py" ]]; then
    py="$(frp_server_fs /usr/local/lib/frp-auto-deploy/frp_install_txn.py)"
  fi
  # Bash 4.2 (Amazon Linux 2) treats empty "${arr[@]}" as unbound under set -u.
  if ! frp_server_skip_systemd && ! frp_server_test_mode; then
    python3 "$py" restore --root "$(frp_server_snapshot_root)" --dest "$dest" --apply-services
  elif [[ -n "${FRP_INSTALL_TXN_HOOK_SYSTEMCTL:-}" ]]; then
    python3 "$py" restore --root "$(frp_server_snapshot_root)" --dest "$dest" --apply-services
  else
    python3 "$py" restore --root "$(frp_server_snapshot_root)" --dest "$dest"
  fi
}

frp_server_fail_after_mutation() {
  local class="$1"
  shift
  echo "ERROR: $*" >&2
  if ! frp_server_rollback_snapshot; then
    echo "UPGRADE_ROLLBACK=FAIL"
    echo "RECOVERY_REQUIRED=YES"
    echo "PENDING_MARKER_CLEARED=NO"
    frp_emit_failure_class UPDATE_ROLLBACK_FAILED
    frp_server_end_tmp
    return 1
  fi
  frp_emit_failure_class "$class"
  frp_txn_clear server
  frp_server_end_tmp
  return 1
}

frp_verify_frontend_proxy_health() {
  local py ca expected
  if [[ "${FRP_INSTALL_HOOK_FRONTEND_PROXY_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated frontend proxy verification failure" >&2
    return 1
  fi
  if frp_server_skip_systemd; then
    return 0
  fi
  if [[ "${FRP_INSTALLED_RUNTIME_LOADED:-0}" != "1" || -z "${FRP_PUBLIC_HOST:-}" || -z "${FRP_CONTROL_PUBLIC_PORT:-}" ]]; then
    frp_load_installed_server_runtime || return 1
  fi
  py="$BASE_DIR/lib/frp_frontend.py"
  if [[ ! -f "$py" ]]; then
    py="$(frp_server_fs /usr/local/lib/frp-auto-deploy/frp_frontend.py)"
  fi
  ca="${FRP_INSTALLED_CA_CERT:-$(frp_pki_dir)/ca.crt}"
  expected="${CA_FINGERPRINT:-}"
  python3 "$py" --verify-proxy \
    --public-host "$FRP_PUBLIC_HOST" \
    --frontend-port "$FRP_CONTROL_PUBLIC_PORT" \
    --ca-cert "$ca" \
    --expected-fingerprint "$expected"
}

frp_server_health_frontend() {
  if [[ "${FRP_INSTALL_HOOK_HEALTH_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated health check failure" >&2
    return 1
  fi
  frp_frontend_validate_config || return 1
  if ! frp_verify_frontend_proxy_health; then
    echo "ERROR: verified frontend proxy health check failed" >&2
    return 1
  fi
  if frp_server_skip_systemd; then
    return 0
  fi
  frp_wait_unit_active frp-frontend
}

frp_ensure_server_pki() {
  local pki url_host extra
  pki="$(frp_pki_dir)"
  mkdir -p "$pki"
  chmod 700 "$pki"
  url_host="$(python3 - "$FRP_ALLOCATOR_PUBLIC_URL" <<'PY'
import sys
url = sys.argv[1].strip()
if not url.lower().startswith('https://'):
    raise SystemExit(1)
rest = url[8:]
rest = rest.split('/', 1)[0]
if rest.startswith('['):
    end = rest.find(']')
    print(rest[1:end])
elif ':' in rest:
    print(rest.rsplit(':', 1)[0])
else:
    print(rest)
PY
)"
  extra=()
  if [[ -n "$url_host" && "$url_host" != "$FRP_PUBLIC_HOST" ]]; then
    extra+=(--url-host "$url_host")
  fi
  if ((${#extra[@]} > 0)); then
    python3 "$BASE_DIR/lib/frp_pki.py" ensure \
      --pki-dir "$pki" \
      --public-host "$FRP_PUBLIC_HOST" \
      "${extra[@]}"
  else
    python3 "$BASE_DIR/lib/frp_pki.py" ensure \
      --pki-dir "$pki" \
      --public-host "$FRP_PUBLIC_HOST"
  fi
}

frp_print_nat_summary() {
  local control_target alloc_target frontend_note=""
  if [[ -n "${FRP_INTERNAL_IP:-}" ]]; then
    control_target="${FRP_INTERNAL_IP}:${FRP_CONTROL_LISTEN_PORT}"
    alloc_target="${FRP_INTERNAL_IP}:${FRP_ALLOCATOR_LISTEN_PORT}"
  else
    control_target="this FRP server (TCP/${FRP_CONTROL_LISTEN_PORT})"
    alloc_target="this FRP server (TCP/${FRP_ALLOCATOR_LISTEN_PORT})"
  fi
  if frp_mode_is_single443; then
    cat <<EOF2

Network / firewall requirements (Enterprise single-443)
=======================================================

Public inbound:
  TCP/${FRP_CONTROL_PUBLIC_PORT}  HTTPS allocator + FRP control over WSS
  TCP/${FRP_PORT_START}-${FRP_PORT_END}  published services (1:1)

Do not expose the allocator backend (TCP/${FRP_ALLOCATOR_LISTEN_PORT}) or
the FRP control backend (TCP/${FRP_CONTROL_LISTEN_PORT}) on the public interface.

This installer does not change cloud security lists, host iptables, or UFW.
Open the public ports above on the network path to this server.

TCP connect succeeding while TLS ClientHello is reset on a non-443 port is a
common enterprise DPI symptom. Do not downgrade the allocator to HTTP; use
this single-443 mode instead.

EOF2
    return 0
  fi
  cat <<EOF2

Network / NAT Requirements
==========================

FRP Control
  Public:
    TCP ${FRP_PUBLIC_HOST}:${FRP_CONTROL_PUBLIC_PORT}

  Forward to:
    ${control_target}


Enrollment HTTPS
  Public:
    TCP ${FRP_PUBLIC_HOST}:${FRP_ALLOCATOR_PUBLIC_PORT}
    ${FRP_ALLOCATOR_PUBLIC_URL}

  Forward to:
    ${alloc_target}


Published Services
  Public:
    TCP ${FRP_PORT_START}-${FRP_PORT_END}

  Forward to:
    same TCP port numbers on this FRP server (1:1)

EOF2
  if [[ -z "${FRP_INTERNAL_IP:-}" ]]; then
    echo "Local bind address could not be detected automatically."
    echo "FRP control target listen port: ${FRP_CONTROL_LISTEN_PORT}"
    echo "Allocator target listen port: ${FRP_ALLOCATOR_LISTEN_PORT}"
    echo "Forward those ports to this FRP server."
    echo
  fi
  if [[ "$FRP_CONTROL_PUBLIC_PORT" == "$FRP_CONTROL_LISTEN_PORT" && "$FRP_ALLOCATOR_PUBLIC_PORT" == "$FRP_ALLOCATOR_LISTEN_PORT" ]]; then
    echo "Public and internal ports match; no NAT remapping is required for FRP or the allocator."
    echo
  fi
}

frp_server_begin_tmp() {
  TMPDIR="$(frp_secure_mktemp_dir)"
  FRP_SERVER_SAVED_EXIT_TRAP="$(trap -p EXIT || true)"
  # shellcheck disable=SC2064
  trap "rm -rf $(printf '%q' "$TMPDIR")" EXIT
}

frp_server_end_tmp() {
  if [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]]; then
    rm -rf "$TMPDIR"
  fi
  if [[ -n "${FRP_SERVER_SAVED_EXIT_TRAP:-}" ]]; then
    eval "$FRP_SERVER_SAVED_EXIT_TRAP"
  else
    trap - EXIT
  fi
}

frp_server_ensure_sandbox_dirs() {
  # Persistent paths listed in unit ReadWritePaths must exist before systemd
  # starts the allocator/frontend. Missing dirs cause status=226/NAMESPACE.
  local etc_frp etc_proj var_lib var_log run_dir
  etc_frp="$(frp_server_fs /etc/frp)"
  etc_proj="$(frp_server_fs /etc/frp-auto-deploy)"
  var_lib="$(frp_server_fs /var/lib/frp-auto-deploy)"
  var_log="$(frp_server_fs /var/log/frp-auto-deploy)"
  run_dir="$(frp_server_fs /run/frp-auto-deploy)"
  mkdir -p "$etc_frp" "$etc_proj" "$var_lib" "$var_log" "$run_dir"
  chmod 700 "$etc_frp" "$etc_proj" "$var_lib" "$var_log" "$run_dir"
  if [[ ${EUID} -eq 0 ]]; then
    chown root:root "$etc_frp" "$etc_proj" "$var_lib" "$var_log" 2>/dev/null || true
  fi
}

frp_server_skip_systemd() {
  frp_server_test_mode || [[ "${FRP_INSTALL_HOOK_SKIP_SYSTEMD:-}" == "1" ]]
}

frp_server_record_action() {
  local log
  log="$(frp_server_fs /var/lib/frp-auto-deploy/install-actions.log)"
  mkdir -p "$(dirname "$log")"
  printf '%s\n' "$1" >>"$log"
}

frp_server_enable_units() {
  if frp_server_skip_systemd; then
    if frp_mode_is_single443; then
      frp_server_record_action "enable frps frp-access-plugin frp-egress-gateway frp-port-allocator frp-frontend"
    else
      frp_server_record_action "enable frps frp-access-plugin frp-egress-gateway frp-port-allocator"
      frp_server_record_action "disable frp-frontend"
    fi
    if [[ "${FRP_INSTALL_HOOK_ENABLE_FAIL:-}" == "1" ]]; then
      echo "ERROR: simulated systemctl enable failure" >&2
      return 1
    fi
    return 0
  fi
  if frp_mode_is_single443; then
    frp_server_systemctl enable frps frp-access-plugin frp-egress-gateway frp-port-allocator frp-frontend >/dev/null
  else
    frp_server_systemctl enable frps frp-access-plugin frp-egress-gateway frp-port-allocator >/dev/null
    frp_server_systemctl disable --now frp-frontend >/dev/null 2>&1 || true
  fi
}

frp_server_restart_unit() {
  local unit="$1"
  if frp_server_skip_systemd; then
    frp_server_record_action "restart ${unit}"
    if [[ "${FRP_INSTALL_HOOK_START_FAIL:-}" == "1" ]]; then
      echo "ERROR: simulated systemd start failure" >&2
      return 1
    fi
    return 0
  fi
  frp_server_systemctl restart "$unit"
}

frp_server_health_frps() {
  if [[ "${FRP_INSTALL_HOOK_HEALTH_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated health check failure" >&2
    return 1
  fi
  if frp_server_skip_systemd; then
    return 0
  fi
  frp_wait_unit_active frps
}

frp_server_health_allocator() {
  local port="$1"
  if [[ "${FRP_INSTALL_HOOK_HEALTH_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated health check failure" >&2
    return 1
  fi
  if frp_server_skip_systemd; then
    return 0
  fi
  frp_wait_allocator_ready "$port"
}

frp_server_health_access() {
  # Access plugin readiness: unit active AND GET /healthz == 200.
  local addr url code
  if [[ "${FRP_INSTALL_HOOK_HEALTH_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated health check failure" >&2
    return 1
  fi
  if frp_server_skip_systemd; then
    return 0
  fi
  frp_wait_unit_active frp-access-plugin || return 1
  addr="${FRP_ACCESS_PLUGIN_ADDR:-127.0.0.1:6101}"
  if [[ -r "$(frp_server_fs /etc/frp-auto-deploy/config.json)" ]]; then
    addr="$(python3 - "$(frp_server_fs /etc/frp-auto-deploy/config.json)" <<'PY' 2>/dev/null || true
import json, sys
from pathlib import Path
try:
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
print(str(cfg.get("access_plugin_addr") or "127.0.0.1:6101").strip())
PY
)"
  fi
  [[ -n "$addr" ]] || addr="127.0.0.1:6101"
  url="http://${addr}/healthz"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 "$url" 2>/dev/null || echo 000)"
  if [[ "$code" != "200" ]]; then
    echo "ERROR: access plugin /healthz returned ${code} (expected 200)" >&2
    return 1
  fi
  return 0
}

frp_server_health_egress() {
  # Egress gateway readiness: unit active. Isolated from inbound FRP health.
  if [[ "${FRP_INSTALL_HOOK_EGRESS_HEALTH_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated egress health check failure" >&2
    return 1
  fi
  if frp_server_skip_systemd; then
    return 0
  fi
  frp_wait_unit_active frp-egress-gateway || return 1
  return 0
}

frp_server_install_frp_binary() {
  local dest archive url extracted
  dest="$(frp_server_fs /usr/local/bin/frps)"
  if [[ "${FRP_INSTALL_HOOK_DOWNLOAD_FAIL:-}" == "1" ]]; then
    echo "ERROR: failed to download FRP archive" >&2
    frp_emit_failure_class DOWNLOAD_FAILED
    return 1
  fi
  if [[ -n "${FRP_INSTALL_HOOK_NEW_BINARY:-}" ]]; then
    [[ -x "${FRP_INSTALL_HOOK_NEW_BINARY}" ]] || {
      echo "ERROR: fixture binary is missing" >&2
      frp_emit_failure_class STAGING_FAILED
      return 1
    }
    if [[ "${FRP_INSTALL_HOOK_CHECKSUM_FAIL:-}" == "1" ]]; then
      echo "ERROR: SHA256 checksum mismatch" >&2
      frp_emit_failure_class INTEGRITY_FAILED
      return 1
    fi
    frp_validate_frp_binary "${FRP_INSTALL_HOOK_NEW_BINARY}" "$FRP_VERSION" "$FRP_ARCH" || {
      frp_emit_failure_class INTEGRITY_FAILED
      return 1
    }
    frp_atomic_install "${FRP_INSTALL_HOOK_NEW_BINARY}" "$dest" 0755 || {
      frp_emit_failure_class FILE_COMMIT_FAILED
      return 1
    }
    return 0
  fi

  if [[ -x "$dest" ]]; then
    if [[ "$(frp_parse_binary_version "$dest")" == "$FRP_VERSION" ]]; then
      echo "Existing frps ${FRP_VERSION} reused."
      return 0
    fi
  fi

  archive="${TMPDIR}/frp.tar.gz"
  url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz"
  echo "Downloading official FRP ${FRP_VERSION} (${FRP_ARCH}) ..."
  if ! curl -fL --retry 3 -o "$archive" "$url"; then
    echo "ERROR: failed to download FRP archive" >&2
    frp_emit_failure_class DOWNLOAD_FAILED
    return 1
  fi
  printf '%s  %s\n' "$EXPECTED_SHA" "$archive" | sha256sum -c - || {
    frp_emit_failure_class INTEGRITY_FAILED
    return 1
  }
  extracted="$(frp_extract_frp_member "$archive" "$TMPDIR" frps)" || {
    frp_emit_failure_class STAGING_FAILED
    return 1
  }
  frp_validate_frp_binary "$extracted" "$FRP_VERSION" "$FRP_ARCH" || {
    frp_emit_failure_class INTEGRITY_FAILED
    return 1
  }
  # Final path remains /usr/local/bin/frps (prefixed only in isolated tests).
  frp_atomic_install "$extracted" "$dest" 0755 || {
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  }
}

frp_server_main() {
  if [[ ${EUID} -ne 0 ]] && ! frp_server_test_mode; then
    echo "ERROR: run with sudo" >&2
    return 1
  fi
  # Server install/reinstall owns the server transaction marker only.
  FRP_TXN_ROLE=server
  export FRP_TXN_ROLE
  if ! frp_acquire_server_lock; then
    return 1
  fi
  trap 'frp_server_lock_return_trap' RETURN

  frp_server_prepare_host

  if ! frp_server_test_mode; then
    DETECTED_PUBLIC_IP="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
  else
    DETECTED_PUBLIC_IP="${DETECTED_PUBLIC_IP:-}"
  fi
  DETECTED_INTERNAL_IP="$(frp_detect_internal_ip)"

  load_existing_server_config
  resolve_server_settings

  if frp_mode_is_single443; then
    if ! frp_nginx_preflight; then
      frp_emit_failure_class INSTALL_PRECHECK_FAILED
      return 1
    fi
    if ! frp_ensure_nginx; then
      frp_emit_failure_class DEPENDENCY_INSTALL_FAILED
      return 1
    fi
    frp_nginx_reconcile_distro_unit
    if ! frp_frontend_port_preflight; then
      frp_emit_failure_class INSTALL_PRECHECK_FAILED
      return 1
    fi
  fi

  if [[ -z "${FRP_ARCH:-}" ]]; then
    frp_detect_architecture || return 1
  fi

  local etc_frp etc_proj var_lib version_file token_file frps_toml
  local registry_file access_control_file service_profiles_file egress_control_file backups_dir lib_dir unit_frps unit_alloc unit_access unit_egress unit_frontend sbin_dir
  local frontend_conf toml_backup
  etc_frp="$(frp_server_fs /etc/frp)"
  etc_proj="$(frp_server_fs /etc/frp-auto-deploy)"
  var_lib="$(frp_server_fs /var/lib/frp-auto-deploy)"
  version_file="$(frp_server_fs /etc/frp-auto-deploy/version)"
  token_file="$(frp_server_fs /etc/frp/server_token)"
  frps_toml="$(frp_server_fs /etc/frp/frps.toml)"
  frontend_conf="$(frp_server_fs /etc/frp-auto-deploy/frontend.conf)"
  registry_file="$(frp_server_fs /var/lib/frp-auto-deploy/registry.json)"
  access_control_file="$(frp_server_fs /var/lib/frp-auto-deploy/access-control.json)"
  egress_control_file="$(frp_server_fs /var/lib/frp-auto-deploy/egress-control.json)"
  backups_dir="$(frp_server_fs /var/lib/frp-auto-deploy/backups)"
  lib_dir="$(frp_server_fs /usr/local/lib/frp-auto-deploy)"
  unit_frps="$(frp_server_fs /etc/systemd/system/frps.service)"
  unit_alloc="$(frp_server_fs /etc/systemd/system/frp-port-allocator.service)"
  unit_access="$(frp_server_fs /etc/systemd/system/frp-access-plugin.service)"
  unit_egress="$(frp_server_fs /etc/systemd/system/frp-egress-gateway.service)"
  unit_frontend="$(frp_server_fs /etc/systemd/system/frp-frontend.service)"
  sbin_dir="$(frp_server_fs /usr/local/sbin)"

  local existing_install=0
  if [[ -f "$(frp_server_config_path)" || -s "$token_file" || -f "$registry_file" ]]; then
    existing_install=1
  fi
  local previous_project
  previous_project="$(frp_read_kv_file "$version_file" PROJECT_VERSION)"
  if [[ -n "$previous_project" ]]; then
    local vcmp
    vcmp="$(frp_version_compare "$previous_project" "$PROJECT_VERSION")"
    if [[ "$vcmp" == "gt" ]]; then
      echo "ERROR: installed project version ${previous_project} is newer than this bundle (${PROJECT_VERSION})." >&2
      echo "Refusing to downgrade. Use the matching release or restore from backup." >&2
      return 1
    fi
  fi

  local hash_frps_before hash_toml_before hash_unit_frps_before hash_unit_alloc_before
  local hash_unit_access_before hash_access_plugin_before hash_access_lib_before
  local hash_unit_egress_before hash_egress_gateway_before hash_egress_lib_before
  local hash_frontend_conf_before hash_unit_frontend_before
  local hash_alloc_helpers_before=() alloc_helper_rel
  hash_frps_before="$(frp_file_sha256 "$(frp_server_fs /usr/local/bin/frps)")"
  hash_toml_before="$(frp_file_sha256 "$frps_toml")"
  hash_unit_frps_before="$(frp_file_sha256 "$unit_frps")"
  hash_unit_alloc_before="$(frp_file_sha256 "$unit_alloc")"
  hash_unit_access_before="$(frp_file_sha256 "$unit_access")"
  hash_access_plugin_before="$(frp_file_sha256 "${lib_dir}/frp-access-plugin.py")"
  hash_access_lib_before="$(frp_file_sha256 "${lib_dir}/frp_access_control.py")"
  hash_unit_egress_before="$(frp_file_sha256 "$unit_egress")"
  hash_egress_gateway_before="$(frp_file_sha256 "${lib_dir}/frp-egress-gateway.py")"
  hash_egress_lib_before="$(frp_file_sha256 "${lib_dir}/frp_egress_control.py")"
  # Any Python module imported by the allocator must be listed in FRP_ALLOCATOR_RUNTIME_HELPERS.
  for alloc_helper_rel in frp-port-allocator.py "${FRP_ALLOCATOR_RUNTIME_HELPERS[@]}"; do
    hash_alloc_helpers_before+=("$(frp_file_sha256 "${lib_dir}/${alloc_helper_rel}")")
  done
  hash_frontend_conf_before="$(frp_file_sha256 "$frontend_conf")"
  hash_unit_frontend_before="$(frp_file_sha256 "$unit_frontend")"

  # Capture existing listeners before restarting an existing frps. On first migration,
  # this preserves ports such as 6000/6001 already used by unmanaged clients.
  ACTIVE_PORTS="$(frp_listening_tcp_ports_in_range "$FRP_PORT_START" "$FRP_PORT_END")"

  FRP_INSTALL_SNAPSHOT="${backups_dir}/pre-install-snapshot"
  frp_server_create_snapshot "$FRP_INSTALL_SNAPSHOT"

  frp_server_begin_tmp
  frp_txn_write install commit "${previous_project}" "${PROJECT_VERSION}"

  if ! frp_server_install_frp_binary; then
    frp_server_rollback_snapshot
    frp_txn_clear server
    frp_server_end_tmp
    return 1
  fi

  mkdir -p "${var_lib}/enrollments" "${var_lib}/bootstrap" "$backups_dir" "$lib_dir" "$sbin_dir" \
    "$(dirname "$unit_frps")"
  frp_server_ensure_sandbox_dirs
  chmod 700 "$etc_frp" "$etc_proj" "$var_lib" "${var_lib}/enrollments" "${var_lib}/bootstrap" "$backups_dir"
  if [[ ${EUID} -eq 0 ]]; then
    chown root:root "$etc_frp" "$etc_proj" "$var_lib" "$(frp_server_fs /var/log/frp-auto-deploy)" 2>/dev/null || true
  fi

  TOKEN_ACTION=""
  TOKEN_PRESERVED="N/A"
  TOKEN_BACKUP=""
  migrate_out="$(python3 "$BASE_DIR/server/migrate_token.py" ensure --etc-dir "$etc_frp" --backup)"
  while IFS= read -r line; do
    case "$line" in
      TOKEN_ACTION=*|TOKEN_PRESERVED=*|TOKEN_BACKUP=*)
        printf -v "${line%%=*}" '%s' "${line#*=}"
        ;;
    esac
  done <<< "$migrate_out"
  [[ -s "$token_file" ]] || { frp_server_fail_after_mutation FILE_COMMIT_FAILED "FRP server token is missing after migration"; return 1; }
  chmod 600 "$token_file"

  toml_backup=""
  if [[ -f "$frps_toml" ]]; then
    toml_backup="${backups_dir}/frps.toml.pre-install"
    cp "$frps_toml" "$toml_backup"
    chmod 600 "$toml_backup"
  fi

  write_frps_toml "$frps_toml"
  "$(frp_server_fs /usr/local/bin/frps)" verify -c "$frps_toml" || {
    frp_server_fail_after_mutation STAGING_FAILED "generated frps.toml failed verification"
    return 1
  }

  write_server_config
  pki_out="$(frp_ensure_server_pki)"
  CA_FINGERPRINT=""
  PKI_ACTION=""
  while IFS= read -r line; do
    case "$line" in
      PKI_ACTION=*|CA_FINGERPRINT=*|TLS_CA_CERT=*|TLS_SERVER_CERT=*|TLS_SERVER_KEY=*)
        printf -v "${line%%=*}" '%s' "${line#*=}"
        ;;
    esac
  done <<< "$pki_out"
  [[ -n "$CA_FINGERPRINT" ]] || { frp_server_fail_after_mutation FILE_COMMIT_FAILED "allocator CA fingerprint is missing"; return 1; }

  REGISTRY_ACTION=""
  MIGRATED_CLIENTS="0"
  PRESERVED_PORTS="0"
  registry_out="$(python3 "$BASE_DIR/server/migrate_token.py" init-registry \
    --registry "$registry_file" \
    --ports "$ACTIVE_PORTS" \
    --port-start "$FRP_PORT_START" \
    --port-end "$FRP_PORT_END" \
    --allocator-port "$FRP_ALLOCATOR_PORT")"
  while IFS= read -r line; do
    case "$line" in
      REGISTRY_ACTION=*|MIGRATED_CLIENTS=*|PRESERVED_PORTS=*)
        printf -v "${line%%=*}" '%s' "${line#*=}"
        ;;
    esac
  done <<< "$registry_out"
  [[ -f "$registry_file" ]] || { frp_server_fail_after_mutation FILE_COMMIT_FAILED "registry.json is missing"; return 1; }
  chmod 600 "$registry_file"

  if [[ ! -f "$access_control_file" ]]; then
    if ! python3 - "$access_control_file" "$BASE_DIR/lib/frp_access_control.py" <<'PY'
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("frp_access_control", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
path = Path(sys.argv[1])
mod.save_access_state(mod.empty_access_state(), path=path)
PY
    then
      frp_server_fail_after_mutation FILE_COMMIT_FAILED "failed to create access-control.json"
      return 1
    fi
  fi
  [[ -f "$access_control_file" ]] || { frp_server_fail_after_mutation FILE_COMMIT_FAILED "access-control.json is missing"; return 1; }

  service_profiles_file="$(frp_server_fs /var/lib/frp-auto-deploy/service-profiles.json)"
  if [[ ! -f "$service_profiles_file" ]]; then
    if ! python3 - "$service_profiles_file" "$BASE_DIR/lib/frp_service_profiles.py" <<'PY'
import importlib.util, sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("frp_service_profiles", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.save_profiles_state(mod.empty_profiles_state(), path=path)
print(path)
PY
    then
      frp_server_fail_after_mutation FILE_COMMIT_FAILED "failed to create service-profiles.json"
      return 1
    fi
  fi
  chmod 600 "$service_profiles_file"
  [[ -f "$service_profiles_file" ]] || { frp_server_fail_after_mutation FILE_COMMIT_FAILED "service-profiles.json is missing"; return 1; }
  chmod 600 "$access_control_file"

  if [[ ! -f "$egress_control_file" ]]; then
    if ! python3 - "$egress_control_file" "$BASE_DIR/lib/frp_egress_control.py" <<'PY'
import importlib.util, sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("frp_egress_control", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.save_egress_state(mod.empty_egress_state(), path=path)
print(path)
PY
    then
      frp_server_fail_after_mutation FILE_COMMIT_FAILED "failed to create egress-control.json"
      return 1
    fi
  fi
  chmod 600 "$egress_control_file"
  [[ -f "$egress_control_file" ]] || { frp_server_fail_after_mutation FILE_COMMIT_FAILED "egress-control.json is missing"; return 1; }

  # Ensure Controlled Egress keys exist on upgrades without rewriting unrelated config.
  if [[ -f "$(frp_server_fs /etc/frp-auto-deploy/config.json)" ]]; then
    python3 - "$(frp_server_fs /etc/frp-auto-deploy/config.json)" <<'PY' || true
import json, sys, tempfile, os
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text(encoding="utf-8"))
changed = False
defaults = {
    "egress_control_file": "/var/lib/frp-auto-deploy/egress-control.json",
    "egress_conn_log_file": "/var/log/frp-auto-deploy/egress-conn.jsonl",
    "egress_listen_addr": "0.0.0.0",
    "egress_listen_port": 6080,
}
for key, value in defaults.items():
    if key not in cfg or cfg.get(key) in (None, ""):
        cfg[key] = value
        changed = True
if changed:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
PY
  fi

  frp_server_install_manifest_files "$lib_dir" "$sbin_dir"
  install -m 0644 "$BASE_DIR/server/frps.service" "$unit_frps"
  frp_write_compatible_systemd_unit \
    "$BASE_DIR/server/frp-port-allocator.service" \
    "$unit_alloc"
  frp_write_compatible_systemd_unit \
    "$BASE_DIR/server/frp-access-plugin.service" \
    "$unit_access"
  frp_write_compatible_systemd_unit \
    "$BASE_DIR/server/frp-egress-gateway.service" \
    "$unit_egress"
  if frp_mode_is_single443; then
    write_frontend_config "$frontend_conf"
    write_frontend_unit "$unit_frontend"
  else
    rm -f "$unit_frontend" "$frontend_conf"
  fi

  local need_frps_restart=0 need_alloc_restart=0 need_access_restart=0 need_egress_restart=0 need_frontend_restart=0
  if [[ "$existing_install" != "1" ]]; then
    need_frps_restart=1
    need_alloc_restart=1
    need_access_restart=1
    need_egress_restart=1
    if frp_mode_is_single443; then
      need_frontend_restart=1
    fi
  else
    if [[ "$(frp_file_sha256 "$(frp_server_fs /usr/local/bin/frps)")" != "$hash_frps_before" ]]; then
      need_frps_restart=1
    fi
    if [[ "$(frp_file_sha256 "$frps_toml")" != "$hash_toml_before" ]]; then
      need_frps_restart=1
    fi
    if [[ "$(frp_file_sha256 "$unit_frps")" != "$hash_unit_frps_before" ]]; then
      need_frps_restart=1
    fi
    if [[ "$(frp_file_sha256 "$unit_alloc")" != "$hash_unit_alloc_before" ]]; then
      need_alloc_restart=1
    fi
    local _alloc_idx=0
    for alloc_helper_rel in frp-port-allocator.py "${FRP_ALLOCATOR_RUNTIME_HELPERS[@]}"; do
      if [[ "$(frp_file_sha256 "${lib_dir}/${alloc_helper_rel}")" != "${hash_alloc_helpers_before[_alloc_idx]}" ]]; then
        need_alloc_restart=1
      fi
      _alloc_idx=$((_alloc_idx + 1))
    done
    if [[ "$(frp_file_sha256 "$unit_access")" != "$hash_unit_access_before" ]]; then
      need_access_restart=1
    fi
    if [[ "$(frp_file_sha256 "${lib_dir}/frp-access-plugin.py")" != "$hash_access_plugin_before" ]]; then
      need_access_restart=1
    fi
    if [[ "$(frp_file_sha256 "${lib_dir}/frp_access_control.py")" != "$hash_access_lib_before" ]]; then
      need_access_restart=1
    fi
    if [[ "$(frp_file_sha256 "$unit_egress")" != "$hash_unit_egress_before" ]]; then
      need_egress_restart=1
    fi
    if [[ "$(frp_file_sha256 "${lib_dir}/frp-egress-gateway.py")" != "$hash_egress_gateway_before" ]]; then
      need_egress_restart=1
    fi
    if [[ "$(frp_file_sha256 "${lib_dir}/frp_egress_control.py")" != "$hash_egress_lib_before" ]]; then
      need_egress_restart=1
    fi
    if [[ "${PKI_ACTION:-}" == "reissued-server" || "${PKI_ACTION:-}" == "generated" ]]; then
      need_alloc_restart=1
      if frp_mode_is_single443; then
        need_frontend_restart=1
      fi
    fi
    if frp_mode_is_single443; then
      if [[ "$(frp_file_sha256 "$frontend_conf")" != "$hash_frontend_conf_before" ]]; then
        need_frontend_restart=1
      fi
      if [[ "$(frp_file_sha256 "$unit_frontend")" != "$hash_unit_frontend_before" ]]; then
        need_frontend_restart=1
      fi
    fi
    if [[ "${FRP_MODE_SWITCH:-0}" == "1" ]]; then
      need_frps_restart=1
      need_alloc_restart=1
      need_access_restart=1
      need_egress_restart=1
      if frp_mode_is_single443; then
        need_frontend_restart=1
      fi
    fi
  fi

  frp_server_ensure_sandbox_dirs
  if ! frp_server_skip_systemd; then
    systemctl daemon-reload || {
      frp_server_fail_after_mutation SYSTEMD_RELOAD_FAILED "systemd daemon-reload failed"
      return 1
    }
  else
    frp_server_record_action "daemon-reload"
  fi

  if ! frp_server_enable_units; then
    frp_server_fail_after_mutation SYSTEMD_ENABLE_FAILED "systemd enable failed; installation is not complete."
    return 1
  fi

  if frp_mode_is_single443; then
    if ! frp_frontend_validate_config; then
      frp_server_fail_after_mutation STAGING_FAILED "frontend configuration is invalid; FRP listeners were not restarted."
      return 1
    fi
  fi

  if [[ "$need_access_restart" == "1" ]]; then
    if ! frp_server_restart_unit frp-access-plugin; then
      frp_server_fail_after_mutation SERVICE_START_FAILED "frp-access-plugin failed to start; installation is not complete."
      return 1
    fi
  fi
  if [[ "$need_egress_restart" == "1" ]]; then
    if ! frp_server_restart_unit frp-egress-gateway; then
      frp_server_fail_after_mutation SERVICE_START_FAILED "frp-egress-gateway failed to start; installation is not complete."
      return 1
    fi
  fi
  if [[ "$need_frps_restart" == "1" ]]; then
    if ! frp_server_restart_unit frps; then
      frp_server_fail_after_mutation SERVICE_START_FAILED "frps failed to start; installation is not complete."
      return 1
    fi
  fi
  if [[ "$need_alloc_restart" == "1" ]]; then
    if ! frp_server_restart_unit frp-port-allocator; then
      frp_server_fail_after_mutation SERVICE_START_FAILED "frp-port-allocator failed to start; previous semantic configuration restored."
      return 1
    fi
  fi
  if [[ "$need_frontend_restart" == "1" ]]; then
    if ! frp_server_restart_unit frp-frontend; then
      frp_server_fail_after_mutation SERVICE_START_FAILED "frp-frontend failed to start; previous semantic configuration restored."
      return 1
    fi
  fi

  if [[ "$need_frps_restart" == "1" ]] || [[ "$existing_install" != "1" ]]; then
    if ! frp_server_health_frps; then
      frp_server_fail_after_mutation HEALTH_CHECK_FAILED "frps health check failed; previous semantic configuration restored."
      return 1
    fi
  fi
  if [[ "$need_alloc_restart" == "1" ]] || [[ "$existing_install" != "1" ]]; then
    if ! frp_server_health_allocator "$FRP_ALLOCATOR_LISTEN_PORT"; then
      frp_server_fail_after_mutation HEALTH_CHECK_FAILED "allocator health check failed; previous semantic configuration restored."
      return 1
    fi
  fi
  if [[ "$need_access_restart" == "1" ]] || [[ "$existing_install" != "1" ]] || [[ "$need_frps_restart" == "1" ]]; then
    if ! frp_server_health_access; then
      frp_server_fail_after_mutation HEALTH_CHECK_FAILED "access plugin health check failed; previous semantic configuration restored."
      return 1
    fi
  fi
  if [[ "$need_egress_restart" == "1" ]] || [[ "$existing_install" != "1" ]]; then
    if ! frp_server_health_egress; then
      frp_server_fail_after_mutation HEALTH_CHECK_FAILED "egress gateway health check failed; previous semantic configuration restored."
      return 1
    fi
  fi
  if frp_mode_is_single443; then
    if ! frp_server_health_frontend; then
      frp_server_fail_after_mutation HEALTH_CHECK_FAILED "verified frontend proxy health check failed; previous semantic configuration restored."
      return 1
    fi
  fi

  # Version metadata is written only after a successful install/reinstall.
  frp_write_version_file "$(frp_server_fs /etc/frp-auto-deploy/version)"
  frp_txn_clear server
  frp_prune_backup_dirs "$backups_dir" "$FRP_BACKUP_KEEP"
  frp_server_end_tmp
  FRP_INSTALL_SNAPSHOT=""

  cat <<EOF2

============================================================
 FRP Auto Deploy server installation complete
============================================================

Project version   : ${PROJECT_VERSION}
FRP version       : ${FRP_VERSION}
Deployment mode   : ${FRP_DEPLOYMENT_MODE}
Public IP         : ${FRP_PUBLIC_IP}
Public hostname   : ${FRP_PUBLIC_HOSTNAME:-not configured}
Bootstrap hostname: ${FRP_BOOTSTRAP_HOSTNAME:-not configured}
FRP control public: TCP/${FRP_CONTROL_PUBLIC_PORT}
FRP transport     : ${FRP_TRANSPORT}
FRP control listen: TCP/${FRP_CONTROL_LISTEN_PORT} (${FRP_CONTROL_BIND_ADDR})
Allocator public  : ${FRP_ALLOCATOR_PUBLIC_URL}
Allocator listen  : TCP/${FRP_ALLOCATOR_LISTEN_PORT} (${FRP_LISTEN_HOST})
Service range     : TCP/${FRP_PORT_START}-${FRP_PORT_END}
TLS CA SHA256     : ${CA_FINGERPRINT}
EOF2
  if [[ -n "$ACTIVE_PORTS" ]]; then
    echo "Preserved existing ports as reserved: $ACTIVE_PORTS"
  fi
  if [[ "$TOKEN_PRESERVED" == "PASS" ]]; then
    echo "Existing FRP authentication token preserved: TOKEN_PRESERVED=PASS"
  elif [[ "$TOKEN_ACTION" == "generated" ]]; then
    echo "Generated a new FRP authentication token for this fresh install."
  fi
  if [[ -n "$TOKEN_BACKUP" ]]; then
    echo "Existing frps.toml backed up with mode 600"
  fi
  if [[ "${PKI_ACTION:-}" == "reused" ]]; then
    echo "Existing allocator CA preserved."
  elif [[ "${PKI_ACTION:-}" == "reissued-server" ]]; then
    echo "Reissued allocator server certificate using the existing CA."
  elif [[ "${PKI_ACTION:-}" == "generated" ]]; then
    echo "Generated a new allocator private CA and server certificate."
  fi
  if [[ "$existing_install" == "1" && "$need_frps_restart" != "1" && "$need_alloc_restart" != "1" && "$need_frontend_restart" != "1" ]]; then
    echo "Runtime services were not restarted (project files only)."
  fi
  frp_print_nat_summary
  cat <<EOF2
Create a client enrollment:
  sudo frpctl create-client
  sudo frp-create-client

Everyday command (remember this one):
  sudo frpctl
  Then type help inside the CLI.

Check schema v2 deployment readiness:
  sudo frpctl status
  sudo frp-server-status
  sudo frp-server-status --check

Update FRP to the tested version:
  sudo frpctl update
  sudo frp-update

List clients:
  sudo frp-clients

============================================================
EOF2
}

if [[ "${FRP_SERVER_SOURCED:-}" != "1" ]]; then
  if [[ "${1:-}" == "--upgrade" || "${1:-}" == "upgrade" ]]; then
    shift
    FRP_SERVER_UPGRADE_CHECK=0
    FRP_SERVER_UPGRADE_SOURCE="$BASE_DIR"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --check|--dry-run) FRP_SERVER_UPGRADE_CHECK=1; shift ;;
        --source)
          if [[ $# -lt 2 || "$2" == --* ]]; then
            echo "ERROR: --source requires a directory" >&2
            exit 2
          fi
          FRP_SERVER_UPGRADE_SOURCE="$2"
          shift 2
          ;;
        *) echo "ERROR: unknown server upgrade option: $1" >&2; exit 2 ;;
      esac
    done
    frp_server_apply_project_upgrade "$FRP_SERVER_UPGRADE_SOURCE" "$FRP_SERVER_UPGRADE_CHECK" || exit $?
  else
    frp_server_main "$@" || exit $?
  fi
fi
