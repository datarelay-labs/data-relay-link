#!/usr/bin/env bash
# Apple Silicon macOS filesystem, identity, checksum, and launchd helpers.

if [[ -n "${FRP_MACOS_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
FRP_MACOS_LOADED=1

FRP_MACOS_LAUNCHD_LABEL="${FRP_MACOS_LAUNCHD_LABEL:-com.datarelay.frp-auto-deploy.frpc}"
FRP_MACOS_STATE_ROOT_DEFAULT='/Library/Application Support/frp-auto-deploy'
FRP_MACOS_LAUNCHDAEMON_DIR='/Library/LaunchDaemons'
FRP_MACOS_MIN_PRODUCT_VERSION="${FRP_MACOS_MIN_PRODUCT_VERSION:-11}"

frp_macos_state_root() {
  printf '%s' "${FRP_MACOS_STATE_ROOT:-$FRP_MACOS_STATE_ROOT_DEFAULT}"
}

frp_macos_plist_path() {
  printf '%s/%s.plist' "$FRP_MACOS_LAUNCHDAEMON_DIR" "$FRP_MACOS_LAUNCHD_LABEL"
}

frp_macos_brew_prefix() {
  local prefix="" brew_bin=""
  if [[ -n "${FRP_MACOS_PREFIX:-}" ]]; then
    printf '%s' "$FRP_MACOS_PREFIX"
    return 0
  fi
  if frp_command_exists brew; then
    prefix="$(frp_invoke brew --prefix 2>/dev/null || true)"
    prefix="${prefix%%$'\n'*}"
    if [[ -z "$prefix" ]]; then
      brew_bin="$(frp_invoke command -v brew 2>/dev/null || true)"
      [[ -n "$brew_bin" ]] && prefix="$(dirname "$(dirname "$brew_bin")")"
    fi
  fi
  case "$prefix" in
    /*) [[ -d "$prefix" ]] || prefix=/usr/local ;;
    *) prefix=/usr/local ;;
  esac
  printf '%s' "${prefix%/}"
}

frp_macos_map_path() {
  local p="${1:-}" state prefix
  if ! frp_is_darwin; then printf '%s' "$p"; return 0; fi
  state="$(frp_macos_state_root)"
  case "$p" in
    /etc/frp|/etc/frp-auto-deploy) printf '%s' "$state"; return ;;
    /etc/frp/*) printf '%s/%s' "$state" "${p#/etc/frp/}"; return ;;
    /etc/frp-auto-deploy/*) printf '%s/%s' "$state" "${p#/etc/frp-auto-deploy/}"; return ;;
    /var/lib/frp-auto-deploy) printf '%s/state' "$state"; return ;;
    /var/lib/frp-auto-deploy/*) printf '%s/state/%s' "$state" "${p#/var/lib/frp-auto-deploy/}"; return ;;
    /etc/systemd/system/frpc.service) frp_macos_plist_path; return ;;
    /usr/local/lib/frp-auto-deploy) printf '%s/lib' "$state"; return ;;
    /usr/local/lib/frp-auto-deploy/*) printf '%s/lib/%s' "$state" "${p#/usr/local/lib/frp-auto-deploy/}"; return ;;
    /usr/local/bin/frpc) printf '%s/bin/frpc' "$state"; return ;;
  esac
  prefix="$(frp_macos_brew_prefix)"
  case "$p" in
    /usr/local/bin/*) printf '%s/bin/%s' "$prefix" "${p#/usr/local/bin/}" ;;
    /usr/local/sbin/*) printf '%s/sbin/%s' "$prefix" "${p#/usr/local/sbin/}" ;;
    *) printf '%s' "$p" ;;
  esac
}

frp_macos_fs() {
  local p root
  p="$(frp_macos_map_path "$1")"
  root="${FRP_CLIENT_TEST_ROOT:-${FRP_CTL_TEST_ROOT:-${FRP_UNINSTALL_TEST_ROOT:-${FRP_DEPLOY_TEST_ROOT:-}}}}"
  [[ -n "$root" ]] && printf '%s' "${root}${p}" || printf '%s' "$p"
}

frp_macos_ensure_dirs() {
  local state dir
  frp_is_darwin || return 0
  state="$(frp_macos_fs /etc/frp)"
  for dir in "$state" "$state/bin" "$state/lib" "$state/state" "$state/logs"; do
    mkdir -p "$dir" || return 1
    chmod 0755 "$dir" 2>/dev/null || true
    if [[ ${EUID} -eq 0 ]]; then chown root:wheel "$dir" 2>/dev/null || true; fi
  done
  chmod 0750 "$state/logs" 2>/dev/null || true
}

frp_macos_platform_uuid() {
  local uuid="${FRP_TEST_IOPLATFORM_UUID:-}"
  if [[ -z "$uuid" ]] && frp_command_exists ioreg; then
    uuid="$(frp_invoke ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null |
      awk -F'"' '/IOPlatformUUID/ {print $4; exit}')"
  fi
  uuid="$(printf '%s' "$uuid" | tr -d '[:space:]')"
  [[ "$uuid" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || return 1
  printf '%s' "$uuid" | tr '[:lower:]' '[:upper:]'
}

frp_macos_machine_id() {
  local uuid
  uuid="$(frp_macos_platform_uuid)" || {
    echo "ERROR: could not read IOPlatformUUID from ioreg." >&2
    return 1
  }
  printf '%s' "$uuid" | python3 -c '
import hashlib,sys
u=sys.stdin.read().strip()
sys.stdout.write(hashlib.sha256(("frp-auto-deploy:macos:"+u).encode()).hexdigest()[:32])
'
}

frp_macos_product_version() {
  local v="${FRP_TEST_MACOS_PRODUCT_VERSION:-}"
  [[ -z "$v" ]] && frp_command_exists sw_vers && v="$(frp_invoke sw_vers -productVersion 2>/dev/null || true)"
  printf '%s' "$v"
}

frp_macos_require_supported_release() {
  local v major
  v="$(frp_macos_product_version)"
  [[ -z "$v" ]] && return 0
  major="${v%%.*}"
  [[ "$major" =~ ^[0-9]+$ ]] || return 0
  if (( major < FRP_MACOS_MIN_PRODUCT_VERSION )); then
    echo "ERROR: macOS ${v} is older than the supported minimum (macOS ${FRP_MACOS_MIN_PRODUCT_VERSION})." >&2
    return 1
  fi
}

frp_macos_print_detected() {
  echo "Detected macOS:"
  echo "  Version      : $(frp_macos_product_version)"
  echo "  Architecture : ${FRP_ARCH:-unknown} (Apple Silicon)"
  echo "  Service mgr  : launchd"
  echo "  State        : $(frp_macos_state_root)"
}

frp_macos_required_commands() {
  printf '%s\n' curl openssl python3 tar shasum launchctl
}

frp_macos_require_dependencies() {
  local cmd missing=""
  while IFS= read -r cmd; do
    frp_command_exists "$cmd" || missing="${missing}${cmd}"$'\n'
  done < <(frp_macos_required_commands)
  [[ -z "$missing" ]] && return 0
  echo "ERROR: required tools are missing:" >&2
  printf '%s' "$missing" | sed 's/^/  /' >&2
  echo "This installer does not modify system packages on macOS." >&2
  echo "Install the Command Line Tools: xcode-select --install" >&2
  return 1
}

frp_macos_sha256_check() {
  printf '%s  %s\n' "$1" "$2" | shasum -a 256 -c - >/dev/null
}

frp_launchd_usable() {
  frp_command_exists launchctl
}

frp_macos_launchd_template() {
  local here candidate
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  for candidate in "${FRP_MACOS_PLIST_TEMPLATE:-}" \
    "${here}/../client/${FRP_MACOS_LAUNCHD_LABEL}.plist" \
    "$(frp_macos_fs "/usr/local/lib/frp-auto-deploy/${FRP_MACOS_LAUNCHD_LABEL}.plist")"; do
    [[ -n "$candidate" && -f "$candidate" ]] && { printf '%s' "$candidate"; return; }
  done
  return 1
}

frp_macos_render_plist() {
  local dest="$1" template
  template="$(frp_macos_launchd_template)" || {
    echo "ERROR: launchd plist template not found" >&2
    return 1
  }
  FRP_PLIST_LABEL="$FRP_MACOS_LAUNCHD_LABEL" \
  FRP_PLIST_FRPC="$(frp_macos_fs /usr/local/bin/frpc)" \
  FRP_PLIST_CONFIG="$(frp_macos_fs /etc/frp/frpc.toml)" \
  FRP_PLIST_STDOUT="$(frp_macos_fs /etc/frp)/logs/frpc.out.log" \
  FRP_PLIST_STDERR="$(frp_macos_fs /etc/frp)/logs/frpc.err.log" \
  python3 - "$template" "$dest" <<'PY'
import os,plistlib,sys
from pathlib import Path
with open(sys.argv[1],'rb') as f: data=plistlib.load(f)
subs={'@LABEL@':os.environ['FRP_PLIST_LABEL'],'@FRPC@':os.environ['FRP_PLIST_FRPC'],
'@CONFIG@':os.environ['FRP_PLIST_CONFIG'],'@STDOUT@':os.environ['FRP_PLIST_STDOUT'],
'@STDERR@':os.environ['FRP_PLIST_STDERR']}
def expand(v):
    if isinstance(v,str):
        for a,b in subs.items(): v=v.replace(a,b)
    elif isinstance(v,list): v=[expand(x) for x in v]
    elif isinstance(v,dict): v={k:expand(x) for k,x in v.items()}
    return v
data=expand(data)
if any(t in repr(data) for t in subs): raise SystemExit('ERROR: unresolved placeholder in launchd plist')
if data.get('Label') != subs['@LABEL@']: raise SystemExit('ERROR: launchd plist Label does not match')
if data.get('ProgramArguments') != [subs['@FRPC@'],'-c',subs['@CONFIG@']]:
    raise SystemExit('ERROR: launchd plist ProgramArguments are not the pinned frpc invocation')
out=Path(sys.argv[2]); out.parent.mkdir(parents=True,exist_ok=True)
tmp=out.with_name(out.name+'.tmp')
with open(tmp,'wb') as f: plistlib.dump(data,f)
tmp.chmod(0o644); tmp.replace(out)
PY
}

frp_macos_launchd_install() {
  local dest
  dest="$(frp_macos_fs /etc/systemd/system/frpc.service)"
  frp_require_safe_write_path "$dest" && frp_macos_render_plist "$dest"
}

frp_macos_launchd_bootout() {
  frp_launchd_usable || return 0
  frp_invoke launchctl bootout "system/${FRP_MACOS_LAUNCHD_LABEL}" >/dev/null 2>&1 ||
    frp_invoke launchctl unload -w "$(frp_macos_fs /etc/systemd/system/frpc.service)" >/dev/null 2>&1 || true
}

frp_macos_launchd_bootstrap() {
  local plist
  frp_launchd_usable || return 0
  plist="$(frp_macos_fs /etc/systemd/system/frpc.service)"
  if frp_invoke launchctl bootstrap system "$plist" >/dev/null 2>&1; then
    return 0
  fi
  if frp_invoke launchctl load -w "$plist" >/dev/null 2>&1; then
    return 0
  fi
  echo "ERROR: launchctl bootstrap/load of ${plist} failed" >&2
  return 1
}

frp_macos_launchd_kickstart() {
  frp_invoke launchctl kickstart -k "system/${FRP_MACOS_LAUNCHD_LABEL}" >/dev/null 2>&1
}

frp_macos_launchd_pid() {
  frp_invoke launchctl print "system/${FRP_MACOS_LAUNCHD_LABEL}" 2>/dev/null |
    awk '/^[[:space:]]*pid[[:space:]]*=/ {print $3; exit}'
}

frp_macos_launchd_running() {
  local pid
  pid="$(frp_macos_launchd_pid || true)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]]
}

frp_macos_launchd_set_enabled() {
  local action="${1:-}"
  if ! frp_launchd_usable; then
    return 0
  fi
  case "$action" in
    enable|disable) ;;
    *)
      echo "ERROR: launchctl enable/disable action is invalid: ${action}" >&2
      return 1
      ;;
  esac
  if ! frp_invoke launchctl "$action" "system/${FRP_MACOS_LAUNCHD_LABEL}"; then
    echo "ERROR: launchctl ${action} system/${FRP_MACOS_LAUNCHD_LABEL} failed" >&2
    return 1
  fi
  return 0
}

frp_macos_recent_logs() {
  local lines="${1:-80}" state
  state="$(frp_macos_fs /etc/frp)"
  for f in "$state/logs/frpc.out.log" "$state/logs/frpc.err.log"; do
    [[ -f "$f" ]] && tail -n "$lines" "$f"
  done
}
