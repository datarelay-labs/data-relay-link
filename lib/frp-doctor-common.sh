#!/usr/bin/env bash
# Read-only doctor orchestration. Source this file; do not execute it.
# Must stay compatible with Bash 4.2.

if [[ -n "${FRP_DOCTOR_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
FRP_DOCTOR_LOADED=1

_FRP_DOCTOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${FRP_COMMON_LOADED:-}" ]]; then
  if [[ -f "${_FRP_DOCTOR_DIR}/frp-common.sh" ]]; then
    # shellcheck source=frp-common.sh
    . "${_FRP_DOCTOR_DIR}/frp-common.sh"
  elif [[ -f /usr/local/lib/frp-auto-deploy/frp-common.sh ]]; then
    # shellcheck disable=SC1091
    . /usr/local/lib/frp-auto-deploy/frp-common.sh
  fi
fi

frp_doctor_lib_dir() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  printf '%s' "$here"
}

frp_doctor_py() {
  local cand libdir
  if [[ -n "${FRP_DOCTOR_PY:-}" && -f "${FRP_DOCTOR_PY}" ]]; then
    printf '%s' "$FRP_DOCTOR_PY"
    return 0
  fi
  libdir="$(frp_doctor_lib_dir)"
  for cand in \
    "${libdir}/frp_doctor.py" \
    /usr/local/lib/frp-auto-deploy/frp_doctor.py
  do
    if [[ -f "$cand" ]]; then
      printf '%s' "$cand"
      return 0
    fi
  done
  echo "ERROR: missing frp_doctor.py" >&2
  return 1
}

frp_doctor_root() {
  local root="${FRP_CTL_TEST_ROOT:-${FRP_CLIENT_TEST_ROOT:-${FRP_DEPLOY_TEST_ROOT:-${FRP_UPDATE_ROOT:-${FRP_SERVER_TEST_ROOT:-${FRP_ROLE_TEST_ROOT:-}}}}}}"
  printf '%s' "$root"
}

frp_doctor_fs() {
  local p="$1"
  if declare -F frp_platform_map_path >/dev/null 2>&1; then
    p="$(frp_platform_map_path "$p")"
  fi
  local root
  root="$(frp_doctor_root)"
  if [[ -n "$root" ]]; then
    printf '%s' "${root}${p}"
  else
    printf '%s' "$p"
  fi
}

# Allowed systemd verbs only. Never start/stop/restart/enable/disable/daemon-reload.
frp_doctor_systemctl() {
  local verb="$1"
  shift || true
  case "$verb" in
    is-active|is-enabled|status|show)
      ;;
    *)
      echo "ERROR: doctor refused systemd verb ${verb}" >&2
      return 2
      ;;
  esac
  if ! command -v systemctl >/dev/null 2>&1; then
    return 1
  fi
  systemctl "$verb" "$@"
}

frp_doctor_systemd_usable() {
  if [[ "${FRP_SKIP_SYSTEMD:-}" == "1" ]]; then
    return 1
  fi
  if [[ "${FRP_DOCTOR_FORCE_SYSTEMD:-}" == "1" ]]; then
    command -v systemctl >/dev/null 2>&1
    return $?
  fi
  if [[ -n "$(frp_doctor_root)" ]]; then
    return 1
  fi
  if type frp_systemd_usable >/dev/null 2>&1; then
    frp_systemd_usable || return 1
  elif [[ ! -d /run/systemd/system ]]; then
    return 1
  fi
  command -v systemctl >/dev/null 2>&1
}

frp_doctor_unit_state() {
  local unit="$1"
  local active="unknown" enabled="unknown"
  if ! frp_doctor_systemd_usable; then
    printf '%s %s' "$active" "$enabled"
    return 0
  fi
  active="$(frp_doctor_systemctl is-active "$unit" 2>/dev/null || true)"
  enabled="$(frp_doctor_systemctl is-enabled "$unit" 2>/dev/null || true)"
  [[ -n "$active" ]] || active="unknown"
  [[ -n "$enabled" ]] || enabled="unknown"
  printf '%s %s' "$active" "$enabled"
}

frp_doctor_journal() {
  local unit="$1"
  if [[ "${FRP_DOCTOR_VERBOSE:-}" != "1" ]]; then
    return 0
  fi
  if ! command -v journalctl >/dev/null 2>&1; then
    return 0
  fi
  if ! frp_doctor_systemd_usable; then
    return 0
  fi
  journalctl -u "$unit" -n 20 --no-pager -o cat 2>/dev/null | tail -n 20 || true
}

frp_doctor_port_listening() {
  local port="$1"
  local raw
  command -v ss >/dev/null 2>&1 || return 2
  raw="$(ss -H -lnt 2>/dev/null || ss -lnt 2>/dev/null)" || return 2
  printf '%s\n' "$raw" | awk -v wanted="$port" '
    $1 ~ /^(State|Netid)$/ { next }
    { p=$4; gsub(/\]$/, "", p); sub(/^.*:/, "", p); if (p == wanted) found=1 }
    END { exit(found ? 0 : 1) }
  '
}

frp_doctor_clock_status() {
  local detail="" status="unknown"
  if command -v timedatectl >/dev/null 2>&1; then
    detail="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    case "$detail" in
      yes) status="synchronized" ;;
      no) status="unsynchronized" ;;
    esac
    if [[ "$status" == "unknown" ]]; then
      detail="$(timedatectl 2>/dev/null | awk -F: '/synchronized/ {gsub(/^ +/,"",$2); print $2; exit}' || true)"
      case "$detail" in
        yes) status="synchronized" ;;
        no) status="unsynchronized" ;;
      esac
    fi
  elif command -v chronyc >/dev/null 2>&1; then
    detail="$(chronyc tracking 2>/dev/null | awk -F: '/Leap status/ {gsub(/^ +/,"",$2); print $2; exit}' || true)"
    case "$detail" in
      Normal) status="synchronized" ;;
      *Not*|*unknown*|"") status="unknown" ;;
      *) status="unsynchronized" ;;
    esac
  fi
  printf '%s\t%s' "$status" "$detail"
}

frp_doctor_disk_mb() {
  local path="$1"
  python3 - "$path" <<'PY'
import os, sys
path = sys.argv[1]
try:
    st = os.statvfs(path)
except OSError:
    print("")
    raise SystemExit(0)
avail = (st.f_bavail * st.f_frsize) // (1024 * 1024)
print(avail)
PY
}

frp_doctor_collect_facts() {
  local facts_file="$1"
  local root py_ver openssl_ver systemd_ver kernel arch os_name os_id
  local frps_a frps_e alloc_a alloc_e frpc_a frpc_e frontend_a frontend_e
  local clock_status clock_detail disk_mb
  local systemd_usable=0 skip_net=0 expect_root=1 have_systemctl=0
  root="$(frp_doctor_root)"
  [[ -z "$root" ]] || expect_root=0
  [[ "${FRP_DOCTOR_SKIP_NETWORK:-}" == "1" ]] && skip_net=1
  command -v systemctl >/dev/null 2>&1 && have_systemctl=1

  os_name="Linux"
  os_id="unknown"
  if type frp_detect_platform >/dev/null 2>&1; then
    frp_detect_platform
    os_name="${DISTRO_NAME:-Linux}"
    os_id="${DISTRO_ID:-unknown}"
  elif [[ -r /etc/os-release ]]; then
    os_id="$(awk -F= '$1=="ID" {gsub(/"/,"",$2); print $2; exit}' /etc/os-release)"
    os_name="$(awk -F= '$1=="PRETTY_NAME" {gsub(/"/,"",$2); print $2; exit}' /etc/os-release)"
  fi
  kernel="$(uname -r 2>/dev/null || true)"
  arch="$(uname -m 2>/dev/null || true)"
  py_ver="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || true)"
  openssl_ver="$(openssl version 2>/dev/null || true)"
  systemd_ver=""
  if type frp_systemd_version >/dev/null 2>&1; then
    systemd_ver="$(frp_systemd_version 2>/dev/null || true)"
  fi

  if type frp_doctor_systemd_usable >/dev/null 2>&1 && frp_doctor_systemd_usable; then
    systemd_usable=1
    read -r frps_a frps_e <<<"$(frp_doctor_unit_state frps)"
    read -r alloc_a alloc_e <<<"$(frp_doctor_unit_state frp-port-allocator)"
    read -r frpc_a frpc_e <<<"$(frp_doctor_unit_state frpc)"
    read -r frontend_a frontend_e <<<"$(frp_doctor_unit_state frp-frontend)"
  else
    frps_a=unknown; frps_e=unknown
    alloc_a=unknown; alloc_e=unknown
    frpc_a=unknown; frpc_e=unknown
    frontend_a=unknown; frontend_e=unknown
  fi
  if type frp_is_darwin >/dev/null 2>&1 && frp_is_darwin && type frp_macos_launchd_running >/dev/null 2>&1; then
    if frp_macos_launchd_running; then
      frpc_a=active
    else
      frpc_a=inactive
    fi
    frpc_e=enabled
  fi

  IFS=$'\t' read -r clock_status clock_detail <<<"$(frp_doctor_clock_status)"
  disk_mb="$(frp_doctor_disk_mb "$(frp_doctor_fs /var/lib/frp-auto-deploy)")"
  if [[ -z "$disk_mb" ]]; then
    disk_mb="$(frp_doctor_disk_mb "$(frp_doctor_fs /etc/frp)")"
  fi

  python3 - "$facts_file" \
    "$expect_root" "$systemd_usable" "$have_systemctl" "$skip_net" \
    "$frps_a" "$frps_e" "$alloc_a" "$alloc_e" "$frpc_a" "$frpc_e" \
    "$frontend_a" "$frontend_e" \
    "$clock_status" "$clock_detail" \
    "$os_name" "$os_id" "$kernel" "$arch" "$BASH_VERSION" "$py_ver" "$openssl_ver" "$systemd_ver" \
    "$disk_mb" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
expect_root, systemd_usable, have_systemctl, skip_net = (sys.argv[i] == "1" for i in range(2, 6))
(frps_a, frps_e, alloc_a, alloc_e, frpc_a, frpc_e, frontend_a, frontend_e,
 clock_status, clock_detail, os_name, os_id, kernel, arch,
 bash, py_ver, openssl_ver, systemd_ver, disk_mb) = sys.argv[6:25]
avail = int(disk_mb) if disk_mb.isdigit() else None
facts = {
    "expect_root_owner": expect_root,
    "systemd_usable": systemd_usable,
    "systemctl_present": have_systemctl,
    "skip_network": skip_net,
    "units": {
        "frps": {"active": frps_a, "enabled": frps_e},
        "frp-port-allocator": {"active": alloc_a, "enabled": alloc_e},
        "frpc": {"active": frpc_a, "enabled": frpc_e},
        "frp-frontend": {"active": frontend_a, "enabled": frontend_e},
    },
    "clock": {"status": clock_status, "detail": clock_detail},
    "platform": {
        "os": os_name,
        "os_id": os_id,
        "kernel": kernel,
        "arch": arch,
        "bash": bash,
        "python": py_ver,
        "openssl": openssl_ver,
        "systemd": systemd_ver,
    },
    "disk": {"path": "/var/lib/frp-auto-deploy", "avail_mb": avail},
    "listeners": {},
    "journal": {},
    "network": {},
}
path.write_text(json.dumps(facts) + "\n", encoding="utf-8")
PY

  # Local listen probes for configured server ports. Read-only TCP connect.
  local cfg listen_frp listen_alloc listen_frontend
  cfg="$(frp_doctor_fs /etc/frp-auto-deploy/config.json)"
  if [[ -f "$cfg" ]]; then
    eval "$(python3 - "$cfg" <<'PY'
import json, sys
from pathlib import Path
try:
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(0)
def port(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 65535 else None
frp = port(cfg.get('frp_control_listen_port')) or port(cfg.get('control_port'))
alloc = port(cfg.get('allocator_listen_port')) or port(cfg.get('listen_port'))
frontend = None
mode = str(cfg.get('deployment_mode') or 'direct').strip().lower().replace('-', '').replace('_', '')
if mode in ('single443', 'enterprise', 'enterprisesingle443'):
    frontend = port(cfg.get('frp_control_public_port')) or port(cfg.get('control_port'))
if frp:
    print('listen_frp=%s' % frp)
if alloc:
    print('listen_alloc=%s' % alloc)
if frontend:
    print('listen_frontend=%s' % frontend)
PY
)"
    python3 - "$facts_file" "${listen_frp:-}" "${listen_alloc:-}" "${listen_frontend:-}" <<'PY'
import json, re, shutil, subprocess, sys
from pathlib import Path
path = Path(sys.argv[1])
facts = json.loads(path.read_text(encoding='utf-8'))
listeners = facts.setdefault('listeners', {})
ports = set()
known = False
binary = shutil.which('ss')
if binary:
    for args in ([binary, '-H', '-lnt'], [binary, '-lnt']):
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=5, check=False, universal_newlines=True)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        known = True
        for line in proc.stdout.splitlines():
            fields = line.split()
            if not fields or fields[0] in ('State', 'Netid'):
                continue
            for field in fields:
                match = re.search(r':(\d+)$', field.rstrip(']'))
                if match:
                    ports.add(int(match.group(1)))
                    break
        break
for raw in sys.argv[2:]:
    if not raw:
        continue
    port = int(raw)
    listeners[str(port)] = {'listening': (port in ports) if known else None}
path.write_text(json.dumps(facts) + '\n', encoding='utf-8')
PY
  fi

  if [[ "${FRP_DOCTOR_VERBOSE:-}" == "1" ]] && frp_doctor_systemd_usable; then
    local jfrps jalloc jfrpc
    jfrps="$(frp_doctor_journal frps)"
    jalloc="$(frp_doctor_journal frp-port-allocator)"
    jfrpc="$(frp_doctor_journal frpc)"
    python3 - "$facts_file" "$jfrps" "$jalloc" "$jfrpc" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
facts = json.loads(path.read_text(encoding='utf-8'))
facts['journal'] = {
    'frps': sys.argv[2],
    'frp-port-allocator': sys.argv[3],
    'frpc': sys.argv[4],
}
path.write_text(json.dumps(facts) + '\n', encoding='utf-8')
PY
  fi
}

frp_doctor_usage() {
  cat <<'EOF'
Usage: frpctl doctor [--json] [--verbose] [--quiet]

Run read-only health and consistency checks. Doctor does not restart
services, rewrite config, consume a management nonce, release ports,
revoke clients, re-enroll, or update software.

  --json      Machine-readable report
  --verbose   Include paths, certificate SAN summary, and extra detail
  --quiet     Print summary and failures only
EOF
}

frp_doctor_main() {
  local fmt="human" verbose=0 quiet=0
  local arg py facts_file rc=0
  FRP_DOCTOR_VERBOSE=0
  for arg in "$@"; do
    case "$arg" in
      -h|--help)
        frp_doctor_usage
        return 0
        ;;
      --json) fmt="json" ;;
      --verbose) verbose=1; FRP_DOCTOR_VERBOSE=1 ;;
      --quiet) quiet=1 ;;
      --skip-network) FRP_DOCTOR_SKIP_NETWORK=1 ;;
      *)
        echo "ERROR: unknown doctor option: ${arg}" >&2
        frp_doctor_usage >&2
        return 2
        ;;
    esac
  done

  py="$(frp_doctor_py)" || return 2
  facts_file="$(mktemp)"
  # Temp facts only. EXIT removes it; do not override the frpctl INT trap.
  trap 'rm -f "$facts_file"' EXIT

  frp_doctor_collect_facts "$facts_file" || true

  local extra=()
  extra+=(--root "$(frp_doctor_root)")
  extra+=(--facts "$facts_file")
  extra+=(--format "$fmt")
  extra+=(--embedded-version "${PROJECT_VERSION:-}")
  extra+=(--pinned-frp "${FRP_VERSION:-0.70.1}")
  if [[ "$verbose" == "1" ]]; then
    extra+=(--verbose)
  fi
  if [[ "$quiet" == "1" ]]; then
    extra+=(--quiet)
  fi
  if [[ "${FRP_DOCTOR_SKIP_NETWORK:-}" == "1" ]]; then
    extra+=(--skip-network)
  fi

  set +e
  python3 "$py" "${extra[@]}"
  rc=$?
  set -e
  rm -f "$facts_file"
  trap - EXIT
  return "$rc"
}
