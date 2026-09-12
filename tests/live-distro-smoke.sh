#!/usr/bin/env bash
# Non-destructive live-distro smoke collector for a systemd host.
# Collects version info, unit state, listeners, allocator health, and frpctl
# status. Does not create/release/revoke objects, print secrets, or reset state.
set -euo pipefail

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; }
note() { echo "INFO $1"; }
not_installed() { echo "NOT_INSTALLED $1"; }
not_applicable() { echo "NOT_APPLICABLE $1"; }
not_tested() { echo "NOT_TESTED $1"; }

have() { command -v "$1" >/dev/null 2>&1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

redact_status() {
  # Drop lines that can carry secrets even if a tool regresses.
  grep -viE 'token|secret|private.?key|mac.?key|enrollment|password|BEGIN |ciphertext' || true
}

echo "LIVE_DISTRO_SMOKE=begin"
echo "COLLECTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "OS_PRETTY=${PRETTY_NAME:-unknown}"
  echo "OS_ID=${ID:-unknown}"
  echo "OS_VERSION_ID=${VERSION_ID:-unknown}"
else
  echo "OS_PRETTY=unknown"
  echo "OS_ID=unknown"
  echo "OS_VERSION_ID=unknown"
fi

echo "UNAME=$(uname -srm)"
echo "ARCH=$(uname -m)"
case "$(uname -m)" in
  x86_64) echo "FRP_ARCH=amd64" ;;
  aarch64|arm64) echo "FRP_ARCH=arm64" ;;
  *) echo "FRP_ARCH=unknown" ;;
esac
echo "BASH_VERSION=${BASH_VERSION}"
if have python3; then
  echo "PYTHON_VERSION=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
else
  echo "PYTHON_VERSION=missing"
fi
if have openssl; then
  echo "OPENSSL_VERSION=$(openssl version 2>/dev/null | awk '{print $1" "$2}')"
  if openssl version 2>/dev/null | grep -q '1\.0\.2'; then
    echo "OPENSSL_1_0_2=yes"
  else
    echo "OPENSSL_1_0_2=no"
  fi
else
  echo "OPENSSL_VERSION=missing"
  echo "OPENSSL_1_0_2=no"
fi

if have systemd-detect-virt; then
  echo "VIRT=$(systemd-detect-virt 2>/dev/null || echo unknown)"
elif [[ -f /.dockerenv ]]; then
  echo "VIRT=docker"
else
  echo "VIRT=unknown"
fi
echo "NOTE=live-distro-smoke.sh never sets REAL_VM=PASS"

if have systemctl; then
  echo "SYSTEMD_VERSION=$(systemctl --version 2>/dev/null | awk 'NR==1 {print $2; exit}')"
  if [[ -d /run/systemd/system ]]; then
    echo "SYSTEMD_RUNTIME=yes"
    echo "PID1=$(tr '\0' ' ' </proc/1/comm 2>/dev/null || true)"
  else
    echo "SYSTEMD_RUNTIME=no"
  fi
else
  echo "SYSTEMD_VERSION=missing"
  echo "SYSTEMD_RUNTIME=no"
fi

if have getenforce; then
  echo "SELINUX_MODE=$(getenforce 2>/dev/null || echo unknown)"
else
  echo "SELINUX_MODE=N/A"
fi
if [[ -r /etc/selinux/config ]]; then
  awk -F= '/^SELINUX=/ {print "SELINUX_CONFIG="$2}' /etc/selinux/config
fi

if bash -c 'bind -x "\"\\t\": true"' >/dev/null 2>&1; then
  echo "BIND_X=yes"
else
  echo "BIND_X=no"
fi

if [[ -f /etc/drlink/version ]]; then
  awk -F= '/^(PROJECT_VERSION|FRP_VERSION)=/ {print}' /etc/drlink/version
else
  echo "PROJECT_VERSION=missing"
  echo "FRP_VERSION=missing"
fi

unit_present() {
  local unit="$1"
  have systemctl || return 1
  [[ "$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)" == "loaded" ]]
}

unit_probe() {
  local unit="$1"
  local required="${2:-optional}"
  local enabled active load
  if ! have systemctl; then
    echo "${unit}_ENABLED=missing"
    echo "${unit}_ACTIVE=missing"
    echo "${unit}_LOAD=missing"
    not_tested "${unit} (systemctl missing)"
    return 0
  fi
  load="$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)"
  if [[ "$load" != "loaded" ]]; then
    echo "${unit}_ENABLED=absent"
    echo "${unit}_ACTIVE=absent"
    echo "${unit}_LOAD=${load:-absent}"
    if [[ "$required" == required ]]; then
      fail "${unit} not installed on this host"
    else
      not_installed "${unit}"
    fi
    return 0
  fi
  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  active="$(systemctl is-active "$unit" 2>/dev/null || true)"
  echo "${unit}_ENABLED=${enabled:-unknown}"
  echo "${unit}_ACTIVE=${active:-unknown}"
  echo "${unit}_LOAD=${load}"
  if [[ "$active" == active && "$enabled" == enabled ]]; then
    pass "${unit}"
  else
    fail "${unit} enabled=${enabled:-unknown} active=${active:-unknown}"
  fi
}

HOST_ROLE=uninstalled
SERVER_PRESENT=no
CLIENT_PRESENT=no
if unit_present drlink-allocator || [[ -f /etc/drlink/config.json ]]; then
  SERVER_PRESENT=yes
fi
if unit_present frpc || [[ -f /etc/frp/client-state.json ]]; then
  CLIENT_PRESENT=yes
fi
if [[ "$SERVER_PRESENT" == yes && "$CLIENT_PRESENT" == yes ]]; then
  HOST_ROLE=server+client
elif [[ "$SERVER_PRESENT" == yes ]]; then
  HOST_ROLE=server
elif [[ "$CLIENT_PRESENT" == yes ]]; then
  HOST_ROLE=client
fi
echo "HOST_ROLE=${HOST_ROLE}"

if [[ "$SERVER_PRESENT" == yes ]]; then
  unit_probe frps required
  unit_probe drlink-allocator required
else
  unit_probe frps optional
  unit_probe drlink-allocator optional
fi
if [[ "$CLIENT_PRESENT" == yes ]]; then
  unit_probe frpc required
else
  unit_probe frpc optional
fi

if have systemctl; then
  for unit in frps drlink-allocator frpc; do
    if unit_present "$unit"; then
      echo "----- systemctl cat ${unit} -----"
      systemctl cat "$unit" 2>/dev/null | grep -viE 'token|secret|private.?key|mac.?key' || true
      echo "----- systemctl show ${unit} (subset) -----"
      systemctl show "$unit" -p Id -p Description -p LoadState -p ActiveState \
        -p SubState -p UnitFileState -p WantedBy -p FragmentPath -p Result \
        -p ExecMainStatus -p ProtectSystem -p ReadWritePaths -p NoNewPrivileges \
        -p PrivateTmp 2>/dev/null || true
    fi
  done
  if [[ "$SERVER_PRESENT" == yes ]]; then
    if journalctl -u drlink-allocator -n 30 --no-pager >"$WORKDIR/alloc-j.log" 2>/dev/null; then
      if grep -Ei 'unknown lvalue|Failed to load|cannot be started' "$WORKDIR/alloc-j.log" >/dev/null; then
        echo "ALLOCATOR_JOURNAL_DIAGNOSTIC=present"
        grep -Ei 'unknown lvalue|Failed to load|cannot be started|error' "$WORKDIR/alloc-j.log" | head -20
      else
        echo "ALLOCATOR_JOURNAL_DIAGNOSTIC=none"
      fi
    else
      echo "ALLOCATOR_JOURNAL_DIAGNOSTIC=unavailable"
      not_tested "allocator journal"
    fi
  else
    echo "ALLOCATOR_JOURNAL_DIAGNOSTIC=NOT_APPLICABLE"
    not_applicable "allocator journal"
  fi
fi

file_meta() {
  local path="$1" label="$2" kind="${3:-secret}"
  if [[ -f "$path" ]]; then
    echo "${label}_EXISTS=yes"
    echo "${label}_MODE=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%OLp' "$path")"
    if [[ "$kind" == cert ]] && have openssl; then
      if openssl x509 -in "$path" -noout >/dev/null 2>&1; then
        openssl x509 -in "$path" -outform DER -out "$WORKDIR/cert.der" 2>/dev/null || true
        if [[ -s "$WORKDIR/cert.der" ]]; then
          echo "${label}_FINGERPRINT=$(sha256sum "$WORKDIR/cert.der" | awk '{print $1}')"
        else
          echo "${label}_FINGERPRINT=invalid"
        fi
      else
        echo "${label}_FINGERPRINT=invalid"
      fi
    fi
  else
    echo "${label}_EXISTS=no"
  fi
}

if [[ "$SERVER_PRESENT" == yes ]]; then
  HEALTHZ_PORT=""
  if [[ -r /etc/drlink/config.json ]] && have python3; then
    HEALTHZ_PORT="$(python3 - <<'PY'
import json
from pathlib import Path
p = Path("/etc/drlink/config.json")
try:
    cfg = json.loads(p.read_text(encoding="utf-8"))
    port = cfg.get("allocator_listen_port") or cfg.get("listen_port")
    print(int(port) if port else "")
except Exception:
    print("")
PY
)"
  fi
  CA_FILE="/etc/drlink/pki/ca.crt"
  if [[ -z "$HEALTHZ_PORT" ]]; then
    echo "HEALTHZ=NOT_TESTED"
    not_tested "allocator_healthz (listen port unknown)"
  elif [[ ! -f "$CA_FILE" ]]; then
    echo "HEALTHZ=NOT_TESTED"
    not_tested "allocator_healthz (public CA missing)"
  elif ! have curl; then
    echo "HEALTHZ=NOT_TESTED"
    not_tested "allocator_healthz (curl missing)"
  else
    if curl -fsS --max-time 5 --cacert "$CA_FILE" \
      "https://127.0.0.1:${HEALTHZ_PORT}/healthz" >"$WORKDIR/healthz.out" 2>"$WORKDIR/healthz.err"; then
      echo "HEALTHZ=$(tr -d '\n' <"$WORKDIR/healthz.out")"
      pass "allocator_healthz"
    else
      echo "HEALTHZ=FAIL"
      fail "allocator_healthz"
    fi
  fi
else
  echo "HEALTHZ=NOT_APPLICABLE"
  not_applicable "allocator healthz"
fi

echo "----- listeners (ss/netstat, local) -----"
note "local listen ports; public NAT ports may differ"
if have ss; then
  ss -lnt >"$WORKDIR/listeners.out" 2>/dev/null || true
  head -40 "$WORKDIR/listeners.out"
elif have netstat; then
  netstat -lnt >"$WORKDIR/listeners.out" 2>/dev/null || true
  head -40 "$WORKDIR/listeners.out"
else
  note "no ss/netstat"
fi

file_meta /etc/frp/server_token SERVER_TOKEN secret
file_meta /etc/frp/frps.toml FRPS_TOML secret
file_meta /etc/frp/frpc.toml FRPC_TOML secret
file_meta /etc/frp/client-state.json CLIENT_STATE secret
file_meta /etc/frp/client-identity.key CLIENT_IDENTITY secret
file_meta /etc/drlink/pki/ca.crt SERVER_CA cert
file_meta /etc/drlink/pki/ca.key SERVER_CA_KEY secret
file_meta /etc/drlink/pki/server.key SERVER_TLS_KEY secret
file_meta /etc/drlink/allocator-ca.crt ALLOCATOR_CA cert
file_meta /var/lib/drlink/registry.json REGISTRY secret

if [[ -f /var/lib/drlink/registry.json ]] && have python3; then
  python3 - <<'PY'
import json
from pathlib import Path
p = Path("/var/lib/drlink/registry.json")
try:
    d = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    print("REGISTRY_PARSE=FAIL")
    raise SystemExit(0)
print("REGISTRY_SCHEMA=%s" % d.get("schema_version", "missing"))
clients = d.get("clients") if isinstance(d.get("clients"), dict) else {}
reserved = d.get("reserved") if isinstance(d.get("reserved"), list) else []
print("REGISTRY_CLIENTS=%d" % len(clients))
print("REGISTRY_RESERVED=%d" % len(reserved))
print("REGISTRY_PARSE=PASS")
PY
fi

if [[ -f /etc/frp/client-state.json ]] && have python3; then
  python3 - <<'PY'
import json
from pathlib import Path
d = json.loads(Path("/etc/frp/client-state.json").read_text(encoding="utf-8"))
svcs = d.get("services") if isinstance(d.get("services"), dict) else {}
print("CLIENT_SCHEMA=%s" % d.get("schema_version", "missing"))
print("CLIENT_HOSTNAME=%s" % d.get("hostname", ""))
print("CLIENT_SERVICE_COUNT=%d" % len(svcs))
print("CLIENT_HAS_MACHINE_ID=%s" % ("yes" if d.get("machine_id") else "no"))
print("CLIENT_HAS_ALLOCATOR_URL=%s" % ("yes" if d.get("allocator_url") else "no"))
PY
fi

if have frpctl; then
  echo "----- frpctl status -----"
  if frpctl status 2>"$WORKDIR/frpctl.err" | redact_status; then
    pass "frpctl_status"
  else
    fail "frpctl_status"
    redact_status <"$WORKDIR/frpctl.err"
  fi
  echo "----- frpctl doctor (read-only) -----"
  set +e
  frpctl doctor >"$WORKDIR/doctor.out" 2>"$WORKDIR/doctor.err"
  doctor_rc=$?
  set -e
  redact_status <"$WORKDIR/doctor.out"
  redact_status <"$WORKDIR/doctor.err"
  echo "DOCTOR_EXIT=${doctor_rc}"
  if [[ "$doctor_rc" -eq 0 ]]; then
    pass "frpctl_doctor"
  elif [[ "$doctor_rc" -eq 1 ]]; then
    note "frpctl doctor reported FAIL findings (collector is non-mutating)"
  else
    fail "frpctl_doctor (exit ${doctor_rc})"
  fi
else
  if [[ "$HOST_ROLE" == uninstalled ]]; then
    not_installed "frpctl"
  else
    fail "frpctl_missing"
  fi
fi

if have frpc && [[ -f /etc/frp/frpc.toml ]]; then
  if frpc verify -c /etc/frp/frpc.toml >"$WORKDIR/frpc-verify.out" 2>"$WORKDIR/frpc-verify.err"; then
    pass "frpc_verify"
  else
    fail "frpc_verify"
    redact_status <"$WORKDIR/frpc-verify.err"
  fi
else
  not_applicable "frpc_verify"
fi

echo "LIVE_DISTRO_SMOKE=end"
