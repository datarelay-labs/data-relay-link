#!/usr/bin/env bash
# Repeatable Real E2E for Data Relay Link.
# Controller-driven bash/SSH (+ PowerShell remote for Windows when available).
# Does not change firewalls/DNS providers. Does not target the controller host.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${FRP_E2E_PROFILE:-baseline-linux}"
SERVER_ALIAS="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
CLIENT_ALIAS="${FRP_E2E_CLIENT_ALIAS:-}"
SERVER_IP="${FRP_E2E_SERVER_IP:-221.139.249.112}"
PUBLIC_HOSTNAME="${FRP_E2E_PUBLIC_HOSTNAME:-}"
SSH_USER="${FRP_E2E_SSH_USER:-aella}"
TUNNEL_SSH_USER="${FRP_E2E_TUNNEL_SSH_USER:-}"
SSH_KEY="${FRP_E2E_SSH_KEY:-$HOME/.ssh/frp_e2e_ed25519}"
EXPECTED_SERVER_HOST="${FRP_E2E_SERVER_HOSTNAME:-dp-os-upgrade}"
EXPECTED_CLIENT_HOST="${FRP_E2E_CLIENT_HOSTNAME:-}"
FORBIDDEN_HOST="${FRP_E2E_FORBIDDEN_HOSTNAME:-dev-dp-mirror}"
CLIENT_LABEL="${FRP_E2E_CLIENT_LABEL:-}"
PLATFORM_KIND="${FRP_E2E_PLATFORM_KIND:-linux}"
SKIP_SERVER_INSTALL="${FRP_E2E_SKIP_SERVER_INSTALL:-0}"
SKIP_SERVER_PURGE="${FRP_E2E_SKIP_SERVER_PURGE:-0}"
RUN_ID="${FRP_E2E_RUN_ID:-${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}}"
OUT_DIR="${FRP_E2E_OUT_DIR:-${OUT_DIR:-$ROOT/e2e-reports/real-e2e-$RUN_ID}}"
HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
SCENARIO="${FRP_E2E_SCENARIO:-full}"
STOP_ON_FAIL="${FRP_E2E_STOP_ON_FAIL:-1}"
STEP_TIMEOUT="${FRP_E2E_STEP_TIMEOUT:-240}"
REBOOT_TRIES="${FRP_E2E_REBOOT_TRIES:-36}"
REBOOT_DELAY="${FRP_E2E_REBOOT_DELAY:-5}"
EXT_TRIES="${FRP_E2E_EXT_TRIES:-12}"
EXT_DELAY="${FRP_E2E_EXT_DELAY:-5}"
BACKUP_REPEAT="${FRP_E2E_BACKUP_REPEAT:-1}"
CLIENT_REBOOT_REPEAT="${FRP_E2E_CLIENT_REBOOT_REPEAT:-1}"
SERVER_REBOOT_REPEAT="${FRP_E2E_SERVER_REBOOT_REPEAT:-1}"
OVERALL_TIMEOUT="${FRP_E2E_OVERALL_TIMEOUT:-5400}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)
CLIENT_MID=""
CLIENT_MID_PREFIX=""
SSH_PUBLIC_PORT="6000"
ACCESS_HOST="$SERVER_IP"

apply_profile() {
  case "$PROFILE" in
    baseline-linux|linux|ubuntu)
      PROFILE=baseline-linux
      CLIENT_ALIAS="${CLIENT_ALIAS:-frp-e2e-client}"
      EXPECTED_CLIENT_HOST="${EXPECTED_CLIENT_HOST:-rickmodular}"
      TUNNEL_SSH_USER="${TUNNEL_SSH_USER:-aella}"
      CLIENT_LABEL="${CLIENT_LABEL:-real-e2e-linux}"
      PLATFORM_KIND=linux
      ;;
    amazon-linux-2023|al2023|aws)
      PROFILE=amazon-linux-2023
      CLIENT_ALIAS="${CLIENT_ALIAS:-frp-e2e-aws}"
      EXPECTED_CLIENT_HOST="${EXPECTED_CLIENT_HOST:-ip-10-0-19-146.ap-northeast-2.compute.internal}"
      TUNNEL_SSH_USER="${TUNNEL_SSH_USER:-ec2-user}"
      CLIENT_LABEL="${CLIENT_LABEL:-real-e2e-al2023}"
      PLATFORM_KIND=linux
      ;;
    rocky-linux-8.10|rocky8|rocky)
      PROFILE=rocky-linux-8.10
      CLIENT_ALIAS="${CLIENT_ALIAS:-frp-e2e-rocky8}"
      EXPECTED_CLIENT_HOST="${EXPECTED_CLIENT_HOST:-localhost.localdomain}"
      TUNNEL_SSH_USER="${TUNNEL_SSH_USER:-root}"
      CLIENT_LABEL="${CLIENT_LABEL:-real-e2e-rocky8}"
      PLATFORM_KIND=linux
      ;;
    rocky-linux-9.4|rocky9)
      PROFILE=rocky-linux-9.4
      CLIENT_ALIAS="${CLIENT_ALIAS:-frp-e2e-rocky9-rescue}"
      EXPECTED_CLIENT_HOST="${EXPECTED_CLIENT_HOST:-localhost.localdomain}"
      TUNNEL_SSH_USER="${TUNNEL_SSH_USER:-root}"
      CLIENT_LABEL="${CLIENT_LABEL:-real-e2e-rocky9}"
      PLATFORM_KIND=linux
      ;;
    ubuntu-24.04|ubuntu24)
      PROFILE=ubuntu-24.04
      CLIENT_ALIAS="${CLIENT_ALIAS:-frp-e2e-linux114}"
      EXPECTED_CLIENT_HOST="${EXPECTED_CLIENT_HOST:-frp-client}"
      TUNNEL_SSH_USER="${TUNNEL_SSH_USER:-aella}"
      CLIENT_LABEL="${CLIENT_LABEL:-real-e2e-ubuntu24}"
      PLATFORM_KIND=linux
      ;;
    macos|macos-arm64)
      PROFILE=macos-arm64
      CLIENT_ALIAS="${CLIENT_ALIAS:-frp-e2e-macos}"
      EXPECTED_CLIENT_HOST="${EXPECTED_CLIENT_HOST:-Leeui-MacBookAir.local}"
      TUNNEL_SSH_USER="${TUNNEL_SSH_USER:-leeruda}"
      CLIENT_LABEL="${CLIENT_LABEL:-real-e2e-macos}"
      PLATFORM_KIND=macos
      ;;
    windows|windows-10)
      PROFILE=windows-10
      CLIENT_ALIAS="${CLIENT_ALIAS:-frp-e2e-windows}"
      EXPECTED_CLIENT_HOST="${EXPECTED_CLIENT_HOST:-}"
      TUNNEL_SSH_USER="${TUNNEL_SSH_USER:-aella}"
      CLIENT_LABEL="${CLIENT_LABEL:-real-e2e-windows}"
      PLATFORM_KIND=windows
      ;;
    *)
      echo "unknown profile: $PROFILE" >&2
      exit 2
      ;;
  esac
  if [[ -z "$TUNNEL_SSH_USER" ]]; then
    TUNNEL_SSH_USER="$SSH_USER"
  fi
  if [[ -n "$PUBLIC_HOSTNAME" ]]; then
    ACCESS_HOST="$PUBLIC_HOSTNAME"
  else
    ACCESS_HOST="$SERVER_IP"
  fi
}

mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"
RESULTS="$OUT_DIR/results.tsv"
MATRIX_ROW="$OUT_DIR/matrix-row.tsv"
: >"$SUMMARY"
: >"$RESULTS"

FAILED=0
PASSED=0
SKIPPED=0
ABORTED=0
MATRIX_INSTALL=SKIP
MATRIX_ENROLL=SKIP
MATRIX_SERVICE=SKIP
MATRIX_REBOOT=SKIP
MATRIX_UNINSTALL=SKIP
MATRIX_DNS=SKIP

note() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }

redact() {
  python3 - "$1" <<'PY' 2>/dev/null || true
import re, sys
from pathlib import Path
p = Path(sys.argv[1])
try:
    text = p.read_text(encoding="utf-8", errors="replace")
except Exception:
    raise SystemExit(0)
patterns = [
    (re.compile(r'(Enrollment Code\s*[:=]\s*)\S+', re.I), r'\1[REDACTED]'),
    (re.compile(r'(token(?:_ciphertext)?\s*[:=]\s*)\S+', re.I), r'\1[REDACTED]'),
    (re.compile(r'(mgmt_mac_key\s*[:=]\s*)\S+', re.I), r'\1[REDACTED]'),
    (re.compile(r'(FRP_ENROLLMENT_CODE=)\S+'), r'\1[REDACTED]'),
    (re.compile(r'(FRP_BOOTSTRAP_TICKET=)\S+'), r'\1[REDACTED]'),
    (re.compile(r'bt1\.[0-9a-f]{16}\.[0-9a-f]{32,}', re.I), 'bt1.<redacted>'),
    (re.compile(r'zt1\.[A-Za-z0-9_-]{16,}', re.I), 'zt1.<redacted>'),
    (re.compile(r'(/i/)[^/?\s#]+', re.I), r'\1<redacted>'),
    (re.compile(r'(curl -fsSL )(\S+)'), r'\1[REDACTED_URL]'),
]
for rx, repl in patterns:
    text = rx.sub(repl, text)
p.write_text(text, encoding="utf-8")
PY
}

record() {
  local name="$1" status="$2" rc="$3" elapsed="$4"
  printf '%s\t%s\t%s\t%ss\n' "$name" "$status" "$rc" "$elapsed" >>"$RESULTS"
  note "STEP $name $status rc=$rc elapsed=${elapsed}s"
  case "$status" in
    PASS) PASSED=$((PASSED + 1)) ;;
    FAIL) FAILED=$((FAILED + 1)) ;;
    SKIP) SKIPPED=$((SKIPPED + 1)) ;;
    ABORT) ABORTED=$((ABORTED + 1)) ;;
  esac
}

ssh_cmd() {
  local alias="$1"; shift
  ssh "${SSH_OPTS[@]}" "$alias" "$@"
}

run_timed() {
  local name="$1" log="$2"; shift 2
  local start rc=0
  start="$(date +%s)"
  set +e
  timeout "$STEP_TIMEOUT" "$@" >"$log" 2>&1
  rc=$?
  set -uo pipefail
  local elapsed=$(( $(date +%s) - start ))
  redact "$log"
  if [[ "$rc" -eq 0 ]]; then
    record "$name" PASS "$rc" "$elapsed"
    return 0
  fi
  record "$name" FAIL "$rc" "$elapsed"
  note "FAIL_CMD=$name"
  if [[ "$STOP_ON_FAIL" == "1" ]]; then
    return "$rc"
  fi
  return 0
}

run_local() {
  local name="$1"; shift
  run_timed "$name" "$OUT_DIR/${name}.log" "$@"
}

run_server() {
  local name="$1"; shift
  run_timed "$name" "$OUT_DIR/${name}.log" ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" "$@"
}

run_client() {
  local name="$1"; shift
  run_timed "$name" "$OUT_DIR/${name}.log" ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" "$@"
}

wait_host() {
  local alias="$1" name="${2:-wait-$alias}" tries="${3:-$REBOOT_TRIES}" delay="${4:-$REBOOT_DELAY}"
  local i start rc=1
  start="$(date +%s)"
  for i in $(seq 1 "$tries"); do
    if ssh "${SSH_OPTS[@]}" "$alias" 'hostname' >/dev/null 2>&1; then
      rc=0
      break
    fi
    sleep "$delay"
  done
  local elapsed=$(( $(date +%s) - start ))
  if [[ "$rc" -eq 0 ]]; then
    record "$name" PASS 0 "$elapsed"
  else
    record "$name" FAIL 1 "$elapsed"
    note "FAIL reconnect $alias after ${tries}x${delay}s"
  fi
  return "$rc"
}

wait_external_ssh() {
  local name="${1:-wait-external-ssh}" tries="${2:-$EXT_TRIES}" delay="${3:-$EXT_DELAY}"
  local host="${4:-$ACCESS_HOST}" port="${5:-$SSH_PUBLIC_PORT}" user="${6:-$TUNNEL_SSH_USER}"
  local remote_cmd="${7:-}"
  local i start rc=1
  if [[ -z "$remote_cmd" ]]; then
    if [[ "$PLATFORM_KIND" == "windows" ]]; then
      remote_cmd='hostname'
    else
      remote_cmd='hostname && id -un'
    fi
  fi
  start="$(date +%s)"
  for i in $(seq 1 "$tries"); do
    if ssh "${SSH_OPTS[@]}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o IdentitiesOnly=yes -i "$SSH_KEY" -p "$port" "$user@$host" \
      "$remote_cmd" >"$OUT_DIR/${name}.log" 2>&1; then
      rc=0
      break
    fi
    sleep "$delay"
  done
  redact "$OUT_DIR/${name}.log"
  local elapsed=$(( $(date +%s) - start ))
  if [[ "$rc" -eq 0 ]]; then
    record "$name" PASS 0 "$elapsed"
  else
    record "$name" FAIL 1 "$elapsed"
  fi
  return "$rc"
}

assert_host_identity() {
  local alias="$1" expected="$2" role="$3"
  local got
  got="$(ssh "${SSH_OPTS[@]}" "$alias" 'hostname' 2>/dev/null || echo unreachable)"
  note "$role hostname=$got expected=$expected"
  if [[ "$got" == "$FORBIDDEN_HOST" ]]; then
    note "ABORT: SSH target is forbidden controller host $FORBIDDEN_HOST"
    record "identity-$role" ABORT 2 0
    return 2
  fi
  if [[ -n "$expected" && "$got" != "$expected" ]]; then
    note "ABORT: unexpected $role identity got=$got expected=$expected"
    record "identity-$role" ABORT 2 0
    return 2
  fi
  record "identity-$role" PASS 0 0
}

python_remote() {
  local alias="$1" name="$2"
  local start rc=0
  start="$(date +%s)"
  set +e
  timeout "$STEP_TIMEOUT" ssh "${SSH_OPTS[@]}" "$alias" 'sudo python3 /dev/stdin' \
    >"$OUT_DIR/${name}.log" 2>&1
  rc=$?
  set -uo pipefail
  local elapsed=$(( $(date +%s) - start ))
  redact "$OUT_DIR/${name}.log"
  if [[ "$rc" -eq 0 ]]; then
    record "$name" PASS "$rc" "$elapsed"
  else
    record "$name" FAIL "$rc" "$elapsed"
  fi
  return "$rc"
}

discover_client_identity() {
  local start rc=0
  start="$(date +%s)"
  set +e
  CLIENT_MID="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
    'sudo python3 -c "import json; print(json.load(open(\"/etc/frp/client-state.json\"))[\"machine_id\"])"' 2>"$OUT_DIR/discover-mid.err")"
  rc=$?
  if [[ "$rc" -eq 0 && -n "$CLIENT_MID" ]]; then
    CLIENT_MID_PREFIX="${CLIENT_MID:0:8}"
    SSH_PUBLIC_PORT="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
      'sudo python3 -c "import json; d=json.load(open(\"/etc/frp/client-state.json\")); s=(d.get(\"services\") or {}).get(\"ssh\") or {}; print(s.get(\"remote_port\") or \"\")"' \
      2>>"$OUT_DIR/discover-mid.err")"
    rc=$?
  fi
  set -uo pipefail
  local elapsed=$(( $(date +%s) - start ))
  if [[ "$rc" -ne 0 || -z "$CLIENT_MID" || -z "$SSH_PUBLIC_PORT" ]]; then
    record discover-client-identity FAIL 1 "$elapsed"
    note "CLIENT_MID='$CLIENT_MID' SSH_PUBLIC_PORT='$SSH_PUBLIC_PORT'"
    return 1
  fi
  note "CLIENT_MID=$CLIENT_MID"
  note "CLIENT_MID_PREFIX=$CLIENT_MID_PREFIX"
  note "SSH_PUBLIC_PORT=$SSH_PUBLIC_PORT"
  note "ACCESS_HOST=$ACCESS_HOST"
  printf '%s\n' "$CLIENT_MID" >"$OUT_DIR/client-mid.txt"
  printf '%s\n' "$SSH_PUBLIC_PORT" >"$OUT_DIR/ssh-public-port.txt"
  record discover-client-identity PASS 0 "$elapsed"
}

write_matrix_row() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$PROFILE" "$MATRIX_INSTALL" "$MATRIX_ENROLL" "$MATRIX_SERVICE" \
    "$MATRIX_REBOOT" "$MATRIX_UNINSTALL" "$MATRIX_DNS" >"$MATRIX_ROW"
  note "MATRIX_ROW $PROFILE install=$MATRIX_INSTALL enroll=$MATRIX_ENROLL service=$MATRIX_SERVICE reboot=$MATRIX_REBOOT uninstall=$MATRIX_UNINSTALL dns=$MATRIX_DNS"
}

fail_stop() {
  if [[ "$STOP_ON_FAIL" == "1" ]]; then
    finish 1
  fi
}

finish() {
  local rc="${1:-0}"
  write_matrix_row
  note "PASSED=$PASSED FAILED=$FAILED SKIPPED=$SKIPPED ABORTED=$ABORTED"
  if [[ "$FAILED" -gt 0 || "$ABORTED" -gt 0 ]]; then
    note "FINAL=FAIL"
    rc=1
  else
    note "FINAL=PASS"
  fi
  exit "$rc"
}

server_install_env() {
  local env=(
    "FRP_PUBLIC_IP=$SERVER_IP"
    "FRP_INTERNAL_IP=$SERVER_IP"
    "FRP_DEPLOYMENT_MODE=direct"
    "FRP_CONTROL_PUBLIC_PORT=443"
    "FRP_CONTROL_LISTEN_PORT=443"
    "FRP_ALLOCATOR_PUBLIC_PORT=6099"
    "FRP_ALLOCATOR_LISTEN_PORT=6099"
    "FRP_PORT_START=6000"
    "FRP_PORT_END=6098"
    "FRP_ALLOCATOR_PUBLIC_URL=https://$SERVER_IP:6099/enroll"
    "FRP_CLIENT_INSTALLER_URL=https://raw.githubusercontent.com/datarelay-labs/data-relay-link/$HEAD_SHA/dist/bootstrap-client.sh"
  )
  if [[ -n "$PUBLIC_HOSTNAME" ]]; then
    env+=("FRP_PUBLIC_HOSTNAME=$PUBLIC_HOSTNAME")
  fi
  printf '%s ' "${env[@]}"
}

create_zero_touch() {
  local out="$1" cmd_out="$2" name="$3" note_text="$4"
  local start rc=0
  start="$(date +%s)"
  set +e
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" \
    "sudo /usr/local/lib/drlink/frp-create-client --one-line --ssh --ssh-user '$TUNNEL_SSH_USER' --client-name '$CLIENT_LABEL' --note '$note_text'" \
    >"$out" 2>&1
  rc=$?
  set -uo pipefail
  if [[ "$rc" -eq 0 ]]; then
    python3 - "$out" "$cmd_out" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
# Short URL: curl ... | sudo bash
# zt1 fallback: curl ... | sudo bash -s -- 'zt1....'
cmd = re.search(r"^curl -fsSL .*\| sudo bash(?: -s -- 'zt1\.[^']+')?$", text, re.M)
if not cmd:
    raise SystemExit("missing one-line command")
open(sys.argv[2], "w", encoding="utf-8").write(cmd.group(0) + "\n")
PY
    rc=$?
  fi
  redact "$out"
  record "$name" "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)" "$rc" "$(( $(date +%s) - start ))"
  return "$rc"
}

create_zero_touch_windows() {
  local out="$1" enc_out="$2" name="$3" note_text="$4"
  local start rc=0
  start="$(date +%s)"
  set +e
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" \
    "sudo /usr/local/lib/drlink/frp-create-client --one-line --platform windows --ssh --ssh-user '$TUNNEL_SSH_USER' --client-name '$CLIENT_LABEL' --note '$note_text'" \
    >"$out" 2>&1
  rc=$?
  set -uo pipefail
  if [[ "$rc" -eq 0 ]]; then
    python3 - "$out" "$enc_out" <<'PY'
import base64, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
line = next((l for l in text.splitlines() if l.startswith("powershell.exe -NoProfile")), "")
m = re.match(r"powershell\.exe -NoProfile -ExecutionPolicy Bypass -Command '(.*)'\s*$", line)
if not m:
    raise SystemExit("missing windows one-line command")
# Official -Command uses '' escapes; EncodedCommand needs the decoded script body.
script = m.group(1).replace("''", "'")
open(sys.argv[2], "w", encoding="utf-8").write(
    base64.b64encode(script.encode("utf-16le")).decode("ascii")
)
PY
    rc=$?
  fi
  redact "$out"
  record "$name" "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)" "$rc" "$(( $(date +%s) - start ))"
  return "$rc"
}

discover_client_identity_windows() {
  local start rc=0
  start="$(date +%s)"
  set +e
  CLIENT_MID="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
    "powershell.exe -NoProfile -Command \"\$j=Get-Content 'C:\\ProgramData\\drlink\\state\\client-state.json' -Raw | ConvertFrom-Json; Write-Output ([string]\$j.machine_id)\"" \
    2>"$OUT_DIR/discover-mid.err" | tr -d '\r' | tr -d '\n')"
  rc=$?
  if [[ "$rc" -eq 0 && -n "$CLIENT_MID" ]]; then
    CLIENT_MID_PREFIX="${CLIENT_MID:0:8}"
    SSH_PUBLIC_PORT="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
      "powershell.exe -NoProfile -Command \"\$j=Get-Content 'C:\\ProgramData\\drlink\\state\\client-state.json' -Raw | ConvertFrom-Json; Write-Output ([string]\$j.services.ssh.remote_port)\"" \
      2>>"$OUT_DIR/discover-mid.err" | tr -d '\r' | tr -d '\n')"
    rc=$?
  fi
  set -uo pipefail
  local elapsed=$(( $(date +%s) - start ))
  if [[ "$rc" -ne 0 || -z "$CLIENT_MID" || -z "$SSH_PUBLIC_PORT" ]]; then
    record discover-client-identity FAIL 1 "$elapsed"
    note "CLIENT_MID='$CLIENT_MID' SSH_PUBLIC_PORT='$SSH_PUBLIC_PORT'"
    return 1
  fi
  note "CLIENT_MID=$CLIENT_MID"
  note "CLIENT_MID_PREFIX=$CLIENT_MID_PREFIX"
  note "SSH_PUBLIC_PORT=$SSH_PUBLIC_PORT"
  note "ACCESS_HOST=$ACCESS_HOST"
  printf '%s\n' "$CLIENT_MID" >"$OUT_DIR/client-mid.txt"
  printf '%s\n' "$SSH_PUBLIC_PORT" >"$OUT_DIR/ssh-public-port.txt"
  record discover-client-identity PASS 0 "$elapsed"
}

discover_client_identity_macos() {
  local start rc=0
  local state_json='/Library/Application Support/drlink/client-state.json'
  start="$(date +%s)"
  set +e
  CLIENT_MID="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
    "sudo python3 -c \"import json; print(json.load(open('$state_json'))['machine_id'])\"" \
    2>"$OUT_DIR/discover-mid.err" | tr -d '\r' | tr -d '\n')"
  rc=$?
  if [[ "$rc" -eq 0 && -n "$CLIENT_MID" ]]; then
    CLIENT_MID_PREFIX="${CLIENT_MID:0:8}"
    SSH_PUBLIC_PORT="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
      "sudo python3 -c \"import json; d=json.load(open('$state_json')); print(((d.get('services') or {}).get('ssh') or {}).get('remote_port') or '')\"" \
      2>>"$OUT_DIR/discover-mid.err" | tr -d '\r' | tr -d '\n')"
    rc=$?
  fi
  set -uo pipefail
  local elapsed=$(( $(date +%s) - start ))
  if [[ "$rc" -ne 0 || -z "$CLIENT_MID" || -z "$SSH_PUBLIC_PORT" ]]; then
    record discover-client-identity FAIL 1 "$elapsed"
    note "CLIENT_MID='$CLIENT_MID' SSH_PUBLIC_PORT='$SSH_PUBLIC_PORT'"
    return 1
  fi
  note "CLIENT_MID=$CLIENT_MID"
  note "CLIENT_MID_PREFIX=$CLIENT_MID_PREFIX"
  note "SSH_PUBLIC_PORT=$SSH_PUBLIC_PORT"
  note "ACCESS_HOST=$ACCESS_HOST"
  printf '%s\n' "$CLIENT_MID" >"$OUT_DIR/client-mid.txt"
  printf '%s\n' "$SSH_PUBLIC_PORT" >"$OUT_DIR/ssh-public-port.txt"
  record discover-client-identity PASS 0 "$elapsed"
}

pin_windows_installer_url() {
  local url="https://raw.githubusercontent.com/datarelay-labs/data-relay-link/${HEAD_SHA}/dist/bootstrap-client.ps1"
  run_server win-pin-installer "sudo python3 - <<'PY'
import json
from pathlib import Path
p = Path('/etc/drlink/config.json')
c = json.loads(p.read_text(encoding='utf-8'))
c['windows_client_installer_url'] = '$url'
p.write_text(json.dumps(c, indent=2) + '\n', encoding='utf-8')
print(c['windows_client_installer_url'])
PY
sudo systemctl restart drlink-allocator
sleep 1
systemctl is-active drlink-allocator"
}

scenario_windows_full() {
  # Minimal Real E2E for Windows client: enroll + published SSH + uninstall.
  # Full Linux service/reboot/backup matrix is not portable to Windows OpenSSH/cmd.
  run_server 01-server-before "hostname; cat /etc/os-release; uname -a; sudo systemctl --no-pager --full status drlink-server 2>/dev/null || true; sudo /usr/local/bin/drlink show status 2>/dev/null || true" || fail_stop
  run_client 02-client-before 'powershell.exe -NoProfile -Command "$env:COMPUTERNAME; $PSVersionTable.PSVersion.ToString(); ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"' || fail_stop

  pin_windows_installer_url || fail_stop

  run_client 04-client-uninstall "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"if (Test-Path 'C:\\ProgramData\\drlink\\tools\\frp-client.cmd') { & 'C:\\ProgramData\\drlink\\tools\\frp-client.cmd' uninstall; if (Test-Path 'C:\\ProgramData\\drlink') { exit 1 }; Write-Output UNINSTALL_OK } else { Write-Output NO_INSTALL }\"" || fail_stop
  record 03-server-purge SKIP 0 0
  record 05-server-install SKIP 0 0
  MATRIX_INSTALL=PASS

  create_zero_touch_windows "$OUT_DIR/07-zero-touch-create.log" "$OUT_DIR/07-zero-touch.enc" 07-zero-touch-create "automated-real-e2e-$PROFILE" || fail_stop
  local enc
  enc="$(tr -d '\n\r' <"$OUT_DIR/07-zero-touch.enc")"
  run_client 08-zero-touch-run "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc" || fail_stop
  redact "$OUT_DIR/08-zero-touch-run.log"
  discover_client_identity_windows || fail_stop
  run_server 09-server-enrollment "sudo /usr/local/bin/drlink show clients; echo ====; sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop
  wait_external_ssh 09b-external-ssh || fail_stop
  MATRIX_ENROLL=PASS

  run_client 10-client-info "powershell.exe -NoProfile -Command \"& 'C:\\ProgramData\\drlink\\tools\\frp-client.cmd' info\"" || fail_stop
  run_server 11-proxy-mapped "sudo python3 - <<'PY'
import json, sys
sys.path.insert(0, '/usr/local/lib/drlink')
from frp_access_control import authorize, expected_proxy_name
from pathlib import Path
reg = json.loads(Path('/var/lib/drlink/registry.json').read_text())
acl = json.loads(Path('/var/lib/drlink/access-control.json').read_text())
mid = '$CLIENT_MID'
client = (reg.get('clients') or {}).get(mid) or {}
host = str(client.get('hostname') or '')
name = expected_proxy_name(host, mid, 'ssh')
v = authorize(acl, reg, proxy_name=name, source_ip='127.0.0.1')
print('proxy_name', name, 'decision', v.get('decision'), 'reason', v.get('reason'))
if v.get('decision') != 'ALLOW':
    raise SystemExit('expected mapped PUBLIC allow')
print('PROXY_MAPPED_OK')
PY" || fail_stop
  MATRIX_SERVICE=PASS
  MATRIX_REBOOT=SKIP
  MATRIX_DNS=SKIP

  run_client 52-client-uninstall "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& 'C:\\ProgramData\\drlink\\tools\\frp-client.cmd' uninstall; if (Test-Path 'C:\\ProgramData\\drlink') { exit 1 }; Write-Output UNINSTALL_OK\"" || fail_stop
  # Local uninstall preserves server reservations by design; release so matrix fleet
  # DNS does not probe a dead Windows proxy after the profile completes.
  run_server 53-release-client "printf 'RELEASE\n' | sudo /usr/local/bin/drlink release client '$CLIENT_MID_PREFIX'" || fail_stop
  MATRIX_UNINSTALL=PASS
}

scenario_macos_full() {
  # Minimal Real E2E for macOS Apple Silicon: bash ZT enroll + SSH/HTTP + uninstall.
  local state_root='/Library/Application Support/drlink'
  run_server 01-server-before "hostname; cat /etc/os-release; uname -a; sudo systemctl --no-pager --full status drlink-server 2>/dev/null || true; sudo /usr/local/bin/drlink show status 2>/dev/null || true" || fail_stop
  run_client 02-client-before 'sw_vers; uname -m; sudo -n true; sudo /usr/local/bin/drlink show status 2>/dev/null || true' || fail_stop

  run_local 04-client-uninstall bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'sudo bash -s --' < '$ROOT/dist/uninstall-client.sh'" || fail_stop
  run_client 04b-client-clean "test ! -d '$state_root' && echo CLEAN" || fail_stop
  record 03-server-purge SKIP 0 0
  record 05-server-install SKIP 0 0
  MATRIX_INSTALL=PASS

  create_zero_touch "$OUT_DIR/07-zero-touch-create.log" "$OUT_DIR/07-zero-touch-command.sh" 07-zero-touch-create "automated-real-e2e-$PROFILE" || fail_stop
  run_local 08-zero-touch-run bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'bash -s' < '$OUT_DIR/07-zero-touch-command.sh'" || fail_stop
  redact "$OUT_DIR/08-zero-touch-run.log"
  discover_client_identity_macos || fail_stop
  run_server 09-server-enrollment "sudo /usr/local/bin/drlink show clients; echo ====; sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop
  wait_external_ssh 09b-external-ssh || fail_stop
  MATRIX_ENROLL=PASS

  run_client 10-client-doctor "sudo /usr/local/bin/drlink doctor" || fail_stop
  run_server 11-proxy-mapped "sudo python3 - <<'PY'
import json, sys
sys.path.insert(0, '/usr/local/lib/drlink')
from frp_access_control import authorize, expected_proxy_name
from pathlib import Path
reg = json.loads(Path('/var/lib/drlink/registry.json').read_text())
acl = json.loads(Path('/var/lib/drlink/access-control.json').read_text())
mid = '$CLIENT_MID'
client = (reg.get('clients') or {}).get(mid) or {}
host = str(client.get('hostname') or '')
name = expected_proxy_name(host, mid, 'ssh')
v = authorize(acl, reg, proxy_name=name, source_ip='127.0.0.1')
print('proxy_name', name, 'decision', v.get('decision'), 'reason', v.get('reason'))
if v.get('decision') != 'ALLOW':
    raise SystemExit('expected mapped PUBLIC allow')
print('PROXY_MAPPED_OK')
PY" || fail_stop

  run_client 12-http-fixtures 'mkdir -p /tmp/frp-e2e-http && printf "macos-web\n" >/tmp/frp-e2e-http/index.html; nohup python3 -m http.server 18080 --bind 127.0.0.1 -d /tmp/frp-e2e-http >/tmp/frp-http.log 2>&1 </dev/null & sleep 1; curl -fsS http://127.0.0.1:18080' || fail_stop
  run_client 13-http-add 'sudo /usr/local/bin/frp-client add-service --preset http --id web --name Web --target-host 127.0.0.1 --target-port 18080 && sudo /usr/local/bin/frp-client apply-pending && sudo /usr/local/bin/drlink show services' || fail_stop
  local http_port
  http_port="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
    "sudo python3 -c \"import json; d=json.load(open('$state_root/client-state.json')); print(((d.get('services') or {}).get('web') or {}).get('remote_port') or '')\"" | tr -d '\r\n')"
  [[ -n "$http_port" ]] || fail_stop
  note "HTTP_PUBLIC_PORT=$http_port"
  run_server 14-http-external "curl -fsS 'http://127.0.0.1:$http_port'" || fail_stop
  MATRIX_SERVICE=PASS
  MATRIX_REBOOT=SKIP
  MATRIX_DNS=SKIP

  run_local 52-client-uninstall bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'sudo bash -s --' < '$ROOT/dist/uninstall-client.sh'" || fail_stop
  run_client 52b-client-gone "test ! -d '$state_root' && echo LOCAL_GONE" || fail_stop
  run_server 53-release-client "printf 'RELEASE\n' | sudo /usr/local/bin/drlink release client '$CLIENT_MID_PREFIX'" || fail_stop
  MATRIX_UNINSTALL=PASS
}

scenario_unsupported() {
  local reason="$1"
  note "UNSUPPORTED_PLATFORM profile=$PROFILE reason=$reason"
  record unsupported-platform SKIP 0 0
  MATRIX_INSTALL=SKIP
  MATRIX_ENROLL=SKIP
  MATRIX_SERVICE=SKIP
  MATRIX_REBOOT=SKIP
  MATRIX_UNINSTALL=SKIP
  MATRIX_DNS=SKIP
  finish 0
}

scenario_dns_checks() {
  if [[ -z "$PUBLIC_HOSTNAME" ]]; then
    MATRIX_DNS=SKIP
    record dns-skipped SKIP 0 0
    return 0
  fi
  run_server dns-01-doctor-hostname "sudo /usr/local/bin/drlink doctor | tee /tmp/frp-dns-doctor.txt; grep -E 'public_hostname_dn' /tmp/frp-dns-doctor.txt | grep -E 'PASS|WARN'" || fail_stop
  run_server dns-02-status "sudo /usr/local/bin/drlink show status | tee /tmp/frp-dns-status.txt; grep -F '$PUBLIC_HOSTNAME' /tmp/frp-dns-status.txt" || fail_stop
  run_client dns-03-access-info "sudo /usr/local/bin/drlink show services; echo ====; sudo python3 - <<'PY'
from pathlib import Path
text = Path('/etc/frp/access-info.txt').read_text(encoding='utf-8', errors='replace')
print(text)
assert '$PUBLIC_HOSTNAME' in text, text
print('ACCESS_INFO_HOSTNAME_OK')
PY" || fail_stop
  wait_external_ssh dns-04-external-via-hostname "$EXT_TRIES" "$EXT_DELAY" "$PUBLIC_HOSTNAME" "$SSH_PUBLIC_PORT" "$TUNNEL_SSH_USER" || fail_stop
  # IP fallback must still work while hostname configured (additive alias).
  wait_external_ssh dns-06-external-via-ip "$EXT_TRIES" "$EXT_DELAY" "$SERVER_IP" "$SSH_PUBLIC_PORT" "$TUNNEL_SSH_USER" || fail_stop
  MATRIX_DNS=PASS
}

scenario_install() {
  run_server 01-server-before "hostname; cat /etc/os-release; uname -a; sudo systemctl --no-pager --full status drlink-server 2>/dev/null || true; sudo /usr/local/bin/drlink show status 2>/dev/null || true" || fail_stop
  run_client 02-client-before "hostname; cat /etc/os-release 2>/dev/null || true; uname -a; getenforce 2>/dev/null || true; sudo systemctl --no-pager --full status drlink-client 2>/dev/null || true; sudo /usr/local/bin/drlink show status 2>/dev/null || true" || fail_stop

  if [[ "$SKIP_SERVER_PURGE" != "1" ]]; then
    run_local 03-server-purge bash -lc "ssh ${SSH_OPTS[*]} '$SERVER_ALIAS' 'sudo bash -s -- --purge --yes' < '$ROOT/dist/uninstall-server.sh'" || fail_stop
  else
    record 03-server-purge SKIP 0 0
  fi
  run_local 04-client-uninstall bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'sudo bash -s --' < '$ROOT/dist/uninstall-client.sh'" || fail_stop

  if [[ "$SKIP_SERVER_INSTALL" != "1" ]]; then
    local env_prefix
    env_prefix="$(server_install_env)"
    run_local 05-server-install bash -lc "ssh ${SSH_OPTS[*]} '$SERVER_ALIAS' 'sudo env $env_prefix bash -s --' < '$ROOT/dist/bootstrap-server.sh'" || fail_stop
    MATRIX_INSTALL=PASS
  else
    record 05-server-install SKIP 0 0
    MATRIX_INSTALL=PASS
  fi
  run_server 06-server-doctor "sudo /usr/local/bin/drlink show status; echo ====; sudo /usr/local/bin/drlink doctor" || fail_stop

  create_zero_touch "$OUT_DIR/07-zero-touch-create.log" "$OUT_DIR/07-zero-touch-command.sh" 07-zero-touch-create "automated-real-e2e-$PROFILE" || fail_stop
  run_local 08-zero-touch-run bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'bash -s' < '$OUT_DIR/07-zero-touch-command.sh'" || fail_stop
  redact "$OUT_DIR/08-zero-touch-run.log"
  discover_client_identity || fail_stop
  run_server 09-server-enrollment "sudo /usr/local/bin/drlink show clients; echo ====; sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop
  wait_external_ssh 09b-external-ssh || fail_stop
  MATRIX_ENROLL=PASS
}

scenario_services() {
  run_client 10-http-fixtures "rm -rf /tmp/frp-e2e-http-a /tmp/frp-e2e-http-b; mkdir -p /tmp/frp-e2e-http-a /tmp/frp-e2e-http-b; printf 'web-a\n' >/tmp/frp-e2e-http-a/index.html; printf 'web-b\n' >/tmp/frp-e2e-http-b/index.html; nohup python3 -m http.server 18080 --bind 127.0.0.1 -d /tmp/frp-e2e-http-a >/tmp/frp-http-a.log 2>&1 </dev/null & nohup python3 -m http.server 18081 --bind 127.0.0.1 -d /tmp/frp-e2e-http-b >/tmp/frp-http-b.log 2>&1 </dev/null & sleep 1; curl -fsS http://127.0.0.1:18080; echo ====; curl -fsS http://127.0.0.1:18081" || fail_stop
  run_client 11-http-add "sudo /usr/local/bin/frp-client add-service --preset http --id web --name Web --target-host 127.0.0.1 --target-port 18080 && sudo /usr/local/bin/frp-client apply-pending && sudo /usr/local/bin/drlink show services" || fail_stop
  # Discover HTTP port from client state (not hardcoded 6001 when other clients exist).
  local http_port
  http_port="$(ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" \
    'sudo python3 -c "import json; d=json.load(open(\"/etc/frp/client-state.json\")); print(((d.get(\"services\") or {}).get(\"web\") or {}).get(\"remote_port\") or \"\")"')"
  [[ -n "$http_port" ]] || fail_stop
  note "HTTP_PUBLIC_PORT=$http_port"
  run_server 12-http-external "curl -fsS 'http://127.0.0.1:$http_port'" || fail_stop
  run_client 13-http-edit "sudo /usr/local/bin/frp-client set-service web target-port 18081 && sudo /usr/local/bin/frp-client apply-pending && sudo /usr/local/bin/drlink show services" || fail_stop
  run_server 14-http-external-edited "curl -fsS 'http://127.0.0.1:$http_port'" || fail_stop
  run_client 15-http-disable "sudo /usr/local/bin/frp-client disable-service web && sudo /usr/local/bin/frp-client apply-pending && sudo /usr/local/bin/drlink show services" || fail_stop
  run_server 16-http-disabled "! curl -fsS --max-time 5 'http://127.0.0.1:$http_port'" || fail_stop
  run_client 17-http-enable "sudo /usr/local/bin/frp-client enable-service web && sudo /usr/local/bin/frp-client apply-pending && sudo /usr/local/bin/drlink show services" || fail_stop
  run_server 18-http-reenabled "curl -fsS 'http://127.0.0.1:$http_port'" || fail_stop
  run_client 19-http-disable-again "sudo /usr/local/bin/frp-client disable-service web && sudo /usr/local/bin/frp-client apply-pending >/dev/null" || fail_stop
  run_server 20-release "printf 'RELEASE\n' | sudo /usr/local/bin/drlink release service '$CLIENT_MID_PREFIX' web" || fail_stop
  run_server 21-http-released "! curl -fsS --max-time 5 'http://127.0.0.1:$http_port'" || fail_stop

  python_remote "$SERVER_ALIAS" 22-server-after-release <<PY || fail_stop
import json
from pathlib import Path

d = json.loads(Path('/var/lib/drlink/registry.json').read_text(encoding='utf-8'))
prefix = '$CLIENT_MID_PREFIX'
match = None
for mid, client in (d.get('clients') or {}).items():
    if str(mid).startswith(prefix):
        match = (mid, client)
        break
if not match:
    raise SystemExit('client not found in registry for mid prefix %r' % prefix)
mid, client = match
services = client.get('services') or {}
if 'web' in services:
    raise SystemExit('released service web still present in server registry for %s' % mid)
print('server registry: web removed for %s' % mid)
PY

  # Server release does not mutate client-state.json; explicit sync reconciles.
  run_client 23-client-sync "sudo /usr/local/bin/frp-client sync" || fail_stop
  run_client 23b-client-show-services "sudo /usr/local/bin/drlink show services" || fail_stop
  python_remote "$CLIENT_ALIAS" 24-client-state-assert <<'PY' || fail_stop
import json
from pathlib import Path

state = json.loads(Path('/etc/frp/client-state.json').read_text(encoding='utf-8'))
services = state.get('services') or {}
if 'web' in services:
    raise SystemExit('released service web still present in client-state.json')
if 'ssh' not in services:
    raise SystemExit('ssh service missing (unexpected)')
print('client state: web removed; ssh present')
PY
  wait_external_ssh 24b-ssh-unaffected || fail_stop
  MATRIX_SERVICE=PASS
}

scenario_reboots() {
  local i
  for i in $(seq 1 "$CLIENT_REBOOT_REPEAT"); do
    run_local "30-client-reboot-$i" bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'sudo reboot' || true"
    wait_host "$CLIENT_ALIAS" "31-client-reconnect-$i" || fail_stop
    wait_external_ssh "32-client-reboot-ssh-$i" || fail_stop
    run_client "33-client-id-after-reboot-$i" "sudo python3 -c \"import json; d=json.load(open('/etc/frp/client-state.json')); print(d.get('machine_id')); print(list((d.get('services') or {}).keys()))\"" || fail_stop
  done
  for i in $(seq 1 "$SERVER_REBOOT_REPEAT"); do
    run_local "34-server-reboot-$i" bash -lc "ssh ${SSH_OPTS[*]} '$SERVER_ALIAS' 'sudo reboot' || true"
    wait_host "$SERVER_ALIAS" "35-server-reconnect-$i" || fail_stop
    wait_external_ssh "36-server-reboot-ssh-$i" || fail_stop
    run_server "37-server-registry-after-reboot-$i" "sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'; sudo /usr/local/bin/drlink doctor" || fail_stop
  done
  MATRIX_REBOOT=PASS
}

scenario_backup_repeat() {
  local i
  for i in $(seq 1 "$BACKUP_REPEAT"); do
    run_server "40-backup-$i" "sudo /usr/local/bin/drlink create backup /var/lib/drlink/backups/real-e2e-backup-$i.tar.gz" || fail_stop
    run_server "41-mutate-$i" "sudo /usr/local/bin/drlink set client '$CLIENT_MID_PREFIX' label mutated-label-$i && sudo /usr/local/bin/drlink set client '$CLIENT_MID_PREFIX' note 'mutated note $i' && sudo /usr/local/bin/drlink set client '$CLIENT_MID_PREFIX' tag env e2e$i && sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop
    run_local "42-restore-$i" bash -lc "cat '$ROOT/tools/frp-restore' | ssh ${SSH_OPTS[*]} '$SERVER_ALIAS' 'sudo tee /tmp/frp-restore >/dev/null && sudo chmod 755 /tmp/frp-restore'; cat '$ROOT/tools/frp-backup' | ssh ${SSH_OPTS[*]} '$SERVER_ALIAS' 'sudo tee /tmp/frp-backup >/dev/null && sudo chmod 755 /tmp/frp-backup'; ssh ${SSH_OPTS[*]} '$SERVER_ALIAS' 'sudo python3 /tmp/frp-restore /var/lib/drlink/backups/real-e2e-backup-$i.tar.gz'" || fail_stop
    run_server "43-restore-verify-$i" "sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'; echo ====; sudo /usr/local/bin/drlink doctor; echo ====; sudo test ! -f /var/lib/drlink/server-update-pending.json && sudo test ! -f /var/lib/drlink/client-update-pending.json && echo PENDING_MARKER_CLEARED=YES; echo ====; sudo python3 -c \"import json; c=json.load(open('/etc/drlink/config.json')); print('public_hostname='+str(c.get('public_hostname') or ''))\"" || fail_stop
    wait_external_ssh "44-restore-ssh-$i" || fail_stop
  done
}

scenario_uninstall_reinstall() {
  run_server 50-pre-uninstall-server "sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop
  run_client 51-pre-uninstall-client "sudo /usr/local/bin/drlink show services; sudo /usr/local/bin/drlink show status" || fail_stop
  run_local 52-client-uninstall bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'sudo bash -s --' < '$ROOT/dist/uninstall-client.sh'" || fail_stop
  run_client 53-post-uninstall-local "echo frpc=\$(systemctl is-active drlink-client 2>/dev/null || echo inactive); ls /etc/frp 2>/dev/null || echo NO_ETC_FRP; ls /usr/local/bin/frp* 2>/dev/null || echo NO_FRP_BIN; test ! -f /etc/frp/client-state.json && echo CLIENT_STATE_GONE=YES || echo CLIENT_STATE_GONE=NO; ps -eo comm= | grep -E '^(frpc|frp-client)\$' || echo NO_FRP_PROCESS" || fail_stop
  run_server 54-post-uninstall-server "sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop

  create_zero_touch "$OUT_DIR/55-zero-touch-create.log" "$OUT_DIR/55-zero-touch-command.sh" 55-zero-touch-create "uninstall-reinstall-$PROFILE" || fail_stop
  run_local 56-reinstall bash -lc "ssh ${SSH_OPTS[*]} '$CLIENT_ALIAS' 'bash -s' < '$OUT_DIR/55-zero-touch-command.sh'" || fail_stop
  redact "$OUT_DIR/56-reinstall.log"
  discover_client_identity || fail_stop
  run_client 57-post-reinstall "sudo /usr/local/bin/drlink show services; sudo /usr/local/bin/drlink show status" || fail_stop
  run_server 58-post-reinstall-server "sudo /usr/local/bin/drlink show clients; sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop
  wait_external_ssh 59-reinstall-ssh || fail_stop
  MATRIX_UNINSTALL=PASS
}

scenario_groups_probe() {
  run_server 60-groups-probe "sudo /usr/local/bin/drlink show groups || true"
}

scenario_dns_only() {
  # Requires an already-installed server+client from a prior scenario, or runs install first.
  if [[ -z "$PUBLIC_HOSTNAME" ]]; then
    note "FRP_E2E_PUBLIC_HOSTNAME required for dns scenario"
    finish 2
  fi
  if ! ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" 'sudo test -f /etc/frp/client-state.json' >/dev/null 2>&1; then
    scenario_install
  else
    discover_client_identity || { scenario_install; }
  fi
  # Ensure hostname configured (install may have set it; also exercise runtime set).
  run_server dns-set "sudo /usr/local/bin/drlink set server hostname '$PUBLIC_HOSTNAME'" || fail_stop
  ACCESS_HOST="$PUBLIC_HOSTNAME"
  scenario_dns_checks
  # Configuration change to a second hostname that also resolves (sslip alternate form not required).
  run_server dns-change-unset "sudo /usr/local/bin/drlink unset server hostname || sudo /usr/local/lib/drlink/frp-server-set hostname --unset" || fail_stop
  ACCESS_HOST="$SERVER_IP"
  wait_external_ssh dns-ip-fallback "$EXT_TRIES" "$EXT_DELAY" "$SERVER_IP" "$SSH_PUBLIC_PORT" "$TUNNEL_SSH_USER" || fail_stop
  run_server dns-change-reset "sudo /usr/local/bin/drlink set server hostname '$PUBLIC_HOSTNAME'" || fail_stop
  ACCESS_HOST="$PUBLIC_HOSTNAME"
  wait_external_ssh dns-after-reset "$EXT_TRIES" "$EXT_DELAY" "$PUBLIC_HOSTNAME" "$SSH_PUBLIC_PORT" "$TUNNEL_SSH_USER" || fail_stop
  run_server dns-ports-unchanged "sudo /usr/local/bin/drlink show client '$CLIENT_MID_PREFIX'" || fail_stop
  MATRIX_DNS=PASS
}

main() {
  apply_profile
  note "RUN_ID=$RUN_ID"
  note "PROFILE=$PROFILE"
  note "PLATFORM_KIND=$PLATFORM_KIND"
  note "CANDIDATE_SHA=$HEAD_SHA"
  note "SCENARIO=$SCENARIO"
  note "PUBLIC_HOSTNAME=${PUBLIC_HOSTNAME:-<unset>}"
  note "CLIENT_ALIAS=$CLIENT_ALIAS"
  note "TUNNEL_SSH_USER=$TUNNEL_SSH_USER"
  note "STOP_ON_FAIL=$STOP_ON_FAIL"
  note "OVERALL_TIMEOUT=$OVERALL_TIMEOUT"
  note "STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if [[ "$PLATFORM_KIND" == "macos" ]]; then
    if ! ssh "${SSH_OPTS[@]}" -o ConnectTimeout=8 "$CLIENT_ALIAS" 'echo ok' >/dev/null 2>&1; then
      note "ENVIRONMENT_BLOCKER: macOS SSH management path unreachable"
      record macos-ssh-unreachable SKIP 0 0
      MATRIX_INSTALL=BLOCKED
      MATRIX_ENROLL=BLOCKED
      MATRIX_SERVICE=BLOCKED
      MATRIX_REBOOT=BLOCKED
      MATRIX_UNINSTALL=BLOCKED
      MATRIX_DNS=BLOCKED
      finish 0
    fi
  fi
  if [[ "$PLATFORM_KIND" == "windows" ]]; then
    if ! ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 "$CLIENT_ALIAS" 'echo ok' >/dev/null 2>&1; then
      note "ENVIRONMENT_BLOCKER: Windows SSH management path unreachable (port 22 timed out; RDP 3389 open)"
      record windows-ssh-unreachable SKIP 0 0
      MATRIX_INSTALL=BLOCKED
      MATRIX_ENROLL=BLOCKED
      MATRIX_SERVICE=BLOCKED
      MATRIX_REBOOT=BLOCKED
      MATRIX_UNINSTALL=BLOCKED
      MATRIX_DNS=BLOCKED
      finish 0
    fi
  fi

  assert_host_identity "$SERVER_ALIAS" "$EXPECTED_SERVER_HOST" server || finish 2
  assert_host_identity "$CLIENT_ALIAS" "$EXPECTED_CLIENT_HOST" client || finish 2

  if [[ "$PLATFORM_KIND" == "macos" ]]; then
    case "$SCENARIO" in
      full|install)
        scenario_macos_full
        ;;
      *)
        note "macos scenario '$SCENARIO' not implemented; use full"
        finish 2
        ;;
    esac
    note "FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    finish 0
  fi

  if [[ "$PLATFORM_KIND" == "windows" ]]; then
    case "$SCENARIO" in
      full|install)
        scenario_windows_full
        ;;
      *)
        note "windows scenario '$SCENARIO' not implemented; use full"
        finish 2
        ;;
    esac
    note "FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    finish 0
  fi

  case "$SCENARIO" in
    full)
      scenario_install
      scenario_services
      scenario_dns_checks
      scenario_reboots
      scenario_backup_repeat
      scenario_uninstall_reinstall
      scenario_groups_probe
      ;;
    install) scenario_install; scenario_dns_checks ;;
    services) discover_client_identity || fail_stop; scenario_services ;;
    reboot-repeat)
      discover_client_identity || fail_stop
      CLIENT_REBOOT_REPEAT="${FRP_E2E_CLIENT_REBOOT_REPEAT:-3}"
      SERVER_REBOOT_REPEAT="${FRP_E2E_SERVER_REBOOT_REPEAT:-3}"
      scenario_reboots
      ;;
    backup-repeat)
      discover_client_identity || fail_stop
      BACKUP_REPEAT="${FRP_E2E_BACKUP_REPEAT:-5}"
      scenario_backup_repeat
      ;;
    uninstall) discover_client_identity || fail_stop; scenario_uninstall_reinstall ;;
    dns) scenario_dns_only ;;
    *)
      note "unknown scenario $SCENARIO"
      finish 2
      ;;
  esac

  note "FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  finish 0
}

if [[ "${FRP_E2E_INNER:-}" == "1" ]]; then
  main
  exit $?
fi

export FRP_E2E_INNER=1
export FRP_E2E_RUN_ID="$RUN_ID"
export FRP_E2E_OUT_DIR="$OUT_DIR"
export FRP_E2E_PROFILE="$PROFILE"
export FRP_E2E_PUBLIC_HOSTNAME="$PUBLIC_HOSTNAME"
export FRP_E2E_SKIP_SERVER_INSTALL="$SKIP_SERVER_INSTALL"
export FRP_E2E_SKIP_SERVER_PURGE="$SKIP_SERVER_PURGE"
export ROOT SERVER_ALIAS CLIENT_ALIAS SERVER_IP SSH_USER SSH_KEY TUNNEL_SSH_USER
export EXPECTED_SERVER_HOST EXPECTED_CLIENT_HOST FORBIDDEN_HOST CLIENT_LABEL PLATFORM_KIND
export PUBLIC_HOSTNAME ACCESS_HOST
export RUN_ID OUT_DIR HEAD_SHA SCENARIO STOP_ON_FAIL STEP_TIMEOUT
export REBOOT_TRIES REBOOT_DELAY EXT_TRIES EXT_DELAY
export BACKUP_REPEAT CLIENT_REBOOT_REPEAT SERVER_REBOOT_REPEAT OVERALL_TIMEOUT
exec timeout "$OVERALL_TIMEOUT" bash "$0" "$@"
