#!/usr/bin/env bash
# Multi-OS Real E2E matrix + fleet/DNS orchestration.
# Reuses tests/run-real-e2e.sh profile adapters.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${FRP_E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${FRP_E2E_MATRIX_OUT:-$ROOT/e2e-reports/matrix-$RUN_ID}"
PUBLIC_HOSTNAME="${FRP_E2E_PUBLIC_HOSTNAME:-221.139.249.112.nip.io}"
SERVER_IP="${FRP_E2E_SERVER_IP:-221.139.249.112}"
SERVER_ALIAS="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)
SSH_KEY="${FRP_E2E_SSH_KEY:-$HOME/.ssh/frp_e2e_ed25519}"
TARGETS="${FRP_E2E_MATRIX_TARGETS:-ubuntu-24.04,amazon-linux-2023,rocky-linux-8.10,rocky-linux-9.4,macos-arm64,windows-10}"
INCLUDE_FLEET="${FRP_E2E_MATRIX_FLEET:-1}"
INCLUDE_DNS_IP_FALLBACK="${FRP_E2E_MATRIX_IP_FALLBACK:-1}"

mkdir -p "$OUT_ROOT"
SUMMARY="$OUT_ROOT/summary.txt"
TABLE="$OUT_ROOT/matrix.tsv"
: >"$SUMMARY"
: >"$TABLE"
printf 'PLATFORM\tINSTALL\tENROLL\tSERVICE\tREBOOT\tUNINSTALL\tDNS\n' >>"$TABLE"

note() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }

note "MATRIX_RUN_ID=$RUN_ID"
note "PUBLIC_HOSTNAME=$PUBLIC_HOSTNAME"
note "TARGETS=$TARGETS"
note "STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# DNS preflight from controller (do not modify external DNS).
note "DNS_TEST_HOSTNAME=$PUBLIC_HOSTNAME"
DNS_A="$(dig +short "$PUBLIC_HOSTNAME" A 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
DNS_AAAA="$(dig +short "$PUBLIC_HOSTNAME" AAAA 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
note "DNS_A_RECORD=${DNS_A:-<none>}"
note "DNS_AAAA_RECORD=${DNS_AAAA:-<none>}"
note "EXPECTED_FRP_SERVER_IP=$SERVER_IP"
if printf '%s\n' "$DNS_A" | tr ' ' '\n' | grep -qx "$SERVER_IP"; then
  note "DNS_MATCH=YES"
  DNS_OK=1
else
  note "DNS_MATCH=NO"
  DNS_OK=0
  note "Required record: A $PUBLIC_HOSTNAME -> $SERVER_IP"
fi

IFS=',' read -r -a PROFILE_LIST <<<"$TARGETS"
FAILED=0

run_profile() {
  local profile="$1"
  local skip_purge="${2:-0}"
  local skip_install="${3:-0}"
  local out="$OUT_ROOT/$profile"
  mkdir -p "$out"
  note "==== PROFILE $profile purge=$skip_purge install_skip=$skip_install ===="
  local env_dns=()
  if [[ "$DNS_OK" -eq 1 ]]; then
    env_dns=(FRP_E2E_PUBLIC_HOSTNAME="$PUBLIC_HOSTNAME")
  else
    env_dns=(FRP_E2E_PUBLIC_HOSTNAME="")
  fi
  set +e
  env \
    "${env_dns[@]}" \
    FRP_E2E_PROFILE="$profile" \
    FRP_E2E_SCENARIO=full \
    FRP_E2E_RUN_ID="$RUN_ID-$profile" \
    FRP_E2E_OUT_DIR="$out" \
    FRP_E2E_SKIP_SERVER_PURGE="$skip_purge" \
    FRP_E2E_SKIP_SERVER_INSTALL="$skip_install" \
    FRP_E2E_SERVER_IP="$SERVER_IP" \
    FRP_E2E_SERVER_ALIAS="$SERVER_ALIAS" \
    FRP_E2E_CLIENT_REBOOT_REPEAT=1 \
    FRP_E2E_SERVER_REBOOT_REPEAT=0 \
    FRP_E2E_BACKUP_REPEAT=1 \
    FRP_E2E_STOP_ON_FAIL=1 \
    bash "$ROOT/tests/run-real-e2e.sh"
  local rc=$?
  set -uo pipefail
  if [[ -f "$out/matrix-row.tsv" ]]; then
    cat "$out/matrix-row.tsv" >>"$TABLE"
  else
    printf '%s\tFAIL\tFAIL\tFAIL\tFAIL\tFAIL\tFAIL\n' "$profile" >>"$TABLE"
  fi
  note "PROFILE_RC_$profile=$rc"
  if [[ "$rc" -ne 0 ]]; then
    FAILED=$((FAILED + 1))
  fi
  return "$rc"
}

# First supported Linux profile installs/purges server; subsequent share server.
first_linux=1
for profile in "${PROFILE_LIST[@]}"; do
  profile="$(echo "$profile" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -n "$profile" ]] || continue
  case "$profile" in
    macos|macos-arm64|windows|windows-10)
      run_profile "$profile" 1 1 || true
      ;;
    *)
      if [[ "$first_linux" -eq 1 ]]; then
        run_profile "$profile" 0 0 || true
        first_linux=0
      else
        # Keep server; do not purge between Linux clients (fleet buildup).
        run_profile "$profile" 1 1 || true
      fi
      ;;
  esac
done

# Fleet simultaneous-state checks for Linux clients that enrolled.
if [[ "$INCLUDE_FLEET" == "1" && "$first_linux" -eq 0 ]]; then
  note "==== FLEET simultaneous enrollment checks ===="
  set +e
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'sudo /usr/local/sbin/frpctl show clients' \
    | tee "$OUT_ROOT/fleet-clients.txt"
  python3 - "$OUT_ROOT/fleet-clients.txt" "$OUT_ROOT/fleet-assert.log" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
# Collect machine id prefixes / ids from show clients output.
ids = sorted(set(re.findall(r'\b([0-9a-f]{8,64})\b', text, flags=re.I)))
open(sys.argv[2], "w", encoding="utf-8").write("IDS=%s\nCOUNT=%d\n" % (",".join(ids), len(ids)))
if len(ids) < 2:
    raise SystemExit("expected at least 2 enrolled clients in fleet output, got %d" % len(ids))
print("FLEET_CLIENT_IDS_OK count=%d" % len(ids))
PY
  fleet_rc=$?
  set -uo pipefail
  note "FLEET_ASSERT_RC=$fleet_rc"
  if [[ "$fleet_rc" -ne 0 ]]; then
    FAILED=$((FAILED + 1))
  fi

  # Cross-client isolation: release must not affect other clients' SSH ports.
  note "==== FLEET server reboot ===="
  set +e
  # Snapshot ports before reboot.
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" \
    "sudo python3 -c \"import json; d=json.load(open('/var/lib/frp-auto-deploy/registry.json'));
print(json.dumps({mid[:8]: ((c.get('services') or {}).get('ssh') or {}).get('remote_port') for mid,c in (d.get('clients') or {}).items()}))\"" \
    | tee "$OUT_ROOT/fleet-ports-before-reboot.json"
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'sudo reboot' || true
  for i in $(seq 1 36); do
    if ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'hostname' >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
  # Bounded wait for published SSH proxies to recover after frps restart.
  for i in $(seq 1 24); do
    if ssh "${SSH_OPTS[@]}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o IdentitiesOnly=yes -i "$SSH_KEY" -p 6000 "aella@$SERVER_IP" 'hostname' >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'sudo /usr/local/sbin/frpctl show clients; sudo /usr/local/sbin/frpctl doctor' \
    | tee "$OUT_ROOT/fleet-after-reboot.txt"
  set -uo pipefail

  # External SSH via DNS hostname for each discovered ssh port from registry.
  if [[ "$DNS_OK" -eq 1 ]]; then
    note "==== FLEET DNS access ===="
    set +e
    python3 - "$OUT_ROOT" "$SERVER_ALIAS" "$PUBLIC_HOSTNAME" "$SSH_KEY" <<'PY'
import json, subprocess, sys, time
from pathlib import Path
out, alias, host, key = sys.argv[1:5]
raw = subprocess.check_output(
    ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", alias,
     "sudo python3 -c \"import json; print(json.dumps(json.load(open('/var/lib/frp-auto-deploy/registry.json'))))\""],
    text=True,
)
reg = json.loads(raw)
ports = []
for mid, client in (reg.get("clients") or {}).items():
    ssh_svc = (client.get("services") or {}).get("ssh") or {}
    port = ssh_svc.get("remote_port")
    user = ssh_svc.get("ssh_user") or "aella"
    if port:
        ports.append((mid[:8], int(port), user))
Path(out, "fleet-ports.json").write_text(json.dumps(ports, indent=2), encoding="utf-8")
fails = 0
for mid, port, user in ports:
    ok = False
    for _ in range(12):
        cmd = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes", "-i", key, "-p", str(port),
            f"{user}@{host}", "hostname",
        ]
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ok = True
            break
        except Exception:
            time.sleep(5)
    if ok:
        print(f"PASS dns-ssh {mid} {user}@{host}:{port}")
    else:
        print(f"FAIL dns-ssh {mid} {user}@{host}:{port}")
        fails += 1
raise SystemExit(fails)
PY
    fleet_dns_rc=$?
    set -uo pipefail
    note "FLEET_DNS_RC=$fleet_dns_rc"
    if [[ "$fleet_dns_rc" -ne 0 ]]; then
      FAILED=$((FAILED + 1))
    fi
  fi

  # Cross-client isolation: disable one SSH must not drop another client's port.
  note "==== FLEET cross-client isolation ===="
  set +e
  ssh "${SSH_OPTS[@]}" frp-e2e-client 'sudo /usr/local/bin/frp-client disable-service ssh && sudo /usr/local/bin/frp-client apply-pending' \
    | tee "$OUT_ROOT/fleet-isolation-disable.txt"
  sleep 3
  if ssh "${SSH_OPTS[@]}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -i "$SSH_KEY" -p 6001 "ec2-user@$PUBLIC_HOSTNAME" 'hostname' >/dev/null 2>&1; then
    note "CROSS_CLIENT_ISOLATION=PASS"
  else
    note "CROSS_CLIENT_ISOLATION=FAIL"
    FAILED=$((FAILED + 1))
  fi
  ssh "${SSH_OPTS[@]}" frp-e2e-client 'sudo /usr/local/bin/frp-client enable-service ssh && sudo /usr/local/bin/frp-client apply-pending' \
    | tee "$OUT_ROOT/fleet-isolation-enable.txt"
  set -uo pipefail

  # Fleet backup/restore once.
  note "==== FLEET backup/restore ===="
  set +e
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" \
    'sudo /usr/local/sbin/frpctl create backup /var/lib/frp-auto-deploy/backups/matrix-fleet-backup.tar.gz' \
    | tee "$OUT_ROOT/fleet-backup.txt"
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" \
    "sudo /usr/local/sbin/frpctl set server hostname '$PUBLIC_HOSTNAME' || true; sudo python3 -c \"import json; c=json.load(open('/etc/frp-auto-deploy/config.json')); print(c.get('public_hostname'))\"" \
    | tee "$OUT_ROOT/fleet-hostname-before-restore.txt"
  # Mutate then restore.
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'sudo /usr/local/sbin/frpctl set client $(sudo python3 -c "import json; print(next(iter(json.load(open(\"/var/lib/frp-auto-deploy/registry.json\"))[\"clients\"])))") label fleet-mutated' || true
  cat "$ROOT/tools/frp-restore" | ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'sudo tee /tmp/frp-restore >/dev/null && sudo chmod 755 /tmp/frp-restore'
  cat "$ROOT/tools/frp-backup" | ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'sudo tee /tmp/frp-backup >/dev/null && sudo chmod 755 /tmp/frp-backup'
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" 'sudo python3 /tmp/frp-restore /var/lib/frp-auto-deploy/backups/matrix-fleet-backup.tar.gz' \
    | tee "$OUT_ROOT/fleet-restore.txt"
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" \
    "sudo python3 -c \"import json; c=json.load(open('/etc/frp-auto-deploy/config.json')); print('public_hostname='+str(c.get('public_hostname') or ''))\"" \
    | tee "$OUT_ROOT/fleet-hostname-after-restore.txt"
  set -uo pipefail
fi

# Targeted IP fallback (hostname unset) on baseline if requested.
if [[ "$INCLUDE_DNS_IP_FALLBACK" == "1" && "$DNS_OK" -eq 1 ]]; then
  note "==== DNS IP fallback regression ===="
  set +e
  env \
    FRP_E2E_PROFILE=baseline-linux \
    FRP_E2E_SCENARIO=dns \
    FRP_E2E_PUBLIC_HOSTNAME="$PUBLIC_HOSTNAME" \
    FRP_E2E_RUN_ID="$RUN_ID-ip-fallback" \
    FRP_E2E_OUT_DIR="$OUT_ROOT/ip-fallback" \
    FRP_E2E_SKIP_SERVER_PURGE=1 \
    FRP_E2E_SKIP_SERVER_INSTALL=1 \
    FRP_E2E_SERVER_REBOOT_REPEAT=0 \
    bash "$ROOT/tests/run-real-e2e.sh"
  note "IP_FALLBACK_RC=$?"
  set -uo pipefail
fi

note "FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "MATRIX_TABLE:"
column -t -s $'\t' "$TABLE" 2>/dev/null || cat "$TABLE"
note "FAILED_PROFILES=$FAILED"
if [[ "$FAILED" -gt 0 ]]; then
  note "FINAL=FAIL"
  exit 1
fi
note "FINAL=PASS"
exit 0
