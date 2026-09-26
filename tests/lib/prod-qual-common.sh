#!/usr/bin/env bash
# Shared helpers for production-realistic qualification.
# shellcheck disable=SC2034
set -uo pipefail

PROD_QUAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROD_QUAL_SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)
PROD_QUAL_SSH_KEY="${FRP_E2E_SSH_KEY:-$HOME/.ssh/frp_e2e_ed25519}"
PROD_QUAL_SERVER="${FRP_E2E_SERVER_ALIAS:-}"
PROD_QUAL_SERVER_IP="${FRP_E2E_SERVER_IP:-}"
PROD_QUAL_PUBLIC_HOSTNAME="${FRP_E2E_PUBLIC_HOSTNAME:-}"

# Real E2E fleet aliases (discoverable; stale .112 must never appear).
PROD_QUAL_HOSTS=(
  "ubuntu:frp-e2e-client:aella"
  "ubuntu24:frp-e2e-linux114:aella"
  "rocky:frp-e2e-rocky8:root"
  "aws:frp-e2e-aws:ec2-user"
  "macos:frp-e2e-macos:leeruda"
  "windows:frp-e2e-windows:aella"
)

pq_note() {
  local msg="$*"
  printf '%s\n' "$msg"
  if [[ -n "${PROD_QUAL_SUMMARY:-}" ]]; then
    printf '%s\n' "$msg" >>"$PROD_QUAL_SUMMARY"
  fi
}

pq_ssh() {
  local alias="$1"
  shift
  ssh "${PROD_QUAL_SSH_OPTS[@]}" "$alias" "$@"
}

pq_gate() {
  local name="$1" status="$2"
  local gates="${PROD_QUAL_GATES:-}"
  # Replace prior value for the same key so retries cannot leave FAIL+PASS.
  if [[ -n "$gates" && -f "$gates" ]]; then
    grep -Ev "^${name}=" "$gates" >"${gates}.tmp" 2>/dev/null || true
    mv "${gates}.tmp" "$gates"
  fi
  printf '%s=%s\n' "$name" "$status" | tee -a "${gates:-/dev/null}"
  pq_note "GATE $name=$status"
  if [[ "$status" == "FAIL" || "$status" == "BLOCKED" ]]; then
    PROD_QUAL_FAILS=$((${PROD_QUAL_FAILS:-0} + 1))
  fi
}

pq_sample_server_resources() {
  local out="$1"
  pq_ssh "$PROD_QUAL_SERVER" 'sudo python3 -' <<'PY' >"$out"
import json, os, subprocess, time
def main_pid(unit):
    try:
        return int(subprocess.check_output(
            ["systemctl", "show", "-p", "MainPID", "--value", unit], text=True).strip() or 0)
    except Exception:
        return 0
units = ["drlink-server", "drlink-allocator", "drlink-access", "drlink-egress", "drlink-tcp-egress", "drlink-frontend"]
sample = {"ts": time.time(), "units": {}, "loadavg": os.getloadavg()}
for u in units:
    pid = main_pid(u)
    d = {"pid": pid}
    if pid > 0:
        try:
            st = open(f"/proc/{pid}/status", encoding="utf-8").read().splitlines()
            for line in st:
                if line.startswith(("VmRSS:", "Threads:", "FDSize:")):
                    k, v = line.split(":", 1)
                    d[k] = v.strip()
            d["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().split()
                # utime+stime jiffies
                d["cpu_jiffies"] = int(fields[13]) + int(fields[14])
        except Exception as e:
            d["err"] = str(e)
    sample["units"][u] = d
print(json.dumps(sample))
PY
}

pq_precheck_hosts() {
  local fails=0
  local stale
  stale="$(grep -c '221\.139\.249\.112' "$HOME/.ssh/config" 2>/dev/null || true)"
  if [[ "${stale:-0}" != "0" ]]; then
    pq_note "STALE_112_REFERENCE_IN_ACTIVE_CONFIG=$stale"
    fails=$((fails + 1))
  else
    pq_note "STALE_112_REFERENCE_IN_ACTIVE_CONFIG=0"
  fi
  if pq_ssh "$PROD_QUAL_SERVER" 'hostname' >/dev/null 2>&1; then
    pq_gate SERVER_SSH PASS
  else
    pq_gate SERVER_SSH FAIL
    fails=$((fails + 1))
  fi
  if pq_ssh "$PROD_QUAL_SERVER" 'sudo -n true' >/dev/null 2>&1; then
    pq_gate SERVER_SUDO PASS
  else
    pq_gate SERVER_SUDO FAIL
    fails=$((fails + 1))
  fi
  local entry alias label
  for entry in "UBUNTU:frp-e2e-client" "ROCKY:frp-e2e-rocky8" "AWS_LINUX:frp-e2e-aws" \
               "WINDOWS:frp-e2e-windows" "MACOS:frp-e2e-macos" "UBUNTU24:frp-e2e-linux114"; do
    label="${entry%%:*}"
    alias="${entry##*:}"
    if pq_ssh "$alias" 'echo ok' >/dev/null 2>&1; then
      pq_gate "${label}_SSH" PASS
    else
      pq_gate "${label}_SSH" FAIL
      fails=$((fails + 1))
    fi
  done
  return "$fails"
}

pq_head_sha() {
  git -C "$PROD_QUAL_ROOT" rev-parse HEAD
}

pq_macos_listener_owned() {
  # Ownership proof for :2222 reverse-SSH cleanup. Never kill unrelated listeners.
  # Accept if: recorded PID matches, or cmdline looks like our reverse tunnel, or
  # process user matches the expected macOS reverse-SSH owner on this controller.
  local pid="$1"
  local recorded="${PROD_QUAL_MACOS_SSH_PID:-}"
  local recorded_file="${PROD_QUAL_MACOS_SSH_PID_FILE:-/tmp/frp-macos-reverse-ssh.pid}"
  local expect_user="${PROD_QUAL_MACOS_SSH_USER:-}"
  [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] || return 1
  if [[ -z "$recorded" && -f "$recorded_file" ]]; then
    recorded="$(tr -d '[:space:]' <"$recorded_file" 2>/dev/null || true)"
  fi
  if [[ -n "$recorded" && "$recorded" == "$pid" ]]; then
    return 0
  fi
  local cmdline=""
  cmdline="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  if printf '%s' "$cmdline" | grep -Eqi \
    'frp-e2e-macos|macos.*2222|2222.*(ssh|autossh)|reverse.?ssh|sshd.*:2222|ssh.*-R.*2222'; then
    return 0
  fi
  if [[ -n "$expect_user" ]]; then
    local owner=""
    owner="$(ps -p "$pid" -o user= 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ -n "$owner" && "$owner" == "$expect_user" ]]; then
      # User match alone is insufficient without a tunnel-ish cmdline.
      if printf '%s' "$cmdline" | grep -Eqi 'ssh|autossh|sshd|reverse'; then
        return 0
      fi
    fi
  fi
  return 1
}

pq_wait_macos() {
  local max="${1:-60}"
  local t
  pq_note "Waiting for macOS reverse SSH (max ${max} tries)..."
  for t in $(seq 1 "$max"); do
    if ssh "${PROD_QUAL_SSH_OPTS[@]}" -o ConnectTimeout=6 frp-e2e-macos 'echo ok' >/dev/null 2>&1; then
      pq_note "MACOS_SSH_READY try=$t"
      return 0
    fi
    # Clear only owned stale listeners so Mac-side launchd can rebind.
    # Never kill an unrelated :2222 process (ownership via cmdline/user/recorded PID).
    local p
    for p in $(sudo -n lsof -t -iTCP:2222 -sTCP:LISTEN 2>/dev/null || true); do
      if pq_macos_listener_owned "$p"; then
        pq_note "MACOS_STALE_LISTENER_KILL pid=$p (owned)"
        sudo -n kill "$p" 2>/dev/null || true
      else
        pq_note "MACOS_STALE_LISTENER_SKIP pid=$p (unrelated; not owned)"
      fi
    done
    sleep 10
  done
  pq_note "MACOS_SSH_NOT_READY after ${max} tries"
  return 1
}

pq_matrix_platform_gate() {
  # Args: tsv_path
  # INSTALL / ENROLL / SERVICE are required for a platform PASS.
  # REBOOT / UNINSTALL / DNS may be intentional SKIP on some profiles.
  # Unexpected values (empty, UNKNOWN, etc.) are FAIL — never silent PASS.
  local tsv="$1"
  [[ -f "$tsv" ]] || return 1
  local plat install enroll service reboot uninstall dns
  local any_fail=0
  local allowed_skip='^(PASS|SKIP|HEADROOM_LIMIT)$'
  while IFS=$'\t' read -r plat install enroll service reboot uninstall dns; do
    [[ "$plat" == "PLATFORM" || -z "$plat" ]] && continue
    local status=PASS
    # Normalize empties to UNKNOWN so they cannot slip through as PASS.
    [[ -n "$install" ]] || install=UNKNOWN
    [[ -n "$enroll" ]] || enroll=UNKNOWN
    [[ -n "$service" ]] || service=UNKNOWN
    [[ -n "$reboot" ]] || reboot=UNKNOWN
    [[ -n "$uninstall" ]] || uninstall=UNKNOWN
    [[ -n "$dns" ]] || dns=UNKNOWN

    if [[ "$install" == "FAIL" || "$enroll" == "FAIL" || "$service" == "FAIL" ]]; then
      status=FAIL
      any_fail=1
    elif [[ "$install" == "BLOCKED" || "$enroll" == "BLOCKED" || "$service" == "BLOCKED" ]]; then
      status=BLOCKED
      any_fail=1
    elif [[ "$install" != "PASS" || "$enroll" != "PASS" || "$service" != "PASS" ]]; then
      # Required columns must be PASS. SKIP/UNKNOWN/empty on SERVICE is not OK.
      status=FAIL
      any_fail=1
    else
      # Optional columns: only PASS, intentional SKIP, or HEADROOM_LIMIT allowed.
      for col in "$reboot" "$uninstall" "$dns"; do
        if [[ "$col" == "FAIL" ]]; then
          status=FAIL
          any_fail=1
          break
        elif [[ "$col" == "BLOCKED" ]]; then
          status=BLOCKED
          any_fail=1
          break
        elif [[ ! "$col" =~ $allowed_skip ]]; then
          status=FAIL
          any_fail=1
          break
        fi
      done
    fi
    case "$plat" in
      ubuntu-24.04|baseline-linux) pq_gate UBUNTU_REAL_E2E "$status" ;;
      rocky-linux-8.10) pq_gate ROCKY_REAL_E2E "$status" ;;
      amazon-linux-2023) pq_gate AWS_LINUX_REAL_E2E "$status" ;;
      macos-arm64) pq_gate MACOS_REAL_E2E "$status" ;;
      windows-10) pq_gate WINDOWS_REAL_E2E "$status" ;;
    esac
  done <"$tsv"
  return "$any_fail"
}
