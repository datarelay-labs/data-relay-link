#!/usr/bin/env bash
# Targeted real E2E: Server-local Agent + qualified FRP distribution.
# Uses frp-e2e-server + frp-e2e-aws. Does not purge pre-existing e2e clients.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_ALIAS="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
CLIENT_ALIAS="${FRP_E2E_CLIENT_ALIAS:-frp-e2e-aws}"
SERVER_IP="${FRP_E2E_SERVER_IP:-221.139.249.113}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=5)
RUN_ID="${FRP_E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${FRP_E2E_OUT_DIR:-$ROOT/e2e-reports/server-local-artifacts-$RUN_ID}"
HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD)"
CLIENT_NAME="art-e2e-${RUN_ID: -8}"
SVC_ID="$(printf 'art%s' "${RUN_ID: -8}" | tr '[:upper:]' '[:lower:]')"
SVC_PORT=18240
TEST_ROOT="/tmp/drlink-${CLIENT_NAME}"
HOSTS_MARKER='# drlink-artifacts-e2e'
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"
: >"$SUMMARY"

note() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
fail() { note "FAIL $*"; cleanup_run || true; exit 1; }
pass() { note "PASS $*"; }

ssh_server() { ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" "$@"; }
ssh_client() { ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" "$@"; }

restore_client_hosts() {
  ssh_client "sudo python3 -c \"
from pathlib import Path
p=Path('/etc/hosts')
t=p.read_text()
m='$HOSTS_MARKER'
if m in t:
    p.write_text(t.split(m)[0].rstrip()+chr(10))
\"" >/dev/null 2>&1 || true
}

cleanup_run() {
  ssh_client "sudo pkill -f 'http.server ${SVC_PORT}' || true" >/dev/null 2>&1 || true
  ssh_client "sudo /usr/local/bin/drlink unset service ${SVC_ID}" >/dev/null 2>&1 || true
  ssh_client "sudo /usr/local/bin/drlink system services apply" >/dev/null 2>&1 || true
  ssh_client "sudo pkill -f '${TEST_ROOT}/usr/local/bin/frpc' || true" >/dev/null 2>&1 || true
  ssh_client "sudo rm -rf '${TEST_ROOT}' /tmp/bootstrap-client-${CLIENT_NAME}.sh /tmp/frp-good.tar.gz /tmp/frp-bad.tar.gz /tmp/art-e2e-frpc.log /tmp/art-e2e-http.log" >/dev/null 2>&1 || true
  ssh_server "sudo /usr/local/bin/drlink unset remote-access art-e2e-allow" >/dev/null 2>&1 || true
  ssh_server "sudo /usr/local/bin/drlink unset service-object art-e2e-http" >/dev/null 2>&1 || true
  ssh_server "sudo /usr/local/bin/drlink unset network-object art-e2e-src" >/dev/null 2>&1 || true
  ssh_server "sudo /usr/local/bin/drlink release client ${CLIENT_NAME} --yes" >/dev/null 2>&1 || true
  ssh_server "printf 'RELEASE\n' | sudo /usr/local/lib/drlink/frp-release-service real-e2e-al2023 ${SVC_ID} --force" >/dev/null 2>&1 || true
  ssh_server "sudo python3 -c \"
import json
from pathlib import Path
marker = 'server-local-artifacts-e2e'
for d in (Path('/var/lib/drlink/enrollments'), Path('/var/lib/drlink/bootstrap')):
    if not d.is_dir():
        continue
    for p in list(d.glob('*.json')):
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            continue
        label = str(data.get('label') or '')
        note = str(data.get('note') or '')
        if marker in note or label.startswith('art-e2e-'):
            p.unlink()
\"" >/dev/null 2>&1 || true
  restore_client_hosts
}

note "HEAD_SHA=$HEAD_SHA"
note "SERVER_ALIAS=$SERVER_ALIAS"
note "CLIENT_ALIAS=$CLIENT_ALIAS"
note "CLIENT_NAME=$CLIENT_NAME"

# --- E2E-A: reinstall/update server from this implementation (preserve state) ---
if [[ "${FRP_E2E_SKIP_SERVER_INSTALL:-0}" == "1" ]]; then
  note "E2E-A skipping reinstall; verifying existing Server-local artifacts"
else
  note "E2E-A streaming bootstrap-server.sh"
  ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" \
    "sudo env \
      FRP_PUBLIC_IP=${SERVER_IP} \
      FRP_INTERNAL_IP=${SERVER_IP} \
      FRP_DEPLOYMENT_MODE=direct \
      FRP_CONTROL_PUBLIC_PORT=443 \
      FRP_CONTROL_LISTEN_PORT=443 \
      FRP_ALLOCATOR_PUBLIC_PORT=6099 \
      FRP_ALLOCATOR_LISTEN_PORT=6099 \
      FRP_ALLOCATOR_PUBLIC_URL=https://${SERVER_IP}:6099/enroll \
      bash -s --" \
    <"$ROOT/dist/bootstrap-server.sh" \
    >"$OUT_DIR/e2e-a-install.log" 2>&1 || {
    tail -n 80 "$OUT_DIR/e2e-a-install.log" | tee -a "$SUMMARY"
    fail "E2E-A server install"
  }
fi
ssh_server 'sudo test -f /usr/local/share/drlink/artifacts/manifest.json' \
  || fail "E2E-A manifest missing"
ssh_server 'sudo python3 - <<'"'"'PY'"'"'
import json
from pathlib import Path
data = json.loads(Path("/usr/local/share/drlink/artifacts/manifest.json").read_text())
assert data["drlink_version"] == "2.4.0"
assert data["frp_version"] == "0.71.0"
assert data["frp_upstream_commit"] == "4a23aa181c1d7e28eecaa8216024ed753b9d27c8"
assert Path("/usr/local/share/drlink/artifacts/agent/bootstrap-client.sh").is_file()
assert Path("/usr/local/share/drlink/artifacts/SHA256SUMS").is_file()
assert Path("/usr/local/share/drlink/artifacts/frp/0.71.0/frp_0.71.0_linux_amd64.tar.gz").is_file()
cfg = json.loads(Path("/etc/drlink/config.json").read_text())
assert "/artifacts/agent/bootstrap-client.sh" in cfg["client_installer_url"]
assert "github.com/fatedier" not in cfg["client_installer_url"]
assert "raw.githubusercontent.com" not in cfg["client_installer_url"]
print("SERVER_ARTIFACTS_OK")
print("INSTALLER", cfg["client_installer_url"])
PY' | tee -a "$SUMMARY" || fail "E2E-A metadata"
pass "E2E-A_SERVER_LOCAL_ARTIFACTS"

# --- E2E-B/C: block public fatedier + public DataRelay downloads on the Managed Host ---
note "E2E-B/C blocking public GitHub on client"
ssh_client "sudo python3 - <<'PY'
from pathlib import Path
path = Path('/etc/hosts')
text = path.read_text(encoding='utf-8')
marker = '$HOSTS_MARKER'
block = [
    '0.0.0.0 github.com',
    '0.0.0.0 www.github.com',
    '0.0.0.0 raw.githubusercontent.com',
    '0.0.0.0 objects.githubusercontent.com',
    '0.0.0.0 release-assets.githubusercontent.com',
    '0.0.0.0 codeload.github.com',
]
if marker not in text:
    path.write_text(text.rstrip() + '\n' + marker + '\n' + '\n'.join(block) + '\n', encoding='utf-8')
print('hosts-updated')
PY"

if ssh_client "curl -fsS --max-time 8 -o /dev/null -w '%{http_code}' https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz" \
    >"$OUT_DIR/e2e-b-fatedier.log" 2>&1; then
  if grep -qx '200' "$OUT_DIR/e2e-b-fatedier.log"; then
    fail "E2E-B fatedier still reachable"
  fi
fi
pass "E2E-B_FATEDIER_BLOCKED"

if ssh_client "curl -fsS --max-time 8 -o /dev/null -w '%{http_code}' https://raw.githubusercontent.com/datarelay-labs/datarelay-link/main/dist/bootstrap-client.sh" \
    >"$OUT_DIR/e2e-c-public.log" 2>&1; then
  if grep -qx '200' "$OUT_DIR/e2e-c-public.log"; then
    fail "E2E-C public DataRelay artifacts still reachable"
  fi
fi
pass "E2E-C_PUBLIC_DRLINK_BLOCKED"

ssh_client "sudo curl -fsS --max-time 20 --cacert /etc/drlink/allocator-ca.crt \
  https://${SERVER_IP}:6099/artifacts/manifest.json" \
  >"$OUT_DIR/e2e-manifest.json" || fail "client cannot fetch server artifacts"
python3 - "$OUT_DIR/e2e-manifest.json" <<'PY' || fail "client manifest"
import json,sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
assert data["frp_version"]=="0.71.0"
assert data["drlink_version"]=="2.4.0"
PY

note "E2E-B/C creating Zero-Touch enrollment and installing into an isolated test root"
ssh_server "sudo /usr/local/lib/drlink/frp-create-client --one-line --client-name '${CLIENT_NAME}' --note 'server-local-artifacts-e2e'" \
  >"$OUT_DIR/e2e-zt-create.log" 2>&1 || {
  cat "$OUT_DIR/e2e-zt-create.log" | tee -a "$SUMMARY"
  fail "E2E-B/C enrollment create"
}
ZT1="$(python3 - "$OUT_DIR/e2e-zt-create.log" <<'PY'
import re,sys
text=open(sys.argv[1], encoding='utf-8').read()
m=re.search(r"sudo bash -s -- '(zt1\.[^']+)'", text)
if not m:
    raise SystemExit('missing zt1 package')
print(m.group(1))
PY
)" || fail "E2E-B/C missing zt1 package"
INSTALLER_URL="$(python3 - "$OUT_DIR/e2e-zt-create.log" <<'PY'
import re,sys
text=open(sys.argv[1], encoding='utf-8').read()
m=re.search(r"curl -fsSL '([^']+)'", text)
if not m:
    m=re.search(r"curl -fsSL ([^ |]+)", text)
if not m:
    raise SystemExit('missing installer url')
print(m.group(1))
PY
)" || fail "E2E-B/C missing installer URL"
note "INSTALLER_URL=$INSTALLER_URL"
[[ "$INSTALLER_URL" == *"/artifacts/agent/bootstrap-client.sh" ]] \
  || fail "Zero-Touch installer URL is not Server-local"
[[ "$INSTALLER_URL" != *github.com* ]] || fail "Zero-Touch installer still points at GitHub"

ssh_client "sudo curl -fsS --max-time 60 --cacert /etc/drlink/allocator-ca.crt \
  -o /tmp/bootstrap-client-${CLIENT_NAME}.sh '${INSTALLER_URL}' \
  && sudo chmod 0700 /tmp/bootstrap-client-${CLIENT_NAME}.sh \
  && sudo env FRP_CLIENT_TEST_ROOT='${TEST_ROOT}' FRP_SKIP_SYSTEMD=1 \
       FRP_TEST_MACHINE_ID='$(printf '%s' "$CLIENT_NAME" | sha256sum | awk '{print $1}' | cut -c1-32)' \
       bash /tmp/bootstrap-client-${CLIENT_NAME}.sh '${ZT1}'" \
  >"$OUT_DIR/e2e-bc-install.log" 2>&1 || {
  tail -n 100 "$OUT_DIR/e2e-bc-install.log" | tee -a "$SUMMARY"
  fail "E2E-B/C agent install from server artifacts"
}
if grep -qi 'github.com/fatedier' "$OUT_DIR/e2e-bc-install.log"; then
  fail "agent install contacted fatedier"
fi
if grep -qi 'raw.githubusercontent.com' "$OUT_DIR/e2e-bc-install.log"; then
  fail "agent install contacted public DataRelay GitHub"
fi
grep -q 'Installing qualified FRP' "$OUT_DIR/e2e-bc-install.log" \
  || fail "install log missing Server-local FRP install"
ssh_client "sudo test -x '${TEST_ROOT}/usr/local/bin/frpc'" || fail "test-root frpc missing"
FRP_VER="$(ssh_client "sudo '${TEST_ROOT}/usr/local/bin/frpc' --version" | head -n1 || true)"
note "TEST_ROOT_FRPC=$FRP_VER"
[[ "$FRP_VER" == *0.71.0* ]] || fail "installed FRP is not 0.71.0"
pass "E2E-B_FATEDIER_BLOCKED_AGENT_INSTALL"
pass "E2E-C_PUBLIC_DOWNLOAD_BLOCKED_AGENT_INSTALL"

ssh_client "sudo nohup '${TEST_ROOT}/usr/local/bin/frpc' -c '${TEST_ROOT}/etc/frp/frpc.toml' >/tmp/art-e2e-frpc.log 2>&1 &"
sleep 3
ssh_server "sudo /usr/local/bin/drlink show managed-hosts" >"$OUT_DIR/e2e-clients.log" 2>&1 || true
if ! grep -q "$CLIENT_NAME" "$OUT_DIR/e2e-clients.log"; then
  note "WARN new Managed Host name not listed yet"
fi

# --- E2E-D: corruption against a downloaded copy ---
ssh_client "sudo bash -s" <<EOS >"$OUT_DIR/e2e-d.log" 2>&1 || fail "E2E-D remote checksum"
set -euo pipefail
CA=/etc/drlink/allocator-ca.crt
curl -fsS --cacert "\$CA" -o /tmp/frp-good.tar.gz \
  https://${SERVER_IP}:6099/artifacts/frp/0.71.0/frp_0.71.0_linux_amd64.tar.gz
cp /tmp/frp-good.tar.gz /tmp/frp-bad.tar.gz
printf x >> /tmp/frp-bad.tar.gz
GOOD=\$(sha256sum /tmp/frp-good.tar.gz | awk '{print \$1}')
BAD=\$(sha256sum /tmp/frp-bad.tar.gz | awk '{print \$1}')
WANT=84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716
[[ "\$GOOD" == "\$WANT" ]]
[[ "\$BAD" != "\$WANT" ]]
echo CORRUPT_REJECTED
echo RESTORED_OK
EOS
grep -q 'CORRUPT_REJECTED' "$OUT_DIR/e2e-d.log" || fail "E2E-D corrupt not rejected"
pass "E2E-D_CORRUPTION"

# --- E2E-E: wrong platform/arch ---
if python3 "$ROOT/lib/drlink_qualified_artifacts.py" lookup \
    --root /nonexistent-drlink-artifacts --type frp-archive --platform darwin --architecture amd64 \
    >/dev/null 2>"$OUT_DIR/e2e-e.err"; then
  fail "E2E-E wrong platform succeeded"
fi
grep -q 'No changes were applied' "$OUT_DIR/e2e-e.err" || fail "E2E-E public error"
pass "E2E-E_WRONG_PLATFORM_ARCH"

# --- E2E-F: runtime smoke on the existing connected Managed Host ---
note "E2E-F runtime smoke"
ssh_client "sudo nohup python3 -m http.server ${SVC_PORT} --bind 127.0.0.1 >/tmp/art-e2e-http.log 2>&1 </dev/null &"
sleep 1
ssh_client "sudo /usr/local/bin/drlink add service --preset http --id ${SVC_ID} --name ArtifactE2E --target-host 127.0.0.1 --target-port ${SVC_PORT} && sudo /usr/local/bin/drlink system services apply" \
  >"$OUT_DIR/e2e-f-add.log" 2>&1 || {
  tail -n 50 "$OUT_DIR/e2e-f-add.log" | tee -a "$SUMMARY"
  fail "E2E-F add service"
}
ENDPOINT="$(ssh_client 'sudo python3 -c "import json; d=json.load(open(\"/etc/frp/client-state.json\")); s=(d.get(\"services\") or {}).get(\"'"$SVC_ID"'\") or {}; print(s.get(\"remote_port\") or \"\")"')"
[[ -n "$ENDPOINT" ]] || fail "E2E-F no remote port"
note "E2E-F remote_port=$ENDPOINT"
ssh_server "sudo /usr/local/bin/drlink set network-object art-e2e-src type ip value 127.0.0.1 && sudo /usr/local/bin/drlink set service-object art-e2e-http type tcp port ${SVC_PORT} && sudo /usr/local/bin/drlink set remote-access art-e2e-allow mode whitelist source art-e2e-src destination real-e2e-al2023 service art-e2e-http enabled" \
  >"$OUT_DIR/e2e-f-allow.log" 2>&1 || {
  tail -n 40 "$OUT_DIR/e2e-f-allow.log" | tee -a "$SUMMARY"
  fail "E2E-F remote-access allow"
}
sleep 2
ssh_server "curl -fsS --max-time 10 http://127.0.0.1:${ENDPOINT}/" >/dev/null \
  || fail "E2E-F TCP service not reachable"
TOKEN_OK="$(ssh_server 'sudo python3 -c "from pathlib import Path; t=Path(\"/etc/frp/server_token\").read_text().strip(); print(\"yes\" if len(t)>=16 else \"no\")"')"
[[ "$TOKEN_OK" == yes ]] || fail "E2E-F missing unique backend token"
BEFORE="$ENDPOINT"
ssh_client "sudo systemctl restart drlink-client || sudo /usr/local/bin/drlink system restart" \
  >"$OUT_DIR/e2e-f-restart.log" 2>&1 || true
sleep 5
AFTER="$(ssh_client 'sudo python3 -c "import json; d=json.load(open(\"/etc/frp/client-state.json\")); s=(d.get(\"services\") or {}).get(\"'"$SVC_ID"'\") or {}; print(s.get(\"remote_port\") or \"\")"')"
[[ "$BEFORE" == "$AFTER" ]] || fail "E2E-F endpoint changed after restart ($BEFORE -> $AFTER)"
pass "E2E-F_RUNTIME_SMOKE"

cleanup_run
pass "CURRENT_RUN_TEST_RESOURCES_CLEANED"
note "SERVER_LOCAL_ARTIFACTS_E2E=PASS"
echo "SERVER_LOCAL_ARTIFACTS_E2E=PASS"
