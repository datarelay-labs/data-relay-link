#!/usr/bin/env bash
# Targeted Real E2E for Access Control Pack.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
SERVER="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
CLIENT_HOST="${FRP_ACCESS_E2E_CLIENT:-frp-e2e-aws}"
SOURCE_A_HOST="${FRP_ACCESS_E2E_SOURCE_A:-frp-e2e-client}"
SOURCE_B_HOST="${FRP_ACCESS_E2E_SOURCE_B:-frp-e2e-rocky8}"
TTL="${FRP_ACCESS_E2E_TTL:-2m}"
OUT_DIR="${FRP_ACCESS_E2E_OUT:-$ROOT/e2e-reports/access-control-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"
exec > >(tee -a "$OUT_DIR/run.log") 2>&1

pass(){ echo "PASS $1"; }
fail(){ echo "FAIL $1" >&2; echo "TARGETED_REAL_E2E=FAIL" >"$OUT_DIR/result.env"; exit 1; }
blocker(){ echo "ENVIRONMENT_BLOCKER $1" >&2; echo "TARGETED_REAL_E2E=ENVIRONMENT_BLOCKER" >"$OUT_DIR/result.env"; exit 2; }
sshx(){ local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$h" "$@"; }

echo "=== Access Control targeted Real E2E ==="
sshx "$SERVER" 'echo ok' >/dev/null || blocker "server unreachable"
sshx "$CLIENT_HOST" 'echo ok' >/dev/null || blocker "client unreachable"
sshx "$SOURCE_A_HOST" 'echo ok' >/dev/null || blocker "source A unreachable"
sshx "$SOURCE_B_HOST" 'echo ok' >/dev/null || blocker "source B unreachable"

SOURCE_A_IP="$(sshx "$SOURCE_A_HOST" 'curl -4 -fsS --max-time 8 https://ifconfig.me')"
SOURCE_B_IP="$(sshx "$SOURCE_B_HOST" 'curl -4 -fsS --max-time 8 https://ifconfig.me')"
SOURCE_A_IP="${SOURCE_A_IP//[$'\r\n']/}"
SOURCE_B_IP="${SOURCE_B_IP//[$'\r\n']/}"
echo "SOURCE_A_IP=$SOURCE_A_IP SOURCE_B_IP=$SOURCE_B_IP"
[[ "$SOURCE_A_IP" != "$SOURCE_B_IP" ]] || blocker "A/B share NAT egress"

SERVER_IP="$(sshx "$SERVER" 'curl -4 -fsS --max-time 8 https://ifconfig.me')"
SERVER_IP="${SERVER_IP//[$'\r\n']/}"

# Resolve target client + ssh service from inventory (prefer configured client).
# Harness must not hard-require AL2023; use FRP_ACCESS_E2E_CLIENT_ID / label /
# hostname hints when set, otherwise any enrolled client with an SSH service.
read -r CLIENT_ID SERVICE_ID PUBLIC_PORT < <(sshx "$SERVER" "sudo CLIENT_HINT='${FRP_ACCESS_E2E_CLIENT_ID:-}' CLIENT_HOST_HINT='${FRP_ACCESS_E2E_CLIENT_HOST_HINT:-}' CLIENT_LABEL_HINT='${FRP_ACCESS_E2E_CLIENT_LABEL_HINT:-}' python3 - <<'PY'
import json, os
from pathlib import Path
reg=json.loads(Path('/var/lib/drlink/registry.json').read_text())
hint_id=(os.environ.get('CLIENT_HINT') or '').strip().lower()
hint_host=(os.environ.get('CLIENT_HOST_HINT') or '').strip().lower()
hint_label=(os.environ.get('CLIENT_LABEL_HINT') or '').strip().lower()

def score(mid, c):
  label=str((c or {}).get('label') or '').lower()
  host=str((c or {}).get('hostname') or '').lower()
  s=0
  if hint_id and (mid.lower()==hint_id or mid.lower().startswith(hint_id)):
    s += 100
  if hint_label and hint_label in label:
    s += 50
  if hint_host and (hint_host in host or host.startswith(hint_host)):
    s += 40
  # Soft preference for common lab labels when no explicit hint is set.
  if not hint_id and not hint_label and not hint_host:
    for token in ('al2023', 'al2', 'aws', 'rocky', 'e2e'):
      if token in label or token in host:
        s += 5
        break
  return s

def pick_service(services):
  if not isinstance(services, dict):
    return None
  if 'e2e-acl' in services and isinstance(services.get('e2e-acl'), dict):
    svc=services['e2e-acl']
    return 'e2e-acl', svc.get('remote_port')
  for sid,svc in services.items():
    if isinstance(svc,dict) and svc.get('enabled',True) and int(svc.get('local_port') or 0)==22:
      return sid, svc.get('remote_port')
  return None

ranked=[]
for mid,c in (reg.get('clients') or {}).items():
  ranked.append((score(mid,c), mid, c))
ranked.sort(key=lambda t: (-t[0], t[1]))
for _, mid, c in ranked:
  picked=pick_service((c or {}).get('services') or {})
  if picked:
    sid, port = picked
    print(mid, sid, port); raise SystemExit
print('NOTFOUND','','')
PY")
[[ "$CLIENT_ID" != "NOTFOUND" && -n "$PUBLIC_PORT" ]] || blocker "no enrolled client ssh service found in inventory"
echo "CLIENT_ID=$CLIENT_ID SERVICE_ID=$SERVICE_ID PUBLIC_PORT=$PUBLIC_PORT SERVER_IP=$SERVER_IP"

probe(){
  local host="$1"
  sshx "$host" "python3 - <<'PY'
import socket,sys
s=socket.socket(); s.settimeout(6)
try:
  s.connect(('$SERVER_IP', int('$PUBLIC_PORT')))
except Exception as e:
  print('CONNECT_FAIL', type(e).__name__); sys.exit(2)
try:
  data=s.recv(64)
except Exception as e:
  print('DENY_CLOSED', type(e).__name__); sys.exit(1)
finally:
  s.close()
if data and data.startswith(b'SSH-'):
  print('ALLOW_BANNER'); sys.exit(0)
print('NO_BANNER', repr(data)); sys.exit(1)
PY"
}

# Sync feature files
echo "=== sync feature onto server ==="
TMP_SYNC=/tmp/frp-access-sync-$$
sshx "$SERVER" "sudo rm -rf $TMP_SYNC && sudo mkdir -p $TMP_SYNC && sudo chmod 777 $TMP_SYNC"
for f in \
  lib/frp_access_control.py \
  server/frp-access-plugin.py \
  server/drlink-access.service \
  tools/frp-access \
  tools/frpctl \
  tools/drlink \
  lib/frp_ctl_grammar.py \
  lib/frp_cli_catalog.py \
  tools/frp-release-service \
  tools/frp-client-info
 do
  scp -o BatchMode=yes -o ConnectTimeout=15 "$ROOT/$f" "$SERVER:$TMP_SYNC/$(basename "$f")"
done
sshx "$SERVER" "sudo install -m 0644 $TMP_SYNC/frp_access_control.py /usr/local/lib/drlink/frp_access_control.py
sudo install -m 0700 $TMP_SYNC/frp-access-plugin.py /usr/local/lib/drlink/frp-access-plugin.py
sudo install -m 0644 $TMP_SYNC/frp_ctl_grammar.py /usr/local/lib/drlink/frp_ctl_grammar.py
sudo install -m 0644 $TMP_SYNC/frp_cli_catalog.py /usr/local/lib/drlink/frp_cli_catalog.py
sudo install -m 0755 $TMP_SYNC/frp-access /usr/local/sbin/frp-access
sudo install -m 0755 $TMP_SYNC/frpctl /usr/local/lib/drlink/frpctl
sudo install -m 0755 $TMP_SYNC/drlink /usr/local/bin/drlink
sudo rm -f /usr/local/sbin/frpctl /usr/local/bin/frpctl
sudo install -m 0755 $TMP_SYNC/frp-release-service /usr/local/sbin/frp-release-service
sudo install -m 0755 $TMP_SYNC/frp-client-info /usr/local/sbin/frp-client-info
sudo install -m 0644 $TMP_SYNC/drlink-access.service /etc/systemd/system/drlink-access.service
sudo python3 - <<'PY'
import json, importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('acl','/usr/local/lib/drlink/frp_access_control.py')
acl=importlib.util.module_from_spec(spec); spec.loader.exec_module(acl)
path=Path('/var/lib/drlink/access-control.json')
if not path.exists():
  acl.save_access_state(acl.empty_access_state(), path=path)
cfgp=Path('/etc/drlink/config.json')
cfg=json.loads(cfgp.read_text())
changed=False
for k,v in {
  'access_control_file':'/var/lib/drlink/access-control.json',
  'access_conn_log_file':'/var/log/drlink/access-conn.jsonl',
  'access_plugin_addr':'127.0.0.1:6101',
  'access_plugin_path':'/access-auth',
}.items():
  if cfg.get(k)!=v:
    cfg[k]=v; changed=True
if changed:
  cfgp.write_text(json.dumps(cfg, indent=2, sort_keys=True)+'\n')
toml=Path('/etc/frp/frps.toml')
text=toml.read_text()
if 'NewUserConn' not in text:
  toml.write_text(text.rstrip()+'''

[[httpPlugins]]
name = \"frp-access\"
addr = \"127.0.0.1:6101\"
path = \"/access-auth\"
ops = [\"NewUserConn\"]
''')
print('wired')
PY
sudo systemctl daemon-reload
sudo systemctl enable --now drlink-access
sudo systemctl restart drlink-access
sleep 1
curl -fsS http://127.0.0.1:6101/healthz
sudo systemctl restart drlink-server
sleep 2
systemctl is-active drlink-access
systemctl is-active drlink-server"

# PUBLIC baseline
echo "=== PUBLIC ==="
sshx "$SERVER" "sudo frp-access public ${CLIENT_ID} ${SERVICE_ID}"
sleep 1
probe "$SOURCE_A_HOST" || fail "PUBLIC A"
pass PUBLIC_A
probe "$SOURCE_B_HOST" || fail "PUBLIC B"
pass PUBLIC_B

# ALLOWLIST A only
echo "=== ALLOWLIST ==="
sshx "$SERVER" "sudo frp-access delete E2E-Allow" >/dev/null 2>&1 || true
sshx "$SERVER" "sudo frp-access create 'E2E-Allow' --description 'Access Control Pack Real E2E'"
sshx "$SERVER" "sudo frp-access add-source 'E2E-Allow' --name SourceA --source ${SOURCE_A_IP}/32 --yes"
sshx "$SERVER" "sudo frp-access assign ${CLIENT_ID} ${SERVICE_ID} 'E2E-Allow'"
sleep 1
probe "$SOURCE_A_HOST" || fail "ALLOW A"
pass ALLOW_A
if probe "$SOURCE_B_HOST"; then fail "DENY B expected"; else pass DENY_B; fi

sshx "$SERVER" "sudo frp-access test ${CLIENT_ID} ${SERVICE_ID} ${SOURCE_A_IP}" | tee "$OUT_DIR/test-a.txt"
grep -q 'Decision      : ALLOW' "$OUT_DIR/test-a.txt" || fail "test A"
sshx "$SERVER" "sudo frp-access test ${CLIENT_ID} ${SERVICE_ID} ${SOURCE_B_IP}" | tee "$OUT_DIR/test-b.txt"
grep -q 'Decision      : DENY' "$OUT_DIR/test-b.txt" || fail "test B"
pass ACCESS_TEST

# list update
sshx "$SERVER" "sudo frp-access add-source 'E2E-Allow' --name SourceB --source ${SOURCE_B_IP}/32 --yes"
sleep 1
probe "$SOURCE_B_HOST" || fail "B after add"
sshx "$SERVER" "sudo frp-access remove-source 'E2E-Allow' --source ${SOURCE_B_IP}/32 --yes"
sleep 1
if probe "$SOURCE_B_HOST"; then fail "B after remove"; else pass LIST_UPDATE; fi

# Runtime mapping-failure fail-closed (registry hostname drift vs live proxy_name)
echo "=== UNMAPPED_PROXY fail-closed ==="
ORIG_HOST="$(sshx "$SERVER" "sudo python3 - <<'PY'
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/drlink/registry.json').read_text())
print(reg['clients']['$CLIENT_ID'].get('hostname') or '')
PY")"
sshx "$SERVER" "sudo python3 - <<'PY'
import json
from pathlib import Path
path=Path('/var/lib/drlink/registry.json')
reg=json.loads(path.read_text())
client=reg['clients']['$CLIENT_ID']
client['hostname']='drift-unmapped-e2e'
path.write_text(json.dumps(reg, indent=2, sort_keys=True)+'\n')
print('drifted')
PY"
sleep 2
# Plugin reloads on registry mtime; allowed source must still DENY when unmapped.
if probe "$SOURCE_A_HOST"; then
  # Restore before failing so later steps are not poisoned.
  sshx "$SERVER" "sudo python3 - <<'PY'
import json
from pathlib import Path
path=Path('/var/lib/drlink/registry.json')
reg=json.loads(path.read_text())
reg['clients']['$CLIENT_ID']['hostname']='$ORIG_HOST'
path.write_text(json.dumps(reg, indent=2, sort_keys=True)+'\n')
PY"
  fail "UNMAPPED_PROXY should DENY"
fi
pass UNMAPPED_PROXY_DENY
sshx "$SERVER" "sudo python3 - <<'PY'
import json
from pathlib import Path
path=Path('/var/lib/drlink/registry.json')
reg=json.loads(path.read_text())
reg['clients']['$CLIENT_ID']['hostname']='$ORIG_HOST'
path.write_text(json.dumps(reg, indent=2, sort_keys=True)+'\n')
print('restored')
PY"
sleep 2
probe "$SOURCE_A_HOST" || fail "A after mapping restore"
pass UNMAPPED_PROXY_RESTORE

# Confirm authorize reason on server for an unmapped name while ALLOWLIST is assigned
sshx "$SERVER" "sudo python3 - <<'PY'
import importlib.util, json
from pathlib import Path
spec=importlib.util.spec_from_file_location('acl','/usr/local/lib/drlink/frp_access_control.py')
acl=importlib.util.module_from_spec(spec); spec.loader.exec_module(acl)
cfg=json.loads(Path('/etc/drlink/config.json').read_text())
state=acl.load_access_state(cfg=cfg)
reg=json.loads(Path('/var/lib/drlink/registry.json').read_text())
v=acl.authorize(state, reg, proxy_name='totally-unmapped-proxy', source_ip='${SOURCE_A_IP}')
assert v['decision']=='DENY', v
assert v['reason']=='UNMAPPED_PROXY', v
print('authorize_unmapped_ok')
PY" || fail "authorize unmapped reason"
pass UNMAPPED_PROXY_REASON

# TTL
echo "=== TTL $TTL ==="
sshx "$SERVER" "sudo frp-access add-source 'E2E-Allow' --name SourceBTemp --source ${SOURCE_B_IP}/32 --ttl ${TTL} --yes"
sleep 1
probe "$SOURCE_B_HOST" || fail "TTL pre"
pass TTL_PRE
SLEEP_SECS=140
[[ "$TTL" =~ ^([0-9]+)m$ ]] && SLEEP_SECS=$((BASH_REMATCH[1]*60+25))
echo "sleep ${SLEEP_SECS}s"
sleep "$SLEEP_SECS"
if probe "$SOURCE_B_HOST"; then fail "TTL post"; else pass TTL_POST; fi
sshx "$SERVER" "sudo frp-access log ${CLIENT_ID} ${SERVICE_ID} --limit 30" | tee "$OUT_DIR/access-log.txt"

# Expired-only cleanup: prune expired rows; stay ALLOWLIST; stay DENY.
echo "=== expired cleanup ==="
sshx "$SERVER" "sudo python3 - <<'PY'
import importlib.util, json
from datetime import datetime, timedelta, timezone
from pathlib import Path
spec=importlib.util.spec_from_file_location('acl','/usr/local/lib/drlink/frp_access_control.py')
acl=importlib.util.module_from_spec(spec); spec.loader.exec_module(acl)
path=Path('/var/lib/drlink/access-control.json')
state=acl.load_access_state(path=path)
lid,_=acl.resolve_access_list(state,'E2E-Allow')
past=(datetime.now(timezone.utc)-timedelta(hours=2)).replace(microsecond=0).isoformat().replace('+00:00','Z')
state['access_lists'][lid]['entries']=[]
acl.add_source_entry(state, lid, 'expired-only', '${SOURCE_B_IP}/32', expires_at=past)
# Keep ALLOWLIST binding even with only expired sources.
sa=state.setdefault('service_access', {}).setdefault('${CLIENT_ID}', {})
sa['${SERVICE_ID}']={'access_mode':'ALLOWLIST','access_list_id':lid}
acl.save_access_state(state, path=path)
print('seeded_expired_only')
PY"
sshx "$SERVER" "sudo frp-access remove-expired 'E2E-Allow' --yes" | tee "$OUT_DIR/expired-cleanup.txt"
MODE="$(sshx "$SERVER" "sudo frp-access show-service ${CLIENT_ID} ${SERVICE_ID}" | awk -F: '/Access mode/{print $2}' | tr -d ' ')"
[[ "$MODE" == "ALLOWLIST" ]] || fail "expired cleanup must stay ALLOWLIST"
if probe "$SOURCE_A_HOST"; then fail "A should DENY after expired-only cleanup"; else pass EXPIRED_CLEANUP_DENY; fi
pass EXPIRED_CLEANUP_ALLOWLIST

# Missing access-control.json => health 503 + connection DENY; restore recovers.
echo "=== missing access policy fail-closed ==="
sshx "$SERVER" "sudo mv /var/lib/drlink/access-control.json /var/lib/drlink/access-control.json.bak-e2e"
sleep 1
CODE="$(sshx "$SERVER" 'curl -s -o /tmp/ac-health.json -w %{http_code} http://127.0.0.1:6101/healthz || true')"
[[ "$CODE" == "503" ]] || fail "healthz expected 503 when policy missing (got $CODE)"
if probe "$SOURCE_A_HOST"; then
  sshx "$SERVER" "sudo mv /var/lib/drlink/access-control.json.bak-e2e /var/lib/drlink/access-control.json"
  fail "missing policy must DENY"
fi
pass MISSING_POLICY_DENY
sshx "$SERVER" "sudo mv /var/lib/drlink/access-control.json.bak-e2e /var/lib/drlink/access-control.json"
sleep 1
CODE="$(sshx "$SERVER" 'curl -s -o /tmp/ac-health.json -w %{http_code} http://127.0.0.1:6101/healthz || true')"
[[ "$CODE" == "200" ]] || fail "healthz expected 200 after policy restore (got $CODE)"
# Re-seed usable SourceA for subsequent checks
sshx "$SERVER" "sudo frp-access add-source 'E2E-Allow' --name SourceA --source ${SOURCE_A_IP}/32 --yes" >/dev/null
sleep 1
probe "$SOURCE_A_HOST" || fail "A after policy restore"
pass MISSING_POLICY_RECOVERY

# Missing registry => health 503 + connection DENY; restore recovers.
echo "=== missing registry fail-closed ==="
sshx "$SERVER" "sudo cp -a /var/lib/drlink/registry.json /var/lib/drlink/registry.json.bak-e2e
sudo mv /var/lib/drlink/registry.json /var/lib/drlink/registry.json.gone-e2e"
sleep 1
CODE="$(sshx "$SERVER" 'curl -s -o /tmp/ac-health-reg.json -w %{http_code} http://127.0.0.1:6101/healthz || true')"
[[ "$CODE" == "503" ]] || fail "healthz expected 503 when registry missing (got $CODE)"
if probe "$SOURCE_A_HOST"; then
  sshx "$SERVER" "sudo mv /var/lib/drlink/registry.json.gone-e2e /var/lib/drlink/registry.json"
  fail "missing registry must DENY"
fi
pass MISSING_REGISTRY_DENY
sshx "$SERVER" "sudo mv /var/lib/drlink/registry.json.gone-e2e /var/lib/drlink/registry.json
sudo rm -f /var/lib/drlink/registry.json.bak-e2e"
sleep 2
CODE="$(sshx "$SERVER" 'curl -s -o /tmp/ac-health-reg2.json -w %{http_code} http://127.0.0.1:6101/healthz || true')"
[[ "$CODE" == "200" ]] || fail "healthz expected 200 after registry restore (got $CODE)"
# Wait for published port again if frps was unsettled
for i in $(seq 1 24); do
  if sshx "$SERVER" "ss -lnt | grep -q ':${PUBLIC_PORT} '" >/dev/null 2>&1; then break; fi
  sleep 2
done
probe "$SOURCE_A_HOST" || fail "A after registry restore"
pass MISSING_REGISTRY_RECOVERY

# disable/enable on client
echo "=== disable/enable ==="
sshx "$CLIENT_HOST" "sudo drlink disable service ${SERVICE_ID}; sudo drlink apply" \
  || sshx "$CLIENT_HOST" "sudo frp-client disable-service ${SERVICE_ID}; sudo frp-client apply"
sleep 3
sshx "$CLIENT_HOST" "sudo drlink enable service ${SERVICE_ID}; sudo drlink apply" \
  || sshx "$CLIENT_HOST" "sudo frp-client enable-service ${SERVICE_ID}; sudo frp-client apply"
sleep 3
NEW_PORT="$(sshx "$SERVER" "sudo python3 -c \"import json;from pathlib import Path;r=json.loads(Path('/var/lib/drlink/registry.json').read_text());print(r['clients']['$CLIENT_ID']['services']['$SERVICE_ID']['remote_port'])\"")"
[[ "$NEW_PORT" == "$PUBLIC_PORT" ]] || fail "port changed"
probe "$SOURCE_A_HOST" || fail "A after enable"
if probe "$SOURCE_B_HOST"; then fail "B after enable"; else pass DISABLE_ENABLE; fi

# reboot
echo "=== server reboot ==="
sshx "$SERVER" 'sudo reboot' || true
for i in $(seq 1 40); do
  sleep 5
  if sshx "$SERVER" 'systemctl is-active drlink-access && systemctl is-active drlink-server' >/dev/null 2>&1; then break; fi
done
sshx "$SERVER" 'systemctl is-active drlink-access && systemctl is-active drlink-server && curl -fsS http://127.0.0.1:6101/healthz' || fail "units after reboot"
# Wait until published proxy is listening again (client republish after frps restart).
for i in $(seq 1 36); do
  if sshx "$SERVER" "ss -lnt | grep -q ':${PUBLIC_PORT} '" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
sshx "$SERVER" "ss -lnt | grep -q ':${PUBLIC_PORT} '" || fail "public port not listening after reboot"
sleep 3
# Retry probes briefly while frpc work-conns settle.
ok=0
for i in 1 2 3 4 5 6; do
  if probe "$SOURCE_A_HOST"; then ok=1; break; fi
  sleep 5
done
[[ "$ok" == "1" ]] || fail "A after reboot"
if probe "$SOURCE_B_HOST"; then fail "B after reboot"; else pass REBOOT; fi

# PUBLIC restore + cleanup (keep service; only clear ACL binding + list)
sshx "$SERVER" "sudo frp-access public ${CLIENT_ID} ${SERVICE_ID}"
sleep 1
probe "$SOURCE_A_HOST" || fail "public restore A"
probe "$SOURCE_B_HOST" || fail "public restore B"
pass PUBLIC_RESTORE

# Release dedicated e2e-acl service when used; otherwise keep production ssh.
if [[ "$SERVICE_ID" == "e2e-acl" ]]; then
  sshx "$CLIENT_HOST" "sudo drlink disable service ${SERVICE_ID}; sudo drlink apply" || true
  sleep 2
  sshx "$SERVER" "printf 'RELEASE\n' | sudo frp-release-service ${CLIENT_ID} ${SERVICE_ID}" || true
  sshx "$CLIENT_HOST" "sudo drlink apply" || true
fi
sshx "$SERVER" "sudo frp-access delete 'E2E-Allow'" || true
# list gone; binding should be gone after release or public
if [[ "$SERVICE_ID" == "e2e-acl" ]]; then
  if sshx "$SERVER" "sudo python3 -c \"import json;from pathlib import Path;r=json.loads(Path('/var/lib/drlink/registry.json').read_text());import sys;sys.exit(0 if 'e2e-acl' in (r['clients']['${CLIENT_ID}'].get('services') or {}) else 1)\""; then
    fail "service still present after release"
  fi
else
  SHOW="$(sshx "$SERVER" "sudo frp-access show-service ${CLIENT_ID} ${SERVICE_ID}")"
  echo "$SHOW" | tee "$OUT_DIR/show-service-final.txt"
  echo "$SHOW" | grep -q 'Access mode   : PUBLIC' || fail "not public after cleanup"
fi
pass CLEANUP

cat >"$OUT_DIR/result.env" <<EOF
TARGETED_REAL_E2E=PASS
REAL_E2E_SOURCE_A=$SOURCE_A_IP
REAL_E2E_SOURCE_B=$SOURCE_B_IP
REAL_E2E_PUBLIC_PORT=$PUBLIC_PORT
REAL_E2E_SERVICE_ID=$SERVICE_ID
REAL_E2E_CLIENT_ID=$CLIENT_ID
REAL_E2E_ALLOW_A=PASS
REAL_E2E_DENY_B=PASS
REAL_E2E_TTL_PRE_EXPIRY=PASS
REAL_E2E_TTL_POST_EXPIRY=PASS
REAL_E2E_EXPIRED_CLEANUP=PASS
REAL_E2E_MISSING_POLICY=PASS
REAL_E2E_MISSING_REGISTRY=PASS
REAL_E2E_REBOOT=PASS
REAL_E2E_CLEANUP=PASS
EOF
echo "TARGETED_REAL_E2E=PASS report=$OUT_DIR"
