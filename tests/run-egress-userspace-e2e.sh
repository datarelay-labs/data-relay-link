#!/usr/bin/env bash
set -euo pipefail
SERVER=frp-e2e-server
CLIENT=frp-e2e-client
PORT=16080
SSH=(-o BatchMode=yes -o ConnectTimeout=10)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== userspace Controlled Egress Real E2E =="
ssh "${SSH[@]}" "$SERVER" 'rm -rf /tmp/frp-egress-user-smoke && mkdir -p /tmp/frp-egress-user-smoke/{lib,server}'
scp "${SSH[@]}" "$ROOT/lib/frp_egress_control.py" "$SERVER:/tmp/frp-egress-user-smoke/lib/"
scp "${SSH[@]}" "$ROOT/server/frp-egress-gateway.py" "$SERVER:/tmp/frp-egress-user-smoke/server/"

ssh "${SSH[@]}" "$SERVER" bash -s <<'REMOTE'
set -euo pipefail
export FRP_DEPLOY_TEST_ROOT=/tmp/frp-egress-user-smoke
mkdir -p "$FRP_DEPLOY_TEST_ROOT/usr/local/lib/frp-auto-deploy" \
  "$FRP_DEPLOY_TEST_ROOT/etc/frp-auto-deploy" \
  "$FRP_DEPLOY_TEST_ROOT/var/lib/frp-auto-deploy" \
  "$FRP_DEPLOY_TEST_ROOT/var/log/frp-auto-deploy"
cp /tmp/frp-egress-user-smoke/lib/frp_egress_control.py \
  "$FRP_DEPLOY_TEST_ROOT/usr/local/lib/frp-auto-deploy/"
python3 - <<'PY'
import importlib.util, json, os
from pathlib import Path
root=Path(os.environ['FRP_DEPLOY_TEST_ROOT'])
spec=importlib.util.spec_from_file_location('eg', root/'usr/local/lib/frp-auto-deploy/frp_egress_control.py')
eg=importlib.util.module_from_spec(spec); spec.loader.exec_module(eg)
path=root/'var/lib/frp-auto-deploy/egress-control.json'
eg.save_egress_state(eg.empty_egress_state(), path=path)
def mut(st):
    pid,_=eg.create_profile(st,'smoke')
    eg.add_source(st,pid,'0.0.0.0/0')
    eg.add_destination(st,pid,'example.com',80)
    eg.add_destination(st,pid,'example.com',443)
    return pid
eg.mutate_egress_state(mut, path=path)
cfg={
 'egress_control_file':'/var/lib/frp-auto-deploy/egress-control.json',
 'egress_conn_log_file':'/var/log/frp-auto-deploy/egress-conn.jsonl',
 'egress_listen_addr':'0.0.0.0',
 'egress_listen_port':16080,
}
(root/'etc/frp-auto-deploy/config.json').write_text(json.dumps(cfg,indent=2)+'\n')
print('ready')
PY
pkill -f 'frp-egress-gateway.py --listen-port 16080' 2>/dev/null || true
nohup env FRP_DEPLOY_TEST_ROOT=/tmp/frp-egress-user-smoke \
  python3 /tmp/frp-egress-user-smoke/server/frp-egress-gateway.py \
  --config /etc/frp-auto-deploy/config.json \
  --listen-addr 0.0.0.0 --listen-port 16080 \
  >/tmp/frp-egress-user-smoke/gateway.log 2>&1 &
echo $! >/tmp/frp-egress-user-smoke/gateway.pid
sleep 1
ss -lntn | grep ':16080' || { echo FAIL_LISTEN; cat /tmp/frp-egress-user-smoke/gateway.log; exit 1; }
echo LISTEN_OK
hostname -I | awk '{print $1}'
REMOTE

SERVER_IP=$(ssh "${SSH[@]}" "$SERVER" "hostname -I | awk '{print \$1}'")
echo "SERVER_IP=$SERVER_IP"

ssh "${SSH[@]}" "$CLIENT" bash -s <<CLIENT
set -euo pipefail
export HTTP_PROXY=http://${SERVER_IP}:16080
export HTTPS_PROXY=http://${SERVER_IP}:16080
echo HOST=\$(hostname)
code=\$(curl -sS -o /tmp/a.body -w '%{http_code}' --max-time 25 http://example.com/)
echo ALLOW_HTTP=\$code
test "\$code" = "200"
deny=\$(curl -sS -o /tmp/d.body -w '%{http_code}' --max-time 10 http://never-allowed.invalid/ || true)
echo DENY_HTTP=\$deny
test "\$deny" != "200"
https=\$(curl -sS -o /tmp/h.body -w '%{http_code}' --max-time 30 https://example.com/)
echo ALLOW_HTTPS=\$https
test "\$https" = "200"
echo AGENTLESS_EGRESS_PASS
CLIENT

ssh "${SSH[@]}" "$SERVER" bash -s <<'REMOTE2'
set -euo pipefail
kill "$(cat /tmp/frp-egress-user-smoke/gateway.pid)" 2>/dev/null || true
sleep 1
nohup env FRP_DEPLOY_TEST_ROOT=/tmp/frp-egress-user-smoke \
  python3 /tmp/frp-egress-user-smoke/server/frp-egress-gateway.py \
  --config /etc/frp-auto-deploy/config.json \
  --listen-addr 0.0.0.0 --listen-port 16080 \
  >/tmp/frp-egress-user-smoke/gateway.log 2>&1 &
echo $! >/tmp/frp-egress-user-smoke/gateway.pid
sleep 1
ss -lntn | grep ':16080'
systemctl is-active frps || true
REMOTE2

code=$(ssh "${SSH[@]}" "$CLIENT" "HTTP_PROXY=http://${SERVER_IP}:16080 HTTPS_PROXY=http://${SERVER_IP}:16080 curl -sS -o /dev/null -w '%{http_code}' --max-time 25 https://example.com/")
echo "RESTART_HTTPS=$code"
test "$code" = "200"
echo REAL_EGRESS_USERSPACE_E2E=PASS
