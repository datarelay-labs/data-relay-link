#!/usr/bin/env bash
# Lightweight Real E2E smoke for Controlled Egress (agentless).
# Uses frp-e2e-server + frp-e2e-client SSH aliases. Does not purge FRP install.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_ALIAS="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
CLIENT_ALIAS="${FRP_E2E_CLIENT_ALIAS:-frp-e2e-client}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
PROXY_PORT="${FRP_E2E_EGRESS_PORT:-16080}"
PROFILE="e2e-egress-smoke"

sshx() { ssh "${SSH_OPTS[@]}" "$1" "${@:2}"; }
scpx() { scp "${SSH_OPTS[@]}" "$@"; }

echo "== Controlled Egress Real E2E smoke =="
sshx "$SERVER_ALIAS" 'hostname; id -u'

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp "$ROOT/lib/frp_egress_control.py" "$TMP/"
cp "$ROOT/server/frp-egress-gateway.py" "$TMP/"
cp "$ROOT/tools/frp-egress" "$TMP/"

scpx "$TMP/frp_egress_control.py" "$TMP/frp-egress-gateway.py" "$TMP/frp-egress" \
  "${SERVER_ALIAS}:/tmp/frp-egress-smoke/"

sshx "$SERVER_ALIAS" "sudo bash -s" <<EOF
set -euo pipefail
install -d -m 0755 /tmp/frp-egress-smoke
install -m 0644 /tmp/frp-egress-smoke/frp_egress_control.py /usr/local/lib/drlink/frp_egress_control.py
install -m 0700 /tmp/frp-egress-smoke/frp-egress-gateway.py /usr/local/lib/drlink/frp-egress-gateway.py
install -m 0755 /tmp/frp-egress-smoke/frp-egress /usr/local/sbin/frp-egress
python3 - <<'PY'
import importlib.util, json
from pathlib import Path
spec=importlib.util.spec_from_file_location('eg','/usr/local/lib/drlink/frp_egress_control.py')
eg=importlib.util.module_from_spec(spec); spec.loader.exec_module(eg)
path=Path('/var/lib/drlink/egress-control.json')
if not path.is_file():
    eg.save_egress_state(eg.empty_egress_state(), path=path)
cfg_path=Path('/etc/drlink/config.json')
cfg=json.loads(cfg_path.read_text())
cfg.setdefault('egress_control_file','/var/lib/drlink/egress-control.json')
cfg.setdefault('egress_conn_log_file','/var/log/drlink/egress-conn.jsonl')
cfg.setdefault('egress_listen_addr','0.0.0.0')
cfg.setdefault('egress_listen_port', ${PROXY_PORT})
cfg_path.write_text(json.dumps(cfg, indent=2, sort_keys=True)+'\\n')
print('config ready')
PY
# Stop previous smoke gateway if any
pkill -f 'frp-egress-gateway.py --listen-port ${PROXY_PORT}' 2>/dev/null || true
nohup python3 /usr/local/lib/drlink/frp-egress-gateway.py \
  --config /etc/drlink/config.json \
  --listen-addr 0.0.0.0 --listen-port ${PROXY_PORT} \
  >/tmp/frp-egress-smoke.log 2>&1 &
echo \$! >/tmp/frp-egress-smoke.pid
sleep 1
test -s /tmp/frp-egress-smoke.pid
ss -lnt | grep -q ':${PROXY_PORT}' || { echo 'gateway not listening'; cat /tmp/frp-egress-smoke.log; exit 1; }
# Reset profile
python3 - <<'PY'
import importlib.util, json, socket
from pathlib import Path
spec=importlib.util.spec_from_file_location('eg','/usr/local/lib/drlink/frp_egress_control.py')
eg=importlib.util.module_from_spec(spec); spec.loader.exec_module(eg)
path=Path('/var/lib/drlink/egress-control.json')
state=eg.empty_egress_state()
eg.save_egress_state(state, path=path)

def mut(st):
    pid,_=eg.create_profile(st, '${PROFILE}', enabled=True)
    # Allow client NAT/public IP and common private ranges for smoke; tighten in real ops.
    for cidr in ('0.0.0.0/0',):
        eg.add_source(st, pid, cidr)
    eg.add_destination(st, pid, 'example.com', 80, protocol='http')
    eg.add_destination(st, pid, 'example.com', 443, protocol='https')
    return pid
eg.mutate_egress_state(mut, path=path)
print('profile ready')
PY
EOF

SERVER_IP=$(sshx "$SERVER_ALIAS" 'hostname -I | awk "{print \$1}"')
echo "Server IP: $SERVER_IP proxy :$PROXY_PORT"

# Agentless client tests (no frpc required)
sshx "$CLIENT_ALIAS" "bash -s" <<EOF
set -euo pipefail
export HTTP_PROXY=http://${SERVER_IP}:${PROXY_PORT}
export HTTPS_PROXY=http://${SERVER_IP}:${PROXY_PORT}
export NO_PROXY=127.0.0.1,localhost
echo 'CLIENT host:' \$(hostname)
# Approved HTTP
code=\$(curl -sS -o /tmp/eg-allow.body -w '%{http_code}' --max-time 20 http://example.com/ || true)
echo "ALLOW HTTP code=\$code"
grep -qi example /tmp/eg-allow.body || test "\$code" = "200"
# Denied host
deny=\$(curl -sS -o /tmp/eg-deny.body -w '%{http_code}' --max-time 10 http://never-allowed.invalid/ || true)
echo "DENY HTTP code=\$deny"
test "\$deny" = "403" -o "\$deny" = "000" -o "\$deny" = "502"
# Approved CONNECT / HTTPS
https=\$(curl -sS -o /tmp/eg-https.body -w '%{http_code}' --max-time 25 https://example.com/ || true)
echo "ALLOW HTTPS code=\$https"
test "\$https" = "200"
# Wrong port deny (CONNECT to 8443)
wrong=\$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 https://example.com:8443/ || true)
echo "DENY wrong-port code=\$wrong"
test "\$wrong" != "200"
echo CLIENT_SMOKE_PASS
EOF

# Restart persistence
sshx "$SERVER_ALIAS" "sudo bash -s" <<EOF
set -euo pipefail
kill \$(cat /tmp/frp-egress-smoke.pid) 2>/dev/null || true
sleep 1
nohup python3 /usr/local/lib/drlink/frp-egress-gateway.py \
  --config /etc/drlink/config.json \
  --listen-addr 0.0.0.0 --listen-port ${PROXY_PORT} \
  >/tmp/frp-egress-smoke.log 2>&1 &
echo \$! >/tmp/frp-egress-smoke.pid
sleep 1
ss -lnt | grep -q ':${PROXY_PORT}'
# inbound FRP still up
systemctl is-active drlink-server >/dev/null
EOF

sshx "$CLIENT_ALIAS" "HTTP_PROXY=http://${SERVER_IP}:${PROXY_PORT} HTTPS_PROXY=http://${SERVER_IP}:${PROXY_PORT} curl -sS -o /dev/null -w '%{http_code}' --max-time 20 https://example.com/" | grep -q 200

echo "REAL_EGRESS_E2E_SMOKE=PASS"
echo "Note: smoke used temporary listen port ${PROXY_PORT}; profile ${PROFILE} left on server for inspection."
