#!/usr/bin/env bash
# Targeted Real E2E for Target Health Check (FRP healthCheck thin wrapper).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
SERVER="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
CLIENT_HOST="${FRP_HEALTH_E2E_CLIENT:-${FRP_ACCESS_E2E_CLIENT:-frp-e2e-aws}}"
OUT_DIR="${FRP_HEALTH_E2E_OUT:-$ROOT/e2e-reports/target-health-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"
exec > >(tee -a "$OUT_DIR/run.log") 2>&1

pass(){ echo "PASS $1"; }
fail(){ echo "FAIL $1" >&2; echo "TARGETED_REAL_E2E=FAIL" >"$OUT_DIR/result.env"; exit 1; }
blocker(){ echo "ENVIRONMENT_BLOCKER $1" >&2; echo "TARGETED_REAL_E2E=ENVIRONMENT_BLOCKER" >"$OUT_DIR/result.env"; exit 2; }
sshx(){ local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$h" "$@"; }

echo "=== Target Health Check targeted Real E2E ==="
sshx "$SERVER" 'echo ok' >/dev/null || blocker "server unreachable: $SERVER"
sshx "$CLIENT_HOST" 'echo ok' >/dev/null || blocker "client unreachable: $CLIENT_HOST"

SVC_ID="e2e-health"
BACKEND_PORT=18765

echo "=== sync client feature files ==="
TMP_SYNC=/tmp/frp-health-sync-$$
sshx "$CLIENT_HOST" "sudo rm -rf $TMP_SYNC && sudo mkdir -p $TMP_SYNC && sudo chmod 777 $TMP_SYNC"
for f in \
  lib/frp_health_check.py \
  lib/frp-client-common.sh \
  lib/frp_ctl_grammar.py \
  tools/frp-client \
  tools/frpctl
do
  scp -o BatchMode=yes -o ConnectTimeout=15 "$ROOT/$f" "$CLIENT_HOST:$TMP_SYNC/$(basename "$f")"
done
sshx "$CLIENT_HOST" "sudo install -m 0644 $TMP_SYNC/frp_health_check.py /usr/local/lib/frp-auto-deploy/frp_health_check.py
sudo install -m 0644 $TMP_SYNC/frp-client-common.sh /usr/local/lib/frp-auto-deploy/frp-client-common.sh
sudo install -m 0644 $TMP_SYNC/frp_ctl_grammar.py /usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py
sudo install -m 0755 $TMP_SYNC/frp-client /usr/local/bin/frp-client
sudo install -m 0755 $TMP_SYNC/frpctl /usr/local/bin/frpctl
sudo rm -rf $TMP_SYNC"

# Also sync allocator helper onto server so enroll preserves health_check
TMP_SRV=/tmp/frp-health-srv-$$
sshx "$SERVER" "sudo rm -rf $TMP_SRV && sudo mkdir -p $TMP_SRV && sudo chmod 777 $TMP_SRV"
for f in lib/frp_health_check.py server/frp-port-allocator.py; do
  scp -o BatchMode=yes -o ConnectTimeout=15 "$ROOT/$f" "$SERVER:$TMP_SRV/$(basename "$f")"
done
sshx "$SERVER" "sudo install -m 0644 $TMP_SRV/frp_health_check.py /usr/local/lib/frp-auto-deploy/frp_health_check.py
sudo install -m 0700 $TMP_SRV/frp-port-allocator.py /usr/local/lib/frp-auto-deploy/frp-port-allocator.py
sudo systemctl restart frp-port-allocator || true
sudo rm -rf $TMP_SRV"

echo "=== start local TCP backend on client ==="
sshx "$CLIENT_HOST" "sudo pkill -f 'frp-e2e-health-backend' >/dev/null 2>&1 || true
python3 - <<'PY' >/tmp/frp-e2e-health-backend.log 2>&1 &
import socket, threading
# frp-e2e-health-backend
sock = socket.socket(); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', $BACKEND_PORT)); sock.listen(5)
def serve(c):
    try:
        c.recv(64); c.sendall(b'OK\\n')
    finally:
        c.close()
while True:
    c, _ = sock.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
sleep 1
python3 -c \"import socket; s=socket.create_connection(('127.0.0.1',$BACKEND_PORT),2); s.close()\" "

echo "=== add/configure health TCP service ==="
sshx "$CLIENT_HOST" "sudo /usr/local/bin/frpctl discard >/dev/null 2>&1 || true
if ! sudo python3 - <<'PY'
import json
from pathlib import Path
p=Path('/etc/frp/client-state.json')
d=json.loads(p.read_text())
print('yes' if '$SVC_ID' in (d.get('services') or {}) else 'no')
PY | grep -qx yes; then
  sudo /usr/local/bin/frp-client add-service --preset custom --id '$SVC_ID' --name 'E2E Health' --target-host 127.0.0.1 --target-port $BACKEND_PORT
fi
sudo /usr/local/bin/frpctl set service '$SVC_ID' target-port $BACKEND_PORT || sudo /usr/local/bin/frp-client set-service '$SVC_ID' target-port $BACKEND_PORT
sudo /usr/local/bin/frpctl set service '$SVC_ID' health-type tcp || sudo /usr/local/bin/frp-client set-service '$SVC_ID' health-type tcp
sudo /usr/local/bin/frpctl apply || sudo /usr/local/bin/frp-client apply-pending
"

echo "=== verify frpc.toml healthCheck ==="
sshx "$CLIENT_HOST" "sudo grep -A20 'name = \".*-$SVC_ID\"' /etc/frp/frpc.toml | grep -q 'healthCheck.type = \"tcp\"'" \
  || fail "frpc.toml missing healthCheck.type tcp"
pass "frpc.toml has healthCheck tcp"

echo "=== TARGET healthy while backend up ==="
STATUS_OUT="$(sshx "$CLIENT_HOST" "sudo /usr/local/bin/frpctl show services || sudo /usr/local/bin/frp-client list")"
echo "$STATUS_OUT" | tee "$OUT_DIR/show-services-healthy.txt"
echo "$STATUS_OUT" | grep -A20 "$SVC_ID" | grep -Eq 'TARGET[[:space:]]*:[[:space:]]*HEALTHY' \
  || echo "$STATUS_OUT" | grep -A20 "$SVC_ID" | grep -Eq 'TARGET[[:space:]]+HEALTHY' \
  || fail "TARGET not HEALTHY with backend up"
pass "TARGET HEALTHY"

echo "=== stop backend -> TARGET unhealthy ==="
sshx "$CLIENT_HOST" "sudo pkill -f 'frp-e2e-health-backend' >/dev/null 2>&1 || true; sleep 1"
STATUS_DOWN="$(sshx "$CLIENT_HOST" "sudo /usr/local/bin/frpctl show services || sudo /usr/local/bin/frp-client list")"
echo "$STATUS_DOWN" | tee "$OUT_DIR/show-services-unhealthy.txt"
echo "$STATUS_DOWN" | grep -A20 "$SVC_ID" | grep -Eq 'TARGET[[:space:]]*:[[:space:]]*UNHEALTHY' \
  || fail "TARGET not UNHEALTHY with backend down"
# Ensure we never print DOWN for unknown
echo "$STATUS_DOWN" | grep -A20 "$SVC_ID" | grep -Eq 'TARGET[[:space:]]*:[[:space:]]*DOWN' && fail "TARGET displayed DOWN" || true
pass "TARGET UNHEALTHY"

echo "=== restore backend -> TARGET healthy ==="
sshx "$CLIENT_HOST" "python3 - <<'PY' >/tmp/frp-e2e-health-backend.log 2>&1 &
import socket, threading
# frp-e2e-health-backend
sock = socket.socket(); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', $BACKEND_PORT)); sock.listen(5)
def serve(c):
    try:
        c.recv(64); c.sendall(b'OK\\n')
    finally:
        c.close()
while True:
    c, _ = sock.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
sleep 1"
STATUS_UP="$(sshx "$CLIENT_HOST" "sudo /usr/local/bin/frpctl show services || sudo /usr/local/bin/frp-client list")"
echo "$STATUS_UP" | tee "$OUT_DIR/show-services-restored.txt"
echo "$STATUS_UP" | grep -A20 "$SVC_ID" | grep -Eq 'TARGET[[:space:]]*:[[:space:]]*HEALTHY' \
  || fail "TARGET not HEALTHY after restore"
pass "TARGET restored HEALTHY"

echo "=== HTTP health if feasible ==="
HTTP_PORT=18766
sshx "$CLIENT_HOST" "sudo pkill -f 'frp-e2e-health-http' >/dev/null 2>&1 || true
python3 - <<'PY' >/tmp/frp-e2e-health-http.log 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
# frp-e2e-health-http
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a):
        pass
HTTPServer(('127.0.0.1', $HTTP_PORT), H).serve_forever()
PY
sleep 1
sudo /usr/local/bin/frpctl set service '$SVC_ID' target-port $HTTP_PORT || sudo /usr/local/bin/frp-client set-service '$SVC_ID' target-port $HTTP_PORT
sudo /usr/local/bin/frpctl set service '$SVC_ID' health-type http || sudo /usr/local/bin/frp-client set-service '$SVC_ID' health-type http
sudo /usr/local/bin/frpctl set service '$SVC_ID' health-path /health || sudo /usr/local/bin/frp-client set-service '$SVC_ID' health-path /health
sudo /usr/local/bin/frpctl apply || sudo /usr/local/bin/frp-client apply-pending
sudo grep -A25 'name = \".*-$SVC_ID\"' /etc/frp/frpc.toml | grep -q 'healthCheck.type = \"http\"'
sudo grep -A25 'name = \".*-$SVC_ID\"' /etc/frp/frpc.toml | grep -q 'healthCheck.path = \"/health\"'
"
pass "HTTP healthCheck rendered"

echo "=== disable/enable preserves health config ==="
sshx "$CLIENT_HOST" "
sudo /usr/local/bin/frpctl disable service '$SVC_ID' || sudo /usr/local/bin/frp-client disable-service '$SVC_ID'
sudo /usr/local/bin/frpctl enable service '$SVC_ID' || sudo /usr/local/bin/frp-client enable-service '$SVC_ID'
sudo /usr/local/bin/frpctl apply || sudo /usr/local/bin/frp-client apply-pending
sudo python3 - <<'PY'
import json
from pathlib import Path
d=json.loads(Path('/etc/frp/client-state.json').read_text())
hc=(d.get('services') or {}).get('$SVC_ID', {}).get('health_check') or {}
assert hc.get('type')=='http', hc
assert hc.get('path')=='/health', hc
print('preserved')
PY
sudo grep -A25 'name = \".*-$SVC_ID\"' /etc/frp/frpc.toml | grep -q 'healthCheck.type = \"http\"'
"
pass "disable/enable preserves health_check"

# cleanup backends (leave service configured)
sshx "$CLIENT_HOST" "sudo pkill -f 'frp-e2e-health-backend' >/dev/null 2>&1 || true
sudo pkill -f 'frp-e2e-health-http' >/dev/null 2>&1 || true" || true

echo "TARGETED_REAL_E2E=PASS" | tee "$OUT_DIR/result.env"
echo "=== Target Health Check E2E PASS ==="
echo "Report: $OUT_DIR"
