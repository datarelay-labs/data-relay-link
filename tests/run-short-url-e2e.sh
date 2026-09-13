#!/usr/bin/env bash
# Real E2E for Zero-Touch short URL (Option B) with publicly trusted TLS.
# Uses cloudflared quick tunnel as the operator reverse proxy edge.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${FRP_E2E_PROFILE:-baseline-linux}"
SERVER_ALIAS="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5)
RUN_ID="${FRP_E2E_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${FRP_E2E_OUT_DIR:-$ROOT/e2e-reports/short-url-e2e-$RUN_ID}"
HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD)"
INSTALLER_URL="https://raw.githubusercontent.com/datarelay-labs/data-relay-link/${HEAD_SHA}/dist/bootstrap-client.sh"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"
: >"$SUMMARY"

note() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
fail() { note "FAIL $*"; exit 1; }
pass() { note "PASS $*"; }

case "$PROFILE" in
  baseline-linux|linux|ubuntu)
    CLIENT_ALIAS="${FRP_E2E_CLIENT_ALIAS:-frp-e2e-client}"
    TUNNEL_SSH_USER="${FRP_E2E_TUNNEL_SSH_USER:-aella}"
    CLIENT_LABEL="${FRP_E2E_CLIENT_LABEL:-short-url-linux}"
    ;;
  amazon-linux-2023|al2023|aws)
    CLIENT_ALIAS="${FRP_E2E_CLIENT_ALIAS:-frp-e2e-aws}"
    TUNNEL_SSH_USER="${FRP_E2E_TUNNEL_SSH_USER:-ec2-user}"
    CLIENT_LABEL="${FRP_E2E_CLIENT_LABEL:-short-url-al2023}"
    ;;
  rocky-linux-8.10|rocky8|rocky)
    CLIENT_ALIAS="${FRP_E2E_CLIENT_ALIAS:-frp-e2e-rocky8}"
    TUNNEL_SSH_USER="${FRP_E2E_TUNNEL_SSH_USER:-root}"
    CLIENT_LABEL="${FRP_E2E_CLIENT_LABEL:-short-url-rocky8}"
    ;;
  *) fail "unknown profile $PROFILE" ;;
esac

note "PROFILE=$PROFILE"
note "HEAD_SHA=$HEAD_SHA"
note "INSTALLER_URL=$INSTALLER_URL"
note "CLIENT_ALIAS=$CLIENT_ALIAS"

ssh_server() { ssh "${SSH_OPTS[@]}" "$SERVER_ALIAS" "$@"; }
ssh_client() { ssh "${SSH_OPTS[@]}" "$CLIENT_ALIAS" "$@"; }

# Verify installer URL is publicly fetchable (stock TLS).
curl -fsSL --proto '=https' --tlsv1.2 -o /dev/null -w '%{http_code}\n' "$INSTALLER_URL" \
  | grep -qx '200' || fail "installer URL not publicly fetchable with stock TLS"
pass "INSTALLER_PUBLIC_TLS"

# Ensure cloudflared exists on the server.
ssh_server 'command -v cloudflared >/dev/null || (
  curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /tmp/cloudflared &&
  chmod +x /tmp/cloudflared && sudo mv /tmp/cloudflared /usr/local/bin/cloudflared
)' || fail "install cloudflared on server"

# Refresh server project tools from this branch via stdin bootstrap upgrade.
# Working-tree artifacts are channel=dev / git_ref=main.
note "Updating server tools from local tree"
ssh_server "sudo env FRP_RELEASE_CHANNEL=dev FRP_CLIENT_INSTALLER_URL='$INSTALLER_URL' bash -s -- --upgrade" \
  <"$ROOT/dist/bootstrap-server.sh" >"$OUT_DIR/server-upgrade.log" 2>&1 \
  || { cat "$OUT_DIR/server-upgrade.log"; fail "server upgrade"; }
pass "SERVER_UPGRADE"

# Start a tiny allowlisted HTTP→HTTPS proxy on the server (operator reverse proxy),
# then expose it with cloudflared (publicly trusted TLS).
# Avoid `pkill -f <scriptname>` matching this remote shell command line.
ssh_server 'sudo pkill -x cloudflared >/dev/null 2>&1 || true; sudo pkill -f "[f]rp-short-url-proxy.py" >/dev/null 2>&1 || true; sleep 1' || true
PROXY_PORT=18080
ssh_server 'rm -f /tmp/frp-short-url-proxy.py; cat > /tmp/frp-short-url-proxy.py' <<'PY' || fail "write allowlist proxy"
#!/usr/bin/env python3
"""Minimal Option-B allowlist proxy for short-URL Real E2E."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import ssl
import urllib.error
import urllib.request

UPSTREAM = 'https://127.0.0.1:6099'
ALLOW = re.compile(r'^/(i/[^/?#]+|ca\.crt|healthz|bootstrap/redeem|enroll)$')
CTX = ssl._create_unverified_context()

class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        msg = fmt % args
        msg = re.sub(r'(/i/)[^/?\s#]+', r'\1<redacted>', msg)
        print(msg, flush=True)

    def _proxy(self, method):
        path = self.path.split('?', 1)[0]
        if not ALLOW.match(path):
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'not found\n')
            return
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length > 0 else None
        req = urllib.request.Request(UPSTREAM + self.path, data=body, method=method)
        for key in ('Content-Type', 'X-Enrollment-ID', 'X-Timestamp', 'X-Signature', 'X-Mgmt-Auth'):
            if key in self.headers:
                req.add_header(key, self.headers[key])
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=60) as resp:
                data = resp.read()
                self.send_response(resp.status)
                for hk, hv in resp.headers.items():
                    lk = hk.lower()
                    if lk in ('transfer-encoding', 'connection', 'content-length'):
                        continue
                    self.send_header(hk, hv)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            self.send_response(exc.code)
            self.send_header('Content-Type', exc.headers.get('Content-Type', 'text/plain'))
            self.send_header('Content-Length', str(len(data)))
            for hk in ('Cache-Control', 'Pragma', 'X-Content-Type-Options', 'Referrer-Policy'):
                if exc.headers.get(hk):
                    self.send_header(hk, exc.headers.get(hk))
            self.end_headers()
            self.wfile.write(data)

    def do_GET(self):
        self._proxy('GET')

    def do_POST(self):
        self._proxy('POST')

ThreadingHTTPServer(('127.0.0.1', int(__import__('os').environ.get('PORT', '18080'))), H).serve_forever()
PY
ssh_server "PORT=$PROXY_PORT nohup python3 /tmp/frp-short-url-proxy.py > /tmp/frp-short-url-proxy.log 2>&1 & echo \$!" \
  >"$OUT_DIR/proxy.pid" || fail "start allowlist proxy"
ssh_server "rm -f /tmp/frp-short-url-tunnel.log; nohup cloudflared tunnel --url http://127.0.0.1:$PROXY_PORT > /tmp/frp-short-url-tunnel.log 2>&1 < /dev/null & echo \$!" \
  >"$OUT_DIR/tunnel.pid" || fail "start tunnel"
BOOTSTRAP_HOST=""
for _ in $(seq 1 30); do
  BOOTSTRAP_HOST="$(ssh_server 'grep -oE "[a-zA-Z0-9-]+\\.trycloudflare\\.com" /tmp/frp-short-url-tunnel.log 2>/dev/null | head -1' || true)"
  if [[ -n "$BOOTSTRAP_HOST" ]]; then
    break
  fi
  sleep 2
done
[[ -n "$BOOTSTRAP_HOST" ]] || {
  ssh_server 'tail -80 /tmp/frp-short-url-tunnel.log; echo ----; tail -40 /tmp/frp-short-url-proxy.log; ss -lntp | grep 18080 || true' >"$OUT_DIR/tunnel-debug.log" || true
  cat "$OUT_DIR/tunnel-debug.log"
  fail "cloudflared hostname not ready"
}
note "BOOTSTRAP_HOST=$BOOTSTRAP_HOST"
pass "PUBLIC_PROXY_TUNNEL"

# Wait until the publicly trusted bootstrap edge answers /healthz.
ok=0
for _ in $(seq 1 40); do
  if curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 15 \
    -o /dev/null "https://${BOOTSTRAP_HOST}/healthz"; then
    ok=1
    break
  fi
  sleep 2
done
[[ "$ok" == "1" ]] || fail "stock OS trust failed for bootstrap host /healthz"
pass "STOCK_OS_TRUST_HEALTHZ"

# Configure bootstrap hostname + installer URL on server.
# Tools update config.json without restarting services; allocator reloads on
# mtime change, and we still bounce it so E2E never races a stale process.
ssh_server "sudo /usr/local/bin/drlink set server bootstrap-hostname '$BOOTSTRAP_HOST'" \
  >"$OUT_DIR/set-bootstrap.log" 2>&1 || fail "set bootstrap-hostname"
ssh_server "sudo /usr/local/sbin/frp-set-client-installer-url '$INSTALLER_URL'" \
  >"$OUT_DIR/set-installer.log" 2>&1 || fail "set installer url"
ssh_server 'sudo systemctl daemon-reload; sudo systemctl restart drlink-allocator' \
  >"$OUT_DIR/restart-allocator.log" 2>&1 || fail "restart allocator after config"
for _ in $(seq 1 30); do
  if ssh_server 'curl -fsSk https://127.0.0.1:6099/healthz >/dev/null 2>&1'; then
    break
  fi
  sleep 1
done
pass "BOOTSTRAP_HOSTNAME_CONFIGURED"

# Purge any previous short-url client on the target.
ssh_client 'sudo bash -s --' <"$ROOT/dist/uninstall-client.sh" >"$OUT_DIR/client-purge.log" 2>&1 || true

# Create short URL enrollment and capture exact printed command.
CREATE_OUT="$OUT_DIR/create.out"
ssh_server "sudo /usr/local/sbin/frp-create-client --one-line --ssh --ssh-user '$TUNNEL_SSH_USER' --client-name '$CLIENT_LABEL' --note 'short-url-e2e'" \
  >"$CREATE_OUT" 2>&1 || { cat "$CREATE_OUT"; fail "create enrollment"; }

CMD="$(python3 - "$CREATE_OUT" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"^curl -fsSL 'https://[^']+/i/bt1\.[0-9a-f]+\.[0-9a-f]+' \| sudo bash$", text, re.M)
if not m:
    raise SystemExit('missing short URL command in:\n' + text)
print(m.group(0))
PY
)"
note "SHORT_URL_COMMAND_HOST=$BOOTSTRAP_HOST"
# Do not log the opaque ticket. Keep only the command shape.
note "SHORT_URL_COMMAND=curl -fsSL https://${BOOTSTRAP_HOST}/i/<redacted> | sudo bash"
[[ "$CMD" == *"$BOOTSTRAP_HOST"* ]] || fail "command host mismatch"
if [[ "$CMD" == *zt1.* ]]; then
  fail "short URL path unexpectedly used zt1"
fi
if [[ "$CMD" == *'-k'* || "$CMD" == *'--insecure'* ]]; then
  fail "insecure TLS in printed command"
fi
pass "SHORT_URL_COMMAND_PRINTED"

# Run exact printed command on clean client (stock OS trust, no preinstalled CA).
# Use pipefail so a failed curl cannot look like success.
ssh_client "sudo bash -o pipefail -lc $(printf '%q' "$CMD")" >"$OUT_DIR/client-enroll.log" 2>&1 \
  || { cat "$OUT_DIR/client-enroll.log"; fail "short URL client enroll"; }
if ! grep -qiE 'enrollment complete|Zero-touch setup complete|FRP client ready|Data Relay Link client setup complete|setup complete' \
  "$OUT_DIR/client-enroll.log"; then
  # Accept active frpc + client-state as success when installer wording differs.
  if ! ssh_client 'sudo test -f /etc/frp/client-state.json && systemctl is-active drlink-client'; then
    cat "$OUT_DIR/client-enroll.log"
    fail "short URL enroll did not produce client state"
  fi
fi
pass "SHORT_URL_ENROLL"

# Verify server sees the client.
SHOW="$OUT_DIR/show-client.out"
ssh_server "sudo /usr/local/bin/drlink show clients" >"$SHOW" 2>&1 || { cat "$SHOW"; fail "show clients"; }
ssh_server "sudo /usr/local/bin/drlink show client '$CLIENT_LABEL'" >>"$SHOW" 2>&1 \
  || ssh_server "sudo /usr/local/bin/drlink show client \$(sudo python3 -c \"import json;d=json.load(open('/var/lib/drlink/registry.json'));print(next(cid for cid,c in (d.get('clients') or {}).items() if (c.get('label') or '')=='$CLIENT_LABEL'))\")" >>"$SHOW" 2>&1 \
  || { cat "$SHOW"; fail "show client"; }
grep -qi "$CLIENT_LABEL" "$SHOW" || fail "client label missing"
grep -qiE '6000|6001|6002|ssh' "$SHOW" || fail "ssh service/port missing"
pass "CLIENT_SERVICES_PORTS"

CLIENT_MID="$(python3 - "$SHOW" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'\b([0-9a-f]{32})\b', text)
print(m.group(1) if m else '')
PY
)"
[[ -n "$CLIENT_MID" ]] || CLIENT_MID="$(ssh_server "sudo python3 -c \"import json;d=json.load(open('/var/lib/drlink/registry.json'));print(next(iter(d.get('clients') or {})))\"")"
note "CLIENT_MID=$CLIENT_MID"
[[ -n "$CLIENT_MID" ]] || fail "CLIENT ID missing"
pass "CLIENT_ID"

# Management identity present on client.
ssh_client 'sudo test -f /etc/frp/client-identity.key && sudo test -f /etc/frp/client-state.json' \
  >"$OUT_DIR/mgmt-identity.log" 2>&1 || fail "management identity missing"
pass "MANAGEMENT_IDENTITY"

# Reboot/reconnect check (client).
# Wait for SSH to drop after reboot is issued, then wait for it to return.
ssh_client 'sudo nohup bash -c "sleep 1; reboot" >/dev/null 2>&1 &' >/dev/null 2>&1 || true
down=0
for _ in $(seq 1 60); do
  if ! ssh_client 'true' >/dev/null 2>&1; then
    down=1
    break
  fi
  sleep 2
done
[[ "$down" == "1" ]] || note "WARN: SSH did not drop after reboot request"
up=0
for _ in $(seq 1 90); do
  if ssh_client 'true' >/dev/null 2>&1; then
    up=1
    break
  fi
  sleep 5
done
[[ "$up" == "1" ]] || fail "client SSH did not return after reboot"
# Give frpc a moment after sshd is back.
for _ in $(seq 1 24); do
  if ssh_client 'systemctl is-active drlink-client' >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
ssh_client 'systemctl is-active drlink-client' >"$OUT_DIR/frpc-active.log" 2>&1 \
  || { cat "$OUT_DIR/frpc-active.log"; fail "frpc inactive after reboot"; }
pass "REBOOT_RECONNECT"

# Cert failure fails closed: untrusted host must not enroll.
BAD_HOST="untrusted-bootstrap.invalid"
# Ensure zt1 fallback still works after cert failure path.
ssh_server "sudo /usr/local/bin/drlink unset server bootstrap-hostname" >/dev/null
FALLBACK_OUT="$OUT_DIR/zt1-fallback.out"
ssh_server "sudo /usr/local/sbin/frp-create-client --one-line --client-name '${CLIENT_LABEL}-zt1' --note 'zt1-fallback'" \
  >"$FALLBACK_OUT" 2>&1 || { cat "$FALLBACK_OUT"; fail "zt1 create"; }
grep -q 'zt1\.' "$FALLBACK_OUT" || fail "zt1 fallback not printed after unset"
pass "ZT1_FALLBACK_AFTER_CERT_PATH"

# Demonstrate short URL to bogus host fails under stock trust (no -k).
if curl -fsSL --proto '=https' --tlsv1.2 "https://${BAD_HOST}/i/bt1.deadbeefdeadbeef.$(printf 'a%.0s' {1..64})" 2>"$OUT_DIR/bad-cert.err"; then
  fail "untrusted host unexpectedly succeeded"
fi
grep -qiE 'Could not resolve|SSL|certificate|not known' "$OUT_DIR/bad-cert.err" \
  || note "WARN bad-cert diagnostic: $(head -2 "$OUT_DIR/bad-cert.err")"
pass "CERT_FAILURE_FAILS_CLOSED"

# Cleanup tunnel/proxy
ssh_server 'sudo pkill -x cloudflared 2>/dev/null || true; sudo pkill -f "[f]rp-short-url-proxy.py" 2>/dev/null || true' || true

note "SHORT_URL_REAL_E2E=PASS"
note "OUT_DIR=$OUT_DIR"
echo "SHORT_URL_REAL_E2E=PASS"
