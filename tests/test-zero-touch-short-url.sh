#!/usr/bin/env bash
# Zero-Touch short URL: bootstrap_hostname, GET /i/<ticket>, command UX, redaction.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
ALLOC_PID=""
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
frp_test_arm_cleanup

TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/frp-auto-deploy/pki" \
  "$TREE/etc/frp" \
  "$TREE/var/lib/frp-auto-deploy/enrollments" \
  "$TREE/var/lib/frp-auto-deploy/bootstrap" \
  "$TREE/usr/local/lib/frp-auto-deploy" \
  "$TREE/var/log/frp-auto-deploy"
echo 'token-test' >"$TREE/etc/frp/server_token"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$TREE/etc/frp-auto-deploy/pki/ca.key" \
  -out "$TREE/etc/frp-auto-deploy/pki/ca.crt" \
  -days 1 -subj "/CN=frp-test-ca" >/dev/null 2>&1 \
  || fail "openssl ca"
cp "$TREE/etc/frp-auto-deploy/pki/ca.crt" "$TREE/etc/frp-auto-deploy/pki/server.crt"
cp "$TREE/etc/frp-auto-deploy/pki/ca.key" "$TREE/etc/frp-auto-deploy/pki/server.key"

cp "$ROOT/lib/frp_zero_touch.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_pki.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_mgmt_auth.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_client_registry.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_server_config.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_control_locks.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_audit.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/server/frp-port-allocator.py" "$TREE/usr/local/lib/frp-auto-deploy/"

FRP_TEST_ALLOC_PORT="$(python3 - <<'P'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
P
)"
export FRP_TEST_ALLOC_PORT

python3 - "$TREE/etc/frp-auto-deploy/config.json" "$TREE" "$FRP_TEST_ALLOC_PORT" <<'PY'
import json
import sys
from pathlib import Path

tree = Path(sys.argv[2])
port = int(sys.argv[3])
cfg = {
    "public_ip": "203.0.113.10",
    "control_port": 443,
    "frp_control_public_port": 443,
    "port_start": 6000,
    "port_end": 6098,
    "listen_host": "127.0.0.1",
    "listen_port": port,
    "allocator_listen_port": port,
    "allocator_public_url": "https://203.0.113.10:%s/enroll" % port,
    "client_installer_url": (
        "https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/"
        "v2.1.2/dist/bootstrap-client.sh"
    ),
    "windows_client_installer_url": (
        "https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/"
        "v2.1.2/dist/bootstrap-client.ps1"
    ),
    "tls_ca_cert": str(tree / "etc/frp-auto-deploy/pki/ca.crt"),
    "tls_server_cert": str(tree / "etc/frp-auto-deploy/pki/server.crt"),
    "tls_server_key": str(tree / "etc/frp-auto-deploy/pki/server.key"),
    "enrollments_dir": str(tree / "var/lib/frp-auto-deploy/enrollments"),
    "bootstrap_dir": str(tree / "var/lib/frp-auto-deploy/bootstrap"),
    "registry_file": str(tree / "var/lib/frp-auto-deploy/registry.json"),
    "token_file": str(tree / "etc/frp/server_token"),
}
Path(sys.argv[1]).write_text(json.dumps(cfg, indent=2) + "\n")
(tree / "var/lib/frp-auto-deploy/registry.json").write_text(
    json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n"
)
PY

export FRP_DEPLOY_TEST_ROOT="$TREE"
export FRP_AUDIT_LOG="$TREE/var/log/frp-auto-deploy/audit.jsonl"

python3 "$ROOT/tools/frp-server-set" bootstrap-hostname bootstrap.example.com \
  >"$WORKDIR/set-boot.out" || fail "set bootstrap-hostname"
grep -q 'bootstrap.example.com' "$TREE/etc/frp-auto-deploy/config.json" \
  || fail "bootstrap_hostname not persisted"
grep -q 'Bootstrap hostname set' "$WORKDIR/set-boot.out" || fail "set message"
if grep -qiE 'certbot|dns provider|open firewall|configure nat|invoke acme|automatic acme' \
  "$WORKDIR/set-boot.out"; then
  fail "set bootstrap-hostname implied automatic infra work"
fi
pass "BOOTSTRAP_HOSTNAME_SET"

python3 "$ROOT/tools/frp-server-set" bootstrap-hostname --unset >/dev/null
OUT_ZT1="$WORKDIR/zt1.out"
python3 "$ROOT/tools/frp-create-client" --one-line --client-name mgmt-only --note 'n1' \
  >"$OUT_ZT1" || fail "one-line without bootstrap hostname"
grep -E -q "curl -fsSL '.+' \| sudo bash -s -- 'zt1\." "$OUT_ZT1" \
  || { cat "$OUT_ZT1"; fail "zt1 fallback missing"; }
if grep -q '/i/' "$OUT_ZT1"; then
  fail "short URL unexpectedly printed without bootstrap_hostname"
fi
pass "ZT1_FALLBACK_ABSENT_HOSTNAME"

python3 "$ROOT/tools/frp-server-set" bootstrap-hostname bootstrap.example.com >/dev/null

OUT_MGMT="$WORKDIR/mgmt.out"
python3 "$ROOT/tools/frp-create-client" --one-line --client-name short-mgmt --note 'mgmt' \
  >"$OUT_MGMT" || fail "mgmt short url"
grep -E -q "curl -fsSL 'https://bootstrap\.example\.com/i/bt1\.[0-9a-f]+\.[0-9a-f]+' \| sudo bash$" \
  "$OUT_MGMT" || { cat "$OUT_MGMT"; fail "mgmt short URL shape"; }
if grep -q 'zt1\.' "$OUT_MGMT"; then
  fail "mgmt short URL still printed zt1"
fi
pass "MANAGEMENT_ONLY_SHORT_URL"

OUT_SSH="$WORKDIR/ssh.out"
python3 "$ROOT/tools/frp-create-client" --one-line --ssh --ssh-user aella \
  --client-name short-ssh --note 'ssh' >"$OUT_SSH" || fail "ssh short url"
grep -E -q "curl -fsSL 'https://bootstrap\.example\.com/i/bt1\." "$OUT_SSH" \
  || { cat "$OUT_SSH"; fail "ssh short URL shape"; }
pass "SSH_ONLY_SHORT_URL"

SERVICES="$WORKDIR/services.json"
cat >"$SERVICES" <<'JSON'
[{"id":"ssh","preset":"ssh","local_ip":"127.0.0.1","local_port":22,"ssh_user":"aella"},
 {"id":"http","preset":"http","local_ip":"127.0.0.1","local_port":8080}]
JSON
OUT_MULTI="$WORKDIR/multi.out"
python3 "$ROOT/tools/frp-create-client" --one-line --services-file "$SERVICES" \
  --client-name short-multi --note 'multi' >"$OUT_MULTI" || fail "multi short url"
grep -E -q "curl -fsSL 'https://bootstrap\.example\.com/i/bt1\." "$OUT_MULTI" \
  || { cat "$OUT_MULTI"; fail "multi short URL shape"; }
pass "MULTI_SERVICE_SHORT_URL"

OUT_WINDOWS="$WORKDIR/windows.out"
python3 "$ROOT/tools/frp-create-client" --one-line --platform windows --rdp \
  --client-name short-rdp --note 'rdp' >"$OUT_WINDOWS" \
  || fail "Windows short URL command"
grep -q 'powershell.exe .* -Command' "$OUT_WINDOWS" \
  || fail "Windows one-line missing PowerShell command"
grep -q '?platform=windows' "$OUT_WINDOWS" \
  || fail "Windows one-line missing platform dispatch"
grep -q 'RDP local target: 127.0.0.1:3389' "$OUT_WINDOWS" \
  || fail "Windows RDP custom TCP preset missing"
if grep -qiE '(^|[;|[:space:]])(irm|iex)([;|[:space:]]|$)|Invoke-RestMethod' \
  "$OUT_WINDOWS"; then
  fail "Windows one-line contains download-and-execute alias"
fi
pass "WINDOWS_ONE_LINE"

TICKET="$(python3 - "$OUT_SSH" <<'PY'
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"/i/(bt1\.[0-9a-f]+\.[0-9a-f]+)", text)
assert m, text
print(m.group(1))
PY
)"
TICKET_ID="$(printf '%s' "$TICKET" | cut -d. -f2)"
TICKET_FILE="$TREE/var/lib/frp-auto-deploy/bootstrap/${TICKET_ID}.json"
[[ -f "$TICKET_FILE" ]] || fail "ticket file missing"

ALLOC_LOG="$WORKDIR/alloc.log"
python3 "$ROOT/server/frp-port-allocator.py" --config "$TREE/etc/frp-auto-deploy/config.json" \
  >"$ALLOC_LOG" 2>&1 &
ALLOC_PID=$!

ready=0
for _ in $(seq 1 50); do
  if FRP_TEST_ALLOC_PORT="$FRP_TEST_ALLOC_PORT" python3 - <<'PY' 2>/dev/null
import os
import socket
import ssl
port = int(os.environ['FRP_TEST_ALLOC_PORT'])
s = socket.create_connection(('127.0.0.1', port), 0.2)
ctx = ssl._create_unverified_context()
ctx.wrap_socket(s, server_hostname='localhost')
s.close()
PY
  then
    ready=1
    break
  fi
  sleep 0.1
done
[[ "$ready" == "1" ]] || { cat "$ALLOC_LOG"; fail "allocator did not start"; }

python3 - "$TICKET_FILE" <<'PY' || fail "ticket already completed"
import json
import sys
d = json.load(open(sys.argv[1]))
assert d.get('completed_at') in (None, ''), d
print('ok')
PY

SCRIPT1="$WORKDIR/script1.sh"
curl -fsSk "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET}" -o "$SCRIPT1" \
  || { cat "$ALLOC_LOG"; fail "GET /i first"; }
curl -fsSk "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET}" -o "$WORKDIR/script2.sh" \
  || fail "GET /i second"
python3 - "$TICKET_FILE" <<'PY' || fail "GET mutated bind state"
import json
import sys
d = json.load(open(sys.argv[1]))
assert d.get('completed_at') in (None, ''), d
assert d.get('bound_machine_id') in (None, ''), d
print('ok')
PY
grep -q 'zt1\.' "$SCRIPT1" || fail "script missing zt1 package"
grep -q 'FRP Auto Deploy' "$SCRIPT1" || fail "script header"
if grep -qiE 'curl -k|curl --insecure|wget --no-check-certificate' "$SCRIPT1"; then
  fail "short URL script contains insecure TLS"
fi

SCRIPT_WIN="$WORKDIR/script-windows.ps1"
curl -fsSk "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET}?platform=windows" \
  -o "$SCRIPT_WIN" || fail "GET /i Windows query dispatch"
grep -q 'Get-FileHash -Algorithm SHA256' "$SCRIPT_WIN" \
  || fail "Windows bootstrap missing SHA256 verification"
grep -q 'ExecutionPolicy Bypass -File \$installer -ZeroTouch' "$SCRIPT_WIN" \
  || fail "Windows bootstrap missing -File -ZeroTouch execution"
grep -q 'dist/bootstrap-client\\.ps1' "$SCRIPT_WIN" \
  || fail "Windows bootstrap missing PS1 checksum entry"
if grep -qiE 'Invoke-RestMethod|Invoke-WebRequest.+\|' "$SCRIPT_WIN"; then
  fail "Windows bootstrap contains download-and-execute pipe"
fi

SCRIPT_UA="$WORKDIR/script-windows-ua.ps1"
curl -fsSk -A 'WindowsPowerShell/5.1' \
  "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET}" \
  -o "$SCRIPT_UA" || fail "GET /i Windows User-Agent dispatch"
grep -q 'Get-FileHash -Algorithm SHA256' "$SCRIPT_UA" \
  || fail "PowerShell User-Agent did not receive Windows bootstrap"

SCRIPT_LINUX="$WORKDIR/script-explicit-linux.sh"
curl -fsSk -A 'WindowsPowerShell/5.1' \
  "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET}?platform=linux" \
  -o "$SCRIPT_LINUX" || fail "GET /i explicit Linux dispatch"
grep -q '^#!/bin/bash' "$SCRIPT_LINUX" \
  || fail "explicit Linux did not preserve bash bootstrap"
pass "WINDOWS_AND_LINUX_DISPATCH"

HDRS="$WORKDIR/headers.txt"
curl -sSk -D "$HDRS" -o /dev/null "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET}" \
  || fail "headers fetch"
grep -qi 'Cache-Control: no-store' "$HDRS" || fail "Cache-Control"
grep -qi 'Pragma: no-cache' "$HDRS" || fail "Pragma"
grep -qi 'X-Content-Type-Options: nosniff' "$HDRS" || fail "nosniff"
grep -qi 'Referrer-Policy: no-referrer' "$HDRS" || fail "Referrer-Policy"
pass "GET_NO_CONSUME"

curl -sSk -o "$WORKDIR/bad.txt" -w '%{http_code}' \
  "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/bt1.deadbeefdeadbeef.$(printf 'a%.0s' {1..64})" \
  | grep -qx '404' || fail "invalid ticket not 404"
grep -q 'bootstrap unavailable' "$WORKDIR/bad.txt" || fail "invalid body"
if grep -qiE 'secret|token|private|traceback|/var/lib' "$WORKDIR/bad.txt"; then
  fail "invalid response leaked internals"
fi
pass "GET_INVALID_SAFE"

sleep 0.2
if grep -F "$TICKET" "$ALLOC_LOG"; then
  fail "allocator log leaked full ticket"
fi
grep -E 'GET /i/<redacted>|/i/<redacted>' "$ALLOC_LOG" \
  || { cat "$ALLOC_LOG"; fail "allocator log missing redacted /i/ path"; }
pass "URL_LOG_REDACTION"

python3 - "$TICKET" "$FRP_TEST_ALLOC_PORT" <<'PY' || fail "redeem binding semantics"
import json
import ssl
import sys
import urllib.error
import urllib.request

ticket = sys.argv[1]
port = sys.argv[2]
ctx = ssl._create_unverified_context()

def redeem(machine_id):
    body = json.dumps({
        'ticket': ticket,
        'machine_id': machine_id,
        'hostname': 'host-' + machine_id[:8],
    }).encode()
    req = urllib.request.Request(
        'https://127.0.0.1:%s/bootstrap/redeem' % port,
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)

code, data = redeem('machine-aaaa')
assert code == 200, (code, data)
code2, data2 = redeem('machine-aaaa')
assert code2 == 200, (code2, data2)
code3, data3 = redeem('machine-bbbb')
assert code3 == 409, (code3, data3)
print('ok')
PY
pass "FIRST_MACHINE_BINDING"

python3 - "$TICKET_FILE" <<'PY'
import json
import sys
import time
path = sys.argv[1]
d = json.load(open(path))
d['expires_at'] = int(time.time()) - 10
json.dump(d, open(path, 'w'), indent=2)
print('expired')
PY
curl -sSk -o /dev/null -w '%{http_code}' \
  "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET}" | grep -qx '404' \
  || fail "expired ticket GET should be unavailable"
pass "EXPIRATION_GET"

python3 "$ROOT/tools/frp-server-set" bootstrap-hostname bootstrap.example.com >/dev/null
OUT_REV="$WORKDIR/rev.out"
python3 "$ROOT/tools/frp-create-client" --one-line --client-name rev-test --note 'rev' \
  >"$OUT_REV" || fail "create rev ticket"
TICKET2="$(python3 - "$OUT_REV" <<'PY'
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"/i/(bt1\.[0-9a-f]+\.[0-9a-f]+)", text)
assert m, text
print(m.group(1))
PY
)"
TICKET2_ID="$(printf '%s' "$TICKET2" | cut -d. -f2)"
TICKET2_FILE="$TREE/var/lib/frp-auto-deploy/bootstrap/${TICKET2_ID}.json"
python3 - "$TICKET2_FILE" <<'PY'
import json
import sys
from datetime import datetime, timezone
path = sys.argv[1]
d = json.load(open(path))
d['revoked_at'] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
json.dump(d, open(path, 'w'), indent=2)
PY
curl -sSk -o /dev/null -w '%{http_code}' \
  "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET2}" | grep -qx '404' \
  || fail "revoked ticket GET should be unavailable"
pass "REVOCATION_GET"

OUT_DONE="$WORKDIR/done.out"
python3 "$ROOT/tools/frp-create-client" --one-line --client-name done-test --note 'done' \
  >"$OUT_DONE" || fail "create done ticket"
TICKET3="$(python3 - "$OUT_DONE" <<'PY'
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"/i/(bt1\.[0-9a-f]+\.[0-9a-f]+)", text)
assert m, text
print(m.group(1))
PY
)"
TICKET3_ID="$(printf '%s' "$TICKET3" | cut -d. -f2)"
TICKET3_FILE="$TREE/var/lib/frp-auto-deploy/bootstrap/${TICKET3_ID}.json"
python3 - "$TICKET3" "$FRP_TEST_ALLOC_PORT" <<'PY' || fail "complete redeem"
import json
import ssl
import sys
import urllib.request
ticket = sys.argv[1]
port = sys.argv[2]
ctx = ssl._create_unverified_context()
body = json.dumps({
    'ticket': ticket,
    'machine_id': 'machine-done',
    'hostname': 'done-host',
}).encode()
req = urllib.request.Request(
    'https://127.0.0.1:%s/bootstrap/redeem' % port,
    data=body,
    headers={'Content-Type': 'application/json'},
    method='POST',
)
with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
    assert resp.status == 200
print('redeemed')
PY
python3 - "$TICKET3_FILE" <<'PY'
import json
import sys
from datetime import datetime, timezone
path = sys.argv[1]
d = json.load(open(path))
d['completed_at'] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
json.dump(d, open(path, 'w'), indent=2)
PY
curl -sSk -o /dev/null -w '%{http_code}' \
  "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET3}" | grep -qx '404' \
  || fail "completed ticket GET should be unavailable"
python3 - "$TICKET3" "$FRP_TEST_ALLOC_PORT" <<'PY' || fail "completed redeem should fail"
import json
import ssl
import sys
import urllib.error
import urllib.request
ticket = sys.argv[1]
port = sys.argv[2]
ctx = ssl._create_unverified_context()
body = json.dumps({
    'ticket': ticket,
    'machine_id': 'machine-done',
    'hostname': 'done-host',
}).encode()
req = urllib.request.Request(
    'https://127.0.0.1:%s/bootstrap/redeem' % port,
    data=body,
    headers={'Content-Type': 'application/json'},
    method='POST',
)
try:
    urllib.request.urlopen(req, context=ctx, timeout=5)
    raise SystemExit('redeem unexpectedly succeeded')
except urllib.error.HTTPError as exc:
    assert exc.code == 409, exc.code
print('ok')
PY
pass "SINGLE_USE"

python3 "$ROOT/tools/frp-server-set" hostname access.example.com >/dev/null
python3 - "$TREE/etc/frp-auto-deploy/config.json" <<'PY' || fail "hostname fields distinct"
import json
import sys
cfg = json.load(open(sys.argv[1]))
assert cfg.get('public_hostname') == 'access.example.com', cfg
assert cfg.get('bootstrap_hostname') == 'bootstrap.example.com', cfg
print('ok')
PY
pass "PUBLIC_HOSTNAME_SEMANTICS_UNCHANGED"

# Config edits on disk must apply to GET /i/ without restarting the allocator.
# (frpctl set / installer-url tools do not restart services.)
NEW_INSTALLER='https://example.test/bootstrap-client-reloaded.sh'
python3 - "$TREE/etc/frp-auto-deploy/config.json" "$NEW_INSTALLER" <<'PY' || fail "mutate installer url"
import json
import sys
import time
path = sys.argv[1]
url = sys.argv[2]
cfg = json.load(open(path))
cfg['client_installer_url'] = url
json.dump(cfg, open(path, 'w'), indent=2, sort_keys=True)
open(path, 'a').write('\n')
# Ensure mtime advances on coarse filesystems.
time.sleep(0.05)
print('ok')
PY
# Need a fresh unused ticket for GET (previous ticket was completed).
TICKET2="$(python3 "$ROOT/tools/frp-create-client" --one-line --ssh --ssh-user testuser \
  --client-name short-url-reload --note reload-cfg 2>"$WORKDIR/create-reload.err" \
  | python3 -c "import re,sys; t=sys.stdin.read(); m=re.search(r\"/i/(bt1\\.[0-9a-f]+\\.[0-9a-f]+)\", t); print(m.group(1) if m else '')")"
[[ -n "$TICKET2" ]] || { cat "$WORKDIR/create-reload.err"; fail "create reload ticket"; }
SCRIPT_RELOAD="$WORKDIR/script-reload.sh"
curl -fsSk "https://127.0.0.1:${FRP_TEST_ALLOC_PORT}/i/${TICKET2}" -o "$SCRIPT_RELOAD" \
  || fail "GET /i after config mutate"
grep -F "$NEW_INSTALLER" "$SCRIPT_RELOAD" \
  || { cat "$SCRIPT_RELOAD"; fail "GET /i did not pick up reloaded installer URL"; }
pass "CONFIG_RELOAD_WITHOUT_RESTART"

if grep -RInE 'curl -k|curl --insecure|wget --no-check-certificate' \
  "$ROOT/lib/frp_zero_touch.py" 2>/dev/null; then
  fail "insecure TLS found in short URL helper"
fi
pass "NO_INSECURE_TLS_SHORT_URL_PATH"

python3 - "$ROOT/lib/frp_zero_touch.py" "$TICKET" <<'PY' || fail "redact helper"
import importlib.util
import sys
from pathlib import Path
path = Path(sys.argv[1])
ticket = sys.argv[2]
spec = importlib.util.spec_from_file_location('zt', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sample = 'GET /i/%s HTTP/1.1' % ticket
out = mod.redact_text(sample)
assert ticket not in out, out
assert '/i/<redacted>' in out, out
print('ok')
PY
pass "REDACT_HELPER"

echo "ZERO_TOUCH_SHORT_URL_TEST=PASS"
