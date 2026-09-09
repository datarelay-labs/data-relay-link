#!/usr/bin/env bash
# P2.11.1 zero-touch bootstrap: CLI, preflight, isolated end-to-end.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
ALLOC_PID=""
LISTEN_PID=""
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
frp_test_arm_cleanup

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

extract_bootstrap_ticket() {
  # Extract bt1 ticket from short zt1 package output or legacy env one-liner.
  python3 - "$1" <<'PY'
import base64, json, re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", text)
if m:
    parts = m.group(1).split('.', 1)
    padded = parts[1] + ('=' * (-len(parts[1]) % 4))
    payload = json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
    print(payload['t'])
    raise SystemExit(0)
m2 = re.search(r"FRP_BOOTSTRAP_TICKET=(?:'([^']+)'|\"([^\"]+)\"|(\S+))", text)
if not m2:
    raise SystemExit(0)
print(next(g for g in m2.groups() if g))
PY
}

chmod +x "$ROOT/tools/frp-create-client"

make_frpc() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<'EOF'
#!/bin/sh
if [ "$1" = verify ]; then
  exit 0
fi
exit 0
EOF
  chmod +x "$dest"
}

start_listener() {
  local port="$1"
  python3 - "$port" <<'PY' &
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port))
s.listen(5)
while True:
    conn, _addr = s.accept()
    conn.close()
PY
  LISTEN_PID=$!
  local i
  for i in $(seq 1 30); do
    python3 - "$port" <<'PY' && return 0
import socket, sys
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(('127.0.0.1', int(sys.argv[1])))
except Exception:
    raise SystemExit(1)
finally:
    s.close()
PY
    sleep 0.1
  done
  fail "test TCP listener did not start"
}

start_allocator() {
  local cfg="$1"
  python3 "$ROOT/server/frp-port-allocator.py" --config "$cfg" >"$WORKDIR/alloc.log" 2>&1 &
  ALLOC_PID=$!
  local i
  for i in $(seq 1 50); do
    if curl -fsS --cacert "$ALLOC_ROOT/pki/ca.crt" "https://127.0.0.1:${ALLOC_PORT}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  cat "$WORKDIR/alloc.log" >&2 || true
  fail "allocator did not start"
}

TREE="$WORKDIR/server-tree"
mkdir -p "$TREE/etc/frp-auto-deploy/pki" "$TREE/var/lib/frp-auto-deploy/enrollments" \
  "$TREE/var/lib/frp-auto-deploy/bootstrap" "$TREE/etc/frp"
python3 "$ROOT/lib/frp_pki.py" ensure \
  --pki-dir "$TREE/etc/frp-auto-deploy/pki" \
  --public-host 203.0.113.10 >/dev/null
CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$TREE/etc/frp-auto-deploy/pki/ca.crt")"
echo 'test-create-token-do-not-use' >"$TREE/etc/frp/server_token"
chmod 600 "$TREE/etc/frp/server_token"
python3 - "$TREE" <<'PY'
import json, sys
from pathlib import Path
tree = Path(sys.argv[1])
(tree / 'var/lib/frp-auto-deploy/registry.json').write_text(json.dumps({
    'schema_version': 2, 'reserved': [], 'clients': {},
}, indent=2) + '\n')
(tree / 'etc/frp-auto-deploy/config.json').write_text(json.dumps({
    'public_host': '203.0.113.10',
    'public_ip': '203.0.113.10',
    'frp_control_public_port': 8443,
    'frp_control_listen_port': 443,
    'allocator_public_url': 'https://203.0.113.10:9443/enroll',
    'tls_ca_cert': str(tree / 'etc/frp-auto-deploy/pki/ca.crt'),
    'client_installer_url': 'https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/main/dist/bootstrap-client.sh',
    'enrollments_dir': str(tree / 'var/lib/frp-auto-deploy/enrollments'),
    'bootstrap_dir': str(tree / 'var/lib/frp-auto-deploy/bootstrap'),
    'registry_file': str(tree / 'var/lib/frp-auto-deploy/registry.json'),
    'token_file': str(tree / 'etc/frp/server_token'),
}, indent=2) + '\n')
PY

CREATE="$ROOT/tools/frp-create-client"
export FRP_DEPLOY_TEST_ROOT="$TREE"

# ---------------------------------------------------------------------------
# Help / CLI validation
# ---------------------------------------------------------------------------
"$CREATE" --help >"$WORKDIR/help.out"
grep -q -- '--one-line' "$WORKDIR/help.out" || fail "help --one-line"
grep -q -- '--ssh' "$WORKDIR/help.out" || fail "help --ssh"
grep -q -- '--ssh-user' "$WORKDIR/help.out" || fail "help --ssh-user"
grep -q -- '--ssh-port' "$WORKDIR/help.out" || fail "help --ssh-port"
grep -q -- '--ttl' "$WORKDIR/help.out" || fail "help --ttl"
grep -q -- '--note' "$WORKDIR/help.out" || fail "help --note"
grep -q 'frp-create-client --one-line --ssh --note client-01' "$WORKDIR/help.out" || fail "help interactive example"
grep -q 'frp-create-client --one-line --ssh --ssh-user aella' "$WORKDIR/help.out" || fail "help explicit example"
pass "CREATE_CLIENT_HELP"

"$CREATE" --one-line --client-name inventory-only >"$WORKDIR/nosvc.out" 2>"$WORKDIR/nosvc.err"
grep -q 'sudo bash -s --' "$WORKDIR/nosvc.out" || fail "short command shape"
grep -q 'zt1.' "$WORKDIR/nosvc.out" || fail "opaque package token"
grep -q 'no service or public port' "$WORKDIR/nosvc.out" || fail "management-only explanation"
# Legacy env marker is no longer required; profile is server-side.
pass "ONE_LINE_MANAGEMENT_ONLY"

set +e
"$CREATE" --ssh-user aella >"$WORKDIR/sshu.out" 2>"$WORKDIR/sshu.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "--ssh-user without --ssh should fail"
grep -q -- '--ssh-user requires --ssh' "$WORKDIR/sshu.err" || fail "ssh-user message"
pass "SSH_USER_REQUIRES_SSH"

set +e
"$CREATE" --one-line --ssh --ssh-user aella --ssh-port 99999 >"$WORKDIR/badport.out" 2>"$WORKDIR/badport.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "invalid ssh-port should fail"
grep -qi 'invalid --ssh-port' "$WORKDIR/badport.err" || fail "ssh-port message"
pass "INVALID_SSH_PORT"

set +e
"$CREATE" --one-line --ssh --ssh-user aella --ttl 0 >"$WORKDIR/badttl.out" 2>"$WORKDIR/badttl.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "ttl 0 should fail"
grep -qi 'TTL' "$WORKDIR/badttl.err" || fail "ttl message"
pass "INVALID_TTL"

echo 'not json' >"$WORKDIR/bad.json"
set +e
"$CREATE" --one-line --services-file "$WORKDIR/bad.json" >"$WORKDIR/badsvc.out" 2>"$WORKDIR/badsvc.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "invalid services file should succeed? no"
grep -qi 'not valid JSON' "$WORKDIR/badsvc.err" || fail "services-file message"
pass "INVALID_SERVICES_FILE"

ticket_count() {
  local dir="${1:-$TREE/var/lib/frp-auto-deploy/bootstrap}"
  python3 - "$dir" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
if not path.is_dir():
    print(0)
    raise SystemExit(0)
print(sum(1 for item in path.iterdir() if item.is_file() and item.suffix == '.json'))
PY
}

ticket_ssh_user() {
  python3 - "$TREE/var/lib/frp-auto-deploy/bootstrap" <<'PY'
import json, sys
from pathlib import Path
d = Path(sys.argv[1])
files = sorted(d.glob('*.json'), key=lambda p: p.stat().st_mtime)
if not files:
    raise SystemExit('no bootstrap ticket')
for path in reversed(files):
    rec = json.loads(path.read_text())
    if str(rec.get('label') or '') != 'seoul-groupware':
        continue
    for item in rec.get('services') or []:
        if str(item.get('preset') or '').lower() == 'ssh':
            print(item.get('ssh_user') or '')
            raise SystemExit(0)
    raise SystemExit('no ssh service')
raise SystemExit('no ssh service')
PY
}

# ---------------------------------------------------------------------------
# P2.17 — interactive SSH user prompt
# ---------------------------------------------------------------------------
BEFORE_TICKETS="$(ticket_count)"
set +e
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --note client-01 \
  </dev/null >"$WORKDIR/nontty.out" 2>"$WORKDIR/nontty.err"
nontty_rc=$?
set -e
[[ "$nontty_rc" -ne 0 ]] || fail "non-TTY --one-line --ssh without --ssh-user should fail"
grep -qF -- '--ssh-user is required for non-interactive zero-touch SSH creation.' \
  "$WORKDIR/nontty.err" || fail "non-TTY ssh-user error"
[[ "$(ticket_count)" == "$BEFORE_TICKETS" ]] || fail "non-TTY created a ticket"
if grep -q 'ubuntu' "$WORKDIR/nontty.out" "$WORKDIR/nontty.err"; then
  fail "non-TTY guessed ubuntu"
fi
if grep -q 'Client SSH user' "$WORKDIR/nontty.out" "$WORKDIR/nontty.err"; then
  fail "non-TTY prompted"
fi
pass "NONINTERACTIVE_SSH_USER_REQUIRED"

BEFORE_TICKETS="$(ticket_count)"
set +e
FRP_CREATE_CLIENT_TEST_INPUT='' FRP_DEPLOY_TEST_ROOT="$TREE" \
  python3 "$CREATE" --one-line --ssh --note client-01 \
  >"$WORKDIR/eof.out" 2>"$WORKDIR/eof.err"
eof_rc=$?
set -e
[[ "$eof_rc" -ne 0 ]] || fail "EOF during SSH prompt should fail"
grep -q 'Client identification' "$WORKDIR/eof.out" || fail "EOF did not show client identification"
grep -q 'Client name:' "$WORKDIR/eof.out" || fail "EOF did not prompt client name"
[[ "$(ticket_count)" == "$BEFORE_TICKETS" ]] || fail "ticket created before input completed"
pass "TICKET_NOT_CREATED_BEFORE_INPUT"

BEFORE_TICKETS="$(ticket_count)"
FRP_CREATE_CLIENT_TEST_INPUT=$'\nseoul-groupware\n\n\naella\n\n' FRP_DEPLOY_TEST_ROOT="$TREE" \
  python3 "$CREATE" --one-line --ssh \
  >"$WORKDIR/prompt.out" 2>"$WORKDIR/prompt.err"
grep -q 'Client identification' "$WORKDIR/prompt.out" || fail "missing client identification"
grep -q 'Client name:' "$WORKDIR/prompt.out" || fail "missing client name prompt"
grep -q 'ERROR: Client name cannot be blank.' "$WORKDIR/prompt.err" \
  || fail "blank client name not rejected"
grep -q 'SSH service setup' "$WORKDIR/prompt.out" || fail "missing SSH setup heading"
grep -q 'Enter the SSH login account that already exists on the client machine.' \
  "$WORKDIR/prompt.out" || fail "missing SSH setup help"
grep -q 'Client SSH user:' "$WORKDIR/prompt.out" || fail "missing username prompt"
grep -qF 'SSH port [22]:' "$WORKDIR/prompt.out" || fail "missing port prompt"
grep -q 'ERROR: SSH username cannot be blank.' "$WORKDIR/prompt.err" \
  || fail "blank username not rejected"
grep -q 'Client configuration' "$WORKDIR/prompt.out" || fail "missing confirmation"
grep -q 'Client name : seoul-groupware' "$WORKDIR/prompt.out" || fail "confirmation client name"
grep -q 'SSH user    : aella' "$WORKDIR/prompt.out" || fail "confirmation user"
grep -q 'SSH port    : 22' "$WORKDIR/prompt.out" || fail "confirmation port"
grep -q 'Target      : 127.0.0.1:22' "$WORKDIR/prompt.out" || fail "confirmation target"
grep -q 'zt1\.' "$WORKDIR/prompt.out" || fail "generated command missing opaque package"
grep -q 'sudo bash -s --' "$WORKDIR/prompt.out" || fail "generated command missing short runner"
if grep -E 'FRP_SSH_USER=.ubuntu|Client SSH user: ubuntu|SSH user : ubuntu' \
  "$WORKDIR/prompt.out" "$WORKDIR/prompt.err"; then
  fail "prompt defaulted to ubuntu"
fi
if grep -E 'SSH user : root|Client SSH user: root' "$WORKDIR/prompt.out"; then
  fail "prompt defaulted to root"
fi
[[ "$(ticket_count)" -gt "$BEFORE_TICKETS" ]] || fail "ticket not created after input"
[[ "$(ticket_ssh_user)" == "aella" ]] || fail "entered username not stored in SSH service"
pass "SSH_USER_INTERACTIVE_PROMPT"
pass "BLANK_SSH_USER_REJECTED"
pass "SSH_USER_STORED_IN_SERVICE"
pass "FRP_SSH_USER_FROM_PROMPT"
pass "TICKET_CREATED_AFTER_INPUT"

FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user aella --note client-01 \
  >"$WORKDIR/explicit.out" 2>"$WORKDIR/explicit.err"
if grep -q 'SSH service setup' "$WORKDIR/explicit.out" "$WORKDIR/explicit.err"; then
  fail "explicit --ssh-user prompted"
fi
if grep -q 'Client SSH user:' "$WORKDIR/explicit.out" "$WORKDIR/explicit.err"; then
  fail "explicit --ssh-user asked for username"
fi
grep -q 'zt1\.' "$WORKDIR/explicit.out" || fail "explicit command missing opaque package"
[[ "$(ticket_ssh_user)" == "aella" ]] || fail "explicit --ssh-user not stored in profile"
pass "EXPLICIT_SSH_USER_NONINTERACTIVE"

# ---------------------------------------------------------------------------
# One-line command generation
# ---------------------------------------------------------------------------
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user aella --note customer-server \
  >"$WORKDIR/oneline.out"
grep -q 'short-lived one-time bootstrap ticket' "$WORKDIR/oneline.out" || fail "sensitive warning"
grep -q 'Treat the command as sensitive' "$WORKDIR/oneline.out" || fail "treat as sensitive"
if grep -q 'Enrollment Code:' "$WORKDIR/oneline.out"; then
  fail "one-line printed Enrollment Code"
fi
if grep -q 'FRP_ENROLLMENT_CODE' "$WORKDIR/oneline.out"; then
  fail "one-line leaked enrollment env"
fi
if grep -q '\\$' "$WORKDIR/oneline.out"; then
  fail "one-line used backslash continuation"
fi
CMD_LINE="$(grep -E '^curl -fsSL ' "$WORKDIR/oneline.out" | head -n1)"
[[ -n "$CMD_LINE" ]] || fail "missing curl command"
[[ "$(grep -cE '^curl -fsSL ' "$WORKDIR/oneline.out")" == "1" ]] || fail "more than one curl line"
printf '%s' "$CMD_LINE" | grep -q "sudo bash -s --" || fail "missing short package runner"
printf '%s' "$CMD_LINE" | grep -q "zt1\." || fail "missing opaque package"
printf '%s' "$CMD_LINE" | grep -q "FRP_SERVICES_JSON=" && fail "services JSON in command"
if printf '%s' "$CMD_LINE" | grep -qiE 'curl -k|curl --insecure|wget --no-check-certificate'; then
  fail "insecure TLS in zero-touch command"
fi
echo "$CMD_LINE" | python3 -c 'import sys; line=sys.stdin.read(); assert "\n" not in line.strip()' || fail "command not one line"
TICKET="$(python3 - "$WORKDIR/oneline.out" <<'PY'
import base64, json, re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", text)
if not m:
    # Legacy long form fallback
    m2 = re.search(r"FRP_BOOTSTRAP_TICKET=(?:'([^']+)'|\"([^\"]+)\"|(\S+))", text)
    if not m2:
        raise SystemExit('missing ticket')
    print(next(g for g in m2.groups() if g))
    raise SystemExit(0)
package = m.group(1)
parts = package.split('.', 1)
padded = parts[1] + ('=' * (-len(parts[1]) % 4))
payload = json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
print(payload['t'])
PY
)"
[[ "$TICKET" == bt1.* ]] || fail "ticket format $TICKET"
TID="${TICKET#bt1.}"
TID="${TID%%.*}"
TSECRET="${TICKET##*.}"
REC="$TREE/var/lib/frp-auto-deploy/bootstrap/${TID}.json"
[[ -f "$REC" ]] || fail "ticket record missing"
python3 - "$REC" "$TSECRET" <<'PY' || fail "record hash only"
import hashlib, json, sys
from pathlib import Path
rec = json.loads(Path(sys.argv[1]).read_text())
secret = sys.argv[2]
assert rec.get('secret_hash') == hashlib.sha256(secret.encode('ascii')).hexdigest()
text = json.dumps(rec)
assert secret not in text
assert 'bt1.' not in text
assert rec.get('bound_machine_id') is None
assert rec.get('services')
PY
python3 - "$TREE/var/lib/frp-auto-deploy/registry.json" <<'PY' || fail "create reserved ports"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert not state.get('clients')
assert not state.get('reserved')
PY
pass "ONE_LINE_COMMAND"
pass "BOOTSTRAP_TICKET_HASHED_AT_REST_CLI"
pass "SERVER_CREATION_NO_PORT_RESERVATION_CLI"

FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-port 2222 --ssh-user user \
  >"$WORKDIR/sshport.out"
# SSH port/user live in the server-side bootstrap profile, not the short command.
python3 - "$WORKDIR/sshport.out" "$TREE/var/lib/frp-auto-deploy/bootstrap" <<'PY' || fail "ssh-port profile"
import base64, json, re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", text)
assert m, text
package = m.group(1)
parts = package.split('.', 1)
padded = parts[1] + ('=' * (-len(parts[1]) % 4))
payload = json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
ticket = payload['t']
tid = ticket.split('.')[1]
record = json.loads((Path(sys.argv[2]) / (tid + '.json')).read_text())
services = record.get('services') or []
if isinstance(services, dict):
    ssh = services.get('ssh') or {}
else:
    ssh = next((s for s in services if isinstance(s, dict) and s.get('id') == 'ssh'), {})
assert int(ssh.get('local_port') or 0) == 2222, ssh
assert str(ssh.get('ssh_user') or '') == 'user', ssh
print('ok')
PY
pass "SSH_PORT_IN_COMMAND"

# Shell injection: allocator URL with semicolon is quoted.
python3 - "$TREE/etc/frp-auto-deploy/config.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text())
cfg['allocator_public_url'] = "https://203.0.113.10/enroll;id"
cfg['client_installer_url'] = "https://example.test/bootstrap-client.sh;uname"
path.write_text(json.dumps(cfg, indent=2) + "\n")
PY
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user aella --note "note;rm -rf /" \
  >"$WORKDIR/quoted.out"
python3 - "$WORKDIR/quoted.out" <<'PY' || fail "command injection"
import base64, json, re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"^curl -fsSL (.+) \| sudo bash -s -- (.+)$", text, re.M)
if not m:
    raise SystemExit('missing one-line command')
line = m.group(0)
if "'https://example.test/bootstrap-client.sh;uname'" not in line:
    raise SystemExit('installer URL not quoted')
# Opaque package must carry the allocator URL safely (decoded value, not shell-evaled).
pm = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", line)
if not pm:
    raise SystemExit('missing opaque package')
parts = pm.group(1).split('.', 1)
padded = parts[1] + ('=' * (-len(parts[1]) % 4))
payload = json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
if payload.get('u') != 'https://203.0.113.10/enroll;id':
    raise SystemExit('allocator URL not preserved in package')
cmd = [l for l in text.splitlines() if l.startswith('curl ')][0]
if 'rm -rf' in cmd:
    raise SystemExit('note leaked into command')
print('ok')
PY
pass "NO_SHELL_INJECTION"

# ssh_user is restricted to [A-Za-z0-9._@-]{1,32} before the command is printed.
set +e
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user "ubuntu admin" \
  >"$WORKDIR/spaceuser.out" 2>"$WORKDIR/spaceuser.err"
src=$?
set -e
[[ "$src" -ne 0 ]] || fail "ssh-user with space should fail"
grep -qi 'invalid ssh_user' "$WORKDIR/spaceuser.out" "$WORKDIR/spaceuser.err" || fail "space ssh-user error"
pass "SSH_USER_SPACES_REJECTED"

set +e
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user "o'reilly" \
  >"$WORKDIR/quoteuser.out" 2>"$WORKDIR/quoteuser.err"
qrc=$?
set -e
[[ "$qrc" -ne 0 ]] || fail "ssh-user with quote should fail"
grep -qi 'invalid ssh_user' "$WORKDIR/quoteuser.out" "$WORKDIR/quoteuser.err" || fail "quote ssh-user error"
pass "SSH_USER_QUOTE_REJECTED"

set +e
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user $'bad\nuser' \
  >"$WORKDIR/nluser.out" 2>"$WORKDIR/nluser.err"
nrc=$?
set -e
[[ "$nrc" -ne 0 ]] || fail "newline ssh-user should fail"
grep -qi 'control characters' "$WORKDIR/nluser.out" "$WORKDIR/nluser.err" || fail "newline ssh-user error"
pass "SSH_USER_NEWLINE_REJECTED"

FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user 'ubuntu.admin@host-01' \
  >"$WORKDIR/safeuser.out"
python3 - "$WORKDIR/safeuser.out" "$TREE/var/lib/frp-auto-deploy/bootstrap" <<'PY' || fail "safe ssh-user not in profile"
import base64, json, re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", text)
assert m
parts = m.group(1).split('.', 1)
padded = parts[1] + ('=' * (-len(parts[1]) % 4))
payload = json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
tid = payload['t'].split('.')[1]
record = json.loads((Path(sys.argv[2]) / (tid + '.json')).read_text())
services = record.get('services') or []
if isinstance(services, dict):
    user = (services.get('ssh') or {}).get('ssh_user')
else:
    ssh = next((s for s in services if isinstance(s, dict) and s.get('id') == 'ssh'), {})
    user = ssh.get('ssh_user')
assert user == 'ubuntu.admin@host-01', user
print('ok')
PY
pass "SSH_USER_SAFE_QUOTED"

# Restore canonical URLs for later tests.
python3 - "$TREE/etc/frp-auto-deploy/config.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text())
cfg['allocator_public_url'] = 'https://203.0.113.10:9443/enroll'
cfg['client_installer_url'] = 'https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/main/dist/bootstrap-client.sh'
path.write_text(json.dumps(cfg, indent=2) + "\n")
PY

# Missing installer URL
python3 - "$TREE/etc/frp-auto-deploy/config.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text())
cfg['client_installer_url'] = ''
path.write_text(json.dumps(cfg, indent=2) + "\n")
PY
set +e
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" --one-line --ssh --ssh-user aella >"$WORKDIR/nourl.out" 2>"$WORKDIR/nourl.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "missing installer URL should fail"
grep -qi 'installer URL' "$WORKDIR/nourl.out" "$WORKDIR/nourl.err" || fail "installer URL error"
python3 - "$TREE/etc/frp-auto-deploy/config.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text())
cfg['client_installer_url'] = 'https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/main/dist/bootstrap-client.sh'
path.write_text(json.dumps(cfg, indent=2) + "\n")
PY
pass "INSTALLER_URL_REQUIRED"

# Manual mode regression still prints Enrollment Code and no ticket.
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$CREATE" >"$WORKDIR/manual.out"
grep -q 'Enrollment Code:' "$WORKDIR/manual.out" || fail "manual enrollment header"
if grep -q 'FRP_BOOTSTRAP_TICKET' "$WORKDIR/manual.out"; then
  fail "manual mode included bootstrap ticket"
fi
if grep -q 'FRP_ZERO_TOUCH' "$WORKDIR/manual.out"; then
  fail "manual mode included zero-touch"
fi
pass "NORMAL_INTERACTIVE_REGRESSION_CREATE"

# ---------------------------------------------------------------------------
# Live allocator + client zero-touch
# ---------------------------------------------------------------------------
ALLOC_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
LISTEN_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
ALLOC_ROOT="$WORKDIR/allocator"
mkdir -p "$ALLOC_ROOT/enrollments" "$ALLOC_ROOT/bootstrap"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$ALLOC_ROOT/pki" --public-host 127.0.0.1 >/dev/null
LIVE_CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$ALLOC_ROOT/pki/ca.crt")"
python3 - "$ALLOC_ROOT" "$ALLOC_PORT" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
port = int(sys.argv[2])
pki = root / 'pki'
(root / 'server_token').write_text('test-enroll-token-do-not-use\n')
(root / 'server_token').chmod(0o600)
(root / 'registry.json').write_text(json.dumps({
    'schema_version': 2, 'reserved': [], 'clients': {},
}, indent=2) + '\n')
(root / 'config.json').write_text(json.dumps({
    'public_host': '203.0.113.10',
    'public_ip': '203.0.113.10',
    'frp_control_public_port': 8443,
    'frp_control_listen_port': 443,
    'port_start': 18300,
    'port_end': 18330,
    'listen_host': '127.0.0.1',
    'listen_port': port,
    'allocator_listen_port': port,
    'allocator_public_port': port,
    'tls_ca_cert': str(pki / 'ca.crt'),
    'tls_server_cert': str(pki / 'server.crt'),
    'tls_server_key': str(pki / 'server.key'),
    'registry_file': str(root / 'registry.json'),
    'enrollments_dir': str(root / 'enrollments'),
    'bootstrap_dir': str(root / 'bootstrap'),
    'token_file': str(root / 'server_token'),
    'client_installer_url': 'https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/main/dist/bootstrap-client.sh',
    'allocator_public_url': 'https://127.0.0.1:%s/enroll' % port,
}, indent=2) + '\n')
PY
start_allocator "$ALLOC_ROOT/config.json"
start_listener "$LISTEN_PORT"
SSH_USER="$(id -un)"

# Point create-client at the live allocator tree.
LIVE_TREE="$WORKDIR/live-server"
mkdir -p "$LIVE_TREE/etc/frp-auto-deploy" "$LIVE_TREE/var/lib/frp-auto-deploy" "$LIVE_TREE/etc/frp"
cp -a "$ALLOC_ROOT/pki" "$LIVE_TREE/etc/frp-auto-deploy/pki"
python3 - "$LIVE_TREE" "$ALLOC_PORT" "$LIVE_CA_FP" <<'PY'
import json, sys
from pathlib import Path
tree = Path(sys.argv[1])
port = int(sys.argv[2])
(tree / 'etc/frp-auto-deploy/config.json').write_text(json.dumps({
    'public_host': '203.0.113.10',
    'public_ip': '203.0.113.10',
    'frp_control_public_port': 8443,
    'frp_control_listen_port': 443,
    'allocator_public_url': 'https://127.0.0.1:%s/enroll' % port,
    'tls_ca_cert': '/etc/frp-auto-deploy/pki/ca.crt',
    'tls_server_cert': '/etc/frp-auto-deploy/pki/server.crt',
    'tls_server_key': '/etc/frp-auto-deploy/pki/server.key',
    'client_installer_url': 'https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/main/dist/bootstrap-client.sh',
    'enrollments_dir': '/var/lib/frp-auto-deploy/enrollments',
    'bootstrap_dir': '/var/lib/frp-auto-deploy/bootstrap',
    'registry_file': '/var/lib/frp-auto-deploy/registry.json',
    'token_file': '/etc/frp/server_token',
}, indent=2) + '\n')
PY
ln -sfn "$ALLOC_ROOT/enrollments" "$LIVE_TREE/var/lib/frp-auto-deploy/enrollments"
ln -sfn "$ALLOC_ROOT/bootstrap" "$LIVE_TREE/var/lib/frp-auto-deploy/bootstrap"
ln -sfn "$ALLOC_ROOT/registry.json" "$LIVE_TREE/var/lib/frp-auto-deploy/registry.json"
ln -sfn "$ALLOC_ROOT/server_token" "$LIVE_TREE/etc/frp/server_token"

issue_ticket() {
  FRP_DEPLOY_TEST_ROOT="$LIVE_TREE" python3 "$CREATE" --one-line --ssh --ssh-user "$SSH_USER" --ssh-port "$LISTEN_PORT" --note customer-01
}

issue_ticket >"$WORKDIR/live-create.out"
LIVE_TICKET="$(extract_bootstrap_ticket "$WORKDIR/live-create.out")"
[[ -n "$LIVE_TICKET" ]] || fail "live ticket missing"

CLIENT="$WORKDIR/client"
mkdir -p "$CLIENT/etc/frp" "$CLIENT/usr/local/bin" "$CLIENT/usr/local/lib/frp-auto-deploy"
make_frpc "$CLIENT/usr/local/bin/frpc"

run_zero_touch() {
  local tree="$1" ticket="$2" machine="$3" out="$4"
  mkdir -p "$tree/etc/frp" "$tree/usr/local/bin" "$tree/usr/local/lib/frp-auto-deploy"
  make_frpc "$tree/usr/local/bin/frpc"
  export FRP_CLIENT_TEST_ROOT="$tree"
  export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
  export FRP_SKIP_DOWNLOAD=1
  export FRP_SKIP_SYSTEMD=1
  export FRP_TEST_HOSTNAME='zt-host'
  export FRP_TEST_MACHINE_ID="$machine"
  export FRP_ALLOCATOR_URL="https://127.0.0.1:${ALLOC_PORT}/enroll"
  export FRP_ALLOCATOR_CA_SHA256="$LIVE_CA_FP"
  export FRP_BOOTSTRAP_TICKET="$ticket"
  export FRP_ZERO_TOUCH=1
  export FRP_SSH_USER="$SSH_USER"
  export FRP_SSH_PORT="$LISTEN_PORT"
  export FRP_CLIENT_SOURCED=1
  export FRP_CLIENT_HOOK_LOG="${out}.hook"
  : >"$FRP_CLIENT_HOOK_LOG"
  unset FRP_ENROLLMENT_CODE FRP_SERVICES_JSON FRP_CLIENT_TEST_INPUT || true
  # shellcheck source=../install-client.sh
  . "$ROOT/install-client.sh"
  set +e
  frp_client_main >"$out" 2>"${out%.out}.err" </dev/null
  rc=$?
  set -e
  return "$rc"
}

if ! run_zero_touch "$CLIENT" "$LIVE_TICKET" 'aabbccddeeff00112233445566778899' "$WORKDIR/zt.out"; then
  cat "$WORKDIR/zt.out" "$WORKDIR/zt.err" >&2
  fail "zero-touch e2e"
fi
grep -q 'FRP client setup complete' "$WORKDIR/zt.out" || fail "success message"
grep -q 'SSH tunnel ready' "$WORKDIR/zt.out" || fail "ssh ready"
grep -q 'ssh -p 18300' "$WORKDIR/zt.out" || fail "public ssh port"
grep -q "${SSH_USER}@203.0.113.10" "$WORKDIR/zt.out" || fail "public ssh user/host"
if grep -q 'Enrollment Code:' "$WORKDIR/zt.out" "$WORKDIR/zt.err"; then
  fail "zero-touch prompted for enrollment"
fi
if grep -q 'Continue?' "$WORKDIR/zt.out" "$WORKDIR/zt.err"; then
  fail "zero-touch confirmation prompt"
fi
if grep -q 'Configured services' "$WORKDIR/zt.out"; then
  fail "zero-touch service menu"
fi
grep -q bootstrap_redeem "$WORKDIR/zt.out.hook" || fail "redeem not logged in hook"
python3 - "$CLIENT" "$LIVE_TICKET" <<'PY' || fail "ticket persisted on client"
import sys
from pathlib import Path
root = Path(sys.argv[1])
ticket = sys.argv[2]
secret = ticket.split('.')[-1]
hits = []
for path in root.rglob('*'):
    if not path.is_file():
        continue
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        continue
    if ticket in text or secret in text:
        hits.append(str(path))
if hits:
    raise SystemExit('ticket found in %s' % hits)
PY
python3 - "$ALLOC_ROOT/registry.json" <<'PY' || fail "registry reservation"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
client = next(iter(state['clients'].values()))
assert client['services']['ssh']['remote_port'] == 18300
assert client.get('note') == 'customer-01'
PY
FRP_DEPLOY_TEST_ROOT="$LIVE_TREE" python3 "$ROOT/tools/frp-client-info" zt-host >"$WORKDIR/info.out"
FRP_DEPLOY_TEST_ROOT="$LIVE_TREE" python3 "$ROOT/tools/frp-client-info" zt-host services >"$WORKDIR/info-svc.out"
grep -q '203.0.113.10:18300' "$WORKDIR/info-svc.out" || fail "client-info public endpoint"
grep -q "ssh -p 18300 ${SSH_USER}@203.0.113.10" "$WORKDIR/info-svc.out" || fail "client-info ssh connect"
grep -q 'Description    : customer-01' "$WORKDIR/info.out" || fail "client-info note"
if grep -q '127.0.0.1:18300' "$WORKDIR/info.out"; then
  fail "internal listener in connection info"
fi
pass "ZERO_TOUCH_END_TO_END"
pass "ZERO_TOUCH_NO_PROMPTS"
pass "ZERO_TOUCH_SSH"
pass "SSH_CONNECTION_INFO_PUBLIC_ENDPOINT"
pass "BOOTSTRAP_TICKET_NOT_PERSISTED_CLIENT"

# Allocator log has redeem path, not raw ticket.
if grep -F "$LIVE_TICKET" "$WORKDIR/alloc.log"; then
  fail "ticket logged"
fi
if grep -F "$TSECRET" "$WORKDIR/alloc.log" 2>/dev/null; then
  :
fi
SECRET_PART="${LIVE_TICKET##*.}"
if grep -F "$SECRET_PART" "$WORKDIR/alloc.log"; then
  fail "ticket secret in allocator log"
fi
grep -q '/bootstrap/redeem' "$WORKDIR/alloc.log" || fail "redeem path not logged"
pass "BOOTSTRAP_REDEEM_NOT_IN_URL"
pass "BOOTSTRAP_TICKET_NOT_LOGGED"

# Already installed refuses without redeem.
CLIENT2="$WORKDIR/client-again"
mkdir -p "$CLIENT2/etc/frp"
cp -a "$CLIENT/." "$CLIENT2/"
HOOK_BEFORE="$(wc -c <"$WORKDIR/zt.out.hook")"
if run_zero_touch "$CLIENT2" "$LIVE_TICKET" 'aabbccddeeff00112233445566778899' "$WORKDIR/again.out"; then
  fail "existing install should refuse"
fi
grep -q 'This client is already installed' "$WORKDIR/again.err" || fail "already installed message"
grep -q 'drlink update' "$WORKDIR/again.err" || fail "already installed update hint"
if grep -q bootstrap_redeem "$WORKDIR/again.out.hook"; then
  fail "existing install redeemed ticket"
fi
pass "EXISTING_CLIENT_REENROLL_PROTECTION"

# Same-machine retry before enrollment completion is covered by Python tests
# (REDEEM_RETRY_BEFORE_ENROLL). After enrollment succeeds the ticket is consumed.
RETRY="$WORKDIR/client-retry"
issue_ticket >"$WORKDIR/retry-create.out"
RETRY_TICKET="$(extract_bootstrap_ticket "$WORKDIR/retry-create.out")"
if ! run_zero_touch "$RETRY" "$RETRY_TICKET" 'ccddeeff00112233445566778899aa' "$WORKDIR/retry1.out"; then
  cat "$WORKDIR/retry1.out" "$WORKDIR/retry1.err" >&2
  fail "retry first run"
fi
PORT_BEFORE="$(python3 -c 'import json; print(json.load(open("'"$ALLOC_ROOT"'/registry.json"))["clients"]["ccddeeff00112233445566778899aa"]["services"]["ssh"]["remote_port"])')"
rm -rf "$RETRY"
if run_zero_touch "$RETRY" "$RETRY_TICKET" 'ccddeeff00112233445566778899aa' "$WORKDIR/retry2.out"; then
  fail "post-success ticket reuse should fail"
fi
grep -q 'BOOTSTRAP_TICKET_USED' "$WORKDIR/retry2.out" "$WORKDIR/retry2.err" \
  || fail "post-success reuse class"
PORT_AFTER="$(python3 -c 'import json; print(json.load(open("'"$ALLOC_ROOT"'/registry.json"))["clients"]["ccddeeff00112233445566778899aa"]["services"]["ssh"]["remote_port"])')"
[[ "$PORT_BEFORE" == "$PORT_AFTER" ]] || fail "failed reuse mutated port"
pass "REDEEM_AFTER_SUCCESS_REJECTED"
pass "SAME_MACHINE_POST_SUCCESS_REJECTED"

# Second machine rejected (post-success → USED; bind-before-enroll BOUND is in Python tests).
OTHER="$WORKDIR/client-other"
if run_zero_touch "$OTHER" "$RETRY_TICKET" 'ffffffffffffffffffffffffffffffff' "$WORKDIR/other.out"; then
  fail "second machine should fail"
fi
grep -qE 'BOOTSTRAP_TICKET_(USED|BOUND)' "$WORKDIR/other.out" "$WORKDIR/other.err" \
  || fail "second-machine reject class"
python3 - "$ALLOC_ROOT/registry.json" <<'PY' || fail "second machine created client"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert 'ffffffffffffffffffffffffffffffff' not in state['clients']
PY
pass "SECOND_MACHINE_REJECTED"

# Bound-but-not-completed: redeem only via HTTPS, then a different machine must get BOUND.
issue_ticket >"$WORKDIR/bound-create.out"
BOUND_TICKET="$(extract_bootstrap_ticket "$WORKDIR/bound-create.out")"
python3 - "$ALLOC_PORT" "$LIVE_CA_FP" "$BOUND_TICKET" "$ALLOC_ROOT/pki/ca.crt" <<'PY'
import json, ssl, sys, urllib.request
port, fp, ticket, ca = sys.argv[1:5]
body = json.dumps({
    'ticket': ticket,
    'machine_id': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'hostname': 'bound-host',
}).encode()
ctx = ssl.create_default_context(cafile=ca)
req = urllib.request.Request(
    'https://127.0.0.1:%s/bootstrap/redeem' % port,
    data=body,
    method='POST',
    headers={'Content-Type': 'application/json'},
)
with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
    assert resp.status == 200, resp.read()
PY
BOUND_OTHER="$WORKDIR/client-bound-other"
if run_zero_touch "$BOUND_OTHER" "$BOUND_TICKET" 'cccccccccccccccccccccccccccccccc' "$WORKDIR/bound-other.out"; then
  fail "bound second machine should fail"
fi
grep -q 'BOOTSTRAP_TICKET_BOUND' "$WORKDIR/bound-other.out" "$WORKDIR/bound-other.err" \
  || fail "bound class for second machine before enroll"
pass "SECOND_MACHINE_BOUND_BEFORE_ENROLL"

# SSH user missing fails before redeem.
issue_ticket >"$WORKDIR/missuser-create.out"
MU_TICKET="$(extract_bootstrap_ticket "$WORKDIR/missuser-create.out")"
MU="$WORKDIR/client-missuser"
mkdir -p "$MU/etc/frp" "$MU/usr/local/bin"
make_frpc "$MU/usr/local/bin/frpc"
export FRP_CLIENT_TEST_ROOT="$MU"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_SKIP_DOWNLOAD=1
export FRP_SKIP_SYSTEMD=1
export FRP_TEST_HOSTNAME='miss-user'
export FRP_TEST_MACHINE_ID='11112222333344445555666677778888'
export FRP_ALLOCATOR_URL="https://127.0.0.1:${ALLOC_PORT}/enroll"
export FRP_ALLOCATOR_CA_SHA256="$LIVE_CA_FP"
export FRP_BOOTSTRAP_TICKET="$MU_TICKET"
export FRP_ZERO_TOUCH=1
export FRP_SSH_USER='frpztmissinguser'
export FRP_SSH_PORT="$LISTEN_PORT"
export FRP_CLIENT_SOURCED=1
export FRP_CLIENT_HOOK_LOG="$WORKDIR/missuser.hook"
: >"$FRP_CLIENT_HOOK_LOG"
unset FRP_ENROLLMENT_CODE FRP_SERVICES_JSON FRP_CLIENT_TEST_INPUT || true
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"
set +e
frp_client_main >"$WORKDIR/missuser.out" 2>"$WORKDIR/missuser.err" </dev/null
mu_rc=$?
set -e
[[ "$mu_rc" -ne 0 ]] || fail "missing ssh user should fail"
grep -q 'SSH_USER_NOT_FOUND' "$WORKDIR/missuser.out" "$WORKDIR/missuser.err" || fail "missing user class"
if grep -q bootstrap_redeem "$WORKDIR/missuser.hook"; then
  fail "missing user redeemed ticket"
fi
MU_ID="${MU_TICKET#bt1.}"
MU_ID="${MU_ID%%.*}"
python3 - "$ALLOC_ROOT/bootstrap/${MU_ID}.json" <<'PY' || fail "missing user bound ticket"
import json, sys
from pathlib import Path
rec = json.loads(Path(sys.argv[1]).read_text())
assert rec.get('bound_machine_id') in (None, '')
PY
pass "SSH_USER_MISSING_FAILS_BEFORE_REDEEM"
pass "CLIENT_PREFLIGHT_PRESERVED"

# SSH port closed fails before redeem.
issue_ticket >"$WORKDIR/missport-create.out"
MP_TICKET="$(extract_bootstrap_ticket "$WORKDIR/missport-create.out")"
CLOSED_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); print(p)')"
MP="$WORKDIR/client-missport"
mkdir -p "$MP/etc/frp" "$MP/usr/local/bin"
make_frpc "$MP/usr/local/bin/frpc"
export FRP_CLIENT_TEST_ROOT="$MP"
export FRP_TEST_MACHINE_ID='aaaabbbbccccddddeeeeffff00001111'
export FRP_BOOTSTRAP_TICKET="$MP_TICKET"
export FRP_ZERO_TOUCH=1
export FRP_SSH_USER="$SSH_USER"
export FRP_SSH_PORT="$CLOSED_PORT"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/missport.hook"
: >"$FRP_CLIENT_HOOK_LOG"
set +e
frp_client_main >"$WORKDIR/missport.out" 2>"$WORKDIR/missport.err" </dev/null
mp_rc=$?
set -e
[[ "$mp_rc" -ne 0 ]] || fail "closed ssh port should fail"
grep -q 'SSH_TARGET_UNAVAILABLE' "$WORKDIR/missport.out" "$WORKDIR/missport.err" || fail "closed port class"
if grep -q bootstrap_redeem "$WORKDIR/missport.hook"; then
  fail "closed port redeemed ticket"
fi
pass "SSH_TARGET_DOWN_FAILS_BEFORE_REDEEM"

# Wrong CA fingerprint fails before ticket is sent.
issue_ticket >"$WORKDIR/badca-create.out"
BC_TICKET="$(extract_bootstrap_ticket "$WORKDIR/badca-create.out")"
BC="$WORKDIR/client-badca"
mkdir -p "$BC/etc/frp" "$BC/usr/local/bin"
make_frpc "$BC/usr/local/bin/frpc"
export FRP_CLIENT_TEST_ROOT="$BC"
export FRP_TEST_MACHINE_ID='badcabadcabadcabadcabadcabadca00'
export FRP_BOOTSTRAP_TICKET="$BC_TICKET"
export FRP_ZERO_TOUCH=1
export FRP_SSH_USER="$SSH_USER"
export FRP_SSH_PORT="$LISTEN_PORT"
export FRP_ALLOCATOR_CA_SHA256='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
export FRP_CLIENT_HOOK_LOG="$WORKDIR/badca.hook"
: >"$FRP_CLIENT_HOOK_LOG"
set +e
frp_client_main >"$WORKDIR/badca.out" 2>"$WORKDIR/badca.err" </dev/null
bc_rc=$?
set -e
[[ "$bc_rc" -ne 0 ]] || fail "wrong CA should fail"
if grep -q bootstrap_redeem "$WORKDIR/badca.hook"; then
  fail "wrong CA redeemed ticket"
fi
BC_ID="${BC_TICKET#bt1.}"
BC_ID="${BC_ID%%.*}"
python3 - "$ALLOC_ROOT/bootstrap/${BC_ID}.json" <<'PY' || fail "wrong CA bound ticket"
import json, sys
from pathlib import Path
rec = json.loads(Path(sys.argv[1]).read_text())
assert rec.get('bound_machine_id') in (None, '')
PY
pass "BOOTSTRAP_TICKET_NOT_SENT_BEFORE_CA_PIN"

# HTTP allocator URL fails before ticket use.
export FRP_ALLOCATOR_URL='http://203.0.113.10:9443/enroll'
export FRP_ALLOCATOR_CA_SHA256="$LIVE_CA_FP"
export FRP_CLIENT_TEST_ROOT="$WORKDIR/client-http"
mkdir -p "$FRP_CLIENT_TEST_ROOT/etc/frp"
export FRP_BOOTSTRAP_TICKET="$BC_TICKET"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/http.hook"
: >"$FRP_CLIENT_HOOK_LOG"
set +e
(
  frp_client_main
) >"$WORKDIR/http.out" 2>"$WORKDIR/http.err" </dev/null
http_rc=$?
set -e
[[ "$http_rc" -ne 0 ]] || fail "http allocator should fail"
grep -qi 'HTTPS is required' "$WORKDIR/http.err" "$WORKDIR/http.out" || fail "http error"
if grep -q bootstrap_redeem "$WORKDIR/http.hook"; then
  fail "http redeemed ticket"
fi
pass "HTTP_ALLOCATOR_REJECTED"

# Partial install refuses before redeem.
export FRP_ALLOCATOR_URL="https://127.0.0.1:${ALLOC_PORT}/enroll"
PARTIAL="$WORKDIR/client-partial"
mkdir -p "$PARTIAL/etc/systemd/system" "$PARTIAL/etc/frp"
echo '[Unit]' >"$PARTIAL/etc/systemd/system/frpc.service"
export FRP_CLIENT_TEST_ROOT="$PARTIAL"
export FRP_BOOTSTRAP_TICKET="$BC_TICKET"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/partial.hook"
: >"$FRP_CLIENT_HOOK_LOG"
set +e
frp_client_main >"$WORKDIR/partial.out" 2>"$WORKDIR/partial.err" </dev/null
part_rc=$?
set -e
[[ "$part_rc" -ne 0 ]] || fail "partial install should fail"
grep -q 'RECOVERY_REQUIRED' "$WORKDIR/partial.out" "$WORKDIR/partial.err" || fail "partial class"
if grep -q bootstrap_redeem "$WORKDIR/partial.hook"; then
  fail "partial redeemed ticket"
fi
pass "PARTIAL_CLIENT_RECOVERY_PROTECTION"

# Expired ticket via client.
EXP="$WORKDIR/client-exp"
issue_ticket >"$WORKDIR/exp-create.out"
EXP_TICKET="$(extract_bootstrap_ticket "$WORKDIR/exp-create.out")"
EXP_ID="${EXP_TICKET#bt1.}"
EXP_ID="${EXP_ID%%.*}"
python3 - "$ALLOC_ROOT/bootstrap/${EXP_ID}.json" "$ALLOC_ROOT/enrollments" <<'PY'
import json, sys, time
from pathlib import Path
path = Path(sys.argv[1])
rec = json.loads(path.read_text())
rec['expires_at'] = int(time.time()) - 10
path.write_text(json.dumps(rec, indent=2) + '\n')
enroll_id = rec['enrollment_id']
ep = Path(sys.argv[2]) / (enroll_id + '.json')
en = json.loads(ep.read_text())
en['expires_at'] = rec['expires_at']
ep.write_text(json.dumps(en, indent=2) + '\n')
PY
mkdir -p "$EXP/etc/frp" "$EXP/usr/local/bin"
make_frpc "$EXP/usr/local/bin/frpc"
export FRP_CLIENT_TEST_ROOT="$EXP"
export FRP_TEST_MACHINE_ID='eeeeffff000011112222333344445555'
export FRP_BOOTSTRAP_TICKET="$EXP_TICKET"
export FRP_ZERO_TOUCH=1
export FRP_SSH_USER="$SSH_USER"
export FRP_SSH_PORT="$LISTEN_PORT"
export FRP_ALLOCATOR_CA_SHA256="$LIVE_CA_FP"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/exp.hook"
: >"$FRP_CLIENT_HOOK_LOG"
set +e
frp_client_main >"$WORKDIR/exp.out" 2>"$WORKDIR/exp.err" </dev/null
exp_rc=$?
set -e
[[ "$exp_rc" -ne 0 ]] || fail "expired ticket should fail"
grep -q 'BOOTSTRAP_TICKET_EXPIRED' "$WORKDIR/exp.out" "$WORKDIR/exp.err" || fail "expired class"
pass "COMMAND_AFTER_EXPIRY"

# Redeem uses verified HTTPS: source review.
python3 - "$ROOT/lib/frp-client-common.sh" <<'PY' || fail "redeem https source"
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text(encoding='utf-8')
idx = text.find('frp_redeem_bootstrap_ticket()')
if idx < 0:
    raise SystemExit('missing redeem helper')
end = text.find('\nfrp_', idx + 10)
# next top-level after redeem may be enroll
fn = text[idx:]
if 'frp_allocator_curl' not in fn.split('frp_enroll_services', 1)[0]:
    raise SystemExit('redeem does not use verified helper')
chunk = fn.split('frp_enroll_services', 1)[0]
if '--insecure' in chunk or re.search(r'(^|[\s])-k([\s]|$)', chunk):
    raise SystemExit('redeem uses insecure curl')
if '/bootstrap/redeem' not in chunk:
    raise SystemExit('redeem missing endpoint')
print('ok')
PY
pass "BOOTSTRAP_REDEEM_HTTPS_VERIFIED"

# Doctor reports ticket count without printing secrets.
export FRP_DOCTOR_SKIP_NETWORK=1
export FRP_DOCTOR_PY="$ROOT/lib/frp_doctor.py"
mkdir -p "$LIVE_TREE/usr/local/sbin" "$LIVE_TREE/usr/local/bin" "$LIVE_TREE/usr/local/lib/frp-auto-deploy"
touch "$LIVE_TREE/usr/local/sbin/frp-create-client"
chmod +x "$LIVE_TREE/usr/local/sbin/frp-create-client"
python3 "$ROOT/lib/frp_doctor.py" --root "$LIVE_TREE" --format json --skip-network >"$WORKDIR/doctor.json" || true
python3 - "$WORKDIR/doctor.json" "$LIVE_TICKET" <<'PY' || fail "doctor leaked ticket"
import json, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
ticket = sys.argv[2]
assert ticket not in text
assert ticket.split('.')[-1] not in text
data = json.loads(text)
ids = [c['id'] for c in data.get('checks') or []]
# Role may be server-ish depending on files present.
print('ok')
PY
pass "DOCTOR_NO_TICKET_SECRET"

echo
echo "ZERO_TOUCH_BOOTSTRAP_TEST=PASS"
