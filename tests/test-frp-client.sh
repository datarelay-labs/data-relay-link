#!/usr/bin/env bash
# Post-install frp-client management: state, read-only CLI, apply, rollback.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
ALLOC_PID=""
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
frp_test_arm_cleanup

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

chmod +x "$ROOT/tools/frp-client"

# shellcheck disable=SC1091
. "$ROOT/VERSION"

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

write_enrollment() {
  local dir="$1" eid="$2" secret="$3"
  python3 - "$dir" "$eid" "$secret" <<'PY'
import json, sys, time
from pathlib import Path
d, eid, secret = sys.argv[1], sys.argv[2], sys.argv[3]
now = int(time.time())
Path(d).mkdir(parents=True, exist_ok=True)
Path(d, f'{eid}.json').write_text(json.dumps({
    'id': eid,
    'secret': secret,
    'expires_at': now + 600,
    'bound_machine_id': None,
    'used_at': None,
}, indent=2) + '\n')
PY
}

ALLOC_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
ALLOC_ROOT="$WORKDIR/allocator"
mkdir -p "$ALLOC_ROOT/enrollments"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$ALLOC_ROOT/pki" --public-host 127.0.0.1 >/dev/null
CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$ALLOC_ROOT/pki/ca.crt")"
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
    'port_start': 18200,
    'port_end': 18230,
    'listen_host': '127.0.0.1',
    'listen_port': port,
    'allocator_listen_port': port,
    'allocator_public_port': port,
    'tls_ca_cert': str(pki / 'ca.crt'),
    'tls_server_cert': str(pki / 'server.crt'),
    'tls_server_key': str(pki / 'server.key'),
    'registry_file': str(root / 'registry.json'),
    'enrollments_dir': str(root / 'enrollments'),
    'token_file': str(root / 'server_token'),
}, indent=2) + '\n')
PY
start_allocator "$ALLOC_ROOT/config.json"

EID='abcdef0123456789'
SECRET='enroll-secret-abcdef0123456789abcdef0123456789ab'
write_enrollment "$ALLOC_ROOT/enrollments" "$EID" "$SECRET"

TREE="$WORKDIR/client"
mkdir -p "$TREE/etc/frp" "$TREE/usr/local/bin" "$TREE/usr/local/lib/frp-auto-deploy"
make_frpc "$TREE/usr/local/bin/frpc"

export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_SKIP_DOWNLOAD=1
export FRP_SKIP_SYSTEMD=1
export FRP_SKIP_CONNECTIVITY_CHECK=1
export FRP_TEST_HOSTNAME='dp-example'
export FRP_TEST_MACHINE_ID='aabbccddeeff00112233445566778899'
export FRP_ALLOCATOR_URL="https://127.0.0.1:${ALLOC_PORT}/enroll"
export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
export FRP_SERVICES_JSON='[{"id":"ssh","name":"SSH","protocol":"tcp","local_ip":"127.0.0.1","local_port":22,"preset":"ssh","ssh_user":"aella"}]'
export FRP_CLIENT_SOURCED=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"
frp_client_main >"$WORKDIR/install.out"

STATE="$TREE/etc/frp/client-state.json"
[[ -f "$STATE" ]] || fail "client-state.json missing after install"
mode="$(python3 - "$STATE" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
[[ "$mode" == "0o600" ]] || fail "client-state mode $mode"
python3 - "$STATE" <<'PY' || fail "client-state schema"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['schema_version']==1
assert d['allocator_url'].startswith('https://127.0.0.1:')
assert d['frp_server']=='203.0.113.10'
assert int(d['frp_server_port'])==8443
assert d['hostname']=='dp-example'
assert 'ssh' in d['services']
assert d['services']['ssh']['remote_port']==18200
assert d['services']['ssh']['enabled'] is True
assert 'token' not in json.dumps(d).lower() or 'frp_server' in d
for bad in ('token_ciphertext','enrollment_code','enrollment_secret','server_token','auth.token'):
    assert bad not in json.dumps(d)
PY
frp_state_has_secrets "$STATE" || fail "secrets in client-state"
[[ -f "$TREE/etc/frp/client-identity.key" ]] || fail "identity key missing"
[[ -f "$TREE/etc/frp/client-identity.pub" ]] || fail "identity pub missing"
[[ -f "$TREE/etc/frp/client-identity.mac" ]] || fail "identity mac missing"
ident_mode="$(python3 - "$TREE/etc/frp/client-identity.key" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
[[ "$ident_mode" == "0o600" ]] || fail "identity key mode $ident_mode"
if grep -q 'BEGIN .*PRIVATE KEY' "$STATE" "$TREE/etc/frp/access-info.txt" "$ALLOC_ROOT/registry.json"; then
  fail "private key leaked"
fi
python3 - "$ALLOC_ROOT/registry.json" "$TREE/etc/frp/client-identity.key" "$TREE/etc/frp/client-identity.mac" <<'PY' || fail "registry stores pubkey only"
import json,sys
from pathlib import Path
reg=json.loads(Path(sys.argv[1]).read_text())
priv=Path(sys.argv[2]).read_text()
text=json.dumps(reg)
assert 'PRIVATE KEY' not in text
client=next(iter(reg['clients'].values()))
assert client.get('mgmt_status')=='enrolled'
assert 'BEGIN PUBLIC KEY' in (client.get('mgmt_pubkey') or '')
assert client.get('mgmt_mac_key')
assert client['mgmt_mac_key'] not in priv
file_mac=Path(sys.argv[3]).read_text().strip()
assert file_mac==client.get('mgmt_mac_key')
PY
[[ -x "$TREE/usr/local/bin/frp-client" ]] || fail "frp-client not installed"
[[ -x "$TREE/usr/local/bin/frpctl" ]] || fail "frpctl not installed"
[[ -f "$TREE/usr/local/lib/frp-auto-deploy/frp-client-common.sh" ]] || fail "client lib not installed"
[[ -f "$TREE/usr/local/lib/frp-auto-deploy/frp_mgmt_auth.py" ]] || fail "mgmt auth helper not installed"
[[ -f "$TREE/etc/frp-auto-deploy/version" ]] || fail "client version file missing"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$TREE/etc/frp-auto-deploy/version" || fail "client project version"
grep -q 'FRP_VERSION=0.71.0' "$TREE/etc/frp-auto-deploy/version" || fail "client FRP version"
[[ -f "$TREE/etc/frp-auto-deploy/allocator-ca.crt" ]] || fail "trusted CA missing"
grep -q 'serverPort = 8443' "$TREE/etc/frp/frpc.toml" || fail "frpc must use public control port"
if grep -q 'serverPort = 443' "$TREE/etc/frp/frpc.toml"; then
  fail "frpc used internal listen port"
fi
ca_mode="$(python3 - "$TREE/etc/frp-auto-deploy/allocator-ca.crt" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
[[ "$ca_mode" == "0o644" ]] || fail "trusted CA mode $ca_mode"
pass "fresh install writes client-state"

HOOK="$WORKDIR/hook.log"
: >"$HOOK"
export FRP_CLIENT_HOOK_LOG="$HOOK"
before="$(python3 - "$TREE" <<'PY'
import hashlib, sys
from pathlib import Path
root=Path(sys.argv[1])
h=hashlib.sha256()
for p in sorted(root.rglob('*')):
    if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc':
        h.update(p.read_bytes())
print(h.hexdigest())
PY
)"
"$ROOT/tools/frp-client" status >"$WORKDIR/status.out"
"$ROOT/tools/frp-client" info >"$WORKDIR/info.out"
"$ROOT/tools/frp-client" list >"$WORKDIR/list.out"
after="$(python3 - "$TREE" <<'PY'
import hashlib, sys
from pathlib import Path
root=Path(sys.argv[1])
h=hashlib.sha256()
for p in sorted(root.rglob('*')):
    if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc':
        h.update(p.read_bytes())
print(h.hexdigest())
PY
)"
[[ "$before" == "$after" ]] || fail "read-only CLI modified files"
if grep -q 'Pending service changes exist' "$WORKDIR/list.out"; then
  fail "list should not invent pending notice without draft"
fi
# Create empty draft marker and ensure list reports it (cheap detection).
mkdir -p "$TREE/var/lib/frp-auto-deploy"
cp "$TREE/etc/frp/client-state.json" "$TREE/var/lib/frp-auto-deploy/client-draft.json"
"$ROOT/tools/frp-client" list >"$WORKDIR/list-pending.out"
grep -q 'Pending service changes exist' "$WORKDIR/list-pending.out" || fail "list pending notice"
grep -q 'service apply' "$WORKDIR/list-pending.out" || fail "list pending apply"
grep -q 'service discard' "$WORKDIR/list-pending.out" || fail "list pending discard"
rm -f "$TREE/var/lib/frp-auto-deploy/client-draft.json"
if grep -qx enroll "$HOOK"; then fail "read-only contacted allocator"; fi
if grep -qx restart "$HOOK"; then fail "read-only restarted frpc"; fi
grep -q "Project version : ${PROJECT_VERSION}" "$WORKDIR/status.out" || fail "status project version"
grep -q 'Hostname        : dp-example' "$WORKDIR/status.out" || fail "status hostname"
grep -q 'Management identity : enrolled' "$WORKDIR/status.out" || fail "status identity"
grep -q 'ssh' "$WORKDIR/status.out" || fail "status ssh"
grep -q 'FRP Server: 203.0.113.10' "$WORKDIR/info.out" || fail "info server"
grep -q 'ssh -p 18200 aella@203.0.113.10' "$WORKDIR/info.out" || fail "info ssh connect"
: >"$HOOK"
FRP_CLIENT_TEST_MENU=1 "$ROOT/tools/frp-client" >"$WORKDIR/menu.out"
grep -q 'FRP Client Management' "$WORKDIR/menu.out" || fail "menu header"
grep -q '1) Add service' "$WORKDIR/menu.out" || fail "menu add"
if grep -qx enroll "$HOOK"; then fail "menu contacted allocator"; fi
if grep -qx restart "$HOOK"; then fail "menu restarted frpc"; fi
after_menu="$(python3 - "$TREE" <<'PY'
import hashlib, sys
from pathlib import Path
root=Path(sys.argv[1])
h=hashlib.sha256()
for p in sorted(root.rglob('*')):
    if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc':
        h.update(p.read_bytes())
print(h.hexdigest())
PY
)"
[[ "$before" == "$after_menu" ]] || fail "menu modified files"
pass "read-only status/info do not mutate"

# No pending changes
: >"$HOOK"
export FRP_CLIENT_CANDIDATE="$STATE"
if ! "$ROOT/tools/frp-client" apply >"$WORKDIR/noop.out" 2>"$WORKDIR/noop.err"; then
  fail "no-change apply should succeed"
fi
grep -q 'No pending changes.' "$WORKDIR/noop.out" || fail "noop message"
if grep -qx enroll "$HOOK"; then fail "noop enrolled"; fi
if grep -qx restart "$HOOK"; then fail "noop restart"; fi
pass "no-change apply is a no-op"

# Name-only local metadata
CAND="$WORKDIR/cand-name.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['ssh']['name']='ssh'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
toml_before="$(sha256sum "$TREE/etc/frp/frpc.toml" | awk '{print $1}')"
: >"$HOOK"
unset FRP_ENROLLMENT_CODE || true
export FRP_CLIENT_CANDIDATE="$CAND"
frp_state_diff "$STATE" "$CAND" >"$WORKDIR/name-pending.out"
frp_ux_print_apply_summary "$STATE" "$CAND" >"$WORKDIR/name-summary.out"
grep -q 'Display name: SSH -> ssh' "$WORKDIR/name-pending.out" || fail "pending missing name"
grep -q 'Display name: SSH -> ssh' "$WORKDIR/name-summary.out" || fail "apply summary missing name"
if grep -A2 '^Changes:' "$WORKDIR/name-summary.out" | grep -q '(none)'; then
  fail "apply summary Changes=(none) while pending name exists"
fi
grep -q 'local connection information only' "$WORKDIR/name-summary.out" || fail "local-only apply help"
if ! "$ROOT/tools/frp-client" apply >"$WORKDIR/name.out" 2>"$WORKDIR/name.err"; then
  fail "name-only apply should succeed"
fi
grep -q 'Applied local changes.' "$WORKDIR/name.out" || fail "local apply success"
grep -q 'Allocator contacted : NO' "$WORKDIR/name.out" || fail "local apply allocator line"
grep -q 'frpc restarted      : NO' "$WORKDIR/name.out" || fail "local apply restart line"
if grep -q 'Enrollment Code' "$WORKDIR/name.out" "$WORKDIR/name.err"; then
  fail "name-only asked for Enrollment Code"
fi
if grep -qx enroll "$HOOK"; then fail "name-only enrolled"; fi
if grep -qx restart "$HOOK"; then fail "name-only restarted"; fi
toml_after="$(sha256sum "$TREE/etc/frp/frpc.toml" | awk '{print $1}')"
[[ "$toml_before" == "$toml_after" ]] || fail "name-only rewrote frpc.toml"
python3 - "$STATE" <<'PY' || fail "name-only state"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['ssh']['name']=='ssh'
assert d['services']['ssh']['remote_port']==18200
PY
grep -q 'ssh -p 18200 aella@203.0.113.10' "$TREE/etc/frp/access-info.txt" || fail "access-info after name"
pass "name-only is local metadata apply"

# ssh_user-only local metadata
CAND="$WORKDIR/cand-user.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['ssh']['ssh_user']='tester'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
toml_before="$(sha256sum "$TREE/etc/frp/frpc.toml" | awk '{print $1}')"
: >"$HOOK"
unset FRP_ENROLLMENT_CODE || true
export FRP_CLIENT_CANDIDATE="$CAND"
frp_state_diff "$STATE" "$CAND" >"$WORKDIR/user-pending.out"
frp_ux_print_apply_summary "$STATE" "$CAND" >"$WORKDIR/user-summary.out"
grep -q 'SSH user: aella -> tester' "$WORKDIR/user-pending.out" || fail "pending missing ssh_user"
grep -q 'SSH user: aella -> tester' "$WORKDIR/user-summary.out" || fail "apply summary missing ssh_user"
if ! "$ROOT/tools/frp-client" apply >"$WORKDIR/user.out" 2>"$WORKDIR/user.err"; then
  fail "ssh_user-only apply should succeed"
fi
grep -q 'Applied local changes.' "$WORKDIR/user.out" || fail "ssh_user local apply"
if grep -qx enroll "$HOOK"; then fail "ssh_user enrolled"; fi
if grep -qx restart "$HOOK"; then fail "ssh_user restarted"; fi
toml_after="$(sha256sum "$TREE/etc/frp/frpc.toml" | awk '{print $1}')"
[[ "$toml_before" == "$toml_after" ]] || fail "ssh_user-only rewrote frpc.toml"
grep -q 'ssh -p 18200 tester@203.0.113.10' "$TREE/etc/frp/access-info.txt" || fail "access-info ssh_user"
python3 - "$STATE" <<'PY' || fail "ssh_user state"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['ssh']['ssh_user']=='tester'
assert d['services']['ssh']['remote_port']==18200
PY
pass "ssh_user-only is local metadata apply"

# Add grafana
CAND="$WORKDIR/cand-add.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']={
  'id':'grafana','name':'Grafana','preset':'custom','protocol':'tcp',
  'local_ip':'127.0.0.1','local_port':3000,'enabled':True,
}
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
: >"$HOOK"
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
"$ROOT/tools/frp-client" apply >"$WORKDIR/add.out"
python3 - "$STATE" <<'PY' || fail "add service ports"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['ssh']['remote_port']==18200
assert d['services']['grafana']['remote_port']==18201
assert d['services']['grafana']['enabled'] is True
PY
grep -q 'grafana' "$TREE/etc/frp/frpc.toml" || fail "frpc.toml missing grafana"
grep -q 'name = "dp-example-aabbccdd-grafana"' "$TREE/etc/frp/frpc.toml" || fail "grafana proxy name"
grep -q 'remotePort = 18200' "$TREE/etc/frp/frpc.toml" || fail "ssh port in toml"
grep -q '203.0.113.10:18201' "$TREE/etc/frp/access-info.txt" || fail "access-info grafana"
if grep -q 'Enrollment Code' "$WORKDIR/add.out"; then
  fail "post-enroll add asked for Enrollment Code"
fi
grep -q 'existing client identity' "$WORKDIR/add.out" || fail "add should use client identity"
pass "add service preserves ssh port"

# Edit grafana target
CAND="$WORKDIR/cand-edit.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.30'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
"$ROOT/tools/frp-client" apply >"$WORKDIR/edit.out"
python3 - "$STATE" <<'PY' || fail "edit kept remote port"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['local_ip']=='10.10.20.30'
assert d['services']['grafana']['remote_port']==18201
PY
grep -q 'localIP = "10.10.20.30"' "$TREE/etc/frp/frpc.toml" || fail "toml local ip"
grep -q 'Target: 127.0.0.1:3000 -> 10.10.20.30:3000' "$WORKDIR/edit.out" || fail "edit summary missing target"
if grep -q 'Enrollment Code' "$WORKDIR/edit.out"; then
  fail "post-enroll edit asked for Enrollment Code"
fi
grep -q 'existing client identity' "$WORKDIR/edit.out" || fail "edit should use client identity"
pass "edit target preserves remote port"

# Mixed name + target is runtime
CAND="$WORKDIR/cand-mixed.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['name']='Dash'
d['services']['grafana']['local_ip']='10.10.20.31'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
: >"$HOOK"
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
frp_state_diff "$STATE" "$CAND" >"$WORKDIR/mixed-pending.out"
frp_ux_print_apply_summary "$STATE" "$CAND" >"$WORKDIR/mixed-summary.out"
grep -q 'Display name: Grafana -> Dash' "$WORKDIR/mixed-pending.out" || fail "mixed pending name"
grep -q 'Target: 10.10.20.30:3000 -> 10.10.20.31:3000' "$WORKDIR/mixed-pending.out" || fail "mixed pending target"
grep -q 'Display name: Grafana -> Dash' "$WORKDIR/mixed-summary.out" || fail "mixed summary name"
grep -q 'Target: 10.10.20.30:3000 -> 10.10.20.31:3000' "$WORKDIR/mixed-summary.out" || fail "mixed summary target"
grep -q 'will restart the FRP client' "$WORKDIR/mixed-summary.out" || fail "mixed is runtime"
"$ROOT/tools/frp-client" apply >"$WORKDIR/mixed.out"
if ! grep -qx enroll "$HOOK"; then fail "mixed did not enroll"; fi
if ! grep -qx restart "$HOOK"; then fail "mixed did not restart"; fi
python3 - "$STATE" <<'PY' || fail "mixed kept remote port"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['name']=='Dash'
assert d['services']['grafana']['local_ip']=='10.10.20.31'
assert d['services']['grafana']['remote_port']==18201
PY
grep -q 'localIP = "10.10.20.31"' "$TREE/etc/frp/frpc.toml" || fail "mixed toml ip"
pass "mixed name+target uses secured apply"

# Disable grafana
CAND="$WORKDIR/cand-disable.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['enabled']=False
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
"$ROOT/tools/frp-client" apply >"$WORKDIR/disable.out"
python3 - "$STATE" "$TREE/etc/frp/frpc.toml" "$ALLOC_ROOT/registry.json" <<'PY' || fail "disable semantics"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
toml=Path(sys.argv[2]).read_text()
reg=json.loads(Path(sys.argv[3]).read_text())
assert d['services']['grafana']['enabled'] is False
assert d['services']['grafana']['remote_port']==18201
assert 'grafana' not in toml
mid=d['machine_id']
assert reg['clients'][mid]['services']['grafana']['enabled'] is False
assert reg['clients'][mid]['services']['grafana']['remote_port']==18201
PY
if grep -q 'Enrollment Code' "$WORKDIR/disable.out"; then
  fail "post-enroll disable asked for Enrollment Code"
fi
pass "disable keeps reservation and omits proxy"

# Re-enable grafana
CAND="$WORKDIR/cand-enable.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['enabled']=True
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
"$ROOT/tools/frp-client" apply >"$WORKDIR/enable.out"
python3 - "$STATE" <<'PY' || fail "re-enable port"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['enabled'] is True
assert d['services']['grafana']['remote_port']==18201
PY
grep -q 'grafana' "$TREE/etc/frp/frpc.toml" || fail "re-enabled proxy missing"
if grep -q 'Enrollment Code' "$WORKDIR/enable.out"; then
  fail "post-enroll re-enable asked for Enrollment Code"
fi
pass "re-enable reuses the same public port"

# Last enabled service cannot be disabled
CAND="$WORKDIR/cand-last.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['ssh']['enabled']=False
d['services']['grafana']['enabled']=False
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_CANDIDATE="$CAND"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/last.out" 2>"$WORKDIR/last.err"; then
  fail "disabling last services should fail"
fi
grep -q 'at least one enabled service is required' "$WORKDIR/last.err" || fail "last-service error"
python3 - "$STATE" <<'PY' || fail "last disable mutated state"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['ssh']['enabled'] is True
PY
pass "last enabled service cannot be disabled"

# Invalid signed/auth path: bad enrollment on a legacy client
CAND="$WORKDIR/cand-bad.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.99'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
cp "$STATE" "$WORKDIR/state.before"
cp "$TREE/etc/frp/frpc.toml" "$WORKDIR/toml.before"
cp "$TREE/etc/frp/access-info.txt" "$WORKDIR/access.before"
mkdir -p "$WORKDIR/ident.bak"
cp "$TREE/etc/frp/client-identity.key" "$WORKDIR/ident.bak/"
cp "$TREE/etc/frp/client-identity.pub" "$WORKDIR/ident.bak/"
cp "$TREE/etc/frp/client-identity.mac" "$WORKDIR/ident.bak/"
rm -f "$TREE/etc/frp/client-identity.key" "$TREE/etc/frp/client-identity.pub" "$TREE/etc/frp/client-identity.mac"
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE='deadbeefdeadbeef.0000000000000000000000000000000000000000000000000000000000000000'
: >"$HOOK"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/bad.out" 2>"$WORKDIR/bad.err"; then
  fail "invalid enrollment should fail"
fi
cmp -s "$STATE" "$WORKDIR/state.before" || fail "invalid enroll changed state"
cmp -s "$TREE/etc/frp/frpc.toml" "$WORKDIR/toml.before" || fail "invalid enroll changed toml"
cmp -s "$TREE/etc/frp/access-info.txt" "$WORKDIR/access.before" || fail "invalid enroll changed access"
if grep -qx restart "$HOOK"; then fail "invalid enroll restarted"; fi
cp "$WORKDIR/ident.bak/"* "$TREE/etc/frp/"
pass "invalid enrollment leaves local config unchanged"

# Allocator unreachable
export FRP_CLIENT_HOOK_ENROLL_FAIL=1
if "$ROOT/tools/frp-client" apply >"$WORKDIR/unreach.out" 2>"$WORKDIR/unreach.err"; then
  fail "unreachable allocator should fail"
fi
unset FRP_CLIENT_HOOK_ENROLL_FAIL
cmp -s "$STATE" "$WORKDIR/state.before" || fail "unreachable allocator changed state"
pass "allocator unreachable leaves local config unchanged"

# Verify failure + compensation
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.98'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
export FRP_CLIENT_HOOK_VERIFY_FAIL=1
export FRP_CLIENT_ENROLL_COUNT_FILE="$WORKDIR/enroll.count"
echo 0 >"$FRP_CLIENT_ENROLL_COUNT_FILE"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/verify.out" 2>"$WORKDIR/verify.err"; then
  fail "verify failure should fail apply"
fi
unset FRP_CLIENT_HOOK_VERIFY_FAIL
grep -q 'LOCAL_ROLLBACK=PASS' "$WORKDIR/verify.out" "$WORKDIR/verify.err" || fail "verify local rollback"
grep -q 'SERVER_ROLLBACK=PASS' "$WORKDIR/verify.out" "$WORKDIR/verify.err" || fail "verify server compensation"
cmp -s "$STATE" "$WORKDIR/state.before" || fail "verify failure changed state"
pass "verify failure preserves config and compensates server"

# Restart failure + local rollback
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.97'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_HOOK_RESTART_FAIL=1
echo 0 >"$FRP_CLIENT_ENROLL_COUNT_FILE"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/restart.out" 2>"$WORKDIR/restart.err"; then
  fail "restart failure should fail apply"
fi
unset FRP_CLIENT_HOOK_RESTART_FAIL
grep -q 'LOCAL_ROLLBACK=PASS' "$WORKDIR/restart.out" "$WORKDIR/restart.err" || fail "restart local rollback"
grep -q 'SERVER_ROLLBACK=PASS' "$WORKDIR/restart.out" "$WORKDIR/restart.err" || fail "restart server compensation"
python3 - "$STATE" <<'PY' || fail "restart left grafana target"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['local_ip']=='10.10.20.31'
assert d['services']['grafana']['name']=='Dash'
PY
pass "restart failure restores local files"

# Proxy health failure
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.96'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_HOOK_PROXY_FAIL=1
echo 0 >"$FRP_CLIENT_ENROLL_COUNT_FILE"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/proxy.out" 2>"$WORKDIR/proxy.err"; then
  fail "proxy failure should fail apply"
fi
unset FRP_CLIENT_HOOK_PROXY_FAIL
grep -q 'LOCAL_ROLLBACK=PASS' "$WORKDIR/proxy.out" "$WORKDIR/proxy.err" || fail "proxy local rollback"
grep -q 'SERVER_ROLLBACK=PASS' "$WORKDIR/proxy.out" "$WORKDIR/proxy.err" || fail "proxy server compensation"
pass "proxy health failure restores local files"

# Compensation failure is reported
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.95'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_HOOK_VERIFY_FAIL=1
export FRP_CLIENT_HOOK_COMPENSATE_FAIL=1
echo 0 >"$FRP_CLIENT_ENROLL_COUNT_FILE"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/comp.out" 2>"$WORKDIR/comp.err"; then
  fail "compensation-fail path should fail apply"
fi
unset FRP_CLIENT_HOOK_VERIFY_FAIL FRP_CLIENT_HOOK_COMPENSATE_FAIL
grep -q 'SERVER_ROLLBACK=FAIL' "$WORKDIR/comp.out" "$WORKDIR/comp.err" || fail "compensation failure not reported"
grep -qi 'reconcile' "$WORKDIR/comp.err" || fail "compensation warning"
pass "compensation failure is reported loudly"

# Missing state
rm -f "$STATE"
if "$ROOT/tools/frp-client" status >"$WORKDIR/missing.out" 2>"$WORKDIR/missing.err"; then
  fail "missing state should fail"
fi
grep -q 'predates local management state' "$WORKDIR/missing.err" || fail "missing state message"
pass "missing pre-P2 state fails closed"

# Lock
LOCKFILE="$TREE/etc/frp/client-manage.lock"
python3 - "$WORKDIR/state.before" "$STATE" <<'PY'
import pathlib,sys
pathlib.Path(sys.argv[2]).write_bytes(pathlib.Path(sys.argv[1]).read_bytes())
PY
exec {LOCKFD}>>"$LOCKFILE"
flock -n "$LOCKFD"
export FRP_CLIENT_CANDIDATE="$CAND"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/lock.out" 2>"$WORKDIR/lock.err"; then
  flock -u "$LOCKFD"
  exec {LOCKFD}>&-
  fail "lock should block apply"
fi
grep -q 'another frp-client management operation is already running' "$WORKDIR/lock.err" || fail "lock error"
flock -u "$LOCKFD"
exec {LOCKFD}>&-
# Stale mkdir lock from a dead PID must not block forever.
rm -f "$LOCKFILE" "${LOCKFILE}.pid"
mkdir -p "$LOCKFILE"
printf '999999\n' >"$LOCKFILE/pid"
if ! "$ROOT/tools/frp-client" apply >"$WORKDIR/stale-lock.out" 2>"$WORKDIR/stale-lock.err"; then
  # candidate may be a no-op or a change; either must not fail on stale lock
  if grep -q 'another frp-client management operation is already running' "$WORKDIR/stale-lock.err"; then
    fail "stale directory lock blocked apply"
  fi
fi
pass "local management lock"

# Draft mutation commands must take the same lock; read-only status must not.
LOCKFILE="$TREE/etc/frp/client-manage.lock"
python3 - "$WORKDIR/state.before" "$STATE" <<'PY'
import pathlib,sys
pathlib.Path(sys.argv[2]).write_bytes(pathlib.Path(sys.argv[1]).read_bytes())
PY
exec {LOCKFD}>>"$LOCKFILE"
flock -n "$LOCKFD"
if "$ROOT/tools/frp-client" add-service --preset custom --id web --name Web --target-host 127.0.0.1 --target-port 8080 \
  >"$WORKDIR/add-lock.out" 2>"$WORKDIR/add-lock.err"; then
  flock -u "$LOCKFD"
  exec {LOCKFD}>&-
  fail "lock should block add-service"
fi
grep -q 'another frp-client management operation is already running' "$WORKDIR/add-lock.err" || fail "add-service lock error"
if "$ROOT/tools/frp-client" discard-pending >"$WORKDIR/disc-lock.out" 2>"$WORKDIR/disc-lock.err"; then
  flock -u "$LOCKFD"
  exec {LOCKFD}>&-
  fail "lock should block discard-pending"
fi
grep -q 'another frp-client management operation is already running' "$WORKDIR/disc-lock.err" || fail "discard lock error"
if ! "$ROOT/tools/frp-client" status >"$WORKDIR/status-lock.out" 2>"$WORKDIR/status-lock.err"; then
  flock -u "$LOCKFD"
  exec {LOCKFD}>&-
  fail "status should remain usable while a management lock is held"
fi
flock -u "$LOCKFD"
exec {LOCKFD}>&-
pass "draft mutation lock; read-only status unlocked"

# flock-based release must remove the lock file; doctor treats leftovers as stale.
rm -f "$TREE/etc/frp/client-manage.lock" "$TREE/etc/frp/client-manage.lock.pid"
rm -rf "$TREE/etc/frp/client-manage.lock"
unset FRP_CLIENT_LOCK_FD || true
frp_acquire_client_lock
lock_path="$(frp_client_lock_dir)"
[[ -e "$lock_path" || -f "${lock_path}.pid" ]] || fail "acquire did not create a lock"
frp_release_client_lock
if [[ -e "$lock_path" || -f "${lock_path}.pid" ]]; then
  fail "lock release left $lock_path"
fi
pass "lock release leaves no stale lock file"

# Existing install refuses re-enrollment via the installer
fp_before="$(python3 "$ROOT/lib/frp_mgmt_auth.py" fingerprint "$TREE/etc/frp/client-identity.pub")"
cp "$TREE/etc/frp/client-identity.key" "$WORKDIR/key.before"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
export FRP_SERVICES_JSON='[{"id":"ssh","name":"SSH","protocol":"tcp","local_ip":"127.0.0.1","local_port":22,"preset":"ssh","ssh_user":"aella"}]'
if frp_client_main >"$WORKDIR/reinstall.out" 2>"$WORKDIR/reinstall.err"; then
  fail "installer should refuse an existing client"
fi
grep -q 'already has an FRP client installed' "$WORKDIR/reinstall.err" || fail "existing-install refusal message"
grep -q 'frpctl system update' "$WORKDIR/reinstall.err" || fail "existing-install should point at upgrade"
fp_after="$(python3 "$ROOT/lib/frp_mgmt_auth.py" fingerprint "$TREE/etc/frp/client-identity.pub")"
[[ "$fp_before" == "$fp_after" ]] || fail "refused reinstall rotated identity"
cmp -s "$TREE/etc/frp/client-identity.key" "$WORKDIR/key.before" || fail "refused reinstall replaced key"
pass "installer refuses to re-enroll an existing client"

# Legacy P2 client: one-time Enrollment Code, then identity
rm -f "$TREE/etc/frp/client-identity.key" "$TREE/etc/frp/client-identity.pub" "$TREE/etc/frp/client-identity.mac"
python3 - "$STATE" "$ALLOC_ROOT/registry.json" <<'PY'
import json,sys
from pathlib import Path
reg=json.loads(Path(sys.argv[2]).read_text())
mid=json.loads(Path(sys.argv[1]).read_text())['machine_id']
client=reg['clients'][mid]
for key in ('mgmt_pubkey','mgmt_mac_key','mgmt_fingerprint','mgmt_alg','mgmt_enrolled_at','mgmt_revoked_at'):
    client.pop(key, None)
client['mgmt_status']='legacy'
Path(sys.argv[2]).write_text(json.dumps(reg, indent=2, sort_keys=True)+'\n')
PY
CAND="$WORKDIR/cand-legacy.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['web']={
  'id':'web','name':'Web','preset':'http','protocol':'tcp',
  'local_ip':'127.0.0.1','local_port':80,'enabled':True,
}
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
eid_legacy='1122334455667788'
secret_legacy='enroll-secret-1122334455667788aabbccddeeff0011'
write_enrollment "$ALLOC_ROOT/enrollments" "$eid_legacy" "$secret_legacy"
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${eid_legacy}.${secret_legacy}"
"$ROOT/tools/frp-client" apply >"$WORKDIR/legacy.out"
grep -q 'one-time Enrollment Code' "$WORKDIR/legacy.out" || fail "legacy should explain one-time code"
[[ -f "$TREE/etc/frp/client-identity.key" ]] || fail "legacy did not establish identity"
python3 - "$STATE" <<'PY' || fail "legacy mutation"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['web']['remote_port']
PY
CAND="$WORKDIR/cand-legacy2.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['web']['local_port']=8080
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
unset FRP_ENROLLMENT_CODE || true
export FRP_CLIENT_CANDIDATE="$CAND"
"$ROOT/tools/frp-client" apply >"$WORKDIR/legacy2.out"
if grep -q 'Enrollment Code' "$WORKDIR/legacy2.out"; then
  fail "second legacy apply asked for Enrollment Code"
fi
grep -q 'existing client identity' "$WORKDIR/legacy2.out" || fail "second apply should use identity"
pass "legacy client migrates with one Enrollment Code"

# Key without MAC is not treated as enrolled (half-enrollment)
cp "$TREE/etc/frp/client-identity.key" "$WORKDIR/key.pending"
rm -f "$TREE/etc/frp/client-identity.mac"
"$ROOT/tools/frp-client" status >"$WORKDIR/pending.out"
grep -q 'Management identity : not established' "$WORKDIR/pending.out" || fail "pending identity should not look enrolled"
CAND="$WORKDIR/cand-pending.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['web']['local_port']=8081
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
eid_pending='aa11bb22cc33dd44'
secret_pending='enroll-secret-aa11bb22cc33dd44aa11bb22cc33dd44'
write_enrollment "$ALLOC_ROOT/enrollments" "$eid_pending" "$secret_pending"
export FRP_CLIENT_CANDIDATE="$CAND"
export FRP_ENROLLMENT_CODE="${eid_pending}.${secret_pending}"
"$ROOT/tools/frp-client" apply >"$WORKDIR/pending-apply.out"
grep -q 'one-time Enrollment Code' "$WORKDIR/pending-apply.out" || fail "pending identity should ask for Enrollment Code"
[[ -f "$TREE/etc/frp/client-identity.mac" ]] || fail "pending apply did not store response key"
cmp -s "$TREE/etc/frp/client-identity.key" "$WORKDIR/key.pending" || fail "pending apply rotated key"
pass "pending identity requires one Enrollment Code"

# Revoked identity: signed apply fails, Enrollment Code recovers, later apply needs no code
python3 - "$ALLOC_ROOT/registry.json" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
reg=json.loads(p.read_text())
for client in reg['clients'].values():
    client['mgmt_status']='revoked'
    client['mgmt_mac_key']=None
    client['mgmt_revoked_at']='2026-01-01T00:00:00Z'
p.write_text(json.dumps(reg, indent=2, sort_keys=True)+'\n')
PY
CAND="$WORKDIR/cand-revoked.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['web']['local_port']=8082
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
unset FRP_ENROLLMENT_CODE || true
export FRP_CLIENT_CANDIDATE="$CAND"
if "$ROOT/tools/frp-client" apply >"$WORKDIR/revoked.out" 2>"$WORKDIR/revoked.err"; then
  fail "revoked identity should not apply without Enrollment Code"
fi
grep -q 'revoked' "$WORKDIR/revoked.err" "$WORKDIR/revoked.out" || fail "revoked error not shown"
eid_rev='bb22cc33dd44ee55'
secret_rev='enroll-secret-bb22cc33dd44ee55bb22cc33dd44ee55'
write_enrollment "$ALLOC_ROOT/enrollments" "$eid_rev" "$secret_rev"
export FRP_ENROLLMENT_CODE="${eid_rev}.${secret_rev}"
"$ROOT/tools/frp-client" apply >"$WORKDIR/recovered.out" 2>"$WORKDIR/recovered.err"
python3 - "$STATE" <<'PY' || fail "re-enroll after revoke"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['web']['local_port']==8082
PY
python3 - "$ALLOC_ROOT/registry.json" <<'PY' || fail "re-enroll status"
import json,sys
from pathlib import Path
reg=json.loads(Path(sys.argv[1]).read_text())
client=next(iter(reg['clients'].values()))
assert client.get('mgmt_status')=='enrolled'
assert client.get('mgmt_mac_key')
assert client['services']['web']['remote_port']
PY
CAND="$WORKDIR/cand-after-revoke.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['web']['local_port']=8083
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
unset FRP_ENROLLMENT_CODE || true
export FRP_CLIENT_CANDIDATE="$CAND"
"$ROOT/tools/frp-client" apply >"$WORKDIR/after-revoke.out"
if grep -q 'Enrollment Code' "$WORKDIR/after-revoke.out"; then
  fail "apply after re-enroll asked for Enrollment Code"
fi
grep -q 'existing client identity' "$WORKDIR/after-revoke.out" || fail "apply after re-enroll should use identity"
pass "revoked identity recovers with Enrollment Code"

# Interactive recoverable errors
export FRP_SSH_USER=aella
frp_reset_test_input
export FRP_CLIENT_TEST_INPUT=$'1\n1\nSSH\n\n\n\n9\n2\n99\n3\nabc\n2\n1\n\n\n0\n\n8\n'
if ! "$ROOT/tools/frp-client" >"$WORKDIR/recover.out" 2>"$WORKDIR/recover.err"; then
  fail "interactive recovery should not terminate frp-client"
fi
grep -q 'duplicate service id: ssh' "$WORKDIR/recover.err" "$WORKDIR/recover.out" || fail "duplicate SSH not reported"
grep -q 'case-insensitive' "$WORKDIR/recover.err" "$WORKDIR/recover.out" || fail "case-insensitive help"
grep -q 'ERROR: select 1-8' "$WORKDIR/recover.err" "$WORKDIR/recover.out" || fail "invalid menu not recovered"
grep -q 'invalid service number' "$WORKDIR/recover.err" "$WORKDIR/recover.out" || fail "invalid service number not recovered"
grep -q 'invalid local_port' "$WORKDIR/recover.err" "$WORKDIR/recover.out" || fail "invalid port not recovered"
grep -q 'FRP Client Management' "$WORKDIR/recover.out" || fail "menu did not continue"
python3 - "$STATE" <<'PY' || fail "recovery corrupted state"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
ids=list(d['services'])
assert 'ssh' in ids
assert 'SSH' not in ids
assert 'ssh' == [s.lower() for s in ids if s.lower()=='ssh'][0]
PY
unset FRP_CLIENT_TEST_INPUT
frp_reset_test_input
pass "interactive input errors are recoverable"

echo
echo "FRP_CLIENT_MANAGEMENT_TEST=PASS"
