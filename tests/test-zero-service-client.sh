#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 - "$ROOT" "$WORK" <<'PY'
import hashlib, hmac, importlib.util, json, sys, time
from pathlib import Path
root, work = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('allocator', root / 'server/frp-port-allocator.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
enroll = work / 'enrollments'
enroll.mkdir()
token = work / 'token'
token.write_text('test-token\n')
registry = work / 'registry.json'
mod.atomic_write_json(registry, mod.empty_registry())
cfg = work / 'config.json'
cfg.write_text(json.dumps({
    'public_host': 'example.test',
    'frp_control_public_port': 7000,
    'port_start': 19000,
    'port_end': 19010,
    'listen_port': 6999,
    'registry_file': str(registry),
    'enrollments_dir': str(enroll),
    'bootstrap_dir': str(work / 'bootstrap'),
    'token_file': str(token),
}) + '\n')
a = mod.Allocator(str(cfg))
mod.port_is_available = lambda port: True
ticket, enrollment, _ = a.issue_bootstrap_ticket([], 600, 'inventory', 'zero-node')
code, redeemed = a.redeem_bootstrap(json.dumps({
    'ticket': ticket, 'machine_id': 'machine-zero', 'hostname': 'zero-host'
}).encode())
assert code == 200 and redeemed['services'] == []
key, pub = work / 'identity.key', work / 'identity.pub'
mod.MGMT.generate_keypair(key, pub)


def enroll_hmac(services):
    body = json.dumps({
        'machine_id': 'machine-zero',
        'hostname': 'zero-host',
        'services': services,
        'mgmt_pubkey': pub.read_text(),
        'mgmt_alg': mod.MGMT.MGMT_ALG,
    }, separators=(',', ':')).encode()
    ts = str(int(time.time()))
    sig = hmac.new(
        enrollment['secret'].encode(),
        (ts + '\n' + body.decode()).encode(),
        hashlib.sha256,
    ).hexdigest()
    return a.enroll(enrollment['id'], ts, sig, body)


ssh_spec = [{
    'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp',
    'local_ip': '127.0.0.1', 'local_port': 22, 'preset': 'ssh', 'ssh_user': 'aella',
}]

# A management-only ticket authorizes no services: the Enrollment Code must
# not be usable to smuggle one in (F27).
status, result = enroll_hmac(ssh_spec)
assert status == 403 and result.get('error_class') == 'SERVICE_SCOPE_VIOLATION', (status, result)
state = a.load_registry()
assert 'machine-zero' not in (state.get('clients') or {}), state
assert a.used_ports(state) == set(), state

status, result = enroll_hmac([])
assert status == 200 and result['services'] == [], (status, result)
state = a.load_registry()
client = state['clients']['machine-zero']
assert client['mgmt_status'] == 'enrolled', client
assert client['services'] == {}
assert a.used_ports(state) == set()

# After Enrollment Code consumption, service changes use management identity.
body = json.dumps({
    'machine_id': 'machine-zero',
    'hostname': 'zero-host',
    'services': ssh_spec,
}, separators=(',', ':')).encode()
ts = int(time.time())
nonce = mod.MGMT.new_nonce()
message = mod.MGMT.signed_message('machine-zero', body, ts, nonce)
signature = mod.MGMT.sign_message(key, message)
headers = {
    'X-Mgmt-Auth': '1',
    'X-Timestamp': str(ts),
    'X-Mgmt-Nonce': nonce,
    'X-Mgmt-Signature': signature,
}
status, result = a.enroll('', str(ts), '', body, headers=headers)
assert status == 200 and result['services'] == [{'id': 'ssh', 'remote_port': 19000}], (status, result)
state = a.load_registry()
assert state['clients']['machine-zero']['services']['ssh']['remote_port'] == 19000

# Used Enrollment Code cannot change authority (new key) or services, and the
# management-identity service addition above did not widen the ticket scope.
status, result = enroll_hmac([{
    'id': 'web', 'name': 'Web', 'protocol': 'tcp',
    'local_ip': '127.0.0.1', 'local_port': 8080, 'preset': 'custom',
}])
assert status == 403 and result.get('error_class') == 'SERVICE_SCOPE_VIOLATION', (status, result)
status, result = enroll_hmac(ssh_spec)
assert status == 403 and result.get('error_class') == 'SERVICE_SCOPE_VIOLATION', (status, result)

# The in-scope (empty) request stays in scope, but the registry has since moved
# on under management identity, so it is no longer an exact lost-response replay.
status, result = enroll_hmac([])
assert status == 403 and 'already used' in result.get('error', ''), (status, result)
PY
cat >"$WORK/empty.json" <<'JSON'
[]
JSON
export FRP_CLIENT_TEST_ROOT="$WORK/client"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
mkdir -p "$FRP_CLIENT_TEST_ROOT/etc/frp"
# shellcheck source=../lib/frp-client-common.sh
. "$ROOT/lib/frp-client-common.sh"
render_frpc_toml "$WORK/frpc.toml" example.test 7000 token host-zero "$WORK/empty.json" tcp
grep -q 'serverAddr = "example.test"' "$WORK/frpc.toml"
! grep -q '^\[\[proxies\]\]' "$WORK/frpc.toml"
frp_write_client_state "$WORK/state.json" https://example.test/enroll example.test 7000 \
  zero-host machine-zero host-zero "$WORK/empty.json" tcp
python3 - "$WORK/state.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
assert s['management_only'] is True
assert s['services']=={}
PY
echo "ZERO_SERVICE_CLIENT_TEST=PASS"
