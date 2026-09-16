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

# --- F17: interactive initial onboarding requires a service; automation empty OK -
(
  set -euo pipefail
  INSTALL_WORK="$WORK/install-ux"
  mkdir -p "$INSTALL_WORK"
  export FRP_CLIENT_SOURCED=1
  export FRP_CLIENT_TEST_ROOT="$INSTALL_WORK/root"
  mkdir -p "$FRP_CLIENT_TEST_ROOT/etc/frp"
  # shellcheck source=../install-client.sh
  . "$ROOT/install-client.sh"

  SERVICES_FILE="$INSTALL_WORK/services.json"
  FRP_VERSION="${FRP_VERSION:-0.71.0}"

  # Interactive empty menu: management-only option removed; Cancel exits.
  export FRP_CLIENT_TEST_INPUT=$'3\n'
  rm -f "$(frp_test_input_path)" 2>/dev/null || true
  if collect_services >"$INSTALL_WORK/interactive.out" 2>&1; then
    cat "$INSTALL_WORK/interactive.out" >&2
    echo "FAIL F17 interactive empty install should cancel" >&2
    exit 1
  fi
  grep -qi 'Install management-only' "$INSTALL_WORK/interactive.out" \
    && { echo "FAIL F17 management-only still offered" >&2; exit 1; }
  unset FRP_CLIENT_TEST_INPUT

  # Non-interactive: an explicit empty service list remains valid for
  # automation / already-authorized management-only tickets.
  export FRP_SERVICES_JSON='[]'
  collect_services >"$INSTALL_WORK/env.out" 2>&1 \
    || { cat "$INSTALL_WORK/env.out" >&2; echo "FAIL F17 FRP_SERVICES_JSON=[] was rejected" >&2; exit 1; }
  [[ "$(services_count)" == "0" ]] || { echo "FAIL F17 env path invented a service" >&2; exit 1; }
  unset FRP_SERVICES_JSON

  # The installer starts frpc only when a service exists; management-only
  # installs leave the unit installed but stopped.
  python3 - "$ROOT/install-client.sh" <<'PY' || { echo "FAIL F17 install start guard" >&2; exit 1; }
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(encoding="utf-8")
markers = (
    'echo "Starting Data Relay Link client ..."',
    'echo "Starting FRP client ..."',
)
start = -1
for marker in markers:
    idx = text.find(marker)
    if idx >= 0:
        start = idx
        break
assert start >= 0, "client start echo missing"
guard = text.rindex('if [[ "$(services_count)" != "0"', 0, start)
assert 'FRP_SKIP_SYSTEMD' in text[guard:start], "start guard lost its systemd condition"
assert re.search(
    r'Management-only mode: frpc is not started until a service is enabled',
    text[start:],
), "management-only branch no longer explains the stopped client"
PY
) || exit 1
pass_f17="PASS F17 interactive onboarding requires a service; automation empty OK"
echo "$pass_f17"

# A management-only client can publish a service afterwards.
(
  set -euo pipefail
  LATER="$WORK/later-add"
  export FRP_CLIENT_TEST_ROOT="$LATER/root"
  export FRP_SKIP_SYSTEMD=1
  export FRP_SKIP_CONNECTIVITY_CHECK=1
  mkdir -p "$FRP_CLIENT_TEST_ROOT/etc/frp" "$FRP_CLIENT_TEST_ROOT/var/lib/drlink" \
    "$FRP_CLIENT_TEST_ROOT/usr/local/lib/drlink"
  cp "$ROOT/lib/frp_health_check.py" "$FRP_CLIENT_TEST_ROOT/usr/local/lib/drlink/"
  cp "$ROOT/lib/frp-client-common.sh" "$FRP_CLIENT_TEST_ROOT/usr/local/lib/drlink/"
  cp "$WORK/state.json" "$FRP_CLIENT_TEST_ROOT/etc/frp/client-state.json"
  "$ROOT/tools/frp-client" add-service --preset ssh --id ssh --name SSH \
    --target-port 22 --ssh-user aella >"$LATER.out" 2>&1 \
    || { cat "$LATER.out" >&2; echo "FAIL F17 service add after management-only install" >&2; exit 1; }
  python3 - "$FRP_CLIENT_TEST_ROOT/var/lib/drlink/client-draft.json" <<'PY' \
    || { echo "FAIL F17 added service missing from pending state" >&2; exit 1; }
import json, sys
from pathlib import Path
draft = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert draft["services"]["ssh"]["preset"] == "ssh", draft
PY
) || exit 1
echo "PASS F17 service add works after a management-only install"

echo "ZERO_SERVICE_CLIENT_TEST=PASS"
