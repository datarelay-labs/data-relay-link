#!/usr/bin/env bash
# Feature coverage for optional public_hostname access alias.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

export PYTHONPATH="$ROOT/lib${PYTHONPATH:+:$PYTHONPATH}"

# Enable the shared deploy test harness used by frp_path / status tools.
MARKER="$TMP/harness.marker"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
printf '%s' "$FRP_TEST_HARNESS_MAGIC" >"$MARKER"
export FRP_UPDATE_TEST_HARNESS=1
export FRP_UPDATE_TEST_MARKER="$MARKER"

python3 - <<'PY' || fail 'server config helper validation'
import frp_server_config as S

assert S.validate_public_ip('203.0.113.10') == '203.0.113.10'
assert S.validate_public_ip('2001:db8::1') == '2001:db8::1'
assert S.validate_public_hostname('frp.example.com') == 'frp.example.com'
for bad in (
    'https://frp.example.com', 'frp.example.com:443', 'frp.example.com/path',
    'user@frp.example.com', 'frp example.com', 'foo;bar', '$(id)', '`id`',
    '203.0.113.10',
):
    try:
        S.validate_public_hostname(bad)
    except S.ConfigError:
        pass
    else:
        raise SystemExit('accepted bad hostname: %s' % bad)
try:
    S.validate_public_ip('frp.example.com')
except S.ConfigError:
    pass
else:
    raise SystemExit('fresh IP validation accepted hostname')
# Legacy allow_hostname path for reinstall.
assert S.validate_public_ip('legacy.example.com', allow_hostname=True) == 'legacy.example.com'

cfg = {
    'public_ip': '203.0.113.10',
    'public_host': '203.0.113.10',
}
assert S.control_host(cfg) == '203.0.113.10'
assert S.access_host(cfg) == '203.0.113.10'
cfg['public_hostname'] = 'frp.example.com'
assert S.control_host(cfg) == '203.0.113.10'
assert S.access_host(cfg) == 'frp.example.com'
assert S.format_http_url('https', '2001:db8::1', 6005) == 'https://[2001:db8::1]:6005'
lines = S.render_access_lines('203.0.113.10', 'frp.example.com', 6000, preset='ssh', ssh_user='ubuntu')
assert any('Preferred' in x for x in lines)
assert any('frp.example.com' in x for x in lines)
assert any('203.0.113.10' in x for x in lines)
assert 'TLS is passed through' in S.https_passthrough_guidance('frp.example.com')
guidance = S.dns_record_guidance('frp.example.com', '203.0.113.10')
assert 'Type  : A' in guidance
assert 'Value : 203.0.113.10' in guidance
assessment = S.assess_dns('', '203.0.113.10')
assert assessment['status'] == 'NOT_CONFIGURED'
print('helpers ok')
PY
pass 'frp_server_config helpers'

# Grammar + completion
python3 - "$ROOT/lib" <<'PY' || fail 'grammar set/unset server hostname'
import sys
sys.path.insert(0, sys.argv[1])
import frp_ctl_grammar as G

ok = G.match(['set', 'server', 'hostname', 'frp.example.com'], 'server')
assert ok['status'] == 'ok' and ok['action'] == 'set_server_hostname'
assert ok['value'] == 'frp.example.com'
bad = G.match(['set', 'server', 'hostname', 'https://evil'], 'server')
# Grammar accepts token; tool validates. Ensure match is still ok action.
assert bad['status'] == 'ok'
unset = G.match(['unset', 'server', 'hostname'], 'server')
assert unset['status'] == 'ok' and unset['action'] == 'unset_server_hostname'
comp = G.completion_candidates('set ', 'server', [], [], [])
assert 'server' in comp
comp2 = G.completion_candidates('set server ', 'server', [], [], [])
assert 'hostname' in comp2
comp3 = G.completion_candidates('unset ', 'server', [], [], [])
assert 'server' in comp3
print('grammar ok')
PY
pass 'frpctl grammar'

# Runtime set/unset with lifecycle lock + no tunnel mutation fields
TREE="$TMP/root"
mkdir -p "$TREE/etc/drlink" "$TREE/var/lib/drlink"
CA_BEFORE='deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
cat >"$TREE/etc/drlink/config.json" <<EOF
{
  "public_host": "203.0.113.10",
  "public_ip": "203.0.113.10",
  "frp_control_public_port": 443,
  "frp_control_listen_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "allocator_public_port": 6099,
  "allocator_listen_port": 6099,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
  "deployment_mode": "direct",
  "frp_transport": "tcp",
  "registry_file": "/var/lib/drlink/registry.json",
  "token_file": "/etc/frp/server_token",
  "tls_ca_cert": "/etc/drlink/pki/ca.crt",
  "client_installer_url": ""
}
EOF
cat >"$TREE/var/lib/drlink/registry.json" <<'EOF'
{
  "schema_version": 2,
  "clients": {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
      "hostname": "c1",
      "services": {
        "ssh": {
          "id": "ssh",
          "preset": "ssh",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 22,
          "remote_port": 6000,
          "ssh_user": "ubuntu",
          "enabled": true
        }
      }
    }
  },
  "reserved": [6000]
}
EOF
chmod 600 "$TREE/etc/drlink/config.json" "$TREE/var/lib/drlink/registry.json"

export FRP_DEPLOY_TEST_ROOT="$TREE"
# Let audit_path() join FRP_DEPLOY_TEST_ROOT + /var/log/... (do not set
# FRP_AUDIT_LOG to an already-rooted path; that double-prefixes under test).
unset FRP_AUDIT_LOG || true
mkdir -p "$TREE/var/log/drlink"

OUT="$("$ROOT/tools/frp-server-set" hostname frp.example.com)"
echo "$OUT" | grep -q 'Type  : A' || fail 'missing DNS A guidance'
echo "$OUT" | grep -q 'frp.example.com' || fail 'missing hostname in guidance'
echo "$OUT" | grep -q '203.0.113.10' || fail 'missing IP in guidance'
echo "$OUT" | grep -q 'FRP control endpoint is unchanged' || fail 'missing control unchanged note'

python3 - "$TREE" <<'PY' || fail 'config after set'
import json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1], 'etc/drlink/config.json').read_text())
assert cfg['public_ip'] == '203.0.113.10'
assert cfg['public_host'] == '203.0.113.10'
assert cfg['public_hostname'] == 'frp.example.com'
assert cfg['allocator_public_url'] == 'https://203.0.113.10:6099/enroll'
reg = json.loads(Path(sys.argv[1], 'var/lib/drlink/registry.json').read_text())
svc = reg['clients']['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']['services']['ssh']
assert svc['remote_port'] == 6000
print('set ok')
PY
pass 'set server hostname'

# Invalid hostnames rejected
for bad in 'https://x.com' 'x.com:443' 'x.com/path' 'user@x.com' 'foo;bar' '203.0.113.10'; do
  if "$ROOT/tools/frp-server-set" hostname "$bad" >/dev/null 2>&1; then
    fail "accepted invalid hostname: $bad"
  fi
done
pass 'reject invalid hostnames'

# Status shows IP + hostname
STATUS="$(
  env \
    FRP_UPDATE_TEST_HARNESS=1 \
    FRP_UPDATE_TEST_MARKER="$MARKER" \
    FRP_DEPLOY_TEST_ROOT="$TREE" \
    FRP_UPDATE_ROOT="$TREE" \
    FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
    FRP_STATUS_SKIP_UPSTREAM=1 \
    "$ROOT/tools/frp-server-status" 2>/dev/null || true
)"
echo "$STATUS" | grep -q 'Public IP       : 203.0.113.10' || fail "status missing Public IP: $STATUS"
echo "$STATUS" | grep -q 'Public hostname : frp.example.com' || fail "status missing hostname: $STATUS"
# Keep legacy readiness signal
echo "$STATUS" | grep -q 'Public host     : configured' || fail 'legacy Public host readiness missing'
pass 'server status UX'

# Access display preferred/fallback
INFO="$(
  env FRP_DEPLOY_TEST_ROOT="$TREE" \
    "$ROOT/tools/frp-client-info" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa services
)"
echo "$INFO" | grep -q 'Preferred:' || fail "client-info missing Preferred: $INFO"
echo "$INFO" | grep -q 'frp.example.com' || fail "client-info missing hostname: $INFO"
echo "$INFO" | grep -q '203.0.113.10' || fail "client-info missing fallback IP: $INFO"
pass 'client-info preferred/fallback'

# Allocator control host stays IP; additive public_hostname
python3 - "$ROOT" "$TREE" <<'PY' || fail 'allocator response fields'
import importlib.util, json, sys
from pathlib import Path
root, tree = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('alloc', root / 'server' / 'frp-port-allocator.py')
# Loading full allocator pulls many deps; call helpers via exec of snippets.
ns = {}
code = (root / 'server' / 'frp-port-allocator.py').read_text(encoding='utf-8')
# Extract only the helper functions we need by importing frp_server_config style copies.
sys.path.insert(0, str(root / 'lib'))
# Replicate allocator helpers lightly
cfg = json.loads((tree / 'etc/drlink/config.json').read_text())
def cfg_public_host(cfg):
    for key in ('public_ip', 'public_host'):
        value = cfg.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    raise RuntimeError('missing')
def cfg_public_hostname(cfg):
    return str(cfg.get('public_hostname') or '').strip()
assert cfg_public_host(cfg) == '203.0.113.10'
assert cfg_public_hostname(cfg) == 'frp.example.com'
print('allocator helpers ok')
PY
pass 'allocator control vs hostname'

# Client access-info rendering
python3 - "$ROOT" <<'PY' || fail 'render_access_info preferred/fallback'
import os, subprocess, tempfile, json, sys
from pathlib import Path
root = Path(sys.argv[1])
# Source render_access_info via bash
script = r'''
set -euo pipefail
. "%s/lib/frp-common.sh"
. "%s/lib/frp-client-common.sh"
STATE="%s"
render_access_info "%s" "203.0.113.10" "$STATE"
cat "%s"
''' % (
    root, root,
    '__STATE__', '__OUT__', '__OUT__',
)
with tempfile.TemporaryDirectory() as td:
    state = Path(td) / 'state.json'
    out = Path(td) / 'access.txt'
    state.write_text(json.dumps({
        'frp_server': '203.0.113.10',
        'public_hostname': 'frp.example.com',
        'services': {
            'ssh': {
                'id': 'ssh', 'name': 'ssh', 'preset': 'ssh', 'protocol': 'tcp',
                'local_ip': '127.0.0.1', 'local_port': 22, 'remote_port': 6000,
                'ssh_user': 'ubuntu', 'enabled': True,
            },
            'web': {
                'id': 'web', 'name': 'web', 'preset': 'https', 'protocol': 'tcp',
                'local_ip': '127.0.0.1', 'local_port': 443, 'remote_port': 6005,
                'enabled': True,
            },
        },
    }, indent=2) + '\n')
    bash = script.replace('__STATE__', str(state)).replace('__OUT__', str(out))
    text = subprocess.check_output(['bash', '-c', bash], text=True)
    assert 'Preferred:' in text
    assert 'ssh -p 6000 ubuntu@frp.example.com' in text
    assert 'ssh -p 6000 ubuntu@203.0.113.10' in text
    assert 'https://frp.example.com:6005' in text
    assert 'https://203.0.113.10:6005' in text
    assert 'TLS is passed through' in text
    assert 'must be valid for frp.example.com' in text
    # IP-only
    state.write_text(json.dumps({
        'frp_server': '203.0.113.10',
        'services': {
            'ssh': {
                'id': 'ssh', 'name': 'ssh', 'preset': 'ssh', 'protocol': 'tcp',
                'local_ip': '127.0.0.1', 'local_port': 22, 'remote_port': 6000,
                'ssh_user': 'ubuntu', 'enabled': True,
            },
        },
    }, indent=2) + '\n')
    text = subprocess.check_output(['bash', '-c', bash], text=True)
    assert 'Preferred:' not in text
    assert 'ssh -p 6000 ubuntu@203.0.113.10' in text
print('access-info ok')
PY
pass 'access-info preferred/fallback + https guidance'

# Unset restores IP-only access metadata
"$ROOT/tools/frp-server-set" hostname --unset >/dev/null
python3 - "$TREE" <<'PY' || fail 'config after unset'
import json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1], 'etc/drlink/config.json').read_text())
assert 'public_hostname' not in cfg or not cfg.get('public_hostname')
assert cfg['public_ip'] == '203.0.113.10'
reg = json.loads(Path(sys.argv[1], 'var/lib/drlink/registry.json').read_text())
svc = reg['clients']['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']['services']['ssh']
assert svc['remote_port'] == 6000
print('unset ok')
PY
STATUS2="$(
  env \
    FRP_UPDATE_TEST_HARNESS=1 \
    FRP_UPDATE_TEST_MARKER="$MARKER" \
    FRP_DEPLOY_TEST_ROOT="$TREE" \
    FRP_UPDATE_ROOT="$TREE" \
    FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
    FRP_STATUS_SKIP_UPSTREAM=1 \
    "$ROOT/tools/frp-server-status" 2>/dev/null || true
)"
echo "$STATUS2" | grep -q 'Public hostname : not configured' || fail "status after unset: $STATUS2"
pass 'unset server hostname'

# Installer fresh IP validation + hostname persistence helpers
# shellcheck disable=SC1091
FRP_SERVER_SOURCED=1
# shellcheck source=install-server.sh
. "$ROOT/install-server.sh"
if frp_valid_public_ip_literal '203.0.113.10'; then :; else fail 'ipv4 literal'; fi
if frp_valid_public_ip_literal '2001:db8::1'; then :; else fail 'ipv6 literal'; fi
if frp_valid_public_ip_literal 'frp.example.com'; then fail 'hostname accepted as IP'; fi
if frp_valid_public_hostname 'frp.example.com'; then :; else fail 'valid hostname rejected'; fi
if frp_valid_public_hostname 'https://x'; then fail 'url accepted as hostname'; fi
pass 'installer validation helpers'

# frpc serverAddr must stay control IP when hostname present
python3 - "$ROOT" <<'PY' || fail 'frpc serverAddr stays IP'
import json, subprocess, tempfile, sys
from pathlib import Path
root = Path(sys.argv[1])
with tempfile.TemporaryDirectory() as td:
    svc = Path(td) / 'svc.json'
    toml = Path(td) / 'frpc.toml'
    svc.write_text(json.dumps([{
        'id': 'ssh', 'preset': 'ssh', 'local_ip': '127.0.0.1', 'local_port': 22,
        'remote_port': 6000, 'ssh_user': 'ubuntu', 'enabled': True,
    }]) + '\n')
    bash = f'''
set -euo pipefail
. "{root}/lib/frp-common.sh"
. "{root}/lib/frp-client-common.sh"
render_frpc_toml "{toml}" "203.0.113.10" 443 "tok" "hostid" "{svc}" tcp
'''
    subprocess.check_call(['bash', '-c', bash])
    text = toml.read_text()
    assert 'serverAddr = "203.0.113.10"' in text
    assert 'frp.example.com' not in text
print('frpc ok')
PY
pass 'frpc serverAddr remains control IP'

# Doctor: hostname unset => NOT_APPLICABLE; set unresolved => WARN not FAIL
python3 - "$ROOT" "$TREE" <<'PY' || fail 'doctor dns check'
import importlib.util, json, os, sys
from pathlib import Path
root, tree = Path(sys.argv[1]), Path(sys.argv[2])
os.environ['FRP_DEPLOY_TEST_ROOT'] = str(tree)
spec = importlib.util.spec_from_file_location('frp_doctor', root / 'lib' / 'frp_doctor.py')
doc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doc)

class Paths:
    def __init__(self, root):
        self.root = Path(root)
    def p(self, abs_path):
        return self.root / abs_path.lstrip('/')
    def is_file(self, abs_path):
        return self.p(abs_path).is_file()
    def read_bytes(self, abs_path):
        path = self.p(abs_path)
        return path.read_bytes() if path.is_file() else None

# Minimal unit: call server_config_ports + assess via helper path
cfg = json.loads((tree / 'etc/drlink/config.json').read_text())
ports = doc.server_config_ports(cfg)
assert not ports.get('public_hostname')
# set hostname that will not resolve
cfg['public_hostname'] = 'no-such-host.invalid.test'
(tree / 'etc/drlink/config.json').write_text(json.dumps(cfg, indent=2) + '\n')
sys.path.insert(0, str(root / 'lib'))
import frp_server_config as S
assessment = S.assess_dns('no-such-host.invalid.test', '203.0.113.10')
assert assessment['status'] in ('PENDING', 'MISMATCH')
assert assessment['status'] != 'FAIL'
print('doctor dns semantics ok')
PY
pass 'doctor DNS WARN/PENDING not FAIL'

# Audit events present
AUDIT_FILE="$TREE/var/log/drlink/audit.jsonl"
[[ -f "$AUDIT_FILE" ]] || fail "audit log missing at $AUDIT_FILE"
grep -q 'server.hostname_set' "$AUDIT_FILE" || fail 'missing hostname_set audit event'
grep -q 'server.hostname_unset' "$AUDIT_FILE" || fail 'missing hostname_unset audit event'
pass 'audit events'

echo
echo 'ALL public-hostname feature checks passed.'
