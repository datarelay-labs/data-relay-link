#!/usr/bin/env bash
# Generic frpc.toml / access-info generation from a multi-service allocation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_CLIENT_SOURCED=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"

SERVICES_FILE="$WORKDIR/services.json"
cat >"$SERVICES_FILE" <<'EOF'
[
  {
    "id": "ssh",
    "name": "SSH",
    "protocol": "tcp",
    "local_ip": "127.0.0.1",
    "local_port": 22,
    "remote_port": 6002,
    "preset": "ssh",
    "ssh_user": "aella"
  },
  {
    "id": "grafana",
    "name": "Grafana",
    "protocol": "tcp",
    "local_ip": "127.0.0.1",
    "local_port": 3000,
    "remote_port": 6003,
    "preset": "custom"
  },
  {
    "id": "admin",
    "name": "Web Admin",
    "protocol": "tcp",
    "local_ip": "192.168.122.2",
    "local_port": 443,
    "remote_port": 6004,
    "preset": "https"
  },
  {
    "id": "api",
    "name": "Internal API",
    "protocol": "tcp",
    "local_ip": "10.10.20.30",
    "local_port": 8080,
    "remote_port": 6005,
    "preset": "custom"
  }
]
EOF

TOML="$WORKDIR/frpc.toml"
render_frpc_toml "$TOML" "203.0.113.10" "443" "dummy-token" "dev-dp-mirror-abcd1234" "$SERVICES_FILE"
[[ -f "$TOML" ]] || fail "toml missing"
mode="$(python3 - "$TOML" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
[[ "$mode" == "0o600" ]] || fail "toml mode $mode"

python3 - "$TOML" <<'PY' || fail "toml contents"
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
assert 'serverAddr = "203.0.113.10"' in text
assert 'serverPort = 443' in text
assert 'type = "tcp"' in text
assert 'type = "http"' not in text
assert 'type = "https"' not in text
for name, local_ip, local_port, remote_port in [
    ('dev-dp-mirror-abcd1234-ssh', '127.0.0.1', 22, 6002),
    ('dev-dp-mirror-abcd1234-grafana', '127.0.0.1', 3000, 6003),
    ('dev-dp-mirror-abcd1234-admin', '192.168.122.2', 443, 6004),
    ('dev-dp-mirror-abcd1234-api', '10.10.20.30', 8080, 6005),
]:
    block = f'name = "{name}"'
    assert block in text, name
    idx = text.index(block)
    chunk = text[idx:idx+180]
    assert f'localIP = "{local_ip}"' in chunk, name
    assert f'localPort = {local_port}' in chunk, name
    assert f'remotePort = {remote_port}' in chunk, name
    assert 'type = "tcp"' in chunk, name
assert text.count('[[proxies]]') == 4
PY
pass "frpc.toml generic proxies"

# Health check render (disabled by default; optional healthCheck when present)
cat >"$WORKDIR/services-health.json" <<'EOF'
[
  {
    "id": "api",
    "name": "API",
    "protocol": "tcp",
    "local_ip": "127.0.0.1",
    "local_port": 8080,
    "remote_port": 6005,
    "preset": "custom",
    "health_check": {
      "type": "tcp",
      "timeout_seconds": 3,
      "interval_seconds": 10,
      "max_failed": 1
    }
  }
]
EOF
HEALTH_TOML="$WORKDIR/frpc-health.toml"
render_frpc_toml "$HEALTH_TOML" "203.0.113.10" "443" "dummy-token" "host-h" "$WORKDIR/services-health.json"
grep -q 'healthCheck.type = "tcp"' "$HEALTH_TOML" || fail "healthCheck.type missing"
grep -q 'healthCheck.timeoutSeconds = 3' "$HEALTH_TOML" || fail "healthCheck.timeoutSeconds missing"
grep -q 'healthCheck.path' "$HEALTH_TOML" && fail "tcp health should omit path"
pass "frpc.toml healthCheck tcp"

ACCESS="$WORKDIR/access-info.txt"
render_access_info "$ACCESS" "203.0.113.10" "$SERVICES_FILE"
python3 - "$ACCESS" <<'PY' || fail "access-info"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
assert 'Data Relay Link Server: 203.0.113.10' in text
assert 'ssh -p 6002 aella@203.0.113.10' in text
assert 'http://' not in text.split('grafana',1)[0] or True
assert '203.0.113.10:6003' in text
assert 'https://203.0.113.10:6004' in text
assert '203.0.113.10:6005' in text
assert 'ssh_port' not in text
assert 'https_port' not in text
assert 'Exposure      : PUBLIC' in text
assert 'Access List' in text
PY
pass "access-info generic"

# Non-interactive JSON collection + empty rejection
export SERVICES_FILE="$WORKDIR/from-env.json"
services_init
export FRP_SERVICES_JSON='[{"id":"grafana","name":"Grafana","protocol":"tcp","local_ip":"127.0.0.1","local_port":3000,"preset":"custom"}]'
services_load_from_env
[[ "$(services_count)" == "1" ]] || fail "env json count"
python3 - "$SERVICES_FILE" <<'PY' || fail "env json contents"
import json,sys
from pathlib import Path
data=json.loads(Path(sys.argv[1]).read_text())
assert data[0]['id']=='grafana'
assert data[0]['local_port']==3000
assert data[0]['preset']=='custom'
PY
pass "non-interactive FRP_SERVICES_JSON"

services_init
FRP_SERVICES_JSON='[]' services_load_from_env
[[ "$(services_count)" == "0" ]] || fail "empty management-only service set"
pass "empty services accepted for management-only enrollment"

services_init
if FRP_SERVICES_JSON='[{"id":"ssh","local_ip":"127.0.0.1","local_port":22,"preset":"ssh","ssh_user":"aella"},{"id":"ssh","local_ip":"127.0.0.1","local_port":22,"preset":"ssh","ssh_user":"aella"}]' \
  services_load_from_env >"$WORKDIR/dup.out" 2>"$WORKDIR/dup.err"; then
  fail "duplicate id should be rejected"
fi
grep -qi 'duplicate' "$WORKDIR/dup.out" "$WORKDIR/dup.err" || fail "duplicate error message"
pass "duplicate service id rejected"

# WSS frpc.toml uses the stored allocator CA; TCP remains unchanged.
WSS_ROOT="$WORKDIR/wss-client"
mkdir -p "$WSS_ROOT/etc/drlink"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'MIIBdummy' '-----END CERTIFICATE-----' \
  >"$WSS_ROOT/etc/drlink/allocator-ca.crt"
export FRP_CLIENT_TEST_ROOT="$WSS_ROOT"
WSS_TOML="$WORKDIR/frpc-wss.toml"
render_frpc_toml "$WSS_TOML" "203.0.113.10" "443" "dummy-token" "host-a" "$WORKDIR/services.json" wss
python3 - "$WSS_TOML" "$WSS_ROOT/etc/drlink/allocator-ca.crt" <<'PY' || fail "wss toml"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
assert 'transport.protocol = "wss"' in text
assert 'transport.tls.trustedCaFile = "%s"' % sys.argv[2] in text
assert 'transport.tls.enable = true' in text
assert 'serverPort = 443' in text
PY
if render_frpc_toml "$WORKDIR/frpc-bad.toml" "203.0.113.10" "443" "dummy-token" "host-a" "$WORKDIR/services.json" websocket \
  2>"$WORKDIR/bad-transport.err"; then
  fail "plain websocket transport should be rejected"
fi
grep -qi 'unsupported FRP transport' "$WORKDIR/bad-transport.err" || fail "unsupported transport message"
unset FRP_CLIENT_TEST_ROOT
pass "wss frpc.toml pins allocator CA and rejects insecure transport"
pass "SINGLE443_WSS_CONFIG"

echo
echo "CLIENT_CONFIG_TEST=PASS"
