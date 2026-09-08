#!/usr/bin/env bash
# Public vs internal port model, NAT summary, and generated configs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

reset_env() {
  unset FRP_PUBLIC_IP FRP_PUBLIC_HOST FRP_INTERNAL_IP FRP_CONTROL_PORT \
    FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
    FRP_PORT_START FRP_PORT_END FRP_ALLOCATOR_PORT \
    FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT \
    FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_CLIENT_INSTALLER_URL \
    FRP_SERVER_CONFIG DETECTED_PUBLIC_IP DETECTED_INTERNAL_IP \
    CLIENT_INSTALLER_URL FRP_DEPLOYMENT_MODE FRP_CONFIRM_MODE_SWITCH \
    FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR FRP_TRANSPORT FRP_MODE_SWITCH \
    EXISTING_DEPLOYMENT_MODE EXISTING_SERVER_CONFIG || true
}

export FRP_SERVER_SOURCED=1
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"

assert_ports() {
  local label="$1"
  [[ "$FRP_CONTROL_PUBLIC_PORT" == "$2" ]] || fail "$label control public"
  [[ "$FRP_CONTROL_LISTEN_PORT" == "$3" ]] || fail "$label control listen"
  [[ "$FRP_ALLOCATOR_PUBLIC_PORT" == "$4" ]] || fail "$label allocator public"
  [[ "$FRP_ALLOCATOR_LISTEN_PORT" == "$5" ]] || fail "$label allocator listen"
}

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_CONTROL_PUBLIC_PORT=443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "direct FRP" 443 443 6099 6099
pass "direct FRP public 443 / listen 443"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_CONTROL_PUBLIC_PORT=8443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "NAT FRP" 8443 443 6099 6099
pass "NAT FRP public 8443 / listen 443"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_CONTROL_PUBLIC_PORT=8443
export FRP_CONTROL_LISTEN_PORT=8443
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "direct 8443" 8443 8443 6099 6099
pass "FRP public 8443 / listen 8443"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_ALLOCATOR_PUBLIC_PORT=6099
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "direct allocator" 443 443 6099 6099
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10:6099/enroll' ]] || fail "direct allocator URL"
pass "direct allocator public 6099 / listen 6099"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_ALLOCATOR_PUBLIC_PORT=9443
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "NAT allocator" 443 443 9443 6099
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10:9443/enroll' ]] || fail "NAT allocator URL"
pass "NAT allocator public 9443 / listen 6099"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_CONTROL_PUBLIC_PORT=8443
export FRP_CONTROL_LISTEN_PORT=8443
export FRP_ALLOCATOR_PUBLIC_PORT=443
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "allocator public 443" 8443 8443 443 6099
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10/enroll' ]] || fail "allocator public 443 URL omits port"
pass "allocator public 443 / listen 6099 with FRP elsewhere"

# write_server_config consumers
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_CONTROL_PUBLIC_PORT=8443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=9443
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_INTERNAL_IP=192.0.2.50
export FRP_SERVER_CONFIG="$WORKDIR/written.json"
load_existing_server_config
resolve_server_settings >/dev/null
write_server_config
python3 - "$FRP_SERVER_CONFIG" <<'PY' || fail "written config fields"
import json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1]).read_text())
assert cfg['public_host'] == '203.0.113.10'
assert cfg['frp_control_public_port'] == 8443
assert cfg['frp_control_listen_port'] == 443
assert cfg['allocator_public_port'] == 9443
assert cfg['allocator_listen_port'] == 6099
assert cfg['listen_port'] == 6099
assert cfg['allocator_public_url'] == 'https://203.0.113.10:9443/enroll'
assert 'control_port' not in cfg
assert cfg.get('deployment_mode') == 'direct'
assert cfg.get('frp_transport') == 'tcp'
assert cfg.get('listen_host') == '0.0.0.0'
PY
pass "generated config keeps public/listen distinct"

# NAT summary uses public endpoints and internal listen ports.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_CONTROL_PUBLIC_PORT=8443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=9443
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_INTERNAL_IP=192.0.2.50
export FRP_PORT_START=6000
export FRP_PORT_END=6098
export FRP_ALLOCATOR_PUBLIC_URL='https://203.0.113.10:9443/enroll'
frp_print_nat_summary >"$WORKDIR/nat.out"
grep -q '203.0.113.10:8443' "$WORKDIR/nat.out" || fail "NAT summary FRP public"
grep -q '192.0.2.50:443' "$WORKDIR/nat.out" || fail "NAT summary FRP listen"
grep -q '203.0.113.10:9443' "$WORKDIR/nat.out" || fail "NAT summary allocator public"
grep -q '192.0.2.50:6099' "$WORKDIR/nat.out" || fail "NAT summary allocator listen"
grep -q '6000-6098' "$WORKDIR/nat.out" || fail "NAT summary service range"
grep -q '1:1' "$WORKDIR/nat.out" || fail "NAT summary 1:1 services"
if grep -q '192.0.2.50:8443' "$WORKDIR/nat.out"; then
  fail "NAT summary showed internal host with public FRP port"
fi
pass "installer summary shows public -> internal mapping"

# Public port collision warns, does not fail.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_CONTROL_PUBLIC_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=443
export FRP_CONTROL_LISTEN_PORT=8443
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >"$WORKDIR/share.out" 2>"$WORKDIR/share.err"
grep -qi 'proxy' "$WORKDIR/share.err" || fail "public port share warning"
pass "public FRP/allocator same port warns"

# CA is not rotated when only ports change.
PKI="$WORKDIR/pki"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$PKI" --public-host 203.0.113.10 >/dev/null
FP1="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$PKI/ca.crt")"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$PKI" --public-host 203.0.113.10 >/dev/null
FP2="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$PKI/ca.crt")"
[[ "$FP1" == "$FP2" ]] || fail "ensure reused rotated CA"
pass "changing only public/listen ports does not regenerate CA"

# Allocator listen overlap with service range is rejected.
reset_env
if (
  export FRP_PUBLIC_HOST=203.0.113.10
  export FRP_ALLOCATOR_LISTEN_PORT=6002
  export FRP_PORT_START=6000
  export FRP_PORT_END=6098
  export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
  load_existing_server_config
  resolve_server_settings
) >/dev/null 2>"$WORKDIR/range.err"; then
  fail "allocator listen in service range should fail"
fi
grep -qi 'outside' "$WORKDIR/range.err" || fail "range overlap message"
pass "service range collision protection preserved"

# No hard-coded product requirement that FRP owns TCP/443.
if grep -nE 'FRP must (own|use|bind).*443|require.*TCP/443|hard.?coded.*443' "$ROOT/install-server.sh"; then
  fail "installer still treats 443 as mandatory"
fi
grep -q 'Public control port' "$ROOT/install-server.sh" || fail "missing public control prompt"
grep -q 'Internal listen port' "$ROOT/install-server.sh" || fail "missing listen prompt"
pass "no fixed TCP/443 product requirement"

# Enterprise single-443 defaults.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "single443" 443 7000 443 6099
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10/enroll' ]] || fail "single443 allocator URL omits :443"
[[ "$FRP_TRANSPORT" == wss ]] || fail "single443 transport"
[[ "$FRP_LISTEN_HOST" == 127.0.0.1 ]] || fail "single443 listen host"
[[ "$FRP_CONTROL_BIND_ADDR" == 127.0.0.1 ]] || fail "single443 bind addr"
[[ "${FRP_MODE_SWITCH:-0}" == "0" ]] || fail "fresh single443 should not be a mode switch"
[[ -z "${EXISTING_SERVER_CONFIG:-}" ]] || fail "missing config was treated as existing"
pass "single443 clean-install defaults"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_CONTROL_PUBLIC_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=6099
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
if (
  load_existing_server_config
  resolve_server_settings
) >/dev/null 2>"$WORKDIR/split.err"; then
  fail "single443 split public ports should fail"
fi
grep -qi 'share the same public TCP port' "$WORKDIR/split.err" || fail "single443 split public message"
pass "single443 rejects split public ports"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_SERVER_CONFIG="$WORKDIR/s443.json"
load_existing_server_config
resolve_server_settings >/dev/null
write_server_config
write_frps_toml "$WORKDIR/frps-s443.toml"
python3 "$ROOT/lib/frp_frontend.py" \
  --dest "$WORKDIR/frontend.conf" \
  --public-host 203.0.113.10 \
  --frontend-port 443 \
  --allocator-listen-port 6099 \
  --control-listen-port 7000 \
  --ca-cert /etc/frp-auto-deploy/pki/ca.crt \
  --server-cert /etc/frp-auto-deploy/pki/server.crt \
  --server-key /etc/frp-auto-deploy/pki/server.key >/dev/null
python3 - "$FRP_SERVER_CONFIG" "$WORKDIR/frps-s443.toml" "$WORKDIR/frontend.conf" <<'PY' || fail "single443 generated files"
import json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1]).read_text())
assert cfg['deployment_mode'] == 'single443'
assert cfg['frp_transport'] == 'wss'
assert cfg['listen_host'] == '127.0.0.1'
assert cfg['frp_control_listen_port'] == 7000
assert cfg['allocator_public_url'] == 'https://203.0.113.10/enroll'
toml = Path(sys.argv[2]).read_text()
assert 'bindAddr = "127.0.0.1"' in toml
assert 'bindPort = 7000' in toml
assert 'proxyBindAddr = "0.0.0.0"' in toml
assert 'transport.tls.force = false' in toml
assert '[[httpPlugins]]' in toml
assert 'name = "frp-access"' in toml
assert 'NewUserConn' in toml
conf = Path(sys.argv[3]).read_text()
assert 'location = "/~!frp"' in conf
assert 'proxy_pass http://127.0.0.1:7000' in conf
assert 'proxy_pass https://127.0.0.1:6099' in conf
assert 'proxy_ssl_verify on' in conf
assert 'proxy_ssl_name localhost;' in conf
assert 'proxy_ssl_server_name on' in conf
assert 'proxy_ssl_name 203.0.113.10;' not in conf
assert 'ssl_certificate /etc/frp-auto-deploy/pki/server.crt' in conf
assert 'listen 443 ssl;' in conf
assert 'ca\\.crt|healthz|enroll|bootstrap/redeem|i/[^/?#]+' in conf
assert 'return 404;' in conf
# Catch-all must not proxy arbitrary paths to a localhost backend.
idx = conf.find('location / {')
assert idx >= 0
assert 'proxy_pass' not in conf[idx:idx+80]
PY
python3 "$ROOT/lib/frp_frontend.py" \
  --syntax-check-from "$WORKDIR/frontend.conf" \
  --dest "$WORKDIR/frontend.check.conf" \
  --syntax-check-port 49152
grep -q 'listen 127.0.0.1:49152 ssl;' "$WORKDIR/frontend.check.conf" || fail "syntax-check listen rewrite"
if grep -q 'listen 443 ssl;' "$WORKDIR/frontend.check.conf"; then
  fail "syntax-check copy still listens on 443"
fi
pass "single443 generated config, frps.toml, and nginx frontend"
pass "NGINX_BACKEND_DNS_IDENTITY"
pass "NGINX_NO_PUBLIC_IP_PROXY_SSL_NAME"
pass "NGINX_BACKEND_VERIFY_ON"

# Public DNS hostname still verifies the loopback allocator as localhost.
python3 "$ROOT/lib/frp_frontend.py" \
  --dest "$WORKDIR/frontend-dns.conf" \
  --public-host frp.example.test \
  --frontend-port 443 \
  --allocator-listen-port 6099 \
  --control-listen-port 7000 \
  --ca-cert /etc/frp-auto-deploy/pki/ca.crt \
  --server-cert /etc/frp-auto-deploy/pki/server.crt \
  --server-key /etc/frp-auto-deploy/pki/server.key >/dev/null
python3 - "$WORKDIR/frontend-dns.conf" <<'PY' || fail "dns public host backend identity"
from pathlib import Path
import sys
conf = Path(sys.argv[1]).read_text()
assert 'server_name frp.example.test;' in conf
assert 'proxy_ssl_name localhost;' in conf
assert 'proxy_ssl_name frp.example.test;' not in conf
assert 'proxy_ssl_verify on' in conf
assert 'proxy_ssl_verify off' not in conf
PY
pass "single443 DNS public host still uses localhost backend identity"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_ALLOCATOR_PUBLIC_URL='https://203.0.113.10:6099/enroll'
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
if (
  load_existing_server_config
  resolve_server_settings
) >/dev/null 2>"$WORKDIR/url-mismatch.err"; then
  fail "single443 URL on 6099 should fail"
fi
grep -qi 'must match public port' "$WORKDIR/url-mismatch.err" || fail "single443 URL mismatch message"
pass "single443 rejects leftover :6099 allocator URL"

reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_SERVER_CONFIG="$WORKDIR/existing-direct.json"
python3 - "$FRP_SERVER_CONFIG" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_host": "203.0.113.10",
  "frp_control_public_port": 443,
  "frp_control_listen_port": 443,
  "allocator_public_port": 6099,
  "allocator_listen_port": 6099,
  "listen_port": 6099,
  "port_start": 6000,
  "port_end": 6098,
  "deployment_mode": "direct",
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
}, indent=2)+"\n")
PY
load_existing_server_config
if (
  load_existing_server_config
  resolve_server_settings
) >/dev/null 2>"$WORKDIR/switch.err"; then
  fail "mode switch without confirmation should fail"
fi
grep -qi 'FRP_CONFIRM_MODE_SWITCH' "$WORKDIR/switch.err" || fail "mode switch confirmation message"
export FRP_CONFIRM_MODE_SWITCH=yes
resolve_server_settings >/dev/null
assert_ports "mode switch" 443 7000 443 6099
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10/enroll' ]] || fail "mode switch rewrote allocator URL"
[[ "$FRP_MODE_SWITCH" == "1" ]] || fail "explicit direct config did not set FRP_MODE_SWITCH"
pass "direct to single443 requires explicit confirmation"

write_legacy_19_config() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_host": "203.0.113.10",
  "public_ip": "203.0.113.10",
  "frp_control_public_port": 443,
  "frp_control_listen_port": 443,
  "allocator_public_port": 6099,
  "allocator_listen_port": 6099,
  "listen_port": 6099,
  "port_start": 6000,
  "port_end": 6098,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
}, indent=2) + "\n")
PY
}

# Case 2: pre-2.1 config without deployment_mode is legacy Direct.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_SERVER_CONFIG="$WORKDIR/legacy-1.9.1.json"
write_legacy_19_config "$FRP_SERVER_CONFIG"
load_existing_server_config
[[ "${EXISTING_SERVER_CONFIG:-}" == "1" ]] || fail "legacy config not detected as existing"
[[ "${EXISTING_DEPLOYMENT_MODE:-}" == "direct" ]] || fail "legacy config not treated as direct"
if (
  load_existing_server_config
  resolve_server_settings
) >/dev/null 2>"$WORKDIR/legacy-switch.err"; then
  fail "legacy Direct to single443 without confirmation should fail"
fi
grep -qi 'FRP_CONFIRM_MODE_SWITCH' "$WORKDIR/legacy-switch.err" || fail "legacy switch confirmation message"
export FRP_CONFIRM_MODE_SWITCH=yes
resolve_server_settings >/dev/null
assert_ports "legacy 1.9.1 switch" 443 7000 443 6099
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10/enroll' ]] || fail "legacy switch rewrote allocator URL"
[[ "$FRP_TRANSPORT" == wss ]] || fail "legacy switch transport"
[[ "$FRP_LISTEN_HOST" == 127.0.0.1 ]] || fail "legacy switch listen host"
[[ "$FRP_CONTROL_BIND_ADDR" == 127.0.0.1 ]] || fail "legacy switch bind addr"
[[ "$FRP_MODE_SWITCH" == "1" ]] || fail "legacy Direct to single443 did not set FRP_MODE_SWITCH"
pass "pre-2.1 Direct to single443 requires confirmation and applies defaults"

# Explicit user port overrides still win on a legacy switch.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_CONFIRM_MODE_SWITCH=yes
export FRP_CONTROL_LISTEN_PORT=7100
export FRP_ALLOCATOR_LISTEN_PORT=6199
export FRP_SERVER_CONFIG="$WORKDIR/legacy-1.9.1.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "legacy override" 443 7100 443 6199
[[ "$FRP_MODE_SWITCH" == "1" ]] || fail "legacy override lost FRP_MODE_SWITCH"
pass "legacy switch honors explicit listen port overrides"

# Case 4: existing single443 reinstall is not a mode switch.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_SERVER_CONFIG="$WORKDIR/existing-s443.json"
python3 - "$FRP_SERVER_CONFIG" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_host": "203.0.113.10",
  "frp_control_public_port": 443,
  "frp_control_listen_port": 7000,
  "allocator_public_port": 443,
  "allocator_listen_port": 6099,
  "listen_port": 6099,
  "port_start": 6000,
  "port_end": 6098,
  "deployment_mode": "single443",
  "frp_transport": "wss",
  "allocator_public_url": "https://203.0.113.10/enroll",
}, indent=2)+"\n")
PY
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "single443 reinstall" 443 7000 443 6099
[[ "${FRP_MODE_SWITCH:-0}" == "0" ]] || fail "single443 reinstall set FRP_MODE_SWITCH"
pass "existing single443 reinstall is not a mode switch"

# Case 5: existing Direct without a new mode request stays Direct.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_SERVER_CONFIG="$WORKDIR/legacy-1.9.1.json"
load_existing_server_config
resolve_server_settings >/dev/null
assert_ports "legacy remain direct" 443 443 6099 6099
[[ "${FRP_DEPLOYMENT_MODE}" == "direct" ]] || fail "legacy remain mode"
[[ "${FRP_TRANSPORT}" == "tcp" ]] || fail "legacy remain transport"
[[ "${FRP_MODE_SWITCH:-0}" == "0" ]] || fail "legacy remain set FRP_MODE_SWITCH"
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10:6099/enroll' ]] || fail "legacy remain allocator URL"
pass "existing Direct without mode request remains Direct"

# NAT summary for single443 must not tell operators to publish backends.
reset_env
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_DEPLOYMENT_MODE=single443
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
load_existing_server_config
resolve_server_settings >/dev/null
frp_print_nat_summary >"$WORKDIR/s443-fw.out"
grep -q 'TCP/443' "$WORKDIR/s443-fw.out" || fail "single443 firewall 443"
grep -q '6000-6098' "$WORKDIR/s443-fw.out" || fail "single443 firewall services"
grep -qi 'Do not expose the allocator backend' "$WORKDIR/s443-fw.out" || fail "single443 backend warning"
if grep -E 'Public inbound:.*6099' "$WORKDIR/s443-fw.out"; then
  fail "single443 summary published allocator 6099"
fi
if grep -E 'Public inbound:.*7000' "$WORKDIR/s443-fw.out"; then
  fail "single443 summary published FRP backend 7000"
fi
pass "single443 firewall summary hides backends"

echo
echo "DIRECT_MODE_REGRESSION=PASS"
echo "SINGLE443_CONFIG=PASS"
echo "SINGLE443_FRONTEND_CONFIG=PASS"
echo "SINGLE443_ALLOCATOR_PROXY_VERIFY=PASS"
echo "SINGLE443_BACKEND_LOOPBACK_ONLY=PASS"
echo "SINGLE443_MODE_SWITCH_GUARD=PASS"
echo "FRESH_INSTALL_REGRESSION=PASS"
echo "LEGACY_DIRECT_TO_SINGLE443_REGRESSION=PASS"
echo "NO_PUBLIC_BACKEND_6099_SINGLE443=PASS"
echo "NO_PUBLIC_BACKEND_7000_SINGLE443=PASS"
echo "PORT_ARCHITECTURE_TEST=PASS"
