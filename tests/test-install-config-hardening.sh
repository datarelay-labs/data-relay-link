#!/usr/bin/env bash
# Regressions for overnight hardening findings A/B/C (install config).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
export FRP_SERVER_TEST_ROOT="$WORKDIR/isolated-root"
mkdir -p "$FRP_SERVER_TEST_ROOT/etc/drlink"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

reset_env() {
  unset FRP_PUBLIC_IP FRP_PUBLIC_HOST FRP_INTERNAL_IP FRP_CONTROL_PORT \
    FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
    FRP_PORT_START FRP_PORT_END FRP_ALLOCATOR_PORT \
    FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT \
    FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_CLIENT_INSTALLER_URL \
    FRP_WINDOWS_CLIENT_INSTALLER_URL \
    FRP_SERVER_CONFIG DETECTED_PUBLIC_IP DETECTED_INTERNAL_IP \
    CLIENT_INSTALLER_URL WINDOWS_CLIENT_INSTALLER_URL \
    FRP_DEPLOYMENT_MODE FRP_CONFIRM_MODE_SWITCH \
    FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR FRP_TRANSPORT FRP_MODE_SWITCH \
    EXISTING_DEPLOYMENT_MODE EXISTING_SERVER_CONFIG FRP_RELEASE_CHANNEL \
    FRP_EGRESS_LISTEN_ADDR FRP_EGRESS_LISTEN_PORT \
    FRP_EGRESS_CONTROL_FILE FRP_EGRESS_CONN_LOG_FILE \
    EXISTING_EGRESS_LISTEN_ADDR EXISTING_EGRESS_LISTEN_PORT \
    EXISTING_EGRESS_CONTROL_FILE EXISTING_EGRESS_CONN_LOG_FILE || true
}

reset_env
export FRP_SERVER_SOURCED=1
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"

CFG="$FRP_SERVER_TEST_ROOT/etc/drlink/config.json"

# --- Finding A: malformed / wrong-type config fail closed ---
printf 'not-json{\n' >"$CFG"
reset_env
export FRP_PUBLIC_IP='203.0.113.10'
if load_existing_server_config >"$WORKDIR/a1.out" 2>"$WORKDIR/a1.err"; then
  fail "malformed config treated as missing"
fi
grep -qi 'malformed\|corrupt\|JSON' "$WORKDIR/a1.err" || fail "malformed error wording"
pass "malformed config fail-closed"

printf '[]\n' >"$CFG"
reset_env
export FRP_PUBLIC_IP='203.0.113.10'
if load_existing_server_config >"$WORKDIR/a2.out" 2>"$WORKDIR/a2.err"; then
  fail "array config treated as missing"
fi
grep -qi 'object\|corrupt\|JSON' "$WORKDIR/a2.err" || fail "wrong-type error wording"
pass "wrong JSON type fail-closed"

# Missing config remains supported fresh-install path.
rm -f "$CFG"
reset_env
export FRP_PUBLIC_IP='203.0.113.10'
export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
load_existing_server_config
[[ "${EXISTING_SERVER_CONFIG:-}" != "1" ]] || fail "missing config marked existing"
pass "missing config fresh-install path"

# Valid existing config is preserved / detected.
reset_env
python3 - "$CFG" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
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
  "client_installer_url": "https://example.test/bootstrap-client.sh",
  "windows_client_installer_url": "https://example.test/bootstrap-client.ps1",
  "deployment_mode": "direct",
  "egress_listen_addr": "127.0.0.1",
  "egress_listen_port": 6122,
  "egress_control_file": "/var/lib/drlink/custom-egress.json",
  "egress_conn_log_file": "/var/log/drlink/egress/custom.jsonl",
}, indent=2) + "\n", encoding="utf-8")
PY
export FRP_PUBLIC_IP='203.0.113.10'
load_existing_server_config
[[ "$EXISTING_SERVER_CONFIG" == "1" ]] || fail "valid config not detected"
[[ "$EXISTING_EGRESS_LISTEN_ADDR" == "127.0.0.1" ]] || fail "egress addr not loaded"
[[ "$EXISTING_EGRESS_LISTEN_PORT" == "6122" ]] || fail "egress port not loaded"
[[ "$EXISTING_EGRESS_CONTROL_FILE" == "/var/lib/drlink/custom-egress.json" ]] || fail "egress control not loaded"
[[ "$EXISTING_EGRESS_CONN_LOG_FILE" == "/var/log/drlink/egress/custom.jsonl" ]] || fail "egress log not loaded"
pass "valid existing config preserved fields"

# --- Finding B: reinstall preserves custom egress listener settings ---
resolve_server_settings
CLIENT_INSTALLER_URL="${CLIENT_INSTALLER_URL}"
WINDOWS_CLIENT_INSTALLER_URL="${WINDOWS_CLIENT_INSTALLER_URL}"
write_server_config
python3 - "$CFG" <<'PY' || fail "egress custom settings overwritten"
import json, sys
cfg = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert cfg.get("egress_listen_addr") == "127.0.0.1", cfg
assert int(cfg.get("egress_listen_port")) == 6122, cfg
assert "egress_control_file" not in cfg, cfg
assert cfg.get("egress_conn_log_file") == "/var/log/drlink/egress/custom.jsonl", cfg
print("ok")
PY
pass "reinstall preserves custom egress listener settings"

# Explicit operator override still wins.
reset_env
export FRP_PUBLIC_IP='203.0.113.10'
export FRP_EGRESS_LISTEN_ADDR='0.0.0.0'
export FRP_EGRESS_LISTEN_PORT='6102'
load_existing_server_config
resolve_server_settings
CLIENT_INSTALLER_URL="${CLIENT_INSTALLER_URL}"
WINDOWS_CLIENT_INSTALLER_URL="${WINDOWS_CLIENT_INSTALLER_URL}"
write_server_config
python3 - "$CFG" <<'PY' || fail "explicit egress override ignored"
import json, sys
cfg = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert cfg.get("egress_listen_addr") == "0.0.0.0", cfg
assert int(cfg.get("egress_listen_port")) == 6102, cfg
print("ok")
PY
pass "explicit egress env override honored"

# --- Finding C: IPv6 URL authority brackets ---
ipv4_url="$(frp_format_https_url '203.0.113.10' 6099 /enroll)"
[[ "$ipv4_url" == "https://203.0.113.10:6099/enroll" ]] || fail "ipv4 url=$ipv4_url"
host_url="$(frp_format_https_url 'relay.example.com' 6099 /enroll)"
[[ "$host_url" == "https://relay.example.com:6099/enroll" ]] || fail "host url=$host_url"
ipv6_url="$(frp_format_https_url '2001:db8::10' 6099 /enroll)"
[[ "$ipv6_url" == "https://[2001:db8::10]:6099/enroll" ]] || fail "ipv6 url=$ipv6_url"
ipv6_443="$(frp_format_https_url '2001:db8::10' 443 /enroll)"
[[ "$ipv6_443" == "https://[2001:db8::10]/enroll" ]] || fail "ipv6:443 url=$ipv6_443"
prebracket="$(frp_format_https_url '[2001:db8::10]' 6099 /enroll)"
[[ "$prebracket" == "https://[2001:db8::10]:6099/enroll" ]] || fail "prebracket=$prebracket"
pass "IPv6 URL authority brackets"

echo
echo "INSTALL_CONFIG_HARDENING_TEST=PASS"
