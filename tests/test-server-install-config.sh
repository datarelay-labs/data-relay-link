#!/usr/bin/env bash
# Server installer config resolution without touching a live FRP install.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
export FRP_SERVER_TEST_ROOT="$WORKDIR/isolated-root"
mkdir -p "$FRP_SERVER_TEST_ROOT/etc/frp-auto-deploy"

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
    EXISTING_DEPLOYMENT_MODE EXISTING_SERVER_CONFIG FRP_RELEASE_CHANNEL || true
}

reset_env
export FRP_SERVER_SOURCED=1
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"

# CASE B — non-interactive env vars.
export FRP_PUBLIC_HOST='203.0.113.10'
export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
load_existing_server_config
resolve_server_settings
[[ "$FRP_PUBLIC_IP" == '203.0.113.10' ]] || fail "CASE B public host"
[[ "$FRP_PUBLIC_HOST" == '203.0.113.10' ]] || fail "CASE B public_host"
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10:6099/enroll' ]] || fail "CASE B allocator URL"
[[ "$FRP_CONTROL_PUBLIC_PORT" == '443' ]] || fail "CASE B control public default"
[[ "$FRP_CONTROL_LISTEN_PORT" == '443' ]] || fail "CASE B control listen default"
[[ "$FRP_CONTROL_PORT" == '443' ]] || fail "CASE B control port alias"
[[ "$FRP_PORT_START" == '6000' ]] || fail "CASE B port start default"
[[ "$FRP_PORT_END" == '6098' ]] || fail "CASE B port end default"
[[ "$FRP_ALLOCATOR_PUBLIC_PORT" == '6099' ]] || fail "CASE B allocator public default"
[[ "$FRP_ALLOCATOR_LISTEN_PORT" == '6099' ]] || fail "CASE B allocator listen default"
[[ "$FRP_ALLOCATOR_PORT" == '6099' ]] || fail "CASE B allocator port alias"
pass "CASE B non-interactive env config"

# Derived allocator URL when only public host is set.
reset_env
export FRP_PUBLIC_IP='203.0.113.10'
export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
load_existing_server_config
resolve_server_settings
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10:6099/enroll' ]] || fail "derived allocator URL"
pass "derived allocator URL from public host"

# NAT split: public ports differ from listen ports.
reset_env
export FRP_PUBLIC_HOST='203.0.113.10'
export FRP_CONTROL_PUBLIC_PORT=8443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=9443
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
load_existing_server_config
resolve_server_settings
[[ "$FRP_CONTROL_PUBLIC_PORT" == '8443' ]] || fail "NAT FRP public"
[[ "$FRP_CONTROL_LISTEN_PORT" == '443' ]] || fail "NAT FRP listen"
[[ "$FRP_ALLOCATOR_PUBLIC_PORT" == '9443' ]] || fail "NAT allocator public"
[[ "$FRP_ALLOCATOR_LISTEN_PORT" == '6099' ]] || fail "NAT allocator listen"
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10:9443/enroll' ]] || fail "NAT allocator URL"
[[ "$FRP_CONTROL_PORT" == '443' ]] || fail "NAT control alias is listen"
[[ "$FRP_ALLOCATOR_PORT" == '6099' ]] || fail "NAT allocator alias is listen"
pass "NAT public/listen port split"

# Explicit public URL is not rewritten.
reset_env
export FRP_PUBLIC_HOST='203.0.113.10'
export FRP_ALLOCATOR_PUBLIC_PORT=9443
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_ALLOCATOR_URL='https://frp.example.com:9443/enroll'
export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
load_existing_server_config
resolve_server_settings
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://frp.example.com:9443/enroll' ]] || fail "explicit URL rewritten"
pass "explicit HTTPS allocator URL preserved"

# Plain HTTP allocator URL is rejected.
reset_env
if (
  export FRP_PUBLIC_HOST='203.0.113.10'
  export FRP_ALLOCATOR_URL='http://203.0.113.10:6099/enroll'
  export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
  load_existing_server_config
  resolve_server_settings
) >"$WORKDIR/http.out" 2>"$WORKDIR/http.err"; then
  fail "HTTP allocator URL should be rejected"
fi
grep -qi 'https' "$WORKDIR/http.err" || fail "HTTP rejection message"
pass "plain HTTP allocator URL rejected"

# Local listen collision is rejected.
reset_env
if (
  export FRP_PUBLIC_HOST='203.0.113.10'
  export FRP_CONTROL_LISTEN_PORT=6099
  export FRP_ALLOCATOR_LISTEN_PORT=6099
  export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
  load_existing_server_config
  resolve_server_settings
) >"$WORKDIR/collide.out" 2>"$WORKDIR/collide.err"; then
  fail "listen collision should be rejected"
fi
grep -qi 'collision' "$WORKDIR/collide.err" || fail "collision error message"
pass "local FRP/allocator listen collision rejected"

# Invalid ports.
reset_env
if (
  export FRP_PUBLIC_HOST='203.0.113.10'
  export FRP_CONTROL_PUBLIC_PORT=0
  export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
  load_existing_server_config
  resolve_server_settings
) >"$WORKDIR/port0.out" 2>"$WORKDIR/port0.err"; then
  fail "port 0 should be rejected"
fi
grep -qi 'port' "$WORKDIR/port0.err" || fail "port 0 error"
pass "invalid port 0 rejected"

reset_env
if (
  export FRP_PUBLIC_HOST='203.0.113.10'
  export FRP_ALLOCATOR_PUBLIC_PORT=65536
  export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
  load_existing_server_config
  resolve_server_settings
) >"$WORKDIR/port65536.out" 2>"$WORKDIR/port65536.err"; then
  fail "port 65536 should be rejected"
fi
pass "invalid port 65536 rejected"

reset_env
if (
  export FRP_PUBLIC_HOST='203.0.113.10'
  export FRP_CONTROL_LISTEN_PORT=abc
  export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
  load_existing_server_config
  resolve_server_settings
) >"$WORKDIR/nonnum.out" 2>"$WORKDIR/nonnum.err"; then
  fail "nonnumeric port should be rejected"
fi
pass "nonnumeric port rejected"

# CASE C — missing required deployment value, no silent production fallback.
reset_env
if (
  export FRP_SERVER_CONFIG="$WORKDIR/missing-config.json"
  export DETECTED_PUBLIC_IP='198.51.100.99'
  load_existing_server_config
  resolve_server_settings
) >"$WORKDIR/case-c.out" 2>"$WORKDIR/case-c.err"; then
  fail "CASE C should fail without public host"
fi
grep -qi 'required' "$WORKDIR/case-c.err" || fail "CASE C error message"
if grep -F '198.51.100.99' "$WORKDIR/case-c.out" >/dev/null; then
  fail "CASE C used detected IP as silent fallback"
fi
pass "CASE C missing public host fails"

# CASE D — rerun reuses existing runtime config. HTTP URLs are not reused.
EXISTING="$WORKDIR/existing-config.json"
python3 - "$EXISTING" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_host": "203.0.113.10",
  "public_ip": "203.0.113.10",
  "frp_control_public_port": 443,
  "frp_control_listen_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "allocator_listen_port": 6099,
  "allocator_public_port": 6099,
  "listen_port": 6099,
  "allocator_public_url": "http://203.0.113.10/enroll",
  "client_installer_url": "https://example.invalid/bootstrap-client.sh",
  "windows_client_installer_url": "https://example.invalid/bootstrap-client.ps1",
}, indent=2, sort_keys=True) + "\n")
PY
reset_env
export FRP_SERVER_CONFIG="$EXISTING"
load_existing_server_config
resolve_server_settings
[[ "$FRP_PUBLIC_IP" == '203.0.113.10' ]] || fail "CASE D public ip overwritten"
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://203.0.113.10:6099/enroll' ]] || fail "CASE D HTTP URL must not be reused"
[[ "$CLIENT_INSTALLER_URL" == 'https://example.invalid/bootstrap-client.sh' ]] || fail "CASE D installer URL overwritten"
[[ "$WINDOWS_CLIENT_INSTALLER_URL" == 'https://example.invalid/bootstrap-client.ps1' ]] \
  || fail "CASE D Windows installer URL overwritten"
pass "CASE D rerun preserves runtime config"

# Explicit env wins over existing config.
reset_env
export FRP_SERVER_CONFIG="$EXISTING"
export FRP_PUBLIC_HOST='192.0.2.10'
export FRP_ALLOCATOR_URL='https://frp.example.test/enroll'
load_existing_server_config
resolve_server_settings
[[ "$FRP_PUBLIC_IP" == '192.0.2.10' ]] || fail "env should override existing public host"
[[ "$FRP_ALLOCATOR_PUBLIC_URL" == 'https://frp.example.test/enroll' ]] || fail "env should override existing allocator URL"
pass "explicit env overrides existing config"

legacy_owner='RickLee-kr'
legacy_repo='frp-auto-deploy'
LEGACY_INSTALLER_URL="https://raw.githubusercontent.com/${legacy_owner}/${legacy_repo}/main/dist/bootstrap-client.sh"
# Stable releases must pin an immutable tag/commit URL, never mutable main.
CANONICAL_INSTALLER_URL="https://raw.githubusercontent.com/datarelay-labs/frp-auto-deploy/v${PROJECT_VERSION}/dist/bootstrap-client.sh"
OFFICIAL_MAIN_INSTALLER_URL='https://raw.githubusercontent.com/datarelay-labs/frp-auto-deploy/main/dist/bootstrap-client.sh'

# Known obsolete project installer URL is migrated on a safe installer rerun.
EXISTING_LEGACY="$WORKDIR/legacy-installer-url.json"
python3 - "$EXISTING_LEGACY" "$LEGACY_INSTALLER_URL" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
  "client_installer_url": sys.argv[2],
}, indent=2, sort_keys=True) + "\n")
PY
reset_env
# Pin stable so this assertion is independent of any host-persisted
# /etc/frp-auto-deploy/version RELEASE_CHANNEL (dev vs stable).
export FRP_RELEASE_CHANNEL=stable
export FRP_SERVER_CONFIG="$EXISTING_LEGACY"
load_existing_server_config
resolve_server_settings
[[ "$CLIENT_INSTALLER_URL" == "$CANONICAL_INSTALLER_URL" ]] || fail "legacy installer URL not migrated"
pass "legacy project installer URL migrated"

# Official mutable-main installer URL is rewritten to the immutable stable tag.
EXISTING_MAIN="$WORKDIR/main-installer-url.json"
python3 - "$EXISTING_MAIN" "$OFFICIAL_MAIN_INSTALLER_URL" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
  "client_installer_url": sys.argv[2],
}, indent=2, sort_keys=True) + "\n")
PY
reset_env
export FRP_RELEASE_CHANNEL=stable
export FRP_SERVER_CONFIG="$EXISTING_MAIN"
load_existing_server_config
resolve_server_settings
[[ "$CLIENT_INSTALLER_URL" == "$CANONICAL_INSTALLER_URL" ]] || fail "official main installer URL not migrated to immutable tag"
[[ "$CLIENT_INSTALLER_URL" != *'/main/'* ]] || fail "stable channel still uses mutable main"
pass "official main installer URL migrated to immutable tag"

# Arbitrary custom installer URLs are left unchanged.
EXISTING_CUSTOM="$WORKDIR/custom-installer-url.json"
python3 - "$EXISTING_CUSTOM" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
  "client_installer_url": "https://example.org/my-custom-client.sh",
}, indent=2, sort_keys=True) + "\n")
PY
reset_env
export FRP_SERVER_CONFIG="$EXISTING_CUSTOM"
load_existing_server_config
resolve_server_settings
[[ "$CLIENT_INSTALLER_URL" == 'https://example.org/my-custom-client.sh' ]] || fail "custom installer URL rewritten"
pass "custom installer URL preserved"

# Empty installer URL uses the current canonical default.
EXISTING_EMPTY="$WORKDIR/empty-installer-url.json"
python3 - "$EXISTING_EMPTY" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
  "client_installer_url": "",
}, indent=2, sort_keys=True) + "\n")
PY
reset_env
export FRP_RELEASE_CHANNEL=stable
export FRP_SERVER_CONFIG="$EXISTING_EMPTY"
load_existing_server_config
resolve_server_settings
[[ "$CLIENT_INSTALLER_URL" == "$CANONICAL_INSTALLER_URL" ]] || fail "empty installer URL did not use canonical default"
pass "empty installer URL uses canonical default"

# Legacy control_port is used for both public and listen when split fields are absent.
reset_env
export FRP_SERVER_CONFIG="$EXISTING_EMPTY"
load_existing_server_config
resolve_server_settings
[[ "$FRP_CONTROL_PUBLIC_PORT" == '443' ]] || fail "legacy control public"
[[ "$FRP_CONTROL_LISTEN_PORT" == '443' ]] || fail "legacy control listen"
pass "legacy control_port maps to public and listen equally"

echo
echo "SERVER_INSTALL_CONFIG_TEST=PASS"
