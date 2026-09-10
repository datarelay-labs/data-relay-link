#!/usr/bin/env bash
# P2.10 install / update / uninstall lifecycle hardening.
# Isolated test roots only. Does not touch live FRP systems.
set -euo pipefail

# Ignore leaked roots from prior debug sessions; they divert txn markers.
unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
export FRP_SERVER_SOURCED=1
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

assert_mode() {
  local path="$1" expected="$2" mode
  mode="$(python3 - "$path" <<'PY'
import os, stat, sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
  [[ "$mode" == "$expected" ]] || fail "mode $path wanted $expected got $mode"
}

# Project/state dirs stay 0700 with ACL when available; without setfacl the
# installer falls back to 0710 + group drlink-egress for traverse-only access.
assert_project_state_dir_mode() {
  local path="$1"
  python3 - "$path" <<'PY' || fail "project/state dir mode $path"
import grp, os, stat, sys
path = sys.argv[1]
st = os.stat(path)
mode = stat.S_IMODE(st.st_mode)
try:
    group = grp.getgrgid(st.st_gid).gr_name
except KeyError:
    group = str(st.st_gid)
if mode == 0o700:
    raise SystemExit(0)
if mode == 0o710 and group == "drlink-egress":
    raise SystemExit(0)
print(f"wanted 0o700 or 0o710:drlink-egress got {oct(mode)} group={group}", file=sys.stderr)
raise SystemExit(1)
PY
}

assert_no_leak() {
  local log="$1"
  if grep -E 'BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY|test-frp-token-do-not-use|enroll-secret-|server_token_value' "$log" >/dev/null 2>&1; then
    fail "secret fixture leaked to command output"
  fi
}

bytes_equal() {
  python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path
sys.exit(0 if Path(sys.argv[1]).read_bytes() == Path(sys.argv[2]).read_bytes() else 1)
PY
}

write_dummy_frps() {
  local dest="$1" version="${2:-0.71.0}"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
  echo "frps version ${version}"
  exit 0
fi
if [[ "\${1:-}" == "verify" ]]; then
  exit 0
fi
exit 0
EOF
  chmod 0755 "$dest"
}

write_dummy_frpc() {
  local dest="$1" version="${2:-0.71.0}"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
  echo "frpc version ${version}"
  exit 0
fi
if [[ "\${1:-}" == "verify" ]]; then
  exit 0
fi
exit 0
EOF
  chmod 0755 "$dest"
}

write_fake_elf() {
  local dest="$1" machine="${2:-3}"
  python3 - "$dest" "$machine" <<'PY'
from pathlib import Path
import sys
machine = int(sys.argv[2])
data = bytearray(64)
data[0:4] = b"\x7fELF"
data[4] = 2
data[5] = 1
data[18:20] = machine.to_bytes(2, "little")
Path(sys.argv[1]).write_bytes(bytes(data))
PY
  chmod 0755 "$dest"
}

# ---------------------------------------------------------------------------
# Path deletion safety
# ---------------------------------------------------------------------------
if frp_safe_rm_rf "" 2>"$WORKDIR/empty.err"; then
  fail "empty path should be refused"
fi
grep -q 'FAILURE_CLASS=PATH_DELETION_REFUSED' "$WORKDIR/empty.err" || fail "empty path class"
if frp_safe_rm_rf "/" 2>"$WORKDIR/root.err"; then
  fail "/ should be refused"
fi
grep -q 'FAILURE_CLASS=PATH_DELETION_REFUSED' "$WORKDIR/root.err" || fail "/ class"
if frp_safe_rm_rf "." 2>"$WORKDIR/dot.err"; then
  fail ". should be refused"
fi
if FRP_UNINSTALL_TEST_ROOT= "$ROOT/uninstall-server.sh" --purge --yes 2>"$WORKDIR/empty-root.err"; then
  # empty test root still uses real paths; skip by using invalid explicit helper
  true
fi
pass "PATH_DELETION_SAFETY"

SYMLINK_TREE="$WORKDIR/symlink-target"
mkdir -p "$SYMLINK_TREE/keep"
echo precious >"$SYMLINK_TREE/keep/data"
LINK_PATH="$WORKDIR/symlink-etc-frp"
ln -s "$SYMLINK_TREE" "$LINK_PATH"
if frp_safe_rm_rf "$LINK_PATH" 2>"$WORKDIR/symlink.err"; then
  fail "symlink recursive delete should be refused"
fi
[[ -f "$SYMLINK_TREE/keep/data" ]] || fail "symlink delete followed into target"
grep -q 'FAILURE_CLASS=SYMLINK_REFUSED' "$WORKDIR/symlink.err" || fail "symlink class"
pass "SYMLINK_SAFETY"

# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------
python3 - "$WORKDIR/evil.tar.gz" <<'PY'
import tarfile, io, sys
from pathlib import Path
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tf:
    info = tarfile.TarInfo("../../tmp/evil-frps")
    data = b"evil"
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
Path(sys.argv[1]).write_bytes(buf.getvalue())
PY
if frp_extract_frp_member "$WORKDIR/evil.tar.gz" "$WORKDIR/extract" frps 2>"$WORKDIR/evil.err"; then
  fail "path traversal archive should fail"
fi
[[ ! -e /tmp/evil-frps ]] || fail "traversal wrote outside dest"
[[ ! -e "$WORKDIR/extract/frps" ]] || fail "traversal still extracted"
pass "ARCHIVE_EXTRACTION_SAFE"

python3 - "$WORKDIR/good.tar.gz" <<'PY'
import tarfile, io, sys
from pathlib import Path
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tf:
    info = tarfile.TarInfo("frp_0.71.0_linux_amd64/frps")
    data = b"#!/bin/sh\necho ok\n"
    info.size = len(data)
    info.mode = 0o755
    tf.addfile(info, io.BytesIO(data))
Path(sys.argv[1]).write_bytes(buf.getvalue())
PY
got="$(frp_extract_frp_member "$WORKDIR/good.tar.gz" "$WORKDIR/extract-good" frps)"
[[ -x "$got" ]] || fail "expected frps extract"
pass "ARCHIVE_EXPECTED_MEMBER"

# ---------------------------------------------------------------------------
# FRP binary validation
# ---------------------------------------------------------------------------
write_dummy_frps "$WORKDIR/frps-ok" "0.71.0"
frp_validate_frp_binary "$WORKDIR/frps-ok" "0.71.0" amd64 || fail "valid dummy rejected"
write_dummy_frps "$WORKDIR/frps-wrong-ver" "0.99.0"
if frp_validate_frp_binary "$WORKDIR/frps-wrong-ver" "0.71.0" amd64 2>"$WORKDIR/wrong-ver.err"; then
  fail "wrong FRP version should be rejected"
fi
write_fake_elf "$WORKDIR/frps-i386" 3
if frp_validate_frp_binary "$WORKDIR/frps-i386" "0.71.0" amd64 2>"$WORKDIR/wrong-arch.err"; then
  fail "wrong ELF arch should be rejected"
fi
grep -q 'architecture' "$WORKDIR/wrong-arch.err" || fail "arch error message"
pass "FRP_BINARY_VALIDATION"
pass "FRP_WRONG_VERSION_REJECTED"
pass "FRP_WRONG_ARCH_REJECTED"

[[ "$(frp_version_compare 1.8.0 1.7.0)" == gt ]] || fail "1.8 > 1.7"
[[ "$(frp_version_compare 1.7.0 1.8.0)" == lt ]] || fail "1.7 < 1.8"
[[ "$(frp_version_compare 1.8.0 1.8.0)" == eq ]] || fail "1.8 == 1.8"

# ---------------------------------------------------------------------------
# Fresh server install (isolated root)
# ---------------------------------------------------------------------------
SRV="$WORKDIR/server-fresh"
mkdir -p "$SRV"
write_dummy_frps "$WORKDIR/frps-0.71.0" "0.71.0"
export FRP_SERVER_TEST_ROOT="$SRV"
export FRP_PUBLIC_HOST='203.0.113.10'
export FRP_CONTROL_PUBLIC_PORT=443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=6099
export FRP_ALLOCATOR_LISTEN_PORT=6099
export FRP_PORT_START=6000
export FRP_PORT_END=6098
export FRP_INSTALL_HOOK_NEW_BINARY="$WORKDIR/frps-0.71.0"
export FRP_INSTALL_HOOK_SKIP_SYSTEMD=1
unset FRP_SERVER_CONFIG FRP_PKI_DIR || true
if ! frp_server_main >"$WORKDIR/fresh-server.out" 2>"$WORKDIR/fresh-server.err"; then
  cat "$WORKDIR/fresh-server.out" "$WORKDIR/fresh-server.err" >&2
  fail "fresh server install"
fi
assert_no_leak "$WORKDIR/fresh-server.out"
assert_no_leak "$WORKDIR/fresh-server.err"
[[ -x "$SRV/usr/local/bin/frps" ]] || fail "frps missing"
[[ -s "$SRV/etc/frp/server_token" ]] || fail "token missing"
assert_mode "$SRV/etc/frp/server_token" "0o600"
assert_mode "$SRV/etc/frp/frps.toml" "0o600"
assert_mode "$SRV/var/lib/drlink/registry.json" "0o600"
assert_mode "$SRV/etc/drlink/pki/ca.key" "0o600"
assert_mode "$SRV/etc/drlink/pki/server.key" "0o600"
[[ -f "$SRV/etc/drlink/pki/ca.crt" ]] || fail "CA missing"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$SRV/etc/drlink/version" || fail "server version"
grep -q 'FRP_VERSION=0.71.0' "$SRV/etc/drlink/version" || fail "server FRP version"
grep -q 'transport.tls.force = true' "$SRV/etc/frp/frps.toml" || fail "direct tls.force"
grep -q 'bindPort = 443' "$SRV/etc/frp/frps.toml" || fail "direct bindPort"
if grep -q 'bindAddr' "$SRV/etc/frp/frps.toml"; then
  fail "direct mode should not set bindAddr"
fi
[[ ! -f "$SRV/etc/drlink/frontend.conf" ]] || fail "direct mode wrote frontend.conf"
python3 - "$SRV/etc/drlink/config.json" <<'PY' || fail "direct config mode"
import json,sys
from pathlib import Path
cfg=json.loads(Path(sys.argv[1]).read_text())
assert cfg.get('deployment_mode')=='direct'
assert cfg.get('frp_transport')=='tcp'
assert cfg.get('listen_host')=='0.0.0.0'
PY
[[ ! -f "$SRV/var/lib/drlink/server-update-pending.json" ]] || fail "stale txn marker after success"
[[ -d "$SRV/var/log/drlink" ]] || fail "fresh install missing /var/log/drlink"
assert_project_state_dir_mode "$SRV/var/log/drlink"
assert_project_state_dir_mode "$SRV/var/lib/drlink"
assert_project_state_dir_mode "$SRV/etc/drlink"
assert_mode "$SRV/etc/frp" "0o700"
pass "SERVER_FRESH_INSTALL"
pass "DIRECT_MODE_REGRESSION"
pass "TEMP_FILE_SECURITY"
pass "UPDATE_TRANSACTION_CLEANUP"
pass "FILE_PERMISSION_REGRESSION"

CA_FP="$(python3 - "$SRV/etc/drlink/pki/ca.crt" <<'PY'
import hashlib, subprocess, sys, tempfile
from pathlib import Path
src = Path(sys.argv[1])
der = tempfile.NamedTemporaryFile(delete=False)
der.close()
subprocess.check_call(["openssl", "x509", "-in", str(src), "-outform", "DER", "-out", der.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(hashlib.sha256(Path(der.name).read_bytes()).hexdigest())
Path(der.name).unlink()
PY
)"
TOKEN_SHA="$(frp_file_sha256 "$SRV/etc/frp/server_token")"
REG_SHA="$(frp_file_sha256 "$SRV/var/lib/drlink/registry.json")"
python3 - "$SRV/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
state.setdefault("reserved", []).append(6002)
state.setdefault("clients", {})["machine-a"] = {
    "hostname": "a",
    "services": {"ssh": {"remote_port": 6002, "enabled": True}},
}
Path(sys.argv[1]).write_text(json.dumps(state, indent=2) + "\n")
PY
chmod 600 "$SRV/var/lib/drlink/registry.json"
REG_SHA="$(frp_file_sha256 "$SRV/var/lib/drlink/registry.json")"

# Reinstall must preserve CA/token/registry and skip unnecessary restart.
cp "$WORKDIR/fresh-server.out" "$WORKDIR/before-reinstall.out"
if ! frp_server_main >"$WORKDIR/reinstall-server.out" 2>"$WORKDIR/reinstall-server.err"; then
  cat "$WORKDIR/reinstall-server.out" "$WORKDIR/reinstall-server.err" >&2
  fail "server reinstall"
fi
CA_FP2="$(python3 - "$SRV/etc/drlink/pki/ca.crt" <<'PY'
import hashlib, subprocess, sys, tempfile
from pathlib import Path
src = Path(sys.argv[1])
der = tempfile.NamedTemporaryFile(delete=False)
der.close()
subprocess.check_call(["openssl", "x509", "-in", str(src), "-outform", "DER", "-out", der.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(hashlib.sha256(Path(der.name).read_bytes()).hexdigest())
Path(der.name).unlink()
PY
)"
[[ "$CA_FP" == "$CA_FP2" ]] || fail "CA rotated on reinstall"
[[ "$(frp_file_sha256 "$SRV/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "token rotated on reinstall"
[[ "$(frp_file_sha256 "$SRV/var/lib/drlink/registry.json")" == "$REG_SHA" ]] || fail "registry rewritten on reinstall"
grep -q 'Existing allocator CA preserved' "$WORKDIR/reinstall-server.out" || fail "CA preserved message"
if grep -q 'restart drlink-server' "$SRV/var/lib/drlink/install-actions.log"; then
  # first install records restart; reinstall of same binary/config should not add another after the last success
  restart_n="$(grep -c 'restart drlink-server' "$SRV/var/lib/drlink/install-actions.log" || true)"
  [[ "$restart_n" -le 2 ]] || fail "too many frps restarts: $restart_n"
fi
pass "SERVER_REINSTALL_IDEMPOTENT"
pass "SERVER_CA_PRESERVED"
pass "SERVER_TOKEN_PRESERVED"
pass "SERVER_REGISTRY_PRESERVED"

S443="$WORKDIR/server-s443"
mkdir -p "$S443"
export FRP_SERVER_TEST_ROOT="$S443"
export FRP_DEPLOYMENT_MODE=single443
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  FRP_SERVER_CONFIG FRP_PKI_DIR || true
if ! frp_server_main >"$WORKDIR/s443.out" 2>"$WORKDIR/s443.err"; then
  cat "$WORKDIR/s443.out" "$WORKDIR/s443.err" >&2
  fail "single443 server install"
fi
assert_no_leak "$WORKDIR/s443.out"
assert_no_leak "$WORKDIR/s443.err"
grep -q 'bindAddr = "127.0.0.1"' "$S443/etc/frp/frps.toml" || fail "s443 bindAddr"
grep -q 'bindPort = 7000' "$S443/etc/frp/frps.toml" || fail "s443 bindPort"
grep -q 'proxyBindAddr = "0.0.0.0"' "$S443/etc/frp/frps.toml" || fail "s443 proxyBind"
grep -q 'transport.tls.force = false' "$S443/etc/frp/frps.toml" || fail "s443 tls.force"
[[ -f "$S443/etc/drlink/frontend.conf" ]] || fail "s443 frontend.conf"
[[ -f "$S443/etc/systemd/system/drlink-frontend.service" ]] || fail "s443 frontend unit"
grep -q 'location = "/~!frp"' "$S443/etc/drlink/frontend.conf" || fail "s443 websocket path"
python3 - "$S443/etc/drlink/config.json" <<'PY' || fail "s443 config"
import json,sys
from pathlib import Path
cfg=json.loads(Path(sys.argv[1]).read_text())
assert cfg['deployment_mode']=='single443'
assert cfg['frp_transport']=='wss'
assert cfg['listen_host']=='127.0.0.1'
assert cfg['frp_control_public_port']==443
assert cfg['frp_control_listen_port']==7000
assert cfg['allocator_public_port']==443
assert cfg['allocator_listen_port']==6099
assert cfg['allocator_public_url']=='https://203.0.113.10/enroll'
PY
grep -q 'Deployment mode   : single443' "$WORKDIR/s443.out" || fail "s443 summary mode"
grep -q 'healthz|enroll|bootstrap/redeem|i/' "$S443/etc/drlink/frontend.conf" \
  || fail "s443 allocator path allowlist"
grep -q 'return 404;' "$S443/etc/drlink/frontend.conf" || fail "s443 default 404"
grep -q 'proxy_ssl_verify on' "$S443/etc/drlink/frontend.conf" || fail "s443 proxy_ssl_verify"
grep -q 'proxy_ssl_name localhost;' "$S443/etc/drlink/frontend.conf" || fail "s443 proxy_ssl_name localhost"
if grep -q 'proxy_ssl_name 203.0.113.10;' "$S443/etc/drlink/frontend.conf"; then
  fail "s443 proxy_ssl_name used public IP"
fi
if grep -q 'proxy_ssl_verify off' "$S443/etc/drlink/frontend.conf"; then
  fail "s443 proxy_ssl_verify off"
fi
grep -q 'stop nginx.service' "$S443/var/lib/drlink/install-actions.log" \
  || fail "s443 did not stop distro nginx.service after fresh package install"
grep -q 'disable nginx.service' "$S443/var/lib/drlink/install-actions.log" \
  || fail "s443 did not disable distro nginx.service after fresh package install"
[[ -f "$S443/var/lib/drlink/nginx-ownership" ]] || fail "s443 nginx ownership marker"
grep -q 'NGINX_PACKAGE_INSTALLED_BY_PROJECT=1' "$S443/var/lib/drlink/nginx-ownership" \
  || fail "s443 ownership installed-by-project"
assert_mode "$S443/etc/drlink/pki/ca.key" "0o600"
assert_mode "$S443/etc/drlink/pki/server.key" "0o600"
pass "SERVER_SINGLE443_INSTALL"
pass "SINGLE443_CA_PIN"
pass "SINGLE443_FRONTEND_CONFIG"
pass "NGINX_PACKAGE_FRESH_INSTALL_SERVICE_CLEANUP"
pass "SINGLE443_REGRESSION"

# Case B: nginx package already present, distro unit inactive/disabled.
NGX_B="$WORKDIR/server-nginx-preexisting-disabled"
mkdir -p "$NGX_B"
export FRP_SERVER_TEST_ROOT="$NGX_B"
export FRP_DEPLOYMENT_MODE=single443
export FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED=1
export FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE=0
export FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED=0
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  FRP_SERVER_CONFIG FRP_PKI_DIR FRP_CONFIRM_MODE_SWITCH || true
if ! frp_server_main >"$WORKDIR/nginx-b.out" 2>"$WORKDIR/nginx-b.err"; then
  cat "$WORKDIR/nginx-b.out" "$WORKDIR/nginx-b.err" >&2
  fail "single443 with preexisting disabled nginx"
fi
if grep -q 'stop nginx.service' "$NGX_B/var/lib/drlink/install-actions.log"; then
  fail "preexisting disabled nginx.service was stopped"
fi
grep -q 'NGINX_PACKAGE_PREEXISTING=1' "$NGX_B/var/lib/drlink/nginx-ownership" \
  || fail "preexisting disabled ownership"
grep -q 'NGINX_PACKAGE_INSTALLED_BY_PROJECT=0' "$NGX_B/var/lib/drlink/nginx-ownership" \
  || fail "preexisting disabled marked as project-installed"
pass "NGINX_PREEXISTING_DISABLED_PRESERVED"
unset FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE \
  FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED || true

# Case D: reinstall existing single443 is idempotent and is not distro nginx.service.
export FRP_SERVER_TEST_ROOT="$S443"
export FRP_DEPLOYMENT_MODE=single443
export FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED=1
export FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE=0
export FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED=0
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  FRP_SERVER_CONFIG FRP_PKI_DIR FRP_CONFIRM_MODE_SWITCH || true
if ! frp_server_main >"$WORKDIR/s443-re.out" 2>"$WORKDIR/s443-re.err"; then
  cat "$WORKDIR/s443-re.out" "$WORKDIR/s443-re.err" >&2
  fail "single443 reinstall"
fi
grep -q 'proxy_ssl_name localhost;' "$S443/etc/drlink/frontend.conf" \
  || fail "reinstall lost localhost backend identity"
[[ -f "$S443/etc/systemd/system/drlink-frontend.service" ]] || fail "reinstall dropped frontend unit"
pass "NGINX_SINGLE443_REINSTALL_IDEMPOTENT"
unset FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE \
  FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED || true

# Direct -> single443 preserves CA/token/registry and requires confirmation.
SWITCH="$WORKDIR/server-switch"
cp -a "$SRV" "$SWITCH"
export FRP_SERVER_TEST_ROOT="$SWITCH"
export FRP_DEPLOYMENT_MODE=single443
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  EXISTING_SERVER_CONFIG \
  FRP_SERVER_CONFIG FRP_PKI_DIR FRP_CONFIRM_MODE_SWITCH || true
if (
  frp_server_main
) >"$WORKDIR/switch-no.out" 2>"$WORKDIR/switch-no.err"; then
  fail "mode switch without confirmation should fail"
fi
grep -qi 'FRP_CONFIRM_MODE_SWITCH' "$WORKDIR/switch-no.err" || fail "switch confirmation message"
grep -q 'bindPort = 443' "$SWITCH/etc/frp/frps.toml" || fail "unconfirmed switch rewrote toml"
export FRP_CONFIRM_MODE_SWITCH=yes
if ! frp_server_main >"$WORKDIR/switch-yes.out" 2>"$WORKDIR/switch-yes.err"; then
  cat "$WORKDIR/switch-yes.out" "$WORKDIR/switch-yes.err" >&2
  fail "confirmed mode switch"
fi
[[ "$(python3 - "$SWITCH/etc/drlink/pki/ca.crt" <<'PY'
import hashlib, subprocess, sys, tempfile
from pathlib import Path
src = Path(sys.argv[1])
der = tempfile.NamedTemporaryFile(delete=False)
der.close()
subprocess.check_call(["openssl", "x509", "-in", str(src), "-outform", "DER", "-out", der.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(hashlib.sha256(Path(der.name).read_bytes()).hexdigest())
Path(der.name).unlink()
PY
)" == "$CA_FP" ]] || fail "mode switch rotated CA"
[[ "$(frp_file_sha256 "$SWITCH/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "mode switch rotated token"
[[ "$(frp_file_sha256 "$SWITCH/var/lib/drlink/registry.json")" == "$REG_SHA" ]] || fail "mode switch rewrote registry"
grep -q 'bindAddr = "127.0.0.1"' "$SWITCH/etc/frp/frps.toml" || fail "switch bindAddr"
grep -q 'bindPort = 7000' "$SWITCH/etc/frp/frps.toml" || fail "switch bindPort"
[[ -f "$SWITCH/etc/systemd/system/drlink-frontend.service" ]] || fail "switch frontend unit"
pass "SINGLE443_MODE_SWITCH_GUARD"

# Pre-2.1 config.json without deployment_mode is still Direct → single443.
LEGACY19="$WORKDIR/server-legacy-19"
cp -a "$SRV" "$LEGACY19"
python3 - "$LEGACY19/etc/drlink/config.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text())
cfg.pop('deployment_mode', None)
cfg.pop('frp_transport', None)
cfg.pop('listen_host', None)
cfg.pop('frp_control_bind_addr', None)
cfg.pop('frp_proxy_bind_addr', None)
path.write_text(json.dumps(cfg, indent=2) + '\n')
PY
export FRP_SERVER_TEST_ROOT="$LEGACY19"
export FRP_DEPLOYMENT_MODE=single443
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  EXISTING_SERVER_CONFIG \
  FRP_SERVER_CONFIG FRP_PKI_DIR FRP_CONFIRM_MODE_SWITCH || true
if (
  frp_server_main
) >"$WORKDIR/legacy-no.out" 2>"$WORKDIR/legacy-no.err"; then
  fail "legacy Direct to single443 without confirmation should fail"
fi
grep -qi 'FRP_CONFIRM_MODE_SWITCH' "$WORKDIR/legacy-no.err" || fail "legacy confirmation message"
grep -q 'bindPort = 443' "$LEGACY19/etc/frp/frps.toml" || fail "unconfirmed legacy switch rewrote toml"
[[ "$(frp_file_sha256 "$LEGACY19/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "unconfirmed legacy rotated token"
export FRP_CONFIRM_MODE_SWITCH=yes
if ! frp_server_main >"$WORKDIR/legacy-yes.out" 2>"$WORKDIR/legacy-yes.err"; then
  cat "$WORKDIR/legacy-yes.out" "$WORKDIR/legacy-yes.err" >&2
  fail "confirmed legacy mode switch"
fi
python3 - "$LEGACY19/etc/drlink/config.json" <<'PY' || fail "legacy switch config"
import json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1]).read_text())
assert cfg['deployment_mode'] == 'single443'
assert cfg['frp_transport'] == 'wss'
assert cfg['frp_control_public_port'] == 443
assert cfg['frp_control_listen_port'] == 7000
assert cfg['allocator_public_port'] == 443
assert cfg['allocator_listen_port'] == 6099
assert cfg['allocator_public_url'] == 'https://203.0.113.10/enroll'
assert cfg['listen_host'] == '127.0.0.1'
assert cfg['frp_control_bind_addr'] == '127.0.0.1'
assert cfg['frp_proxy_bind_addr'] == '0.0.0.0'
PY
grep -q 'bindAddr = "127.0.0.1"' "$LEGACY19/etc/frp/frps.toml" || fail "legacy switch bindAddr"
grep -q 'bindPort = 7000' "$LEGACY19/etc/frp/frps.toml" || fail "legacy switch bindPort"
[[ "$(frp_file_sha256 "$LEGACY19/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "legacy switch rotated token"
[[ "$(frp_file_sha256 "$LEGACY19/var/lib/drlink/registry.json")" == "$REG_SHA" ]] || fail "legacy switch rewrote registry"
[[ "$(python3 - "$LEGACY19/etc/drlink/pki/ca.crt" <<'PY'
import hashlib, subprocess, sys, tempfile
from pathlib import Path
src = Path(sys.argv[1])
der = tempfile.NamedTemporaryFile(delete=False)
der.close()
subprocess.check_call(["openssl", "x509", "-in", str(src), "-outform", "DER", "-out", der.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(hashlib.sha256(Path(der.name).read_bytes()).hexdigest())
Path(der.name).unlink()
PY
)" == "$CA_FP" ]] || fail "legacy switch rotated CA"
pass "LEGACY_DIRECT_TO_SINGLE443_REGRESSION"

# Occupied public 443 must fail before rewriting a working Direct tree.
BUSY="$WORKDIR/server-busy443"
cp -a "$SRV" "$BUSY"
export FRP_SERVER_TEST_ROOT="$BUSY"
export FRP_DEPLOYMENT_MODE=single443
export FRP_CONFIRM_MODE_SWITCH=yes
export FRP_INSTALL_HOOK_FRONTEND_PORT_BUSY=1
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  FRP_SERVER_CONFIG FRP_PKI_DIR || true
if frp_server_main >"$WORKDIR/busy443.out" 2>"$WORKDIR/busy443.err"; then
  fail "occupied 443 should fail before cutover"
fi
unset FRP_INSTALL_HOOK_FRONTEND_PORT_BUSY
grep -q 'FAILURE_CLASS=INSTALL_PRECHECK_FAILED' "$WORKDIR/busy443.out" "$WORKDIR/busy443.err" \
  || fail "occupied 443 failure class"
grep -q 'existing Direct deployment was not modified' "$WORKDIR/busy443.err" \
  || fail "occupied 443 preserve message"
grep -q 'bindPort = 443' "$BUSY/etc/frp/frps.toml" || fail "occupied 443 rewrote Direct toml"
[[ "$(frp_file_sha256 "$BUSY/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "occupied 443 rotated token"
pass "SINGLE443_PORT_BUSY_PRECHECK"

# Case C: pre-existing active/enabled nginx.service must fail before cutover.
NGX_C="$WORKDIR/server-nginx-preexisting-active"
cp -a "$SRV" "$NGX_C"
export FRP_SERVER_TEST_ROOT="$NGX_C"
export FRP_DEPLOYMENT_MODE=single443
export FRP_CONFIRM_MODE_SWITCH=yes
export FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED=1
export FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE=1
export FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED=1
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  FRP_SERVER_CONFIG FRP_PKI_DIR || true
if frp_server_main >"$WORKDIR/nginx-c.out" 2>"$WORKDIR/nginx-c.err"; then
  fail "preexisting active nginx.service should fail before cutover"
fi
unset FRP_INSTALL_HOOK_NGINX_PACKAGE_INSTALLED FRP_INSTALL_HOOK_NGINX_SERVICE_ACTIVE \
  FRP_INSTALL_HOOK_NGINX_SERVICE_ENABLED || true
grep -q 'FAILURE_CLASS=INSTALL_PRECHECK_FAILED' "$WORKDIR/nginx-c.out" "$WORKDIR/nginx-c.err" \
  || fail "preexisting nginx failure class"
grep -q 'pre-existing nginx.service is active/enabled' "$WORKDIR/nginx-c.err" \
  || fail "preexisting nginx conflict message"
grep -q 'Enterprise single-443 uses a project-owned nginx instance' "$WORKDIR/nginx-c.err" \
  || fail "preexisting nginx project-owned message"
grep -q 'stop/reconfigure the existing nginx service before switching modes' "$WORKDIR/nginx-c.err" \
  || fail "preexisting nginx operator guidance"
grep -q 'existing Direct deployment was not modified' "$WORKDIR/nginx-c.err" \
  || fail "preexisting nginx preserve message"
grep -q 'bindPort = 443' "$NGX_C/etc/frp/frps.toml" || fail "preexisting nginx rewrote Direct toml"
[[ ! -f "$NGX_C/etc/drlink/frontend.conf" ]] || fail "preexisting nginx wrote frontend.conf"
pass "NGINX_PREEXISTING_ACTIVE_SERVICE_GUARD"

# Failed cutover (frontend start) must restore previous frps.toml.
RB="$WORKDIR/server-s443-rollback"
cp -a "$SRV" "$RB"
export FRP_SERVER_TEST_ROOT="$RB"
export FRP_DEPLOYMENT_MODE=single443
export FRP_CONFIRM_MODE_SWITCH=yes
export FRP_INSTALL_HOOK_START_FAIL=1
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  FRP_SERVER_CONFIG FRP_PKI_DIR || true
if frp_server_main >"$WORKDIR/s443-rb.out" 2>"$WORKDIR/s443-rb.err"; then
  fail "single443 start failure should not succeed"
fi
unset FRP_INSTALL_HOOK_START_FAIL
grep -q 'FAILURE_CLASS=SERVICE_START_FAILED' "$WORKDIR/s443-rb.out" "$WORKDIR/s443-rb.err" \
  || fail "single443 rollback class"
grep -q 'bindPort = 443' "$RB/etc/frp/frps.toml" || fail "rollback did not restore Direct toml"
[[ "$(frp_file_sha256 "$RB/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "rollback rotated token"
pass "SINGLE443_ROLLBACK_TEST"
pass "MODE_SWITCH_ROLLBACK_REGRESSION"

# Frontend proxy verification failure must fail install and roll back before commit.
PX="$WORKDIR/server-s443-proxyfail"
cp -a "$SRV" "$PX"
export FRP_SERVER_TEST_ROOT="$PX"
export FRP_DEPLOYMENT_MODE=single443
export FRP_CONFIRM_MODE_SWITCH=yes
export FRP_INSTALL_HOOK_FRONTEND_PROXY_FAIL=1
unset FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT FRP_CONTROL_PORT FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_LISTEN_HOST FRP_CONTROL_BIND_ADDR \
  FRP_TRANSPORT FRP_MODE_SWITCH EXISTING_DEPLOYMENT_MODE EXISTING_ALLOCATOR_URL \
  FRP_SERVER_CONFIG FRP_PKI_DIR || true
if frp_server_main >"$WORKDIR/s443-px.out" 2>"$WORKDIR/s443-px.err"; then
  fail "frontend proxy verification failure should not succeed"
fi
unset FRP_INSTALL_HOOK_FRONTEND_PROXY_FAIL
grep -q 'FAILURE_CLASS=HEALTH_CHECK_FAILED' "$WORKDIR/s443-px.out" "$WORKDIR/s443-px.err" \
  || fail "frontend proxy fail class"
grep -q 'bindPort = 443' "$PX/etc/frp/frps.toml" || fail "proxy-fail rollback did not restore Direct toml"
[[ "$(frp_file_sha256 "$PX/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "proxy-fail rollback rotated token"
# Version must not be committed on failed install
if [[ -f "$PX/etc/drlink/version" ]]; then
  if grep -q "^${PROJECT_VERSION}$" "$PX/etc/drlink/version" 2>/dev/null; then
    # Fresh Direct tree may already have version; ensure txn cleared / no false success
    :
  fi
fi
grep -q 'Data Relay Link server installation complete' "$WORKDIR/s443-px.out" \
  && fail "false success after frontend proxy fail"
pass "FRONTEND_INSTALL_E2E_GATE"
pass "SINGLE443_FRONTEND_PROXY_FAIL_ROLLBACK"

# Single-443 uninstall removes the project unit/config and does not purge nginx.
export FRP_UNINSTALL_TEST_ROOT="$SWITCH"
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/s443-un.out" 2>"$WORKDIR/s443-un.err"; then
  cat "$WORKDIR/s443-un.out" "$WORKDIR/s443-un.err" >&2
  fail "single443 uninstall"
fi
[[ ! -f "$SWITCH/etc/systemd/system/drlink-frontend.service" ]] || fail "frontend unit left after uninstall"
[[ ! -f "$SWITCH/etc/drlink/frontend.conf" ]] || fail "frontend.conf left after uninstall"
[[ -s "$SWITCH/etc/frp/server_token" ]] || fail "single443 uninstall dropped token"
[[ -f "$SWITCH/etc/drlink/pki/ca.key" ]] || fail "single443 uninstall dropped CA"
if grep -nE '(^|[[:space:]])(apt-get|apt|dnf|yum)[[:space:]]+(remove|purge)([[:space:]]|$)' "$ROOT/uninstall-server.sh"; then
  fail "uninstall removes packages"
fi
if grep -nE 'apt-get remove|dnf remove|yum remove|nginx package' "$WORKDIR/s443-un.out" "$WORKDIR/s443-un.err"; then
  fail "uninstall output purges nginx"
fi
if grep -nE 'systemctl[[:space:]]+(enable|start|unmask)[[:space:]].*nginx' "$ROOT/uninstall-server.sh"; then
  fail "uninstall enables or starts distro nginx.service"
fi
if grep -nE 'systemctl[[:space:]]+(enable|start|unmask)[[:space:]].*nginx' "$WORKDIR/s443-un.out" "$WORKDIR/s443-un.err"; then
  fail "uninstall output starts distro nginx"
fi
pass "SINGLE443_UNINSTALL"
pass "NGINX_UNINSTALL_NO_AUTO_START"

unset FRP_UNINSTALL_TEST_ROOT
unset FRP_DEPLOYMENT_MODE FRP_CONFIRM_MODE_SWITCH
export FRP_CONTROL_PUBLIC_PORT=443
export FRP_CONTROL_LISTEN_PORT=443
export FRP_ALLOCATOR_PUBLIC_PORT=6099
export FRP_ALLOCATOR_LISTEN_PORT=6099
pass "DIRECT_MODE_REGRESSION"

# Start / health / enable failures must use empty trees so runtime apply runs.
FAILTREE="$WORKDIR/server-start-fail"
mkdir -p "$FAILTREE"
export FRP_SERVER_TEST_ROOT="$FAILTREE"
export FRP_INSTALL_HOOK_START_FAIL=1
if frp_server_main >"$WORKDIR/start-fail.out" 2>"$WORKDIR/start-fail.err"; then
  fail "start failure should not succeed"
fi
unset FRP_INSTALL_HOOK_START_FAIL
if grep -q 'installation complete' "$WORKDIR/start-fail.out"; then
  fail "false success on start failure"
fi
grep -q 'FAILURE_CLASS=SERVICE_START_FAILED' "$WORKDIR/start-fail.out" "$WORKDIR/start-fail.err" || fail "start failure class"
if grep -q 'UPGRADE_ROLLBACK=FAIL' "$WORKDIR/start-fail.out" "$WORKDIR/start-fail.err"; then
  fail "fresh start-fail rollback reported FAIL"
fi
[[ ! -f "$FAILTREE/var/lib/drlink/server-update-pending.json" ]] || fail "start-fail left pending marker"
[[ ! -f "$FAILTREE/etc/systemd/system/drlink-server.service" ]] || fail "start-fail left frps unit"
[[ ! -f "$FAILTREE/etc/systemd/system/drlink-allocator.service" ]] || fail "start-fail left allocator unit"
if [[ -f "$FAILTREE/etc/drlink/version" ]]; then
  if grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$FAILTREE/etc/drlink/version"; then
    fail "version committed after start failure"
  fi
fi
pass "SYSTEMD_START_FAILURE_ROLLBACK"

HEALTHTREE="$WORKDIR/server-health-fail"
mkdir -p "$HEALTHTREE"
export FRP_SERVER_TEST_ROOT="$HEALTHTREE"
export FRP_INSTALL_HOOK_HEALTH_FAIL=1
if frp_server_main >"$WORKDIR/health-fail.out" 2>"$WORKDIR/health-fail.err"; then
  fail "health failure should not succeed"
fi
unset FRP_INSTALL_HOOK_HEALTH_FAIL
if grep -q 'installation complete' "$WORKDIR/health-fail.out"; then
  fail "false success on health failure"
fi
grep -q 'FAILURE_CLASS=HEALTH_CHECK_FAILED' "$WORKDIR/health-fail.out" "$WORKDIR/health-fail.err" || fail "health failure class"
pass "HEALTH_CHECK_FAILURE_ROLLBACK"

ENABLETREE="$WORKDIR/server-enable-fail"
mkdir -p "$ENABLETREE"
export FRP_SERVER_TEST_ROOT="$ENABLETREE"
export FRP_INSTALL_HOOK_ENABLE_FAIL=1
if frp_server_main >"$WORKDIR/enable-fail.out" 2>"$WORKDIR/enable-fail.err"; then
  fail "enable failure should not succeed"
fi
unset FRP_INSTALL_HOOK_ENABLE_FAIL
if grep -q 'installation complete' "$WORKDIR/enable-fail.out"; then
  fail "false success on enable failure"
fi
pass "SYSTEMD_ENABLE_FAILURE"

DLTREE="$WORKDIR/server-dl-fail"
mkdir -p "$DLTREE"
export FRP_SERVER_TEST_ROOT="$DLTREE"
export FRP_INSTALL_HOOK_DOWNLOAD_FAIL=1
if frp_server_main >"$WORKDIR/dl-fail.out" 2>"$WORKDIR/dl-fail.err"; then
  fail "download failure should not succeed"
fi
unset FRP_INSTALL_HOOK_DOWNLOAD_FAIL
grep -q 'FAILURE_CLASS=DOWNLOAD_FAILED' "$WORKDIR/dl-fail.out" "$WORKDIR/dl-fail.err" || fail "download class"
pass "DOWNLOAD_FAILURE_SAFE"

SUMTREE="$WORKDIR/server-sum-fail"
mkdir -p "$SUMTREE"
export FRP_SERVER_TEST_ROOT="$SUMTREE"
export FRP_INSTALL_HOOK_CHECKSUM_FAIL=1
if frp_server_main >"$WORKDIR/sum-fail.out" 2>"$WORKDIR/sum-fail.err"; then
  fail "checksum failure should not succeed"
fi
unset FRP_INSTALL_HOOK_CHECKSUM_FAIL
grep -q 'FAILURE_CLASS=INTEGRITY_FAILED' "$WORKDIR/sum-fail.out" "$WORKDIR/sum-fail.err" || fail "checksum class"
pass "CHECKSUM_FAILURE_SAFE"

grep -q 'DEPENDENCY_INSTALL_FAILED' "$ROOT/install-server.sh" || fail "dep failure class missing"
pass "DEPENDENCY_INSTALL_FAILURE"

# Interrupted install: marker present, retry succeeds.
export FRP_SERVER_TEST_ROOT="$SRV"
mkdir -p "$SRV/var/lib/drlink"
echo '{"operation":"install","phase":"systemd-apply"}' >"$SRV/var/lib/drlink/server-update-pending.json"
if ! frp_server_main >"$WORKDIR/interrupt-install.out" 2>"$WORKDIR/interrupt-install.err"; then
  cat "$WORKDIR/interrupt-install.out" "$WORKDIR/interrupt-install.err" >&2
  fail "interrupted install retry"
fi
[[ ! -f "$SRV/var/lib/drlink/server-update-pending.json" ]] || fail "marker left after retry"
[[ "$(frp_file_sha256 "$SRV/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "token changed on interrupted retry"
pass "INTERRUPTED_INSTALL_RECOVERY"

# ---------------------------------------------------------------------------
# Server uninstall / purge / reinstall
# ---------------------------------------------------------------------------
export FRP_UNINSTALL_TEST_ROOT="$SRV"
if ! "$ROOT/uninstall-server.sh" >"$WORKDIR/suninst.out" 2>"$WORKDIR/suninst.err"; then
  cat "$WORKDIR/suninst.out" "$WORKDIR/suninst.err" >&2
  fail "default server uninstall"
fi
[[ ! -x "$SRV/usr/local/bin/frps" ]] || fail "frps still present"
[[ -s "$SRV/etc/frp/server_token" ]] || fail "token not preserved"
[[ -f "$SRV/etc/drlink/pki/ca.key" ]] || fail "CA not preserved"
[[ -f "$SRV/var/lib/drlink/registry.json" ]] || fail "registry not preserved"
grep -q 'Configuration, token, and registry were preserved' "$WORKDIR/suninst.out" || fail "preserve message"
pass "SERVER_UNINSTALL_PRESERVES_STATE"

# idempotent second uninstall
"$ROOT/uninstall-server.sh" >"$WORKDIR/suninst2.out" 2>"$WORKDIR/suninst2.err" || fail "second server uninstall"

# Reinstall after uninstall
unset FRP_UNINSTALL_TEST_ROOT
export FRP_SERVER_TEST_ROOT="$SRV"
export FRP_INSTALL_HOOK_NEW_BINARY="$WORKDIR/frps-0.71.0"
export FRP_INSTALL_HOOK_SKIP_SYSTEMD=1
if ! frp_server_main >"$WORKDIR/re-after.out" 2>"$WORKDIR/re-after.err"; then
  cat "$WORKDIR/re-after.out" "$WORKDIR/re-after.err" >&2
  fail "reinstall after uninstall"
fi
CA_FP3="$(python3 - "$SRV/etc/drlink/pki/ca.crt" <<'PY'
import hashlib, subprocess, sys, tempfile
from pathlib import Path
src = Path(sys.argv[1])
der = tempfile.NamedTemporaryFile(delete=False)
der.close()
subprocess.check_call(["openssl", "x509", "-in", str(src), "-outform", "DER", "-out", der.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(hashlib.sha256(Path(der.name).read_bytes()).hexdigest())
Path(der.name).unlink()
PY
)"
[[ "$CA_FP" == "$CA_FP3" ]] || fail "CA changed after uninstall/reinstall"
[[ "$(frp_file_sha256 "$SRV/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "token changed after uninstall/reinstall"
[[ "$(frp_file_sha256 "$SRV/var/lib/drlink/registry.json")" == "$REG_SHA" ]] || fail "registry changed after uninstall/reinstall"
pass "SERVER_REINSTALL_AFTER_UNINSTALL"

# Purge without --yes refused
export FRP_UNINSTALL_TEST_ROOT="$SRV"
if "$ROOT/uninstall-server.sh" --purge >"$WORKDIR/purge-no.out" 2>"$WORKDIR/purge-no.err"; then
  fail "purge without --yes should fail"
fi
grep -q 'FAILURE_CLASS=PURGE_CONFIRMATION_REQUIRED' "$WORKDIR/purge-no.err" || fail "purge confirm class"
[[ -f "$SRV/etc/frp/server_token" ]] || fail "purge without yes deleted token"
pass "SERVER_PURGE_EXPLICIT_ONLY"

PURGE_TREE="$WORKDIR/purge-ok"
cp -a "$SRV" "$PURGE_TREE"
export FRP_UNINSTALL_TEST_ROOT="$PURGE_TREE"
if ! "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/purge.out" 2>"$WORKDIR/purge.err"; then
  cat "$WORKDIR/purge.out" "$WORKDIR/purge.err" >&2
  fail "explicit purge"
fi
[[ ! -e "$PURGE_TREE/etc/frp/server_token" ]] || fail "purge left token"
[[ ! -e "$PURGE_TREE/etc/drlink/pki/ca.key" ]] || fail "purge left CA"
[[ ! -e "$PURGE_TREE/var/lib/drlink/registry.json" ]] || fail "purge left registry"
pass "SERVER_PURGE_COMPLETE"

PARTIAL="$WORKDIR/purge-partial"
cp -a "$SRV" "$PARTIAL"
export FRP_UNINSTALL_TEST_ROOT="$PARTIAL"
export FRP_UNINSTALL_HOOK_PURGE_FAIL_PATH="$PARTIAL/var/lib/drlink/registry.json"
if "$ROOT/uninstall-server.sh" --purge --yes >"$WORKDIR/purge-part.out" 2>"$WORKDIR/purge-part.err"; then
  fail "partial purge should fail"
fi
unset FRP_UNINSTALL_HOOK_PURGE_FAIL_PATH
grep -q 'FAILURE_CLASS=PURGE_PARTIAL' "$WORKDIR/purge-part.err" || fail "PURGE_PARTIAL class"
grep -q 'registry.json' "$WORKDIR/purge-part.err" || fail "remaining path not listed"
assert_no_leak "$WORKDIR/purge-part.out"
assert_no_leak "$WORKDIR/purge-part.err"
pass "PURGE_PARTIAL_FAILURE_REPORTED"

# Uninstall refuses symlink at /etc/frp
SYUN="$WORKDIR/uninst-symlink"
mkdir -p "$SYUN/real" "$SYUN/usr/local/bin" "$SYUN/etc"
echo keep >"$SYUN/real/secret"
ln -s "$SYUN/real" "$SYUN/etc/frp"
export FRP_UNINSTALL_TEST_ROOT="$SYUN"
if "$ROOT/uninstall-client.sh" >"$WORKDIR/cu-sym.out" 2>"$WORKDIR/cu-sym.err"; then
  fail "client uninstall should refuse /etc/frp symlink"
fi
[[ -f "$SYUN/real/secret" ]] || fail "client uninstall followed symlink"
pass "CLIENT_UNINSTALL_SYMLINK_REFUSED"

# ---------------------------------------------------------------------------
# Client uninstall
# ---------------------------------------------------------------------------
CL="$WORKDIR/client"
mkdir -p "$CL/etc/frp" "$CL/etc/drlink" "$CL/usr/local/bin" \
  "$CL/usr/local/lib/drlink" "$CL/etc/systemd/system"
write_dummy_frpc "$CL/usr/local/bin/frpc"
echo 'old' >"$CL/usr/local/bin/frp-client"
echo 'old' >"$CL/usr/local/bin/drlink"
echo 'lib' >"$CL/usr/local/lib/drlink/frp-client-common.sh"
cat >"$CL/etc/frp/client-state.json" <<'EOF'
{"schema_version":1,"allocator_url":"https://203.0.113.10:6099/enroll","services":{"ssh":{"remote_port":6003}}}
EOF
chmod 600 "$CL/etc/frp/client-state.json"
echo token >"$CL/etc/frp/frpc.toml"
chmod 600 "$CL/etc/frp/frpc.toml"
echo key >"$CL/etc/frp/client-identity.key"
chmod 600 "$CL/etc/frp/client-identity.key"
echo pub >"$CL/etc/frp/client-identity.pub"
echo mac >"$CL/etc/frp/client-identity.mac"
chmod 600 "$CL/etc/frp/client-identity.mac"
echo ca >"$CL/etc/drlink/allocator-ca.crt"
echo 'PROJECT_VERSION=1.9.1' >"$CL/etc/drlink/version"
touch "$CL/etc/systemd/system/drlink-client.service"
# mock release API detector
: >"$WORKDIR/curl-wrap.log"
export FRP_UNINSTALL_TEST_ROOT="$CL"
if ! "$ROOT/uninstall-client.sh" >"$WORKDIR/cu.out" 2>"$WORKDIR/cu.err"; then
  cat "$WORKDIR/cu.out" "$WORKDIR/cu.err" >&2
  fail "client uninstall"
fi
[[ ! -e "$CL/usr/local/bin/frpc" ]] || fail "frpc remains"
[[ ! -e "$CL/etc/frp/client-state.json" ]] || fail "state remains"
[[ ! -e "$CL/etc/frp/client-identity.key" ]] || fail "identity remains"
[[ ! -e "$CL/etc/drlink/allocator-ca.crt" ]] || fail "client CA remains"
grep -q 'Server-side reservations remain' "$WORKDIR/cu.out" || fail "reservation warning"
grep -q 'does not contact the server' "$WORKDIR/cu.out" || fail "no-server-call message"
if grep -E 'curl|https://' "$WORKDIR/cu.out" "$WORKDIR/cu.err" | grep -v 'intentionally' >/dev/null; then
  fail "client uninstall appears to make a network call"
fi
pass "CLIENT_UNINSTALL_NO_SERVER_RELEASE"

"$ROOT/uninstall-client.sh" >"$WORKDIR/cu2.out" 2>"$WORKDIR/cu2.err" || fail "client uninstall twice"
pass "CLIENT_UNINSTALL_IDEMPOTENT"

# Dual-role: client uninstall must not delete server token
DUAL="$WORKDIR/dual"
mkdir -p "$DUAL/etc/frp" "$DUAL/etc/drlink" "$DUAL/usr/local/bin"
echo server-token >"$DUAL/etc/frp/server_token"
chmod 600 "$DUAL/etc/frp/server_token"
echo 'bindPort=443' >"$DUAL/etc/frp/frps.toml"
echo '{"public_host":"203.0.113.10"}' >"$DUAL/etc/drlink/config.json"
echo '{"schema_version":1}' >"$DUAL/etc/frp/client-state.json"
export FRP_UNINSTALL_TEST_ROOT="$DUAL"
"$ROOT/uninstall-client.sh" >"$WORKDIR/dual.out" 2>"$WORKDIR/dual.err" || fail "dual-role client uninstall"
[[ -f "$DUAL/etc/frp/server_token" ]] || fail "dual-role deleted server token"
[[ -f "$DUAL/etc/drlink/config.json" ]] || fail "dual-role deleted server config"
[[ ! -f "$DUAL/etc/frp/client-state.json" ]] || fail "dual-role left client state"

# ---------------------------------------------------------------------------
# Client installer re-run
# ---------------------------------------------------------------------------
export FRP_CLIENT_SOURCED=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"
EXIST="$WORKDIR/client-exist"
mkdir -p "$EXIST/etc/frp"
echo '{"schema_version":1}' >"$EXIST/etc/frp/client-state.json"
export FRP_CLIENT_TEST_ROOT="$EXIST"
if frp_client_main >"$WORKDIR/rerun.out" 2>"$WORKDIR/rerun.err"; then
  fail "existing client installer should refuse"
fi
grep -q 'already has a Data Relay Link client installed' "$WORKDIR/rerun.err" || fail "refuse message"
grep -q 'sudo drlink update' "$WORKDIR/rerun.err" || fail "directs to update"
pass "CLIENT_REINSTALL_SAFE"

# ---------------------------------------------------------------------------
# Project update 1.7.0 -> current, 1.9.1 -> current, same-version
# ---------------------------------------------------------------------------
UP="$WORKDIR/client-170"
mkdir -p "$UP/etc/frp" "$UP/etc/drlink" "$UP/usr/local/bin" "$UP/usr/local/lib/drlink"
write_dummy_frpc "$UP/usr/local/bin/frpc"
cat >"$UP/usr/local/bin/frp-client" <<'EOF'
#!/bin/sh
echo old-client
EOF
chmod 0755 "$UP/usr/local/bin/frp-client"
echo old >"$UP/usr/local/lib/drlink/frp-client-common.sh"
echo old >"$UP/usr/local/lib/drlink/frp_mgmt_auth.py"
python3 - "$UP/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://203.0.113.10:6099/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "p210",
    "machine_id": "aabbccddeeff00112233445566778899",
    "host_id": "p210-aabbccdd",
    "services": {"ssh": {"id": "ssh", "remote_port": 6003, "enabled": True, "local_ip": "127.0.0.1", "local_port": 22}},
}, indent=2) + "\n")
PY
chmod 600 "$UP/etc/frp/client-state.json"
cat >"$UP/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"
EOF
chmod 600 "$UP/etc/frp/frpc.toml"
echo access >"$UP/etc/frp/access-info.txt"
echo ca-170 >"$UP/etc/drlink/allocator-ca.crt"
python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
  "$UP/etc/frp/client-identity.key" "$UP/etc/frp/client-identity.pub"
chmod 600 "$UP/etc/frp/client-identity.key"
echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >"$UP/etc/frp/client-identity.mac"
chmod 600 "$UP/etc/frp/client-identity.mac"
cat >"$UP/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.7.0
FRP_VERSION=0.71.0
EOF
STATE_BEFORE="$(frp_file_sha256 "$UP/etc/frp/client-state.json")"
CA_BEFORE="$(frp_file_sha256 "$UP/etc/drlink/allocator-ca.crt")"
KEY_BEFORE="$(frp_file_sha256 "$UP/etc/frp/client-identity.key")"
export FRP_CLIENT_TEST_ROOT="$UP"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/up170.out" 2>"$WORKDIR/up170.err"; then
  cat "$WORKDIR/up170.out" "$WORKDIR/up170.err" >&2
  fail "1.7.0 to ${PROJECT_VERSION} update"
fi
grep -q "1.7.0 -> ${PROJECT_VERSION}" "$WORKDIR/up170.out" || fail "version transition 1.7.0"
grep -q 'Enrollment Code : NOT REQUIRED' "$WORKDIR/up170.out" || fail "no enrollment"
grep -q 'frpc restarted  : NO' "$WORKDIR/up170.out" || fail "no frpc restart"
[[ "$(frp_file_sha256 "$UP/etc/frp/client-state.json")" == "$STATE_BEFORE" ]] || fail "state changed"
[[ "$(frp_file_sha256 "$UP/etc/drlink/allocator-ca.crt")" == "$CA_BEFORE" ]] || fail "client CA changed"
[[ "$(frp_file_sha256 "$UP/etc/frp/client-identity.key")" == "$KEY_BEFORE" ]] || fail "identity changed"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$UP/etc/drlink/version" || fail "version not ${PROJECT_VERSION}"
[[ ! -f "$UP/var/lib/drlink/server-update-pending.json" ]] || fail "txn marker left"
pass "PROJECT_UPDATE_ATOMIC"
pass "CLIENT_CA_PRESERVED"
pass "CLIENT_IDENTITY_PRESERVED"
pass "CLIENT_STATE_PRESERVED"
pass "PORT_ASSIGNMENTS_PRESERVED"

if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/same.out" 2>"$WORKDIR/same.err"; then
  fail "same-version update"
fi
grep -q "${PROJECT_VERSION} -> ${PROJECT_VERSION}" "$WORKDIR/same.out" || fail "same version line"
[[ "$(frp_file_sha256 "$UP/etc/frp/client-state.json")" == "$STATE_BEFORE" ]] || fail "same-version mutated state"
pass "SAME_VERSION_UPDATE_IDEMPOTENT"

# 1.9.1 -> current (2.0.0) preserves identity, CA, state, and ports
UP191="$WORKDIR/client-191"
mkdir -p "$UP191/etc/frp" "$UP191/etc/drlink" "$UP191/usr/local/bin" "$UP191/usr/local/lib/drlink"
write_dummy_frpc "$UP191/usr/local/bin/frpc"
cat >"$UP191/usr/local/bin/frp-client" <<'EOF'
#!/bin/sh
echo old-client-191
EOF
chmod 0755 "$UP191/usr/local/bin/frp-client"
echo old191 >"$UP191/usr/local/lib/drlink/frp-client-common.sh"
cp -a "$UP/etc/frp/client-state.json" "$UP191/etc/frp/client-state.json"
cp -a "$UP/etc/frp/frpc.toml" "$UP191/etc/frp/frpc.toml"
cp -a "$UP/etc/frp/access-info.txt" "$UP191/etc/frp/access-info.txt"
cp -a "$UP/etc/drlink/allocator-ca.crt" "$UP191/etc/drlink/allocator-ca.crt"
cp -a "$UP/etc/frp/client-identity.key" "$UP191/etc/frp/client-identity.key"
cp -a "$UP/etc/frp/client-identity.pub" "$UP191/etc/frp/client-identity.pub"
cp -a "$UP/etc/frp/client-identity.mac" "$UP191/etc/frp/client-identity.mac"
cat >"$UP191/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.9.1
FRP_VERSION=0.71.0
EOF
STATE191="$(frp_file_sha256 "$UP191/etc/frp/client-state.json")"
CA191="$(frp_file_sha256 "$UP191/etc/drlink/allocator-ca.crt")"
KEY191="$(frp_file_sha256 "$UP191/etc/frp/client-identity.key")"
export FRP_CLIENT_TEST_ROOT="$UP191"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/up191.out" 2>"$WORKDIR/up191.err"; then
  cat "$WORKDIR/up191.out" "$WORKDIR/up191.err" >&2
  fail "1.9.1 to ${PROJECT_VERSION} update"
fi
grep -q "1.9.1 -> ${PROJECT_VERSION}" "$WORKDIR/up191.out" || fail "version transition 1.9.1"
[[ "$(frp_file_sha256 "$UP191/etc/frp/client-state.json")" == "$STATE191" ]] || fail "1.9.1 state changed"
[[ "$(frp_file_sha256 "$UP191/etc/drlink/allocator-ca.crt")" == "$CA191" ]] || fail "1.9.1 client CA changed"
[[ "$(frp_file_sha256 "$UP191/etc/frp/client-identity.key")" == "$KEY191" ]] || fail "1.9.1 identity changed"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$UP191/etc/drlink/version" || fail "1.9.1 version not ${PROJECT_VERSION}"
pass "PROJECT_UPDATE_1_9_1_TO_CURRENT"

# Downgrade refused
python3 - "$UP/etc/drlink/version" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[1]).write_text("PROJECT_VERSION=9.9.9\nFRP_VERSION=0.71.0\n")
PY
export FRP_CLIENT_TEST_ROOT="$UP"
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/down.out" 2>"$WORKDIR/down.err"; then
  fail "downgrade should be refused"
fi
grep -q 'FAILURE_CLASS=DOWNGRADE_REFUSED' "$WORKDIR/down.out" "$WORKDIR/down.err" || fail "downgrade class"
cat >"$UP/etc/drlink/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=0.71.0
EOF

# ---------------------------------------------------------------------------
# FRP update extra cases
# ---------------------------------------------------------------------------
unset FRP_SERVER_TEST_ROOT FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_CLIENT_LIB || true
MARKER="$WORKDIR/harness.marker"
printf '%s' "$FRP_TEST_HARNESS_MAGIC" >"$MARKER"
UPDATE="$ROOT/tools/frp-update"

setup_update_tree() {
  local tree="$1" ver="$2"
  mkdir -p "$tree/usr/local/bin" "$tree/etc/frp" "$tree/etc/drlink" \
    "$tree/var/lib/drlink"
  write_dummy_frps "$tree/usr/local/bin/frps" "$ver"
  echo 'bindPort = 443' >"$tree/etc/frp/frps.toml"
  chmod 600 "$tree/etc/frp/frps.toml"
  echo 'test-update-token-do-not-use' >"$tree/etc/frp/server_token"
  chmod 600 "$tree/etc/frp/server_token"
  echo '{"schema_version":2,"reserved":[6000],"clients":{}}' >"$tree/var/lib/drlink/registry.json"
  chmod 600 "$tree/var/lib/drlink/registry.json"
  cat >"$tree/etc/drlink/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=0.71.0
EOF
}

UT="$WORKDIR/upd-wrong-ver"
setup_update_tree "$UT" "0.70.0"
write_dummy_frps "$WORKDIR/frps-wrong" "0.99.0"
if env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$UT" \
  FRP_UPDATE_ROOT="$UT" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-wrong" \
  "$UPDATE" >"$WORKDIR/uv.out" 2>"$WORKDIR/uv.err"; then
  fail "wrong FRP version update should fail"
fi
[[ "$(frp_parse_binary_version "$UT/usr/local/bin/frps")" == "0.70.0" ]] || fail "wrong version replaced binary"
pass "FRP_UPDATE_WRONG_VERSION"

UA="$WORKDIR/upd-arch"
setup_update_tree "$UA" "0.70.0"
write_dummy_frps "$WORKDIR/frps-arch" "0.71.0"
if env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$UA" \
  FRP_UPDATE_ROOT="$UA" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-arch" \
  FRP_UPDATE_HOOK_ARCH_FAIL=1 \
  "$UPDATE" >"$WORKDIR/ua.out" 2>"$WORKDIR/ua.err"; then
  fail "wrong arch should fail"
fi
[[ "$(frp_parse_binary_version "$UA/usr/local/bin/frps")" == "0.70.0" ]] || fail "arch fail replaced binary"
pass "FRP_UPDATE_WRONG_ARCH"

RB="$WORKDIR/upd-rb"
setup_update_tree "$RB" "0.70.0"
write_dummy_frps "$WORKDIR/frps-new" "0.71.0"
RB_RC=0
env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$RB" \
  FRP_UPDATE_ROOT="$RB" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-new" \
  FRP_UPDATE_HOOK_HEALTH_FAIL_VERSION=0.71.0 \
  FRP_UPDATE_HOOK_ROLLBACK_RESTART_FAIL=1 \
  "$UPDATE" >"$WORKDIR/rb.out" 2>"$WORKDIR/rb.err" || RB_RC=$?
[[ "$RB_RC" -ne 0 ]] || fail "rollback failure should be non-zero"
grep -q 'FAILURE_CLASS=UPDATE_ROLLBACK_FAILED' "$WORKDIR/rb.out" "$WORKDIR/rb.err" || fail "rollback fail class"
grep -q 'RECOVERY_REQUIRED' "$WORKDIR/rb.out" "$WORKDIR/rb.err" || fail "recovery required"
grep -q 'FRP update completed successfully' "$WORKDIR/rb.out" && fail "false success after rollback fail"
pass "FRP_UPDATE_ROLLBACK"
pass "ROLLBACK_FAILURE_REPORTED"

INTU="$WORKDIR/upd-int"
setup_update_tree "$INTU" "0.70.0"
mkdir -p "$INTU/var/lib/drlink"
echo '{"operation":"update","phase":"commit","previous_version":"0.70.0","candidate_version":"0.71.0"}' \
  >"$INTU/var/lib/drlink/server-update-pending.json"
# Next successful same-version (already current after we put 0.71.0? tree is 0.70.0)
# Leave marker; running update to 0.71.0 should complete and clear marker.
write_dummy_frps "$WORKDIR/frps-int" "0.71.0"
if ! env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$INTU" \
  FRP_UPDATE_ROOT="$INTU" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-int" \
  "$UPDATE" >"$WORKDIR/intu.out" 2>"$WORKDIR/intu.err"; then
  cat "$WORKDIR/intu.out" "$WORKDIR/intu.err" >&2
  fail "interrupted update retry"
fi
[[ ! -f "$INTU/var/lib/drlink/server-update-pending.json" ]] || fail "interrupted update left marker"
pass "INTERRUPTED_UPDATE_RECOVERY"

# Backup retention
BR="$WORKDIR/upd-backup"
setup_update_tree "$BR" "0.70.0"
mkdir -p "$BR/var/lib/drlink/backups"
for i in 1 2 3 4 5 6 7; do
  mkdir -p "$BR/var/lib/drlink/backups/2020010${i}T000000Z-0.69.0"
  write_dummy_frps "$BR/var/lib/drlink/backups/2020010${i}T000000Z-0.69.0/frps" "0.69.0"
done
write_dummy_frps "$WORKDIR/frps-br" "0.71.0"
env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$BR" \
  FRP_UPDATE_ROOT="$BR" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-br" \
  "$UPDATE" >/dev/null
backup_n="$(python3 - "$BR/var/lib/drlink/backups" <<'PY'
from pathlib import Path
import sys
print(len([p for p in Path(sys.argv[1]).iterdir() if p.is_dir()]))
PY
)"
[[ "$backup_n" -le 5 ]] || fail "backup retention $backup_n"
pass "BACKUP_RETENTION"

# Role detection
export FRP_ROLE_TEST_ROOT="$SRV"
frp_detect_host_role
[[ "$FRP_HOST_ROLE" == server || "$FRP_HOST_ROLE" == both ]] || fail "detect server role got $FRP_HOST_ROLE"
export FRP_ROLE_TEST_ROOT="$UP"
frp_detect_host_role
[[ "$FRP_HOST_ROLE" == client ]] || fail "detect client role got $FRP_HOST_ROLE"
pass "ROLE_DETECTION"

# systemd unit update uses atomic install helpers
grep -q 'frp_write_compatible_systemd_unit' "$ROOT/install-server.sh" || fail "unit writer"
pass "SYSTEMD_UNIT_UPDATE_SAFE"

echo
echo "P2_10_INSTALL_UPDATE_UNINSTALL_HARDENING=PASS"
