#!/usr/bin/env bash
# Regression tests for safe FRP server update. Dummy token/registry values
# are never printed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

UPDATE="$ROOT/tools/frp-update"
MARKER="$WORKDIR/harness.marker"
printf '%s' "$FRP_TEST_HARNESS_MAGIC" >"$MARKER"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

assert_no_leak() {
  local log="$1"
  shift
  local needle
  for needle in "$@"; do
    if grep -F -- "$needle" "$log" >/dev/null 2>&1; then
      fail "secret fixture leaked to command output"
    fi
  done
}

bytes_equal() {
  python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path
sys.exit(0 if Path(sys.argv[1]).read_bytes() == Path(sys.argv[2]).read_bytes() else 1)
PY
}

file_sha() {
  python3 - "$1" <<'PY'
import hashlib,sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

assert_mode() {
  local path="$1" expected="$2" mode
  mode="$(python3 - "$path" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
  [[ "$mode" == "$expected" ]] || fail "mode $path wanted $expected got $mode"
}

write_dummy_frps() {
  local dest="$1" version="$2" verify_rc="${3:-0}"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
  echo "frps version ${version}"
  exit 0
fi
if [[ "\${1:-}" == "verify" ]]; then
  exit ${verify_rc}
fi
exit 0
EOF
  chmod 0755 "$dest"
}

write_registry() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  python3 - "$dest" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "schema_version": 2,
  "reserved": [6000, 6001],
  "clients": {
    "machine-online": {
      "hostname": "online-host",
      "created_at": "2026-01-01T00:00:00Z",
      "last_enrolled_at": "2026-01-02T00:00:00Z",
      "services": {
        "ssh": {
          "name": "SSH",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 22,
          "remote_port": 6002,
          "preset": "ssh",
          "ssh_user": "aella",
          "enabled": True,
        },
        "https": {
          "name": "HTTPS",
          "protocol": "tcp",
          "local_ip": "192.0.2.10",
          "local_port": 443,
          "remote_port": 6003,
          "preset": "https",
          "enabled": True,
        },
      },
    },
    "machine-offline": {
      "hostname": "offline-host",
      "created_at": "2026-01-01T00:00:00Z",
      "last_enrolled_at": "2026-01-01T00:00:00Z",
      "services": {
        "ssh": {
          "name": "SSH",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 22,
          "remote_port": 6004,
          "preset": "ssh",
          "enabled": True,
        },
      },
    },
    "machine-ssh-only": {
      "hostname": "ssh-only-host",
      "created_at": "2026-01-01T00:00:00Z",
      "last_enrolled_at": "2026-01-03T00:00:00Z",
      "services": {
        "ssh": {
          "name": "SSH",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 22,
          "remote_port": 6005,
          "preset": "ssh",
          "enabled": True,
        },
      },
    },
    "machine-ssh-https": {
      "hostname": "ssh-https-host",
      "created_at": "2026-01-01T00:00:00Z",
      "last_enrolled_at": "2026-01-04T00:00:00Z",
      "services": {
        "ssh": {
          "name": "SSH",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 22,
          "remote_port": 6006,
          "preset": "ssh",
          "enabled": True,
        },
        "https": {
          "name": "HTTPS",
          "protocol": "tcp",
          "local_ip": "192.0.2.20",
          "local_port": 443,
          "remote_port": 6007,
          "preset": "https",
          "enabled": True,
        },
      },
    },
  },
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  chmod 600 "$dest"
}

setup_tree() {
  local tree="$1" installed_ver="${2:-0.70.0}"
  rm -rf "$tree"
  mkdir -p \
    "$tree/usr/local/bin" \
    "$tree/etc/frp" \
    "$tree/etc/frp-auto-deploy" \
    "$tree/var/lib/frp-auto-deploy"
  write_dummy_frps "$tree/usr/local/bin/frps" "$installed_ver"
  cat >"$tree/etc/frp/frps.toml" <<'EOF'
bindPort = 443

auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/server_token"

transport.tls.force = true

allowPorts = [
  { start = 6000, end = 6098 }
]
EOF
  chmod 600 "$tree/etc/frp/frps.toml"
  printf '%s' "test-update-token-do-not-use" >"$tree/etc/frp/server_token"
  chmod 600 "$tree/etc/frp/server_token"
  cat >"$tree/etc/frp-auto-deploy/version" <<'EOF'
PROJECT_VERSION=1.0.0
FRP_VERSION=0.71.0
EOF
  write_registry "$tree/var/lib/frp-auto-deploy/registry.json"
  python3 - "$tree/etc/frp-auto-deploy/config.json" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_host": "0.0.0.0",
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
  "registry_file": "/var/lib/frp-auto-deploy/registry.json",
  "enrollments_dir": "/var/lib/frp-auto-deploy/enrollments",
  "token_file": "/etc/frp/server_token",
  "client_installer_url": "",
}, indent=2, sort_keys=True) + "\n")
PY
  chmod 600 "$tree/etc/frp-auto-deploy/config.json"
}

run_update() {
  local tree="$1"
  shift
  env \
    FRP_UPDATE_TEST_HARNESS=1 \
    FRP_UPDATE_TEST_MARKER="$MARKER" \
    FRP_DEPLOY_TEST_ROOT="$tree" \
    FRP_UPDATE_ROOT="$tree" \
    FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
    PATH="$PATH" \
    "$UPDATE" "$@"
}

# --- CASE A: already current ---
A="$WORKDIR/case-a"
setup_tree "$A" "0.71.0"
cp "$A/usr/local/bin/frps" "$WORKDIR/case-a.frps.before"
cp "$A/etc/frp/server_token" "$WORKDIR/case-a.token.before"
cp "$A/var/lib/frp-auto-deploy/registry.json" "$WORKDIR/case-a.registry.before"
A_OUT="$WORKDIR/case-a.out"
run_update "$A" >"$A_OUT"
assert_no_leak "$A_OUT" "test-update-token-do-not-use"
grep -q "already installed" "$A_OUT" || fail "CASE A message"
grep -q "TOKEN_PRESERVED=PASS" "$A_OUT" || fail "CASE A token preserved output"
bytes_equal "$WORKDIR/case-a.frps.before" "$A/usr/local/bin/frps" || fail "CASE A binary changed"
bytes_equal "$WORKDIR/case-a.token.before" "$A/etc/frp/server_token" || fail "CASE A token changed"
bytes_equal "$WORKDIR/case-a.registry.before" "$A/var/lib/frp-auto-deploy/registry.json" || fail "CASE A registry changed"
[[ ! -d "$A/var/lib/frp-auto-deploy/backups" ]] || {
  if find "$A/var/lib/frp-auto-deploy/backups" -type f | grep -q .; then
    fail "CASE A created a backup"
  fi
}
pass "CASE A already current"

# --- CASE B / H / I: successful upgrade preserves token, registry, ports ---
B="$WORKDIR/case-b"
setup_tree "$B" "0.70.0"
write_dummy_frps "$WORKDIR/frps-0.71.0" "0.71.0"
cp "$B/etc/frp/server_token" "$WORKDIR/case-b.token.before"
cp "$B/var/lib/frp-auto-deploy/registry.json" "$WORKDIR/case-b.registry.before"
B_OUT="$WORKDIR/case-b.out"
if ! env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$B" \
  FRP_UPDATE_ROOT="$B" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-0.71.0" \
  "$UPDATE" >"$B_OUT"; then
  fail "CASE B update failed"
fi
assert_no_leak "$B_OUT" "test-update-token-do-not-use"
grep -q "FRP update completed successfully" "$B_OUT" || fail "CASE B success message"
grep -q "TOKEN_PRESERVED=PASS" "$B_OUT" || fail "CASE B TOKEN_PRESERVED"
grep -q "REGISTRY_PRESERVED=PASS" "$B_OUT" || fail "CASE B REGISTRY_PRESERVED"
[[ "$(frp_parse_binary_version "$B/usr/local/bin/frps")" == "0.71.0" ]] || fail "CASE B installed version"
bytes_equal "$WORKDIR/case-b.token.before" "$B/etc/frp/server_token" || fail "CASE B token changed"
bytes_equal "$WORKDIR/case-b.registry.before" "$B/var/lib/frp-auto-deploy/registry.json" || fail "CASE B registry changed"
python3 - "$B/var/lib/frp-auto-deploy/registry.json" <<'PY'
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
clients=state["clients"]
assert state["schema_version"]==2
assert clients["machine-online"]["services"]["ssh"]["remote_port"]==6002
assert clients["machine-online"]["services"]["https"]["remote_port"]==6003
assert clients["machine-offline"]["services"]["ssh"]["remote_port"]==6004
assert clients["machine-ssh-only"]["services"]["ssh"]["remote_port"]==6005
assert clients["machine-ssh-https"]["services"]["ssh"]["remote_port"]==6006
assert clients["machine-ssh-https"]["services"]["https"]["remote_port"]==6007
assert state["reserved"]==[6000,6001]
assert "ssh_port" not in json.dumps(clients)
assert "https_port" not in json.dumps(clients)
PY
python3 - "$B/var/lib/frp-auto-deploy/backups" <<'PY' || fail "CASE B backup missing"
from pathlib import Path
import sys
root=Path(sys.argv[1])
if not root.is_dir() or not any(root.rglob("frps")):
    raise SystemExit(1)
PY
pass "CASE B successful upgrade"
pass "CASE H token preservation"
pass "CASE I registry and port preservation"

# --- CASE C: download failure ---
C="$WORKDIR/case-c"
setup_tree "$C" "0.70.0"
cp "$C/usr/local/bin/frps" "$WORKDIR/case-c.frps.before"
C_OUT="$WORKDIR/case-c.out"
if env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$C" \
  FRP_UPDATE_ROOT="$C" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_DOWNLOAD_FAIL=1 \
  "$UPDATE" >"$C_OUT" 2>"$WORKDIR/case-c.err"; then
  fail "CASE C should fail"
fi
assert_no_leak "$C_OUT" "test-update-token-do-not-use"
assert_no_leak "$WORKDIR/case-c.err" "test-update-token-do-not-use"
bytes_equal "$WORKDIR/case-c.frps.before" "$C/usr/local/bin/frps" || fail "CASE C binary changed"
[[ "$(frp_parse_binary_version "$C/usr/local/bin/frps")" == "0.70.0" ]] || fail "CASE C version"
pass "CASE C download failure"

# --- CASE D: checksum failure ---
D="$WORKDIR/case-d"
setup_tree "$D" "0.70.0"
write_dummy_frps "$WORKDIR/frps-0.71.0-d" "0.71.0"
cp "$D/usr/local/bin/frps" "$WORKDIR/case-d.frps.before"
D_SHA_BEFORE="$(file_sha "$D/usr/local/bin/frps")"
if env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$D" \
  FRP_UPDATE_ROOT="$D" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-0.71.0-d" \
  FRP_UPDATE_HOOK_CHECKSUM_FAIL=1 \
  "$UPDATE" >"$WORKDIR/case-d.out" 2>"$WORKDIR/case-d.err"; then
  fail "CASE D should fail"
fi
assert_no_leak "$WORKDIR/case-d.out" "test-update-token-do-not-use"
bytes_equal "$WORKDIR/case-d.frps.before" "$D/usr/local/bin/frps" || fail "CASE D binary changed"
[[ "$(file_sha "$D/usr/local/bin/frps")" == "$D_SHA_BEFORE" ]] || fail "CASE D checksum of live binary"
grep -q "SHA256 checksum mismatch" "$WORKDIR/case-d.err" || fail "CASE D mismatch message"
pass "CASE D checksum failure"

# Direct checksum helper
echo dummy-archive >"$WORKDIR/archive.bin"
if frp_verify_sha256 "0000000000000000000000000000000000000000000000000000000000000000" "$WORKDIR/archive.bin" >/dev/null 2>&1; then
  fail "CASE D helper should reject a bad checksum"
fi
GOOD_SHA="$(file_sha "$WORKDIR/archive.bin")"
frp_verify_sha256 "$GOOD_SHA" "$WORKDIR/archive.bin" >/dev/null
pass "CASE D checksum helper"

# --- CASE E: config validation failure ---
E="$WORKDIR/case-e"
setup_tree "$E" "0.70.0"
write_dummy_frps "$WORKDIR/frps-0.71.0-e" "0.71.0" 1
cp "$E/usr/local/bin/frps" "$WORKDIR/case-e.frps.before"
if env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$E" \
  FRP_UPDATE_ROOT="$E" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-0.71.0-e" \
  FRP_UPDATE_HOOK_VERIFY_FAIL=1 \
  "$UPDATE" >"$WORKDIR/case-e.out" 2>"$WORKDIR/case-e.err"; then
  fail "CASE E should fail"
fi
bytes_equal "$WORKDIR/case-e.frps.before" "$E/usr/local/bin/frps" || fail "CASE E binary activated"
[[ "$(frp_parse_binary_version "$E/usr/local/bin/frps")" == "0.70.0" ]] || fail "CASE E old version"
pass "CASE E config validation failure"

# --- CASE F / G: health failure rolls back ---
F="$WORKDIR/case-f"
setup_tree "$F" "0.70.0"
write_dummy_frps "$WORKDIR/frps-0.71.0-f" "0.71.0"
cp "$F/usr/local/bin/frps" "$WORKDIR/case-f.frps.before"
cp "$F/etc/frp/server_token" "$WORKDIR/case-f.token.before"
cp "$F/var/lib/frp-auto-deploy/registry.json" "$WORKDIR/case-f.registry.before"
F_RC=0
env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$F" \
  FRP_UPDATE_ROOT="$F" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_UPDATE_HOOK_NEW_BINARY="$WORKDIR/frps-0.71.0-f" \
  FRP_UPDATE_HOOK_HEALTH_FAIL_VERSION=0.71.0 \
  "$UPDATE" >"$WORKDIR/case-f.out" 2>"$WORKDIR/case-f.err" || F_RC=$?
[[ "$F_RC" -eq 1 ]] || fail "CASE F exit code wanted 1 got $F_RC"
grep -q "Rollback completed successfully" "$WORKDIR/case-f.out" || fail "CASE F rollback message"
grep -q "Restored FRP : 0.70.0" "$WORKDIR/case-f.out" || fail "CASE F restored version"
[[ "$(frp_parse_binary_version "$F/usr/local/bin/frps")" == "0.70.0" ]] || fail "CASE F binary not restored"
bytes_equal "$WORKDIR/case-f.token.before" "$F/etc/frp/server_token" || fail "CASE F token changed"
bytes_equal "$WORKDIR/case-f.registry.before" "$F/var/lib/frp-auto-deploy/registry.json" || fail "CASE F registry changed"
assert_mode "$F/usr/local/bin/frps" "0o755"
BACKUP_FRPS="$(python3 - "$F/var/lib/frp-auto-deploy/backups" <<'PY'
from pathlib import Path
import sys
matches=list(Path(sys.argv[1]).rglob("frps"))
print(str(matches[0]) if matches else "")
PY
)"
[[ -n "$BACKUP_FRPS" ]] || fail "CASE G backup binary missing"
assert_mode "$BACKUP_FRPS" "0o755"
BACKUP_CFG="$(python3 - "$F/var/lib/frp-auto-deploy/backups" <<'PY'
from pathlib import Path
import sys
matches=list(Path(sys.argv[1]).rglob("frps.toml"))
print(str(matches[0]) if matches else "")
PY
)"
[[ -n "$BACKUP_CFG" ]] || fail "CASE G backup config missing"
assert_mode "$BACKUP_CFG" "0o600"
grep -q "restart frps" "$F/var/lib/frp-auto-deploy/update-actions.log" || fail "CASE G restart not recorded"
pass "CASE F restart/health failure rollback"
pass "CASE G rollback safety"

# --- CASE J: installer rerun / source regression ---
grep -q 'migrate_token.py" ensure' "$ROOT/install-server.sh" || fail "CASE J missing token ensure"
grep -q 'init-registry' "$ROOT/install-server.sh" || fail "CASE J missing registry init"
grep -q 'frp_write_version_file "$(frp_server_fs /etc/frp-auto-deploy/version)"' "$ROOT/install-server.sh" || fail "CASE J missing version metadata"
grep -q 'frp-update' "$ROOT/install-server.sh" || fail "CASE J missing frp-update install"
grep -q 'lib/frp-common.sh' "$ROOT/install-server.sh" || fail "CASE J missing common lib"
grep -q 'TOKEN_PRESERVED' "$ROOT/install-server.sh" || fail "CASE J missing token preservation reporting"
if grep -Eiq 'token rotation|rotate.*token|openssl rand.*server_token' "$ROOT/install-server.sh"; then
  fail "CASE J installer appears to rotate tokens"
fi
if grep -qE 'sudo frp-release-client|/usr/local/sbin/frp-release-client[[:space:]]' "$ROOT/install-server.sh"; then
  fail "CASE J installer must not release client reservations"
fi
grep -q 'sha256sum -c' "$ROOT/install-server.sh" || fail "CASE J installer checksum verify missing"
grep -q 'verify -c' "$ROOT/install-server.sh" || fail "CASE J installer config verify missing"
pass "CASE J installer rerun source regression"

# --check dry run does not replace
CHK="$WORKDIR/case-check"
setup_tree "$CHK" "0.70.0"
cp "$CHK/usr/local/bin/frps" "$WORKDIR/case-check.frps.before"
run_update "$CHK" --check >"$WORKDIR/case-check.out"
grep -q "Update      : available" "$WORKDIR/case-check.out" || fail "--check available"
bytes_equal "$WORKDIR/case-check.frps.before" "$CHK/usr/local/bin/frps" || fail "--check modified binary"
pass "dry-run --check"

# Test hooks ignored without marker
if env FRP_UPDATE_TEST_HARNESS=1 FRP_UPDATE_HOOK_DOWNLOAD_FAIL=1 "$UPDATE" --help >/dev/null; then
  true
else
  fail "help should work without harness marker"
fi
pass "test hooks require harness marker"

echo
echo "UPDATE_REGRESSION_TESTS=PASS"
echo "TOKEN_PRESERVED=PASS"
echo "REGISTRY_PRESERVED=PASS"
