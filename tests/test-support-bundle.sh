#!/usr/bin/env bash
# Support Bundle: sanitized read-only archive unit tests (fixtures only).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export PYTHONDONTWRITEBYTECODE=1
export FRP_SKIP_SYSTEMD=1
export FRP_DOCTOR_SKIP_NETWORK=1
unset FRP_TEST_UNAME_S FRP_TEST_UNAME_M FRP_TEST_MACOS_PRODUCT_VERSION \
  FRP_MACOS_STATE_ROOT FRP_MACOS_PREFIX FRP_MACOS_LAUNCHD_LABEL || true

SB="$ROOT/tools/frp-support-bundle"
LIB="$ROOT/lib/frp_support_bundle.py"
[[ -x "$SB" ]] || chmod +x "$SB"
[[ -f "$LIB" ]] || fail "missing frp_support_bundle.py"

# shellcheck disable=SC1091
. "$ROOT/VERSION"

write_version() {
  local tree="$1"
  mkdir -p "$tree/etc/frp-auto-deploy"
  cat >"$tree/etc/frp-auto-deploy/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=${FRP_VERSION}
RELEASE_CHANNEL=dev
SOURCE_REF=test
EOF
}

snapshot_tree() {
  local tree="$1" dest="$2"
  python3 - "$tree" "$dest" <<'PY'
import hashlib, json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
out = {}
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for name in sorted(filenames):
        path = Path(dirpath) / name
        rel = str(path.relative_to(root))
        try:
            st = path.stat()
        except OSError:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ''
        out[rel] = {'sha256': digest, 'mtime': st.st_mtime, 'size': st.st_size}
Path(sys.argv[2]).write_text(json.dumps(out, sort_keys=True) + '\n', encoding='utf-8')
PY
}

assert_unchanged() {
  local before="$1" after="$2" label="$3"
  python3 - "$before" "$after" "$label" <<'PY' || fail "$label mutated runtime state"
import json, sys
from pathlib import Path
a = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
b = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
if a != b:
    changed = sorted(set(a) ^ set(b) | {k for k in a if a.get(k) != b.get(k)})
    sys.stderr.write('changed keys: %s\n' % changed)
    raise SystemExit(1)
PY
}

extract_list() {
  local archive="$1"
  tar -tzf "$archive"
}

assert_absent_in_archive() {
  local archive="$1" pattern="$2" label="$3"
  if tar -xOzf "$archive" 2>/dev/null | grep -E "$pattern" >/dev/null 2>&1; then
    fail "$label: secret pattern still present in archive ($pattern)"
  fi
  # Also check member names
  if extract_list "$archive" | grep -E "$pattern" >/dev/null 2>&1; then
    fail "$label: secret-looking member name in archive ($pattern)"
  fi
}

assert_member() {
  local archive="$1" member="$2"
  extract_list "$archive" | grep -qx "$member" || fail "missing archive member: $member"
}

# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------
SERVER="$WORKDIR/server"
mkdir -p \
  "$SERVER/etc/frp-auto-deploy/pki" \
  "$SERVER/etc/frp" \
  "$SERVER/var/lib/frp-auto-deploy" \
  "$SERVER/var/log/frp-auto-deploy" \
  "$SERVER/etc/systemd/system" \
  "$SERVER/usr/local/bin" \
  "$SERVER/usr/local/sbin" \
  "$SERVER/usr/local/lib/frp-auto-deploy"
write_version "$SERVER"

# Inject secrets that must never appear in the bundle (generated at runtime so
# the test source itself does not trip secret-scan).
SECRET_TOKEN='test-frp-token-do-not-use-AABBCCDDEEFF00112233445566778899'
PRIVATE_KEY_FILE="$WORKDIR/injected.key"
python3 - "$PRIVATE_KEY_FILE" <<'PY'
from pathlib import Path
import sys
# Deliberately non-PEM in source; assemble PEM only on disk for fixtures.
body = 'MIIEowIBAAKCAQEA0fakeprivatekeymaterial0001'
pem = '-----BEGIN ' + 'RSA PRIVATE KEY-----\n' + body + '\n-----END ' + 'RSA PRIVATE KEY-----\n'
Path(sys.argv[1]).write_text(pem, encoding='utf-8')
PY
PRIVATE_KEY="$(cat "$PRIVATE_KEY_FILE")"
ENROLL='zt1.abcdefghijklmnopqrstuvwxyz012345'

cat >"$SERVER/etc/frp-auto-deploy/config.json" <<EOF
{
  "schema_version": 1,
  "public_host": "203.0.113.10",
  "bind_port": 7000,
  "token_file": "/etc/frp/server_token",
  "mgmt_mac_key": "should-never-leak-mgmt-mac-key",
  "client_installer_url": "https://example.test/bootstrap-client.sh"
}
EOF
printf '%s\n' "$SECRET_TOKEN" >"$SERVER/etc/frp/server_token"
chmod 600 "$SERVER/etc/frp/server_token"
printf '%s\n' "$PRIVATE_KEY" >"$SERVER/etc/frp-auto-deploy/pki/ca.key"
chmod 600 "$SERVER/etc/frp-auto-deploy/pki/ca.key"
printf '%s\n' "$PRIVATE_KEY" >"$SERVER/etc/frp-auto-deploy/pki/server.key"
chmod 600 "$SERVER/etc/frp-auto-deploy/pki/server.key"
cat >"$SERVER/etc/frp-auto-deploy/pki/ca.crt" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBlVqfakeCERTIFICATEmaterial0001
-----END CERTIFICATE-----
EOF
cat >"$SERVER/etc/frp/frps.toml" <<EOF
bindPort = 7000
auth.token = "$SECRET_TOKEN"
EOF
cat >"$SERVER/var/lib/frp-auto-deploy/registry.json" <<EOF
{
  "schema_version": 2,
  "clients": {
    "aabbccddeeff0011": {
      "label": "lab-client",
      "hostname": "client-a",
      "token": "$SECRET_TOKEN",
      "services": {
        "ssh": {"enabled": true, "local_port": 22, "remote_port": 60022, "type": "tcp"}
      }
    }
  },
  "groups": {}
}
EOF
cat >"$SERVER/var/lib/frp-auto-deploy/access-control.json" <<'EOF'
{
  "schema_version": 1,
  "access_lists": {
    "ops": {
      "description": "ops",
      "entries": [{"name": "office", "cidr": "198.51.100.0/24"}]
    }
  },
  "service_access": {}
}
EOF
# Enrollment-looking secret in a log line
printf 'Enrollment Code: %s\n' "$ENROLL" >"$SERVER/var/log/frp-auto-deploy/audit.jsonl"
# Path traversal bait: symlink outside tree
mkdir -p "$WORKDIR/outside"
echo 'OUTSIDE_SECRET=should-not-be-archived' >"$WORKDIR/outside/secret.txt"
ln -s "$WORKDIR/outside/secret.txt" "$SERVER/etc/frp-auto-deploy/evil-link"
# Unit markers for role detection
echo '[Unit]' >"$SERVER/etc/systemd/system/frps.service"
echo '[Unit]' >"$SERVER/etc/systemd/system/frp-port-allocator.service"
: >"$SERVER/usr/local/bin/frps"
: >"$SERVER/usr/local/sbin/frp-create-client"
: >"$SERVER/usr/local/lib/frp-auto-deploy/frp-port-allocator.py"

snapshot_tree "$SERVER" "$WORKDIR/server.before"

OUT_SERVER="$WORKDIR/out-server"
mkdir -p "$OUT_SERVER"
ARCHIVE_SERVER="$OUT_SERVER/bundle.tar.gz"
FRP_DEPLOY_TEST_ROOT="$SERVER" python3 "$LIB" --output "$ARCHIVE_SERVER" \
  >"$WORKDIR/server.out" 2>"$WORKDIR/server.err" || {
  cat "$WORKDIR/server.out" "$WORKDIR/server.err" >&2
  fail "server support-bundle failed"
}
[[ -f "$ARCHIVE_SERVER" ]] || fail "server archive missing"
tar -tzf "$ARCHIVE_SERVER" >/dev/null || fail "server archive not readable"
grep -q 'Support bundle created' "$WORKDIR/server.out" || fail "missing created banner"
grep -q 'sections' "$WORKDIR/server.out" || fail "missing sections summary"
grep -qi 'redact' "$WORKDIR/server.out" || fail "missing redaction summary"

assert_member "$ARCHIVE_SERVER" "meta.json"
assert_member "$ARCHIVE_SERVER" "manifest.json"
assert_member "$ARCHIVE_SERVER" "doctor.txt"
assert_member "$ARCHIVE_SERVER" "product-config.sanitized.json"
assert_member "$ARCHIVE_SERVER" "registry-summary.json"
assert_member "$ARCHIVE_SERVER" "access-control-summary.json"
assert_member "$ARCHIVE_SERVER" "versions.txt"
assert_member "$ARCHIVE_SERVER" "os-info.txt"

# Secrets must be absent
assert_absent_in_archive "$ARCHIVE_SERVER" "$SECRET_TOKEN" "server-token"
assert_absent_in_archive "$ARCHIVE_SERVER" "fakeprivatekeymaterial" "private-key-body"
# Construct PEM header at runtime so this source file stays secret-scan clean.
PEM_HDR="$(python3 -c 'print("BEGIN "+"RSA PRIVATE KEY")')"
assert_absent_in_archive "$ARCHIVE_SERVER" "$PEM_HDR" "private-key-header"
assert_absent_in_archive "$ARCHIVE_SERVER" "should-never-leak-mgmt-mac-key" "mgmt-mac"
assert_absent_in_archive "$ARCHIVE_SERVER" "$ENROLL" "enrollment-code"
assert_absent_in_archive "$ARCHIVE_SERVER" "OUTSIDE_SECRET" "symlink-traversal"
# Private key files must not be archive members
if extract_list "$ARCHIVE_SERVER" | grep -E 'ca\.key|server\.key|server_token' >/dev/null; then
  fail "private key/token path present as archive member"
fi
# Public cert may be present
extract_list "$ARCHIVE_SERVER" | grep -E 'ca\.crt|certs/' >/dev/null || fail "expected public cert section"

# Sanitized config must redact mgmt_mac_key
tar -xOzf "$ARCHIVE_SERVER" product-config.sanitized.json | grep -q '<redacted>' \
  || fail "product config not redacted"
tar -xOzf "$ARCHIVE_SERVER" product-config.sanitized.json | grep -q 'should-never-leak' \
  && fail "mgmt_mac_key leaked in sanitized config"

# Registry summary must not include client token field value
tar -xOzf "$ARCHIVE_SERVER" registry-summary.json | grep -q 'lab-client' \
  || fail "registry summary missing client label"
tar -xOzf "$ARCHIVE_SERVER" registry-summary.json | grep -q "$SECRET_TOKEN" \
  && fail "token leaked in registry summary"

snapshot_tree "$SERVER" "$WORKDIR/server.after"
assert_unchanged "$WORKDIR/server.before" "$WORKDIR/server.after" "server-fixture"
pass "SERVER_BUNDLE_BUILDS"
pass "SERVER_SECRETS_ABSENT"
pass "SERVER_READ_ONLY"
pass "SERVER_NO_TRAVERSAL"

# Path traversal via --output
if FRP_DEPLOY_TEST_ROOT="$SERVER" python3 "$LIB" --output "$OUT_SERVER/../escape.tar.gz" \
  >"$WORKDIR/trav.out" 2>"$WORKDIR/trav.err"; then
  fail "accepted path with .."
fi
grep -qi 'refusing\|unsafe\|ERROR' "$WORKDIR/trav.err" "$WORKDIR/trav.out" \
  || fail "expected unsafe path error"
pass "OUTPUT_PATH_TRAVERSAL_REJECTED"

# ---------------------------------------------------------------------------
# Client fixture
# ---------------------------------------------------------------------------
CLIENT="$WORKDIR/client"
mkdir -p \
  "$CLIENT/etc/frp" \
  "$CLIENT/etc/frp-auto-deploy" \
  "$CLIENT/etc/systemd/system" \
  "$CLIENT/usr/local/bin" \
  "$CLIENT/var/lib/frp-auto-deploy"
write_version "$CLIENT"
cat >"$CLIENT/etc/frp/client-state.json" <<EOF
{
  "client_id": "client-aabb",
  "label": "edge",
  "hostname": "edge-1",
  "allocator_url": "https://203.0.113.10/enroll",
  "token": "$SECRET_TOKEN",
  "mgmt_mac_key": "client-mac-should-not-leak",
  "services": {
    "ssh": {"enabled": true, "local_port": 22, "type": "tcp"}
  }
}
EOF
cat >"$CLIENT/etc/frp/frpc.toml" <<EOF
serverAddr = "203.0.113.10"
auth.token = "$SECRET_TOKEN"
EOF
printf '%s\n' "$PRIVATE_KEY" >"$CLIENT/etc/frp/client-identity.key"
chmod 600 "$CLIENT/etc/frp/client-identity.key"
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyMaterial0001 test' \
  >"$CLIENT/etc/frp/client-identity.pub"
echo '[Unit]' >"$CLIENT/etc/systemd/system/frpc.service"
: >"$CLIENT/usr/local/bin/frpc"
: >"$CLIENT/usr/local/bin/frp-client"

snapshot_tree "$CLIENT" "$WORKDIR/client.before"
OUT_CLIENT="$WORKDIR/out-client"
mkdir -p "$OUT_CLIENT"
ARCHIVE_CLIENT="$OUT_CLIENT/client-bundle.tar.gz"
FRP_DEPLOY_TEST_ROOT="$CLIENT" python3 "$LIB" --output "$ARCHIVE_CLIENT" \
  >"$WORKDIR/client.out" 2>"$WORKDIR/client.err" || {
  cat "$WORKDIR/client.out" "$WORKDIR/client.err" >&2
  fail "client support-bundle failed"
}
[[ -f "$ARCHIVE_CLIENT" ]] || fail "client archive missing"
tar -tzf "$ARCHIVE_CLIENT" >/dev/null || fail "client archive not readable"
assert_member "$ARCHIVE_CLIENT" "client-summary.json"
assert_member "$ARCHIVE_CLIENT" "meta.json"
assert_absent_in_archive "$ARCHIVE_CLIENT" "$SECRET_TOKEN" "client-token"
assert_absent_in_archive "$ARCHIVE_CLIENT" "fakeprivatekeymaterial" "client-private-key-body"
PEM_HDR="$(python3 -c 'print("BEGIN "+"RSA PRIVATE KEY")')"
assert_absent_in_archive "$ARCHIVE_CLIENT" "$PEM_HDR" "client-private-key-header"
assert_absent_in_archive "$ARCHIVE_CLIENT" "client-mac-should-not-leak" "client-mac"
if extract_list "$ARCHIVE_CLIENT" | grep -E 'client-identity\.key' >/dev/null; then
  fail "client identity private key archived"
fi
tar -xOzf "$ARCHIVE_CLIENT" meta.json | grep -q '"role": "client"' \
  || fail "client role not detected"
snapshot_tree "$CLIENT" "$WORKDIR/client.after"
assert_unchanged "$WORKDIR/client.before" "$WORKDIR/client.after" "client-fixture"
pass "CLIENT_BUNDLE_BUILDS"
pass "CLIENT_SECRETS_ABSENT"
pass "CLIENT_READ_ONLY"

# Default output naming (UTC Z)
DEFAULT_DIR="$SERVER/var/lib/frp-auto-deploy/support-bundles"
FRP_DEPLOY_TEST_ROOT="$SERVER" python3 "$LIB" >"$WORKDIR/default.out" 2>"$WORKDIR/default.err" || {
  cat "$WORKDIR/default.out" "$WORKDIR/default.err" >&2
  fail "default output failed"
}
DEFAULT_ARCHIVE="$(find "$DEFAULT_DIR" -maxdepth 1 -type f -name 'frp-support-*.tar.gz' | head -n 1)"
[[ -n "$DEFAULT_ARCHIVE" ]] || fail "default archive not created"
basename "$DEFAULT_ARCHIVE" | grep -E '^frp-support-.+-[0-9]{8}T[0-9]{6}Z\.tar\.gz$' >/dev/null \
  || fail "default archive name not UTC Z stamped"
pass "DEFAULT_UTC_Z_NAMING"

# frpctl wiring (dry grammar + dispatch surface)
python3 - "$ROOT/lib/frp_ctl_grammar.py" <<'PY' || fail "grammar support-bundle"
import importlib.util, sys
spec = importlib.util.spec_from_file_location('g', sys.argv[1])
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
r = g.match(g.tokenize('support-bundle --output /tmp/x.tar.gz'), 'server')
assert r.get('status') == 'ok' and r.get('action') == 'support_bundle', r
assert '--output' in (r.get('passthrough') or [])
r2 = g.match(g.tokenize('support-bundle'), 'client')
assert r2.get('status') == 'ok' and r2.get('action') == 'support_bundle', r2
print('ok')
PY
pass "FRPCTL_GRAMMAR"

# Optional target-health: absent on this fixture -> skipped section, not included as content
if tar -tzf "$ARCHIVE_SERVER" | grep -E '^target-health/' >/dev/null; then
  fail "target-health content should be absent when feature is not installed"
fi
tar -xOzf "$ARCHIVE_SERVER" manifest.json | grep -q 'target-health (not installed)' \
  || fail "expected target-health skip note in manifest"
pass "TARGET_HEALTH_OPTIONAL"

# Command surface for Windows (existence only)
grep -q "support-bundle" "$ROOT/windows/tools/FrpClient.ps1" \
  || fail "windows FrpClient missing support-bundle"
pass "WINDOWS_COMMAND_SURFACE"

echo "ALL SUPPORT BUNDLE TESTS PASSED"
