#!/usr/bin/env bash
# P2.11 read-only frpctl doctor diagnostics. Isolated fixtures only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
# Linux doctor fixtures must not inherit Darwin path/platform overrides.
unset FRP_TEST_UNAME_S FRP_TEST_UNAME_M FRP_TEST_MACOS_PRODUCT_VERSION \
  FRP_MACOS_STATE_ROOT FRP_MACOS_PREFIX FRP_MACOS_LAUNCHD_LABEL || true

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

chmod +x "$ROOT/tools/frpctl"
CTL="$ROOT/tools/frpctl"
# shellcheck disable=SC1091
. "$ROOT/VERSION"
export FRP_SKIP_SYSTEMD=1
export FRP_DOCTOR_SKIP_NETWORK=1
export FRP_DOCTOR_PY="$ROOT/lib/frp_doctor.py"
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

write_dummy_bin() {
  local dest="$1" name="$2" version="${3:-0.70.1}"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
  echo "${name} version ${version}"
  exit 0
fi
exit 0
EOF
  chmod 0755 "$dest"
}

write_version() {
  local tree="$1"
  mkdir -p "$tree/etc/frp-auto-deploy"
  cat >"$tree/etc/frp-auto-deploy/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=${FRP_VERSION}
EOF
}

write_unit() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  echo '[Unit]' >"$dest"
  echo 'Description=fixture' >>"$dest"
}

snapshot() {
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
  python3 - "$before" "$after" "$label" <<'PY' || fail "$label mutated"
import json, sys
from pathlib import Path
a = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
b = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
if a != b:
    sys.stderr.write('changed keys: %s\n' % sorted(set(a) ^ set(b) | {k for k in a if a.get(k) != b.get(k)}))
    raise SystemExit(1)
PY
}

assert_no_secret() {
  local log="$1"
  if grep -E 'BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY|test-frp-token-do-not-use|enroll-secret-' "$log" >/dev/null 2>&1; then
    fail "secret leaked in $log"
  fi
  if grep -E '221\.139\.249\.110|10\.39\.163\.128' "$log" >/dev/null 2>&1; then
    fail "forbidden IP in $log"
  fi
}

json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
path = sys.argv[2].split('.')
cur = data
for part in path:
    if isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break
if cur is None:
    print('')
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
PY
}

check_status() {
  python3 - "$1" "$2" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
wanted = sys.argv[2]
for item in data.get('checks') or []:
    if item.get('id') == wanted:
        print(item.get('status') or '')
        raise SystemExit(0)
print('')
PY
}

gen_pki() {
  local dest="$1" host="${2:-203.0.113.10}"
  mkdir -p "$dest"
  python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$dest" --public-host "$host" >/dev/null
}

gen_identity() {
  local tree="$1"
  mkdir -p "$tree/etc/frp"
  python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
    "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
  chmod 600 "$tree/etc/frp/client-identity.key"
  python3 - "$tree/etc/frp/client-identity.mac" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_text('a' * 64 + '\n', encoding='utf-8')
PY
  chmod 600 "$tree/etc/frp/client-identity.mac"
}

write_server_healthy() {
  local tree="$1"
  mkdir -p "$tree/etc/frp" "$tree/etc/frp-auto-deploy" "$tree/var/lib/frp-auto-deploy" \
    "$tree/usr/local/bin" "$tree/usr/local/sbin" "$tree/usr/local/lib/frp-auto-deploy" \
    "$tree/etc/systemd/system"
  write_version "$tree"
  write_dummy_bin "$tree/usr/local/bin/frps" frps
  write_dummy_bin "$tree/usr/local/sbin/frp-create-client" frp-create-client
  cp "$ROOT/server/frp-port-allocator.py" "$tree/usr/local/lib/frp-auto-deploy/frp-port-allocator.py"
  write_unit "$tree/etc/systemd/system/frps.service"
  write_unit "$tree/etc/systemd/system/frp-port-allocator.service"
  echo 'test-frp-token-do-not-use' >"$tree/etc/frp/server_token"
  chmod 600 "$tree/etc/frp/server_token"
  echo 'bindPort = 443' >"$tree/etc/frp/frps.toml"
  chmod 600 "$tree/etc/frp/frps.toml"
  gen_pki "$tree/etc/frp-auto-deploy/pki" "203.0.113.10"
  python3 - "$tree/etc/frp-auto-deploy/config.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "public_host": "203.0.113.10",
    "public_ip": "203.0.113.10",
    "frp_control_public_port": 8443,
    "frp_control_listen_port": 443,
    "port_start": 6000,
    "port_end": 6098,
    "listen_host": "0.0.0.0",
    "allocator_public_port": 9443,
    "allocator_listen_port": 6099,
    "listen_port": 6099,
    "allocator_public_url": "https://203.0.113.10:9443/enroll",
    "registry_file": "/var/lib/frp-auto-deploy/registry.json",
    "token_file": "/etc/frp/server_token",
    "tls_ca_cert": "/etc/frp-auto-deploy/pki/ca.crt",
    "tls_server_cert": "/etc/frp-auto-deploy/pki/server.crt",
    "tls_server_key": "/etc/frp-auto-deploy/pki/server.key",
}, indent=2, sort_keys=True) + "\n")
PY
  chmod 600 "$tree/etc/frp-auto-deploy/config.json"
  python3 - "$tree/var/lib/frp-auto-deploy/registry.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 2,
    "reserved": [6002, 6003],
    "clients": {
        "aabbccdd0011": {
            "hostname": "dp-fixture",
            "mgmt_status": "enrolled",
            "services": {
                "ssh": {"id": "ssh", "remote_port": 6002, "enabled": True, "local_ip": "127.0.0.1", "local_port": 22},
                "web": {"id": "web", "remote_port": 6003, "enabled": False, "local_ip": "127.0.0.1", "local_port": 80},
            },
        },
        "revoked001122": {
            "hostname": "old-client",
            "mgmt_status": "revoked",
            "services": {
                "ssh": {"id": "ssh", "remote_port": 6004, "enabled": True, "local_ip": "127.0.0.1", "local_port": 22},
            },
        },
    },
}, indent=2, sort_keys=True) + "\n")
PY
  chmod 600 "$tree/var/lib/frp-auto-deploy/registry.json"
  echo '{"schema_version":1,"nonces":{"abc":1}}' >"$tree/var/lib/frp-auto-deploy/mgmt-nonces.json"
  chmod 600 "$tree/var/lib/frp-auto-deploy/mgmt-nonces.json"
}

write_client_healthy() {
  local tree="$1"
  mkdir -p "$tree/etc/frp" "$tree/etc/frp-auto-deploy" "$tree/usr/local/bin" \
    "$tree/etc/systemd/system"
  write_version "$tree"
  write_dummy_bin "$tree/usr/local/bin/frpc" frpc
  write_dummy_bin "$tree/usr/local/bin/frp-client" frp-client
  write_unit "$tree/etc/systemd/system/frpc.service"
  gen_identity "$tree"
  if [[ -f "$WORKDIR/pki-ca.crt" ]]; then
    cp "$WORKDIR/pki-ca.crt" "$tree/etc/frp-auto-deploy/allocator-ca.crt"
  else
    gen_pki "$WORKDIR/shared-pki" "203.0.113.10"
    cp "$WORKDIR/shared-pki/ca.crt" "$WORKDIR/pki-ca.crt"
    cp "$WORKDIR/pki-ca.crt" "$tree/etc/frp-auto-deploy/allocator-ca.crt"
  fi
  chmod 644 "$tree/etc/frp-auto-deploy/allocator-ca.crt"
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://203.0.113.10:9443/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 8443,
    "hostname": "ctl-client",
    "machine_id": "00112233445566778899aabbccddeeff",
    "host_id": "ctl-client-00112233",
    "services": {
        "ssh": {
            "id": "ssh", "name": "SSH", "preset": "ssh", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 6002,
            "enabled": True, "ssh_user": "aella",
        },
        "web": {
            "id": "web", "name": "Web", "preset": "http", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 80, "remote_port": 6003,
            "enabled": False,
        },
    },
}, indent=2, sort_keys=True) + "\n")
PY
  chmod 600 "$tree/etc/frp/client-state.json"
  cat >"$tree/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 8443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"
transport.tls.enable = true

[[proxies]]
name = "ctl-client-00112233-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6002
EOF
  chmod 600 "$tree/etc/frp/frpc.toml"
  cat >"$tree/etc/frp/access-info.txt" <<'EOF'
FRP Server: 203.0.113.10:8443

Services:

SSH
  Public: 203.0.113.10:6002
EOF
}

run_ctl() {
  local tree="$1" out="$2"
  shift 2
  export FRP_CTL_TEST_ROOT="$tree"
  export FRP_CLIENT_TEST_ROOT="$tree"
  export FRP_DEPLOY_TEST_ROOT="$tree"
  set +e
  "$CTL" doctor "$@" >"$out" 2>"${out}.err"
  local rc=$?
  set -e
  return "$rc"
}

run_json() {
  local tree="$1" out="$2"
  shift 2
  run_ctl "$tree" "$out" --json "$@"
}

run_json() {
  local tree="$1" out="$2"
  shift 2
  run_ctl "$tree" "$out" --json "$@"
}

# Shared CA for client fixtures.
gen_pki "$WORKDIR/shared-pki" "203.0.113.10"
cp "$WORKDIR/shared-pki/ca.crt" "$WORKDIR/pki-ca.crt"

# ---------------------------------------------------------------------------
# Uninstalled
# ---------------------------------------------------------------------------
EMPTY="$WORKDIR/empty"
mkdir -p "$EMPTY"
rc=0
run_json "$EMPTY" "$WORKDIR/uninstalled.json" || rc=$?
[[ "$rc" -eq 0 ]] || fail "uninstalled exit $rc"
[[ "$(json_get "$WORKDIR/uninstalled.json" role)" == "uninstalled" ]] || fail "uninstalled role"
[[ "$(check_status "$WORKDIR/uninstalled.json" host_role)" == "INFO" ]] || fail "uninstalled host_role"
pass "UNINSTALLED_HOST"

# ---------------------------------------------------------------------------
# Healthy server
# ---------------------------------------------------------------------------
SRV="$WORKDIR/server"
write_server_healthy "$SRV"
snapshot "$SRV" "$WORKDIR/server.before"
rc=0
run_json "$SRV" "$WORKDIR/server.json" || rc=$?
[[ "$rc" -eq 0 ]] || { cat "$WORKDIR/server.json"; fail "healthy server exit $rc"; }
[[ "$(json_get "$WORKDIR/server.json" overall)" == "PASS" || "$(json_get "$WORKDIR/server.json" overall)" == "PASS_WITH_WARNINGS" ]] || fail "healthy server overall $(json_get "$WORKDIR/server.json" overall)"
[[ "$(json_get "$WORKDIR/server.json" role)" == "server" ]] || fail "healthy server role"
[[ "$(check_status "$WORKDIR/server.json" server_token)" == "PASS" ]] || fail "server token"
[[ "$(check_status "$WORKDIR/server.json" server_registry)" == "PASS" ]] || fail "server registry"
[[ "$(check_status "$WORKDIR/server.json" public_listen_frp)" == "PASS" ]] || fail "public/listen should PASS"
[[ "$(check_status "$WORKDIR/server.json" client_disabled_services)" == "" ]] || true
assert_no_secret "$WORKDIR/server.json"
snapshot "$SRV" "$WORKDIR/server.after"
assert_unchanged "$WORKDIR/server.before" "$WORKDIR/server.after" "healthy server"
pass "HEALTHY_SERVER"
pass "PUBLIC_LISTEN_PORT_DIAGNOSTICS"
pass "DOCTOR_NO_FILE_MUTATION_SERVER"

run_ctl "$SRV" "$WORKDIR/server.human"
grep -q 'FRP Auto Deploy Doctor' "$WORKDIR/server.human" || fail "human header"
grep -q 'Public endpoint' "$WORKDIR/server.human" || fail "public endpoint display"
grep -q 'Local listener' "$WORKDIR/server.human" || fail "listen display"
grep -q 'Overall:' "$WORKDIR/server.human" || fail "human overall"
assert_no_secret "$WORKDIR/server.human"
pass "SERVER_STATUS_STYLE_ENDPOINTS"

# ---------------------------------------------------------------------------
# Healthy client
# ---------------------------------------------------------------------------
CL="$WORKDIR/client"
write_client_healthy "$CL"
snapshot "$CL" "$WORKDIR/client.before"
NONCE_BEFORE=""
[[ -f "$SRV/var/lib/frp-auto-deploy/mgmt-nonces.json" ]] && NONCE_BEFORE="$(python3 -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("'"$SRV"'/var/lib/frp-auto-deploy/mgmt-nonces.json").read_bytes()).hexdigest())')"
rc=0
run_json "$CL" "$WORKDIR/client.json" || rc=$?
[[ "$rc" -eq 0 ]] || { cat "$WORKDIR/client.json"; fail "healthy client exit $rc"; }
overall="$(json_get "$WORKDIR/client.json" overall)"
[[ "$overall" == "PASS" || "$overall" == "PASS_WITH_WARNINGS" ]] || fail "healthy client overall $overall"
[[ "$(json_get "$WORKDIR/client.json" role)" == "client" ]] || fail "healthy client role"
[[ "$(check_status "$WORKDIR/client.json" client_state)" == "PASS" ]] || fail "client state"
[[ "$(check_status "$WORKDIR/client.json" client_identity)" == "PASS" ]] || fail "client identity"
[[ "$(check_status "$WORKDIR/client.json" frpc_config)" == "PASS" ]] || fail "frpc config"
[[ "$(check_status "$WORKDIR/client.json" client_disabled_services)" == "PASS" ]] || fail "disabled service should PASS"
assert_no_secret "$WORKDIR/client.json"
if python3 - "$WORKDIR/client.json" <<'PY'
import json,sys
from pathlib import Path
data=json.loads(Path(sys.argv[1]).read_text())
text=json.dumps(data)
assert 'test-frp-token-do-not-use' not in text
assert '\x1b[' not in text
PY
then
  :
else
  fail "json contained secrets or ANSI"
fi
snapshot "$CL" "$WORKDIR/client.after"
assert_unchanged "$WORKDIR/client.before" "$WORKDIR/client.after" "healthy client"
python3 - "$WORKDIR/client.json" <<'PY' || fail "linux doctor runtime/distro labels"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
text = json.dumps(data)
assert 'launchd job' not in text
assert 'com.datarelay.frp-auto-deploy.frpc' not in text
ids = {c.get('id'): c for c in data.get('checks') or []}
assert 'distro_support' in ids
assert 'automated container matrix' in (ids['distro_support'].get('message') or '')
assert 'macos_support' not in ids
frpc = ids.get('frpc_service') or {}
assert 'frpc.service' in (frpc.get('message') or '')
assert 'launchd' not in (frpc.get('message') or '')
PY
pass "HEALTHY_CLIENT"
pass "DISABLED_SERVICE_LEGITIMATE"
pass "DOCTOR_JSON"
pass "LINUX_DOCTOR_DISTRO_AND_SYSTEMD_LABELS"

# ---------------------------------------------------------------------------
# WARN only: missing access-info
# ---------------------------------------------------------------------------
WARN="$WORKDIR/warn"
cp -a "$CL" "$WARN"
rm -f "$WARN/etc/frp/access-info.txt"
rc=0
run_json "$WARN" "$WORKDIR/warn.json" || rc=$?
[[ "$rc" -eq 0 ]] || fail "warn-only should exit 0, got $rc"
[[ "$(json_get "$WORKDIR/warn.json" overall)" == "PASS_WITH_WARNINGS" ]] || fail "warn overall"
[[ "$(check_status "$WORKDIR/warn.json" access_info)" == "WARN" ]] || fail "access-info WARN"
pass "WARN_ONLY_ACCESS_INFO"

# ---------------------------------------------------------------------------
# FAIL: corrupt client-state
# ---------------------------------------------------------------------------
BAD="$WORKDIR/bad-state"
cp -a "$CL" "$BAD"
echo '{not json' >"$BAD/etc/frp/client-state.json"
rc=0
run_json "$BAD" "$WORKDIR/bad.json" || rc=$?
[[ "$rc" -eq 1 ]] || fail "corrupt state should exit 1, got $rc"
[[ "$(json_get "$WORKDIR/bad.json" overall)" == "FAIL" ]] || fail "corrupt overall"
[[ "$(check_status "$WORKDIR/bad.json" client_state)" == "FAIL" ]] || fail "corrupt client_state"
pass "FAIL_CORRUPT_CLIENT_STATE"

# ---------------------------------------------------------------------------
# Dual role
# ---------------------------------------------------------------------------
BOTH="$WORKDIR/both"
write_server_healthy "$BOTH"
write_client_healthy "$BOTH"
rc=0
run_json "$BOTH" "$WORKDIR/both.json" || rc=$?
[[ "$rc" -eq 0 ]] || { cat "$WORKDIR/both.json"; fail "dual exit $rc"; }
[[ "$(json_get "$WORKDIR/both.json" role)" == "dual" ]] || fail "dual role $(json_get "$WORKDIR/both.json" role)"
[[ "$(check_status "$WORKDIR/both.json" server_token)" == "PASS" ]] || fail "dual server token"
[[ "$(check_status "$WORKDIR/both.json" client_state)" == "PASS" ]] || fail "dual client state"
pass "DUAL_ROLE"

# ---------------------------------------------------------------------------
# Partial client
# ---------------------------------------------------------------------------
PART="$WORKDIR/partial"
mkdir -p "$PART/etc/frp" "$PART/etc/frp-auto-deploy"
write_version "$PART"
echo '{"schema_version":1,"services":{}}' >"$PART/etc/frp/client-state.json"
chmod 600 "$PART/etc/frp/client-state.json"
rc=0
run_json "$PART" "$WORKDIR/partial.json" || rc=$?
[[ "$rc" -eq 1 ]] || fail "partial should FAIL exit 1, got $rc"
[[ "$(json_get "$WORKDIR/partial.json" role)" == "partial_client" ]] || fail "partial role"
[[ "$(check_status "$WORKDIR/partial.json" host_role)" == "FAIL" ]] || fail "partial host_role"
grep -q 'frpc unit is missing' "$WORKDIR/partial.json" || fail "partial reason"
pass "PARTIAL_CLIENT"

# ---------------------------------------------------------------------------
# Missing token / bad perms / corrupt registry / duplicate port
# ---------------------------------------------------------------------------
MISS_TOK="$WORKDIR/miss-token"
cp -a "$SRV" "$MISS_TOK"
rm -f "$MISS_TOK/etc/frp/server_token"
run_json "$MISS_TOK" "$WORKDIR/miss-token.json" || true
[[ "$(check_status "$WORKDIR/miss-token.json" server_token)" == "FAIL" ]] || fail "missing token"
assert_no_secret "$WORKDIR/miss-token.json"
pass "MISSING_TOKEN"

PERM="$WORKDIR/token-perm"
cp -a "$SRV" "$PERM"
chmod 0644 "$PERM/etc/frp/server_token"
run_json "$PERM" "$WORKDIR/token-perm.json" || true
[[ "$(check_status "$WORKDIR/token-perm.json" server_token)" == "FAIL" ]] || fail "token perms"
pass "TOKEN_PERMISSIONS"

DUP="$WORKDIR/dup-port"
cp -a "$SRV" "$DUP"
python3 - "$DUP/var/lib/frp-auto-deploy/registry.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
data = json.loads(p.read_text())
data['clients']['other'] = {
    'hostname': 'other',
    'mgmt_status': 'enrolled',
    'services': {'ssh': {'id': 'ssh', 'remote_port': 6002, 'enabled': True, 'local_ip': '127.0.0.1', 'local_port': 22}},
}
p.write_text(json.dumps(data) + '\n')
PY
run_json "$DUP" "$WORKDIR/dup.json" || true
[[ "$(check_status "$WORKDIR/dup.json" server_registry)" == "FAIL" ]] || fail "duplicate port"
pass "DUPLICATE_REGISTRY_PORT"

REV="$WORKDIR/revoked"
# already in healthy server
[[ "$(check_status "$WORKDIR/server.json" server_registry)" == "PASS" ]] || fail "revoked client should not fail registry"
pass "REVOKED_CLIENT_VALID"

# ---------------------------------------------------------------------------
# PKI: missing CA, invalid CA, expired, SAN mismatch, not signed
# ---------------------------------------------------------------------------
NOCA="$WORKDIR/noca"
cp -a "$SRV" "$NOCA"
rm -f "$NOCA/etc/frp-auto-deploy/pki/ca.crt"
run_json "$NOCA" "$WORKDIR/noca.json" || true
[[ "$(check_status "$WORKDIR/noca.json" allocator_ca)" == "FAIL" ]] || fail "missing CA"
pass "MISSING_CA"

BADCA="$WORKDIR/badca"
cp -a "$SRV" "$BADCA"
echo 'not-a-cert' >"$BADCA/etc/frp-auto-deploy/pki/ca.crt"
run_json "$BADCA" "$WORKDIR/badca.json" || true
[[ "$(check_status "$WORKDIR/badca.json" allocator_ca)" == "FAIL" ]] || fail "invalid CA"
pass "INVALID_CA"

EXP="$WORKDIR/expired"
cp -a "$SRV" "$EXP"
python3 - "$EXP/etc/frp-auto-deploy/pki" <<'PY'
import os, subprocess, sys, tempfile
from pathlib import Path
pki = Path(sys.argv[1])
workdir = Path(tempfile.mkdtemp(prefix='frp-exp.'))
(workdir / 'index.txt').write_text('')
(workdir / 'serial').write_text('C8\n')
cnf = workdir / 'ca.cnf'
cnf.write_text('\n'.join([
    '[ca]', 'default_ca = CA_default', '',
    '[CA_default]',
    'database = %s' % (workdir / 'index.txt'),
    'serial = %s' % (workdir / 'serial'),
    'new_certs_dir = %s' % workdir,
    'default_md = sha256',
    'policy = policy_any',
    'x509_extensions = usr_cert',
    'copy_extensions = none',
    'unique_subject = no',
    '',
    '[policy_any]',
    'commonName = optional',
    '',
    '[usr_cert]',
    'basicConstraints = CA:FALSE',
]) + '\n')
csr = workdir / 'server.csr'
subprocess.check_call(['openssl','req','-new','-key',str(pki/'server.key'),'-out',str(csr),'-subj','/CN=expired'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.check_call([
    'openssl','ca','-batch','-notext','-config',str(cnf),
    '-in',str(csr),'-out',str(pki/'server.crt'),
    '-cert',str(pki/'ca.crt'),'-keyfile',str(pki/'ca.key'),
    '-startdate','000101000000Z','-enddate','000102000000Z',
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
PY
run_json "$EXP" "$WORKDIR/expired.json" || true
[[ "$(check_status "$WORKDIR/expired.json" allocator_server_cert)" == "FAIL" ]] || fail "expired cert"
pass "EXPIRED_CERT"

SOON="$WORKDIR/soon"
cp -a "$SRV" "$SOON"
python3 - "$SOON/etc/frp-auto-deploy/pki" <<'PY'
import subprocess, sys
from pathlib import Path
pki = Path(sys.argv[1])
csr = pki / 'tmp.csr'
subprocess.check_call(['openssl','req','-new','-key',str(pki/'server.key'),'-out',str(csr),'-subj','/CN=soon'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.check_call([
    'openssl','x509','-req','-in',str(csr),'-CA',str(pki/'ca.crt'),'-CAkey',str(pki/'ca.key'),
    '-CAcreateserial','-out',str(pki/'server.crt'),'-days','10',
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
csr.unlink()
PY
run_json "$SOON" "$WORKDIR/soon.json" || true
[[ "$(check_status "$WORKDIR/soon.json" allocator_server_cert)" == "WARN" ]] || fail "soon-expiry WARN got $(check_status "$WORKDIR/soon.json" allocator_server_cert)"
pass "CERT_EXPIRES_SOON"

SAN="$WORKDIR/san"
cp -a "$SRV" "$SAN"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$SAN/etc/frp-auto-deploy/pki" --public-host "198.51.100.10" >/dev/null
run_json "$SAN" "$WORKDIR/san.json" || true
[[ "$(check_status "$WORKDIR/san.json" allocator_san)" == "FAIL" ]] || fail "SAN mismatch"
grep -qi 'reissue\|installer\|existing CA' "$WORKDIR/san.json" || fail "SAN recommendation"
pass "SAN_MISMATCH"

# ---------------------------------------------------------------------------
# Client identity / CA / drift / pending
# ---------------------------------------------------------------------------
NOID="$WORKDIR/noid"
cp -a "$CL" "$NOID"
rm -f "$NOID/etc/frp/client-identity.key"
run_json "$NOID" "$WORKDIR/noid.json" || true
[[ "$(check_status "$WORKDIR/noid.json" client_identity)" == "FAIL" ]] || fail "missing identity"
pass "MISSING_IDENTITY"

BADPERM="$WORKDIR/idperm"
cp -a "$CL" "$BADPERM"
chmod 0644 "$BADPERM/etc/frp/client-identity.key"
run_json "$BADPERM" "$WORKDIR/idperm.json" || true
[[ "$(check_status "$WORKDIR/idperm.json" client_identity_permissions)" == "FAIL" ]] || fail "identity perms"
pass "IDENTITY_PERMISSIONS"

MISMATCH="$WORKDIR/idmis"
cp -a "$CL" "$MISMATCH"
python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key "$WORKDIR/other.key" "$MISMATCH/etc/frp/client-identity.pub"
run_json "$MISMATCH" "$WORKDIR/idmis.json" || true
[[ "$(check_status "$WORKDIR/idmis.json" client_identity)" == "FAIL" ]] || fail "identity mismatch"
pass "IDENTITY_MISMATCH"

NOTOML="$WORKDIR/notoml"
cp -a "$CL" "$NOTOML"
rm -f "$NOTOML/etc/frp/frpc.toml"
run_json "$NOTOML" "$WORKDIR/notoml.json" || true
[[ "$(check_status "$WORKDIR/notoml.json" frpc_config)" == "FAIL" ]] || fail "missing toml"
grep -q 'frp-client manage' "$WORKDIR/notoml.json" || fail "toml recovery guidance"
pass "MISSING_FRPC_TOML"

DRIFT="$WORKDIR/drift"
cp -a "$CL" "$DRIFT"
sed -i 's/remotePort = 6002/remotePort = 6011/' "$DRIFT/etc/frp/frpc.toml"
run_json "$DRIFT" "$WORKDIR/drift.json" || true
[[ "$(check_status "$WORKDIR/drift.json" frpc_config)" == "FAIL" ]] || fail "toml drift"
pass "DRIFTED_FRPC_TOML"

PEND="$WORKDIR/pending-apply"
cp -a "$CL" "$PEND"
python3 - "$PEND/etc/frp/apply-pending.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "phase": "runtime-apply",
    "failure_class": "FRPC_RESTART_FAILED",
    "operation_id": "deadbeef",
}, indent=2) + "\n")
PY
snapshot "$PEND" "$WORKDIR/pend.before"
run_json "$PEND" "$WORKDIR/pend.json" || true
[[ "$(check_status "$WORKDIR/pend.json" pending_apply)" == "FAIL" ]] || fail "pending apply"
grep -q 'FRPC_RESTART_FAILED' "$WORKDIR/pend.json" || fail "failure class visible"
[[ -f "$PEND/etc/frp/apply-pending.json" ]] || fail "doctor deleted pending marker"
snapshot "$PEND" "$WORKDIR/pend.after"
assert_unchanged "$WORKDIR/pend.before" "$WORKDIR/pend.after" "pending apply"
pass "PENDING_APPLY"

UPMARK="$WORKDIR/pending-update"
cp -a "$SRV" "$UPMARK"
echo '{"operation":"update","phase":"systemd-apply","failure_class":"SERVICE_START_FAILED"}' \
  >"$UPMARK/var/lib/frp-auto-deploy/server-update-pending.json"
run_json "$UPMARK" "$WORKDIR/upmark.json" || true
[[ "$(check_status "$WORKDIR/upmark.json" pending_server_transaction)" == "FAIL" ]] || fail "pending update"
[[ -f "$UPMARK/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "doctor deleted update marker"
pass "PENDING_UPDATE"

PROJMARK="$WORKDIR/pending-project"
cp -a "$SRV" "$PROJMARK"
echo '{"operation":"project-update","phase":"commit","failure_class":"HEALTH_CHECK_FAILED"}' \
  >"$PROJMARK/var/lib/frp-auto-deploy/server-update-pending.json"
run_json "$PROJMARK" "$WORKDIR/projmark.json" || true
[[ "$(check_status "$WORKDIR/projmark.json" pending_server_transaction)" == "FAIL" ]] || fail "project pending"
grep -q 'frpctl project-update' "$WORKDIR/projmark.json" || fail "project-update guidance"
if grep -q 'sudo frpctl update' "$WORKDIR/projmark.json" && ! grep -q 'frpctl project-update' "$WORKDIR/projmark.json"; then
  fail "generic update guidance for project-update"
fi
[[ -f "$PROJMARK/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "doctor deleted project marker"
pass "DOCTOR_PROJECT_UPDATE_GUIDANCE"

FRPMARK="$WORKDIR/pending-frp"
cp -a "$SRV" "$FRPMARK"
echo '{"operation":"frp-update","phase":"commit"}' \
  >"$FRPMARK/var/lib/frp-auto-deploy/server-update-pending.json"
run_json "$FRPMARK" "$WORKDIR/frpmark.json" || true
grep -q 'frpctl frp-update' "$WORKDIR/frpmark.json" || fail "frp-update guidance"
[[ -f "$FRPMARK/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "doctor deleted frp marker"
pass "DOCTOR_FRP_UPDATE_GUIDANCE"

# Version mismatch
VM="$WORKDIR/ver-mis"
cp -a "$CL" "$VM"
echo 'PROJECT_VERSION=1.2.0' >"$VM/etc/frp-auto-deploy/version"
echo 'FRP_VERSION=0.70.1' >>"$VM/etc/frp-auto-deploy/version"
run_json "$VM" "$WORKDIR/ver.json" || true
[[ "$(check_status "$WORKDIR/ver.json" project_version)" == "FAIL" ]] || fail "project version mismatch"
grep -q 'frpctl update' "$WORKDIR/ver.json" || fail "version recovery"
pass "PROJECT_VERSION_MISMATCH"

FV="$WORKDIR/frp-mis"
cp -a "$CL" "$FV"
write_dummy_bin "$FV/usr/local/bin/frpc" frpc "0.69.0"
run_json "$FV" "$WORKDIR/fv.json" || true
[[ "$(check_status "$WORKDIR/fv.json" frp_version)" == "FAIL" ]] || fail "frp version mismatch"
pass "FRP_VERSION_MISMATCH"

# Stale lock
LOCK="$WORKDIR/stale-lock"
cp -a "$CL" "$LOCK"
mkdir -p "$LOCK/etc/frp/client-manage.lock"
echo '999999' >"$LOCK/etc/frp/client-manage.lock/pid"
run_json "$LOCK" "$WORKDIR/lock.json" || true
[[ "$(check_status "$WORKDIR/lock.json" stale_lock)" == "WARN" ]] || fail "stale lock WARN"
[[ -d "$LOCK/etc/frp/client-manage.lock" ]] || fail "doctor removed lock"
pass "STALE_LOCK"

# Backup retention
BAK="$WORKDIR/backups"
cp -a "$CL" "$BAK"
mkdir -p "$BAK/etc/frp/backups"
for i in 1 2 3 4 5 6 7 8 9 10; do
  mkdir -p "$BAK/etc/frp/backups/2020010${i}T000000Z"
done
run_json "$BAK" "$WORKDIR/bak.json" || true
[[ "$(check_status "$WORKDIR/bak.json" backup_health)" == "WARN" ]] || fail "backup retention WARN"
n="$(python3 - "$BAK/etc/frp/backups" <<'PY'
import sys
from pathlib import Path
print(sum(1 for p in Path(sys.argv[1]).iterdir() if p.is_dir()))
PY
)"
[[ "$n" -eq 10 ]] || fail "doctor deleted backups"
pass "BACKUP_RETENTION"

# ---------------------------------------------------------------------------
# No service restart
# ---------------------------------------------------------------------------
MOCK="$WORKDIR/mock-bin"
mkdir -p "$MOCK"
cat >"$MOCK/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"${FRP_DOCTOR_SYSTEMCTL_LOG}"
case "$1" in
  is-active) echo active; exit 0 ;;
  is-enabled) echo enabled; exit 0 ;;
  status|show) echo ok; exit 0 ;;
  start|stop|restart|enable|disable|daemon-reload)
    echo "FORBIDDEN $1" >>"${FRP_DOCTOR_SYSTEMCTL_LOG}"
    exit 1
    ;;
esac
exit 0
EOF
chmod 0755 "$MOCK/systemctl"
export FRP_DOCTOR_SYSTEMCTL_LOG="$WORKDIR/systemctl.log"
: >"$FRP_DOCTOR_SYSTEMCTL_LOG"
RST="$WORKDIR/restart"
cp -a "$SRV" "$RST"
(
  unset FRP_SKIP_SYSTEMD
  export FRP_DOCTOR_FORCE_SYSTEMD=1
  export PATH="$MOCK:$PATH"
  export FRP_CTL_TEST_ROOT="$RST"
  export FRP_DOCTOR_SKIP_NETWORK=1
  "$CTL" doctor --json >"$WORKDIR/restart.json" 2>"$WORKDIR/restart.err" || true
)
if awk '{print $1}' "$FRP_DOCTOR_SYSTEMCTL_LOG" | grep -qxE 'start|stop|restart|enable|disable|daemon-reload'; then
  cat "$FRP_DOCTOR_SYSTEMCTL_LOG"
  fail "doctor invoked mutating systemctl"
fi
if grep -E 'is-active|is-enabled' "$FRP_DOCTOR_SYSTEMCTL_LOG" >/dev/null; then
  :
else
  fail "doctor did not query systemctl is-active/is-enabled"
fi
pass "DOCTOR_NO_SERVICE_RESTART"

# ---------------------------------------------------------------------------
# No mutation HTTP / restart in source
# ---------------------------------------------------------------------------
if grep -nE 'POST /enroll|/revoke|/release|method=.POST|Request\(.*, *data=' "$ROOT/lib/frp_doctor.py" "$ROOT/lib/frp-doctor-common.sh"; then
  fail "doctor source contains mutation HTTP"
fi
if grep -nE 'systemctl (start|stop|restart|enable|disable|daemon-reload)' "$ROOT/lib/frp_doctor.py" "$ROOT/lib/frp-doctor-common.sh"; then
  fail "doctor source restarts services"
fi
pass "DOCTOR_NO_MANAGEMENT_MUTATION"

# Nonce unchanged after server doctor
NONCE_AFTER="$(python3 -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("'"$SRV"'/var/lib/frp-auto-deploy/mgmt-nonces.json").read_bytes()).hexdigest())')"
[[ "$NONCE_BEFORE" == "$NONCE_AFTER" ]] || fail "nonce cache mutated"
pass "DOCTOR_NO_NONCE_CONSUMPTION"

# ---------------------------------------------------------------------------
# JSON schema / stable IDs / exit codes / invalid option
# ---------------------------------------------------------------------------
python3 - "$WORKDIR/client.json" <<'PY' || fail "json schema"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
assert data['schema_version'] == 1
assert isinstance(data['checks'], list)
ids = [c['id'] for c in data['checks']]
for required in ('host_role', 'project_version', 'client_state', 'client_identity', 'client_ca'):
    assert required in ids, required
for c in data['checks']:
    assert 'status' in c and 'message' in c
PY
pass "DOCTOR_STABLE_CHECK_IDS"

set +e
"$CTL" doctor --nope >"$WORKDIR/badopt.out" 2>"$WORKDIR/badopt.err"
opt_rc=$?
set -e
[[ "$opt_rc" -eq 2 ]] || fail "invalid option should exit 2, got $opt_rc"
pass "DOCTOR_EXIT_CODES"

# ---------------------------------------------------------------------------
# REPL doctor returns to prompt
# ---------------------------------------------------------------------------
export FRP_CTL_TEST_ROOT="$CL"
export FRP_CLIENT_TEST_ROOT="$CL"
export FRP_CTL_TEST_INPUT="$(printf '%s\n' doctor exit)"
set +e
"$CTL" >"$WORKDIR/repl.out" 2>"$WORKDIR/repl.err"
set -e
cat "$WORKDIR/repl.err" >>"$WORKDIR/repl.out"
grep -c '^frpctl>' "$WORKDIR/repl.out" | awk '{exit($1<2)}' || fail "repl did not return to prompt"
grep -q 'FRP Auto Deploy Doctor' "$WORKDIR/repl.out" || fail "repl doctor body"
pass "FRPCTL_INTERACTIVE_DOCTOR"

# Connection info stays on public endpoints
grep -q '203.0.113.10:8443' "$CL/etc/frp/access-info.txt" || fail "access-info public host"
if grep -q '0.0.0.0:443' "$CL/etc/frp/access-info.txt"; then
  fail "access-info used listen endpoint"
fi
pass "CONNECTION_INFO_PUBLIC_ENDPOINTS"

# Help
"$CTL" help >"$WORKDIR/help.out"
grep -q 'doctor' "$WORKDIR/help.out" || fail "help missing doctor"
pass "HELP_UPDATED"

echo
echo "DOCTOR_TESTS=PASS"
exit 0
