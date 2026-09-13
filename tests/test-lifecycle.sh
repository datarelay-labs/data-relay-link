#!/usr/bin/env bash
# P2.9 lifecycle hardening: transactions, idempotency, recovery, failure injection.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
ALLOC_PID=""
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
frp_test_arm_cleanup

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

files_equal() {
  python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path
a, b = Path(sys.argv[1]), Path(sys.argv[2])
raise SystemExit(0 if a.is_file() and b.is_file() and a.read_bytes() == b.read_bytes() else 1)
PY
}

chmod +x "$ROOT/tools/frp-client"

make_frpc() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<'EOF'
#!/bin/sh
if [ "$1" = verify ]; then
  exit 0
fi
exit 0
EOF
  chmod +x "$dest"
}

start_allocator() {
  local cfg="$1"
  python3 "$ROOT/server/frp-port-allocator.py" --config "$cfg" >"$WORKDIR/alloc.log" 2>&1 &
  ALLOC_PID=$!
  local i
  for i in $(seq 1 50); do
    if curl -fsS --cacert "$ALLOC_ROOT/pki/ca.crt" "https://127.0.0.1:${ALLOC_PORT}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  cat "$WORKDIR/alloc.log" >&2 || true
  fail "allocator did not start"
}

write_enrollment() {
  local dir="$1" eid="$2" secret="$3"
  python3 - "$dir" "$eid" "$secret" <<'PY'
import json, sys, time
from pathlib import Path
d, eid, secret = sys.argv[1], sys.argv[2], sys.argv[3]
now = int(time.time())
Path(d).mkdir(parents=True, exist_ok=True)
Path(d, f'{eid}.json').write_text(json.dumps({
    'id': eid,
    'secret': secret,
    'expires_at': now + 600,
    'bound_machine_id': None,
    'used_at': None,
}, indent=2) + '\n')
PY
}

ALLOC_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
ALLOC_ROOT="$WORKDIR/allocator"
mkdir -p "$ALLOC_ROOT/enrollments"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$ALLOC_ROOT/pki" --public-host 127.0.0.1 >/dev/null
CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$ALLOC_ROOT/pki/ca.crt")"
python3 - "$ALLOC_ROOT" "$ALLOC_PORT" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
port = int(sys.argv[2])
pki = root / 'pki'
(root / 'server_token').write_text('test-enroll-token-do-not-use\n')
(root / 'server_token').chmod(0o600)
(root / 'registry.json').write_text(json.dumps({
    'schema_version': 2, 'reserved': [], 'clients': {},
}, indent=2) + '\n')
(root / 'config.json').write_text(json.dumps({
    'public_host': '203.0.113.10',
    'public_ip': '203.0.113.10',
    'frp_control_public_port': 8443,
    'frp_control_listen_port': 443,
    'port_start': 18400,
    'port_end': 18430,
    'listen_host': '127.0.0.1',
    'listen_port': port,
    'allocator_listen_port': port,
    'allocator_public_port': port,
    'tls_ca_cert': str(pki / 'ca.crt'),
    'tls_server_cert': str(pki / 'server.crt'),
    'tls_server_key': str(pki / 'server.key'),
    'registry_file': str(root / 'registry.json'),
    'enrollments_dir': str(root / 'enrollments'),
    'token_file': str(root / 'server_token'),
}, indent=2) + '\n')
PY
start_allocator "$ALLOC_ROOT/config.json"

EID='abcdef0123456789'
SECRET='enroll-secret-abcdef0123456789abcdef0123456789ab'
write_enrollment "$ALLOC_ROOT/enrollments" "$EID" "$SECRET"

TREE="$WORKDIR/client"
mkdir -p "$TREE/etc/frp" "$TREE/usr/local/bin" "$TREE/usr/local/lib/drlink"
make_frpc "$TREE/usr/local/bin/frpc"

export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_SKIP_DOWNLOAD=1
export FRP_SKIP_SYSTEMD=1
export FRP_SKIP_CONNECTIVITY_CHECK=1
export FRP_TEST_HOSTNAME='dp-lifecycle'
export FRP_TEST_MACHINE_ID='aabbccddeeff00112233445566778899'
export FRP_ALLOCATOR_URL="https://127.0.0.1:${ALLOC_PORT}/enroll"
export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
export FRP_ENROLLMENT_CODE="${EID}.${SECRET}"
export FRP_SERVICES_JSON='[{"id":"ssh","name":"SSH","protocol":"tcp","local_ip":"127.0.0.1","local_port":22,"preset":"ssh","ssh_user":"aella"}]'
export FRP_CLIENT_SOURCED=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"
frp_client_main >"$WORKDIR/install.out"

STATE="$TREE/etc/frp/client-state.json"
HOOK="$WORKDIR/hook.log"
: >"$HOOK"
export FRP_CLIENT_HOOK_LOG="$HOOK"

apply_cand() {
  export FRP_CLIENT_CANDIDATE="$1"
  unset FRP_ENROLLMENT_CODE || true
  "$ROOT/tools/frp-client" apply
}

# --- add grafana ---
CAND="$WORKDIR/cand-add.json"
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']={
  'id':'grafana','name':'Grafana','preset':'custom','protocol':'tcp',
  'local_ip':'127.0.0.1','local_port':3000,'enabled':True,
}
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
apply_cand "$CAND" >"$WORKDIR/add.out"
python3 - "$STATE" "$TREE/etc/frp/frpc.toml" "$ALLOC_ROOT/registry.json" <<'PY' || fail "add grafana consistency"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
toml=Path(sys.argv[2]).read_text()
reg=json.loads(Path(sys.argv[3]).read_text())
assert d['services']['grafana']['remote_port']==18401
assert 'grafana' in toml
mid=d['machine_id']
assert reg['clients'][mid]['services']['grafana']['remote_port']==18401
assert reg['clients'][mid]['services']['ssh']['remote_port']==18400
PY
[[ ! -f "$TREE/etc/frp/apply-pending.json" ]] || fail "pending marker left after success"
pass "add service success is consistent"

# --- duplicate add retry ---
cp "$STATE" "$CAND"
: >"$HOOK"
apply_cand "$CAND" >"$WORKDIR/dup.out"
grep -q 'No pending changes.' "$WORKDIR/dup.out" || fail "duplicate add should be no-op"
if grep -qx enroll "$HOOK"; then fail "duplicate add contacted allocator"; fi
python3 - "$STATE" "$ALLOC_ROOT/registry.json" <<'PY' || fail "duplicate add ports"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
reg=json.loads(Path(sys.argv[2]).read_text())
assert d['services']['grafana']['remote_port']==18401
assert len(reg['clients'][d['machine_id']]['services'])==2
PY
pass "duplicate add retry is idempotent"

# --- edit target preserves port ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_port']=3100
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
apply_cand "$CAND" >"$WORKDIR/edit.out"
python3 - "$STATE" <<'PY' || fail "edit port"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['local_port']==3100
assert d['services']['grafana']['remote_port']==18401
PY
pass "edit target preserves public port"

# --- disable / enable loop ---
for step in disable disable enable enable disable enable; do
  python3 - "$STATE" "$CAND" "$step" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['enabled'] = (sys.argv[3] == 'enable')
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
  apply_cand "$CAND" >"$WORKDIR/loop.out" || fail "enable/disable loop $step"
done
python3 - "$STATE" "$TREE/etc/frp/frpc.toml" "$ALLOC_ROOT/registry.json" <<'PY' || fail "loop semantics"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
toml=Path(sys.argv[2]).read_text()
reg=json.loads(Path(sys.argv[3]).read_text())
assert d['services']['grafana']['enabled'] is True
assert d['services']['grafana']['remote_port']==18401
assert 'grafana' in toml
mid=d['machine_id']
assert reg['clients'][mid]['services']['grafana']['remote_port']==18401
assert sorted(reg['clients'][mid]['services'])==['grafana','ssh']
PY
pass "disable/enable loop reuses the same port"

# --- after-server-mutation failure preserves previous local state ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.40'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
cp "$STATE" "$WORKDIR/state.before"
cp "$TREE/etc/frp/frpc.toml" "$WORKDIR/toml.before"
export FRP_CLIENT_HOOK_AFTER_SERVER_MUTATION=1
if apply_cand "$CAND" >"$WORKDIR/after-mut.out" 2>"$WORKDIR/after-mut.err"; then
  fail "after-server-mutation hook should fail apply"
fi
unset FRP_CLIENT_HOOK_AFTER_SERVER_MUTATION
files_equal "$STATE" "$WORKDIR/state.before" || fail "after-mutation changed state"
files_equal "$TREE/etc/frp/frpc.toml" "$WORKDIR/toml.before" || fail "after-mutation changed toml"
grep -q 'FAILURE_CLASS=FAILED_WITH_RESERVATION_PRESERVED' "$WORKDIR/after-mut.out" "$WORKDIR/after-mut.err" || fail "after-mutation class"
python3 - "$ALLOC_ROOT/registry.json" "$STATE" <<'PY' || fail "reservation preserved"
import json,sys
from pathlib import Path
reg=json.loads(Path(sys.argv[1]).read_text())
d=json.loads(Path(sys.argv[2]).read_text())
svc=reg['clients'][d['machine_id']]['services']['grafana']
assert svc['remote_port']==18401
assert svc['local_ip']=='10.10.20.40'
PY
pass "allocator success / local interrupt preserves previous state"

# retry the same logical edit — lost-response recovery
unset FRP_CLIENT_HOOK_AFTER_SERVER_MUTATION || true
apply_cand "$CAND" >"$WORKDIR/retry.out"
python3 - "$STATE" <<'PY' || fail "retry after lost apply"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['local_ip']=='10.10.20.40'
assert d['services']['grafana']['remote_port']==18401
PY
pass "lost-response retry commits the same reservation"

# --- state write failure ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.41'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
cp "$STATE" "$WORKDIR/state.before"
export FRP_CLIENT_HOOK_STATE_WRITE=1
if apply_cand "$CAND" >"$WORKDIR/state-write.out" 2>"$WORKDIR/state-write.err"; then
  fail "state write failure should fail apply"
fi
unset FRP_CLIENT_HOOK_STATE_WRITE
python3 - "$STATE" <<'PY' || fail "state write left invalid json"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['local_ip']=='10.10.20.40'
PY
grep -q 'FAILURE_CLASS=LOCAL_STATE_WRITE_FAILED' "$WORKDIR/state-write.out" "$WORKDIR/state-write.err" || fail "state write class"
mode="$(python3 - "$STATE" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
[[ "$mode" == "0o600" ]] || fail "state mode after write fail $mode"
pass "state write failure preserves previous JSON"

# --- config generation failure ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.42'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
cp "$TREE/etc/frp/frpc.toml" "$WORKDIR/toml.before"
export FRP_CLIENT_HOOK_CONFIG_GENERATION=1
export FRP_CLIENT_ENROLL_COUNT_FILE="$WORKDIR/enroll.count"
echo 0 >"$FRP_CLIENT_ENROLL_COUNT_FILE"
if apply_cand "$CAND" >"$WORKDIR/cfg.out" 2>"$WORKDIR/cfg.err"; then
  fail "config generation failure should fail apply"
fi
unset FRP_CLIENT_HOOK_CONFIG_GENERATION
files_equal "$TREE/etc/frp/frpc.toml" "$WORKDIR/toml.before" || fail "config fail rewrote toml"
grep -q 'LOCAL_ROLLBACK=PASS' "$WORKDIR/cfg.out" "$WORKDIR/cfg.err" || fail "config local rollback"
grep -q 'FAILURE_CLASS=CONFIG_GENERATION_FAILED' "$WORKDIR/cfg.out" "$WORKDIR/cfg.err" || fail "config class"
pass "config generation failure rolls back locally"

# --- restart failure rollback ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.43'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_HOOK_RESTART_FAIL=1
echo 0 >"$FRP_CLIENT_ENROLL_COUNT_FILE"
if apply_cand "$CAND" >"$WORKDIR/rst.out" 2>"$WORKDIR/rst.err"; then
  fail "restart failure should fail apply"
fi
unset FRP_CLIENT_HOOK_RESTART_FAIL
grep -q 'LOCAL_ROLLBACK=PASS' "$WORKDIR/rst.out" "$WORKDIR/rst.err" || fail "restart local rollback"
grep -q 'FAILURE_CLASS=FRPC_RESTART_FAILED' "$WORKDIR/rst.out" "$WORKDIR/rst.err" || fail "restart class"
python3 - "$STATE" <<'PY' || fail "restart left new target"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
assert d['services']['grafana']['local_ip']=='10.10.20.40'
PY
toml_mode="$(python3 - "$TREE/etc/frp/frpc.toml" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
[[ "$toml_mode" == "0o600" ]] || fail "toml mode after rollback $toml_mode"
pass "frpc restart failure restores prior runtime"

# --- compensation failure reported ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.44'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
export FRP_CLIENT_HOOK_VERIFY_FAIL=1
export FRP_CLIENT_HOOK_COMPENSATE_FAIL=1
echo 0 >"$FRP_CLIENT_ENROLL_COUNT_FILE"
if apply_cand "$CAND" >"$WORKDIR/comp.out" 2>"$WORKDIR/comp.err"; then
  fail "compensation-fail path should fail apply"
fi
unset FRP_CLIENT_HOOK_VERIFY_FAIL FRP_CLIENT_HOOK_COMPENSATE_FAIL
grep -q 'SERVER_ROLLBACK=FAIL' "$WORKDIR/comp.out" "$WORKDIR/comp.err" || fail "compensation failure not reported"
grep -q 'FAILURE_CLASS=RECOVERY_REQUIRED' "$WORKDIR/comp.out" "$WORKDIR/comp.err" || fail "rollback-fail class"
pass "rollback failure is reported"

# --- interrupted apply marker ---
python3 - "$TREE/etc/frp/apply-pending.json" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  'schema_version':1,
  'operation_id':'deadbeefdeadbeef',
  'phase':'server_mutation',
  'server_mutation':'ok',
  'service_ids':['ssh','grafana'],
  'prior_state_sha256':'abc',
  'candidate_state_sha256':'def',
}, indent=2)+'\n')
PY
"$ROOT/tools/frp-client" status >"$WORKDIR/pending-status.out"
grep -q 'RECOVERY_REQUIRED' "$WORKDIR/pending-status.out" || fail "status pending marker"
cp "$STATE" "$CAND"
apply_cand "$CAND" >"$WORKDIR/pending-apply.out"
[[ ! -f "$TREE/etc/frp/apply-pending.json" ]] || fail "apply did not clear consistent pending marker"
pass "interrupted apply is detected and cleared when consistent"

# --- missing access-info ---
rm -f "$TREE/etc/frp/access-info.txt"
: >"$HOOK"
cp "$STATE" "$CAND"
apply_cand "$CAND" >"$WORKDIR/access-miss.out"
[[ -f "$TREE/etc/frp/access-info.txt" ]] || fail "access-info not regenerated"
if grep -qx enroll "$HOOK"; then fail "missing access-info contacted allocator"; fi
pass "missing access-info regenerates locally"

# --- missing frpc.toml from backup token ---
cp "$TREE/etc/frp/frpc.toml" "$WORKDIR/toml.keep"
# force a backup that contains the token
"$ROOT/tools/frp-client" status >/dev/null
python3 - "$TREE" <<'PY'
import shutil, sys
from pathlib import Path
root = Path(sys.argv[1])
backup = root / 'etc/frp/backups/19990101T000000Z'
backup.mkdir(parents=True, exist_ok=True)
for name in ('client-state.json','frpc.toml','access-info.txt'):
    src = root / 'etc/frp' / name
    if src.is_file():
        shutil.copy2(src, backup / name)
PY
rm -f "$TREE/etc/frp/frpc.toml"
: >"$HOOK"
cp "$STATE" "$CAND"
apply_cand "$CAND" >"$WORKDIR/toml-miss.out"
[[ -f "$TREE/etc/frp/frpc.toml" ]] || fail "frpc.toml not regenerated"
if grep -qx enroll "$HOOK"; then fail "missing toml contacted allocator"; fi
if grep -q 'Enrollment Code' "$WORKDIR/toml-miss.out"; then fail "missing toml required enrollment"; fi
grep -q 'grafana' "$TREE/etc/frp/frpc.toml" || fail "regenerated toml missing grafana"
pass "missing frpc.toml regenerates from backup token"

# --- stale local target vs server reservation ---
python3 - "$STATE" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
d=json.loads(p.read_text())
d['services']['grafana']['local_ip']='127.0.0.1'
d['services']['grafana']['local_port']=3000
p.write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['grafana']['local_ip']='10.10.20.50'
d['services']['grafana']['local_port']=3200
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
apply_cand "$CAND" >"$WORKDIR/stale.out"
python3 - "$STATE" "$ALLOC_ROOT/registry.json" <<'PY' || fail "stale reconcile"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
reg=json.loads(Path(sys.argv[2]).read_text())
assert d['services']['grafana']['local_ip']=='10.10.20.50'
assert d['services']['grafana']['local_port']==3200
assert d['services']['grafana']['remote_port']==18401
assert reg['clients'][d['machine_id']]['services']['grafana']['remote_port']==18401
PY
pass "stale client state reconciles without reallocating"

# --- backup retention ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['ssh']['name']='SSH-keep'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
for i in $(seq 1 8); do
  python3 - "$STATE" "$CAND" "$i" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['ssh']['name']='SSH-'+sys.argv[3]
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
  apply_cand "$CAND" >/dev/null
done
backup_n="$(python3 - "$TREE/etc/frp/backups" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
print(sum(1 for p in root.iterdir() if p.is_dir()) if root.is_dir() else 0)
PY
)"
if [[ "$backup_n" -gt 5 ]]; then
  fail "backup retention grew to $backup_n"
fi
pass "backup retention stays at 5"

# --- local-only still skips allocator ---
python3 - "$STATE" "$CAND" <<'PY'
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
d['services']['ssh']['name']='ssh-local'
Path(sys.argv[2]).write_text(json.dumps(d, indent=2, sort_keys=True)+'\n')
PY
: >"$HOOK"
apply_cand "$CAND" >"$WORKDIR/local.out"
if grep -qx enroll "$HOOK"; then fail "local-only contacted allocator"; fi
if grep -qx restart "$HOOK"; then fail "local-only restarted"; fi
pass "local-only metadata still skips allocator"

echo
echo "LIFECYCLE_TEST=PASS"
