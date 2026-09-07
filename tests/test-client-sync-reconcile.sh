#!/usr/bin/env bash
# Finding A/B: client sync/reconcile fail-closed + public_hostname lifecycle.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORKDIR/client-root"
mkdir -p \
  "$TREE/etc/frp" \
  "$TREE/etc/frp-auto-deploy" \
  "$TREE/usr/local/lib/frp-auto-deploy" \
  "$TREE/var/lib/frp-auto-deploy"
cp "$ROOT/lib/frp-client-common.sh" "$TREE/usr/local/lib/frp-auto-deploy/frp-client-common.sh"
cp "$ROOT/lib/frp-common.sh" "$TREE/usr/local/lib/frp-auto-deploy/frp-common.sh"
cp "$ROOT/lib/frp_mgmt_auth.py" "$TREE/usr/local/lib/frp-auto-deploy/frp_mgmt_auth.py"
if [[ -f "$ROOT/lib/frp-macos.sh" ]]; then
  cp "$ROOT/lib/frp-macos.sh" "$TREE/usr/local/lib/frp-auto-deploy/frp-macos.sh"
fi

export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_CLIENT_LIB="$TREE/usr/local/lib/frp-auto-deploy/frp-client-common.sh"
export FRP_SKIP_SYSTEMD=1
export FRP_SKIP_DOWNLOAD=1
# Do not skip connectivity unless a case opts in; mocks/hooks drive the network.
unset FRP_SKIP_CONNECTIVITY_CHECK || true

MAC='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
printf '%s\n' "$MAC" >"$TREE/etc/frp/client-identity.mac"
python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key "$TREE/etc/frp/client-identity.key" \
  "$TREE/etc/frp/client-identity.pub" >/dev/null

write_state() {
  python3 - "$TREE/etc/frp/client-state.json" "$@" <<'PY'
import json, sys
from pathlib import Path
dest = Path(sys.argv[1])
hostname = sys.argv[2] if len(sys.argv) > 2 else ''
ssh_enabled = True
web_enabled = True
if len(sys.argv) > 3:
    ssh_enabled = sys.argv[3].lower() == 'true'
if len(sys.argv) > 4:
    web_enabled = sys.argv[4].lower() == 'true'
zero = len(sys.argv) > 5 and sys.argv[5] == 'zero'
state = {
  "schema_version": 1,
  "allocator_url": "https://127.0.0.1:9999/enroll",
  "frp_server": "203.0.113.10",
  "frp_server_port": 443,
  "hostname": "dp-example",
  "machine_id": "aabbccddeeff00112233445566778899",
  "host_id": "host-example",
  "frp_transport": "tcp",
  "install_status": "installed",
  "services": {},
}
if hostname:
    state["public_hostname"] = hostname
if not zero:
    state["services"] = {
      "ssh": {
        "id": "ssh", "name": "SSH", "protocol": "tcp",
        "local_ip": "127.0.0.1", "local_port": 22, "preset": "ssh",
        "ssh_user": "aella", "remote_port": 6000, "enabled": ssh_enabled,
      },
      "web": {
        "id": "web", "name": "Web", "protocol": "tcp",
        "local_ip": "127.0.0.1", "local_port": 18080, "preset": "http",
        "remote_port": 6001, "enabled": web_enabled,
      },
    }
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  cat >"$TREE/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.token = "tok-test-not-a-secret"
[[proxies]]
name = "aabbccddeeff-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000
[[proxies]]
name = "aabbccddeeff-web"
type = "tcp"
localIP = "127.0.0.1"
localPort = 18080
remotePort = 6001
EOF
}

state_json() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")))' \
    "$TREE/etc/frp/client-state.json" >/dev/null
  python3 - "$TREE/etc/frp/client-state.json" "$1" <<'PY'
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
expr = sys.argv[2]
print(eval(expr, {'state': state}))
PY
}

run_reconcile() {
  local out="$WORKDIR/reconcile.out" err="$WORKDIR/reconcile.err"
  set +e
  bash -c 'source "$FRP_CLIENT_LIB"; frp_client_reconcile_released_services "$@"' _ "$@" \
    >"$out" 2>"$err"
  local rc=$?
  set -e
  RECONCILE_RC=$rc
}

run_sync() {
  local out="$WORKDIR/sync.out" err="$WORKDIR/sync.err"
  set +e
  FRP_CLIENT_TOOL_SOURCED=1 bash -c '
    source "$ROOT/tools/frp-client"
    frp_client_sync
  ' >"$out" 2>"$err"
  local rc=$?
  set -e
  SYNC_RC=$rc
}

hmac_response() {
  python3 - "$MAC" "$1" <<'PY'
import hashlib, hmac, json, sys
secret = sys.argv[1].encode()
payload = json.loads(sys.argv[2])
canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
payload['response_hmac'] = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
print(json.dumps(payload, separators=(',', ':')))
PY
}

export ROOT

# 1. successful reconcile (enabled service released)
write_state ''
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS
[[ "$RECONCILE_RC" -eq 0 ]] || fail "successful reconcile rc=$RECONCILE_RC"
[[ "$(state_json "'web' in state['services']")" == "False" ]] || fail "released web still present"
[[ "$(state_json "'ssh' in state['services']")" == "True" ]] || fail "ssh dropped"
grep -q 'remotePort = 6001' "$TREE/etc/frp/frpc.toml" && fail "toml kept released web" || true
grep -q 'serverAddr = "203.0.113.10"' "$TREE/etc/frp/frpc.toml" || fail "serverAddr mutated"
pass "RECONCILE_SUCCESS"

# 2. no-op reconcile
write_state ''
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh","web"]'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS
[[ "$RECONCILE_RC" -eq 0 ]] || fail "no-op reconcile rc"
[[ "$(state_json "'web' in state['services']")" == "True" ]] || fail "no-op dropped web"
pass "RECONCILE_NO_CHANGE"

# 3. allocator unreachable
write_state ''
export FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE=1
run_reconcile
unset FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE
[[ "$RECONCILE_RC" -ne 0 ]] || fail "unreachable treated as success"
grep -q 'FAILURE_CLASS=ALLOCATOR_UNREACHABLE' "$WORKDIR/reconcile.err" || fail "unreachable class"
pass "RECONCILE_ALLOCATOR_UNREACHABLE"

# 4. invalid HMAC
write_state ''
export FRP_CLIENT_HOOK_RECONCILE_HMAC=1
run_reconcile
unset FRP_CLIENT_HOOK_RECONCILE_HMAC
[[ "$RECONCILE_RC" -ne 0 ]] || fail "hmac failure treated as success"
grep -q 'FAILURE_CLASS=HMAC_VERIFICATION_FAILED' "$WORKDIR/reconcile.err" || fail "hmac class"
pass "RECONCILE_HMAC_FAILED"

# 5. malformed response
write_state ''
export FRP_CLIENT_HOOK_RECONCILE_MALFORMED=1
run_reconcile
unset FRP_CLIENT_HOOK_RECONCILE_MALFORMED
[[ "$RECONCILE_RC" -ne 0 ]] || fail "malformed treated as success"
grep -q 'FAILURE_CLASS=INVALID_RESPONSE' "$WORKDIR/reconcile.err" || fail "malformed class"
pass "RECONCILE_MALFORMED"

# 6. released enabled service (already covered; keep explicit)
write_state '' true true
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS
[[ "$(state_json "state['services']['ssh']['enabled']")" == "True" ]] || fail "enabled ssh lost"
[[ "$(state_json "'web' in state['services']")" == "False" ]] || fail "enabled web not released"
pass "RECONCILE_RELEASED_ENABLED"

# 7. released disabled service
write_state '' true false
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS
[[ "$(state_json "'web' in state['services']")" == "False" ]] || fail "disabled released web kept"
[[ "$(state_json "'ssh' in state['services']")" == "True" ]] || fail "ssh lost with disabled web release"
pass "RECONCILE_RELEASED_DISABLED"

# 8. TOML regeneration failure
write_state ''
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
export FRP_CLIENT_HOOK_TOML_REGEN=1
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_HOOK_TOML_REGEN
[[ "$RECONCILE_RC" -ne 0 ]] || fail "toml regen failure treated as success"
grep -q 'RECOVERY_REQUIRED=YES' "$WORKDIR/reconcile.err" || fail "toml recovery flag"
[[ "$(state_json "'web' in state['services']")" == "False" ]] || fail "toml failure restored released service"
pass "RECONCILE_TOML_REGEN_FAILURE"

# 9. access-info regeneration failure
write_state ''
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
export FRP_CLIENT_HOOK_ACCESS_REGEN=1
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_HOOK_ACCESS_REGEN
[[ "$RECONCILE_RC" -ne 0 ]] || fail "access regen failure treated as success"
grep -q 'RECOVERY_REQUIRED=YES' "$WORKDIR/reconcile.err" || fail "access recovery flag"
[[ "$(state_json "'web' in state['services']")" == "False" ]] || fail "access failure restored released service"
pass "RECONCILE_ACCESS_REGEN_FAILURE"

# 10. frpc restart failure
write_state ''
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
export FRP_CLIENT_HOOK_RESTART_FAIL=1
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_HOOK_RESTART_FAIL
[[ "$RECONCILE_RC" -ne 0 ]] || fail "restart failure treated as success"
grep -q 'FAILURE_CLASS=FRPC_RESTART_FAILED' "$WORKDIR/reconcile.err" || fail "restart class"
grep -q 'RECOVERY_REQUIRED=YES' "$WORKDIR/reconcile.err" || fail "restart recovery flag"
pass "RECONCILE_FRPC_RESTART_FAILURE"

# 11/12. explicit sync non-zero and no success line
write_state ''
export FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE=1
run_sync
unset FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE
[[ "$SYNC_RC" -ne 0 ]] || fail "explicit sync succeeded on failure"
if grep -q 'Client sync complete.' "$WORKDIR/sync.out"; then
  fail "sync printed success after failure"
fi
grep -q 'allocator unreachable' "$WORKDIR/sync.err" || fail "sync missing error"
pass "SYNC_FAILURE_NO_SUCCESS_LINE"

write_state ''
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh","web"]'
run_sync
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS
[[ "$SYNC_RC" -eq 0 ]] || fail "explicit sync no-op failed"
grep -q 'Client sync complete.' "$WORKDIR/sync.out" || fail "sync success line missing"
pass "SYNC_NO_CHANGE_SUCCESS"

# 13. apply does not continue after required reconcile failure
write_state ''
python3 - "$TREE/etc/frp/client-state.json" "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY'
import json, shutil, sys
from pathlib import Path
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
shutil.copyfile(src, dest)
d = json.loads(dest.read_text(encoding='utf-8'))
d['services']['web']['local_port'] = 18081
dest.write_text(json.dumps(d, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
BEFORE="$(sha256sum "$TREE/etc/frp/client-state.json" | awk '{print $1}')"
export FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE=1
export FRP_CLIENT_CANDIDATE="$TREE/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_TOOL_SOURCED=1
set +e
bash -c '
  source "$ROOT/tools/frp-client"
  CANDIDATE_FILE="$FRP_CLIENT_CANDIDATE"
  frp_apply_candidate
' >"$WORKDIR/apply.out" 2>"$WORKDIR/apply.err"
APPLY_RC=$?
set -e
unset FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE FRP_CLIENT_CANDIDATE
[[ "$APPLY_RC" -ne 0 ]] || fail "apply continued after reconcile failure"
grep -q 'cannot apply because client synchronization failed' "$WORKDIR/apply.err" \
  || grep -q 'cannot apply because client synchronization failed' "$WORKDIR/apply.out" \
  || fail "apply missing reconcile failure"
AFTER="$(sha256sum "$TREE/etc/frp/client-state.json" | awk '{print $1}')"
[[ "$BEFORE" == "$AFTER" ]] || fail "apply mutated state after reconcile failure"
pass "APPLY_ABORTS_AFTER_RECONCILE_FAILURE"

# 14. local-only apply remains local-only
write_state ''
python3 - "$TREE/etc/frp/client-state.json" "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY'
import json, shutil, sys
from pathlib import Path
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
shutil.copyfile(src, dest)
d = json.loads(dest.read_text(encoding='utf-8'))
d['services']['ssh']['name'] = 'Office SSH'
dest.write_text(json.dumps(d, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
export FRP_SKIP_CONNECTIVITY_CHECK=1
export FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE=1
export FRP_CLIENT_CANDIDATE="$TREE/var/lib/frp-auto-deploy/client-draft.json"
set +e
bash -c '
  source "$ROOT/tools/frp-client"
  CANDIDATE_FILE="$FRP_CLIENT_CANDIDATE"
  frp_apply_candidate
' >"$WORKDIR/local.out" 2>"$WORKDIR/local.err"
LOCAL_RC=$?
set -e
unset FRP_SKIP_CONNECTIVITY_CHECK FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE FRP_CLIENT_CANDIDATE
[[ "$LOCAL_RC" -eq 0 ]] || fail "local-only apply failed rc=$LOCAL_RC $(cat "$WORKDIR/local.err")"
grep -q 'Allocator contacted : NO' "$WORKDIR/local.out" || fail "local-only contacted allocator"
grep -q 'frpc restarted      : NO' "$WORKDIR/local.out" || fail "local-only restarted frpc"
[[ "$(state_json "state['services']['ssh']['name']")" == "Office SSH" ]] || fail "local name not applied"
pass "LOCAL_ONLY_APPLY"

# public_hostname: set / change / clear / old-server absent / zero-service
write_state ''
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh","web"]'
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT=1
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME='access.example.com'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME
[[ "$RECONCILE_RC" -eq 0 ]] || fail "hostname set reconcile"
[[ "$(state_json "state.get('public_hostname')")" == "access.example.com" ]] || fail "hostname not set"
grep -q 'serverAddr = "203.0.113.10"' "$TREE/etc/frp/frpc.toml" || fail "hostname set mutated serverAddr"
pass "PUBLIC_HOSTNAME_SET"

export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh","web"]'
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT=1
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME='access2.example.com'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME
[[ "$(state_json "state.get('public_hostname')")" == "access2.example.com" ]] || fail "hostname not changed"
pass "PUBLIC_HOSTNAME_CHANGE"

export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh","web"]'
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT=1
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME=''
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME
[[ "$(state_json "state.get('public_hostname')")" == "None" ]] || fail "hostname not cleared"
pass "PUBLIC_HOSTNAME_UNSET"

write_state 'stale.example.com'
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh","web"]'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS
[[ "$(state_json "state.get('public_hostname')")" == "stale.example.com" ]] || fail "old-server absent cleared hostname"
pass "PUBLIC_HOSTNAME_OLD_SERVER_COMPAT"

write_state 'keep.example.com' true true zero
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='[]'
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT=1
export FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME='zero.example.com'
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME
[[ "$RECONCILE_RC" -eq 0 ]] || fail "zero-service hostname sync"
[[ "$(state_json "state.get('public_hostname')")" == "zero.example.com" ]] || fail "zero-service hostname"
[[ "$(state_json "len(state.get('services') or {})")" == "0" ]] || fail "zero-service gained proxies"
pass "PUBLIC_HOSTNAME_ZERO_SERVICE_SYNC"

# HMAC-signed payload path
write_state ''
RESP="$(hmac_response '{"frp_server":"203.0.113.10","frp_server_port":443,"frp_transport":"tcp","registry_service_ids":["ssh"],"public_hostname":"signed.example.com"}')"
export FRP_CLIENT_RECONCILE_RESPONSE="$RESP"
run_reconcile
unset FRP_CLIENT_RECONCILE_RESPONSE
[[ "$RECONCILE_RC" -eq 0 ]] || fail "signed reconcile $(cat "$WORKDIR/reconcile.err")"
[[ "$(state_json "state.get('public_hostname')")" == "signed.example.com" ]] || fail "signed hostname"
[[ "$(state_json "'web' in state['services']")" == "False" ]] || fail "signed release"
pass "RECONCILE_SIGNED_RESPONSE"

BAD="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["response_hmac"]="00"*32; print(json.dumps(d))' "$RESP")"
export FRP_CLIENT_RECONCILE_RESPONSE="$BAD"
run_reconcile
unset FRP_CLIENT_RECONCILE_RESPONSE
[[ "$RECONCILE_RC" -ne 0 ]] || fail "bad hmac payload accepted"
grep -q 'HMAC_VERIFICATION_FAILED' "$WORKDIR/reconcile.err" || fail "bad hmac class from payload"
pass "RECONCILE_SIGNED_HMAC_REJECTED"

# Fresh install completion output uses preferred/fallback
python3 - "$WORKDIR/install-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_hostname": "access.example.com",
  "services": {
    "ssh": {
      "id": "ssh", "name": "SSH", "preset": "ssh", "protocol": "tcp",
      "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 6001,
      "ssh_user": "leeruda", "enabled": True,
    }
  }
}, indent=2) + "\n")
PY
export FRP_CLIENT_SOURCED=1
# shellcheck disable=SC1091
. "$ROOT/install-client.sh"
print_complete "203.0.113.10" "$WORKDIR/install-state.json" "access.example.com" \
  >"$WORKDIR/install-complete.out"
grep -q 'ssh -p 6001 leeruda@access.example.com' "$WORKDIR/install-complete.out" \
  || fail "install complete missing preferred host"
grep -q 'ssh -p 6001 leeruda@203.0.113.10' "$WORKDIR/install-complete.out" \
  || fail "install complete missing fallback host"
pass "FRESH_INSTALL_OUTPUT_MATCHES_INFO"

# Pending adds must survive reconcile: registry_service_ids cannot include
# services that have not been allocated yet. Released committed services
# must still be dropped from both committed state and the draft.
write_state ''
python3 - "$TREE/etc/frp/client-state.json" "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY'
import json, shutil, sys
from pathlib import Path
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
# committed: ssh only
d = json.loads(src.read_text(encoding='utf-8'))
d['services'] = {'ssh': d['services']['ssh']}
src.write_text(json.dumps(d, indent=2, sort_keys=True) + '\n', encoding='utf-8')
shutil.copyfile(src, dest)
draft = json.loads(dest.read_text(encoding='utf-8'))
draft['services']['e2ehttp'] = {
    'id': 'e2ehttp', 'name': 'e2ehttp', 'preset': 'http', 'protocol': 'tcp',
    'local_ip': '127.0.0.1', 'local_port': 18080, 'enabled': True,
}
dest.write_text(json.dumps(draft, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
export CANDIDATE_FILE="$TREE/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_CANDIDATE="$CANDIDATE_FILE"
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS CANDIDATE_FILE FRP_CLIENT_CANDIDATE
[[ "$RECONCILE_RC" -eq 0 ]] || fail "pending-add reconcile rc=$RECONCILE_RC $(cat "$WORKDIR/reconcile.err")"
[[ "$(state_json "sorted(state['services'])")" == "['ssh']" ]] || fail "committed gained pending add"
python3 - "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "pending add stripped from draft"
import json, sys
from pathlib import Path
d = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
svcs = d.get('services') or {}
assert 'ssh' in svcs, svcs
assert 'e2ehttp' in svcs, svcs
PY
pass "RECONCILE_KEEPS_PENDING_ADD"

write_state ''
python3 - "$TREE/etc/frp/client-state.json" "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY'
import json, shutil, sys
from pathlib import Path
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
shutil.copyfile(src, dest)
draft = json.loads(dest.read_text(encoding='utf-8'))
draft['services']['e2ehttp'] = {
    'id': 'e2ehttp', 'name': 'e2ehttp', 'preset': 'http', 'protocol': 'tcp',
    'local_ip': '127.0.0.1', 'local_port': 18080, 'enabled': True,
}
dest.write_text(json.dumps(draft, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
export CANDIDATE_FILE="$TREE/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_CANDIDATE="$CANDIDATE_FILE"
run_reconcile
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS CANDIDATE_FILE FRP_CLIENT_CANDIDATE
[[ "$RECONCILE_RC" -eq 0 ]] || fail "released+pending reconcile rc=$RECONCILE_RC"
[[ "$(state_json "sorted(state['services'])")" == "['ssh']" ]] || fail "released web not dropped from committed"
python3 - "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "draft should drop released web and keep pending http"
import json, sys
from pathlib import Path
d = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
svcs = d.get('services') or {}
assert 'ssh' in svcs, svcs
assert 'web' not in svcs, svcs
assert 'e2ehttp' in svcs, svcs
PY
pass "RECONCILE_DROPS_RELEASED_KEEPS_PENDING_ADD"

write_state ''
python3 - "$TREE/etc/frp/client-state.json" "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY'
import json, shutil, sys
from pathlib import Path
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
d = json.loads(src.read_text(encoding='utf-8'))
d['services'] = {'ssh': d['services']['ssh']}
src.write_text(json.dumps(d, indent=2, sort_keys=True) + '\n', encoding='utf-8')
shutil.copyfile(src, dest)
draft = json.loads(dest.read_text(encoding='utf-8'))
draft['services']['e2ehttp'] = {
    'id': 'e2ehttp', 'name': 'e2ehttp', 'preset': 'http', 'protocol': 'tcp',
    'local_ip': '127.0.0.1', 'local_port': 18080, 'enabled': True,
}
dest.write_text(json.dumps(draft, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
export FRP_CLIENT_RECONCILE_REGISTRY_IDS='["ssh"]'
export FRP_CLIENT_CANDIDATE="$TREE/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_TOOL_SOURCED=1
set +e
bash -c '
  source "$ROOT/tools/frp-client"
  CANDIDATE_FILE="$FRP_CLIENT_CANDIDATE"
  frp_apply_candidate
' >"$WORKDIR/apply-add.out" 2>"$WORKDIR/apply-add.err"
APPLY_ADD_RC=$?
set -e
unset FRP_CLIENT_RECONCILE_REGISTRY_IDS FRP_CLIENT_CANDIDATE
python3 - "$TREE/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "apply reconcile stripped pending add"
import json, sys
from pathlib import Path
d = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
assert 'e2ehttp' in (d.get('services') or {}), d
PY
if grep -q 'No pending changes.' "$WORKDIR/apply-add.out"; then
  fail "apply treated pending add as no-op"
fi
# Apply continues to allocator enroll; injected registry has no live allocator.
# The defect under test is the false no-op, not enroll success.
pass "APPLY_DOES_NOT_NOOP_PENDING_ADD"

echo "CLIENT_SYNC_RECONCILE_TEST=PASS"
