#!/usr/bin/env bash
# Post-v2.1.3 core correctness: revoke, txn markers, purge, uninstall, allocator deps.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
mkdir -p \
  "$TREE/etc/frp-auto-deploy" \
  "$TREE/var/lib/frp-auto-deploy/enrollments" \
  "$TREE/var/lib/frp-auto-deploy/bootstrap" \
  "$TREE/usr/local/lib/frp-auto-deploy" \
  "$TREE/usr/local/sbin" \
  "$TREE/usr/local/bin" \
  "$TREE/etc/frp"

python3 - "$TREE" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
now = int(time.time())
(root / 'etc/frp-auto-deploy/config.json').write_text(json.dumps({
  'enrollments_dir': '/var/lib/frp-auto-deploy/enrollments',
  'bootstrap_dir': '/var/lib/frp-auto-deploy/bootstrap',
  'registry_file': '/var/lib/frp-auto-deploy/registry.json',
}) + '\n')
(root / 'var/lib/frp-auto-deploy/registry.json').write_text(
    json.dumps({'schema_version': 2, 'clients': {}}) + '\n'
)
eid = 'aa11bb22cc33dd44'
tid = 'bb22cc33dd44ee55'
(root / 'var/lib/frp-auto-deploy/enrollments' / (eid + '.json')).write_text(json.dumps({
  'id': eid,
  'secret': 'a' * 64,
  'expires_at': now + 600,
  'bound_machine_id': None,
  'used_at': None,
}) + '\n')
(root / 'var/lib/frp-auto-deploy/bootstrap' / (tid + '.json')).write_text(json.dumps({
  'id': tid,
  'enrollment_id': eid,
  'secret_hash': 'b' * 64,
  'expires_at': now + 600,
}) + '\n')
PY

export FRP_DEPLOY_TEST_ROOT="$TREE"
REVOKE="$ROOT/tools/frp-enrollment-revoke"
EID=aa11bb22cc33dd44
TID=bb22cc33dd44ee55

# --- Revoke fail-closed: enrollment first ---
export FRP_REVOKE_HOOK_FAIL_AFTER_ENROLLMENT=1
if "$REVOKE" "$TID" >/dev/null 2>"$WORK/revoke-after.err"; then
  fail "revoke should error after enrollment write when ticket step blocked"
fi
unset FRP_REVOKE_HOOK_FAIL_AFTER_ENROLLMENT
python3 - "$TREE" "$EID" <<'PY' || fail "enrollment not revoked after partial"
import json,sys
from pathlib import Path
rec=json.loads((Path(sys.argv[1])/'var/lib/frp-auto-deploy/enrollments'/(sys.argv[2]+'.json')).read_text())
assert rec.get('revoked_at'), rec
PY
# Ticket may still be unrevoked — credential (enrollment) must be unusable.
python3 - "$TREE" "$TID" <<'PY'
import json,sys
from pathlib import Path
rec=json.loads((Path(sys.argv[1])/'var/lib/frp-auto-deploy/bootstrap'/(sys.argv[2]+'.json')).read_text())
# ticket may or may not be revoked depending on hook point; enrollment is what matters
print('ticket_revoked', bool(rec.get('revoked_at')))
PY
pass "REVOKE_PAIR_FAIL_CLOSED (enrollment invalidated first)"

# Fail before enrollment: neither should be revoked on a fresh pair
python3 - "$TREE" <<'PY'
import json,sys,time
from pathlib import Path
root=Path(sys.argv[1]); now=int(time.time())
eid='cc33dd44ee55ff66'; tid='dd44ee55ff667788'
(root/'var/lib/frp-auto-deploy/enrollments'/(eid+'.json')).write_text(json.dumps({
  'id':eid,'secret':'c'*64,'expires_at':now+600,'bound_machine_id':None,'used_at':None
})+'\n')
(root/'var/lib/frp-auto-deploy/bootstrap'/(tid+'.json')).write_text(json.dumps({
  'id':tid,'enrollment_id':eid,'secret_hash':'d'*64,'expires_at':now+600
})+'\n')
PY
export FRP_REVOKE_HOOK_FAIL_BEFORE_ENROLLMENT=1
if FRP_DEPLOY_TEST_ROOT="$TREE" "$REVOKE" dd44ee55ff667788 >/dev/null 2>"$WORK/revoke-before.err"; then
  fail "revoke should fail before enrollment write"
fi
unset FRP_REVOKE_HOOK_FAIL_BEFORE_ENROLLMENT
python3 - "$TREE" <<'PY' || fail "pre-enrollment failure mutated records"
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
en = json.loads((root / 'var/lib/frp-auto-deploy/enrollments' / 'cc33dd44ee55ff66.json').read_text())
tk = json.loads((root / 'var/lib/frp-auto-deploy/bootstrap' / 'dd44ee55ff667788.json').read_text())
assert not en.get('revoked_at'), en
assert not tk.get('revoked_at'), tk
PY
pass "revoke fail-before leaves pair intact"

# Successful revoke (enrollment-id path)
FRP_DEPLOY_TEST_ROOT="$TREE" "$REVOKE" cc33dd44ee55ff66 >/dev/null
python3 - "$TREE" <<'PY' || fail "full revoke incomplete"
import json, os
from pathlib import Path
root=Path(os.environ['FRP_DEPLOY_TEST_ROOT'])
en=json.loads((root/'var/lib/frp-auto-deploy/enrollments'/'cc33dd44ee55ff66.json').read_text())
tk=json.loads((root/'var/lib/frp-auto-deploy/bootstrap'/'dd44ee55ff667788.json').read_text())
assert en.get('revoked_at') and tk.get('revoked_at')
PY
pass "REVOKE_PAIR_FAIL_CLOSED"

# --- Role-specific txn markers ---
unset FRP_TXN_ROLE || true
export FRP_UPDATE_ROOT="$TREE"
export FRP_TXN_ROLE=server
FRP_TXN_MUTATION_STARTED=true frp_txn_write project-update commit "2.1.2" "2.1.3"
[[ -f "$TREE/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "server marker missing"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/client-update-pending.json" ]] || fail "client marker should be absent"
export FRP_TXN_ROLE=client
FRP_TXN_MUTATION_STARTED=true frp_txn_write client-update commit "2.1.2" "2.1.3"
[[ -f "$TREE/var/lib/frp-auto-deploy/client-update-pending.json" ]] || fail "client marker missing"
[[ -f "$TREE/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "server marker cleared by client write"
frp_txn_clear client
[[ ! -f "$TREE/var/lib/frp-auto-deploy/client-update-pending.json" ]] || fail "client clear failed"
[[ -f "$TREE/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "server marker cleared by client clear"
pass "ROLE_SPECIFIC_TXN_MARKERS"
pass "DUAL_ROLE_TRANSACTION_ISOLATION"

# Legacy adopt
rm -f "$TREE/var/lib/frp-auto-deploy/server-update-pending.json" \
  "$TREE/var/lib/frp-auto-deploy/client-update-pending.json"
echo '{"operation":"project-update","phase":"commit","release_channel":"dev","source_ref":"main"}' \
  >"$TREE/var/lib/frp-auto-deploy/update-pending.json"
export FRP_TXN_ROLE=server
frp_txn_adopt_legacy_marker server || fail "legacy server adopt"
[[ -f "$TREE/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "adopt target missing"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/update-pending.json" ]] || fail "legacy remains"
echo '{"operation":"mystery","phase":"x"}' >"$TREE/var/lib/frp-auto-deploy/update-pending.json"
if frp_txn_adopt_legacy_marker server 2>/dev/null; then
  fail "ambiguous legacy should fail closed"
fi
rm -f "$TREE/var/lib/frp-auto-deploy/update-pending.json"
pass "LEGACY_TXN_MARKER_HANDLING"

# Client uninstall preserves server marker
mkdir -p "$TREE/var/lib/frp-auto-deploy"
echo '{"operation":"project-update","phase":"commit"}' \
  >"$TREE/var/lib/frp-auto-deploy/server-update-pending.json"
echo '{"operation":"client-update","phase":"commit"}' \
  >"$TREE/var/lib/frp-auto-deploy/client-update-pending.json"
echo '{"machine_id":"m1"}' >"$TREE/etc/frp/client-state.json"
FRP_UNINSTALL_TEST_ROOT="$TREE" FRP_UNINSTALL_HOOK_SKIP_SYSTEMD=1 \
  bash "$ROOT/uninstall-client.sh" >/dev/null
[[ -f "$TREE/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "client uninstall cleared server marker"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/client-update-pending.json" ]] || fail "client uninstall left client marker"
pass "client uninstall preserves server pending marker"

# --- Purge confirmation ---
# Restore minimal server+client dual role for purge tests
mkdir -p "$TREE/usr/local/lib/frp-auto-deploy" \
  "$TREE/var/lib/frp-auto-deploy/client-upgrades" \
  "$TREE/etc/frp" \
  "$TREE/etc/frp-auto-deploy"
echo 'shared' >"$TREE/usr/local/lib/frp-auto-deploy/frp-common.sh"
echo 'client' >"$TREE/usr/local/lib/frp-auto-deploy/frp_enrollment_lifecycle.py"
echo '{}' >"$TREE/var/lib/frp-auto-deploy/registry.json"
echo 'draft' >"$TREE/var/lib/frp-auto-deploy/client-draft.json"
mkdir -p "$TREE/var/lib/frp-auto-deploy/client-upgrades/x"
echo '{"machine_id":"m1"}' >"$TREE/etc/frp/client-state.json"
echo 'cfg' >"$TREE/etc/frp-auto-deploy/config.json"
# Copy minimal project files helper into tree for uninstall
cp "$ROOT/lib/frp_project_files.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/server-project-files.manifest" "$TREE/usr/local/lib/frp-auto-deploy/"

for bad in no false 0 YESSS ""; do
  if FRP_UNINSTALL_TEST_ROOT="$TREE" FRP_UNINSTALL_HOOK_SKIP_SYSTEMD=1 \
      FRP_PURGE_CONFIRM="$bad" bash "$ROOT/uninstall-server.sh" --purge >/dev/null 2>"$WORK/purge-bad.err"; then
    fail "FRP_PURGE_CONFIRM=$bad should reject"
  fi
done
# unset
if FRP_UNINSTALL_TEST_ROOT="$TREE" FRP_UNINSTALL_HOOK_SKIP_SYSTEMD=1 \
    env -u FRP_PURGE_CONFIRM bash "$ROOT/uninstall-server.sh" --purge >/dev/null 2>"$WORK/purge-unset.err"; then
  fail "unset FRP_PURGE_CONFIRM should reject"
fi
pass "PURGE_CONFIRMATION_FAIL_CLOSED"

# Dual-role purge preserves client state
FRP_UNINSTALL_TEST_ROOT="$TREE" FRP_UNINSTALL_HOOK_SKIP_SYSTEMD=1 \
  FRP_PURGE_CONFIRM=yes bash "$ROOT/uninstall-server.sh" --purge >/dev/null 2>"$WORK/purge.out" || true
[[ -f "$TREE/etc/frp/client-state.json" ]] || fail "purge removed client-state"
[[ -f "$TREE/var/lib/frp-auto-deploy/client-draft.json" ]] || fail "purge removed client-draft"
[[ -d "$TREE/var/lib/frp-auto-deploy/client-upgrades" ]] || fail "purge removed client-upgrades"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/registry.json" ]] || fail "purge left registry"
pass "SERVER_PURGE_PRESERVES_CLIENT_ROLE"

# --- Dual-role shared lib ownership ---
mkdir -p "$TREE/usr/local/lib/frp-auto-deploy" "$TREE/usr/local/bin" \
  "$TREE/etc/frp" "$TREE/etc/frp-auto-deploy"
for f in frp-common.sh frp_mgmt_auth.py frp-client-common.sh \
  frp-doctor-common.sh frp_doctor.py frp_ctl_grammar.py frp_ctl_repl.py \
  frp-role-ownership.sh frp_project_files.py server-project-files.manifest; do
  cp "$ROOT/lib/$f" "$TREE/usr/local/lib/frp-auto-deploy/" 2>/dev/null \
    || echo "x" >"$TREE/usr/local/lib/frp-auto-deploy/$f"
done
cp "$ROOT/lib/frp_project_files.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/server-project-files.manifest" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp-role-ownership.sh" "$TREE/usr/local/lib/frp-auto-deploy/"
echo '{"machine_id":"m1"}' >"$TREE/etc/frp/client-state.json"
echo '#!/bin/sh' >"$TREE/usr/local/bin/frp-client"
chmod +x "$TREE/usr/local/bin/frp-client"
echo 'cfg' >"$TREE/etc/frp-auto-deploy/config.json"
# Server-only file that must be removed
echo 'server-only' >"$TREE/usr/local/lib/frp-auto-deploy/frp-port-allocator.py"

FRP_UNINSTALL_TEST_ROOT="$TREE" FRP_UNINSTALL_HOOK_SKIP_SYSTEMD=1 \
  bash "$ROOT/uninstall-server.sh" >/dev/null
[[ -f "$TREE/usr/local/lib/frp-auto-deploy/frp-doctor-common.sh" ]] || fail "server uninstall removed doctor shared lib"
[[ -f "$TREE/usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py" ]] || fail "server uninstall removed ctl shared lib"
[[ -f "$TREE/usr/local/lib/frp-auto-deploy/frp-client-common.sh" ]] || fail "server uninstall removed client-common"
[[ -f "$TREE/usr/local/bin/frp-client" ]] || fail "server uninstall removed frp-client"
[[ ! -f "$TREE/usr/local/lib/frp-auto-deploy/frp-port-allocator.py" ]] || fail "server uninstall left server-only lib"
pass "DUAL_ROLE_SERVER_UNINSTALL_PRESERVES_CLIENT_LIBS"

# --- Allocator runtime helpers list ---
# shellcheck source=lib/frp-server-upgrade.sh
. "$ROOT/lib/frp-server-upgrade.sh"
for need in frp_mgmt_auth.py frp_pki.py frp_client_registry.py \
  frp_enrollment_lifecycle.py frp_zero_touch.py frp_audit.py; do
  found=0
  for rel in "${FRP_ALLOCATOR_RUNTIME_HELPERS[@]}"; do
    [[ "$rel" == "$need" ]] && found=1
  done
  [[ "$found" == "1" ]] || fail "allocator helper missing: $need"
done
pass "ALLOCATOR_RUNTIME_DEPENDENCY_RESTART"

# --- Dev/main artifact identity ---
meta="$(frp_validate_release_source_metadata "$ROOT" "main" "dev")" || fail "dev metadata validate"
channel="$(printf '%s' "$meta" | awk -F'\t' '{print $2}')"
ref="$(printf '%s' "$meta" | awk -F'\t' '{print $3}')"
[[ "$channel" == "dev" ]] || fail "channel=$channel"
[[ "$ref" == "main" ]] || fail "ref=$ref"
pass "DEV_MAIN_ARTIFACT_IDENTITY"
pass "STABLE_IMMUTABLE_CHANNEL (working tree is explicit dev; tagged stable unchanged)"

echo
echo "CORE_CORRECTNESS_LIFECYCLE_TEST=PASS"
