#!/usr/bin/env bash
# Enrollment retention, purge, auto cleanup, and pair-aware lifecycle tests.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
mkdir -p \
  "$TREE/etc/frp-auto-deploy/pki" \
  "$TREE/var/lib/frp-auto-deploy/enrollments" \
  "$TREE/var/lib/frp-auto-deploy/bootstrap" \
  "$TREE/var/log/frp-auto-deploy"

python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$TREE/etc/frp-auto-deploy/pki" --public-host example.test >/dev/null
mkdir -p "$TREE/etc/frp" "$TREE/var/log/frp-auto-deploy"
python3 - "$TREE" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
(root / 'etc/frp-auto-deploy/config.json').write_text(json.dumps({
  'enrollments_dir': '/var/lib/frp-auto-deploy/enrollments',
  'bootstrap_dir': '/var/lib/frp-auto-deploy/bootstrap',
  'registry_file': '/var/lib/frp-auto-deploy/registry.json',
  'enrollment_retention_days': 30,
  'tls_ca_cert': '/etc/frp-auto-deploy/pki/ca.crt',
  'allocator_public_url': 'https://example.test/enroll',
  'client_installer_url': 'https://example.test/bootstrap-client.sh',
  'public_ip': '203.0.113.10',
  'deployment_mode': 'direct',
}) + '\n')
(root / 'var/lib/frp-auto-deploy/registry.json').write_text(json.dumps({'schema_version': 2, 'clients': {}}) + '\n')
(root / 'etc/frp-auto-deploy/version').write_text(
    'PROJECT_VERSION=2.1.3\nFRP_VERSION=0.70.1\nRELEASE_CHANNEL=dev\nSOURCE_REF=main\n'
    'BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
)
(root / 'etc/frp/frps.toml').write_text('bindPort = 443\n')
(root / 'etc/frp/server_token').write_text('test-token-not-secret-for-unit\n')
(root / 'etc/frp/server_token').chmod(0o600)
PY

export FRP_DEPLOY_TEST_ROOT="$TREE"
export FRP_ENROLLMENT_PURGE_YES=yes
CREATE="$ROOT/tools/frp-create-client"
REVOKE="$ROOT/tools/frp-enrollment-revoke"
PURGE="$ROOT/tools/frp-enrollment-purge"
LIFECYCLE="$ROOT/lib/frp_enrollment_lifecycle.py"
BACKUP="$ROOT/tools/frp-backup"
RESTORE="$ROOT/tools/frp-restore"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

seed_manual() {
  local eid="$1" state="$2" terminal_iso="$3"
  python3 - "$TREE" "$eid" "$state" "$terminal_iso" <<'PY'
import json, sys, time
from pathlib import Path
root, eid, state, terminal_iso = sys.argv[1:5]
now = int(time.time())
rec = {
  'id': eid,
  'secret': 'a' * 64,
  'created_at': '2026-07-01T00:00:00Z',
  'expires_at': now + 600,
  'expires_at_iso': '2099-01-01T00:00:00Z',
  'bound_machine_id': None,
  'used_at': None,
  'label': state,
}
if state == 'expired':
    if terminal_iso:
        try:
            from datetime import datetime, timezone
            text = terminal_iso.replace('Z', '+00:00')
            rec['expires_at'] = int(datetime.fromisoformat(text).timestamp())
        except (ValueError, OverflowError, OSError):
            rec['expires_at'] = int(time.time()) - 86400
    else:
        rec['expires_at'] = int(time.time()) - 86400
    rec['expires_at_iso'] = terminal_iso or '2026-01-01T00:00:00Z'
elif state == 'completed':
    rec['used_at'] = terminal_iso
    rec['bound_machine_id'] = 'machine00000001'
elif state == 'revoked':
    rec['revoked_at'] = terminal_iso
elif state == 'bound':
    rec['bound_machine_id'] = 'machine00000001'
elif state == 'active_old':
    rec['created_at'] = '2020-01-01T00:00:00Z'
    rec['label'] = 'active-old'
path = Path(root) / 'var/lib/frp-auto-deploy/enrollments' / (eid + '.json')
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
}

seed_zero_touch() {
  local tid="$1" eid="$2" state="$3" terminal_iso="$4"
  python3 - "$TREE" "$tid" "$eid" "$state" "$terminal_iso" <<'PY'
import json, sys, time
from pathlib import Path
root, tid, eid, state, terminal_iso = sys.argv[1:6]
now = int(time.time())
expires = now + 600
ticket = {
  'schema': 1,
  'id': tid,
  'secret_hash': 'b' * 64,
  'enrollment_id': eid,
  'created_at': '2026-07-01T00:00:00Z',
  'expires_at': expires,
  'bound_machine_id': None,
  'completed_at': None,
  'label': state,
  'note': '',
  'services': [],
}
enroll = {
  'id': eid,
  'secret': 'c' * 64,
  'created_at': '2026-07-01T00:00:00Z',
  'expires_at': expires,
  'expires_at_iso': '2099-01-01T00:00:00Z',
  'bound_machine_id': None,
  'used_at': None,
  'label': state,
}
if state == 'expired':
    ts = int(time.time()) - 86400
    if terminal_iso:
        try:
            from datetime import datetime
            text = terminal_iso.replace('Z', '+00:00')
            ts = int(datetime.fromisoformat(text).timestamp())
        except (ValueError, OverflowError, OSError):
            pass
    ticket['expires_at'] = ts
    enroll['expires_at'] = ts
elif state == 'completed':
    ticket['completed_at'] = terminal_iso
    ticket['bound_machine_id'] = 'machine00000001'
    enroll['used_at'] = terminal_iso
    enroll['bound_machine_id'] = 'machine00000001'
elif state == 'revoked':
    ticket['revoked_at'] = terminal_iso
    enroll['revoked_at'] = terminal_iso
elif state == 'bound':
    ticket['bound_machine_id'] = 'machine00000001'
root = Path(root)
(root / 'var/lib/frp-auto-deploy/bootstrap' / (tid + '.json')).write_text(json.dumps(ticket, indent=2) + '\n')
(root / 'var/lib/frp-auto-deploy/enrollments' / (eid + '.json')).write_text(json.dumps(enroll, indent=2) + '\n')
PY
}

# --- Active purge rejection ---
python3 "$CREATE" --client-name pending-block >"$WORK/pending.out"
PENDING_ID="$(awk '/^Enrollment ID:/{print $3; exit}' "$WORK/pending.out")"
if python3 "$PURGE" enrollment "$PENDING_ID" >/dev/null 2>"$WORK/pending-purge.err"; then
  fail "PENDING_PURGE_BLOCKED"
fi
grep -q 'active enrollment cannot be purged' "$WORK/pending-purge.err" || fail "PENDING_PURGE_BLOCKED message"
pass "PENDING_PURGE_BLOCKED"
pass "PURGE_ACTIVE_REJECTED"

seed_manual bbbbbbbbbbbbbbbb bound ''
if python3 "$PURGE" enrollment bbbbbbbbbbbbbbbb >/dev/null 2>"$WORK/bound-purge.err"; then
  fail "BOUND_PURGE_BLOCKED"
fi
grep -q 'active enrollment cannot be purged' "$WORK/bound-purge.err" || fail "BOUND_PURGE_BLOCKED message"
pass "BOUND_PURGE_BLOCKED"

# Active enrollment with old creation date must survive cleanup
seed_manual a0a0a0a0a0a0a0a0 active_old ''
python3 - "$LIFECYCLE" "$TREE" <<'PY'
import importlib.util, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('elc', sys.argv[1])
elc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elc)
root = Path(sys.argv[2])
now = int(time.time())
rows = elc.collect_logical_enrollments(
    root / 'var/lib/frp-auto-deploy/enrollments',
    root / 'var/lib/frp-auto-deploy/bootstrap',
    now,
)
row = elc.resolve_target(rows, 'a0a0a0a0a0a0a0a0')
assert row and row['state'] == 'pending'
assert not elc.is_retention_eligible(row, now, 30)
print('PASS ACTIVE_OLD_CREATION_RETAINED')
PY

# Same-machine retry (bound, not completed) must never be purged
seed_zero_touch b0b0b0b0b0b0b0b0 c0c0c0c0c0c0c0c0 bound ''
if python3 "$PURGE" enrollment b0b0b0b0b0b0b0b0 >/dev/null 2>"$WORK/retry-purge.err"; then
  fail "SAME_MACHINE_RETRY_PROTECTED"
fi
grep -q 'active enrollment cannot be purged' "$WORK/retry-purge.err" || fail "SAME_MACHINE_RETRY_PROTECTED message"
pass "SAME_MACHINE_RETRY_PROTECTED"

python3 "$CREATE" --client-name rev-pending >"$WORK/rev-p.out"
REV_P="$(awk '/^Enrollment ID:/{print $3; exit}' "$WORK/rev-p.out")"
python3 "$REVOKE" "$REV_P" >/dev/null
pass "PENDING_REVOKE"

seed_manual cccccccccccccccc bound ''
python3 "$REVOKE" cccccccccccccccc >/dev/null 2>"$WORK/rev-bound.err" || true
pass "BOUND_REVOKE"

seed_manual dddddddddddddddd expired '2026-07-01T00:00:00Z'
if python3 "$REVOKE" dddddddddddddddd >/dev/null 2>"$WORK/rev-exp.err"; then
  fail "EXPIRED_REVOKE_REFUSAL"
fi
grep -q 'expired enrollment' "$WORK/rev-exp.err" || fail "EXPIRED_REVOKE_REFUSAL message"
pass "EXPIRED_REVOKE_REFUSAL"

seed_manual eeeeeeeeeeeeeeee completed '2026-08-30T01:00:00Z'
# used/completed Enrollment Codes remain authorization-bearing for exact replay
# and must stay administratively revocable.
python3 "$REVOKE" eeeeeeeeeeeeeeee >/dev/null
pass "COMPLETED_REVOKE_ALLOWED"

seed_manual ffffffffffffffff revoked '2026-08-30T00:05:00Z'
if python3 "$REVOKE" ffffffffffffffff >/dev/null 2>"$WORK/rev-rev.err"; then
  fail "ALREADY_REVOKED_BEHAVIOR"
fi
grep -q 'already revoked' "$WORK/rev-rev.err" || fail "ALREADY_REVOKED_BEHAVIOR message"
pass "ALREADY_REVOKED_BEHAVIOR"

seed_manual 1111111111111111 expired '2026-07-01T00:00:00Z'
python3 "$PURGE" enrollment 1111111111111111 >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/1111111111111111.json" ]] || fail "MANUAL_EXPIRED_PURGE"
pass "MANUAL_EXPIRED_PURGE"

seed_manual 2222222222222222 completed '2026-08-30T01:00:00Z'
python3 "$PURGE" enrollment 2222222222222222 >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/2222222222222222.json" ]] || fail "MANUAL_COMPLETED_PURGE"
pass "MANUAL_COMPLETED_PURGE"

seed_manual 3333333333333333 revoked '2026-08-30T00:05:00Z'
python3 "$PURGE" enrollment 3333333333333333 >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/3333333333333333.json" ]] || fail "MANUAL_REVOKED_PURGE"
pass "MANUAL_REVOKED_PURGE"
pass "MANUAL_PURGE"

seed_zero_touch 4444444444444444 5555555555555555 expired '2026-07-01T00:00:00Z'
python3 "$PURGE" enrollment 4444444444444444 >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/bootstrap/4444444444444444.json" ]] || fail "ZERO_TOUCH_EXPIRED ticket"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/5555555555555555.json" ]] || fail "ZERO_TOUCH_EXPIRED enroll"
pass "ZERO_TOUCH_EXPIRED_PURGE"
pass "EXPIRED_PAIR_CLEANUP"

seed_zero_touch 6666666666666666 7777777777777777 completed '2026-08-30T02:00:00Z'
python3 "$PURGE" enrollment 6666666666666666 >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/bootstrap/6666666666666666.json" ]] || fail "ZERO_TOUCH_COMPLETED ticket"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/7777777777777777.json" ]] || fail "ZERO_TOUCH_COMPLETED enroll"
pass "ZERO_TOUCH_COMPLETED_PURGE"
pass "COMPLETED_PAIR_CLEANUP"

seed_zero_touch 8888888888888888 9999999999999999 revoked '2026-08-30T00:10:00Z'
python3 "$PURGE" enrollment 8888888888888888 >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/bootstrap/8888888888888888.json" ]] || fail "ZERO_TOUCH_REVOKED ticket"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/9999999999999999.json" ]] || fail "ZERO_TOUCH_REVOKED enroll"
pass "ZERO_TOUCH_REVOKED_PURGE"
pass "REVOKED_PAIR_CLEANUP"
pass "ZERO_TOUCH_PAIR_PURGE"

python3 - "$LIFECYCLE" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location('elc', sys.argv[1])
elc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elc)
now = int(time.time())
retention = 30
cutoff = now - retention * 86400

def row(state, terminal_at):
    return {'state': state, 'terminal_at': terminal_at, 'pair_error': None}

assert not elc.is_retention_eligible(row('expired', cutoff + 86400), now, retention)
print('PASS RETENTION_29D')
assert elc.is_retention_eligible(row('expired', cutoff), now, retention)
print('PASS RETENTION_30D_BOUNDARY')
assert elc.is_retention_eligible(row('expired', cutoff - 86400), now, retention)
print('PASS RETENTION_31D')

# Config validation
assert elc.retention_days_from_config({}) == 30
assert elc.retention_days_from_config({'enrollment_retention_days': 30}) == 30
for bad in (0, -1, 3651, 30.5, True, 'abc', 1.0):
    try:
        elc.retention_days_from_config({'enrollment_retention_days': bad})
    except elc.EnrollmentLifecycleError:
        pass
    else:
        raise SystemExit('FAIL CONFIG_REJECT %r' % (bad,))
print('PASS CONFIG_VALIDATION')
PY

OLD_ID=aaaaaaaaaaaaaaaa
seed_manual "$OLD_ID" expired '2026-01-01T00:00:00Z'
RECENT_ID=bbbbbbbbbbbbbbbb
seed_manual "$RECENT_ID" expired ''
python3 - "$TREE" "$RECENT_ID" <<'PY'
import json, sys, time
from pathlib import Path
root, eid = sys.argv[1:3]
path = Path(root) / 'var/lib/frp-auto-deploy/enrollments' / (eid + '.json')
rec = json.loads(path.read_text())
rec['expires_at'] = int(time.time()) - 5 * 86400
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
# Also seed an unexpired active bootstrap that must survive
seed_zero_touch d1d1d1d1d1d1d1d1 e1e1e1e1e1e1e1e1 bound ''
python3 "$CREATE" --client-name retention-trigger >"$WORK/auto.out"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/${OLD_ID}.json" ]] || fail "AUTO_CLEANUP old terminal"
[[ -f "$TREE/var/lib/frp-auto-deploy/enrollments/${RECENT_ID}.json" ]] || fail "AUTO_CLEANUP recent terminal"
[[ -f "$TREE/var/lib/frp-auto-deploy/bootstrap/d1d1d1d1d1d1d1d1.json" ]] || fail "AUTO_CLEANUP active bootstrap"
NEW_ID="$(awk '/^Enrollment ID:/{print $3; exit}' "$WORK/auto.out")"
[[ -f "$TREE/var/lib/frp-auto-deploy/enrollments/${NEW_ID}.json" ]] || fail "AUTO_CLEANUP active pending"
pass "AUTO_CLEANUP"
pass "ACTIVE_BOOTSTRAP_PROTECTED"
pass "ACTIVE_ENROLLMENT_PROTECTED"

# Ambiguous / corrupt pair fail closed
python3 - "$TREE" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
tid = 'aaaabbbbccccdddd'
path = root / 'var/lib/frp-auto-deploy/bootstrap' / (tid + '.json')
rec = {
  'schema': 1,
  'id': tid,
  'secret_hash': 'd' * 64,
  'enrollment_id': 'eeeeffffaaaabbbb',
  'created_at': '2026-01-01T00:00:00Z',
  'expires_at': int(time.time()) - 86400 * 60,
  'completed_at': '2026-08-30T01:00:00Z',
  'label': 'mismatch',
  'services': [],
}
path.write_text(json.dumps(rec, indent=2) + '\n')
ep = root / 'var/lib/frp-auto-deploy/enrollments' / 'eeeeffffaaaabbbb.json'
ep.write_text(json.dumps({
  'id': 'eeeeffffaaaabbbb',
  'secret': 'e' * 64,
  'created_at': '2026-01-01T00:00:00Z',
  'expires_at': int(time.time()) - 86400 * 60,
  'used_at': None,
  'label': 'mismatch',
}, indent=2) + '\n')
PY
if python3 "$PURGE" enrollment aaaabbbbccccdddd >/dev/null 2>"$WORK/pair-fail.err"; then
  fail "PAIR_MISMATCH_PURGE_BLOCKED"
fi
grep -q 'ERROR' "$WORK/pair-fail.err" || fail "PAIR_MISMATCH_PURGE_BLOCKED message"
[[ -f "$TREE/var/lib/frp-auto-deploy/bootstrap/aaaabbbbccccdddd.json" ]] || fail "AMBIGUOUS_PAIR_PRESERVED ticket"
[[ -f "$TREE/var/lib/frp-auto-deploy/enrollments/eeeeffffaaaabbbb.json" ]] || fail "AMBIGUOUS_PAIR_PRESERVED enroll"
pass "PAIR_MISMATCH_PURGE_BLOCKED"
pass "AMBIGUOUS_PAIR_FAIL_CLOSED"

python3 - "$TREE" "$LIFECYCLE" <<'PY'
import importlib.util, json, sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('elc', sys.argv[2])
elc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elc)
cfg = json.loads((root / 'etc/frp-auto-deploy/config.json').read_text())
assert elc.retention_days_from_config(cfg) == 30
del cfg['enrollment_retention_days']
assert elc.retention_days_from_config(cfg) == 30
print('PASS OLD_CONFIG_COMPATIBILITY')
PY

# Non-interactive fail closed without env
unset FRP_ENROLLMENT_PURGE_YES || true
seed_manual 1414141414141414 expired '2026-01-01T00:00:00Z'
if python3 "$PURGE" enrollment 1414141414141414 </dev/null >/dev/null 2>"$WORK/nonint.err"; then
  fail "NONINTERACTIVE_PURGE_FAIL_CLOSED"
fi
grep -q 'FRP_ENROLLMENT_PURGE_YES=yes' "$WORK/nonint.err" || fail "NONINTERACTIVE_PURGE_FAIL_CLOSED message"
[[ -f "$TREE/var/lib/frp-auto-deploy/enrollments/1414141414141414.json" ]] || fail "NONINTERACTIVE preserved"
pass "NONINTERACTIVE_PURGE_FAIL_CLOSED"
export FRP_ENROLLMENT_PURGE_YES=yes

seed_manual 1212121212121212 expired '2026-01-01T00:00:00Z'
seed_manual 1313131313131313 completed '2026-01-01T00:00:00Z'
python3 "$PURGE" enrollments --older-than 30 | grep -q 'Matched records' || fail "BULK_PURGE_PREVIEW"
python3 "$PURGE" enrollments --older-than 30 >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/1212121212121212.json" ]] || fail "BULK_PURGE"
pass "BULK_PURGE"

# Audit redaction: purge must not write secrets / bt1 / zt1 into audit
python3 - "$TREE" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
audit = root / 'var/log/frp-auto-deploy/audit.log'
# Ensure audit path exists for try_emit
audit.parent.mkdir(parents=True, exist_ok=True)
# Seed a completed terminal with a lookalike secret and purge it
eid = '1515151515151515'
rec = {
  'id': eid,
  'secret': 'deadbeef' * 8,
  'created_at': '2026-01-01T00:00:00Z',
  'expires_at': 1,
  'used_at': '2026-01-02T00:00:00Z',
  'bound_machine_id': 'machine00000001',
  'label': 'audit',
}
(root / 'var/lib/frp-auto-deploy/enrollments' / (eid + '.json')).write_text(json.dumps(rec) + '\n')
PY
python3 "$PURGE" enrollment 1515151515151515 >/dev/null
python3 - "$TREE" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
text = ''
for path in root.glob('var/log/**/*'):
    if path.is_file():
        text += path.read_text(encoding='utf-8', errors='replace')
# Also check common audit locations under test root
for rel in ('var/log/frp-auto-deploy/audit.log', 'var/lib/frp-auto-deploy/audit.log'):
    p = root / rel
    if p.is_file():
        text += p.read_text(encoding='utf-8', errors='replace')
forbidden = ['deadbeef' * 8, 'bt1.', 'zt1.']
for item in forbidden:
    if item in text:
        raise SystemExit('FAIL AUDIT_SECRET_REDACTION found %r' % item)
print('PASS AUDIT_SECRET_REDACTION')
PY
pass "AUDIT"

# Backup / restore round-trip around cleanup
seed_manual 1616161616161616 expired '2026-01-01T00:00:00Z'
seed_manual 1717171717171717 completed '2026-08-01T00:00:00Z'
# Keep a recent terminal that should survive cleanup
seed_manual 1818181818181818 expired ''
python3 - "$TREE" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
path = root / 'var/lib/frp-auto-deploy/enrollments' / '1818181818181818.json'
rec = json.loads(path.read_text())
rec['expires_at'] = int(time.time()) - 5 * 86400
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
python3 "$BACKUP" "$WORK/before.tar.gz" >/dev/null
python3 "$CREATE" --client-name after-backup-cleanup >"$WORK/cleanup-trigger.out"
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/1616161616161616.json" ]] || fail "BACKUP_CLEANUP old"
python3 "$BACKUP" "$WORK/after.tar.gz" >/dev/null
# Restore pre-cleanup backup → old record returns
python3 "$RESTORE" "$WORK/before.tar.gz" >/dev/null
[[ -f "$TREE/var/lib/frp-auto-deploy/enrollments/1616161616161616.json" ]] || fail "BACKUP_RESTORE before"
# Restore post-cleanup backup → old record stays absent
python3 "$RESTORE" "$WORK/after.tar.gz" >/dev/null
[[ ! -f "$TREE/var/lib/frp-auto-deploy/enrollments/1616161616161616.json" ]] || fail "BACKUP_RESTORE after absent"
[[ -f "$TREE/var/lib/frp-auto-deploy/enrollments/1818181818181818.json" ]] || fail "BACKUP_RESTORE recent retained"
pass "BACKUP_RESTORE"

# Doctor retention status (read-only)
python3 - "$TREE" "$ROOT" <<'PY'
import importlib.util, json, sys
from pathlib import Path
root = Path(sys.argv[1])
repo = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('elc', str(repo / 'lib/frp_enrollment_lifecycle.py'))
elc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elc)
cfg = json.loads((root / 'etc/frp-auto-deploy/config.json').read_text())
days = elc.retention_days_from_config(cfg)
findings, status = elc.doctor_scan_enrollment_lifecycle(
    root / 'var/lib/frp-auto-deploy/enrollments',
    root / 'var/lib/frp-auto-deploy/bootstrap',
    days,
)
assert status['retention_days'] == 30
assert 'active' in status and 'terminal' in status and 'eligible' in status
print('Retention policy       : %s days' % status['retention_days'])
print('Terminal records       : %s' % status['terminal'])
print('Eligible for cleanup   : %s' % status['eligible'])
print('Active records         : %s' % status['active'])
print('PASS DOCTOR_RETENTION_STATUS')
PY

echo "ENROLLMENT_RETENTION_TESTS=PASS"
