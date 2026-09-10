#!/usr/bin/env bash
# Unified show enrollments / create tracking ID / state normalization.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
mkdir -p \
  "$TREE/etc/drlink/pki" \
  "$TREE/var/lib/drlink/enrollments" \
  "$TREE/var/lib/drlink/bootstrap"

python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$TREE/etc/drlink/pki" --public-host example.test >/dev/null
python3 - "$TREE" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
(root / 'etc/drlink/config.json').write_text(json.dumps({
  'enrollments_dir': '/var/lib/drlink/enrollments',
  'bootstrap_dir': '/var/lib/drlink/bootstrap',
  'tls_ca_cert': '/etc/drlink/pki/ca.crt',
  'allocator_public_url': 'https://example.test/enroll',
  'client_installer_url': 'https://example.test/bootstrap-client.sh',
}) + '\n')
PY

export FRP_DEPLOY_TEST_ROOT="$TREE"
ENROLL="$ROOT/tools/frp-enrollments"
CREATE="$ROOT/tools/frp-create-client"
REVOKE="$ROOT/tools/frp-enrollment-revoke"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# --- Manual enrollment visible + tracking ID ---
python3 "$CREATE" --client-name manual-a --note 'manual note' >"$WORK/manual.out"
MANUAL_ID="$(awk '/^Enrollment ID:/{print $3; exit}' "$WORK/manual.out")"
MANUAL_CODE="$(awk '/^Enrollment Code:/{getline; print; exit}' "$WORK/manual.out")"
MANUAL_SECRET="${MANUAL_CODE#*.}"
[[ -n "$MANUAL_ID" && ${#MANUAL_ID} -eq 16 ]] || fail "CREATE_ENROLLMENT_TRACKING_ID missing"
grep -q "Enrollment ID: $MANUAL_ID" "$WORK/manual.out" || fail "CREATE_ENROLLMENT_TRACKING_ID"
pass "CREATE_ENROLLMENT_TRACKING_ID"

python3 "$ENROLL" >"$WORK/list1.out"
grep -q 'ID.*TYPE.*LABEL.*CREATED.*EXPIRES.*STATE' "$WORK/list1.out" || fail "header"
grep -E "^${MANUAL_ID}[[:space:]]+manual[[:space:]]+manual-a" "$WORK/list1.out" | grep -q 'pending' \
  || fail "MANUAL_ENROLLMENT_VISIBLE_IN_SHOW / MANUAL_PENDING_STATE"
pass "MANUAL_ENROLLMENT_VISIBLE_IN_SHOW"
pass "MANUAL_PENDING_STATE"
! grep -Fq "$MANUAL_SECRET" "$WORK/list1.out" || fail "ENROLLMENT_SECRET_NOT_SHOWN"
pass "ENROLLMENT_SECRET_NOT_SHOWN"
grep -q 'revoke enrollment <ID>' "$WORK/list1.out" || fail "SHOW_ENROLLMENTS_REVOKE_GUIDANCE"
pass "SHOW_ENROLLMENTS_REVOKE_GUIDANCE"

# --- Manual completed / expired / revoked states ---
python3 - "$TREE" "$MANUAL_ID" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
eid = sys.argv[2]
path = root / 'var/lib/drlink/enrollments' / (eid + '.json')
rec = json.loads(path.read_text())
rec['used_at'] = '2026-08-30T01:00:00Z'
rec['bound_machine_id'] = 'aabbccddeeff0011'
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
python3 "$ENROLL" >"$WORK/completed.out"
grep -E "^${MANUAL_ID}[[:space:]]+manual" "$WORK/completed.out" | grep -q 'completed' \
  || fail "MANUAL_COMPLETED_STATE"
pass "MANUAL_COMPLETED_STATE"

python3 - "$TREE" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
eid = 'aaaaaaaaaaaaaaaa'
path = root / 'var/lib/drlink/enrollments' / (eid + '.json')
now = int(time.time())
rec = {
  'id': eid,
  'secret': 'deadbeef' * 8,
  'created_at': '2026-08-01T00:00:00Z',
  'expires_at': now - 3600,
  'expires_at_iso': '2026-08-01T01:00:00Z',
  'bound_machine_id': None,
  'used_at': None,
  'label': 'expired-m',
  'note': '',
}
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
python3 "$ENROLL" >"$WORK/expired.out"
grep -E '^aaaaaaaaaaaaaaaa[[:space:]]+manual' "$WORK/expired.out" | grep -q 'expired' \
  || fail "MANUAL_EXPIRED_STATE"
pass "MANUAL_EXPIRED_STATE"
! grep -Fq 'deadbeefdeadbeef' "$WORK/expired.out" || fail "secret in expired list"

python3 - "$TREE" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
eid = 'bbbbbbbbbbbbbbbb'
path = root / 'var/lib/drlink/enrollments' / (eid + '.json')
now = int(time.time())
rec = {
  'id': eid,
  'secret': 'cafebabe' * 8,
  'created_at': '2026-08-30T00:00:00Z',
  'expires_at': now + 600,
  'expires_at_iso': '2026-08-30T01:00:00Z',
  'bound_machine_id': None,
  'used_at': None,
  'revoked_at': '2026-08-30T00:05:00Z',
  'label': 'revoked-m',
  'note': '',
}
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
python3 "$ENROLL" >"$WORK/revoked-m.out"
grep -E '^bbbbbbbbbbbbbbbb[[:space:]]+manual' "$WORK/revoked-m.out" | grep -q 'revoked' \
  || fail "MANUAL_REVOKED_STATE"
pass "MANUAL_REVOKED_STATE"

# --- Zero-touch visible + no duplicate ---
python3 "$CREATE" --one-line --client-name zt-a --note 'zt note' >"$WORK/zt.out"
ZT_ID="$(awk '/^Enrollment ID:/{print $3; exit}' "$WORK/zt.out")"
ZT_TICKET="$(python3 - "$WORK/zt.out" <<'PY'
import base64, json, re, sys
t = open(sys.argv[1]).read()
m = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", t)
if m:
    parts = m.group(1).split('.', 1)
    padded = parts[1] + ('=' * (-len(parts[1]) % 4))
    payload = json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
    print(payload['t'])
else:
    m = re.search(r"FRP_BOOTSTRAP_TICKET='([^']+)'", t)
    print(m.group(1))
PY
)"
ZT_SECRET="${ZT_TICKET##*.}"
[[ -n "$ZT_ID" && ${#ZT_ID} -eq 16 ]] || fail "zero-touch tracking id"
[[ "$ZT_ID" == "${ZT_TICKET#bt1.}" || "$ZT_ID" == "${ZT_TICKET#bt1.}"* ]] || true
# ticket form bt1.id.secret
ZT_TICKET_ID="${ZT_TICKET#bt1.}"; ZT_TICKET_ID="${ZT_TICKET_ID%%.*}"
[[ "$ZT_ID" == "$ZT_TICKET_ID" ]] || fail "zero-touch Enrollment ID != ticket id"

python3 "$ENROLL" >"$WORK/zt-list.out"
grep -E "^${ZT_ID}[[:space:]]+zero-touch[[:space:]]+zt-a" "$WORK/zt-list.out" | grep -q 'pending' \
  || fail "ZERO_TOUCH_ENROLLMENT_VISIBLE_IN_SHOW / BOOTSTRAP_PENDING_STATE"
pass "ZERO_TOUCH_ENROLLMENT_VISIBLE_IN_SHOW"
pass "BOOTSTRAP_PENDING_STATE"
! grep -Fq "$ZT_SECRET" "$WORK/zt-list.out" || fail "BOOTSTRAP_SECRET_NOT_SHOWN"
pass "BOOTSTRAP_SECRET_NOT_SHOWN"

# Paired enrollment record must not appear as a second row.
PAIR_COUNT="$(grep -cE 'zero-touch|manual' "$WORK/zt-list.out" || true)"
# Count how many times ZT_ID appears as an ID column start
ID_HITS="$(grep -cE "^${ZT_ID}[[:space:]]" "$WORK/zt-list.out" || true)"
[[ "$ID_HITS" -eq 1 ]] || fail "NO_DUPLICATE_LOGICAL_ENROLLMENT id hits=$ID_HITS"
# Enrollment-side paired file exists but must not be listed under its own id.
PAIR_EID="$(python3 - "$TREE" "$ZT_ID" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
tid = sys.argv[2]
rec = json.loads((root / 'var/lib/drlink/bootstrap' / (tid + '.json')).read_text())
print(rec['enrollment_id'])
PY
)"
! grep -E "^${PAIR_EID}[[:space:]]" "$WORK/zt-list.out" || fail "NO_DUPLICATE_LOGICAL_ENROLLMENT paired enrollment listed"
pass "NO_DUPLICATE_LOGICAL_ENROLLMENT"

# --- Bootstrap bound / completed / expired / revoked ---
python3 - "$TREE" "$ZT_ID" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
tid = sys.argv[2]
path = root / 'var/lib/drlink/bootstrap' / (tid + '.json')
rec = json.loads(path.read_text())
rec['bound_machine_id'] = 'machinebound0001'
rec['completed_at'] = None
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
python3 "$ENROLL" >"$WORK/bound.out"
grep -E "^${ZT_ID}[[:space:]]+zero-touch" "$WORK/bound.out" | grep -q 'bound' \
  || fail "BOOTSTRAP_BOUND_STATE"
pass "BOOTSTRAP_BOUND_STATE"

python3 - "$TREE" "$ZT_ID" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
tid = sys.argv[2]
path = root / 'var/lib/drlink/bootstrap' / (tid + '.json')
rec = json.loads(path.read_text())
rec['completed_at'] = '2026-08-30T02:00:00Z'
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
python3 "$ENROLL" >"$WORK/zt-done.out"
grep -E "^${ZT_ID}[[:space:]]+zero-touch" "$WORK/zt-done.out" | grep -q 'completed' \
  || fail "BOOTSTRAP_COMPLETED_STATE"
pass "BOOTSTRAP_COMPLETED_STATE"

python3 - "$TREE" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
tid = 'cccccccccccccccc'
path = root / 'var/lib/drlink/bootstrap' / (tid + '.json')
now = int(time.time())
rec = {
  'schema': 1,
  'id': tid,
  'secret_hash': 'hash-not-a-secret-value-xxxxxxxx',
  'enrollment_id': 'dddddddddddddddd',
  'created_at': '2026-08-01T00:00:00Z',
  'expires_at': now - 120,
  'bound_machine_id': None,
  'completed_at': None,
  'label': 'expired-z',
  'note': '',
  'services': [],
}
path.write_text(json.dumps(rec, indent=2) + '\n')
# paired enrollment (must be omitted from listing as duplicate)
ep = root / 'var/lib/drlink/enrollments' / 'dddddddddddddddd.json'
ep.write_text(json.dumps({
  'id': 'dddddddddddddddd',
  'secret': 'shouldneverappear0000000000000000000000000000000000000000000000',
  'created_at': '2026-08-01T00:00:00Z',
  'expires_at': now - 120,
  'label': 'expired-z',
}, indent=2) + '\n')
PY
python3 "$ENROLL" >"$WORK/zt-exp.out"
grep -E '^cccccccccccccccc[[:space:]]+zero-touch' "$WORK/zt-exp.out" | grep -q 'expired' \
  || fail "BOOTSTRAP_EXPIRED_STATE"
! grep -E '^dddddddddddddddd[[:space:]]' "$WORK/zt-exp.out" || fail "paired expired duplicate"
! grep -Fq 'shouldneverappear' "$WORK/zt-exp.out" || fail "paired secret leaked"
pass "BOOTSTRAP_EXPIRED_STATE"

python3 - "$TREE" <<'PY'
import json, sys, time
from pathlib import Path
root = Path(sys.argv[1])
tid = 'eeeeeeeeeeeeeeee'
path = root / 'var/lib/drlink/bootstrap' / (tid + '.json')
now = int(time.time())
rec = {
  'schema': 1,
  'id': tid,
  'secret_hash': 'another-hash-value-not-secret',
  'enrollment_id': 'ffffffffffffffff',
  'created_at': '2026-08-30T00:00:00Z',
  'expires_at': now + 600,
  'bound_machine_id': None,
  'completed_at': None,
  'revoked_at': '2026-08-30T00:10:00Z',
  'label': 'revoked-z',
  'note': '',
  'services': [],
}
path.write_text(json.dumps(rec, indent=2) + '\n')
PY
python3 "$ENROLL" >"$WORK/zt-rev.out"
grep -E '^eeeeeeeeeeeeeeee[[:space:]]+zero-touch' "$WORK/zt-rev.out" | grep -q 'revoked' \
  || fail "BOOTSTRAP_REVOKED_STATE"
pass "BOOTSTRAP_REVOKED_STATE"

# Live revoke of a fresh pending zero-touch via show-enrollments ID
python3 "$CREATE" --one-line --client-name zt-revokable >"$WORK/zt2.out"
ZT2="$(awk '/^Enrollment ID:/{print $3; exit}' "$WORK/zt2.out")"
python3 "$REVOKE" "$ZT2" >"$WORK/revoke2.out"
python3 "$ENROLL" >"$WORK/after-revoke.out"
grep -E "^${ZT2}[[:space:]]+zero-touch" "$WORK/after-revoke.out" | grep -q 'revoked' \
  || fail "revoke via listing id"

# Live revoke of a fresh manual enrollment
python3 "$CREATE" --client-name manual-rev >"$WORK/manual2.out"
M2="$(awk '/^Enrollment ID:/{print $3; exit}' "$WORK/manual2.out")"
python3 "$REVOKE" "$M2" >"$WORK/revoke-m2.out"
python3 "$ENROLL" >"$WORK/after-mrevoke.out"
grep -E "^${M2}[[:space:]]+manual" "$WORK/after-mrevoke.out" | grep -q 'revoked' \
  || fail "manual revoke via listing id"

echo "SHOW_ENROLLMENTS_UNIFIED=PASS"
echo "ENROLLMENT_LISTING_TESTS=PASS"
