#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
mkdir -p "$TREE/etc/drlink/pki" "$TREE/var/lib/drlink/enrollments" "$TREE/var/lib/drlink/bootstrap"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$TREE/etc/drlink/pki" --public-host example.test >/dev/null
python3 - "$TREE" <<'PY'
import json,sys
from pathlib import Path
r=Path(sys.argv[1])
(r/'etc/drlink/config.json').write_text(json.dumps({
 'enrollments_dir':'/var/lib/drlink/enrollments',
 'bootstrap_dir':'/var/lib/drlink/bootstrap',
 'tls_ca_cert':'/etc/drlink/pki/ca.crt',
 'allocator_public_url':'https://example.test/enroll',
 'client_installer_url':'https://example.test/bootstrap-client.sh',
})+'\n')
PY
export FRP_DEPLOY_TEST_ROOT="$TREE"
python3 "$ROOT/tools/frp-enroll-bulk" --count 3 --label-prefix node >"$WORK/count.csv" 2>"$WORK/count.err"
grep -q 'redirected output contains sensitive' "$WORK/count.err"
cat >"$WORK/input.csv" <<'CSV'
label,ssh_user,note
ssh-node,aella,remote shell
inventory-only,,no service
CSV
python3 "$ROOT/tools/frp-enroll-bulk" --csv "$WORK/input.csv" >"$WORK/input.out" 2>"$WORK/input.err"
python3 - "$WORK/count.csv" "$WORK/input.out" "$TREE/var/lib/drlink/bootstrap" <<'PY'
import csv,json,re,sys
from pathlib import Path
rows=[]
for name in sys.argv[1:3]:
    with open(name,newline='') as f:
        batch=list(csv.DictReader(f))
        assert len({row['expires'] for row in batch})==len(batch)
        rows.extend(batch)
assert len(rows)==5
tickets=[]
for row in rows:
    m=re.search(r"sudo bash -s -- '(zt1\.[^']+)'", row['bootstrap_command'])
    if m:
        parts=m.group(1).split('.',1)
        padded=parts[1]+('='*((-len(parts[1]))%4))
        import base64
        payload=json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
        tickets.append(payload['t'])
    else:
        m=re.search(r"FRP_BOOTSTRAP_TICKET='([^']+)'",row['bootstrap_command'])
        assert m, row
        tickets.append(m.group(1))
assert len(set(tickets))==5
records=[json.loads(p.read_text()) for p in Path(sys.argv[3]).glob('*.json')]
assert len(records)==5
assert len({r['id'] for r in records})==5
assert len({r['enrollment_id'] for r in records})==5
for ticket,record in zip(sorted(tickets), sorted(records,key=lambda r:r['id'])):
    assert ticket not in json.dumps(record)
assert any(r.get('services')==[] for r in records)
assert any((r.get('services') or [{}])[0].get('preset')=='ssh' for r in records if r.get('services'))
PY
# Pre-validate all rows: a bad later row issues zero tickets.
BAD="$WORK/bad.csv"
cat >"$BAD" <<'CSV'
label,ssh_user,note
good-one,aella,ok
BAD LABEL!!,aella,no
CSV
BEFORE_TICKETS="$(find "$TREE/var/lib/drlink/bootstrap" -name '*.json' | wc -l)"
if python3 "$ROOT/tools/frp-enroll-bulk" --csv "$BAD" >"$WORK/bad.out" 2>"$WORK/bad.err"; then
  echo "FAIL bad row accepted" >&2
  exit 1
fi
AFTER_TICKETS="$(find "$TREE/var/lib/drlink/bootstrap" -name '*.json' | wc -l)"
[[ "$AFTER_TICKETS" -eq "$BEFORE_TICKETS" ]] || { echo "FAIL bad row issued tickets" >&2; exit 1; }
echo "PASS BULK_PREVALIDATE_ALL"
echo "PASS BULK_BAD_ROW_ZERO_ISSUED"

# Mid-batch failure rolls back only this batch.
EXISTING="$(ls "$TREE/var/lib/drlink/bootstrap"/*.json | wc -l)"
if FRP_ENROLL_BULK_HOOK_FAIL_AFTER=1 \
  python3 "$ROOT/tools/frp-enroll-bulk" --count 3 --label-prefix mid \
  >"$WORK/mid.out" 2>"$WORK/mid.err"; then
  echo "FAIL mid-batch succeeded" >&2
  exit 1
fi
AFTER_MID="$(ls "$TREE/var/lib/drlink/bootstrap"/*.json | wc -l)"
[[ "$AFTER_MID" -eq "$EXISTING" ]] || { echo "FAIL mid-batch left tickets" >&2; exit 1; }
echo "PASS BULK_MID_FAILURE_ROLLBACK"
echo "PASS BULK_EXISTING_RECORDS_PRESERVED"
echo "PASS BULK_ATOMICITY_TEST"

echo "ENROLL_BULK_TEST=PASS"
