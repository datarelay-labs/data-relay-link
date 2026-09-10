#!/usr/bin/env bash
# Server-managed generic client tags and AND filtering.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/drlink" "$TREE/var/lib/drlink"
python3 - "$TREE/etc/drlink/config.json" "$TREE/var/lib/drlink/registry.json" <<'PY'
import json
import sys
from pathlib import Path

cfg_path, reg_path = Path(sys.argv[1]), Path(sys.argv[2])
cfg_path.write_text(json.dumps({
    'public_host': '203.0.113.10',
    'registry_file': str(reg_path),
}, indent=2) + '\n')
reg_path.write_text(json.dumps({
    'schema_version': 2,
    'clients': {
        'aaaaaaaa11111111': {
            'hostname': 'seoul-dp',
            'mgmt_status': 'enrolled',
            'mgmt_pubkey': 'KEEP',
            'services': {
                'ssh': {'remote_port': 6001, 'preset': 'ssh', 'enabled': True},
            },
        },
        'bbbbbbbb22222222': {
            'hostname': 'busan-dp',
            'tags': {'customer': 'lotte', 'site': 'busan'},
            'services': {
                'ssh': {'remote_port': 6002, 'preset': 'ssh', 'enabled': True},
            },
        },
        'cccccccc33333333': {
            'hostname': 'seoul-web',
            'tags': {'customer': 'other', 'site': 'seoul'},
            'services': {},
        },
    },
}, indent=2) + '\n')
PY
chmod 600 "$TREE/var/lib/drlink/registry.json"
export FRP_DEPLOY_TEST_ROOT="$TREE"

python3 "$ROOT/tools/frp-client-set" aaaaaaaa \
  --tag customer=lotte --tag site=seoul --tag role=dp --tag environment=production \
  >"$WORKDIR/set.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "tag update mutated protected fields"
import json
import sys
from pathlib import Path

client = json.loads(Path(sys.argv[1]).read_text())['clients']['aaaaaaaa11111111']
assert client['tags'] == {
    'customer': 'lotte',
    'site': 'seoul',
    'role': 'dp',
    'environment': 'production',
}
assert client['hostname'] == 'seoul-dp'
assert client['services']['ssh']['remote_port'] == 6001
assert client['mgmt_pubkey'] == 'KEEP'
PY
pass "SET_GENERIC_TAGS"

python3 "$ROOT/tools/frp-clients" --tag customer=lotte >"$WORKDIR/customer.out"
grep -q 'seoul-dp' "$WORKDIR/customer.out" || fail "customer filter omitted seoul"
grep -q 'busan-dp' "$WORKDIR/customer.out" || fail "customer filter omitted busan"
grep -q 'seoul-web' "$WORKDIR/customer.out" && fail "customer filter included wrong customer"

python3 "$ROOT/tools/frp-clients" --tag customer=lotte --tag site=seoul >"$WORKDIR/and.out"
grep -q 'seoul-dp' "$WORKDIR/and.out" || fail "AND filter omitted match"
grep -q 'busan-dp' "$WORKDIR/and.out" && fail "AND filter included wrong site"
grep -q 'seoul-web' "$WORKDIR/and.out" && fail "AND filter included wrong customer"
python3 "$ROOT/tools/frp-clients" --help >"$WORKDIR/help.out"
grep -q 'multiple --tag filters use AND' "$WORKDIR/help.out" || fail "AND semantics missing from help"
pass "TAG_FILTER_AND_SEMANTICS"

python3 "$ROOT/tools/frp-client-set" aaaaaaaa --remove-tag site >"$WORKDIR/remove.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "tag removal failed"
import json
import sys
from pathlib import Path

client = json.loads(Path(sys.argv[1]).read_text())['clients']['aaaaaaaa11111111']
assert 'site' not in client['tags']
assert client['tags']['customer'] == 'lotte'
assert client['services']['ssh']['remote_port'] == 6001
PY
pass "REMOVE_TAG"

for bad in 'missing-equals' 'bad key=value' 'key=bad,value'; do
  if python3 "$ROOT/tools/frp-client-set" aaaaaaaa --tag "$bad" >"$WORKDIR/bad.out" 2>"$WORKDIR/bad.err"; then
    fail "invalid tag accepted: $bad"
  fi
done
if python3 "$ROOT/tools/frp-clients" --tag $'key=bad\nvalue' >"$WORKDIR/bad-list.out" 2>"$WORKDIR/bad-list.err"; then
  fail "newline tag filter accepted"
fi
pass "TAG_INPUT_VALIDATION"

echo
echo "CLIENT_TAGS_TEST=PASS"
