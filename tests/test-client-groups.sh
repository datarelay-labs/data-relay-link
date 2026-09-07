#!/usr/bin/env bash
# P3.1 only: manual group CRUD, membership, persistence, doctor, and CLI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/frp-auto-deploy" "$TREE/var/lib/frp-auto-deploy" "$TREE/var/log/frp-auto-deploy"
export FRP_DEPLOY_TEST_ROOT="$TREE"
export FRP_CTL_TEST_ROOT="$TREE"
export FRP_CTL_BIN_DIR="$ROOT/tools"
REG="$TREE/var/lib/frp-auto-deploy/registry.json"

python3 - "$TREE/etc/frp-auto-deploy/config.json" "$REG" <<'PY'
import json, sys
from pathlib import Path
cfg, reg = map(Path, sys.argv[1:])
cfg.write_text(json.dumps({'public_host': '203.0.113.10', 'registry_file': str(reg)}) + '\n')
reg.write_text(json.dumps({
    'schema_version': 2,
    'reserved': [],
    'clients': {
        'aaaaaaaa11111111aaaaaaaa11111111': {
            'hostname': 'gw01', 'label': 'acme-gw',
            'mgmt_status': 'enrolled', 'mgmt_pubkey': 'KEEP',
            'services': {'ssh': {'remote_port': 6001, 'enabled': True}},
        },
        'bbbbbbbb22222222bbbbbbbb22222222': {
            'hostname': 'gw02', 'services': {'ssh': {'remote_port': 6002}},
        },
        'cccccccc33333333cccccccc33333333': {'hostname': 'spare', 'services': {}},
    },
}, indent=2) + '\n')
PY

GSET="$ROOT/tools/frp-group-set"
GROUP_TOOL="$ROOT/tools/frp-groups"
CTL="$ROOT/tools/frpctl"

"$GSET" create customer-acme --description 'ACME systems'
"$GSET" create pilot
"$GSET" create seoul
GID="$(python3 - "$REG" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
print(next(gid for gid, g in s['groups'].items() if g['name'] == 'customer-acme'))
PY
)"
[[ "$GID" =~ ^grp_[0-9a-f]{8}$ ]]
! "$GSET" create customer-acme
! "$GSET" create all
! "$GSET" create 'bad name!'
"$GROUP_TOOL" | grep -q customer-acme
"$GROUP_TOOL" "${GID:0:8}" | grep -q 'ACME systems'

"$GSET" set "$GID" description 'ACME Korea systems'
"$GSET" set customer-acme name acme-korea
"$GSET" add-member aaaaaaaa "$GID"
"$GSET" add-member aaaaaaaa pilot
"$GSET" add-member aaaaaaaa seoul
"$GSET" add-member bbbbbbbb acme-korea
"$GSET" add-member aaaaaaaa acme-korea | grep -qi already
"$ROOT/tools/frp-client-info" aaaaaaaa groups | grep -q acme-korea
"$ROOT/tools/frp-clients" --group acme-korea >"$WORKDIR/filter"
grep -q aaaaaaaa "$WORKDIR/filter"
grep -q bbbbbbbb "$WORKDIR/filter"
! grep -q cccccccc "$WORKDIR/filter"

"$GSET" remove-member aaaaaaaa pilot
"$GSET" remove-member aaaaaaaa pilot | grep -qi 'not in group'
"$GSET" delete seoul
python3 - "$REG" "$GID" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
c = s['clients']['aaaaaaaa11111111aaaaaaaa11111111']
assert sys.argv[2] in c['group_ids']
assert c['hostname'] == 'gw01'
assert c['services']['ssh']['remote_port'] == 6001
assert c['mgmt_pubkey'] == 'KEEP'
assert all(gid in s['groups'] for gid in c.get('group_ids', []))
PY

python3 - "$ROOT/lib/frp_doctor.py" "$REG" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('doctor', sys.argv[1])
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)
status, message, issues = doctor.validate_registry(json.load(open(sys.argv[2])))
assert status == doctor.PASS, (status, message, issues)
PY

cp "$REG" "$WORKDIR/good"
python3 - "$REG" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
s['clients']['aaaaaaaa11111111aaaaaaaa11111111']['group_ids'].append('grp_00000000')
json.dump(s, open(sys.argv[1], 'w'))
PY
python3 - "$ROOT/lib/frp_doctor.py" "$REG" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('doctor', sys.argv[1])
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)
status, message, issues = doctor.validate_registry(json.load(open(sys.argv[2])))
assert status == doctor.FAIL
assert any('nonexistent group' in issue for issue in issues)
PY
cp "$WORKDIR/good" "$REG"

"$CTL" show groups | grep -q acme-korea
"$CTL" show group acme-korea | grep -q "$GID"
"$CTL" show clients --group acme-korea | grep -q aaaaaaaa
"$CTL" show client aaaaaaaa groups | grep -q acme-korea
"$CTL" create group safe-group --description 'literal $HOME `id` ; text'
"$CTL" rename group safe-group safer-group
"$CTL" set group safer-group description 'new description'
"$CTL" add client cccccccc group safer-group
"$CTL" remove client cccccccc group safer-group
"$CTL" delete group safer-group
"$CTL" help create >"$WORKDIR/help-create"
"$CTL" help add >"$WORKDIR/help-add"
"$CTL" help remove >"$WORKDIR/help-remove"
grep -q 'create group' "$WORKDIR/help-create"
grep -q 'add client' "$WORKDIR/help-add"
grep -q 'remove client' "$WORKDIR/help-remove"

grep -q '"event":"group.created"' "$TREE/var/log/frp-auto-deploy/audit.jsonl"
grep -Eq '"event":"group.(renamed|updated)"' "$TREE/var/log/frp-auto-deploy/audit.jsonl"
grep -q '"event":"group.description_changed"' "$TREE/var/log/frp-auto-deploy/audit.jsonl"
grep -q '"event":"group.member_added"' "$TREE/var/log/frp-auto-deploy/audit.jsonl"
grep -q '"event":"group.member_removed"' "$TREE/var/log/frp-auto-deploy/audit.jsonl"
grep -q '"event":"group.deleted"' "$TREE/var/log/frp-auto-deploy/audit.jsonl"

python3 - "$ROOT/lib/frp_ctl_grammar.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('grammar', sys.argv[1])
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
groups = ['grp_11111111']
assert 'groups' in g.completion_candidates('show ', 'server', [], {}, [], groups=groups)
assert 'groups' in g.completion_candidates('show client aaaaaaaa ', 'server', ['aaaaaaaa'], {}, [], groups=groups)
assert 'grp_11111111' in g.completion_candidates(
    'add client aaaaaaaa group ', 'server', ['aaaaaaaa'], {}, [], groups=groups
)
assert 'remove' in g.canonical_verbs('server')
PY

python3 - "$ROOT/lib/frp_client_registry.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('registry', sys.argv[1])
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
state = {'groups': {
    'grp_12345678': {'name': 'first'},
    'grp_1234abcd': {'name': 'second'},
}}
assert r.resolve_group(state, 'grp_12345678')[0] == 'grp_12345678'
assert r.resolve_group(state, 'grp_1234a')[0] == 'grp_1234abcd'
assert r.resolve_group(state, 'second')[0] == 'grp_1234abcd'
try:
    r.resolve_group(state, 'grp_1234')
except r.GroupLookupError as exc:
    assert len(exc.matches) == 2
else:
    raise AssertionError('ambiguous group prefix accepted')
PY

echo "ALL GROUP TESTS PASSED"
