#!/usr/bin/env bash
# P3.1 only: manual group CRUD, membership, persistence, doctor, and CLI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/drlink" "$TREE/var/lib/drlink" "$TREE/var/log/drlink"
export FRP_DEPLOY_TEST_ROOT="$TREE"
export FRP_CTL_TEST_ROOT="$TREE"
export FRP_CTL_BIN_DIR="$ROOT/tools"
REG="$TREE/var/lib/drlink/registry.json"

python3 - "$TREE/etc/drlink/config.json" "$REG" <<'PY'
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

# --- F33: destructive group delete confirmation -------------------------
cat >"$WORKDIR/pty-answer.py" <<'PY'
"""Run a command on a PTY and answer its [y/N] prompt once."""
import os
import pty
import select
import sys
import time

answer = sys.argv[1].encode()
argv = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
buf = bytearray()
sent = False
deadline = time.time() + 20
while time.time() < deadline:
    ready, _w, _x = select.select([fd], [], [], 0.2)
    if not ready:
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    buf.extend(chunk)
    if not sent and b'[y/N]' in bytes(buf):
        os.write(fd, answer + b'\n')
        sent = True
os.close(fd)
_wpid, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(bytes(buf))
sys.stdout.flush()
raise SystemExit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
PY

group_exists() {
  python3 - "$REG" "$1" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
names = {(g.get('name') or '') for g in state['groups'].values()}
raise SystemExit(0 if sys.argv[2] in names else 1)
PY
}

# Non-interactive without --yes fails closed and leaves the group in place.
if "$GSET" delete seoul </dev/null >"$WORKDIR/del-noninteractive.out" \
  2>"$WORKDIR/del-noninteractive.err"; then
  echo "FAIL: non-interactive group delete without --yes succeeded" >&2
  exit 1
fi
grep -q -- '--yes' "$WORKDIR/del-noninteractive.err"
group_exists seoul

# Interactive default (empty answer) and explicit N both abort.
for answer in '' 'n'; do
  if python3 "$WORKDIR/pty-answer.py" "$answer" "$GSET" delete seoul \
    >"$WORKDIR/del-abort.out" 2>&1; then
    echo "FAIL: interactive group delete answered '$answer' deleted the group" >&2
    exit 1
  fi
  grep -q 'Delete group "seoul" from 1 clients? \[y/N\]' "$WORKDIR/del-abort.out"
  grep -qi 'services' "$WORKDIR/del-abort.out"
  grep -qi 'abort' "$WORKDIR/del-abort.out"
  group_exists seoul
done

# Interactive y deletes; services and identity stay untouched.
python3 "$WORKDIR/pty-answer.py" 'y' "$GSET" delete seoul >"$WORKDIR/del-yes.out" 2>&1
grep -q 'Delete group "seoul" from 1 clients? \[y/N\]' "$WORKDIR/del-yes.out"
grep -q 'Deleted group' "$WORKDIR/del-yes.out"
! group_exists seoul
python3 - "$REG" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
client = state['clients']['aaaaaaaa11111111aaaaaaaa11111111']
assert client['services']['ssh']['remote_port'] == 6001, client['services']
assert client['services']['ssh']['enabled'] is True
assert client['mgmt_pubkey'] == 'KEEP'
assert not any(g.get('name') == 'seoul' for g in state['groups'].values())
PY

# --yes deletes non-interactively.
"$GSET" delete pilot --yes </dev/null | grep -q 'Deleted group'
! group_exists pilot

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

# F30: dangling group references fail closed in the allocator load path and
# shared group tooling (legacy registry helpers). Production restore preflight
# does not treat ignored forensic registry.json as authority; that DB-centric
# contract is covered by tests/test-restore-preflight.py.
python3 - "$ROOT" "$REG" <<'PY'
import importlib.util, json, sys
from pathlib import Path

repo, reg = Path(sys.argv[1]), Path(sys.argv[2])
state = json.loads(reg.read_text())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


alloc = load('frp_port_allocator', repo / 'server' / 'frp-port-allocator.py')
try:
    alloc.validate_registry_invariants(state, None)
except alloc.RegistrySchemaError as exc:
    assert 'nonexistent group' in str(exc), exc
else:
    raise AssertionError('allocator accepted a dangling group reference')

creg = load('frp_client_registry', repo / 'lib' / 'frp_client_registry.py')
try:
    creg.validate_group_invariants(state)
except creg.GroupInvariantError as exc:
    assert 'grp_00000000' in str(exc), exc
else:
    raise AssertionError('registry helper accepted a dangling group reference')

print('f30-ok')
PY

# Group tooling refuses to read or mutate a registry with dangling references.
! "$GROUP_TOOL" >/dev/null 2>&1
! "$GSET" create another-group >/dev/null 2>&1
cp "$WORKDIR/good" "$REG"

"$CTL" show groups | grep -q acme-korea
"$CTL" show group acme-korea | grep -q "$GID"
"$ROOT/tools/frp-clients" | grep -q aaaaaaaa
"$CTL" create group safe-group
"$CTL" set group safe-group description 'literal $HOME `id` ; text'
"$CTL" rename group safe-group safer-group
"$CTL" set group safer-group description 'new description'
"$CTL" add client cccccccc group safer-group
"$CTL" remove client cccccccc group safer-group
# Product-owned confirmation (no public --yes).
export FRP_CTL_TEST_INPUT=$'y\n'
set +e
"$CTL" delete group safer-group >"$WORKDIR/del-cli.out" 2>&1
del_rc=$?
set -e
unset FRP_CTL_TEST_INPUT
cat "$WORKDIR/del-cli.out"
[[ "$del_rc" -eq 0 ]] || { echo "FAIL: delete group rc=$del_rc" >&2; exit 1; }
grep -qi 'Deleted group' "$WORKDIR/del-cli.out" || { echo "FAIL: delete group missing confirmation output" >&2; exit 1; }
# Action-first help topics describe the canonical create/add/remove trees
# or reject obsolete topics with a pointer to help commands.
"$CTL" help create >"$WORKDIR/help-create" 2>&1 || true
"$CTL" help add >"$WORKDIR/help-add" 2>&1 || true
"$CTL" help remove >"$WORKDIR/help-remove" 2>&1 || true
grep -qiE 'create |Usage|zero-touch|enrollment|Unknown help topic|help commands|obsolete' \
  "$WORKDIR/help-create"
grep -qiE 'add |Usage|client|service|Unknown help topic|help commands|obsolete' \
  "$WORKDIR/help-add"
grep -qiE 'remove |Usage|client|Unknown help topic|help commands|obsolete' \
  "$WORKDIR/help-remove"
"$CTL" help group >"$WORKDIR/help-group" 2>&1 || true
grep -Eqi 'Compatibility topic|Unknown help topic|create group|show group|set group' "$WORKDIR/help-group"
set +e
"$CTL" help legacy >"$WORKDIR/help-legacy" 2>"$WORKDIR/help-legacy.err"
legacy_rc=$?
set -e
cat "$WORKDIR/help-legacy" "$WORKDIR/help-legacy.err" >"$WORKDIR/help-legacy.all"
[[ "$legacy_rc" -ne 0 ]] || { echo "FAIL: help legacy must be rejected" >&2; exit 1; }
grep -Eqi "help legacy.*removed|help commands|obsolete" "$WORKDIR/help-legacy.all"

grep -q '"event":"group.created"' "$TREE/var/log/drlink/audit.jsonl"
grep -Eq '"event":"group.(renamed|updated)"' "$TREE/var/log/drlink/audit.jsonl"
grep -q '"event":"group.description_changed"' "$TREE/var/log/drlink/audit.jsonl"
grep -q '"event":"group.member_added"' "$TREE/var/log/drlink/audit.jsonl"
grep -q '"event":"group.member_removed"' "$TREE/var/log/drlink/audit.jsonl"
grep -q '"event":"group.deleted"' "$TREE/var/log/drlink/audit.jsonl"

python3 - "$ROOT/lib/frp_ctl_grammar.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('grammar', sys.argv[1])
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
groups = ['grp_11111111']
roots = g.completion_candidates('', 'server', [], {}, [], groups=groups)
assert 'group' not in roots
assert 'show' in roots and 'set' in roots and 'unset' in roots
assert 'groups' in g.completion_candidates('show ', 'server', [], {}, [], groups=groups)
assert 'groups' in g.completion_candidates('show client aaaaaaaa ', 'server', ['aaaaaaaa'], {}, [], groups=groups)
assert 'group' in g.completion_candidates(
    'set client aaaaaaaa ', 'server', ['aaaaaaaa'], {}, [], groups=groups
)
# Compatibility membership path still completes group IDs.
assert 'grp_11111111' in g.completion_candidates(
    'add client aaaaaaaa group ', 'server', ['aaaaaaaa'], {}, [], groups=groups
)
assert g.completion_candidates('group ', 'server', [], {}, [], groups=groups) == []
assert 'group' not in g.canonical_verbs('server')
assert 'set' in g.canonical_verbs('server') and 'show' in g.canonical_verbs('server')
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
