#!/usr/bin/env bash
# Generic registry schema management command tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/drlink" "$TREE/var/lib/drlink"

python3 - "$TREE/etc/drlink/config.json" "$TREE/var/lib/drlink/registry.json" <<'PY'
import json,sys
from pathlib import Path
cfg_path, reg_path = Path(sys.argv[1]), Path(sys.argv[2])
cfg_path.write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "registry_file": "/var/lib/drlink/registry.json",
  "access_control_file": "/var/lib/drlink/access-control.json",
}, indent=2)+"\n")
acl_path = reg_path.parent / "access-control.json"
acl_path.write_text(json.dumps({
  "schema_version": 1,
  "access_lists": {},
  "service_access": {},
}, indent=2)+"\n")
reg_path.write_text(json.dumps({
  "schema_version": 2,
  "reserved": [6000],
  "clients": {
    "aabbccdd": {
      "hostname": "dev-dp-mirror",
      "created_at": "2026-08-26T00:00:00Z",
      "last_enrolled_at": "2026-08-26T01:00:00Z",
      "services": {
        "ssh": {
          "name": "SSH",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 22,
          "remote_port": 6002,
          "preset": "ssh",
          "ssh_user": "aella",
          "enabled": True,
        },
        "grafana": {
          "name": "Grafana",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 3000,
          "remote_port": 6003,
          "preset": "custom",
          "enabled": True,
        },
        "api": {
          "name": "Internal API",
          "protocol": "tcp",
          "local_ip": "10.10.20.30",
          "local_port": 8080,
          "remote_port": 6004,
          "preset": "custom",
          "enabled": False,
        },
      },
    },
    "eeff0011": {
      "hostname": "client-b",
      "created_at": "2026-08-26T00:00:00Z",
      "last_enrolled_at": "2026-08-26T02:00:00Z",
      "services": {
        "http": {
          "name": "HTTP",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 80,
          "remote_port": 6005,
          "preset": "http",
          "enabled": True,
        },
      },
    },
  },
}, indent=2, sort_keys=True)+"\n")
PY
chmod 600 "$TREE/var/lib/drlink/registry.json"

export FRP_DEPLOY_TEST_ROOT="$TREE"

OUT="$WORKDIR/clients.out"
python3 "$ROOT/tools/frp-clients" >"$OUT"
grep -q 'dev-dp-mirror' "$OUT" || fail "clients hostname"
grep -q 'client-b' "$OUT" || fail "clients second host"
# Concise inventory: summary table only (no per-client service dump).
! grep -qE '^\s+ssh:6002' "$OUT" || fail "clients list must stay concise"
! grep -qE '^\s+grafana:6003' "$OUT" || fail "clients list must stay concise"
grep -q 'ACCESS' "$OUT" || fail "clients ACCESS column"
grep -q 'PUBLIC /' "$OUT" || fail "clients ACCESS summary"
grep -qE 'ONLINE|OFFLINE|PARTIAL|MGMT-ONLY|UNKNOWN' "$OUT" || fail "clients STATE label"
grep -q 'client show ' "$OUT" || fail "clients canonical example"
if grep -qE 'ssh_port|https_port' "$OUT"; then
  fail "clients leaked legacy fields"
fi
pass "frp-clients generic"
pass "CLIENT_LIST_CONCISE"

SVC="$WORKDIR/services.out"
python3 "$ROOT/tools/frp-services" >"$SVC"
grep -q 'ssh' "$SVC" || fail "global services ssh"
grep -q 'grafana' "$SVC" || fail "global services grafana"
grep -q 'api' "$SVC" || fail "global services api"
grep -q 'RESERVED' "$SVC" || fail "global services reserved"
pass "GLOBAL_SERVICE_LIST"

INFO="$WORKDIR/info.out"
python3 "$ROOT/tools/frp-client-info" dev-dp-mirror >"$INFO"
grep -q 'Hostname' "$INFO" || fail "info hostname field"
grep -q 'dev-dp-mirror' "$INFO" || fail "info hostname"
grep -q 'Service count' "$INFO" || fail "info service count"
grep -q '2' "$INFO" || fail "info enabled count"
if grep -q '127.0.0.1:22' "$INFO"; then
  fail "overview dumped service detail"
fi
python3 "$ROOT/tools/frp-client-info" dev-dp-mirror services >"$WORKDIR/info-svc.out"
grep -q '127.0.0.1:22' "$WORKDIR/info-svc.out" || fail "info ssh target"
grep -q '203.0.113.10:6002' "$WORKDIR/info-svc.out" || fail "info ssh public"
grep -q 'ssh -p 6002 aella@203.0.113.10' "$WORKDIR/info-svc.out" || fail "info ssh connect"
grep -q '127.0.0.1:3000' "$WORKDIR/info-svc.out" || fail "info grafana target"
grep -qi 'Exposure' "$WORKDIR/info-svc.out" || fail "info PUBLIC exposure banner"
grep -q '6004' "$WORKDIR/info-svc.out" || fail "info should show disabled/reserved service"
grep -q 'DISABLED' "$WORKDIR/info-svc.out" || fail "info disabled STATE"
grep -q 'RESERVED' "$WORKDIR/info-svc.out" || fail "info RESERVED port state"
pass "frp-client-info generic"
pass "CLIENT_SHOW_DISABLED_RESERVED"

cp "$TREE/var/lib/drlink/registry.json" "$WORKDIR/registry.before"
printf 'nope\n' | python3 "$ROOT/tools/frp-release-client" client-b >"$WORKDIR/cancel.out" 2>"$WORKDIR/cancel.err" && fail "cancel should fail"
python3 - "$TREE/var/lib/drlink/registry.json" "$WORKDIR/registry.before" <<'PY'
import sys
from pathlib import Path
assert Path(sys.argv[1]).read_bytes() == Path(sys.argv[2]).read_bytes()
PY
printf 'RELEASE\n' | python3 "$ROOT/tools/frp-release-client" client-b >"$WORKDIR/release.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "release did not drop client-b"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
assert 'eeff0011' not in state['clients']
assert 'aabbccdd' in state['clients']
assert state['clients']['aabbccdd']['services']['ssh']['remote_port']==6002
assert state['clients']['aabbccdd']['services']['api']['remote_port']==6004
PY
grep -q 'http: 6005' "$WORKDIR/release.out" || fail "release listed service port"
pass "frp-release-client generic"

printf 'nope\n' | python3 "$ROOT/tools/frp-release-service" dev-dp-mirror grafana >"$WORKDIR/svc-cancel.out" 2>"$WORKDIR/svc-cancel.err" && fail "service release cancel should fail"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "cancel mutated grafana"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
assert 'grafana' in state['clients']['aabbccdd']['services']
PY
printf 'RELEASE\n' | python3 "$ROOT/tools/frp-release-service" dev-dp-mirror grafana >"$WORKDIR/svc-release.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "service release"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
svc=state['clients']['aabbccdd']['services']
assert 'grafana' not in svc
assert svc['ssh']['remote_port']==6002
assert svc['api']['remote_port']==6004
PY
grep -q 'service grafana' "$WORKDIR/svc-release.out" || fail "service release output"
pass "frp-release-service generic"

# Last-service release must keep the Client record (management-only zero-service).
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
state=json.loads(p.read_text())
state['clients']['lastsvc001']={
  'hostname':'last-svc-host',
  'label':'last-svc-label',
  'note':'keep-me',
  'tags':{'site':'lab'},
  'mgmt_status':'enrolled',
  'mgmt_pubkey':'KEEP',
  'services':{
    'ssh':{'name':'SSH','protocol':'tcp','local_ip':'127.0.0.1','local_port':22,'remote_port':6020,'preset':'ssh','ssh_user':'aella','enabled':True},
  },
}
p.write_text(json.dumps(state, indent=2, sort_keys=True)+'\n')
PY
printf 'RELEASE\n' | python3 "$ROOT/tools/frp-release-service" lastsvc001 ssh >"$WORKDIR/last-svc.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "last service release deleted client"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
client=state['clients'].get('lastsvc001')
assert client is not None, 'client record removed'
assert client.get('services') == {}
assert client.get('label') == 'last-svc-label'
assert client.get('note') == 'keep-me'
assert client.get('tags') == {'site':'lab'}
assert client.get('mgmt_status') == 'enrolled'
assert client.get('mgmt_pubkey') == 'KEEP'
PY
pass "frp-release-service keeps client after last service"
# Cleanup management-only fixture before later status assertions.
printf 'RELEASE\n' | python3 "$ROOT/tools/frp-release-client" lastsvc001 --force >/dev/null

printf 'REVOKE\n' | python3 "$ROOT/tools/frp-revoke-client" dev-dp-mirror >"$WORKDIR/revoke.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "revoke"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
client=state['clients']['aabbccdd']
assert client.get('mgmt_status')=='revoked'
assert client['services']['ssh']['remote_port']==6002
assert client['services']['api']['remote_port']==6004
assert 'grafana' not in client['services']
PY
grep -q 'Revoking management identity' "$WORKDIR/revoke.out" || fail "revoke header"
grep -q 'ssh: 6002' "$WORKDIR/revoke.out" || fail "revoke listed reservation"
if grep -qi 'private key\|mgmt_mac_key\|BEGIN PUBLIC' "$WORKDIR/revoke.out"; then
  fail "revoke leaked identity material"
fi
pass "frp-revoke-client keeps reservations"

printf 'RELEASE\n' | python3 "$ROOT/tools/frp-release-client" dev-dp-mirror --force >"$WORKDIR/revoke-release.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "release after revoke"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
assert 'aabbccdd' not in state['clients']
PY
pass "admin release still works after revoke"

# Restore a client so status still has one remaining host (client-b was already released).
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
state=json.loads(p.read_text())
state['clients']['aabbccdd']={
  'hostname':'dev-dp-mirror',
  'services':{
    'ssh':{'name':'SSH','protocol':'tcp','local_ip':'127.0.0.1','local_port':22,'remote_port':6002,'preset':'ssh','ssh_user':'aella','enabled':True},
    'api':{'name':'API','protocol':'tcp','local_ip':'127.0.0.1','local_port':8080,'remote_port':6004,'preset':'custom','enabled':False},
  },
}
state['clients']['legacy00aa']={
  'hostname':'legacy-ssh',
  'services':{
    'ssh':{'name':'SSH','protocol':'tcp','local_ip':'127.0.0.1','local_port':22,'remote_port':6010,'preset':'ssh','enabled':True},
  },
}
p.write_text(json.dumps(state, indent=2, sort_keys=True)+'\n')
PY

python3 "$ROOT/tools/frp-clients" >"$WORKDIR/legacy-clients.out"
grep -q 'legacy / unspecified' "$WORKDIR/legacy-clients.out" || fail "legacy SSH user display"
python3 "$ROOT/tools/frp-client-info" legacy-ssh services >"$WORKDIR/legacy-info.out"
grep -q 'legacy / unspecified' "$WORKDIR/legacy-info.out" || fail "legacy SSH info display"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "list mutated legacy record"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
assert 'legacy00aa' in state['clients']
assert 'aabbccdd' in state['clients']
assert state['clients']['aabbccdd']['services']['ssh']['remote_port']==6002
assert state['clients']['legacy00aa']['services']['ssh']['remote_port']==6010
assert 'ssh_user' not in state['clients']['legacy00aa']['services']['ssh']
PY
cp "$TREE/var/lib/drlink/registry.json" "$WORKDIR/legacy.before"
printf 'nope\n' | python3 "$ROOT/tools/frp-release-client" legacy-ssh \
  >"$WORKDIR/legacy-cancel.out" 2>"$WORKDIR/legacy-cancel.err" && fail "legacy cancel should fail"
cmp -s "$TREE/var/lib/drlink/registry.json" "$WORKDIR/legacy.before" ||
  fail "cancelled legacy release mutated registry"
pass "legacy SSH readable without auto-release"

printf 'RELEASE\n' | python3 "$ROOT/tools/frp-release-service" legacy-ssh ssh \
  >"$WORKDIR/legacy-svc-release.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "explicit legacy service release"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
# Last-service release keeps the Client record; only the service/port is released.
assert 'legacy00aa' in state['clients']
assert state['clients']['legacy00aa'].get('services') == {}
assert state['clients']['aabbccdd']['services']['ssh']['remote_port']==6002
assert all(
    svc.get('remote_port') != 6010
    for client in state['clients'].values()
    for svc in (client.get('services') or {}).values()
    if isinstance(svc, dict)
)
PY
pass "legacy explicit service release reclaims port"

python3 - "$TREE/var/lib/drlink/registry.json" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
state=json.loads(p.read_text())
state['clients']['legacy00aa']={
  'hostname':'legacy-ssh',
  'services':{
    'ssh':{'name':'SSH','protocol':'tcp','local_ip':'127.0.0.1','local_port':22,'remote_port':6010,'preset':'ssh','enabled':True},
  },
}
p.write_text(json.dumps(state, indent=2, sort_keys=True)+'\n')
PY
printf 'RELEASE\n' | python3 "$ROOT/tools/frp-release-client" legacy-ssh --force \
  >"$WORKDIR/legacy-force-release.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "forced legacy client release"
import json,sys
from pathlib import Path
state=json.loads(Path(sys.argv[1]).read_text())
assert 'legacy00aa' not in state['clients']
assert 'aabbccdd' in state['clients']
assert state['clients']['aabbccdd']['services']['ssh']['remote_port']==6002
assert all(
    svc.get('remote_port') != 6010
    for client in state['clients'].values()
    for svc in (client.get('services') or {}).values()
    if isinstance(svc, dict)
)
PY
pass "legacy force release reclaims port"

# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
MARKER="$WORKDIR/harness.marker"
printf '%s' "$FRP_TEST_HARNESS_MAGIC" >"$MARKER"
STATUS_OUT="$WORKDIR/status.out"
if ! env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_UPDATE_ROOT="$TREE" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  "$ROOT/tools/frp-server-status" >"$STATUS_OUT"; then
  fail "status exited non-zero"
fi
grep -q 'Clients         : 1' "$STATUS_OUT" || fail "status client count after release"
# reserved 6000 + ssh 6002 + api 6004 = 3 (grafana released)
grep -q 'Reserved ports  : 3' "$STATUS_OUT" || fail "status reserved ports"
pass "frp-server-status generic"

echo
echo "MANAGEMENT_COMMAND_TEST=PASS"
