#!/usr/bin/env bash
# P2.18 client label/note management, lookup, and list UX.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/drlink" "$TREE/var/lib/drlink"
python3 - "$TREE/etc/drlink/config.json" "$TREE/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
cfg_path, reg_path = Path(sys.argv[1]), Path(sys.argv[2])
cfg_path.write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "public_host": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "registry_file": str(reg_path),
}, indent=2)+"\n")
reg_path.write_text(json.dumps({
  "schema_version": 2,
  "reserved": [],
  "clients": {
    "aabbccdd00112233445566778899aa": {
      "hostname": "ubuntu",
      "created_at": "2026-08-26T00:00:00Z",
      "last_enrolled_at": "2026-08-26T01:00:00Z",
      "mgmt_status": "enrolled",
      "mgmt_pubkey": "KEEP",
      "mgmt_mac_key": "KEEP-MAC",
      "mgmt_fingerprint": "abcd",
      "tags": {
        "customer": "lotte",
        "site": "seoul"
      },
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
        }
      },
    },
    "ddeeff00112233445566778899bb": {
      "hostname": "ubuntu",
      "label": "busan-backup",
      "note": "Busan backup",
      "mgmt_status": "enrolled",
      "services": {
        "ssh": {
          "name": "SSH",
          "protocol": "tcp",
          "local_ip": "127.0.0.1",
          "local_port": 22,
          "remote_port": 6003,
          "preset": "ssh",
          "ssh_user": "backup",
          "enabled": True,
        }
      },
    },
  },
}, indent=2)+"\n")
PY
chmod 600 "$TREE/var/lib/drlink/registry.json"
export FRP_DEPLOY_TEST_ROOT="$TREE"

python3 "$ROOT/tools/frp-clients" >"$WORKDIR/list.out"
grep -q 'Registered clients' "$WORKDIR/list.out" || fail "list header"
grep -qE '^#[[:space:]]+CLIENT ID[[:space:]]+LABEL' "$WORKDIR/list.out" || fail "list CLIENT ID column"
grep -q 'CLIENT ID' "$WORKDIR/list.out" || fail "list client id column"
grep -q 'aabbccdd' "$WORKDIR/list.out" || fail "list short id unlabeled"
grep -q 'busan-backup' "$WORKDIR/list.out" || fail "list labeled client"
grep -q 'ubuntu' "$WORKDIR/list.out" || fail "list hostname"
grep -q 'Use CLIENT ID in client commands.' "$WORKDIR/list.out" || fail "list CLIENT ID help"
grep -q 'client show aabbccdd' "$WORKDIR/list.out" || grep -q 'client show ddeeff00' "$WORKDIR/list.out" \
  || fail "list CLIENT ID example"
pass "CLIENT_LIST_UX"

python3 "$ROOT/tools/frp-client-info" busan-backup >"$WORKDIR/by-label.out"
grep -q 'busan-backup' "$WORKDIR/by-label.out" || fail "info by label"
grep -q 'ddeeff00112233445566778899bb' "$WORKDIR/by-label.out" || fail "full machine id in detail"
pass "LABEL_LOOKUP"

set +e
python3 "$ROOT/tools/frp-client-info" ubuntu >"$WORKDIR/dup.out" 2>"$WORKDIR/dup.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "duplicate hostname should fail"
grep -q 'multiple clients matched' "$WORKDIR/dup.err" || fail "ambiguous error"
grep -q 'aabbccdd' "$WORKDIR/dup.err" || fail "ambiguous shows short id"
grep -q 'Use a longer CLIENT ID prefix' "$WORKDIR/dup.err" || fail "ambiguous hint"
pass "DUPLICATE_HOSTNAME_SAFE"

python3 "$ROOT/tools/frp-client-set" aabbccdd --label seoul-groupware --note "Seoul office groupware server" \
  >"$WORKDIR/set.out"
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY' || fail "client-set mutated identity"
import json,sys
from pathlib import Path
c=json.loads(Path(sys.argv[1]).read_text())['clients']['aabbccdd00112233445566778899aa']
assert c['label']=='seoul-groupware'
assert c['note']=='Seoul office groupware server'
assert c['hostname']=='ubuntu'
assert c['services']['ssh']['remote_port']==6002
assert c['mgmt_status']=='enrolled'
assert c['mgmt_pubkey']=='KEEP'
assert c['mgmt_mac_key']=='KEEP-MAC'
assert c['tags']=={'customer': 'lotte', 'site': 'seoul'}
PY
python3 "$ROOT/tools/frp-client-info" seoul-groupware >"$WORKDIR/after-set.out"
grep -q 'seoul-groupware' "$WORKDIR/after-set.out" || fail "new label in info"
grep -q 'ubuntu' "$WORKDIR/after-set.out" || fail "hostname unchanged in info"
pass "ADMIN_METADATA_EDIT"

echo
echo "CLIENT_METADATA_TEST=PASS"
