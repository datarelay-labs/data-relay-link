#!/usr/bin/env bash
# Status command regression. Dummy token values are never printed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
STATUS="$ROOT/tools/frp-server-status"
MARKER="$WORKDIR/harness.marker"
printf '%s' "$FRP_TEST_HARNESS_MAGIC" >"$MARKER"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORKDIR/status"
mkdir -p "$TREE/usr/local/bin" "$TREE/etc/drlink" "$TREE/var/lib/drlink"

cat >"$TREE/usr/local/bin/frps" <<'EOF'
#!/usr/bin/env bash
echo "frps version 0.70.0"
exit 0
EOF
chmod 0755 "$TREE/usr/local/bin/frps"

cat >"$TREE/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.0.0
FRP_VERSION=0.71.0
EOF

python3 - "$TREE/etc/drlink/config.json" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
}, indent=2, sort_keys=True)+"\n")
PY

python3 - "$TREE/var/lib/drlink/registry.json" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "schema_version": 2,
  "reserved": [6000, 6001],
  "clients": {
    "a": {"hostname": "a", "services": {
      "ssh": {"remote_port": 6002, "enabled": True},
      "https": {"remote_port": 6003, "enabled": True},
    }},
    "b": {"hostname": "b", "services": {
      "ssh": {"remote_port": 6004, "enabled": True},
    }},
    "c": {"hostname": "c", "services": {
      "ssh": {"remote_port": 6005, "enabled": True},
      "https": {"remote_port": 6006, "enabled": True},
    }},
  },
})+"\n")
PY

OUT="$WORKDIR/status.out"
if ! env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_UPDATE_ROOT="$TREE" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  "$STATUS" >"$OUT"; then
  fail "status exited non-zero"
fi

grep -q "Project version : 1.0.0" "$OUT" || fail "project version"
grep -q "Installed FRP   : 0.70.0" "$OUT" || fail "installed frp"
grep -q "Tested FRP      : 0.71.0" "$OUT" || fail "tested frp"
grep -q "Upstream latest : unavailable" "$OUT" || fail "upstream unavailable"
grep -q "Update status   : update available" "$OUT" || fail "update available"
grep -q "FRP public      : TCP/443" "$OUT" || fail "control port"
grep -q "FRP listen      : TCP/443" "$OUT" || fail "listen port"
grep -q "Service range   : TCP/6000-6098" "$OUT" || fail "service range"
grep -q "Allocator listen: TCP/6099" "$OUT" || fail "allocator port"
grep -q "Clients         : 3" "$OUT" || fail "client count"
grep -q "Reserved ports  : 7" "$OUT" || fail "reserved port count"
grep -q "Registry schema : 2" "$OUT" || fail "registry schema"
grep -q "Registry state  : ready" "$OUT" || fail "registry state"
grep -q "Allocator URL   : configured" "$OUT" || fail "allocator url"
grep -q "Public host     : configured" "$OUT" || fail "public host"
pass "status update-available layout"

if ! env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_UPDATE_ROOT="$TREE" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  "$STATUS" --check >"$WORKDIR/check-ready.out"; then
  fail "status --check should pass for schema v2"
fi
pass "status --check ready"

# Missing binary -> unknown, still exit 0
rm -f "$TREE/usr/local/bin/frps"
env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  "$STATUS" >"$WORKDIR/status-unknown.out"
grep -q "Installed FRP   : unknown" "$WORKDIR/status-unknown.out" || fail "unknown installed version"
pass "status missing binary"

# Current version
cat >"$TREE/usr/local/bin/frps" <<'EOF'
#!/usr/bin/env bash
echo "frps version 0.71.0"
exit 0
EOF
chmod 0755 "$TREE/usr/local/bin/frps"
env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  "$STATUS" >"$WORKDIR/status-current.out"
grep -q "Update status   : up to date" "$WORKDIR/status-current.out" || fail "up to date"
pass "status up to date"

# Incompatible v1 registry: status still exits 0, --check fails.
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "reserved": [],
  "clients": {"old": {"hostname": "legacy", "ssh_port": 6002}},
})+"\n")
PY
env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  "$STATUS" >"$WORKDIR/status-v1.out"
grep -q "Registry schema : 1" "$WORKDIR/status-v1.out" || fail "v1 schema"
grep -q "Registry state  : incompatible" "$WORKDIR/status-v1.out" || fail "v1 state"
grep -q "Action required" "$WORKDIR/status-v1.out" || fail "v1 action"
pass "status v1 incompatible"

if env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  "$STATUS" --check >"$WORKDIR/check-v1.out"; then
  fail "status --check should fail for schema v1"
fi
pass "status --check v1 fail closed"

echo
echo "FRP_STATUS_ENHANCED=PASS"
