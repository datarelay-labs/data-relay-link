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

grep -qE "Data Relay Link[: ].*1\.0\.0" "$OUT" || fail "project version"
grep -qE "Relay Engine \(FRP\) installed : 0\.70\.0|Installed FRP   : 0.70.0" "$OUT" || fail "installed frp"
grep -qE "Relay Engine \(FRP\) tested    : 0\.71\.0|Tested FRP      : 0.71.0" "$OUT" || fail "tested frp"
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
grep -qE "Relay Engine \(FRP\) installed : unknown|Installed FRP   : unknown" "$WORKDIR/status-unknown.out" || fail "unknown installed version"
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

# Finding: Fixed TCP runtime visibility on operator status.
python3 - "$TREE/var/lib/drlink/egress-control.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "schema_version": 3,
  "egress_profiles": {},
  "tcp_relays": {
    "r1": {"enabled": True, "listen_port": 6201, "dest_host": "example.com", "dest_port": 443},
    "r2": {"enabled": False, "listen_port": 6202, "dest_host": "example.com", "dest_port": 80},
  },
}, indent=2, sort_keys=True) + "\n")
PY
OUT_TCP="$WORKDIR/status-tcp.out"
if ! env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$TREE" \
  FRP_UPDATE_ROOT="$TREE" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  FRP_STATUS_TCP_EGRESS_STATE=active \
  FRP_STATUS_TCP_EGRESS_HEALTH=ok \
  FRP_STATUS_TCP_EGRESS_POLICY=healthy \
  FRP_STATUS_TCP_EGRESS_ENABLED=1 \
  FRP_STATUS_TCP_EGRESS_BOUND=1 \
  "$STATUS" >"$OUT_TCP"; then
  fail "status tcp visibility exited non-zero"
fi
grep -q "drlink-tcp-egress :" "$OUT_TCP" || fail "missing tcp-egress unit line"
grep -q "Fixed TCP Egress" "$OUT_TCP" || fail "missing Fixed TCP summary"
grep -q "TCP relays enabled : 1" "$OUT_TCP" || fail "missing enabled relay count"
grep -q "TCP relays bound   : 1" "$OUT_TCP" || fail "missing bound relay count"
pass "status Fixed TCP visibility"

# Restore schema v2 so later --check cases are not failed by the v1 registry.
python3 - "$TREE/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "schema_version": 2,
  "reserved": [6000],
  "clients": {},
}) + "\n")
PY

status_check() {
  env \
    FRP_UPDATE_TEST_HARNESS=1 \
    FRP_UPDATE_TEST_MARKER="$MARKER" \
    FRP_DEPLOY_TEST_ROOT="$TREE" \
    FRP_UPDATE_ROOT="$TREE" \
    FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
    FRP_STATUS_SKIP_UPSTREAM=1 \
    "$@" \
    "$STATUS" --check
}

if ! status_check \
  FRP_STATUS_TCP_EGRESS_STATE=inactive \
  FRP_STATUS_TCP_EGRESS_HEALTH=inactive \
  FRP_STATUS_TCP_EGRESS_POLICY=missing \
  FRP_STATUS_TCP_EGRESS_ENABLED=0 \
  FRP_STATUS_TCP_EGRESS_BOUND=0 \
  >"$WORKDIR/check-tcp-unused.out" 2>"$WORKDIR/check-tcp-unused.err"; then
  fail "unused Fixed TCP plane should not fail --check"
fi
pass "status --check unused Fixed TCP"

if status_check \
  FRP_STATUS_TCP_EGRESS_STATE=inactive \
  FRP_STATUS_TCP_EGRESS_HEALTH="unhealthy(not-running)" \
  FRP_STATUS_TCP_EGRESS_POLICY=healthy \
  FRP_STATUS_TCP_EGRESS_ENABLED=1 \
  FRP_STATUS_TCP_EGRESS_BOUND=0 \
  >"$WORKDIR/check-tcp-down.out" 2>"$WORKDIR/check-tcp-down.err"; then
  fail "enabled Fixed TCP with stopped runtime should fail --check"
fi
grep -q "Fixed TCP is not ready" "$WORKDIR/check-tcp-down.err" || fail "missing Fixed TCP readiness error"
pass "status --check enabled Fixed TCP not running"

if status_check \
  FRP_STATUS_TCP_EGRESS_STATE=active \
  FRP_STATUS_TCP_EGRESS_HEALTH="degraded(configured-not-listening)" \
  FRP_STATUS_TCP_EGRESS_POLICY=healthy \
  FRP_STATUS_TCP_EGRESS_ENABLED=1 \
  FRP_STATUS_TCP_EGRESS_BOUND=0 \
  >"$WORKDIR/check-tcp-degraded.out" 2>"$WORKDIR/check-tcp-degraded.err"; then
  fail "enabled Fixed TCP that is not listening should fail --check"
fi
grep -q "Fixed TCP is not ready" "$WORKDIR/check-tcp-degraded.err" || fail "missing listener readiness error"
pass "status --check enabled Fixed TCP not listening"

if ! status_check \
  FRP_STATUS_TCP_EGRESS_STATE=active \
  FRP_STATUS_TCP_EGRESS_HEALTH=ok \
  FRP_STATUS_TCP_EGRESS_POLICY=healthy \
  FRP_STATUS_TCP_EGRESS_ENABLED=1 \
  FRP_STATUS_TCP_EGRESS_BOUND=1 \
  >"$WORKDIR/check-tcp-ready.out" 2>"$WORKDIR/check-tcp-ready.err"; then
  fail "healthy enabled Fixed TCP should pass --check"
fi
pass "status --check enabled Fixed TCP ready"

echo
echo "FRP_STATUS_ENHANCED=PASS"
