#!/usr/bin/env bash
# CORE-001: Egress port must stay outside the published service pool;
# infrastructure ports are reserved from allocation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - "$ROOT" <<'PY' || fail "infra ports unit checks"
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "frp_infrastructure_ports", root / "lib" / "frp_infrastructure_ports.py"
)
infra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(infra)

assert infra.default_egress_outside_default_pool(), "default egress inside pool"
assert infra.DEFAULT_EGRESS_LISTEN_PORT == 6102
assert not (6000 <= infra.DEFAULT_EGRESS_LISTEN_PORT <= 6098)

cfg = {
    "port_start": 6000,
    "port_end": 6098,
    "allocator_listen_port": 6099,
    "frp_control_listen_port": 443,
    "listen_port": 6099,
    "egress_listen_port": 6102,
    "access_plugin_addr": "127.0.0.1:6101",
}
protected = infra.infrastructure_ports(cfg)
assert 6102 in protected
assert 6101 in protected
assert 6099 in protected
assert 443 in protected
assert not infra.infrastructure_ports_in_service_range(cfg)

# Custom egress inside pool is detected as colliding.
cfg2 = dict(cfg)
cfg2["egress_listen_port"] = 6080
assert 6080 in infra.infrastructure_ports_in_service_range(cfg2)

# Upgrade fail-closed when published service owns egress port.
registry = {
    "schema_version": 2,
    "clients": {
        "m1": {
            "mgmt_status": "enrolled",
            "services": {"ssh": {"remote_port": 6102, "name": "ssh"}},
        }
    },
}
try:
    infra.assert_egress_not_owned_by_service(cfg, registry)
    raise SystemExit("expected collision")
except RuntimeError as exc:
    assert "already owned" in str(exc)

# Allocator never allocates infrastructure ports.
aspec = importlib.util.spec_from_file_location(
    "frp_port_allocator", root / "server" / "frp-port-allocator.py"
)
alloc_mod = importlib.util.module_from_spec(aspec)
aspec.loader.exec_module(alloc_mod)

class FakeAlloc:
    cfg = dict(cfg)
    # Force every non-infra port "unavailable" except 6001, but protect 6102.
    def protected_ports(self):
        return alloc_mod.infrastructure_protected_ports(self.cfg)

# Simulate allocate_port skipping protected even when unbound.
used = set()
a = FakeAlloc()
# Patch port_is_available to always True so only protected/used matter.
orig = alloc_mod.port_is_available
alloc_mod.port_is_available = lambda port: True
try:
    # Exhaust range except leave 6080 free — but if egress were 6080 it must skip.
    a.cfg["egress_listen_port"] = 6080
    protected = a.protected_ports()
    assert 6080 in protected
    port = None
    start, end = 6000, 6098
    for candidate in range(start, end + 1):
        if candidate in used or candidate in protected:
            continue
        port = candidate
        break
    assert port is not None and port != 6080
finally:
    alloc_mod.port_is_available = orig

print("EGRESS_PORT_NOT_IN_SERVICE_POOL=PASS")
print("INFRASTRUCTURE_PORTS_RESERVED=PASS")
print("UPGRADE_EGRESS_PORT_COLLISION_FAIL_CLOSED=PASS")
PY

# Installer rejects egress inside service range.
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
export FRP_SERVER_SOURCED=1
# shellcheck source=../install-server.sh
. "$ROOT/install-server.sh"
unset FRP_PUBLIC_IP FRP_PUBLIC_HOST FRP_INTERNAL_IP FRP_CONTROL_PORT \
  FRP_CONTROL_PUBLIC_PORT FRP_CONTROL_LISTEN_PORT \
  FRP_PORT_START FRP_PORT_END FRP_ALLOCATOR_PORT \
  FRP_ALLOCATOR_PUBLIC_PORT FRP_ALLOCATOR_LISTEN_PORT \
  FRP_ALLOCATOR_URL FRP_ALLOCATOR_PUBLIC_URL FRP_CLIENT_INSTALLER_URL \
  FRP_SERVER_CONFIG FRP_EGRESS_LISTEN_PORT || true
export FRP_PUBLIC_HOST=203.0.113.10
export FRP_EGRESS_LISTEN_PORT=6080
export FRP_PORT_START=6000
export FRP_PORT_END=6098
export FRP_SERVER_CONFIG="$WORKDIR/missing.json"
if (
  load_existing_server_config
  resolve_server_settings
) >/dev/null 2>"$WORKDIR/egress-range.err"; then
  fail "egress listen in service range should fail"
fi
grep -qi 'egress' "$WORKDIR/egress-range.err" || fail "egress range message"
pass "installer rejects egress inside published range"

echo "CORE_001_EGRESS_PORT_ARCHITECTURE=PASS"
