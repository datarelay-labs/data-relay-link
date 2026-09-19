#!/usr/bin/env bash
# Field UX: uninstall packaging + access-control + reconfigure fail-safe.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# shellcheck source=lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
# shellcheck source=lib/frp-client-common.sh
. "$ROOT/lib/frp-client-common.sh"

CLIENT="$WORKDIR/client"
mkdir -p "$CLIENT"
export FRP_CLIENT_TEST_ROOT="$CLIENT"
export FRP_SKIP_SYSTEMD=1
frp_client_install_management_files "$ROOT" || fail "install management files"
[[ -x "$CLIENT/usr/local/lib/frp-auto-deploy/uninstall-client.sh" ]] \
  || fail "uninstall-client.sh not installed to libdir"
grep -q 'usr/local/lib/frp-auto-deploy/uninstall-client.sh:0755:uninstall-client.sh' \
  <<<"$(frp_client_upgrade_destinations)" || fail "upgrade destinations missing uninstall"
pass "CLIENT_UNINSTALL_PACKAGED"

FOUND_PATH="$(
  FRP_CTL_SOURCED=1 FRP_CTL_TEST_ROOT="$CLIENT" FRP_CTL_BIN_DIR="$ROOT/tools" \
    bash -c '
      set -euo pipefail
      # shellcheck disable=SC1091
      . "'"$ROOT"'/tools/frpctl"
      frpctl_find_uninstall_client
    '
)"
[[ "$FOUND_PATH" == "$CLIENT/usr/local/lib/frp-auto-deploy/uninstall-client.sh" ]] \
  || fail "frpctl find uninstall: $FOUND_PATH"
pass "CLIENT_UNINSTALL_OFFLINE_DISPATCH"

python3 - "$ROOT" "$WORKDIR" <<'PY' || fail "access control UX"
import argparse
import contextlib
import io
import json
import os
import runpy
import sys
from pathlib import Path

root = Path(sys.argv[1])
workdir = Path(sys.argv[2])
sys.path.insert(0, str(root / "lib"))

# Load tools/frp-access (no .py suffix) via runpy in a temp module dict.
access_path = root / "tools" / "frp-access"
ns = runpy.run_path(str(access_path), run_name="frp_access_mod")
mod = argparse.Namespace(**{k: v for k, v in ns.items() if not k.startswith("__")})
# Keep callables bound; Namespace works for attribute access.

tree = workdir / "acl"
(tree / "etc/frp-auto-deploy").mkdir(parents=True)
(tree / "var/lib/frp-auto-deploy").mkdir(parents=True)
cfg = {
    "access_control_file": str(tree / "var/lib/frp-auto-deploy/access-control.json"),
    "registry_file": str(tree / "var/lib/frp-auto-deploy/registry.json"),
}
(tree / "etc/frp-auto-deploy/config.json").write_text(json.dumps(cfg) + "\n")
os.environ["FRP_DEPLOY_TEST_ROOT"] = str(tree)
os.environ["FRP_ACCESS_CONTROL_FILE"] = cfg["access_control_file"]
reg = {
    "schema_version": 2,
    "clients": {
        "aabbccdd00112233": {
            "label": "frp client",
            "hostname": "frp-client",
            "services": {
                "https": {"remote_port": 6002, "enabled": True},
                "ssh": {"remote_port": 6000, "enabled": True},
            },
        }
    },
}
(tree / "var/lib/frp-auto-deploy/registry.json").write_text(json.dumps(reg) + "\n")

import frp_access_control as ACL

state = ACL.empty_access_state()
lid, _ = ACL.create_access_list(state, "aaa", "test list")
ACL.add_source_entry(state, lid, "ggg", "1.1.1.4/27")
ACL.set_service_binding(state, "aabbccdd00112233", "https", ACL.MODE_ALLOWLIST, lid)
ACL.set_service_binding(state, "aabbccdd00112233", "ssh", ACL.MODE_PUBLIC, None)
ACL.save_access_state(state, cfg=cfg)

try:
    mod.validate_single_source_ip("10.10.10.0/24")
    raise SystemExit("CIDR should be rejected")
except SystemExit as exc:
    msg = str(exc)
    assert "single source IP" in msg, msg

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    mod.cmd_test(cfg, argparse.Namespace(client="aabbccdd00112233", service="ssh", source="10.10.10.25"))
text = buf.getvalue()
assert "Decision      : ALLOW" in text, text
assert "Reason        : PUBLIC" in text, text

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    mod.cmd_test(cfg, argparse.Namespace(client="aabbccdd00112233", service="https", source="1.1.1.4"))
text = buf.getvalue()
assert "Decision      : ALLOW" in text, text

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    mod.cmd_test(cfg, argparse.Namespace(client="aabbccdd00112233", service="https", source="8.8.8.8"))
text = buf.getvalue()
assert "Decision      : DENY" in text, text
assert "SOURCE_NOT_ALLOWED" in text, text

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    mod.cmd_add_source(
        cfg,
        argparse.Namespace(list="aaa", name="norm", source="2.2.2.5/27", ttl=None, yes=True),
    )
text = buf.getvalue()
assert "Input      : 2.2.2.5/27" in text, text
assert "Normalized : 2.2.2.0/27" in text, text

src = access_path.read_text(encoding="utf-8")
assert "Manage allowed sources" in src
assert "Testing access policy" in src
assert 'ERROR: select 1-%d' in src or 'ERROR: select 1-' in src
assert "if choice.isdigit():" in src
assert "def _is_menu_back" in src
assert mod._is_menu_back("b") and mod._is_menu_back("back") and mod._is_menu_back("q")
assert not mod._is_menu_back("1")
# Static proof the picker rejects out-of-range digits instead of returning them.
assert "if 1 <= n <= len(rows):" in src
assert "continue" in src
print("access ux ok")
PY
pass "ACCESS_CONTROL_FIELD_UX"

python3 -c '
from pathlib import Path
root = Path("'"$ROOT"'")
text = (root / "tools" / "frp-create-client").read_text(encoding="utf-8")
assert "if is_interactive_stdin() and not client_name:" in text
assert "not client_name or not str(a.note" not in text
' || fail "zero-touch identification"
pass "ZERO_TOUCH_SINGLE_IDENTIFICATION"

SERVER="$WORKDIR/server"
mkdir -p "$SERVER/etc/frp-auto-deploy" "$SERVER/var/lib/frp-auto-deploy" "$SERVER/etc/frp-auto-deploy/pki"
python3 - "$SERVER" <<'PY'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
(root / "etc/frp-auto-deploy/config.json").write_text(json.dumps({
    "public_ip": "203.0.113.10",
    "public_hostname": "xzy.xdr.ooo",
    "allocator_public_url": "https://xzy.xdr.ooo:6099/enroll",
    "registry_file": "/var/lib/frp-auto-deploy/registry.json",
    "deployment_mode": "direct",
    "frp_control_public_port": 7000,
    "port_start": 6000,
    "port_end": 6098,
}, indent=2) + "\n")
(root / "var/lib/frp-auto-deploy/registry.json").write_text(json.dumps({
    "schema_version": 2,
    "clients": {"aabb": {"hostname": "c1", "services": {}}},
}, indent=2) + "\n")
PY

export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_CTL_BIN_DIR="$ROOT/tools"

printf '%s\n' '203.0.113.10' 'xyz.xdr.ooo' 'https://xyz.xdr.ooo:6099/enroll' 'y' >"$WORKDIR/reconfig.in"
FRP_CTL_SOURCED=1 bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  . "'"$ROOT"'/tools/frpctl"
  frpctl_server_reconfigure
' <"$WORKDIR/reconfig.in" >"$WORKDIR/reconfig.out" 2>"$WORKDIR/reconfig.err" || true
grep -q 'xyz.xdr.ooo' "$SERVER/etc/frp-auto-deploy/config.json" || {
  cat "$WORKDIR/reconfig.out" "$WORKDIR/reconfig.err"
  fail "hostname reconfigure"
}
grep -q 'https://xyz.xdr.ooo:6099/enroll' "$SERVER/etc/frp-auto-deploy/config.json" || fail "allocator url"

printf '%s\n' '198.51.100.20' 'xyz.xdr.ooo' 'https://xyz.xdr.ooo:6099/enroll' 'y' >"$WORKDIR/reconfig-ip.in"
FRP_CTL_SOURCED=1 bash -c '
  set -euo pipefail
  # shellcheck disable=SC1091
  . "'"$ROOT"'/tools/frpctl"
  frpctl_server_reconfigure
' <"$WORKDIR/reconfig-ip.in" >"$WORKDIR/reconfig-ip.out" 2>"$WORKDIR/reconfig-ip.err" || true
grep -qi 'Public IP cannot be changed while registered clients exist' \
  "$WORKDIR/reconfig-ip.out" "$WORKDIR/reconfig-ip.err" || {
  cat "$WORKDIR/reconfig-ip.out" "$WORKDIR/reconfig-ip.err"
  fail "ip change fail-safe"
}
# Ensure IP was not mutated.
grep -q '"public_ip": "203.0.113.10"' "$SERVER/etc/frp-auto-deploy/config.json" || fail "ip should be unchanged"
pass "SERVER_PUBLIC_ENDPOINT_RECONFIG"

echo "FIELD_UX_UNINSTALL_ACCESS_TEST=PASS"
