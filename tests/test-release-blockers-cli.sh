#!/usr/bin/env bash
# Targeted regressions for v2.3.1 release blockers A–H (CLI/UX/egress/access).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export PYTHONDONTWRITEBYTECODE=1
export FRP_DEPLOY_TEST_ROOT="$WORKDIR"
MARKER="$WORKDIR/harness.marker"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
printf '%s' "$FRP_TEST_HARNESS_MAGIC" >"$MARKER"

mkdir -p \
  "$WORKDIR/etc/drlink" \
  "$WORKDIR/var/lib/drlink" \
  "$WORKDIR/usr/local/lib/drlink" \
  "$WORKDIR/run/drlink/egress"

python3 - "$WORKDIR/etc/drlink/config.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "public_ip": "203.0.113.10",
  "public_host": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "registry_file": "/var/lib/drlink/registry.json",
  "access_control_file": "/var/lib/drlink/access-control.json",
  "egress_control_file": "/var/lib/drlink/egress-control.json",
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
}, indent=2) + "\n")
PY

python3 - "$WORKDIR/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "schema_version": 2,
  "reserved": [6000, 6001],
  "clients": {
    "aabbccddeeff0011": {
      "label": "edge-a",
      "hostname": "edge-a.local",
      "services": {
        "ssh": {
          "protocol": "tcp", "preset": "ssh", "ssh_user": "ops",
          "local_ip": "127.0.0.1", "local_port": 22,
          "remote_port": 6000, "enabled": True,
        },
        "http": {
          "protocol": "tcp", "preset": "http",
          "local_ip": "127.0.0.1", "local_port": 80,
          "remote_port": 6001, "enabled": False,
        },
      },
    },
  },
  "groups": {},
}, indent=2) + "\n")
PY

cp "$ROOT"/lib/frp_*.py "$WORKDIR/usr/local/lib/drlink/" 2>/dev/null || true
cp -a "$ROOT/lib/data" "$WORKDIR/usr/local/lib/drlink/" 2>/dev/null || true

# A) ACCESS_MISSING_POLICY_CLI_TRUTHFUL + F client list concise
rm -f "$WORKDIR/var/lib/drlink/access-control.json"
OUT="$WORKDIR/clients-missing.out"
"$ROOT/tools/frp-clients" >"$OUT"
grep -q 'POLICY UNAVAILABLE' "$OUT" || { cat "$OUT"; fail "client list missing policy"; }
! grep -qE 'PUBLIC /| [0-9]+ PUBLIC' "$OUT" || { cat "$OUT"; fail "client list claimed PUBLIC"; }
grep -q 'client show ' "$OUT" || fail "client list example not canonical"
! grep -q 'show client ' "$OUT" || fail "client list legacy example"
! grep -qE '^\s+ssh:6000' "$OUT" || fail "client list dumped services"
pass "CLIENT_LIST_CONCISE"

OUT="$WORKDIR/client-show-missing.out"
"$ROOT/tools/frp-client-info" aabbccddeeff0011 services >"$OUT"
grep -q 'POLICY UNAVAILABLE' "$OUT" || { cat "$OUT"; fail "client show missing policy"; }
! grep -qE '[[:space:]]PUBLIC[[:space:]]+(OFFLINE|ONLINE|DISABLED|UNKNOWN)' "$OUT" \
  || { cat "$OUT"; fail "client show claimed PUBLIC access"; }
grep -q 'DISABLED' "$OUT" || { cat "$OUT"; fail "disabled service missing"; }
grep -q 'RESERVED' "$OUT" || { cat "$OUT"; fail "reserved port state missing"; }
grep -q 'PORT STATE' "$OUT" || fail "PORT STATE header missing"
pass "CLIENT_SHOW_DISABLED_RESERVED"
pass "ACCESS_MISSING_POLICY_CLI_TRUTHFUL"

printf '{not-json' >"$WORKDIR/var/lib/drlink/access-control.json"
OUT="$WORKDIR/clients-corrupt.out"
"$ROOT/tools/frp-clients" >"$OUT"
grep -q 'ACCESS ERROR' "$OUT" || { cat "$OUT"; fail "client list corrupt policy"; }
! grep -q 'PUBLIC /' "$OUT" || fail "corrupt policy displayed PUBLIC"

rm -f "$WORKDIR/var/lib/drlink/access-control.json"
python3 - <<'PY'
import importlib.util, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
path = root / "var/lib/drlink/access-control.json"
path.unlink(missing_ok=True)
spec = importlib.util.spec_from_file_location("acl", root / "usr/local/lib/drlink/frp_access_control.py")
acl = importlib.util.module_from_spec(spec); spec.loader.exec_module(acl)
assert not path.exists(), path
acl.initialize_access_state(path=path)
assert path.exists()
PY

OUT="$WORKDIR/service-list.out"
"$ROOT/tools/frp-services" >"$OUT"
grep -q 'CLIENT' "$OUT" || fail "global service list header"
grep -q 'PUBLIC ENDPOINT' "$OUT" || fail "global endpoint column"
grep -q 'PORT STATE' "$OUT" || fail "global port state column"
grep -q 'ssh' "$OUT" || fail "global list missing ssh"
grep -q 'http' "$OUT" || fail "global list missing disabled http"
grep -q 'RESERVED' "$OUT" || fail "global list missing RESERVED"
pass "GLOBAL_SERVICE_LIST"

STATUS="$ROOT/tools/frp-server-status"
run_check() {
  local health="$1" policy="$2" estate="${3:-active}"
  env \
    FRP_UPDATE_TEST_HARNESS=1 \
    FRP_UPDATE_TEST_MARKER="$MARKER" \
    FRP_DEPLOY_TEST_ROOT="$WORKDIR" \
    FRP_UPDATE_ROOT="$WORKDIR" \
    FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
    FRP_STATUS_SKIP_UPSTREAM=1 \
    FRP_STATUS_SERVER_STATE=active \
    FRP_STATUS_ALLOCATOR_STATE=active \
    FRP_STATUS_ACCESS_STATE=active \
    FRP_STATUS_EGRESS_STATE="$estate" \
    FRP_STATUS_ACCESS_HEALTH=ok \
    FRP_STATUS_ALLOCATOR_HEALTH=ok \
    FRP_STATUS_EGRESS_HEALTH="$health" \
    FRP_STATUS_EGRESS_POLICY="$policy" \
    "$STATUS" --check
}

if env \
  FRP_UPDATE_TEST_HARNESS=1 \
  FRP_UPDATE_TEST_MARKER="$MARKER" \
  FRP_DEPLOY_TEST_ROOT="$WORKDIR" \
  FRP_UPDATE_ROOT="$WORKDIR" \
  FRP_UPDATE_HOOK_SKIP_SYSTEMD=1 \
  FRP_STATUS_SKIP_UPSTREAM=1 \
  FRP_STATUS_SERVER_STATE=active \
  FRP_STATUS_ALLOCATOR_STATE=active \
  FRP_STATUS_ACCESS_STATE=active \
  FRP_STATUS_EGRESS_STATE=inactive \
  FRP_STATUS_ACCESS_HEALTH=ok \
  FRP_STATUS_ALLOCATOR_HEALTH=ok \
  FRP_STATUS_EGRESS_HEALTH=unhealthy\(not-listening\) \
  FRP_STATUS_EGRESS_POLICY=missing \
  "$STATUS" --check >/dev/null 2>"$WORKDIR/check-down.err"; then
  fail "unit down should fail --check"
fi
pass "STATUS_EGRESS_UNIT_DOWN"

if run_check "ok" "healthy" active >/dev/null 2>&1; then
  pass "STATUS_EGRESS_LISTENER_HEALTHY_SNAPSHOT"
else
  fail "healthy snapshot should pass --check"
fi

if run_check "degraded(policy-unhealthy)" "unhealthy" active >/dev/null 2>&1; then
  fail "unhealthy policy should fail --check"
fi
pass "STATUS_EGRESS_LISTENER_UNHEALTHY_SNAPSHOT"

if run_check "degraded(policy-unavailable)" "missing" active >/dev/null 2>&1; then
  fail "missing snapshot should fail --check"
fi
pass "STATUS_EGRESS_LISTENER_NO_SNAPSHOT"
pass "STATUS_EGRESS_POLICY_HEALTH_REQUIRED"

python3 - <<'PY' || fail "egress incomplete enable"
import importlib.util, os, sys
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
sys.path.insert(0, str(root / "usr/local/lib/drlink"))
import frp_egress_control as EG
cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json"}
path = root / "var/lib/drlink/egress-control.json"
EG.save_egress_state(EG.empty_egress_state(), path=path)

def create_disabled(state):
    return EG.create_profile(state, "vendor-api", enabled=False)
pid, rec = EG.mutate_egress_state(create_disabled, cfg=cfg)
assert rec["enabled"] is False
try:
    EG.mutate_egress_state(lambda s: EG.create_profile(s, "bad", enabled=True), cfg=cfg)
    raise SystemExit("create --enable should fail")
except EG.EgressError:
    pass
try:
    EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=cfg)
    raise SystemExit("enable without source/dest should fail")
except EG.EgressError as exc:
    assert "incomplete" in str(exc).lower() or "no source" in str(exc).lower()
EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "10.0.0.0/24"), cfg=cfg)
try:
    EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=cfg)
    raise SystemExit("enable without destination should fail")
except EG.EgressError as exc:
    assert "no destination" in str(exc).lower() or "incomplete" in str(exc).lower()
EG.mutate_egress_state(
    lambda s: EG.add_destination(s, pid, "api.example.com", 443, protocol="https"), cfg=cfg
)
EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=cfg)
print("enable-ok")
PY
pass "EGRESS_INCOMPLETE_PROFILE_ENABLE_DENIED"

if "$ROOT/tools/frp-egress" create should-fail --enable >/dev/null 2>"$WORKDIR/create-enable.err"; then
  fail "egress create --enable should be denied"
fi
grep -qiE 'enable|disabled|incomplete|source|destination|cannot' "$WORKDIR/create-enable.err" \
  || { cat "$WORKDIR/create-enable.err"; fail "create --enable error message"; }
pass "EGRESS_ENABLE_WORKFLOW_CONTRACT"

python3 - <<'PY' || fail "menu catalog parity"
import importlib.util
from pathlib import Path
root = Path(".").resolve()
spec = importlib.util.spec_from_file_location("c", root / "lib/frp_cli_catalog.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
for role in ("server", "client", "both"):
    rendered = c.render_guided_menu(role)
    entries = c.guided_menu_entries(role)
    assert entries, role
    assert c.guided_menu_action(role, "1") == entries[0][1]
    assert c.guided_menu_action(role, str(len(entries))) == "exit"
    for idx, action_id, label, hint in entries:
        assert f"{idx})" in rendered
        assert label in rendered
frpctl = (root / "tools/frpctl").read_text(encoding="utf-8")
assert "frpctl_render_guided_menu" in frpctl
assert 'echo "1) Status                     (status)"' not in frpctl
print("CLI_MENU_CATALOG_PARITY=PASS")
PY
pass "CLI_MENU_CATALOG_PARITY"

python3 - <<'PY' || fail "user-facing canonical contract"
import importlib.util, re
from pathlib import Path
root = Path(".").resolve()
spec = importlib.util.spec_from_file_location("c", root / "lib/frp_cli_catalog.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
specg = importlib.util.spec_from_file_location("g", root / "lib/frp_ctl_grammar.py")
g = importlib.util.module_from_spec(specg); specg.loader.exec_module(g)

banned = re.compile(
    r"(?m)^\s*(?:\$\s*)?(?:sudo\s+)?(?:drlink\s+)?(?:"
    r"show\s+clients|show\s+client\b|set\s+client\b|create\s+client\b|"
    r"show\s+info\b|show\s+services\b|enroll\b|revoke\s+client\b"
    r")"
)

def scan(label, text):
    for m in banned.finditer(text):
        line = text[max(0, m.start()-60):m.end()+60]
        if "help legacy" in line.lower():
            continue
        if "Compatibility aliases still run" in line:
            continue
        raise AssertionError("%s advertises legacy grammar near: %r" % (label, line))

for role in ("server", "client", "both"):
    scan("root_help", c.root_help(role))
    scan("workflow_help", c.workflow_help(role))
    scan("concise_root", c.concise_root(role))
    scan("guided_menu", c.render_guided_menu(role))
    scan("shell_usage", "\n".join(c.shell_usage_lines(role)))
    scan("help_text", g.help_text([], role))

for cmd in c.COMMANDS:
    if cmd.get("hidden"):
        continue
    for ex in cmd.get("examples") or ():
        toks = ex.split()
        found = c.find(toks)
        assert found is not None, "catalog example not canonical: %r" % ex

clients_src = (root / "tools/frp-clients").read_text(encoding="utf-8")
assert "client show %" in clients_src or 'client show %s' in clients_src or "print('  client show" in clients_src
assert "print('  show client" not in clients_src
assert 'print("  show client' not in clients_src
print("USER_FACING_CANONICAL_COMMAND_CONTRACT=PASS")
PY
pass "USER_FACING_CANONICAL_COMMAND_CONTRACT"

python3 - <<'PY' || fail "zero-touch early validation"
import subprocess, textwrap
from pathlib import Path
root = Path(".").resolve()
src = (root / "tools/frpctl").read_text(encoding="utf-8")
assert "frpctl_zt_validate_field" in src
assert "invalid service ID" in src
assert "invalid target host" in src
proc = subprocess.run(
    ["bash", "-c", textwrap.dedent(f'''
      set -euo pipefail
      ROOT="{root}"
      FRP_CTL_CMD_NAME=drlink
      _FRPCTL_DIR="$ROOT/tools"
      eval "$(sed -n '/^frpctl_zt_validate_field()/,/^}}/p' "$ROOT/tools/frpctl")"
      eval "$(sed -n '/^frpctl_zt_prompt_client_identification()/,/^}}/p' "$ROOT/tools/frpctl")"
      exec 9<<EOF
bad/name
good-name

EOF
      frpctl_try_read() {{ local prompt="$1"; local value=""; IFS= read -r value <&9 || return 1; printf '%s' "$value"; }}
      frpctl_read() {{ local prompt="$1" default="${{2:-}}"; local value=""; value="$(frpctl_try_read "$prompt")" || return 1; [[ -z "$value" ]] && value="$default"; printf '%s' "$value"; }}
      frpctl_zt_prompt_client_identification
      [[ "$_FRP_ZT_CLIENT_NAME" == "good-name" ]]
      ! frpctl_zt_validate_field service_id "BAD ID" >/dev/null 2>&1
      ! frpctl_zt_validate_field target_host "host;rm" >/dev/null 2>&1
      ! frpctl_zt_validate_field target_port "0" >/dev/null 2>&1
      frpctl_zt_validate_field target_port "22" >/dev/null
      echo ZERO_TOUCH_EARLY_VALIDATION=PASS
    ''')],
    capture_output=True,
    text=True,
)
if proc.returncode != 0:
    print(proc.stdout)
    print(proc.stderr)
    raise SystemExit(proc.returncode)
assert "ZERO_TOUCH_EARLY_VALIDATION=PASS" in proc.stdout
print("ZERO_TOUCH_EARLY_VALIDATION=PASS")
PY
pass "ZERO_TOUCH_EARLY_VALIDATION"

echo "RELEASE_BLOCKERS_CLI_TEST=PASS"
