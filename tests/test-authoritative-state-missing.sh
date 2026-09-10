#!/usr/bin/env bash
# Missing ACL/registry/profiles must fail closed at runtime (no silent recreate).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"; unset FRP_DEPLOY_TEST_ROOT' EXIT
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_DEPLOY_TEST_ROOT="$WORKDIR"
export PYTHONDONTWRITEBYTECODE=1

mkdir -p "$WORKDIR/etc/drlink" "$WORKDIR/var/lib/drlink" \
  "$WORKDIR/usr/local/lib/drlink" "$WORKDIR/etc/frp"
cp "$ROOT/lib/frp_access_control.py" "$WORKDIR/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_service_profiles.py" "$WORKDIR/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_client_registry.py" "$WORKDIR/usr/local/lib/drlink/"
cp "$ROOT/server/frp-port-allocator.py" "$WORKDIR/usr/local/lib/drlink/"
cp "$ROOT/lib/"frp_*.py "$WORKDIR/usr/local/lib/drlink/" 2>/dev/null || true

cat >"$WORKDIR/etc/drlink/config.json" <<JSON
{
  "registry_file": "$WORKDIR/var/lib/drlink/registry.json",
  "access_control_file": "$WORKDIR/var/lib/drlink/access-control.json",
  "service_profiles_file": "$WORKDIR/var/lib/drlink/service-profiles.json",
  "port_start": 6000,
  "port_end": 6100,
  "allocator_listen_port": 6099,
  "listen_port": 7000,
  "public_host": "127.0.0.1"
}
JSON

python3 - <<'PY' || fail "ACL require missing"
import importlib.util, sys
from pathlib import Path
root = Path(__import__("os").environ["FRP_DEPLOY_TEST_ROOT"])
sys.path.insert(0, str(root / "usr/local/lib/drlink"))
spec = importlib.util.spec_from_file_location("acl", root / "usr/local/lib/drlink/frp_access_control.py")
acl = importlib.util.module_from_spec(spec); spec.loader.exec_module(acl)
path = root / "var/lib/drlink/access-control.json"
try:
    acl.require_access_state(path=path)
    raise SystemExit("expected missing ACL error")
except acl.AccessError as exc:
    assert "missing" in str(exc).lower()
# mutate must not create
try:
    acl.mutate_access_state(lambda s: s, path=path)
    raise SystemExit("mutate should fail when missing")
except acl.AccessError:
    pass
assert not path.exists(), "ACL file must not be recreated"
print("acl-ok")
PY
pass "ACL missing refuse recreate"

# Populate then remove ACL
python3 - <<'PY'
import importlib.util
from pathlib import Path
import os
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
spec = importlib.util.spec_from_file_location("acl", root / "usr/local/lib/drlink/frp_access_control.py")
acl = importlib.util.module_from_spec(spec); spec.loader.exec_module(acl)
path = root / "var/lib/drlink/access-control.json"
acl.initialize_access_state(path=path)
assert path.exists()
path.rename(path.with_suffix(".json.bak"))
PY

python3 - <<'PY' || fail "profiles require missing"
import importlib.util, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
spec = importlib.util.spec_from_file_location("prof", root / "usr/local/lib/drlink/frp_service_profiles.py")
prof = importlib.util.module_from_spec(spec); spec.loader.exec_module(prof)
path = root / "var/lib/drlink/service-profiles.json"
try:
    prof.require_profiles_state(path=path)
    raise SystemExit("expected missing profiles error")
except prof.ProfileError:
    pass
try:
    prof.mutate_profiles_state(lambda s: s, path=path)
    raise SystemExit("mutate should fail")
except prof.ProfileError:
    pass
assert not path.exists()
print("profiles-ok")
PY
pass "profiles missing refuse recreate"

# Registry: write then remove; group-set and clients must error without recreate
cat >"$WORKDIR/var/lib/drlink/registry.json" <<'JSON'
{"schema_version":2,"reserved":[],"clients":{"aabb":{"label":"t","services":{}}},"groups":{}}
JSON
cp "$WORKDIR/var/lib/drlink/registry.json" "$WORKDIR/registry.bak"
rm -f "$WORKDIR/var/lib/drlink/registry.json"

if "$ROOT/tools/frp-clients" >/dev/null 2>"$WORKDIR/clients.err"; then
  fail "frp-clients should error when registry missing"
fi
grep -qi 'missing\|authoritative\|ERROR' "$WORKDIR/clients.err" || fail "clients error message"
[[ ! -f "$WORKDIR/var/lib/drlink/registry.json" ]] || fail "clients recreated registry"
pass "frp-clients missing registry"

if echo | "$ROOT/tools/frp-group-set" create "Test Group" >/dev/null 2>"$WORKDIR/group.err"; then
  fail "group-set should error when registry missing"
fi
grep -qi 'missing\|authoritative\|ERROR' "$WORKDIR/group.err" || {
  cat "$WORKDIR/group.err" >&2
  fail "group-set error message"
}
[[ ! -f "$WORKDIR/var/lib/drlink/registry.json" ]] || fail "group-set recreated registry"
pass "group-set missing registry"

# Backup must fail without ACL
cp "$WORKDIR/registry.bak" "$WORKDIR/var/lib/drlink/registry.json"
# Minimal required tree for backup path check via collect semantics
ROOT="$ROOT" python3 - <<'PY' || fail "backup missing ACL"
import os, sys, types
from pathlib import Path
repo = Path(os.environ["ROOT"])
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
path = repo / "tools" / "frp-backup"
mod = types.ModuleType("frp_backup")
sys.modules["frp_backup"] = mod
code = compile(path.read_text(encoding="utf-8"), str(path), "exec")
exec(code, mod.__dict__)
for rel in mod.REQUIRED:
    if rel.endswith("access-control.json") or rel.endswith("service-profiles.json"):
        continue
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        if rel.endswith(".json"):
            dest.write_text('{}\n')
        else:
            dest.write_text('x\n')
(root / "var/lib/drlink/registry.json").write_text(
    '{"schema_version":2,"reserved":[],"clients":{}}\n'
)
failed = False
try:
    mod.collect_files(root)
except SystemExit:
    failed = True
if not failed:
    raise SystemExit("backup should fail without ACL")
assert not (root / "var/lib/drlink/access-control.json").exists()
print("backup-ok")
PY
pass "backup missing ACL"

# Restore original ACL path after rename
mv "$WORKDIR/var/lib/drlink/access-control.json.bak" \
  "$WORKDIR/var/lib/drlink/access-control.json" 2>/dev/null || true

# Profile SSH atomic transition + health old_value
python3 - <<'PY' || fail "profile ssh/audit"
import importlib.util, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
spec = importlib.util.spec_from_file_location("prof", root / "usr/local/lib/drlink/frp_service_profiles.py")
prof = importlib.util.module_from_spec(spec); spec.loader.exec_module(prof)
path = root / "var/lib/drlink/service-profiles.json"
prof.initialize_profiles_state(path=path)
state = prof.require_profiles_state(path=path)
pid, _ = prof.create_profile(state, "Web", preset="http", local_ip="127.0.0.1", local_port=80)
# atomic ssh transition
pid2, profile, old = prof.update_profile(state, pid, "preset", "ssh:ops")
assert profile["preset"] == "ssh" and profile["ssh_user"] == "ops"
# health old_value
profile["health_check"] = {"type": "tcp", "timeout_seconds": 3, "interval_seconds": 10, "max_failed": 1}
pid3, profile2, old_to = prof.update_profile(state, pid, "health-timeout", "7")
assert old_to == "3", old_to
assert int(profile2["health_check"]["timeout_seconds"]) == 7
print("profile-ok")
PY
pass "profile ssh transition and health audit old_value"

echo "ALL authoritative-state missing checks passed"
