#!/usr/bin/env bash
# Service Profiles: grammar, CRUD, draft apply, backup/audit contracts.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"; unset FRP_DEPLOY_TEST_ROOT FRP_SOURCE_ROOT' EXIT
TREE="$WORKDIR/root"
export FRP_DEPLOY_TEST_ROOT="$TREE"
export FRP_CTL_TEST_ROOT="$TREE"
export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_CTL_BIN_DIR="$ROOT/tools"
export FRP_SOURCE_ROOT="$ROOT"
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

mkdir -p \
  "$TREE/etc/frp-auto-deploy" \
  "$TREE/etc/frp" \
  "$TREE/var/lib/frp-auto-deploy" \
  "$TREE/var/log/frp-auto-deploy" \
  "$TREE/usr/local/lib/frp-auto-deploy" \
  "$TREE/usr/local/sbin"

cp "$ROOT/lib/frp_service_profiles.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_access_control.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_client_registry.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_ctl_grammar.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_ctl_repl.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_audit.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_doctor.py" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp-doctor-common.sh" "$TREE/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/tools/frp-profile" "$TREE/usr/local/sbin/"
cp "$ROOT/tools/frpctl" "$TREE/usr/local/sbin/"
cp "$ROOT/tools/frp-client" "$TREE/usr/local/sbin/"
chmod +x "$TREE/usr/local/sbin/frp-profile" "$TREE/usr/local/sbin/frpctl" "$TREE/usr/local/sbin/frp-client"
chmod +x "$ROOT/tools/frp-profile" "$ROOT/tools/frpctl" "$ROOT/tools/frp-client"

python3 - <<'PY'
import importlib.util
import json
import os
from pathlib import Path

root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
cfg = {
    "public_host": "203.0.113.10",
    "public_ip": "203.0.113.10",
    "registry_file": "/var/lib/frp-auto-deploy/registry.json",
    "access_control_file": "/var/lib/frp-auto-deploy/access-control.json",
    "service_profiles_file": "/var/lib/frp-auto-deploy/service-profiles.json",
}
(root / "etc/frp-auto-deploy/config.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
(root / "var/lib/frp-auto-deploy/registry.json").write_text(
    json.dumps({"schema_version": 2, "clients": {}, "reserved": [], "groups": {}}, indent=2) + "\n",
    encoding="utf-8",
)
spec = importlib.util.spec_from_file_location(
    "frp_service_profiles",
    str(root / "usr/local/lib/frp-auto-deploy/frp_service_profiles.py"),
)
prof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prof)
prof.save_profiles_state(prof.empty_profiles_state(), cfg=cfg)

# Minimal client state for dual-role draft apply (schema 1).
(root / "etc/frp/client-state.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "allocator_url": "https://203.0.113.10:8443/enroll",
            "frp_server": "203.0.113.10",
            "frp_server_port": 7000,
            "frp_transport": "tcp",
            "hostname": "demo-host",
            "machine_id": "machine-abcdef012345",
            "host_id": "demo-host-machine",
            "services": {},
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

python3 - "$ROOT/lib/frp_ctl_grammar.py" <<'PY' || fail "grammar profile match"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("frp_ctl_grammar", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cases = [
    (["show", "profiles"], "server", "show_profiles"),
    (["show", "profile", "x"], "server", "show_profile"),
    (["create", "profile", "n", "--preset", "ssh", "--target-host", "127.0.0.1", "--target-port", "22", "--ssh-user", "u"], "server", "create_profile"),
    (["set", "profile", "x", "name", "y"], "server", "set_profile"),
    (["delete", "profile", "x"], "server", "delete_profile"),
    (["add", "service", "--profile", "office"], "client", "add_service"),
]
for toks, role, action in cases:
    result = mod.match(toks, role)
    assert result.get("status") == "ok" and result.get("action") == action, (toks, result)
role = mod.match(["create", "profile", "n"], "client")
assert role["status"] == "role", role
print("ok")
PY
pass "frpctl grammar profile actions"

CTL="$ROOT/tools/frpctl"
chmod +x "$ROOT/tools/frpctl" "$ROOT/tools/frp-profile" "$ROOT/tools/frp-client"

"$CTL" show profiles >"$WORKDIR/list.out"
grep -q 'PROFILE ID' "$WORKDIR/list.out" || fail "profiles header"
grep -q '(none)' "$WORKDIR/list.out" || fail "empty profiles"

"$CTL" create profile office-ssh --preset ssh --target-host 127.0.0.1 --target-port 22 --ssh-user ubuntu --description 'desk' >"$WORKDIR/create.out"
grep -q 'Created profile prof_' "$WORKDIR/create.out" || fail "create profile id"
PROFILE_ID="$(python3 -c 'import json,re; from pathlib import Path; import os; p=Path(os.environ["FRP_DEPLOY_TEST_ROOT"])/"var/lib/frp-auto-deploy/service-profiles.json"; d=json.loads(p.read_text()); print(next(iter(d["profiles"])))')"
[[ "$PROFILE_ID" == prof_* ]] || fail "profile id format"

"$CTL" show profile office-ssh >"$WORKDIR/show.out"
grep -q "$PROFILE_ID" "$WORKDIR/show.out" || fail "show profile id"
grep -q 'Preset        : ssh' "$WORKDIR/show.out" || fail "show preset"

if "$CTL" create profile Office-SSH --preset http --target-host 10.0.0.1 --target-port 80 >"$WORKDIR/dup.out" 2>"$WORKDIR/dup.err"; then
  fail "duplicate name should fail"
fi
grep -qi 'already exists' "$WORKDIR/dup.err" || fail "duplicate name error"

ORIG_ID="$PROFILE_ID"
"$CTL" set profile office-ssh target-port 2222 >"$WORKDIR/set.out"
"$CTL" show profile office-ssh >"$WORKDIR/show2.out"
grep -q '127.0.0.1:2222' "$WORKDIR/show2.out" || fail "edited target port"
NEW_ID="$(python3 -c 'import json,os; from pathlib import Path; d=json.loads((Path(os.environ["FRP_DEPLOY_TEST_ROOT"])/"var/lib/frp-auto-deploy/service-profiles.json").read_text()); print(next(iter(d["profiles"])))')"
[[ "$NEW_ID" == "$ORIG_ID" ]] || fail "profile id mutated"

# Health fields accepted when provided
"$CTL" create profile healthy-http --preset http --target-host 127.0.0.1 --target-port 8080 --health-type tcp --health-timeout 3 --health-interval 10 --health-max-failed 2 >"$WORKDIR/hc.out"
"$CTL" show profile healthy-http >"$WORKDIR/hc-show.out"
grep -qi 'Health check' "$WORKDIR/hc-show.out" || fail "health shown"
pass "frpctl profile CRUD + immutable id + health fields"

# Seed draft from profile (local dual-role file)
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
"$CTL" add service --profile office-ssh --id sshdesk --name DeskSSH >"$WORKDIR/add.out"
grep -qi 'Pending service sshdesk' "$WORKDIR/add.out" || fail "add service from profile"
python3 - <<'PY' || fail "draft payload from profile"
import json, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
draft = json.loads((root / "var/lib/frp-auto-deploy/client-draft.json").read_text())
svc = draft["services"]["sshdesk"]
assert svc["preset"] == "ssh"
assert svc["local_ip"] == "127.0.0.1"
assert int(svc["local_port"]) == 2222  # edited profile defaults
assert svc["ssh_user"] == "ubuntu"
assert "remote_port" not in svc
print("ok")
PY

# Capture service snapshot, edit profile, ensure draft service unchanged unless re-added
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
draft = json.loads((root / "var/lib/frp-auto-deploy/client-draft.json").read_text())
(root / "snapshot-svc.json").write_text(json.dumps(draft["services"]["sshdesk"], sort_keys=True))
PY
"$CTL" set profile office-ssh target-host 10.0.0.9 >/dev/null
python3 - <<'PY' || fail "profile edit mutated existing draft service"
import json, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
draft = json.loads((root / "var/lib/frp-auto-deploy/client-draft.json").read_text())
before = json.loads((root / "snapshot-svc.json").read_text())
assert draft["services"]["sshdesk"] == before
print("ok")
PY

# New service gets new defaults
"$CTL" add service --profile office-ssh --id sshnew --name NewSSH >"$WORKDIR/add2.out"
python3 - <<'PY' || fail "new service should use updated profile defaults"
import json, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
draft = json.loads((root / "var/lib/frp-auto-deploy/client-draft.json").read_text())
assert draft["services"]["sshdesk"]["local_ip"] == "127.0.0.1"
assert draft["services"]["sshnew"]["local_ip"] == "10.0.0.9"
assert int(draft["services"]["sshnew"]["local_port"]) == 2222
print("ok")
PY

# Delete profile leaves services
"$CTL" delete profile office-ssh >"$WORKDIR/del.out"
grep -qi 'Existing services were not changed' "$WORKDIR/del.out" || fail "delete disclaimer"
python3 - <<'PY' || fail "delete profile removed draft services"
import json, os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
draft = json.loads((root / "var/lib/frp-auto-deploy/client-draft.json").read_text())
assert "sshdesk" in draft["services"] and "sshnew" in draft["services"]
profiles = json.loads((root / "var/lib/frp-auto-deploy/service-profiles.json").read_text())
assert "office-ssh" not in [p.get("name") for p in profiles["profiles"].values()]
print("ok")
PY
pass "profile apply/edit/delete isolation"

# Audit events
python3 - <<'PY' || fail "audit events missing"
import os
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
log = root / "var/log/frp-auto-deploy/audit.jsonl"
text = log.read_text(encoding="utf-8") if log.is_file() else ""
for event in ("profile.created", "profile.updated", "profile.deleted", "profile.applied_to_draft"):
    assert event in text, event
print("ok")
PY
pass "profile audit events"

# Backup must fail when service-profiles.json is missing (no silent recreate).
python3 - <<'PY' || fail "backup missing profiles fails"
import os, sys, types
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
profiles = root / "var/lib/frp-auto-deploy/service-profiles.json"
profiles.unlink()
path = Path(os.environ["FRP_SOURCE_ROOT"]) / "tools/frp-backup"
mod = types.ModuleType("frp_backup")
exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), mod.__dict__)
failed = False
try:
    mod.collect_files(root)
except SystemExit:
    failed = True
assert failed, "backup should fail without service-profiles.json"
assert not profiles.exists(), "backup must not recreate missing profiles"
print("ok")
PY
pass "backup missing profiles fails closed"


# Doctor check for missing/invalid profiles
python3 - <<'PY' || fail "doctor profiles check"
import importlib.util, json, os
from pathlib import Path
root = Path(os.environ["FRP_SOURCE_ROOT"])
spec = importlib.util.spec_from_file_location("frp_doctor", str(root / "lib/frp_doctor.py"))
doc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doc)
tree = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
paths = doc.Paths(str(tree))
cfg = json.loads((tree / "etc/frp-auto-deploy/config.json").read_text())
# Restore a valid empty store after the missing-profiles backup check.
profiles = tree / "var/lib/frp-auto-deploy/service-profiles.json"
profiles.write_text('{"schema_version":1,"profiles":{}}\n', encoding="utf-8")
report = doc.Report()
doc.check_service_profiles(report, paths, {}, cfg)
assert any(c["status"] == doc.PASS and "readable and valid" in c["message"] for c in report.checks), report.checks
# missing
profiles.unlink()
report2 = doc.Report()
doc.check_service_profiles(report2, paths, {}, cfg)
assert any(c["status"] == doc.FAIL and "missing" in c["message"] for c in report2.checks), report2.checks
print("ok")
PY
pass "doctor service profiles check"

echo "ALL SERVICE PROFILE TESTS PASSED"
