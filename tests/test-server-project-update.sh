#!/usr/bin/env bash
set -euo pipefail

# Ignore leaked roots from prior debug sessions; they divert txn markers.
unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TREE_CHANNEL="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/release-manifest.json"))["channel"])')"
TREE_REF="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/release-manifest.json"))["git_ref"])')"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
# shellcheck disable=SC1091
. "$ROOT/tests/lib/frp-test-procs.sh"
# shellcheck disable=SC1091
. "$ROOT/tests/lib/frp-test-safe-copy.sh"
UPDATE="$ROOT/tools/frp-project-update"
WORKDIR="$(mktemp -d /tmp/frp-test-server-project-update.XXXXXX)"
frp_test_arm_cleanup
cat >"$WORKDIR/nginx" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod 0755 "$WORKDIR/nginx"
export FRP_NGINX_BIN="$WORKDIR/nginx"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

setup_tree() {
  local tree="$1"
  rm -rf "$tree"
  mkdir -p \
    "$tree/etc/drlink/pki" "$tree/etc/frp" \
    "$tree/var/lib/drlink/enrollments/client-a" \
    "$tree/var/lib/drlink/bootstrap/client-a" \
    "$tree/usr/local/bin" "$tree/usr/local/lib/drlink" \
    "$tree/usr/local/sbin" "$tree/etc/systemd/system"
  cat >"$tree/usr/local/bin/frps" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "--version" ]] && echo "0.71.0"
exit 0
EOF
  chmod 0755 "$tree/usr/local/bin/frps"
  printf 'server-token-preserve\n' >"$tree/etc/frp/server_token"
  printf 'ca-preserve\n' >"$tree/etc/drlink/pki/ca.crt"
  printf 'ca-key-preserve\n' >"$tree/etc/drlink/pki/ca.key"
  printf 'server-cert-preserve\n' >"$tree/etc/drlink/pki/server.crt"
  printf 'server-key-preserve\n' >"$tree/etc/drlink/pki/server.key"
  printf 'enrollment-preserve\n' >"$tree/var/lib/drlink/enrollments/client-a/state"
  printf 'bootstrap-preserve\n' >"$tree/var/lib/drlink/bootstrap/client-a/state"
  cat >"$tree/etc/frp/frps.toml" <<'EOF'
bindPort = 7000
auth.tokenSource.file.path = "/etc/frp/server_token"
allowPorts = [{ start = 6000, end = 6098 }]
EOF
  cat >"$tree/etc/drlink/config.json" <<'EOF'
{
  "public_host": "server.example",
  "deployment_mode": "single443",
  "frp_control_public_port": 443,
  "frp_control_listen_port": 7000,
  "allocator_public_port": 443,
  "allocator_listen_port": 6099,
  "allocator_public_url": "https://server.example/enroll",
  "port_start": 6000,
  "port_end": 6098,
  "client_installer_url": "https://updates.example/client.sh",
  "egress_control_file": "/var/lib/drlink/egress-control.json",
  "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
  "egress_listen_addr": "0.0.0.0",
  "egress_listen_port": 6102
}
EOF
  printf 'events {}\nhttp {\n  server {\n    listen 443 ssl;\n  }\n}\n' \
    >"$tree/etc/drlink/frontend.conf"
  cat >"$tree/var/lib/drlink/registry.json" <<'EOF'
{
  "schema_version": 2,
  "reserved": [6000, 6001],
  "clients": {
    "machine-a": {
      "hostname": "host-a",
      "labels": ["production", "database"],
      "notes": "must survive update",
      "services": {
        "ssh": {"local_port": 22, "remote_port": 6002, "enabled": true}
      }
    }
  }
}
EOF
  printf '{"schema_version":1,"access_lists":{},"service_access":{}}\n' \
    >"$tree/var/lib/drlink/access-control.json"
  printf '{"schema_version":1,"profiles":{}}\n' \
    >"$tree/var/lib/drlink/service-profiles.json"
  # Current-product fixtures already have Controlled Egress state so project
  # update preserves config.json. Pre-egress bootstrap is covered separately.
  python3 - "$tree/var/lib/drlink/egress-control.json" "$ROOT/lib/frp_egress_control.py" <<'PY'
import importlib.util, sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("frp_egress_control", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.save_egress_state(mod.empty_egress_state(), path=path)
PY
  cat >"$tree/etc/drlink/version" <<'EOF'
PROJECT_VERSION=2.0.0
FRP_VERSION=0.71.0
RELEASE_CHANNEL=stable
SOURCE_REF=v2.1.1
BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  printf 'old allocator\n' >"$tree/usr/local/lib/drlink/frp-port-allocator.py"
  printf 'old unit\n' >"$tree/etc/systemd/system/drlink-allocator.service"
  cp "$ROOT/server/drlink-frontend.service" "$tree/etc/systemd/system/drlink-frontend.service"
  chmod 600 "$tree/etc/frp/server_token" "$tree/var/lib/drlink/registry.json" \
    "$tree/var/lib/drlink/access-control.json" \
    "$tree/var/lib/drlink/service-profiles.json" \
    "$tree/var/lib/drlink/egress-control.json"
  chmod 600 "$tree/etc/drlink/pki/"*
}

state_digest() {
  local tree="$1"
  python3 - "$tree" <<'PY'
import hashlib, sys
from pathlib import Path
root = Path(sys.argv[1])
paths = [
    "usr/local/bin/frps", "etc/frp/frps.toml", "etc/frp/server_token",
    "etc/drlink/config.json", "etc/drlink/pki",
    "var/lib/drlink/registry.json",
    "var/lib/drlink/access-control.json",
    "var/lib/drlink/enrollments",
    "var/lib/drlink/bootstrap",
]
h = hashlib.sha256()
for rel in paths:
    p = root / rel
    if p.is_dir():
        for child in sorted(x for x in p.rglob("*") if x.is_file()):
            h.update(str(child.relative_to(root)).encode() + b"\0" + child.read_bytes())
    else:
        h.update(rel.encode() + b"\0" + p.read_bytes())
print(h.hexdigest())
PY
}

run_local() {
  local tree="$1"
  shift
  # Working-tree source channel/ref follow release-manifest.json.
  env FRP_SERVER_TEST_ROOT="$tree" FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
    "$UPDATE" --source "$ROOT" "$@"
}

# Check-only validates and reports without changing installed state or backups.
CHECK="$WORKDIR/check"
setup_tree "$CHECK"
CHECK_BEFORE="$(state_digest "$CHECK")"
VERSION_BEFORE="$(sha "$CHECK/etc/drlink/version")"
run_local "$CHECK" --check >"$WORKDIR/check.out"
grep -q 'State mutation             : NO' "$WORKDIR/check.out" || fail "check-only report"
[[ "$(state_digest "$CHECK")" == "$CHECK_BEFORE" ]] || fail "check-only changed protected state"
[[ "$(sha "$CHECK/etc/drlink/version")" == "$VERSION_BEFORE" ]] || fail "check-only changed version"
[[ ! -d "$CHECK/var/lib/drlink/backups" ]] || fail "check-only created backup"
pass "CHECK_ONLY_NO_MUTATION"

# Successful local update installs management files and preserves all server state.
OK="$WORKDIR/ok"
setup_tree "$OK"
OK_BEFORE="$(state_digest "$OK")"
run_local "$OK" >"$WORKDIR/ok.out"
grep -q 'Server project update completed successfully' "$WORKDIR/ok.out" || fail "success report"
grep -q 'FRP binary      : unchanged' "$WORKDIR/ok.out" || fail "FRP unchanged report"
grep -q 'Client re-enroll: NOT REQUIRED' "$WORKDIR/ok.out" || fail "re-enrollment report"
[[ "$(state_digest "$OK")" == "$OK_BEFORE" ]] || fail "server state changed"
cmp "$ROOT/tools/frp-project-update" "$OK/usr/local/lib/drlink/frp-project-update" >/dev/null ||
  fail "project updater not installed"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$OK/etc/drlink/version" ||
  fail "project version not updated"
grep -q 'FRP_VERSION=0.71.0' "$OK/etc/drlink/version" || fail "FRP metadata changed"
pass "STATE_REGISTRY_TOKEN_CA_PRESERVED"
pass "NO_CLIENT_REENROLLMENT"

# Pre-egress installs must bootstrap Controlled Egress without losing identity state.
PRE_EGRESS="$WORKDIR/pre-egress"
setup_tree "$PRE_EGRESS"
python3 - "$PRE_EGRESS/etc/drlink/config.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
cfg = json.loads(p.read_text(encoding="utf-8"))
for key in (
    "egress_control_file",
    "egress_conn_log_file",
    "egress_listen_addr",
    "egress_listen_port",
):
    cfg.pop(key, None)
p.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
rm -f "$PRE_EGRESS/var/lib/drlink/egress-control.json"
PRE_REG_BEFORE="$(sha "$PRE_EGRESS/var/lib/drlink/registry.json")"
PRE_TOKEN_BEFORE="$(sha "$PRE_EGRESS/etc/frp/server_token")"
PRE_CA_BEFORE="$(sha "$PRE_EGRESS/etc/drlink/pki/ca.crt")"
run_local "$PRE_EGRESS" >"$WORKDIR/pre-egress.out"
grep -q 'Server project update completed successfully' "$WORKDIR/pre-egress.out" ||
  fail "pre-egress success report"
[[ -f "$PRE_EGRESS/var/lib/drlink/egress-control.json" ]] ||
  fail "pre-egress did not create egress-control.json"
python3 - "$PRE_EGRESS/etc/drlink/config.json" <<'PY'
import json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = {
    "egress_control_file": "/var/lib/drlink/egress-control.json",
    "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
    "egress_listen_addr": "0.0.0.0",
    "egress_listen_port": 6102,
}
for key, value in required.items():
    if cfg.get(key) != value:
        raise SystemExit(f"missing or wrong {key}: {cfg.get(key)!r}")
if cfg.get("public_host") != "server.example":
    raise SystemExit("public_host changed")
PY
[[ "$(sha "$PRE_EGRESS/var/lib/drlink/registry.json")" == "$PRE_REG_BEFORE" ]] ||
  fail "pre-egress changed registry"
[[ "$(sha "$PRE_EGRESS/etc/frp/server_token")" == "$PRE_TOKEN_BEFORE" ]] ||
  fail "pre-egress changed token"
[[ "$(sha "$PRE_EGRESS/etc/drlink/pki/ca.crt")" == "$PRE_CA_BEFORE" ]] ||
  fail "pre-egress changed CA"
pass "PRE_EGRESS_BOOTSTRAPS_CONTROLLED_EGRESS"

# A Direct deployment must not gain or start the single-443 frontend unit.
DIRECT="$WORKDIR/direct"
setup_tree "$DIRECT"
python3 - "$DIRECT/etc/drlink/config.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["deployment_mode"] = "direct"
d["frp_control_listen_port"] = 443
d["allocator_public_port"] = 6099
d["allocator_public_url"] = "https://server.example:6099/enroll"
p.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n")
PY
rm -f "$DIRECT/etc/systemd/system/drlink-frontend.service" \
  "$DIRECT/etc/drlink/frontend.conf"
run_local "$DIRECT" >"$WORKDIR/direct.out"
[[ ! -f "$DIRECT/etc/systemd/system/drlink-frontend.service" ]] ||
  fail "direct mode gained frontend unit"
grep -q '"deployment_mode": "direct"' "$DIRECT/etc/drlink/config.json" ||
  fail "direct mode changed"
pass "DEPLOYMENT_MODE_PRESERVED"

# Failure injection must restore every replaceable file and leave protected state intact.
for phase in validate install verify; do
  tree="$WORKDIR/rollback-$phase"
  setup_tree "$tree"
  cp "$tree/usr/local/lib/drlink/frp-port-allocator.py" "$WORKDIR/$phase.before"
  before="$(state_digest "$tree")"
  if env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$tree" FRP_SERVER_UPGRADE_HOOK_FAIL="$phase" \
    "$UPDATE" --source "$ROOT" >"$WORKDIR/$phase.out" 2>"$WORKDIR/$phase.err"; then
    fail "$phase failure should fail"
  fi
  if [[ "$phase" == "validate" ]]; then
    grep -q 'UPGRADE_ROLLBACK=NOT_REQUIRED' "$WORKDIR/$phase.out" ||
      fail "$phase rollback marker"
  else
    grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/$phase.out" ||
      fail "$phase rollback marker"
  fi
  cmp "$WORKDIR/$phase.before" "$tree/usr/local/lib/drlink/frp-port-allocator.py" >/dev/null ||
    fail "$phase did not restore project file"
  [[ "$(state_digest "$tree")" == "$before" ]] || fail "$phase changed protected state"
done
pass "ROLLBACK_VALIDATE_INSTALL_VERIFY"

# Local metadata must be present and internally consistent.
BADMETA="$WORKDIR/badmeta"
frp_test_copy_repo_tree "$ROOT" "$BADMETA"
python3 - "$BADMETA/release-manifest.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["project_version"] = "9.9.9"
p.write_text(json.dumps(d) + "\n")
PY
META_TREE="$WORKDIR/meta-tree"
setup_tree "$META_TREE"
# Force a clean role/root env: prior cases or harness exports must not divert
# version-state lookup away from META_TREE (FRP_DEPLOY_TEST_ROOT wins over
# FRP_SERVER_TEST_ROOT in frp_version_state_file).
if env -u FRP_DEPLOY_TEST_ROOT -u FRP_CLIENT_TEST_ROOT -u FRP_CTL_TEST_ROOT \
  -u FRP_UPDATE_ROOT -u FRP_RELEASE_CHANNEL \
  FRP_SERVER_TEST_ROOT="$META_TREE" "$UPDATE" --source "$BADMETA" \
  >"$WORKDIR/meta.out" 2>"$WORKDIR/meta.err"; then
  fail "wrong metadata should fail"
fi
grep -qi 'metadata project version mismatch' "$WORKDIR/meta.err" || fail "wrong metadata message"
rm -f "$BADMETA/release-manifest.json"
if env -u FRP_DEPLOY_TEST_ROOT -u FRP_CLIENT_TEST_ROOT -u FRP_CTL_TEST_ROOT \
  -u FRP_UPDATE_ROOT -u FRP_RELEASE_CHANNEL \
  FRP_SERVER_TEST_ROOT="$META_TREE" "$UPDATE" --source "$BADMETA" \
  >"$WORKDIR/missing.out" 2>"$WORKDIR/missing.err"; then
  fail "missing metadata should fail"
fi
grep -Eqi 'missing (or invalid )?.*release-manifest|missing project file: .*release-manifest' "$WORKDIR/missing.err" ||
  fail "missing metadata message"
pass "METADATA_REQUIRED"

# Simulated HTTPS remote fetch. The curl mock serves immutable local fixtures.
FIX="$WORKDIR/fixture"
MOCKBIN="$WORKDIR/mockbin"
mkdir -p "$FIX" "$MOCKBIN"
cp "$ROOT/dist/bootstrap-server.sh" "$FIX/bootstrap-server.sh"
printf '%s  dist/bootstrap-server.sh\n' "$(sha "$FIX/bootstrap-server.sh")" >"$FIX/SHA256SUMS"
cat >"$MOCKBIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://fixture.invalid/SHA256SUMS) cp "$FRP_TEST_FIXTURE/SHA256SUMS" "$out" ;;
  https://fixture.invalid/bootstrap-server.sh) cp "$FRP_TEST_FIXTURE/bootstrap-server.sh" "$out" ;;
  *) echo "unexpected mock URL: $url" >&2; exit 22 ;;
esac
EOF
chmod 0755 "$MOCKBIN/curl"

REMOTE="$WORKDIR/remote"
setup_tree "$REMOTE"
REMOTE_BEFORE="$(state_digest "$REMOTE")"
env PATH="$MOCKBIN:$PATH" FRP_TEST_FIXTURE="$FIX" FRP_SERVER_TEST_ROOT="$REMOTE" \
  FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
  FRP_SERVER_PROJECT_SHA256SUMS_URL=https://fixture.invalid/SHA256SUMS \
  FRP_SERVER_PROJECT_UPDATE_URL=https://fixture.invalid/bootstrap-server.sh \
  "$UPDATE" >"$WORKDIR/remote.out"
[[ "$(state_digest "$REMOTE")" == "$REMOTE_BEFORE" ]] || fail "remote update changed state"
grep -q 'Server project update completed successfully' "$WORKDIR/remote.out" ||
  fail "remote simulated HTTPS update"
pass "REMOTE_SIMULATED_HTTPS_SHA256"

# Tamper, HTTP, and missing checksum metadata are rejected before execution.
printf '\n# tampered\n' >>"$FIX/bootstrap-server.sh"
TAMPER="$WORKDIR/tamper"
setup_tree "$TAMPER"
if env PATH="$MOCKBIN:$PATH" FRP_TEST_FIXTURE="$FIX" FRP_SERVER_TEST_ROOT="$TAMPER" \
  FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
  FRP_SERVER_PROJECT_SHA256SUMS_URL=https://fixture.invalid/SHA256SUMS \
  FRP_SERVER_PROJECT_UPDATE_URL=https://fixture.invalid/bootstrap-server.sh \
  "$UPDATE" >"$WORKDIR/tamper.out" 2>"$WORKDIR/tamper.err"; then
  fail "tampered bundle should fail"
fi
grep -qi 'SHA256' "$WORKDIR/tamper.err" || fail "tamper SHA message"
pass "TAMPER_REJECTED"

HTTP="$WORKDIR/http"
setup_tree "$HTTP"
if env FRP_SERVER_TEST_ROOT="$HTTP" \
  FRP_SERVER_PROJECT_SHA256SUMS_URL=http://fixture.invalid/SHA256SUMS \
  FRP_SERVER_PROJECT_UPDATE_URL=https://fixture.invalid/bootstrap-server.sh \
  "$UPDATE" >"$WORKDIR/http.out" 2>"$WORKDIR/http.err"; then
  fail "HTTP URL should fail"
fi
grep -qi 'HTTPS' "$WORKDIR/http.err" || fail "HTTP rejection message"
pass "HTTP_REJECTED"

printf '%s  dist/other.sh\n' "$(printf other | sha256sum | awk '{print $1}')" >"$FIX/SHA256SUMS"
MISSING="$WORKDIR/missing-sha"
setup_tree "$MISSING"
if env PATH="$MOCKBIN:$PATH" FRP_TEST_FIXTURE="$FIX" FRP_SERVER_TEST_ROOT="$MISSING" \
  FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
  FRP_SERVER_PROJECT_SHA256SUMS_URL=https://fixture.invalid/SHA256SUMS \
  FRP_SERVER_PROJECT_UPDATE_URL=https://fixture.invalid/bootstrap-server.sh \
  "$UPDATE" >"$WORKDIR/missing-sha.out" 2>"$WORKDIR/missing-sha.err"; then
  fail "missing SHA metadata should fail"
fi
grep -qi 'missing valid metadata' "$WORKDIR/missing-sha.err" ||
  fail "missing SHA metadata message"
pass "MISSING_SHA_METADATA_REJECTED"

# Persisted runtime loader works without installer globals (minimal env).
MINENV="$WORKDIR/minenv"
setup_tree "$MINENV"
MINENV_OUT="$WORKDIR/minenv.out"
if ! env -i \
  PATH="$PATH" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" \
  FRP_SERVER_TEST_ROOT="$MINENV" \
  FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
  "$UPDATE" --source "$ROOT" --check >"$MINENV_OUT" 2>"$WORKDIR/minenv.err"; then
  fail "minimal-env --check"
fi
grep -q 'State mutation             : NO' "$MINENV_OUT" || fail "minimal-env check report"
if grep -q 'unbound variable' "$WORKDIR/minenv.err"; then
  fail "minimal-env unbound"
fi
pass "MINIMAL_ENV_PROJECT_UPDATE"
pass "PERSISTED_RUNTIME_CONFIG_LOADER"
pass "SINGLE443_PROJECT_UPDATE"

# Loader unit check: config.json supplies public_host without FRP_PUBLIC_HOST.
python3 - "$ROOT" "$MINENV" <<'PY'
import os, subprocess, sys, tempfile
from pathlib import Path
root, tree = Path(sys.argv[1]), Path(sys.argv[2])
script = r'''
set -euo pipefail
BASE_DIR="%s"
FRP_SERVER_SOURCED=1
. "$BASE_DIR/install-server.sh"
unset FRP_PUBLIC_HOST FRP_CONTROL_PUBLIC_PORT CA_FINGERPRINT || true
frp_load_installed_server_runtime
[[ -n "${FRP_PUBLIC_HOST}" ]]
[[ "${FRP_PUBLIC_HOST}" == "server.example" ]]
[[ "${FRP_CONTROL_PUBLIC_PORT}" == "443" ]]
[[ "${FRP_DEPLOYMENT_MODE}" == "single443" ]]
[[ -n "${FRP_ALLOCATOR_LISTEN_PORT}" ]]
echo LOADER_OK
''' % root
env = os.environ.copy()
env["FRP_SERVER_TEST_ROOT"] = str(tree)
env["FRP_SERVER_SOURCED"] = "1"
proc = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
if proc.returncode != 0 or "LOADER_OK" not in proc.stdout:
    sys.stderr.write(proc.stdout + proc.stderr)
    raise SystemExit("loader failed")
PY
pass "PERSISTED_RUNTIME_CONFIG_LOADER_VALUES"

# Unexpected post-mutation abort must roll back and clear the marker only after verify.
UNBOUND="$WORKDIR/unbound"
setup_tree "$UNBOUND"
if env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$UNBOUND" FRP_SERVER_UPGRADE_HOOK_FAIL=unbound-after-install \
  "$UPDATE" --source "$ROOT" >"$WORKDIR/unbound.out" 2>"$WORKDIR/unbound.err"; then
  fail "unbound-after-install should fail"
fi
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/unbound.out" "$WORKDIR/unbound.err" || fail "unbound rollback"
grep -q 'LIVE_PROJECT_FILES_RESTORED=YES' "$WORKDIR/unbound.out" "$WORKDIR/unbound.err" || fail "unbound files restored"
grep -q 'PENDING_MARKER_CLEARED=YES' "$WORKDIR/unbound.out" "$WORKDIR/unbound.err" || fail "unbound marker cleared"
[[ ! -f "$UNBOUND/var/lib/drlink/server-update-pending.json" ]] || fail "unbound left pending marker"
cmp "$UNBOUND/usr/local/lib/drlink/frp-port-allocator.py" \
  <(printf 'old allocator\n') >/dev/null || fail "unbound did not restore first replaced file"
pass "UNEXPECTED_POST_MUTATION_ABORT"
pass "ROLLBACK_FILE_RESTORE"

# Rollback systemd/health failures must not print a false PASS or clear the marker.
HEALTHFAIL="$WORKDIR/healthfail"
setup_tree "$HEALTHFAIL"
if env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$HEALTHFAIL" FRP_SERVER_UPGRADE_HOOK_FAIL=install \
  FRP_SERVER_UPGRADE_HOOK_ROLLBACK_HEALTH=1 \
  "$UPDATE" --source "$ROOT" >"$WORKDIR/healthfail.out" 2>"$WORKDIR/healthfail.err"; then
  fail "rollback-health should fail the update"
fi
grep -q 'UPGRADE_ROLLBACK=FAIL' "$WORKDIR/healthfail.out" "$WORKDIR/healthfail.err" || fail "health rollback fail marker"
grep -q 'RECOVERY_REQUIRED=YES' "$WORKDIR/healthfail.out" "$WORKDIR/healthfail.err" || fail "health recovery required"
grep -q 'PENDING_MARKER_CLEARED=NO' "$WORKDIR/healthfail.out" "$WORKDIR/healthfail.err" || fail "health pending preserved"
[[ -f "$HEALTHFAIL/var/lib/drlink/server-update-pending.json" ]] || fail "health pending missing"
if grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/healthfail.out" "$WORKDIR/healthfail.err"; then
  fail "false rollback PASS"
fi
pass "ROLLBACK_HEALTH_FAILURE"
pass "ROLLBACK_FAILURE_PRESERVES_PENDING_MARKER"
pass "NO_FALSE_ROLLBACK_PASS"

SYSROLL="$WORKDIR/sysroll"
setup_tree "$SYSROLL"
if env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$SYSROLL" FRP_SERVER_UPGRADE_HOOK_FAIL=install \
  FRP_SERVER_UPGRADE_HOOK_ROLLBACK_SYSTEMD=1 \
  "$UPDATE" --source "$ROOT" >"$WORKDIR/sysroll.out" 2>"$WORKDIR/sysroll.err"; then
  fail "rollback-systemd should fail"
fi
grep -q 'UPGRADE_ROLLBACK=FAIL' "$WORKDIR/sysroll.out" "$WORKDIR/sysroll.err" || fail "systemd rollback fail"
[[ -f "$SYSROLL/var/lib/drlink/server-update-pending.json" ]] || fail "systemd pending missing"
pass "ROLLBACK_SYSTEMD_FAILURE"

# Transaction schema v2 records snapshot + release identity.
TXN="$WORKDIR/txn"
setup_tree "$TXN"
if env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$TXN" FRP_SERVER_UPGRADE_HOOK_FAIL=install \
  FRP_SERVER_UPGRADE_HOOK_ROLLBACK_HEALTH=1 \
  "$UPDATE" --source "$ROOT" >"$WORKDIR/txn.out" 2>"$WORKDIR/txn.err"; then
  fail "txn fixture should fail after writing marker"
fi
python3 - "$TXN/var/lib/drlink/server-update-pending.json" "$TREE_CHANNEL" "$TREE_REF" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
assert data.get("schema_version") == 2
assert data.get("operation") == "project-update"
# Working-tree source channel/ref come from release-manifest.json.
assert data.get("release_channel") == sys.argv[2], data.get("release_channel")
assert data.get("source_ref") == sys.argv[3], data.get("source_ref")
assert data.get("snapshot_path")
assert data.get("mutation_started") is True
assert Path(data["snapshot_path"]).is_dir()
print("TXN_OK")
PY
pass "TRANSACTION_SCHEMA_V2"
pass "TRANSACTION_SNAPSHOT_REFERENCE"
pass "TRANSACTION_RELEASE_IDENTITY"

# Schema-1 pending remains readable; unknown identity must not fetch stable.
SCHEMA1="$WORKDIR/schema1"
setup_tree "$SCHEMA1"
printf '{"operation":"project-update","phase":"commit","previous_version":"2.1.0","candidate_version":"2.1.0"}\n' \
  >"$SCHEMA1/var/lib/drlink/update-pending.json"
# Keep persisted channel so --source can recover after schema-1 compat.
if env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$SCHEMA1" "$UPDATE" --source "$ROOT" --check \
  >"$WORKDIR/schema1.out" 2>"$WORKDIR/schema1.err"; then
  :
else
  fail "schema1 pending + known persisted channel should still --check"
fi
pass "SCHEMA1_PENDING_COMPAT"

UNKNOWN="$WORKDIR/unknown"
setup_tree "$UNKNOWN"
printf 'PROJECT_VERSION=2.1.0\nFRP_VERSION=0.71.0\n' >"$UNKNOWN/etc/drlink/version"
rm -f "$UNKNOWN/var/lib/drlink/update-pending.json"
if env -u FRP_RELEASE_CHANNEL FRP_SERVER_TEST_ROOT="$UNKNOWN" \
  "$UPDATE" --source "$ROOT" --check >"$WORKDIR/unknown.out" 2>"$WORKDIR/unknown.err"; then
  fail "unknown channel should refuse"
fi
grep -qi 'unknown' "$WORKDIR/unknown.err" || grep -qi 'FRP_RELEASE_CHANNEL' "$WORKDIR/unknown.err" ||
  fail "unknown channel message"
if grep -qi 'stable' "$WORKDIR/unknown.out"; then
  fail "unknown silently selected stable"
fi
pass "UNKNOWN_CHANNEL_NO_SILENT_STABLE_FALLBACK"

PENDDEV="$WORKDIR/penddev"
setup_tree "$PENDDEV"
printf 'PROJECT_VERSION=2.1.0\nFRP_VERSION=0.71.0\n' >"$PENDDEV/etc/drlink/version"
printf '{"schema_version":2,"operation":"project-update","phase":"commit","release_channel":"dev","source_ref":"main","previous_version":"2.1.0","candidate_version":"2.1.3"}\n' \
  >"$PENDDEV/var/lib/drlink/update-pending.json"
# Pending channel=dev requires a matching --source tree even when the RC working tree is stable.
PEND_SRC="$ROOT"
if [[ "$TREE_CHANNEL" != "dev" ]]; then
  PEND_SRC="$WORKDIR/pend-dev-src"
  frp_test_copy_repo_tree "$ROOT" "$PEND_SRC"
  python3 - "$PEND_SRC/release-manifest.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["channel"] = "dev"
d["git_ref"] = "main"
p.write_text(json.dumps(d, indent=2) + "\n")
PY
fi
env -u FRP_RELEASE_CHANNEL FRP_SERVER_TEST_ROOT="$PENDDEV" \
  "$UPDATE" --source "$PEND_SRC" --check >"$WORKDIR/penddev.out" 2>"$WORKDIR/penddev.err" ||
  fail "pending dev --check"
grep -q 'Resolved release channel : dev' "$WORKDIR/penddev.out" || fail "pending stayed on dev"
pass "PENDING_DEV_RETRY_STAYS_DEV"

# Real OCI partial-state fixture: unknown version metadata + schema-1 pending + mixed files.
OCI="$WORKDIR/oci"
setup_tree "$OCI"
printf 'PROJECT_VERSION=2.1.0\nFRP_VERSION=0.71.0\n' >"$OCI/etc/drlink/version"
python3 - "$OCI/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["clients"] = {
  "machine-aella": {
    "hostname": "aella",
    "label": "aella",
    "notes": "oci",
    "tags": {"site": "oci"},
    "services": {"ssh": {"local_port": 22, "remote_port": 6000, "enabled": True, "ssh_user": "aella"}},
  }
}
d["reserved"] = [6000]
p.write_text(json.dumps(d, indent=2) + "\n")
PY
printf '{"operation":"project-update","phase":"commit","previous_version":"2.1.0","candidate_version":"2.1.0"}\n' \
  >"$OCI/var/lib/drlink/update-pending.json"
cp "$ROOT/tools/frpctl" "$OCI/usr/local/sbin/frpctl"
printf 'partial-old\n' >"$OCI/usr/local/lib/drlink/frp-backup"
TOKEN_SHA="$(sha "$OCI/etc/frp/server_token")"
REG_SHA="$(sha "$OCI/var/lib/drlink/registry.json")"
CA_SHA="$(sha "$OCI/etc/drlink/pki/ca.crt")"
if env -u FRP_RELEASE_CHANNEL FRP_SERVER_TEST_ROOT="$OCI" \
  "$UPDATE" --source "$ROOT" --check >"$WORKDIR/oci-check.out" 2>"$WORKDIR/oci-check.err"; then
  fail "OCI unknown+pending schema1 --check must fail closed"
fi
pass "REAL_OCI_PARTIAL_STATE_FIXTURE"

env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$OCI" \
  "$UPDATE" --source "$ROOT" >"$WORKDIR/oci.out" 2>"$WORKDIR/oci.err" || fail "OCI recovery"
grep -q 'Server project update completed successfully' "$WORKDIR/oci.out" || fail "OCI success"
[[ ! -f "$OCI/var/lib/drlink/update-pending.json" ]] || fail "OCI pending remains"
grep -q "RELEASE_CHANNEL=${TREE_CHANNEL}" "$OCI/etc/drlink/version" || fail "OCI channel"
grep -q "SOURCE_REF=${TREE_REF}" "$OCI/etc/drlink/version" || fail "OCI source ref"
cmp "$ROOT/tools/frp-backup" "$OCI/usr/local/lib/drlink/frp-backup" >/dev/null || fail "OCI backup tool not reconciled"
[[ "$(sha "$OCI/etc/frp/server_token")" == "$TOKEN_SHA" ]] || fail "OCI token changed"
[[ "$(sha "$OCI/var/lib/drlink/registry.json")" == "$REG_SHA" ]] || fail "OCI registry changed"
[[ "$(sha "$OCI/etc/drlink/pki/ca.crt")" == "$CA_SHA" ]] || fail "OCI CA changed"
python3 - "$OCI/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
d = json.loads(Path(sys.argv[1]).read_text())
c = d["clients"]["machine-aella"]
assert c["label"] == "aella"
assert c["notes"] == "oci"
assert c["tags"]["site"] == "oci"
assert c["services"]["ssh"]["remote_port"] == 6000
assert c["hostname"] == "aella"
PY
pass "PARTIAL_STATE_RECOVERY"

# --check with pending must stay read-only.
PENDCHECK="$WORKDIR/pendcheck"
setup_tree "$PENDCHECK"
printf '{"schema_version":2,"operation":"project-update","phase":"commit","release_channel":"stable","source_ref":"v2.1.1"}\n' \
  >"$PENDCHECK/var/lib/drlink/server-update-pending.json"
BEFORE_PEND="$(state_digest "$PENDCHECK")"
BEFORE_MARK="$(sha "$PENDCHECK/var/lib/drlink/server-update-pending.json")"
env FRP_RELEASE_CHANNEL="$TREE_CHANNEL" FRP_SERVER_TEST_ROOT="$PENDCHECK" "$UPDATE" --source "$ROOT" --check \
  >"$WORKDIR/pendcheck.out" || fail "pending --check"
[[ "$(state_digest "$PENDCHECK")" == "$BEFORE_PEND" ]] || fail "pending --check mutated"
[[ "$(sha "$PENDCHECK/var/lib/drlink/server-update-pending.json")" == "$BEFORE_MARK" ]] ||
  fail "pending --check wrote marker"
pass "CHECK_ONLY_PENDING_READONLY"

# Same-version decisions use build identity, not PROJECT_VERSION alone.
. "$ROOT/VERSION"
OCI_INSTALLED_SHA=d0a33da2a9d1cb9832fc0f2892eb52dce31e87fdd63803d3a01c8013b1355ff9
OCI_CANDIDATE_SHA=1f67f3b0b96de60b78ff2434abbf2463f5bf222e47a4ca8f791a9933cc8f98cc

write_identity() {
  local tree="$1" project="$2" channel="$3" ref="$4" sha="${5:-}"
  {
    printf 'PROJECT_VERSION=%s\n' "$project"
    printf 'FRP_VERSION=0.71.0\n'
    printf 'RELEASE_CHANNEL=%s\n' "$channel"
    printf 'SOURCE_REF=%s\n' "$ref"
    if [[ -n "$sha" ]]; then
      printf 'BUNDLE_SHA256=%s\n' "$sha"
    fi
  } >"$tree/etc/drlink/version"
}

run_verified() {
  local tree="$1"
  shift
  # Working-tree source is channel=dev; explicit expected channel must match.
  env FRP_SERVER_TEST_ROOT="$tree" FRP_BUNDLE_SHA256="$OCI_CANDIDATE_SHA" \
    FRP_AUDIT_LOG="$tree/var/log/drlink/audit.jsonl" \
    FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
    "$UPDATE" --source "$ROOT" "$@"
}

# Unknown persisted SHA at the same semantic version is never "not needed".
UNK="$WORKDIR/same-unknown"
setup_tree "$UNK"
write_identity "$UNK" "$PROJECT_VERSION" stable "v${PROJECT_VERSION}"
run_verified "$UNK" --check >"$WORKDIR/unk-check.out" || fail "unknown-build --check"
grep -q "Installed project version : ${PROJECT_VERSION}" "$WORKDIR/unk-check.out" || fail "unknown installed version"
grep -q "Target project version    : ${PROJECT_VERSION}" "$WORKDIR/unk-check.out" || fail "unknown target version"
grep -q 'Installed bundle SHA256   : unknown' "$WORKDIR/unk-check.out" || fail "unknown installed sha"
grep -q "Target bundle SHA256      : ${OCI_CANDIDATE_SHA}" "$WORKDIR/unk-check.out" || fail "unknown target sha"
grep -q 'Update                    : available' "$WORKDIR/unk-check.out" || fail "unknown should be available"
grep -q 'State mutation             : NO' "$WORKDIR/unk-check.out" || fail "unknown check mutation"
pass "SERVER_SAME_VERSION_UNKNOWN_BUILD"

# Same version, different verified SHA → available (OCI identity).
DIFF="$WORKDIR/same-diff"
setup_tree "$DIFF"
write_identity "$DIFF" "$PROJECT_VERSION" stable "v${PROJECT_VERSION}" "$OCI_INSTALLED_SHA"
DIFF_BEFORE="$(state_digest "$DIFF")"
DIFF_VER="$(sha "$DIFF/etc/drlink/version")"
FRP_BEFORE="$(sha "$DIFF/usr/local/bin/frps")"
run_verified "$DIFF" --check >"$WORKDIR/diff-check.out" || fail "different-build --check"
grep -q "Installed bundle SHA256   : ${OCI_INSTALLED_SHA}" "$WORKDIR/diff-check.out" || fail "oci installed sha"
grep -q "Target bundle SHA256      : ${OCI_CANDIDATE_SHA}" "$WORKDIR/diff-check.out" || fail "oci target sha"
grep -q "Installed release channel : stable" "$WORKDIR/diff-check.out" || fail "oci installed channel"
grep -q "Target release channel    : ${TREE_CHANNEL}" "$WORKDIR/diff-check.out" || fail "oci target channel"
grep -q "Installed source ref      : v${PROJECT_VERSION}" "$WORKDIR/diff-check.out" || fail "oci installed ref"
grep -q "Target source ref         : ${TREE_REF}" "$WORKDIR/diff-check.out" || fail "oci target ref"
grep -q 'Update                    : available' "$WORKDIR/diff-check.out" || fail "different build should be available"
grep -q 'State mutation             : NO' "$WORKDIR/diff-check.out" || fail "different-build check mutation"
[[ "$(state_digest "$DIFF")" == "$DIFF_BEFORE" ]] || fail "different-build --check mutated state"
[[ "$(sha "$DIFF/etc/drlink/version")" == "$DIFF_VER" ]] || fail "different-build --check mutated version"
[[ ! -d "$DIFF/var/lib/drlink/backups" ]] || fail "different-build --check created backup"
[[ "$(sha "$DIFF/usr/local/bin/frps")" == "$FRP_BEFORE" ]] || fail "check changed frps"
pass "SERVER_SAME_VERSION_DIFFERENT_BUILD"
pass "SERVER_CHECK_DIFFERENT_BUILD_AVAILABLE"
pass "SERVER_CHECK_READONLY"

# Same version, same verified SHA → not needed.
SAME="$WORKDIR/same-same"
setup_tree "$SAME"
write_identity "$SAME" "$PROJECT_VERSION" stable "v${PROJECT_VERSION}" "$OCI_CANDIDATE_SHA"
SAME_BEFORE="$(state_digest "$SAME")"
run_verified "$SAME" --check >"$WORKDIR/same-check.out" || fail "same-build --check"
grep -q 'Update                    : not needed' "$WORKDIR/same-check.out" || fail "same build should be not needed"
grep -q 'State mutation             : NO' "$WORKDIR/same-check.out" || fail "same-build check mutation"
[[ "$(state_digest "$SAME")" == "$SAME_BEFORE" ]] || fail "same-build --check mutated"
pass "SERVER_SAME_VERSION_SAME_BUILD"
pass "SERVER_CHECK_SAME_BUILD_NOT_NEEDED"

# Actual refresh for OCI identity, then idempotent second apply.
REFRESH="$WORKDIR/oci-refresh"
setup_tree "$REFRESH"
write_identity "$REFRESH" "$PROJECT_VERSION" stable "v${PROJECT_VERSION}" "$OCI_INSTALLED_SHA"
REFRESH_STATE="$(state_digest "$REFRESH")"
REFRESH_FRP="$(sha "$REFRESH/usr/local/bin/frps")"
mkdir -p "$REFRESH/var/log/drlink"
run_verified "$REFRESH" >"$WORKDIR/refresh.out" || fail "oci actual refresh"
grep -q 'Server project update completed successfully' "$WORKDIR/refresh.out" || fail "oci refresh success"
grep -q 'Same-version update : refreshed management files' "$WORKDIR/refresh.out" || fail "oci same-version refresh line"
grep -q "BUNDLE_SHA256=${OCI_CANDIDATE_SHA}" "$REFRESH/etc/drlink/version" || fail "verified sha not persisted"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$REFRESH/etc/drlink/version" || fail "project version lost"
grep -q 'FRP_VERSION=0.71.0' "$REFRESH/etc/drlink/version" || fail "frp version changed"
grep -q "RELEASE_CHANNEL=${TREE_CHANNEL}" "$REFRESH/etc/drlink/version" || fail "channel not preserved"
grep -q "SOURCE_REF=${TREE_REF}" "$REFRESH/etc/drlink/version" || fail "source ref not preserved"
[[ "$(state_digest "$REFRESH")" == "$REFRESH_STATE" ]] || fail "oci refresh changed protected state"
[[ "$(sha "$REFRESH/usr/local/bin/frps")" == "$REFRESH_FRP" ]] || fail "oci refresh changed frps"
grep -q 'project_update.completed' "$REFRESH/var/log/drlink/audit.jsonl" || fail "refresh missing audit"
[[ -d "$REFRESH/var/lib/drlink/backups" ]] || fail "refresh missing snapshot"
BACKUP_COUNT="$(find "$REFRESH/var/lib/drlink/backups" -mindepth 1 -maxdepth 1 -type d | wc -l)"
pass "SERVER_ACTUAL_DIFFERENT_BUILD_REFRESH"
pass "SERVER_BUILD_SHA_PERSISTENCE"
pass "SERVER_STABLE_CHANNEL_PRESERVED"
pass "SERVER_SOURCE_REF_PRESERVED"
pass "SERVER_NO_FRP_BINARY_CHANGE"
pass "SERVER_STATE_PRESERVED"
pass "SERVER_NO_CLIENT_REENROLLMENT"

run_verified "$REFRESH" --check >"$WORKDIR/refresh-check2.out" || fail "second --check"
grep -q 'Update                    : not needed' "$WORKDIR/refresh-check2.out" || fail "second check should be not needed"
grep -q 'State mutation             : NO' "$WORKDIR/refresh-check2.out" || fail "second check mutation"

AUDIT_BEFORE="$(sha "$REFRESH/var/log/drlink/audit.jsonl")"
VER_BEFORE="$(sha "$REFRESH/etc/drlink/version")"
run_verified "$REFRESH" >"$WORKDIR/refresh2.out" || fail "second actual"
grep -q 'Update                    : not needed' "$WORKDIR/refresh2.out" || fail "second actual should be not needed"
grep -q 'State mutation             : NO' "$WORKDIR/refresh2.out" || fail "second actual mutation flag"
if grep -q 'Server project update completed successfully' "$WORKDIR/refresh2.out"; then
  fail "second actual mutated"
fi
if grep -q 'Same-version update : refreshed management files' "$WORKDIR/refresh2.out"; then
  fail "second actual refreshed"
fi
[[ "$(sha "$REFRESH/etc/drlink/version")" == "$VER_BEFORE" ]] || fail "second actual rewrote version"
[[ "$(sha "$REFRESH/var/log/drlink/audit.jsonl")" == "$AUDIT_BEFORE" ]] || fail "second actual wrote audit"
[[ "$(find "$REFRESH/var/lib/drlink/backups" -mindepth 1 -maxdepth 1 -type d | wc -l)" == "$BACKUP_COUNT" ]] ||
  fail "second actual created snapshot"
[[ ! -f "$REFRESH/var/lib/drlink/server-update-pending.json" ]] || fail "second actual left txn marker"
pass "SERVER_ACTUAL_SAME_BUILD_NO_MUTATION"

echo "SERVER_PROJECT_UPDATE_TESTS=PASS"
