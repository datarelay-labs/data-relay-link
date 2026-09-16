#!/usr/bin/env bash
# Server installer snapshot/restore must reverse project-owned mutations without
# touching CA/token/registry/reservations.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
TREE="$WORKDIR/root"
SNAP="$WORKDIR/snap"
mkdir -p \
  "$TREE/etc/drlink/pki" \
  "$TREE/etc/frp" \
  "$TREE/etc/systemd/system" \
  "$TREE/usr/local/lib/drlink" \
  "$TREE/usr/local/sbin" \
  "$TREE/var/lib/drlink/enrollments" \
  "$TREE/var/lib/drlink/bootstrap"

# Pre-cutover Direct state
printf 'mode=direct\n' >"$TREE/etc/drlink/config.json"
printf 'bindPort = 443\n' >"$TREE/etc/frp/frps.toml"
printf 'token-secret\n' >"$TREE/etc/frp/server_token"
chmod 600 "$TREE/etc/frp/server_token"
printf '{"schema_version":2,"clients":{},"reserved":{}}\n' >"$TREE/var/lib/drlink/registry.json"
chmod 600 "$TREE/var/lib/drlink/registry.json"
printf 'CA' >"$TREE/etc/drlink/pki/ca.key"
chmod 600 "$TREE/etc/drlink/pki/ca.key"
printf 'ca-crt' >"$TREE/etc/drlink/pki/ca.crt"
printf 'unit-frps\n' >"$TREE/etc/systemd/system/drlink-server.service"
printf 'lib\n' >"$TREE/usr/local/lib/drlink/frp-common.sh"
printf 'tool\n' >"$TREE/usr/local/sbin/frpctl"
printf '1.9.1\n' >"$TREE/etc/drlink/version"
TOKEN_SHA="$(sha256sum "$TREE/etc/frp/server_token" | awk '{print $1}')"
REG_SHA="$(sha256sum "$TREE/var/lib/drlink/registry.json" | awk '{print $1}')"
CA_SHA="$(sha256sum "$TREE/etc/drlink/pki/ca.key" | awk '{print $1}')"

export FRP_SERVER_TEST_ROOT="$TREE"
python3 "$ROOT/lib/frp_install_txn.py" snapshot --root "$TREE" --dest "$SNAP" \
  || fail "snapshot"

# Mutate toward single443 mixed state
printf 'mode=single443\n' >"$TREE/etc/drlink/config.json"
printf 'bindPort = 7000\n' >"$TREE/etc/frp/frps.toml"
printf 'frontend\n' >"$TREE/etc/drlink/frontend.conf"
printf 'unit-frontend\n' >"$TREE/etc/systemd/system/drlink-frontend.service"
printf 'newlib\n' >"$TREE/usr/local/lib/drlink/frp-common.sh"
printf '2.1.0\n' >"$TREE/etc/drlink/version"
# Attempt (forbidden) "rollback" side effects must not be performed by restore
printf 'token-rotated\n' >"$TREE/etc/frp/server_token"
printf '{"schema_version":2,"clients":{"x":{}},"reserved":{"1":1}}\n' \
  >"$TREE/var/lib/drlink/registry.json"
printf 'CA-rotated' >"$TREE/etc/drlink/pki/ca.key"

python3 "$ROOT/lib/frp_install_txn.py" restore --root "$TREE" --dest "$SNAP" \
  || fail "restore"

grep -q 'mode=direct' "$TREE/etc/drlink/config.json" || fail "config not restored"
grep -q 'bindPort = 443' "$TREE/etc/frp/frps.toml" || fail "toml not restored"
[[ ! -f "$TREE/etc/drlink/frontend.conf" ]] || fail "frontend.conf should be absent again"
[[ ! -f "$TREE/etc/systemd/system/drlink-frontend.service" ]] || fail "frontend unit should be absent again"
grep -q '^lib$' "$TREE/usr/local/lib/drlink/frp-common.sh" || fail "lib not restored"
grep -q '1.9.1' "$TREE/etc/drlink/version" || fail "version not restored"

# Protected paths must never be rolled back/rotated by the txn helper.
# Mutations applied after the snapshot must remain (restore skips them).
grep -q 'token-rotated' "$TREE/etc/frp/server_token" || fail "token must not be restored/deleted"
grep -q '"x"' "$TREE/var/lib/drlink/registry.json" || fail "registry must not be restored"
grep -q 'CA-rotated' "$TREE/etc/drlink/pki/ca.key" || fail "CA must not be restored"
[[ "$(sha256sum "$TREE/etc/frp/server_token" | awk '{print $1}')" != "$TOKEN_SHA" ]] \
  || fail "token unexpectedly restored to snapshot value"
[[ "$(sha256sum "$TREE/var/lib/drlink/registry.json" | awk '{print $1}')" != "$REG_SHA" ]] \
  || fail "registry unexpectedly restored"
[[ "$(sha256sum "$TREE/etc/drlink/pki/ca.key" | awk '{print $1}')" != "$CA_SHA" ]] \
  || fail "CA unexpectedly restored"
pass "TXN_RESTORE_PROJECT_STATE"
pass "TXN_NEVER_TOUCH_CA_TOKEN_REGISTRY"

# Failure-injection hooks exist for meaningful install phases.
for hook in \
  FRP_INSTALL_HOOK_FRONTEND_PROXY_FAIL \
  FRP_INSTALL_HOOK_HEALTH_FAIL \
  FRP_INSTALL_HOOK_START_FAIL \
  FRP_INSTALL_HOOK_ENABLE_FAIL \
  FRP_INSTALL_HOOK_DEP_FAIL
do
  grep -q "$hook" "$ROOT/install-server.sh" || fail "missing failure hook $hook"
done
grep -q 'frp_server_fail_after_mutation' "$ROOT/install-server.sh" || fail "missing fail-after-mutation helper"
grep -q 'frp_server_create_snapshot' "$ROOT/install-server.sh" || fail "missing snapshot call site"
grep -q 'frp_verify_frontend_proxy_health' "$ROOT/install-server.sh" || fail "missing frontend proxy gate"
pass "TXN_FAILURE_HOOKS_PRESENT"

python3 - "$ROOT" <<'PY'
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "lib"))
import frp_install_txn
os.environ["FRP_INSTALL_TXN_HOOK_SYSTEMD_FAIL"] = "1"
os.environ.pop("FRP_SERVER_TEST_ROOT", None)
ok = frp_install_txn.apply_service_states({
    "services": {
        "skipped": False,
        "units": [{"unit": "drlink-server.service", "enabled": "enabled", "active": "active"}],
    }
}, skip=False)
if ok:
    raise SystemExit("systemd hook should fail apply_service_states")
print("SYSTEMD_HOOK_OK")
PY
pass "ROLLBACK_SYSTEMD_FAILURE_TEST"

echo "INSTALL_TXN_ROLLBACK_TEST=PASS"
