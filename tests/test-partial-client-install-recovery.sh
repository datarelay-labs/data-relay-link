#!/usr/bin/env bash
# Partial/broken Linux client install classification and safe repair.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_CLIENT_SOURCED=1
export FRP_SKIP_SYSTEMD=1
export FRP_SKIP_DOWNLOAD=1
export FRP_SKIP_CONNECTIVITY_CHECK=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"

write_state() {
  local tree="$1"
  mkdir -p "$tree/etc/frp"
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://203.0.113.10:6099/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "dp1",
    "machine_id": "dddddddddddddddddddddddddddddddd",
    "host_id": "dp1-dddddddd",
    "services": {"ssh": {"id": "ssh", "remote_port": 18300, "enabled": True, "local_ip": "127.0.0.1", "local_port": 22}},
}, indent=2) + "\n")
PY
  chmod 600 "$tree/etc/frp/client-state.json"
}

write_toml_identity() {
  local tree="$1"
  mkdir -p "$tree/etc/frp"
  cat >"$tree/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"
EOF
  chmod 600 "$tree/etc/frp/frpc.toml"
  python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
    "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
  chmod 600 "$tree/etc/frp/client-identity.key"
}

write_frpc() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod 0755 "$dest"
}

write_complete_runtime() {
  local tree="$1"
  mkdir -p "$tree/usr/local/bin" "$tree/usr/local/lib/drlink"
  write_frpc "$tree/usr/local/bin/frpc"
  printf '#!/bin/sh\necho drlink client\n' >"$tree/usr/local/bin/drlink"
  printf '#!/bin/sh\necho frpctl\n' >"$tree/usr/local/lib/drlink/frpctl"
  echo 'common' >"$tree/usr/local/lib/drlink/frp-client-common.sh"
  chmod 0755 "$tree/usr/local/bin/drlink" "$tree/usr/local/lib/drlink/frpctl"
}

assert_class() {
  local tree="$1" want="$2" label="$3"
  export FRP_CLIENT_TEST_ROOT="$tree"
  local got
  got="$(frp_client_install_class)"
  [[ "$got" == "$want" ]] || fail "$label class=$got want=$want"
}

# --- Fresh host -------------------------------------------------------------
FRESH="$WORKDIR/fresh"
mkdir -p "$FRESH/etc/frp"
assert_class "$FRESH" none "fresh"
pass "FRESH_INSTALL_CLASSIFICATION"

# --- State file only --------------------------------------------------------
STATE_ONLY="$WORKDIR/state-only"
write_state "$STATE_ONLY"
assert_class "$STATE_ONLY" partial "state-only"
if frp_client_has_existing_install; then
  fail "state-only must not be complete"
fi
if frp_client_partial_is_safe_to_repair; then
  fail "state-only must not auto-repair"
fi
export FRP_CLIENT_TEST_ROOT="$STATE_ONLY"
if frp_client_main >"$WORKDIR/state-only.out" 2>"$WORKDIR/state-only.err"; then
  fail "state-only should fail closed"
fi
if grep -q 'This client is already installed' "$WORKDIR/state-only.err" \
  || grep -q 'already has a Data Relay Link client installed' "$WORKDIR/state-only.err"; then
  fail "state-only false already-installed"
fi
grep -qi 'partial or broken' "$WORKDIR/state-only.err" || fail "state-only recovery wording"
grep -q 'RECOVERY_REQUIRED' "$WORKDIR/state-only.out" "$WORKDIR/state-only.err" \
  || fail "state-only recovery class"
pass "STATE_ONLY_PARTIAL_FAIL_CLOSED"

# --- Config + identity, missing CLI/service --------------------------------
CFG_ID="$WORKDIR/cfg-id"
write_state "$CFG_ID"
write_toml_identity "$CFG_ID"
write_frpc "$CFG_ID/usr/local/bin/frpc"
assert_class "$CFG_ID" partial "config+identity"
pass "CONFIG_IDENTITY_MISSING_CLI_PARTIAL"

# --- CLI present, incomplete runtime/service --------------------------------
CLI_ONLY="$WORKDIR/cli-only"
mkdir -p "$CLI_ONLY/usr/local/bin"
printf '#!/bin/sh\necho drlink\n' >"$CLI_ONLY/usr/local/bin/drlink"
chmod 0755 "$CLI_ONLY/usr/local/bin/drlink"
assert_class "$CLI_ONLY" partial "cli-only"
pass "CLI_PRESENT_INCOMPLETE_PARTIAL"

# --- DP1 exact remnant ------------------------------------------------------
DP1="$WORKDIR/dp1"
write_state "$DP1"
write_toml_identity "$DP1"
write_frpc "$DP1/usr/local/bin/frpc"
printf '#!/bin/sh\necho frp-client\n' >"$DP1/usr/local/bin/frp-client"
chmod 0755 "$DP1/usr/local/bin/frp-client"
assert_class "$DP1" partial "dp1"
if frp_client_has_existing_install; then
  fail "DP1_COMPLETE_INSTALL_DETECTED"
fi
frp_client_has_partial_install || fail "DP1_PARTIAL_OR_BROKEN_DETECTED"
KEY_BEFORE="$(sha256sum "$DP1/etc/frp/client-identity.key" | awk '{print $1}')"
TOML_BEFORE="$(sha256sum "$DP1/etc/frp/frpc.toml" | awk '{print $1}')"
STATE_BEFORE="$(sha256sum "$DP1/etc/frp/client-state.json" | awk '{print $1}')"
export FRP_CLIENT_TEST_ROOT="$DP1"
export FRP_ZERO_TOUCH=1
export FRP_ALLOCATOR_URL='https://203.0.113.10:6099/enroll'
export FRP_BOOTSTRAP_TICKET='bt1.unused.ticket'
export FRP_CLIENT_HOOK_LOG="$WORKDIR/dp1.hook"
: >"$FRP_CLIENT_HOOK_LOG"
set +e
frp_client_main >"$WORKDIR/dp1.out" 2>"$WORKDIR/dp1.err"
dp1_rc=$?
set -e
unset FRP_ZERO_TOUCH FRP_BOOTSTRAP_TICKET
[[ "$dp1_rc" -eq 0 ]] || {
  cat "$WORKDIR/dp1.out" "$WORKDIR/dp1.err" >&2
  fail "DP1_REPAIR_PATH"
}
if grep -q 'This client is already installed' "$WORKDIR/dp1.out" "$WORKDIR/dp1.err"; then
  fail "DP1_ALREADY_INSTALLED_MESSAGE"
fi
grep -qi 'partial or broken' "$WORKDIR/dp1.err" "$WORKDIR/dp1.out" || fail "DP1 repair wording"
[[ -x "$DP1/usr/local/bin/drlink" ]] || fail "CANONICAL_DRLINK_RESTORED"
[[ -x "$DP1/usr/local/lib/drlink/frpctl" ]] || fail "runtime payload restored"
[[ "$(sha256sum "$DP1/etc/frp/client-identity.key" | awk '{print $1}')" == "$KEY_BEFORE" ]] \
  || fail "DP1 identity changed"
[[ "$(sha256sum "$DP1/etc/frp/frpc.toml" | awk '{print $1}')" == "$TOML_BEFORE" ]] \
  || fail "DP1 toml changed"
[[ "$(sha256sum "$DP1/etc/frp/client-state.json" | awk '{print $1}')" == "$STATE_BEFORE" ]] \
  || fail "DP1 state changed"
if grep -q bootstrap_redeem "$WORKDIR/dp1.hook"; then
  fail "DP1 redeemed ticket"
fi
export FRP_CLIENT_TEST_ROOT="$DP1"
[[ "$(frp_client_install_class)" == "complete" ]] || fail "FINAL_INSTALL_CLASS"
pass "DP1_PARTIAL_AUTO_REPAIR"

# --- Complete install protection -------------------------------------------
COMPLETE="$WORKDIR/complete"
write_state "$COMPLETE"
write_toml_identity "$COMPLETE"
write_complete_runtime "$COMPLETE"
assert_class "$COMPLETE" complete "complete"
KEY_C="$(sha256sum "$COMPLETE/etc/frp/client-identity.key" | awk '{print $1}')"
export FRP_CLIENT_TEST_ROOT="$COMPLETE"
export FRP_ALLOCATOR_URL='https://203.0.113.10:6099/enroll'
export FRP_ENROLLMENT_CODE='deadbeef.deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
if frp_client_main >"$WORKDIR/complete.out" 2>"$WORKDIR/complete.err"; then
  fail "complete install must refuse re-enrollment"
fi
grep -q 'already has a Data Relay Link client installed' "$WORKDIR/complete.err" \
  || fail "complete refuse message"
[[ "$(sha256sum "$COMPLETE/etc/frp/client-identity.key" | awk '{print $1}')" == "$KEY_C" ]] \
  || fail "complete re-enroll mutated identity"
pass "COMPLETE_INSTALL_CLASSIFICATION"
pass "COMPLETE_INSTALL_REENROLLMENT_PROTECTION"

# --- Fresh zero-touch classification stays none until files exist ----------
FRESH2="$WORKDIR/fresh2"
mkdir -p "$FRESH2/etc/frp" "$FRESH2/usr/local/bin" "$FRESH2/usr/local/lib/drlink"
assert_class "$FRESH2" none "fresh2"
pass "FRESH_ZERO_TOUCH_INSTALL_CLASS"

echo "ALL_PARTIAL_CLIENT_INSTALL_RECOVERY_PASS"
