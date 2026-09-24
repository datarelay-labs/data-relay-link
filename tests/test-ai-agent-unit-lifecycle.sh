#!/usr/bin/env bash
# Linux Agent install and product update must install, enable, and restart
# drlink-ai-agent.service without restarting frpc.
set -euo pipefail

unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT \
  FRP_CLIENT_SOURCED FRP_CLIENT_UPGRADE FRP_CLIENT_UPDATE_SOURCE \
  FRP_CLIENT_UPDATE_CHECK FRP_SKIP_SYSTEMD FRP_SYSTEMCTL_BIN || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

grep -q 'frp_client_converge_ai_agent_unit' "$ROOT/install-client.sh" || fail "install path missing AI agent converge"
grep -q 'systemctl enable drlink-client' "$ROOT/install-client.sh" || fail "client unit enable missing"
pass "INSTALL_CALLS_AI_AGENT_CONVERGE"

MOCK="$WORKDIR/systemctl"
LOG="$WORKDIR/systemctl.log"
cat >"$MOCK" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$LOG"
case "\$1" in
  is-enabled) printf '%s\n' enabled ;;
  is-active) printf '%s\n' active ;;
esac
exit 0
EOF
chmod 0755 "$MOCK"

install_tree() {
  local tree="$1"
  mkdir -p "$tree/etc/frp" "$tree/etc/drlink" "$tree/usr/local/bin" "$tree/usr/local/lib/drlink"
  cat >"$tree/usr/local/bin/frpc" <<'EOF'
#!/bin/sh
if [ "$1" = verify ]; then exit 0; fi
if [ "$1" = --version ]; then echo "frpc version 0.71.0"; exit 0; fi
exit 0
EOF
  chmod 0755 "$tree/usr/local/bin/frpc"
  printf '#!/bin/sh\necho old-client\n' >"$tree/usr/local/bin/frp-client"
  chmod 0755 "$tree/usr/local/bin/frp-client"
  echo old >"$tree/usr/local/lib/drlink/frp-client-common.sh"
  echo old >"$tree/usr/local/lib/drlink/frp_mgmt_auth.py"
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://203.0.113.10:6099/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "ai-agent-lifecycle",
    "machine_id": "aabbccddeeff00112233445566778899",
    "host_id": "ai-agent-aabbccdd",
    "services": {"ssh": {"id": "ssh", "remote_port": 6003, "enabled": True, "local_ip": "127.0.0.1", "local_port": 22}},
}, indent=2) + "\n")
PY
  chmod 600 "$tree/etc/frp/client-state.json"
  cat >"$tree/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"
EOF
  chmod 600 "$tree/etc/frp/frpc.toml"
  echo access >"$tree/etc/frp/access-info.txt"
  echo ca >"$tree/etc/drlink/allocator-ca.crt"
  python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
    "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
  chmod 600 "$tree/etc/frp/client-identity.key"
  printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"$tree/etc/frp/client-identity.mac"
  chmod 600 "$tree/etc/frp/client-identity.mac"
  cat >"$tree/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.7.0
FRP_VERSION=0.71.0
EOF
}

INSTALL="$WORKDIR/install-root"
: >"$LOG"
(
  export FRP_CLIENT_TEST_ROOT="$INSTALL"
  export FRP_SYSTEMCTL_BIN="$MOCK"
  # shellcheck disable=SC1091
  . "$ROOT/lib/frp-client-common.sh"
  frp_client_converge_ai_agent_unit "$ROOT"
)
[[ -f "$INSTALL/etc/systemd/system/drlink-ai-agent.service" ]] || fail "install did not write unit"
grep -q 'drlink_ai_agent.py' "$INSTALL/etc/systemd/system/drlink-ai-agent.service" || fail "install unit exec"
grep -qx 'daemon-reload' "$LOG" || fail "install daemon-reload"
grep -qx 'enable drlink-ai-agent' "$LOG" || fail "install enable"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "install restart"
if grep -q 'drlink-client' "$LOG"; then fail "install restarted frpc via AI converge"; fi
pass "INSTALL_ENABLES_AND_RESTARTS_AI_AGENT"

TREE="$WORKDIR/update-root"
install_tree "$TREE"
STATE_BEFORE="$(python3 - "$TREE/etc/frp/client-state.json" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_SYSTEMCTL_BIN="$MOCK"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/update.out" 2>"$WORKDIR/update.err"; then
  cat "$WORKDIR/update.out" "$WORKDIR/update.err" >&2
  fail "product update"
fi
grep -q 'frpc restarted  : NO' "$WORKDIR/update.out" || fail "frpc restart contract"
grep -q 'AI agent service : converged' "$WORKDIR/update.out" || fail "update converge line"
[[ -f "$TREE/etc/systemd/system/drlink-ai-agent.service" ]] || fail "update did not install unit"
grep -q 'drlink_ai_agent.py' "$TREE/etc/systemd/system/drlink-ai-agent.service" || fail "update unit exec"
grep -qx 'daemon-reload' "$LOG" || fail "update daemon-reload"
grep -qx 'enable drlink-ai-agent' "$LOG" || fail "update enable"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "update restart"
cmp -s "$ROOT/client/drlink-ai-agent.service" "$TREE/etc/systemd/system/drlink-ai-agent.service" \
  || fail "update unit is not the canonical source file"
if grep -q 'drlink-client' "$LOG"; then fail "update restarted frpc"; fi
STATE_AFTER="$(python3 - "$TREE/etc/frp/client-state.json" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
[[ "$STATE_BEFORE" == "$STATE_AFTER" ]] || fail "update changed client state"
pass "PRODUCT_UPDATE_CONVERGES_AI_AGENT_WITHOUT_FRPC_RESTART"

(
  # shellcheck disable=SC1091
  . "$ROOT/lib/frp-client-common.sh"
  frp_client_upgrade_destinations | grep -qx \
    'etc/systemd/system/drlink-ai-agent.service:0644:client/drlink-ai-agent.service'
) || fail "AI worker unit missing from upgrade destinations"
pass "UPGRADE_DESTINATIONS_INCLUDE_AI_AGENT_UNIT"

file_sha() {
  python3 - "$1" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

ROLL="$WORKDIR/rollback-root"
install_tree "$ROLL"
KEY_BEFORE="$(file_sha "$ROLL/etc/frp/client-identity.key")"
STATE_BEFORE="$(file_sha "$ROLL/etc/frp/client-state.json")"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$ROLL"
export FRP_SYSTEMCTL_BIN="$MOCK"
export FRP_CLIENT_UPGRADE_HOOK_FAIL=version
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/rollback.out" 2>"$WORKDIR/rollback.err"; then
  fail "rollback update should fail"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/rollback.out" "$WORKDIR/rollback.err" || fail "rollback marker"
[[ ! -e "$ROLL/etc/systemd/system/drlink-ai-agent.service" ]] || fail "rollback left a new AI unit"
python3 - "$LOG" <<'PY'
import sys
from pathlib import Path
lines = [ln.strip() for ln in Path(sys.argv[1]).read_text().splitlines() if ln.strip()]
need = ["daemon-reload", "enable drlink-ai-agent", "restart drlink-ai-agent",
        "daemon-reload", "disable drlink-ai-agent", "stop drlink-ai-agent"]
pos = 0
for item in need:
    while pos < len(lines) and lines[pos] != item:
        pos += 1
    if pos >= len(lines):
        raise SystemExit("missing rollback action " + item + " in " + repr(lines))
    pos += 1
PY
if grep -q 'drlink-client' "$LOG"; then fail "rollback restarted frpc"; fi
[[ "$(file_sha "$ROLL/etc/frp/client-identity.key")" == "$KEY_BEFORE" ]] || fail "rollback rotated identity"
[[ "$(file_sha "$ROLL/etc/frp/client-state.json")" == "$STATE_BEFORE" ]] || fail "rollback changed client state"
pass "PRODUCT_UPDATE_ROLLBACK_RESTORES_ABSENT_AI_UNIT"

PRIOR="$WORKDIR/rollback-prior"
install_tree "$PRIOR"
mkdir -p "$PRIOR/etc/systemd/system"
printf 'PRIOR UNIT\n' >"$PRIOR/etc/systemd/system/drlink-ai-agent.service"
PRIOR_SHA="$(file_sha "$PRIOR/etc/systemd/system/drlink-ai-agent.service")"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$PRIOR"
export FRP_SYSTEMCTL_BIN="$MOCK"
export FRP_CLIENT_UPGRADE_HOOK_FAIL=version
if "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/rollback-prior.out" 2>"$WORKDIR/rollback-prior.err"; then
  fail "prior-unit rollback update should fail"
fi
unset FRP_CLIENT_UPGRADE_HOOK_FAIL
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/rollback-prior.out" "$WORKDIR/rollback-prior.err" || fail "prior-unit rollback marker"
[[ "$(file_sha "$PRIOR/etc/systemd/system/drlink-ai-agent.service")" == "$PRIOR_SHA" ]] || fail "rollback replaced prior unit content"
python3 - "$LOG" <<'PY'
import sys
from pathlib import Path
lines = [ln.strip() for ln in Path(sys.argv[1]).read_text().splitlines() if ln.strip()]
need = ["is-enabled drlink-ai-agent", "is-active drlink-ai-agent",
        "daemon-reload", "enable drlink-ai-agent", "restart drlink-ai-agent",
        "daemon-reload", "enable drlink-ai-agent", "restart drlink-ai-agent"]
pos = 0
for item in need:
    while pos < len(lines) and lines[pos] != item:
        pos += 1
    if pos >= len(lines):
        raise SystemExit("missing prior-state action " + item + " in " + repr(lines))
    pos += 1
if "disable drlink-ai-agent" in lines or "stop drlink-ai-agent" in lines:
    raise SystemExit("rollback disabled a unit that was enabled and active")
PY
pass "PRODUCT_UPDATE_ROLLBACK_RESTORES_PRIOR_AI_UNIT_STATE"

BUNDLE='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
CURRENT="$(awk -F= '$1=="PROJECT_VERSION"{print $2}' "$ROOT/VERSION")"
write_current() {
  local tree="$1"
  cat >"$tree/etc/drlink/version" <<EOF
PROJECT_VERSION=${CURRENT}
FRP_VERSION=0.71.0
BUNDLE_SHA256=${BUNDLE}
EOF
}

SAME="$WORKDIR/same-missing"
install_tree "$SAME"
write_current "$SAME"
KEY_BEFORE="$(file_sha "$SAME/etc/frp/client-identity.key")"
STATE_BEFORE="$(file_sha "$SAME/etc/frp/client-state.json")"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$SAME"
export FRP_SYSTEMCTL_BIN="$MOCK"
export FRP_BUNDLE_SHA256="$BUNDLE"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/same-missing.out" 2>"$WORKDIR/same-missing.err"; then
  cat "$WORKDIR/same-missing.out" "$WORKDIR/same-missing.err" >&2
  fail "same-version missing unit update"
fi
cmp -s "$ROOT/client/drlink-ai-agent.service" "$SAME/etc/systemd/system/drlink-ai-agent.service" \
  || fail "same-version refresh did not install canonical unit"
grep -qx 'daemon-reload' "$LOG" || fail "same-version daemon-reload"
grep -qx 'enable drlink-ai-agent' "$LOG" || fail "same-version enable"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "same-version restart"
grep -q 'frpc restarted  : NO' "$WORKDIR/same-missing.out" || fail "same-version frpc restart contract"
[[ "$(file_sha "$SAME/etc/frp/client-identity.key")" == "$KEY_BEFORE" ]] || fail "same-version rotated identity"
[[ "$(file_sha "$SAME/etc/frp/client-state.json")" == "$STATE_BEFORE" ]] || fail "same-version changed client state"
: >"$LOG"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/same-again.out" 2>"$WORKDIR/same-again.err"; then
  cat "$WORKDIR/same-again.out" "$WORKDIR/same-again.err" >&2
  fail "converged same-version refresh"
fi
grep -q 'Update                    : not needed' "$WORKDIR/same-again.out" || fail "converged host still reported update needed"
[[ ! -s "$LOG" ]] || fail "converged refresh called systemctl"
pass "SAME_VERSION_REFRESH_INSTALLS_MISSING_AI_UNIT"

STALE="$WORKDIR/same-stale"
install_tree "$STALE"
write_current "$STALE"
mkdir -p "$STALE/etc/systemd/system"
printf 'STALE UNIT\n' >"$STALE/etc/systemd/system/drlink-ai-agent.service"
STALE_BEFORE="$(file_sha "$STALE/etc/systemd/system/drlink-ai-agent.service")"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$STALE"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/same-stale.out" 2>"$WORKDIR/same-stale.err"; then
  cat "$WORKDIR/same-stale.out" "$WORKDIR/same-stale.err" >&2
  fail "same-version stale unit update"
fi
cmp -s "$ROOT/client/drlink-ai-agent.service" "$STALE/etc/systemd/system/drlink-ai-agent.service" \
  || fail "same-version refresh left a stale unit"
[[ "$(file_sha "$STALE/etc/systemd/system/drlink-ai-agent.service")" != "$STALE_BEFORE" ]] || fail "stale unit unchanged"
pass "SAME_VERSION_REFRESH_REPLACES_STALE_AI_UNIT"

CHECK="$WORKDIR/check-only"
install_tree "$CHECK"
write_current "$CHECK"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$CHECK"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" --check >"$WORKDIR/check.out" 2>"$WORKDIR/check.err"; then
  cat "$WORKDIR/check.out" "$WORKDIR/check.err" >&2
  fail "check-only"
fi
grep -q 'Update                    : available' "$WORKDIR/check.out" || fail "check-only did not report the missing unit"
grep -q 'State mutation           : NO' "$WORKDIR/check.out" || fail "check-only mutation flag"
[[ ! -e "$CHECK/etc/systemd/system/drlink-ai-agent.service" ]] || fail "check-only wrote the AI unit"
[[ ! -s "$LOG" ]] || fail "check-only called systemctl"
pass "CHECK_ONLY_DOES_NOT_MUTATE_AI_UNIT"
unset FRP_BUNDLE_SHA256
