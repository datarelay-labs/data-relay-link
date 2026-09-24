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
assert_readonly_systemd_log() {
  local leftover
  leftover="$(grep -Ev '^(is-enabled|is-active) ' "$LOG" || true)"
  [[ -z "$leftover" ]] || fail "$1 mutated systemd: ${leftover}"
}

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
grep -q 'frpc restarted  : YES' "$WORKDIR/update.out" || fail "missing client unit should restart relay"
grep -q 'AI agent service : converged' "$WORKDIR/update.out" || fail "update converge line"
[[ -f "$TREE/etc/systemd/system/drlink-ai-agent.service" ]] || fail "update did not install AI unit"
[[ -f "$TREE/etc/systemd/system/drlink-client.service" ]] || fail "update did not install client unit"
cmp -s "$ROOT/client/drlink-ai-agent.service" "$TREE/etc/systemd/system/drlink-ai-agent.service" \
  || fail "update AI unit is not the canonical source file"
cmp -s "$ROOT/client/drlink-client.service" "$TREE/etc/systemd/system/drlink-client.service" \
  || fail "update client unit is not the canonical source file"
grep -qx 'daemon-reload' "$LOG" || fail "update daemon-reload"
grep -qx 'enable drlink-ai-agent' "$LOG" || fail "update AI enable"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "update AI restart"
grep -qx 'enable drlink-client' "$LOG" || fail "update client enable"
grep -qx 'restart drlink-client' "$LOG" || fail "update client restart"
STATE_AFTER="$(python3 - "$TREE/etc/frp/client-state.json" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
[[ "$STATE_BEFORE" == "$STATE_AFTER" ]] || fail "update changed client state"
pass "PRODUCT_UPDATE_CONVERGES_MISSING_LINUX_UNITS"

(
  # shellcheck disable=SC1091
  . "$ROOT/lib/frp-client-common.sh"
  frp_client_upgrade_destinations | grep -qx \
    'etc/systemd/system/drlink-ai-agent.service:0644:client/drlink-ai-agent.service'
  frp_client_upgrade_destinations | grep -qx \
    'etc/systemd/system/drlink-client.service:0644:client/drlink-client.service'
) || fail "Linux units missing from upgrade destinations"
pass "UPGRADE_DESTINATIONS_INCLUDE_LINUX_UNITS"

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
[[ ! -e "$ROLL/etc/systemd/system/drlink-client.service" ]] || fail "rollback left a new client unit"
python3 - "$LOG" <<'PY'
import sys
from pathlib import Path
lines = [ln.strip() for ln in Path(sys.argv[1]).read_text().splitlines() if ln.strip()]
need = ["daemon-reload", "enable drlink-ai-agent", "restart drlink-ai-agent",
        "enable drlink-client", "restart drlink-client",
        "daemon-reload", "disable drlink-client", "stop drlink-client",
        "disable drlink-ai-agent", "stop drlink-ai-agent"]
pos = 0
for item in need:
    while pos < len(lines) and lines[pos] != item:
        pos += 1
    if pos >= len(lines):
        raise SystemExit("missing rollback action " + item + " in " + repr(lines))
    pos += 1
PY
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
[[ "$(file_sha "$PRIOR/etc/systemd/system/drlink-ai-agent.service")" == "$PRIOR_SHA" ]] || fail "rollback replaced prior AI unit content"
[[ ! -e "$PRIOR/etc/systemd/system/drlink-client.service" ]] || fail "rollback left a new client unit"
python3 - "$LOG" <<'PY'
import sys
from pathlib import Path
lines = [ln.strip() for ln in Path(sys.argv[1]).read_text().splitlines() if ln.strip()]
need = ["is-enabled drlink-ai-agent", "is-active drlink-ai-agent",
        "daemon-reload", "enable drlink-ai-agent", "restart drlink-ai-agent",
        "enable drlink-client", "restart drlink-client",
        "daemon-reload", "disable drlink-client", "stop drlink-client",
        "enable drlink-ai-agent", "restart drlink-ai-agent"]
pos = 0
for item in need:
    while pos < len(lines) and lines[pos] != item:
        pos += 1
    if pos >= len(lines):
        raise SystemExit("missing prior-state action " + item + " in " + repr(lines))
    pos += 1
if "disable drlink-ai-agent" in lines or "stop drlink-ai-agent" in lines:
    raise SystemExit("rollback disabled an AI unit that was enabled and active")
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
cmp -s "$ROOT/client/drlink-client.service" "$SAME/etc/systemd/system/drlink-client.service" \
  || fail "same-version refresh did not install client unit"
grep -qx 'restart drlink-client' "$LOG" || fail "same-version client restart"
grep -q 'frpc restarted  : YES' "$WORKDIR/same-missing.out" || fail "missing client unit should restart relay"
[[ "$(file_sha "$SAME/etc/frp/client-identity.key")" == "$KEY_BEFORE" ]] || fail "same-version rotated identity"
[[ "$(file_sha "$SAME/etc/frp/client-state.json")" == "$STATE_BEFORE" ]] || fail "same-version changed client state"
: >"$LOG"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/same-again.out" 2>"$WORKDIR/same-again.err"; then
  cat "$WORKDIR/same-again.out" "$WORKDIR/same-again.err" >&2
  fail "converged same-version refresh"
fi
grep -q 'Update                    : not needed' "$WORKDIR/same-again.out" || fail "converged host still reported update needed"
assert_readonly_systemd_log "converged refresh"
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

plant_units() {
  local tree="$1"
  mkdir -p "$tree/etc/systemd/system"
  install -m 0644 "$ROOT/client/drlink-client.service" "$tree/etc/systemd/system/drlink-client.service"
  install -m 0644 "$ROOT/client/drlink-ai-agent.service" "$tree/etc/systemd/system/drlink-ai-agent.service"
}

KEEP="$WORKDIR/keep-client"
install_tree "$KEEP"
plant_units "$KEEP"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$KEEP"
unset FRP_BUNDLE_SHA256
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/keep-client.out" 2>"$WORKDIR/keep-client.err"; then
  cat "$WORKDIR/keep-client.out" "$WORKDIR/keep-client.err" >&2
  fail "current-unit product update"
fi
grep -q 'frpc restarted  : NO' "$WORKDIR/keep-client.out" || fail "current client unit was restarted"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "AI worker was not restarted"
if grep -qx 'restart drlink-client' "$LOG"; then fail "current client unit was restarted"; fi
if grep -qx 'enable drlink-client' "$LOG"; then fail "current client unit was re-enabled"; fi
pass "CURRENT_CLIENT_UNIT_IS_NOT_RESTARTED"

STALE_CLIENT="$WORKDIR/stale-client"
install_tree "$STALE_CLIENT"
write_current "$STALE_CLIENT"
plant_units "$STALE_CLIENT"
printf 'STALE CLIENT UNIT\n' >"$STALE_CLIENT/etc/systemd/system/drlink-client.service"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$STALE_CLIENT"
export FRP_BUNDLE_SHA256="$BUNDLE"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/stale-client.out" 2>"$WORKDIR/stale-client.err"; then
  cat "$WORKDIR/stale-client.out" "$WORKDIR/stale-client.err" >&2
  fail "same-bundle stale client unit update"
fi
cmp -s "$ROOT/client/drlink-client.service" "$STALE_CLIENT/etc/systemd/system/drlink-client.service" \
  || fail "stale client unit was not replaced"
grep -q 'frpc restarted  : YES' "$WORKDIR/stale-client.out" || fail "stale client unit should restart relay"
grep -qx 'restart drlink-client' "$LOG" || fail "stale client unit restart"
: >"$LOG"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/stale-client-again.out" 2>"$WORKDIR/stale-client-again.err"; then
  cat "$WORKDIR/stale-client-again.out" "$WORKDIR/stale-client-again.err" >&2
  fail "converged client unit refresh"
fi
grep -q 'Update                    : not needed' "$WORKDIR/stale-client-again.out" || fail "converged client unit still needed"
assert_readonly_systemd_log "converged client refresh"
pass "SAME_BUNDLE_REPAIRS_STALE_CLIENT_UNIT_THEN_IDLE"

CHECK_CLIENT="$WORKDIR/check-client"
install_tree "$CHECK_CLIENT"
write_current "$CHECK_CLIENT"
mkdir -p "$CHECK_CLIENT/etc/systemd/system"
install -m 0644 "$ROOT/client/drlink-ai-agent.service" "$CHECK_CLIENT/etc/systemd/system/drlink-ai-agent.service"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$CHECK_CLIENT"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" --check >"$WORKDIR/check-client.out" 2>"$WORKDIR/check-client.err"; then
  cat "$WORKDIR/check-client.out" "$WORKDIR/check-client.err" >&2
  fail "check-only missing client unit"
fi
grep -q 'Update                    : available' "$WORKDIR/check-client.out" || fail "check-only missed client unit drift"
grep -q 'State mutation           : NO' "$WORKDIR/check-client.out" || fail "check-only client mutation flag"
[[ ! -e "$CHECK_CLIENT/etc/systemd/system/drlink-client.service" ]] || fail "check-only wrote the client unit"
[[ ! -s "$LOG" ]] || fail "check-only client called systemctl"
pass "CHECK_ONLY_DOES_NOT_MUTATE_CLIENT_UNIT"

DRIFT="$WORKDIR/service-drift"
install_tree "$DRIFT"
write_current "$DRIFT"
plant_units "$DRIFT"
AI_BYTES="$(file_sha "$DRIFT/etc/systemd/system/drlink-ai-agent.service")"
CLIENT_BYTES="$(file_sha "$DRIFT/etc/systemd/system/drlink-client.service")"
STATE_BYTES="$(file_sha "$DRIFT/etc/frp/client-state.json")"
DRIFT_MODE="$WORKDIR/service-drift.mode"
printf '%s\n' disabled >"$DRIFT_MODE"
DRIFT_MOCK="$WORKDIR/systemctl-drift"
cat >"$DRIFT_MOCK" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$LOG"
mode=\$(cat "$DRIFT_MODE")
case "\$1" in
  is-enabled)
    if [ "\$mode" = disabled ]; then printf '%s\n' disabled; else printf '%s\n' enabled; fi
    ;;
  is-active)
    if [ "\$mode" = repair ]; then printf '%s\n' active; else printf '%s\n' inactive; fi
    ;;
  restart)
    if [ "\$2" = drlink-ai-agent ]; then printf '%s\n' repair >"$DRIFT_MODE"; fi
    ;;
esac
exit 0
EOF
chmod 0755 "$DRIFT_MOCK"
export FRP_CLIENT_TEST_ROOT="$DRIFT"
export FRP_SYSTEMCTL_BIN="$DRIFT_MOCK"
export FRP_BUNDLE_SHA256="$BUNDLE"
: >"$LOG"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" --check >"$WORKDIR/drift-disabled.out" 2>"$WORKDIR/drift-disabled.err"; then
  cat "$WORKDIR/drift-disabled.out" "$WORKDIR/drift-disabled.err" >&2
  fail "check-only disabled AI worker"
fi
grep -q 'Update                    : available' "$WORKDIR/drift-disabled.out" || fail "disabled AI worker was not-needed"
grep -q 'State mutation           : NO' "$WORKDIR/drift-disabled.out" || fail "disabled check-only mutated"
grep -qx 'is-enabled drlink-ai-agent' "$LOG" || fail "disabled check-only skipped is-enabled"
grep -qx 'is-active drlink-ai-agent' "$LOG" || fail "disabled check-only skipped is-active"
assert_readonly_systemd_log "disabled check-only"
[[ "$(file_sha "$DRIFT/etc/systemd/system/drlink-ai-agent.service")" == "$AI_BYTES" ]] || fail "disabled check-only changed AI unit"
printf '%s\n' stopped >"$DRIFT_MODE"
: >"$LOG"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" --check >"$WORKDIR/drift-stopped.out" 2>"$WORKDIR/drift-stopped.err"; then
  cat "$WORKDIR/drift-stopped.out" "$WORKDIR/drift-stopped.err" >&2
  fail "check-only stopped AI worker"
fi
grep -q 'Update                    : available' "$WORKDIR/drift-stopped.out" || fail "stopped AI worker was not-needed"
grep -q 'State mutation           : NO' "$WORKDIR/drift-stopped.out" || fail "stopped check-only mutated"
grep -qx 'is-active drlink-ai-agent' "$LOG" || fail "stopped check-only skipped is-active"
assert_readonly_systemd_log "stopped check-only"
[[ "$(file_sha "$DRIFT/etc/systemd/system/drlink-ai-agent.service")" == "$AI_BYTES" ]] || fail "stopped check-only changed AI unit"
pass "CHECK_ONLY_REPORTS_DISABLED_OR_STOPPED_AI_WORKER"
: >"$LOG"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/drift-repair.out" 2>"$WORKDIR/drift-repair.err"; then
  cat "$WORKDIR/drift-repair.out" "$WORKDIR/drift-repair.err" >&2
  fail "repair stopped AI worker"
fi
grep -q 'AI agent service : converged' "$WORKDIR/drift-repair.out" || fail "repair did not converge AI worker"
grep -q 'frpc restarted  : NO' "$WORKDIR/drift-repair.out" || fail "service repair restarted frpc"
grep -qx 'daemon-reload' "$LOG" || fail "service repair skipped daemon-reload"
grep -qx 'enable drlink-ai-agent' "$LOG" || fail "service repair did not enable AI worker"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "service repair did not restart AI worker"
if grep -qx 'restart drlink-client' "$LOG"; then fail "service repair restarted the relay"; fi
[[ "$(file_sha "$DRIFT/etc/systemd/system/drlink-ai-agent.service")" == "$AI_BYTES" ]] || fail "repair rewrote canonical AI unit"
[[ "$(file_sha "$DRIFT/etc/systemd/system/drlink-client.service")" == "$CLIENT_BYTES" ]] || fail "repair rewrote client unit"
[[ "$(file_sha "$DRIFT/etc/frp/client-state.json")" == "$STATE_BYTES" ]] || fail "repair changed client state"
[[ "$(cat "$DRIFT_MODE")" == "repair" ]] || fail "repair did not restart the AI worker"
: >"$LOG"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/drift-again.out" 2>"$WORKDIR/drift-again.err"; then
  cat "$WORKDIR/drift-again.out" "$WORKDIR/drift-again.err" >&2
  fail "repaired AI worker refresh"
fi
grep -q 'Update                    : not needed' "$WORKDIR/drift-again.out" || fail "repaired AI worker still needed"
assert_readonly_systemd_log "repaired refresh"
pass "APPLY_REPAIRS_STOPPED_AI_WORKER_WITHOUT_FRPC_RESTART"
unset FRP_BUNDLE_SHA256
