#!/usr/bin/env bash
# Role-aware frpctl dispatcher and persistent CLI. Uses fixtures; does not
# mutate a live host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

chmod +x "$ROOT/tools/frpctl" "$ROOT/tools/frp-client"

CTL="$ROOT/tools/frpctl"
export FRP_CTL_FORCE_DRLINK=1
export FRP_CTL_CMD_NAME=drlink
export FRP_CTL_BIN_DIR="$ROOT/tools"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_SKIP_SYSTEMD=1
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

write_client_tree() {
  local tree="$1"
  mkdir -p "$tree/etc/frp" "$tree/etc/drlink"
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://127.0.0.1:9/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "ctl-client",
    "machine_id": "00112233445566778899aabbccddeeff",
    "host_id": "ctl-client-00112233",
    "services": {
        "ssh": {
            "id": "ssh", "name": "SSH", "preset": "ssh", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 6002,
            "enabled": True, "ssh_user": "aella",
        }
    },
}, indent=2, sort_keys=True) + "\n")
PY
  cat >"$tree/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.4.0
FRP_VERSION=0.71.0
EOF
}

write_server_tree() {
  local tree="$1"
  mkdir -p "$tree/etc/drlink" "$tree/var/lib/drlink"
  python3 - "$tree/etc/drlink/config.json" "$tree/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
cfg, reg = Path(sys.argv[1]), Path(sys.argv[2])
cfg.write_text(json.dumps({
    "public_ip": "203.0.113.10",
    "control_port": 443,
    "port_start": 6000,
    "port_end": 6098,
    "listen_port": 6099,
    "allocator_public_url": "https://203.0.113.10:6099/enroll",
    "registry_file": "/var/lib/drlink/registry.json",
}, indent=2, sort_keys=True) + "\n")
reg.write_text(json.dumps({
    "schema_version": 2,
    "reserved": [],
    "clients": {
        "aabbccdd0011": {
            "hostname": "dp-os-upgrade",
            "label": "oci-e2e-renamed",
            "mgmt_status": "enrolled",
            "services": {
                "ssh": {"id": "ssh", "remote_port": 6000, "enabled": True},
            },
        },
    },
}, indent=2, sort_keys=True) + "\n")
PY
  cat >"$tree/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.4.0
FRP_VERSION=0.71.0
EOF
}

prompt_count() {
  grep -cE '^(frpctl|drlink)>' "$1"
}

run_repl() {
  local tree="$1" outfile="$2" rc
  shift 2
  export FRP_CTL_TEST_ROOT="$tree"
  FRP_CTL_TEST_INPUT="$(printf '%s\n' "$@")"
  export FRP_CTL_TEST_INPUT
  set +e
  "$CTL" >"$outfile" 2>"${outfile}.err"
  rc=$?
  set -e
  cat "${outfile}.err" >>"$outfile"
  return "$rc"
}

CLIENT="$WORKDIR/client"
SERVER="$WORKDIR/server"
BOTH="$WORKDIR/both"
write_client_tree "$CLIENT"
write_server_tree "$SERVER"
write_client_tree "$BOTH"
write_server_tree "$BOTH"

# --- Help / unknown (direct mode)
"$CTL" help >"$WORKDIR/help.out"
grep -q 'Grammar: <resource> <action>' "$WORKDIR/help.out" || fail "help grammar line"
grep -qE 'status[[:space:]]+Host status' "$WORKDIR/help.out" || fail "help status resource"
grep -q 'doctor' "$WORKDIR/help.out" || fail "help doctor"
grep -qE 'Tab|help workflows|Navigation' "$WORKDIR/help.out" || fail "help discovery hint"
# Role-aware root help: server tree includes egress
export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_DEPLOY_TEST_ROOT="$SERVER"
"$CTL" help >"$WORKDIR/help-server.out"
grep -q 'egress' "$WORKDIR/help-server.out" || fail "server help egress resource"
unset FRP_CTL_TEST_ROOT FRP_DEPLOY_TEST_ROOT
"$CTL" --help >"$WORKDIR/help2.out"
grep -qE 'Usage: (drlink|frpctl)' "$WORKDIR/help2.out" || fail "--help usage"
grep -q 'only command you need to remember' "$WORKDIR/help2.out" || fail "--help remember line"
grep -q 'frps' "$WORKDIR/help2.out" || fail "--help mentions frps"
grep -q 'frpc' "$WORKDIR/help2.out" || fail "--help mentions frpc"
if "$CTL" definitely-not-a-command >"$WORKDIR/unknown.out" 2>"$WORKDIR/unknown.err"; then
  fail "unknown command should fail"
fi
grep -q 'unknown command' "$WORKDIR/unknown.err" || fail "unknown error"
grep -qE 'Usage: (drlink|frpctl)' "$WORKDIR/unknown.err" || fail "unknown usage"
pass "FRPCTL_HELP"
pass "FRPCTL_UNKNOWN_COMMAND_RECOVERY"

# --- Direct client role
export FRP_CTL_TEST_ROOT="$CLIENT"
export FRP_CLIENT_TEST_ROOT="$CLIENT"
"$CTL" status >"$WORKDIR/client-status.out"
grep -q 'Data Relay Link Client' "$WORKDIR/client-status.out" || fail "client status header"
grep -q 'Hostname        : ctl-client' "$WORKDIR/client-status.out" || fail "client status hostname"
pass "FRPCTL_CLIENT_STATUS"

export FRP_CTL_DRY_RUN=1
"$CTL" manage >"$WORKDIR/client-manage.out"
grep -qx 'DISPATCH frp-client' "$WORKDIR/client-manage.out" || fail "manage dispatch"
set +e
"$CTL" update >"$WORKDIR/client-update.out" 2>"$WORKDIR/client-update.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "bare client update should not mutate"
grep -qiE 'Missing action|project|engine' "$WORKDIR/client-update.out" "$WORKDIR/client-update.err" \
  || fail "bare client update discovery"
"$CTL" update project --check >"$WORKDIR/client-upd-proj.out" || true
"$CTL" update frp --check >"$WORKDIR/client-upd-frp.out"
grep -qx 'DISPATCH frp-update --check' "$WORKDIR/client-upd-frp.out" || fail "client update frp"
"$CTL" info >"$WORKDIR/client-info.out"
grep -qx 'DISPATCH frp-client info' "$WORKDIR/client-info.out" || fail "info dispatch"
"$CTL" services >"$WORKDIR/client-services.out"
grep -qx 'DISPATCH frp-client list' "$WORKDIR/client-services.out" || fail "services dispatch"
unset FRP_CTL_DRY_RUN
pass "FRPCTL_CLIENT_MANAGE_DISPATCH"
pass "FRPCTL_CLIENT_UPDATE_DISPATCH"
pass "FRPCTL_CLIENT_UPDATE_FRP"

if "$CTL" clients >"$WORKDIR/client-clients.out" 2>"$WORKDIR/client-clients.err"; then
  fail "client host should reject server clients command"
fi
grep -q 'installed Data Relay Link server' "$WORKDIR/client-clients.err" || fail "client reject server command"

# --- Direct server role
unset FRP_CLIENT_TEST_ROOT
export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_CTL_DRY_RUN=1
export FRP_UPDATE_TEST_HARNESS=0
"$CTL" status >"$WORKDIR/server-status.out"
grep -qx 'DISPATCH frp-server-status' "$WORKDIR/server-status.out" || fail "server status dispatch"
"$CTL" clients >"$WORKDIR/server-clients.out"
grep -qx 'DISPATCH frp-clients' "$WORKDIR/server-clients.out" || fail "clients dispatch"
"$CTL" create-client >"$WORKDIR/server-create.out"
grep -qx 'DISPATCH frp-create-client' "$WORKDIR/server-create.out" || fail "create-client dispatch"
"$CTL" enroll >"$WORKDIR/server-enroll.out"
grep -qx 'DISPATCH frp-create-client' "$WORKDIR/server-enroll.out" || fail "enroll dispatch"
"$CTL" enroll --one-line --ssh >"$WORKDIR/server-enroll-ssh.out"
grep -Eqx 'DISPATCH frp-create-client( --platform linux)? --one-line --ssh' "$WORKDIR/server-enroll-ssh.out" \
  || fail "enroll --one-line --ssh dispatch"
pass "FRPCTL_ENROLL_ONE_LINE_DISPATCH"
"$CTL" client-info customer-dp >"$WORKDIR/server-info.out"
grep -qx 'DISPATCH frp-client-info customer-dp' "$WORKDIR/server-info.out" || fail "client-info dispatch"
"$CTL" client customer-dp >"$WORKDIR/server-client.out"
grep -qx 'DISPATCH frp-client-info customer-dp' "$WORKDIR/server-client.out" || fail "client alias dispatch"
"$CTL" revoke-client customer-dp >"$WORKDIR/server-revoke.out"
grep -qx 'DISPATCH frp-revoke-client customer-dp' "$WORKDIR/server-revoke.out" || fail "revoke dispatch"
"$CTL" revoke customer-dp >"$WORKDIR/server-revoke2.out"
grep -qx 'DISPATCH frp-revoke-client customer-dp' "$WORKDIR/server-revoke2.out" || fail "revoke alias dispatch"
"$CTL" release-service customer-dp grafana >"$WORKDIR/server-relsvc.out"
grep -qx 'DISPATCH frp-release-service customer-dp grafana' "$WORKDIR/server-relsvc.out" || fail "release-service dispatch"
"$CTL" release-client customer-dp >"$WORKDIR/server-relcli.out"
grep -qx 'DISPATCH frp-release-client customer-dp' "$WORKDIR/server-relcli.out" || fail "release-client dispatch"
set +e
"$CTL" update >"$WORKDIR/server-update.out" 2>"$WORKDIR/server-update.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "bare server update should not mutate"
grep -qiE 'Missing action|project|engine' "$WORKDIR/server-update.out" "$WORKDIR/server-update.err" \
  || fail "bare server update discovery"
"$CTL" update engine --check >"$WORKDIR/server-update-engine.out"
grep -qx 'DISPATCH frp-update --check' "$WORKDIR/server-update-engine.out" || fail "server update engine dispatch"
unset FRP_CTL_DRY_RUN
pass "FRPCTL_SERVER_STATUS"
pass "FRPCTL_CLIENTS_DISPATCH"
pass "FRPCTL_CREATE_CLIENT_DISPATCH"
pass "FRPCTL_REVOKE_DISPATCH"
pass "FRPCTL_RELEASE_SERVICE_DISPATCH"
pass "FRPCTL_DIRECT_COMMANDS_PRESERVED"

for cmd in frp-client frp-clients frp-client-info frp-client-set frp-create-client \
  frp-release-client frp-release-service frp-revoke-client \
  frp-server-status frp-update frp-project-update frp-backup frp-restore \
  frp-enrollments frp-enroll-bulk frp-enrollment-revoke frp-upstream \
  frp-set-client-installer-url frp-server-set; do
  [[ -e "$ROOT/tools/$cmd" ]] || fail "missing command $cmd"
done
pass "EXISTING_COMMANDS_PRESERVED"

export FRP_CTL_TEST_ROOT="$BOTH"
export FRP_CTL_DRY_RUN=1
"$CTL" status >"$WORKDIR/both-status.out"
grep -q 'DISPATCH frp-client status' "$WORKDIR/both-status.out" || fail "both status client"
grep -q 'DISPATCH frp-server-status' "$WORKDIR/both-status.out" || fail "both status server"
unset FRP_CTL_DRY_RUN

# --- Guided menu still available via `menu`
export FRP_CLIENT_TEST_ROOT="$CLIENT"
export FRP_CTL_TEST_ROOT="$CLIENT"
export FRP_CTL_TEST_MENU=1
run_repl "$CLIENT" "$WORKDIR/client-menu.out" menu exit || fail "client menu repl"
unset FRP_CTL_TEST_MENU
grep -q 'Role            : Client' "$WORKDIR/client-menu.out" || fail "client role"
grep -q 'Project version : 1.4.0' "$WORKDIR/client-menu.out" || fail "client menu version"
grep -q '4) Manage services' "$WORKDIR/client-menu.out" || fail "client menu manage"
grep -q '5) Update project' "$WORKDIR/client-menu.out" || fail "client menu update"
[[ "$(prompt_count "$WORKDIR/client-menu.out")" -ge 2 ]] || fail "menu returns to prompt"
pass "FRPCTL_CLIENT_DETECTION"
pass "FRPCTL_REPL_MENU_RETURNS_TO_PROMPT"

unset FRP_CLIENT_TEST_ROOT
export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_CTL_TEST_MENU=1
run_repl "$SERVER" "$WORKDIR/server-menu.out" menu exit || fail "server menu repl"
grep -q 'Role            : Server' "$WORKDIR/server-menu.out" || fail "server role"
grep -q '2) Manage clients' "$WORKDIR/server-menu.out" || fail "server menu manage clients"
grep -q '7) Access Control' "$WORKDIR/server-menu.out" || fail "server menu access control"
grep -q '9) Update FRP' "$WORKDIR/server-menu.out" || fail "server menu frp update"
pass "FRPCTL_SERVER_DETECTION"

unset FRP_CTL_TEST_MENU
export FRP_CTL_TEST_ROOT="$BOTH"
export FRP_CTL_TEST_MENU=1
run_repl "$BOTH" "$WORKDIR/both-menu.out" menu exit || fail "both menu repl"
grep -q 'Role            : Client + Server' "$WORKDIR/both-menu.out" || fail "both role"
grep -q '1) Client operations' "$WORKDIR/both-menu.out" || fail "both menu"
unset FRP_CTL_TEST_MENU
pass "FRPCTL_REPL_START_DUAL_ROLE"

# --- Persistent CLI: client
unset FRP_CTL_DRY_RUN
export FRP_CLIENT_TEST_ROOT="$CLIENT"
run_repl "$CLIENT" "$WORKDIR/client-repl.out" status help version exit || fail "client repl"
grep -q 'Data Relay Link' "$WORKDIR/client-repl.out" || fail "client repl banner"
grep -q 'Role            : Client' "$WORKDIR/client-repl.out" || fail "client repl role"
grep -q 'Project version : 1.4.0' "$WORKDIR/client-repl.out" || fail "client repl version"
grep -q 'FRP version     : 0.71.0' "$WORKDIR/client-repl.out" || fail "client repl frp version"
grep -q "Type '?' for a short command list, or 'help' for full syntax." "$WORKDIR/client-repl.out" || fail "client repl hint"
[[ "$(prompt_count "$WORKDIR/client-repl.out")" -ge 3 ]] || fail "client repl stays after status/help"
grep -q 'Data Relay Link Client' "$WORKDIR/client-repl.out" || fail "client repl status body"
grep -q 'Data Relay Link — Client Commands' "$WORKDIR/client-repl.out" || fail "client repl help"
grep -qE 'service|client' "$WORKDIR/client-repl.out" || fail "client help service"
pass "FRPCTL_REPL_START_CLIENT"
pass "FRPCTL_REPL_HELP"
pass "FRPCTL_REPL_VERSION"
pass "FRPCTL_REPL_STATUS"
pass "FRPCTL_REPL_EXIT"

run_repl "$CLIENT" "$WORKDIR/client-qhelp.out" '?' exit || fail "client ? help"
grep -qE 'service|client' "$WORKDIR/client-qhelp.out" || fail "question mark help service"
grep -qE 'status|update|doctor' "$WORKDIR/client-qhelp.out" || fail "question mark help ops"
if grep -q 'Grammar: <verb>' "$WORKDIR/client-qhelp.out"; then
  fail "root ? dumped full syntax tree"
fi
pass "FRPCTL_REPL_QUESTION_MARK_HELP"

export FRP_CTL_DRY_RUN=1
run_repl "$CLIENT" "$WORKDIR/client-svc.out" services exit || fail "client services"
grep -q 'DISPATCH frp-client list' "$WORKDIR/client-svc.out" || fail "repl services dispatch"
pass "FRPCTL_REPL_CLIENT_SERVICES"
unset FRP_CTL_DRY_RUN

# manage must return to the prompt (no exec)
MOCKBIN="$WORKDIR/mockbin"
mkdir -p "$MOCKBIN"
cat >"$MOCKBIN/frp-client" <<EOF
#!/bin/bash
echo "MOCK-FRP-CLIENT \$*"
echo "frp-client" >> "$WORKDIR/manage.log"
exit 0
EOF
chmod +x "$MOCKBIN/frp-client"
SAVE_BIN="${FRP_CTL_BIN_DIR}"
export FRP_CTL_BIN_DIR="$MOCKBIN"
: >"$WORKDIR/manage.log"
run_repl "$CLIENT" "$WORKDIR/client-manage-repl.out" manage exit || fail "client manage repl"
grep -q 'MOCK-FRP-CLIENT' "$WORKDIR/client-manage-repl.out" || fail "manage invoked frp-client"
[[ "$(prompt_count "$WORKDIR/client-manage-repl.out")" -ge 2 ]] || fail "manage did not return to prompt"
grep -qx 'frp-client' "$WORKDIR/manage.log" || fail "manage mock log"
pass "FRPCTL_REPL_CLIENT_MANAGE_RETURNS_TO_PROMPT"
export FRP_CTL_BIN_DIR="$SAVE_BIN"

# --- Persistent CLI: server
unset FRP_CLIENT_TEST_ROOT
export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/server-repl.out" status help version exit || fail "server repl"
grep -q 'Data Relay Link' "$WORKDIR/server-repl.out" || fail "server repl banner"
grep -q 'Role            : Server' "$WORKDIR/server-repl.out" || fail "server repl role"
grep -q 'DISPATCH frp-server-status' "$WORKDIR/server-repl.out" || fail "server repl status"
grep -q 'Data Relay Link — Server Commands' "$WORKDIR/server-repl.out" || fail "server repl help"
grep -q 'enroll' "$WORKDIR/server-repl.out" || fail "server help enroll"
[[ "$(prompt_count "$WORKDIR/server-repl.out")" -ge 3 ]] || fail "server repl persistent"
pass "FRPCTL_REPL_START_SERVER"

run_repl "$SERVER" "$WORKDIR/server-cmds.out" \
  clients \
  "client dp-os-upgrade" \
  enroll \
  "revoke dp-os-upgrade" \
  "release-service dp-os-upgrade e2e-ssh" \
  "release-client dp-os-upgrade" \
  exit || fail "server cmds"
grep -q 'DISPATCH frp-clients' "$WORKDIR/server-cmds.out" || fail "repl clients"
grep -q 'DISPATCH frp-client-info dp-os-upgrade' "$WORKDIR/server-cmds.out" || fail "repl client info"
grep -q 'DISPATCH frp-create-client' "$WORKDIR/server-cmds.out" || fail "repl enroll"
grep -q 'DISPATCH frp-revoke-client dp-os-upgrade' "$WORKDIR/server-cmds.out" || fail "repl revoke"
grep -q 'DISPATCH frp-release-service dp-os-upgrade e2e-ssh' "$WORKDIR/server-cmds.out" || fail "repl release-service"
grep -q 'DISPATCH frp-release-client dp-os-upgrade' "$WORKDIR/server-cmds.out" || fail "repl release-client"
[[ "$(prompt_count "$WORKDIR/server-cmds.out")" -ge 6 ]] || fail "server cmds returned to prompt"
pass "FRPCTL_REPL_SERVER_CLIENTS"
pass "FRPCTL_REPL_SERVER_CLIENT_INFO"
pass "FRPCTL_REPL_SERVER_ENROLL_DISPATCH"

export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/guided-enroll.out" menu 3 1 zt-ssh-client "" aella "" 17 exit \
  || fail "guided enroll zero-touch"
grep -q 'Create enrollment' "$WORKDIR/guided-enroll.out" || fail "guided enroll heading"
grep -q 'Zero-touch SSH' "$WORKDIR/guided-enroll.out" || fail "guided enroll zero-touch option"
grep -q 'Manual Enrollment Code' "$WORKDIR/guided-enroll.out" || fail "guided enroll manual option"
grep -Eq 'DISPATCH frp-create-client( --platform linux)? --one-line --ssh --ssh-user aella --ssh-port 22 --client-name zt-ssh-client' \
  "$WORKDIR/guided-enroll.out" \
  || fail "guided enroll did not dispatch zero-touch"
pass "FRPCTL_GUIDED_ENROLL_ZERO_TOUCH"

run_repl "$SERVER" "$WORKDIR/guided-enroll-manual.out" menu 3 2 17 exit || fail "guided enroll manual"
grep -q 'DISPATCH frp-create-client' "$WORKDIR/guided-enroll-manual.out" \
  || fail "guided enroll manual dispatch"
if grep -q 'DISPATCH frp-create-client --one-line' "$WORKDIR/guided-enroll-manual.out"; then
  fail "manual enroll used zero-touch flags"
fi
pass "FRPCTL_GUIDED_ENROLL_MANUAL"

export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/enroll-oneline.out" "enroll --one-line --ssh" exit \
  || fail "repl enroll --one-line --ssh"
grep -Eq 'DISPATCH frp-create-client( --platform linux)? --one-line --ssh' "$WORKDIR/enroll-oneline.out" \
  || fail "enroll --one-line --ssh dispatch"
pass "FRPCTL_ENROLL_ONE_LINE_SSH"
pass "FRPCTL_REPL_SERVER_REVOKE_DISPATCH"
pass "FRPCTL_REPL_SERVER_RELEASE_SERVICE_DISPATCH"
pass "FRPCTL_REPL_SERVER_RELEASE_CLIENT_DISPATCH"
pass "SERVER_COMMANDS_RETURN_TO_REPL"
unset FRP_CTL_DRY_RUN

# --- Invalid command recovery
unset FRP_CLIENT_TEST_ROOT
export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/badcmd.out" clints status exit || fail "invalid command recovery"
grep -q 'Unknown command: clints' "$WORKDIR/badcmd.out" || fail "unknown clints"
grep -q 'Did you mean:' "$WORKDIR/badcmd.out" || fail "did you mean header"
grep -q '  clients' "$WORKDIR/badcmd.out" || fail "did you mean clients"
grep -q "Type 'help' for available commands." "$WORKDIR/badcmd.out" || fail "unknown help hint"
grep -q 'DISPATCH frp-server-status' "$WORKDIR/badcmd.out" || fail "status after unknown"
[[ "$(prompt_count "$WORKDIR/badcmd.out")" -ge 3 ]] || fail "unknown stayed in cli"
pass "FRPCTL_REPL_INVALID_COMMAND_RECOVERY"
unset FRP_CTL_DRY_RUN

# --- Invalid argument recovery
unset FRP_CLIENT_TEST_ROOT
export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/badargs.out" client "release-service dp-os-upgrade" clients exit || fail "bad args"
grep -q 'ERROR: usage: client <name>' "$WORKDIR/badargs.out" || fail "client usage"
grep -q 'ERROR: usage: release-service <client> <service-id>' "$WORKDIR/badargs.out" || fail "release-service usage"
grep -q 'DISPATCH frp-clients' "$WORKDIR/badargs.out" || fail "clients after bad args"
[[ "$(prompt_count "$WORKDIR/badargs.out")" -ge 4 ]] || fail "bad args stayed in cli"
pass "FRPCTL_REPL_INVALID_ARGUMENT_RECOVERY"
unset FRP_CTL_DRY_RUN

# --- Child failure recovery
FAILBIN="$WORKDIR/failbin"
mkdir -p "$FAILBIN"
cat >"$FAILBIN/frp-client-info" <<'EOF'
#!/bin/bash
echo "ERROR: no such client" >&2
exit 1
EOF
cat >"$FAILBIN/frp-clients" <<'EOF'
#!/bin/bash
echo "HOSTNAME ..."
exit 0
EOF
chmod +x "$FAILBIN/frp-client-info" "$FAILBIN/frp-clients"
export FRP_CTL_BIN_DIR="$FAILBIN"
run_repl "$SERVER" "$WORKDIR/childfail.out" "client nonexistent" clients exit || fail "child fail repl"
grep -q 'ERROR: no such client' "$WORKDIR/childfail.out" || fail "child error shown"
grep -q 'Command failed with exit code 1.' "$WORKDIR/childfail.out" || fail "child fail message"
grep -q 'HOSTNAME ...' "$WORKDIR/childfail.out" || fail "later command after child fail"
[[ "$(prompt_count "$WORKDIR/childfail.out")" -ge 3 ]] || fail "child fail stayed in cli"
pass "FRPCTL_REPL_CHILD_FAILURE_RECOVERY"
export FRP_CTL_BIN_DIR="$SAVE_BIN"

# --- quit / EOF
export FRP_CLIENT_TEST_ROOT="$CLIENT"
run_repl "$CLIENT" "$WORKDIR/quit.out" quit || fail "quit"
grep -q 'Data Relay Link' "$WORKDIR/quit.out" || fail "quit banner"
[[ "$(prompt_count "$WORKDIR/quit.out")" -ge 1 ]] || fail "quit prompt"
pass "FRPCTL_REPL_QUIT"

run_repl "$CLIENT" "$WORKDIR/eof.out" status || fail "eof exit"
grep -q 'Data Relay Link Client' "$WORKDIR/eof.out" || fail "eof ran status"
pass "FRPCTL_REPL_EOF_EXIT"

# --- No TTY
unset FRP_CTL_TEST_INPUT
export FRP_CTL_TEST_ROOT="$CLIENT"
export FRP_CLIENT_TEST_ROOT="$CLIENT"
set +e
"$CTL" </dev/null >"$WORKDIR/notty.out" 2>"$WORKDIR/notty.err"
notty_rc=$?
set -e
[[ "$notty_rc" -ne 0 ]] || fail "no-tty interactive should fail"
grep -qE "interactive (frpctl|drlink) requires a TTY" "$WORKDIR/notty.err" || fail "no-tty message"
grep -qE "Use: (frpctl|drlink) <command>" "$WORKDIR/notty.err" || fail "no-tty hint"
pass "FRPCTL_NO_TTY_INTERACTIVE_FAILS_CLEANLY"

"$CTL" status </dev/null >"$WORKDIR/notty-status.out"
grep -q 'Data Relay Link Client' "$WORKDIR/notty-status.out" || fail "no-tty direct status"
pass "FRPCTL_NO_TTY_DIRECT_MODE"
pass "FRPCTL_NO_TTY_HANDLING"

# --- No arbitrary shell execution
unset FRP_CLIENT_TEST_ROOT
export FRP_CTL_TEST_ROOT="$SERVER"
CANARY="$WORKDIR/canary.txt"
run_repl "$SERVER" "$WORKDIR/noshell.out" \
  '!ls' \
  shell \
  exec \
  bash \
  "/bin/touch ${CANARY}" \
  exit || fail "noshell repl"
grep -q 'arbitrary shell execution is not allowed' "$WORKDIR/noshell.out" || fail "shell rejected"
grep -q 'Unknown command: /bin/touch' "$WORKDIR/noshell.out" || fail "path command unknown"
[[ ! -f "$CANARY" ]] || fail "canary created"
if grep -nE '(^|[[:space:]])eval |bash -c |sh -c |system\(' "$ROOT/tools/frpctl"; then
  fail "frpctl uses unsafe command dispatch"
fi
pass "NO_ARBITRARY_SHELL_EXECUTION"
pass "NO_EVAL_DISPATCH"

# --- No persistent history
[[ ! -f "$HOME/.frpctl_history" ]] || fail "frpctl history file created"
[[ ! -f "$HOME/.bash_history" ]] || fail "bash history file created"
grep -q 'unset HISTFILE' "$ROOT/tools/frpctl" || fail "HISTFILE is not unset"
if grep -qE 'HISTFILE=' "$ROOT/tools/frpctl"; then
  fail "frpctl assigns HISTFILE"
fi
if grep -qE 'history -[aw]' "$ROOT/tools/frpctl"; then
  fail "frpctl persists history to disk"
fi
pass "NO_PERSISTENT_HISTORY"

# Dual-role help
run_repl "$BOTH" "$WORKDIR/both-help.out" help exit || fail "both help"
grep -q 'Client commands' "$WORKDIR/both-help.out" || fail "dual client section"
grep -q 'Server commands' "$WORKDIR/both-help.out" || fail "dual server section"
grep -q 'Common commands' "$WORKDIR/both-help.out" || fail "dual common section"

# --- Canonical grammar
unset FRP_CLIENT_TEST_ROOT
export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_CTL_DRY_RUN=1
"$CTL" show clients >"$WORKDIR/show-clients.out"
grep -qx 'DISPATCH frp-clients' "$WORKDIR/show-clients.out" || fail "show clients"
"$CTL" show client customer-dp >"$WORKDIR/show-client.out"
grep -qx 'DISPATCH frp-client-info customer-dp overview' "$WORKDIR/show-client.out" || fail "show client"
"$CTL" set client customer-dp label production >"$WORKDIR/set-label.out"
grep -qx 'DISPATCH frp-client-set customer-dp --label production' "$WORKDIR/set-label.out" || fail "set client label"
"$CTL" set client customer-dp tag env=oci >"$WORKDIR/set-tag.out"
grep -qx 'DISPATCH frp-client-set customer-dp --tag env=oci' "$WORKDIR/set-tag.out" || fail "set client tag"
"$CTL" unset client customer-dp label >"$WORKDIR/unset-label.out"
grep -qx 'DISPATCH frp-client-set customer-dp --clear-label' "$WORKDIR/unset-label.out" || fail "unset label"
"$CTL" unset client customer-dp tag env >"$WORKDIR/unset-tag.out"
grep -qx 'DISPATCH frp-client-set customer-dp --remove-tag env' "$WORKDIR/unset-tag.out" || fail "unset tag"
"$CTL" create enrollment --ssh --ssh-user aella --label dp01 >"$WORKDIR/create-enroll.out"
grep -qx 'DISPATCH frp-create-client --ssh --ssh-user aella --label dp01' "$WORKDIR/create-enroll.out" || fail "create enrollment"
"$CTL" revoke client customer-dp >"$WORKDIR/revoke-c.out"
grep -qx 'DISPATCH frp-revoke-client customer-dp' "$WORKDIR/revoke-c.out" || fail "revoke client"
"$CTL" release service customer-dp ssh >"$WORKDIR/rel-svc.out"
grep -qx 'DISPATCH frp-release-service customer-dp ssh' "$WORKDIR/rel-svc.out" || fail "release service"
"$CTL" update project --check >"$WORKDIR/upd-proj.out"
grep -qx 'DISPATCH frp-project-update --check' "$WORKDIR/upd-proj.out" || fail "update project"
"$CTL" update frp --check >"$WORKDIR/upd-frp.out"
grep -qx 'DISPATCH frp-update --check' "$WORKDIR/upd-frp.out" || fail "update frp"
unset FRP_CTL_DRY_RUN
pass "FRPCTL_SHOW_COMMANDS"
pass "FRPCTL_SET_COMMANDS"
pass "FRPCTL_UNSET_COMMANDS"
pass "FRPCTL_CREATE_COMMANDS"
pass "FRPCTL_LIFECYCLE_COMMANDS"
pass "FRPCTL_UPDATE_COMMANDS"

run_repl "$SERVER" "$WORKDIR/incomplete.out" "set client oci-e2e-renamed" exit || fail "incomplete set"
grep -q 'Missing client setting' "$WORKDIR/incomplete.out" || fail "incomplete message"
grep -q 'set client <ID> label <value>' "$WORKDIR/incomplete.out" || fail "incomplete usage"
pass "FRPCTL_INCOMPLETE_SET"

export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/quoted.out" 'set client dp01 note "OCI E2E client"' exit || fail "quoted note"
grep -q 'DISPATCH frp-client-set dp01 --note OCI E2E client' "$WORKDIR/quoted.out" || fail "quoted note dispatch"
run_repl "$SERVER" "$WORKDIR/singleq.out" "set client dp01 label 'Seoul DP'" exit || fail "single quote"
grep -q "DISPATCH frp-client-set dp01 --label Seoul DP" "$WORKDIR/singleq.out" || fail "single quote dispatch"
unset FRP_CTL_DRY_RUN
pass "FRPCTL_QUOTED_VALUE"
pass "FRPCTL_SINGLE_QUOTE_VALUE"
pass "FRPCTL_SPACE_IN_NOTE"
pass "FRPCTL_SPACE_IN_LABEL"

run_repl "$SERVER" "$WORKDIR/meta.out" 'set client dp01 note $HOME' exit || fail "meta reject repl"
grep -qi 'metacharacter' "$WORKDIR/meta.out" || fail "metacharacter rejected"
pass "NO_SHELL_EXPANSION"

run_repl "$SERVER" "$WORKDIR/hist.out" "show clients" "history" exit || fail "history cmd"
grep -q 'show clients' "$WORKDIR/hist.out" || fail "session history listing"
pass "FRPCTL_SESSION_HISTORY"

# Compatibility aliases still dispatch
export FRP_CTL_DRY_RUN=1
"$CTL" clients >"$WORKDIR/legacy-clients.out"
grep -qx 'DISPATCH frp-clients' "$WORKDIR/legacy-clients.out" || fail "legacy clients"
"$CTL" client-set customer-dp --label x >"$WORKDIR/legacy-set.out"
grep -qx 'DISPATCH frp-client-set customer-dp --label x' "$WORKDIR/legacy-set.out" || fail "legacy client-set"
unset FRP_CTL_DRY_RUN
pass "FRPCTL_LEGACY_ALIAS_COMPATIBILITY"
pass "BACKWARD_COMPATIBILITY"
pass "DIRECT_SCRIPT_COMPATIBILITY"

# Hierarchical help
export FRP_CTL_TEST_ROOT="$SERVER"
run_repl "$SERVER" "$WORKDIR/help-set.out" "help set client" exit || fail "help set client"
grep -q 'Set client configuration' "$WORKDIR/help-set.out" || fail "help set heading"
grep -q 'set client <ID> tag' "$WORKDIR/help-set.out" || fail "help set tag"
pass "CONTEXT_HELP"

run_repl "$SERVER" "$WORKDIR/help-legacy.out" "help legacy" exit || fail "help legacy"
grep -q 'Compatibility aliases' "$WORKDIR/help-legacy.out" || fail "legacy help heading"
pass "FRPCTL_HELP_LEGACY"

run_repl "$SERVER" "$WORKDIR/glob.out" 'show clients *' exit || fail "glob reject repl"
grep -qi 'metacharacter\|could not parse' "$WORKDIR/glob.out" || fail "glob not rejected"
run_repl "$SERVER" "$WORKDIR/sub.out" 'show clients $(whoami)' exit || fail "subst reject repl"
grep -qi 'metacharacter\|could not parse' "$WORKDIR/sub.out" || fail "command substitution not rejected"
pass "NO_GLOB_EXPANSION"
pass "NO_COMMAND_SUBSTITUTION"
pass "NO_EVAL"
pass "NO_SHELL_EXECUTION"
pass "SAFE_TOKENIZER"

export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/secret-hist.out" \
  "show clients" \
  "set client dp01 note ticket-secret-value" \
  history \
  exit || fail "secret history repl"
unset FRP_CTL_DRY_RUN
grep -qE '^[[:space:]]*[0-9]+[[:space:]]+show clients$' "$WORKDIR/secret-hist.out" \
  || fail "normal command missing from history"
if grep -qE '^[[:space:]]*[0-9]+[[:space:]]+.*ticket-secret-value' "$WORKDIR/secret-hist.out"; then
  fail "secret-bearing line stored in session history listing"
fi
pass "NO_SECRET_HISTORY_PERSISTENCE"

export FRP_CTL_DRY_RUN=1
run_repl "$SERVER" "$WORKDIR/guided-meta.out" menu 2 1 12 12 exit || fail "guided metadata menu"
grep -q 'Set label' "$WORKDIR/guided-meta.out" || fail "guided set label"
grep -q 'Unset label' "$WORKDIR/guided-meta.out" || fail "guided unset label"
grep -q 'Set description' "$WORKDIR/guided-meta.out" || fail "guided set description"
grep -q 'Unset description' "$WORKDIR/guided-meta.out" || fail "guided unset description"
grep -q 'Set tag' "$WORKDIR/guided-meta.out" || fail "guided set tag"
grep -q 'Unset tag' "$WORKDIR/guided-meta.out" || fail "guided unset tag"
grep -q 'Revoke management access' "$WORKDIR/guided-meta.out" || fail "guided revoke"
grep -q 'Release client' "$WORKDIR/guided-meta.out" || fail "guided release"
unset FRP_CTL_DRY_RUN
pass "GUIDED_MENU_METADATA"
pass "GUIDED_MENU_TAGS"
pass "GUIDED_MENU_UPDATED"

# --- Canonical CLIENT ID selector (real tools, not dry-run)
python3 - "$SERVER/var/lib/drlink/registry.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
data = json.loads(p.read_text())
data["clients"]["24cd7856aabbccdd0011223344556677"] = {
    "hostname": "dp-os-upgrade-2",
    "label": "aaa",
    "mgmt_status": "enrolled",
    "mgmt_mac_key": "SECRET_MAC_SELECTOR_AAA",
    "tags": {"env": "oci", "stage": "acceptance"},
    "note": "acceptance box",
    "services": {
        "ssh": {
            "id": "ssh", "remote_port": 6001, "enabled": True,
            "preset": "ssh", "ssh_user": "aella", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 22,
        }
    },
}
data["clients"]["0303cedf99999999aabbccdd00112233"] = {
    "hostname": "aella",
    "mgmt_status": "enrolled",
    "mgmt_mac_key": "SECRET_MAC_SELECTOR_AELLA",
    "services": {
        "ssh": {
            "id": "ssh", "remote_port": 6005, "enabled": True,
            "preset": "ssh", "ssh_user": "aella",
        }
    },
}
data["clients"]["abcdabcd111122223333444455556666"] = {
    "hostname": "amb-one", "label": "amb-one", "mgmt_status": "enrolled",
    "services": {},
}
data["clients"]["abcdabcd999988887777666655554444"] = {
    "hostname": "amb-two", "label": "amb-two", "mgmt_status": "enrolled",
    "services": {},
}
p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY
unset FRP_CTL_DRY_RUN
export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_DEPLOY_TEST_ROOT="$SERVER"
python3 "$ROOT/tools/frp-clients" >"$WORKDIR/sel-list.out"
grep -qE '^#[[:space:]]+CLIENT ID[[:space:]]+LABEL' "$WORKDIR/sel-list.out" || fail "CLIENT ID column"
grep -q '24cd7856' "$WORKDIR/sel-list.out" || fail "list short id"
grep -q 'aaa' "$WORKDIR/sel-list.out" || fail "list label"
grep -q 'Use CLIENT ID in client commands.' "$WORKDIR/sel-list.out" || fail "CLIENT ID footer"
if grep -q 'SECRET_MAC_SELECTOR' "$WORKDIR/sel-list.out"; then
  fail "selector list leaked secret"
fi
pass "CLIENT_ID_CANONICAL_SELECTOR"

FRP_CTL_REPL=1 "$CTL" show client aaa >"$WORKDIR/sel-label.out"
grep -q '24cd7856' "$WORKDIR/sel-label.out" || fail "label shortcut"
pass "LABEL_SHORTCUT_STILL_WORKS"

FRP_CTL_REPL=1 "$CTL" show client dp-os-upgrade >"$WORKDIR/sel-host.out"
grep -q 'dp-os-upgrade' "$WORKDIR/sel-host.out" || fail "hostname lookup"
pass "HOSTNAME_SHORTCUT_STILL_WORKS"

FRP_CTL_REPL=1 "$CTL" set client 24cd7856 label production >"$WORKDIR/sel-relabel.out"
grep -q 'Updated client 24cd7856' "$WORKDIR/sel-relabel.out" || fail "label update header"
grep -q 'old: aaa' "$WORKDIR/sel-relabel.out" || fail "label old value"
grep -q 'new: production' "$WORKDIR/sel-relabel.out" || fail "label new value"
grep -q 'Client ID remains: 24cd7856' "$WORKDIR/sel-relabel.out" || fail "label id remains"
FRP_CTL_REPL=1 "$CTL" show client 24cd7856 >"$WORKDIR/sel-after-label.out"
grep -q 'production' "$WORKDIR/sel-after-label.out" || fail "id still works after label change"
set +e
FRP_CTL_REPL=1 "$CTL" show client aaa >"$WORKDIR/sel-old-label.out" 2>"$WORKDIR/sel-old-label.err"
old_rc=$?
set -e
[[ "$old_rc" -ne 0 ]] || fail "old label should not remain identity"
pass "LABEL_CHANGE_DOES_NOT_CHANGE_SELECTOR"

set +e
FRP_CTL_REPL=1 "$CTL" show client abcdabcd >"$WORKDIR/amb.out" 2>"$WORKDIR/amb.err"
amb_rc=$?
set -e
[[ "$amb_rc" -ne 0 ]] || fail "ambiguous prefix should fail"
grep -qi 'multiple clients matched' "$WORKDIR/amb.err" || fail "ambiguous prefix message"
pass "AMBIGUOUS_PREFIX_FAILS_CLOSED"

FRP_CTL_REPL=1 "$CTL" show client 24cd7856 >"$WORKDIR/ov.out"
grep -q 'Client ID' "$WORKDIR/ov.out" || fail "overview client id"
grep -q 'Service count' "$WORKDIR/ov.out" || fail "overview service count"
if grep -qE '^SERVICE ' "$WORKDIR/ov.out"; then
  fail "overview dumped services table"
fi
if grep -qE '^KEY ' "$WORKDIR/ov.out"; then
  fail "overview dumped tags table"
fi
pass "SHOW_CLIENT_OVERVIEW_ONLY"

FRP_CTL_REPL=1 "$CTL" show client 24cd7856 services >"$WORKDIR/svc.out"
grep -qE '^SERVICE ' "$WORKDIR/svc.out" || fail "services header"
grep -q '127.0.0.1:22' "$WORKDIR/svc.out" || fail "services target"
if grep -q 'Service count' "$WORKDIR/svc.out"; then
  fail "services view printed overview"
fi
if grep -q 'Description    :' "$WORKDIR/svc.out"; then
  fail "services view printed description"
fi
pass "SHOW_CLIENT_SERVICES_ONLY"

FRP_CTL_REPL=1 "$CTL" show client 24cd7856 tags >"$WORKDIR/tags.out"
grep -qE '^KEY ' "$WORKDIR/tags.out" || fail "tags header"
grep -q 'env' "$WORKDIR/tags.out" || fail "tags env"
grep -q 'oci' "$WORKDIR/tags.out" || fail "tags value"
if grep -q 'Service count' "$WORKDIR/tags.out"; then
  fail "tags view printed overview"
fi
pass "SHOW_CLIENT_TAGS_ONLY"

export FRP_CTL_DRY_RUN=1
"$CTL" set client 24cd7856 tag env oci >"$WORKDIR/tag2.out"
grep -qx 'DISPATCH frp-client-set 24cd7856 --tag env=oci' "$WORKDIR/tag2.out" || fail "tag key value"
pass "TAG_KEY_VALUE_TWO_ARGUMENTS"
run_repl "$SERVER" "$WORKDIR/tagq.out" 'set client 24cd7856 tag location "OCI Osaka"' exit \
  || fail "quoted tag"
grep -q 'DISPATCH frp-client-set 24cd7856 --tag location=OCI Osaka' "$WORKDIR/tagq.out" \
  || fail "quoted tag dispatch"
pass "TAG_QUOTED_VALUE"
"$CTL" set client 24cd7856 tag stage=acceptance >"$WORKDIR/tag-eq.out"
grep -qx 'DISPATCH frp-client-set 24cd7856 --tag stage=acceptance' "$WORKDIR/tag-eq.out" \
  || fail "legacy tag key=value"
pass "LEGACY_TAG_KEY_EQUALS_VALUE_COMPAT"
unset FRP_CTL_DRY_RUN

run_repl "$SERVER" "$WORKDIR/ctx-root.out" "?" exit || fail "root ?"
grep -qE 'client[[:space:]]+Registered clients|^\s+client\s' "$WORKDIR/ctx-root.out" || fail "root ? client"
grep -qE 'status[[:space:]]+Host status|^\s+status\s' "$WORKDIR/ctx-root.out" || fail "root ? status"
grep -q 'egress' "$WORKDIR/ctx-root.out" || fail "root ? egress"
if grep -q 'Grammar: <verb>' "$WORKDIR/ctx-root.out"; then
  fail "root ? dumped full syntax tree"
fi
# Canonical root ? must not advertise verb-first discovery as primary.
if grep -qE '^\s+show\s+|^Available:.*\n\s+show\s' "$WORKDIR/ctx-root.out"; then
  fail "root ? still lists verb-first show as primary"
fi
pass "CONTEXT_HELP_ROOT"
pass "ROOT_HELP_SIMPLIFIED"

run_repl "$SERVER" "$WORKDIR/ctx-show.out" "show ?" exit || fail "show ?"
grep -q 'clients' "$WORKDIR/ctx-show.out" || fail "show ? clients"
pass "CONTEXT_HELP_SHOW"

run_repl "$SERVER" "$WORKDIR/ctx-clist.out" "show client ?" exit || fail "show client ?"
grep -q 'CLIENT ID' "$WORKDIR/ctx-clist.out" || fail "show client ? header"
grep -q '24cd7856' "$WORKDIR/ctx-clist.out" || fail "show client ? id"
if grep -q 'SECRET_MAC_SELECTOR' "$WORKDIR/ctx-clist.out"; then
  fail "context client list leaked secret"
fi
pass "CONTEXT_HELP_CLIENT_LIST"
pass "NO_SECRET_CONTEXT_HELP"

run_repl "$SERVER" "$WORKDIR/ctx-setc.out" "set client 24cd7856 ?" exit || fail "set client ?"
grep -q 'label' "$WORKDIR/ctx-setc.out" || fail "set client ? label"
grep -q 'tag' "$WORKDIR/ctx-setc.out" || fail "set client ? tag"
pass "CONTEXT_HELP_SET_CLIENT"

run_repl "$SERVER" "$WORKDIR/ctx-tag.out" "set client 24cd7856 tag ?" exit || fail "set tag ?"
grep -q 'tag <key> <value>' "$WORKDIR/ctx-tag.out" || fail "set tag ? usage"
pass "CONTEXT_HELP_TAG"

run_repl "$SERVER" "$WORKDIR/miss-show.out" "show client" exit || fail "show client missing"
grep -q 'Missing client.' "$WORKDIR/miss-show.out" || fail "show missing title"
grep -q 'Available CLIENT IDs:' "$WORKDIR/miss-show.out" || fail "show missing available"
grep -q '24cd7856' "$WORKDIR/miss-show.out" || fail "show missing lists id"
grep -q 'show client <ID>' "$WORKDIR/miss-show.out" || fail "show missing usage ID"
pass "SHOW_CLIENT_MISSING_TARGET_HELP"

run_repl "$SERVER" "$WORKDIR/miss-set.out" "set" exit || fail "set missing"
grep -q 'Missing resource.' "$WORKDIR/miss-set.out" || fail "set missing title"
grep -q 'client' "$WORKDIR/miss-set.out" || fail "set missing lists client"
grep -q 'drlink help set' "$WORKDIR/miss-set.out" || fail "set missing tip"
pass "SET_CLIENT_MISSING_TARGET_HELP"

# Residual audit: exact argv round-trip for space/glob-bearing passthrough.
export FRP_CTL_DRY_RUN=1
set +e
"$CTL" enrollment create --note "Seoul production" >"$WORKDIR/argv-space.out" 2>"$WORKDIR/argv-space.err"
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "enrollment create note spaces rc=$rc"
python3 - "$WORKDIR/argv-space.out" <<'PY' || fail "argv space note not preserved"
import json,sys
from pathlib import Path
text=Path(sys.argv[1]).read_text(encoding="utf-8")
rows=[ln.split("\t",1)[1] for ln in text.splitlines() if ln.startswith("DISPATCH_ARGV\t")]
assert rows, text
argv=json.loads(rows[-1])
assert argv == ["frp-create-client", "--note", "Seoul production"], argv
PY
mkdir -p "$WORKDIR/globdir"
touch "$WORKDIR/globdir/a.txt" "$WORKDIR/globdir/b.txt"
"$CTL" enrollment create --note "$WORKDIR/globdir/*.txt" >"$WORKDIR/argv-glob.out" 2>"$WORKDIR/argv-glob.err" \
  || fail "enrollment create glob note"
python3 - "$WORKDIR/argv-glob.out" "$WORKDIR/globdir/*.txt" <<'PY' || fail "glob re-expanded in argv"
import json,sys
from pathlib import Path
text=Path(sys.argv[1]).read_text(encoding="utf-8")
want=sys.argv[2]
rows=[ln.split("\t",1)[1] for ln in text.splitlines() if ln.startswith("DISPATCH_ARGV\t")]
argv=json.loads(rows[-1])
assert argv == ["frp-create-client", "--note", want], argv
PY
"$CTL" backup create "/tmp/Seoul production.tar.gz" >"$WORKDIR/argv-backup.out" \
  || fail "backup create spaced path"
python3 - "$WORKDIR/argv-backup.out" <<'PY' || fail "backup path argv split"
import json,sys
from pathlib import Path
text=Path(sys.argv[1]).read_text(encoding="utf-8")
rows=[ln.split("\t",1)[1] for ln in text.splitlines() if ln.startswith("DISPATCH_ARGV\t")]
argv=json.loads(rows[-1])
assert argv == ["frp-backup", "/tmp/Seoul production.tar.gz"], argv
PY
unset FRP_CTL_DRY_RUN
pass "CLI_ARGV_BOUNDARY_PRESERVED"
pass "CLI_GLOB_REEXPANSION=0"

# Incomplete one-shot must exit non-zero; REPL stays usable.
set +e
"$CTL" group create >"$WORKDIR/inc-direct.out" 2>"$WORKDIR/inc-direct.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "incomplete group create exited 0"
[[ "$rc" -eq 2 ]] || fail "incomplete group create want exit 2 got $rc"
grep -qi 'Missing' "$WORKDIR/inc-direct.out" "$WORKDIR/inc-direct.err" \
  || fail "incomplete direct missing usage"
run_repl "$SERVER" "$WORKDIR/inc-repl.out" "group create" "status" exit || fail "incomplete REPL continuity"
grep -qi 'Missing' "$WORKDIR/inc-repl.out" || fail "incomplete REPL guidance"
pass "CLI_INCOMPLETE_DIRECT_EXIT_NONZERO"
pass "CLI_INCOMPLETE_REPL_STAYS_USABLE"

# Empty passthrough under set -u (Bash 4.2/AL2 + macOS Bash 3.2).
set +e
"$CTL" help >"$WORKDIR/empty-pt-help.out" 2>"$WORKDIR/empty-pt-help.err"
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "help with empty passthrough rc=$rc"
if grep -q 'unbound variable' "$WORKDIR/empty-pt-help.out" "$WORKDIR/empty-pt-help.err"; then
  fail "empty passthrough unbound variable"
fi
grep -qiE 'status|backup|update|help' "$WORKDIR/empty-pt-help.out" || fail "help empty-pt produced no catalog"
pass "CLI_EMPTY_PASSTHROUGH_SET_U"

# Bare roots must discover, not mutate.
export FRP_CTL_DRY_RUN=1
set +e
"$CTL" update >"$WORKDIR/bare-update.out" 2>"$WORKDIR/bare-update.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "bare update exited 0"
if grep -q '^DISPATCH ' "$WORKDIR/bare-update.out"; then
  fail "bare update mutated/dispatched: $(cat "$WORKDIR/bare-update.out")"
fi
grep -qiE 'Missing action|project|engine' "$WORKDIR/bare-update.out" "$WORKDIR/bare-update.err" \
  || fail "bare update missing discovery"
set +e
"$CTL" backup >"$WORKDIR/bare-backup.out" 2>"$WORKDIR/bare-backup.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "bare backup exited 0"
if grep -q '^DISPATCH ' "$WORKDIR/bare-backup.out"; then
  fail "bare backup mutated/dispatched: $(cat "$WORKDIR/bare-backup.out")"
fi
grep -qiE 'Missing action|create|restore' "$WORKDIR/bare-backup.out" "$WORKDIR/bare-backup.err" \
  || fail "bare backup missing discovery"
unset FRP_CTL_DRY_RUN
pass "CLI_BARE_ROOT_MUTATION=0"
pass "CLI_BARE_ROOT_DISCOVERY"

echo "FRPCTL_TESTS=PASS"
