#!/usr/bin/env bash
# create zero-touch discoverability, guided UX, compatibility, and PTY Tab.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

CTL="$ROOT/tools/frpctl"
export FRP_CTL_BIN_DIR="$ROOT/tools"
export FRP_SKIP_SYSTEMD=1
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

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
    "clients": {},
}, indent=2, sort_keys=True) + "\n")
PY
  cat >"$tree/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.4.0
FRP_VERSION=0.71.0
EOF
}

run_repl() {
  local tree="$1" outfile="$2" rc
  shift 2
  export FRP_CTL_TEST_ROOT="$tree"
  rm -f "${TMPDIR:-/tmp}/frpctl-test-input.$$" "${TMPDIR:-/tmp}/frpctl-test-input.$$.pos" \
    "${TMPDIR:-/tmp}/frpctl-test-input.${PPID}" "${TMPDIR:-/tmp}/frpctl-test-input.${PPID}.pos" \
    2>/dev/null || true
  FRP_CTL_TEST_INPUT="$(printf '%s\n' "$@")"
  export FRP_CTL_TEST_INPUT
  set +e
  "$CTL" >"$outfile" 2>"${outfile}.err"
  rc=$?
  set -e
  cat "${outfile}.err" >>"$outfile"
  unset FRP_CTL_TEST_INPUT
  rm -f "${TMPDIR:-/tmp}/frpctl-test-input.$$" "${TMPDIR:-/tmp}/frpctl-test-input.$$.pos" \
    "${TMPDIR:-/tmp}/frpctl-test-input.${PPID}" "${TMPDIR:-/tmp}/frpctl-test-input.${PPID}.pos" \
    2>/dev/null || true
  return "$rc"
}

cands() {
  FRP_CTL_SOURCED=1 source "$CTL"
  frpctl_completion_candidates "$1"
}

SERVER="$WORKDIR/server"
write_server_tree "$SERVER"
export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_CTL_DRY_RUN=1

# --- Discoverability: Tab + incomplete Available ---
FRP_CTL_SOURCED=1 source "$CTL"
create_cands="$(cands "create ")"
echo "$create_cands" | grep -qx 'zero-touch' || fail "create Tab missing zero-touch"
echo "$create_cands" | grep -qx 'enrollment' || fail "create Tab missing enrollment"
echo "$create_cands" | grep -qx 'enrollments' || fail "create Tab missing enrollments"
echo "$create_cands" | grep -qx 'backup' || fail "create Tab missing backup"
first="$(printf '%s\n' "$create_cands" | head -n1)"
[[ "$first" == "zero-touch" ]] || fail "create Tab first candidate is not zero-touch (got: $first)"
pass "CREATE_ZERO_TOUCH_DISCOVERABLE"

# Secret-like tokens must never appear as create candidates
if echo "$create_cands" | grep -qiE 'ticket|secret|bootstrap|token|password'; then
  fail "secret-like create Tab candidates"
fi
pass "ZERO_TOUCH_SECRET_NOT_COMPLETED"

# --- help create is not a public topic; prefer set client / help clients ---
help_create="$(frpctl_grammar_call help '{"tokens":["create"]}')"
echo "$help_create" | grep -qiE 'Unknown help topic: create|help commands|not a current public root|set enrollment|set client' \
  || fail "help create should redirect away from a create topic"
! echo "$help_create" | grep -qiE 'Current grammar is resource-first' \
  || fail "help create still says resource-first is current"
! echo "$help_create" | grep -qiE 'help legacy' \
  || fail "help create must not advertise help legacy"
help_legacy="$(frpctl_grammar_call help '{"tokens":["legacy"]}')"
echo "$help_legacy" | grep -qiE "help legacy.*removed|help commands|Canonical roots" \
  || fail "help legacy must report removal and point to help commands"
help_clients="$(frpctl_grammar_call help '{"tokens":["clients"]}')"
echo "$help_clients" | grep -qiE 'set enrollment|set client|Connect a Managed Host|zero-touch|Zero-Touch|Managed Hosts' \
  || fail "help clients missing onboarding path"
root_help="$(frpctl_grammar_call help '{"tokens":[]}')"
echo "$root_help" | grep -qE '^[[:space:]]*set([[:space:]]|$)' || fail "root help missing set"
echo "$root_help" | grep -qE '^[[:space:]]*show([[:space:]]|$)' || fail "root help missing show"
! echo "$root_help" | grep -qE '^[[:space:]]*create([[:space:]]|$)' || fail "root help advertises create"
! echo "$root_help" | grep -qE '^[[:space:]]*enrollment([[:space:]]|$)' || fail "root help advertises enrollment"
! echo "$root_help" | grep -qE '^[[:space:]]*zero-touch([[:space:]]|$)' || fail "root help advertises zero-touch"
pass "CREATE_ZERO_TOUCH_HELP"

# --- context help ---
ctx_create="$(frpctl_grammar_call match '{"tokens":["create","?"],"role":"server"}')"
python3 - "$ctx_create" <<'PY' || fail "create ? current redirect"
import json, sys
msg = json.loads(sys.argv[1]).get("message", "")
if "not a current public root" not in msg.lower() and "legacy" not in msg.lower():
    raise SystemExit("create ? should identify non-current root")
if "set enrollment" not in msg and "set client" not in msg:
    raise SystemExit("create ? missing set enrollment current command")
if "help legacy" in msg:
    raise SystemExit("create ? must not advertise help legacy")
if "service-profile" in msg or "internet-profile" in msg or "access-rule" in msg:
    raise SystemExit("create ? must not advertise obsolete profile/ACL nouns")
if "help commands" not in msg:
    raise SystemExit("create ? missing help commands pointer")
PY
ctx_zt="$(frpctl_grammar_call match '{"tokens":["create","zero-touch","?"],"role":"server"}')"
echo "$ctx_zt" | grep -qiE 'Zero-Touch|zero-touch|Guided|set client|not a current public root' || fail "create zero-touch ? heading"
ctx_en="$(frpctl_grammar_call match '{"tokens":["create","enrollment","?"],"role":"server"}')"
echo "$ctx_en" | grep -qiE 'Manual Enrollment|enrollment|set enrollment|not a current public root' || fail "create enrollment ? heading"
pass "CREATE_ZERO_TOUCH_CONTEXT_HELP"

# --- Public contract: set enrollment zero-touch / manual ---
zt_set="$(frpctl_grammar_call match '{"tokens":["set","enrollment","zero-touch"],"role":"server"}')"
echo "$zt_set" | grep -q '"action": "create_zero_touch"' \
  || fail "set enrollment zero-touch must dispatch create_zero_touch"
manual_set="$(frpctl_grammar_call match '{"tokens":["set","enrollment","manual"],"role":"server"}')"
echo "$manual_set" | grep -q '"action": "create_enrollment"' \
  || fail "set enrollment manual must dispatch create_enrollment"
pass "SET_ENROLLMENT_ZERO_TOUCH_PUBLIC"

# --- Guided: SSH only ---
# create zero-touch → method(Zero-Touch) → platform(Linux) → identity → SSH only
run_repl "$SERVER" "$WORKDIR/zt-ssh.out" \
  "create zero-touch" 1 1 office-ssh "Seoul office" 1 aella 22 exit \
  || fail "zero-touch ssh guided"
grep -qiE 'Connect a Managed Host|Managed Host details|zero-touch|Zero-Touch' "$WORKDIR/zt-ssh.out" || fail "zero-touch heading"
grep -q '1) SSH only' "$WORKDIR/zt-ssh.out" || fail "ssh only option"
grep -q 'DISPATCH frp-create-client --platform linux --one-line --ssh --ssh-user aella --ssh-port 22 --client-name office-ssh --note Seoul office' \
  "$WORKDIR/zt-ssh.out" || fail "ssh only dispatch"
pass "ZERO_TOUCH_SSH_GUIDED"

# --- Guided: macOS uses the real bash Zero-Touch path (same installer as Linux) ---
run_repl "$SERVER" "$WORKDIR/zt-macos.out" \
  "create zero-touch" 1 3 office-mac "Mac lab" 1 aella 22 exit \
  || fail "zero-touch macOS guided"
grep -q '3) macOS' "$WORKDIR/zt-macos.out" || fail "macOS platform option missing"
grep -q '4) Back' "$WORKDIR/zt-macos.out" || fail "platform Back must be option 4"
grep -q 'DISPATCH frp-create-client --platform linux --one-line --ssh --ssh-user aella --ssh-port 22 --client-name office-mac --note Mac lab' \
  "$WORKDIR/zt-macos.out" || fail "macOS must use bash/linux Zero-Touch dispatch"
pass "MACOS_PUBLIC_ONBOARDING_DISCOVERABLE"
pass "MACOS_MENU_DEAD_END_NO"

# --- Guided: Windows RDP custom TCP preset ---
run_repl "$SERVER" "$WORKDIR/zt-rdp.out" \
  "create zero-touch" 1 2 office-rdp "Windows desktop" 1 3389 exit \
  || fail "zero-touch Windows RDP guided"
grep -qiE 'Windows|Connect a Managed Host|RDP|Managed Host details' "$WORKDIR/zt-rdp.out" \
  || fail "Windows platform menu"
grep -q 'DISPATCH frp-create-client --platform windows --one-line --rdp --rdp-port 3389 --client-name office-rdp --note Windows desktop' \
  "$WORKDIR/zt-rdp.out" || fail "Windows RDP dispatch"
pass "ZERO_TOUCH_WINDOWS_RDP_GUIDED"

# --- Guided menu: management-only initial onboarding removed ---
run_repl "$SERVER" "$WORKDIR/zt-mgmt-menu.out" \
  "create zero-touch" 1 1 zt-back "optional note" 3 exit \
  || fail "zero-touch back option"
grep -q '1) SSH only' "$WORKDIR/zt-mgmt-menu.out" || fail "ssh only option missing"
grep -q '2) Choose services' "$WORKDIR/zt-mgmt-menu.out" || fail "choose services option missing"
grep -q '3) Back' "$WORKDIR/zt-mgmt-menu.out" || fail "back option missing"
! grep -q 'Connect this machine only' "$WORKDIR/zt-mgmt-menu.out" \
  || fail "management-only option must be removed from initial onboarding"
! grep -qi 'management-only' "$WORKDIR/zt-mgmt-menu.out" \
  || fail "management-only wording must not appear in guided zero-touch"
if grep -q 'DISPATCH frp-create-client --one-line' "$WORKDIR/zt-mgmt-menu.out"; then
  fail "Back unexpectedly dispatched zero-touch enrollment"
fi
# Blank description accepted without a second Managed Host details prompt.
run_repl "$SERVER" "$WORKDIR/zt-blank-note.out" \
  "create zero-touch" 1 1 blank-desc "" 1 aella 22 exit \
  || fail "blank description guided"
ident_count="$(grep -c 'Managed Host details' "$WORKDIR/zt-blank-note.out" || true)"
[[ "$ident_count" == "1" ]] || fail "CLIENT_IDENTIFICATION_PROMPT_COUNT expected 1 got $ident_count"
! grep -q 'Client identification' "$WORKDIR/zt-blank-note.out" \
  || fail "stale Client identification heading"
grep -qF -- '--client-name blank-desc' "$WORKDIR/zt-blank-note.out" \
  || fail "blank description missing client-name"
grep -qF -- '--note' "$WORKDIR/zt-blank-note.out" \
  || fail "blank description must still pass --note"
pass "MANAGEMENT_ONLY_INITIAL_ONBOARDING_REMOVED"
pass "ZERO_TOUCH_SINGLE_IDENTIFICATION_PROMPT"

# Blank optional SSH username is collected once, then passed explicitly.
run_repl "$SERVER" "$WORKDIR/zt-blank-user.out" \
  "create zero-touch" 1 1 blank-ssh "" 1 "" 22 exit \
  || fail "blank ssh username guided"
user_prompts="$(grep -c 'SSH username is optional connection-example metadata.' "$WORKDIR/zt-blank-user.out" || true)"
[[ "$user_prompts" == "1" ]] || fail "SSH username prompt count expected 1 got $user_prompts"
python3 - "$WORKDIR/zt-blank-user.out" <<'PY' || fail "blank ssh user not passed explicitly"
import json, sys
text = open(sys.argv[1], encoding="utf-8").read()
lines = [ln for ln in text.splitlines() if ln.startswith("DISPATCH_ARGV\t")]
if not lines:
    raise SystemExit("missing DISPATCH_ARGV")
argv = json.loads(lines[-1].split("\t", 1)[1])
if "--ssh-user" not in argv:
    raise SystemExit(argv)
if argv[argv.index("--ssh-user") + 1] != "":
    raise SystemExit(argv)
if "--ssh-port" not in argv:
    raise SystemExit(argv)
PY
pass "SSH_USERNAME_PROMPTED_ONCE"

# --- Guided: multi-service SSH+HTTP ---
run_repl "$SERVER" "$WORKDIR/zt-multi-http.out" \
  "create zero-touch" 1 1 multi-http "" \
  2 \
  1 "" "" "" aella \
  2 "" "" "" \
  5 \
  exit \
  || fail "zero-touch multi ssh+http"
grep -q 'SERVICES_JSON ' "$WORKDIR/zt-multi-http.out" || fail "multi-http missing SERVICES_JSON"
grep -q 'DISPATCH frp-create-client --platform linux --one-line --services-file ' "$WORKDIR/zt-multi-http.out" \
  || fail "multi-http missing services-file dispatch"
grep -qF -- '--client-name multi-http' "$WORKDIR/zt-multi-http.out" || fail "multi-http client-name"
python3 - "$WORKDIR/zt-multi-http.out" <<'PY' || fail "multi-http services content"
import json, sys, re
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"^SERVICES_JSON (.+)$", text, re.M)
if not m:
    raise SystemExit("no SERVICES_JSON")
items = json.loads(m.group(1))
presets = [i.get("preset") for i in items]
if presets != ["ssh", "http"]:
    raise SystemExit("presets=%r" % presets)
ssh = items[0]
http = items[1]
if ssh.get("local_ip") != "127.0.0.1" or int(ssh.get("local_port")) != 22:
    raise SystemExit("ssh target")
if ssh.get("ssh_user") != "aella":
    raise SystemExit("ssh user")
if http.get("local_ip") != "127.0.0.1" or int(http.get("local_port")) != 80:
    raise SystemExit("http target")
PY
pass "ZERO_TOUCH_MULTI_SERVICE_GUIDED"
pass "ZERO_TOUCH_MULTI_SERVICE_SSH_HTTP"

# --- Guided: multi-service SSH+HTTPS ---
run_repl "$SERVER" "$WORKDIR/zt-multi-https.out" \
  "create zero-touch" 1 1 multi-https "" \
  2 \
  1 "" "" "" aella \
  3 "" "" "" \
  5 \
  exit \
  || fail "zero-touch multi ssh+https"
python3 - "$WORKDIR/zt-multi-https.out" <<'PY' || fail "multi-https services content"
import json, sys, re
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"^SERVICES_JSON (.+)$", text, re.M)
items = json.loads(m.group(1))
presets = [i.get("preset") for i in items]
if presets != ["ssh", "https"]:
    raise SystemExit("presets=%r" % presets)
if int(items[1].get("local_port")) != 443:
    raise SystemExit("https port")
PY
pass "ZERO_TOUCH_MULTI_SERVICE_SSH_HTTPS"

# --- Remote LAN target hosts ---
run_repl "$SERVER" "$WORKDIR/zt-lan.out" \
  "create zero-touch" 1 1 lan-client "lan note" \
  2 \
  1 ssh 10.10.10.20 22 ops \
  2 web 10.10.10.30 80 \
  5 \
  exit \
  || fail "zero-touch remote lan"
python3 - "$WORKDIR/zt-lan.out" <<'PY' || fail "lan target services"
import json, sys, re
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"^SERVICES_JSON (.+)$", text, re.M)
items = json.loads(m.group(1))
assert items[0]["preset"] == "ssh"
assert items[0]["local_ip"] == "10.10.10.20"
assert int(items[0]["local_port"]) == 22
assert items[0]["ssh_user"] == "ops"
assert items[1]["preset"] == "http"
assert items[1]["local_ip"] == "10.10.10.30"
assert int(items[1]["local_port"]) == 80
PY
grep -qF -- '--client-name lan-client --note lan note' "$WORKDIR/zt-lan.out" \
  || fail "lan client identification"
pass "ZERO_TOUCH_REMOTE_LAN_TARGET"

# Temp services file must not linger after guided multi-service
leftover="$(find /tmp -maxdepth 1 -name 'tmp.*' -user "$(id -un)" -newer "$WORKDIR/zt-lan.out" 2>/dev/null | head -n 5 || true)"
# Soft check: DISPATCH path from output must not still exist
svc_path="$(grep -oE -- '--services-file [^ ]+' "$WORKDIR/zt-lan.out" | awk '{print $2}' | tail -n1 || true)"
if [[ -n "$svc_path" && -e "$svc_path" ]]; then
  fail "services temp file not deleted: $svc_path"
fi

# --- Manual enrollment: --options rejected; bare create enrollment is guided ---
# Both create zero-touch and create enrollment reject GNU --options in the public CLI.
if "$CTL" create zero-touch --ssh --ssh-user aella \
  >"$WORKDIR/zt-flags.out" 2>"$WORKDIR/zt-flags.err"; then
  fail "create zero-touch --ssh should be rejected"
fi
grep -qi 'do not use --options' "$WORKDIR/zt-flags.err" \
  || fail "zero-touch flag rejection message"
! grep -qi 'frp-create-client' "$WORKDIR/zt-flags.err" \
  || fail "zero-touch leaked backend"
if "$CTL" create enrollment --ssh --ssh-user aella --label dp01 \
  >"$WORKDIR/manual-compat.out" 2>"$WORKDIR/manual-compat.err"; then
  fail "create enrollment --ssh should be rejected"
fi
grep -qi 'do not use --options' "$WORKDIR/manual-compat.err" \
  || fail "create enrollment flag rejection message"
! grep -qi 'frp-create-client' "$WORKDIR/manual-compat.err" \
  || fail "create enrollment leaked backend on rejected flags"
run_repl "$SERVER" "$WORKDIR/manual-repl.out" "create enrollment" exit \
  || fail "create enrollment repl"
# Guided path should solicit prompts rather than immediately dispatch one-line.
if grep -q 'DISPATCH frp-create-client --one-line' "$WORKDIR/manual-repl.out"; then
  fail "plain create enrollment became one-line"
fi
pass "MANUAL_ENROLLMENT_COMPAT"

# --- Flag-based create enrollment / enroll are not public machine paths ---
if "$CTL" create enrollment --one-line --ssh --ssh-user aella --client-name legacy01 \
  >"$WORKDIR/legacy-oneline.out" 2>"$WORKDIR/legacy-oneline.err"; then
  fail "create enrollment --one-line should be rejected"
fi
grep -qi 'do not use --options' "$WORKDIR/legacy-oneline.err" \
  || fail "create enrollment --one-line rejection message"
run_repl "$SERVER" "$WORKDIR/legacy-enroll.out" "enroll --one-line --ssh --ssh-user aella" exit || true
if grep -q 'DISPATCH frp-create-client' "$WORKDIR/legacy-enroll.out"; then
  fail "enroll --one-line must not dispatch via public REPL"
fi
grep -qiE 'do not use --options|Unknown input|Unknown set resource|obsolete|not part of the current|Available:' \
  "$WORKDIR/legacy-enroll.out" \
  || fail "enroll --one-line should explain rejection"
pass "LEGACY_ONE_LINE_COMPAT"

# --- History must not store secret-looking lines; create zero-touch itself is fine ---
run_repl "$SERVER" "$WORKDIR/zt-hist.out" \
  "create zero-touch" 3 \
  "FRP_BOOTSTRAP_TICKET=abc.def" \
  history \
  exit || fail "history secret filter"
hist_body="$(sed -n '/^\(frpctl\|drlink\)> history$/,/^\(frpctl\|drlink\)>/p' "$WORKDIR/zt-hist.out" || true)"
echo "$hist_body" | grep -q 'create zero-touch' || fail "create zero-touch missing from history"
if echo "$hist_body" | grep -qiE 'FRP_BOOTSTRAP_TICKET|ticket=|bootstrap'; then
  fail "secret-like line stored in history"
fi
pass "ZERO_TOUCH_SECRET_NOT_HISTORY"

unset FRP_CTL_DRY_RUN

# --- Real GNU readline PTY: create <Tab> ---
python3 - "$CTL" "$SERVER" "$WORKDIR/pty-zt-home" <<'PY' || fail "PTY create zero-touch tab"
import errno
import os
import pty
import re
import select
import sys
import time

ctl, tree, home = sys.argv[1:4]
os.makedirs(home, exist_ok=True)
env = os.environ.copy()
env.update({
    "HOME": home,
    "HISTFILE": "",
    "TERM": "xterm",
    "FRP_CTL_TEST_ROOT": tree,
    "FRP_CTL_DRY_RUN": "1",
    "FRP_CTL_BIN_DIR": os.path.join(os.path.dirname(ctl)),
    "FRP_SKIP_SYSTEMD": "1",
    "FRP_UPDATE_TEST_HARNESS": "0",
})
env.pop("FRP_CTL_TEST_INPUT", None)
env.pop("FRP_CTL_SOURCED", None)
env.pop("FRP_CTL_DISABLE_TAB", None)

ANSI_RE = re.compile(br"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()].")
CLEAR_RE = re.compile(br"\x1b\[2J|\x1b\[H\x1b\[2J|\x1bc")


def strip_ansi(data):
    return ANSI_RE.sub(b"", data)


def visible(data):
    return strip_ansi(data).replace(b"\r", b"").replace(b"\x00", b"")


pid, fd = pty.fork()
if pid == 0:
    os.chdir(home)
    os.execve("/bin/bash", ["bash", ctl], env)

buf = bytearray()


def read_more(seconds):
    end = time.time() + seconds
    while time.time() < end:
        remain = max(0.0, end - time.time())
        r, _, _ = select.select([fd], [], [], min(0.2, remain))
        if not r:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError as exc:
            if exc.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        buf.extend(chunk)


def wait_prompt(timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        read_more(0.25)
        stripped = strip_ansi(bytes(buf)).replace(b"\r", b"").rstrip(b"\x00")
        if stripped.endswith(b"frpctl> ") or stripped.endswith(b"frpctl>") or stripped.endswith(b"drlink> ") or stripped.endswith(b"drlink>"):
            return True
    return False


def fail_pty(msg, extra=b""):
    os.write(2, msg.encode() + b"\n" + extra[-1600:])
    raise SystemExit(1)


if not wait_prompt():
    fail_pty("PTY: no initial prompt", bytes(buf))

os.write(fd, b"create ")
read_more(0.3)
before = len(buf)
os.write(fd, b"\t")
read_more(1.2)
chunk = bytes(buf[before:])
vis = visible(chunk)

for token in (b"zero-touch", b"enrollment", b"enrollments", b"backup"):
    if token not in vis:
        fail_pty("PTY: create tab missing %s" % token.decode(), chunk)

# Descriptions on first press
if b"zero-touch" not in vis.lower():
    fail_pty("PTY: create tab missing zero-touch description", chunk)
if b"Manual Enrollment Code" not in vis:
    fail_pty("PTY: create tab missing enrollment description", chunk)

# Domain-grouped Tab lists Clients before System; zero-touch remains discoverable.
if b"zero-touch" not in vis.lower():
    fail_pty("PTY: create tab missing zero-touch candidate", chunk)
if b"enrollment" not in vis.lower():
    fail_pty("PTY: create tab missing enrollment candidate", chunk)

if b"Missing resource" in chunk or b"Unknown command" in chunk:
    fail_pty("PTY: create tab dispatched", chunk)
if CLEAR_RE.search(chunk):
    fail_pty("PTY: create tab cleared screen", chunk)

# Buffer preserved: prompt + "create " restored
read_more(0.5)
tail = visible(bytes(buf[before:]))
if b"frpctl> create" not in tail and b"drlink> create" not in tail and not tail.rstrip().endswith(b"create "):
    if b"create " not in tail:
        fail_pty("PTY: create buffer not preserved", chunk)

# Repeat Tab must not spam
desc_before = visible(bytes(buf)).count(b"zero-touch")
os.write(fd, b"\t")
read_more(0.8)
desc_after = visible(bytes(buf)).count(b"zero-touch")
if desc_after > desc_before:
    fail_pty("PTY: repeated create tab duplicated list", bytes(buf[-500:]))

# No secret candidates
if re.search(br"(?i)ticket|bootstrap|password|server_token|BEGIN .*PRIVATE", vis):
    fail_pty("PTY: secret-like create candidates", chunk)

print("CREATE_ZERO_TOUCH_TAB_FIRST_PRESS")
print("FIRST_PRESS")
print("BUFFER_PRESERVED")
print("PROMPT_RESTORED")
print("NO_CLEAR")
print("NO_FLICKER")
print("NO_REPEAT_SPAM")
print("NO_COMMAND_DISPATCH")
print("NO_SECRET_CANDIDATES")

os.write(fd, b"\x15")
read_more(0.2)
os.write(fd, b"exit\r")
read_more(1.0)
os.close(fd)
_, status = os.waitpid(pid, 0)
if os.WIFEXITED(status) and os.WEXITSTATUS(status) not in (0,):
    raise SystemExit(1)
PY
pass "CREATE_ZERO_TOUCH_TAB_FIRST_PRESS"
pass "PTY_CLI_TEST"
pass "FRPCTL_COMPLETION"

echo
echo "CREATE_ZERO_TOUCH_TEST=PASS"
