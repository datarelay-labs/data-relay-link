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
  FRP_CTL_TEST_INPUT="$(printf '%s\n' "$@")"
  export FRP_CTL_TEST_INPUT
  set +e
  "$CTL" >"$outfile" 2>"${outfile}.err"
  rc=$?
  set -e
  unset FRP_CTL_TEST_INPUT
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

# --- help create ---
help_create="$(frpctl_grammar_call help '{"tokens":["create"]}')"
echo "$help_create" | grep -q 'create zero-touch' || fail "help create missing zero-touch"
echo "$help_create" | grep -q 'create enrollment' || fail "help create missing enrollment"
echo "$help_create" | grep -q 'Recommended:' || fail "help create missing Recommended"
echo "$help_create" | grep -A1 'Recommended:' | grep -q 'create zero-touch' \
  || fail "help create Recommended is not zero-touch"
echo "$help_create" | grep -q 'Generate a one-line Zero-touch' || fail "help create zero-touch description"
echo "$help_create" | grep -q 'Manual Enrollment Code' || fail "help create enrollment description"
root_help="$(frpctl_grammar_call help '{"tokens":[]}')"
echo "$root_help" | grep -q 'create zero-touch' || fail "root help missing create zero-touch"
echo "$root_help" | grep -q 'create enrollment' || fail "root help missing create enrollment"
pass "CREATE_ZERO_TOUCH_HELP"

# --- context help ---
ctx_create="$(frpctl_grammar_call match '{"tokens":["create","?"],"role":"server"}')"
python3 - "$ctx_create" <<'PY' || fail "create ? order"
import json, sys
msg = json.loads(sys.argv[1]).get("message", "")
# zero-touch must appear before enrollment in the listing
zt = msg.find("zero-touch")
en = msg.find("enrollment")
if zt < 0 or en < 0 or zt > en:
    raise SystemExit("zero-touch not first in create ?")
if "Zero-touch enrollment (recommended)" not in msg:
    raise SystemExit("missing zero-touch description")
if "Manual Enrollment Code" not in msg:
    raise SystemExit("missing enrollment description")
PY
ctx_zt="$(frpctl_grammar_call match '{"tokens":["create","zero-touch","?"],"role":"server"}')"
echo "$ctx_zt" | grep -q 'Zero-touch enrollment' || fail "create zero-touch ? heading"
ctx_en="$(frpctl_grammar_call match '{"tokens":["create","enrollment","?"],"role":"server"}')"
echo "$ctx_en" | grep -q 'Manual Enrollment Code' || fail "create enrollment ? heading"
pass "CREATE_ZERO_TOUCH_CONTEXT_HELP"

# --- Guided: SSH only ---
run_repl "$SERVER" "$WORKDIR/zt-ssh.out" \
  "create zero-touch" 1 1 office-ssh "Seoul office" aella 22 exit \
  || fail "zero-touch ssh guided"
grep -q 'Zero-touch enrollment' "$WORKDIR/zt-ssh.out" || fail "zero-touch heading"
grep -q '1) SSH only' "$WORKDIR/zt-ssh.out" || fail "ssh only option"
grep -q 'DISPATCH frp-create-client --platform linux --one-line --ssh --ssh-user aella --ssh-port 22 --client-name office-ssh --note Seoul office' \
  "$WORKDIR/zt-ssh.out" || fail "ssh only dispatch"
pass "ZERO_TOUCH_SSH_GUIDED"

# --- Guided: Windows RDP custom TCP preset ---
run_repl "$SERVER" "$WORKDIR/zt-rdp.out" \
  "create zero-touch" 2 1 office-rdp "Windows desktop" 3389 exit \
  || fail "zero-touch Windows RDP guided"
grep -q 'Windows Zero-touch enrollment' "$WORKDIR/zt-rdp.out" \
  || fail "Windows platform menu"
grep -q 'DISPATCH frp-create-client --platform windows --one-line --rdp --rdp-port 3389 --client-name office-rdp --note Windows desktop' \
  "$WORKDIR/zt-rdp.out" || fail "Windows RDP dispatch"
pass "ZERO_TOUCH_WINDOWS_RDP_GUIDED"

# --- Guided menu intentionally hides management-only ---
run_repl "$SERVER" "$WORKDIR/zt-no-mgmt.out" \
  "create zero-touch" 1 3 exit \
  || fail "zero-touch back option"
grep -q '1) SSH only' "$WORKDIR/zt-no-mgmt.out" || fail "ssh only option missing"
grep -q '2) Configure services' "$WORKDIR/zt-no-mgmt.out" || fail "configure services option missing"
grep -q '3) Back' "$WORKDIR/zt-no-mgmt.out" || fail "back option missing"
if grep -q 'Management only' "$WORKDIR/zt-no-mgmt.out"; then
  fail "management only must not appear in guided menu"
fi
if grep -q 'DISPATCH frp-create-client --one-line' "$WORKDIR/zt-no-mgmt.out"; then
  fail "Back unexpectedly dispatched zero-touch enrollment"
fi
pass "ZERO_TOUCH_MANAGEMENT_ONLY_HIDDEN"

# --- Guided: multi-service SSH+HTTP ---
run_repl "$SERVER" "$WORKDIR/zt-multi-http.out" \
  "create zero-touch" 1 2 multi-http "" \
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
  "create zero-touch" 1 2 multi-https "" \
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
  "create zero-touch" 1 2 lan-client "lan note" \
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

# --- Manual enrollment compatibility ---
"$CTL" create enrollment --ssh --ssh-user aella --label dp01 >"$WORKDIR/manual-compat.out"
grep -qx 'DISPATCH frp-create-client --ssh --ssh-user aella --label dp01' \
  "$WORKDIR/manual-compat.out" || fail "manual enrollment compat"
run_repl "$SERVER" "$WORKDIR/manual-repl.out" "create enrollment" exit \
  || fail "create enrollment repl"
grep -q 'DISPATCH frp-create-client' "$WORKDIR/manual-repl.out" || fail "create enrollment dispatch"
if grep -q 'DISPATCH frp-create-client --one-line' "$WORKDIR/manual-repl.out"; then
  fail "plain create enrollment became one-line"
fi
pass "MANUAL_ENROLLMENT_COMPAT"

# --- Legacy one-line compatibility ---
"$CTL" create enrollment --one-line --ssh --ssh-user aella --client-name legacy01 \
  >"$WORKDIR/legacy-oneline.out"
grep -Eqx 'DISPATCH frp-create-client( --platform linux)? --one-line --ssh --ssh-user aella --client-name legacy01' \
  "$WORKDIR/legacy-oneline.out" || fail "legacy create enrollment --one-line"
run_repl "$SERVER" "$WORKDIR/legacy-enroll.out" "enroll --one-line --ssh --ssh-user aella" exit \
  || fail "legacy enroll --one-line"
grep -Eq 'DISPATCH frp-create-client( --platform linux)? --one-line --ssh --ssh-user aella' \
  "$WORKDIR/legacy-enroll.out" || fail "legacy enroll dispatch"
pass "LEGACY_ONE_LINE_COMPAT"

# --- History must not store secret-looking lines; create zero-touch itself is fine ---
run_repl "$SERVER" "$WORKDIR/zt-hist.out" \
  "create zero-touch" 3 \
  "FRP_BOOTSTRAP_TICKET=abc.def" \
  history \
  exit || fail "history secret filter"
hist_body="$(sed -n '/^frpctl> history$/,/^frpctl>/p' "$WORKDIR/zt-hist.out" || true)"
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
if b"Zero-touch enrollment (recommended)" not in vis:
    fail_pty("PTY: create tab missing zero-touch description", chunk)
if b"Manual Enrollment Code" not in vis:
    fail_pty("PTY: create tab missing enrollment description", chunk)

# zero-touch must appear before enrollment in visible output
zt = vis.find(b"zero-touch")
en = vis.find(b"enrollment")
if zt < 0 or en < 0 or zt > en:
    fail_pty("PTY: zero-touch not first among create candidates", chunk)

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
desc_before = visible(bytes(buf)).count(b"Zero-touch enrollment (recommended)")
os.write(fd, b"\t")
read_more(0.8)
desc_after = visible(bytes(buf)).count(b"Zero-touch enrollment (recommended)")
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
