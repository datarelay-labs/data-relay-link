#!/usr/bin/env bash
# PTY regression: guided create-client confirmation must not share a line
# with the parent drlink> REPL prompt.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

CTL="$ROOT/tools/frpctl"
export FRP_CTL_FORCE_DRLINK=1
export FRP_CTL_CMD_NAME=drlink
export FRP_CTL_BIN_DIR="$ROOT/tools"
export FRP_SKIP_SYSTEMD=1
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

TREE="$WORKDIR/server"
mkdir -p "$TREE/etc/drlink/pki" "$TREE/var/lib/drlink/enrollments" \
  "$TREE/var/lib/drlink/bootstrap" "$TREE/etc/frp"
python3 "$ROOT/lib/frp_pki.py" ensure \
  --pki-dir "$TREE/etc/drlink/pki" \
  --public-host 203.0.113.10 >/dev/null
CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$TREE/etc/drlink/pki/ca.crt")"
python3 - "$TREE/etc/drlink/config.json" "$TREE/var/lib/drlink/enrollments" \
  "$TREE/etc/drlink/pki/ca.crt" "$TREE/var/lib/drlink/bootstrap" \
  "$TREE/var/lib/drlink/registry.json" "$CA_FP" <<'PY'
import json, sys
from pathlib import Path
cfg = Path(sys.argv[1])
enroll = Path(sys.argv[2])
bootstrap = Path(sys.argv[4])
registry = Path(sys.argv[5])
cfg.write_text(json.dumps({
    "public_host": "203.0.113.10",
    "public_ip": "203.0.113.10",
    "control_port": 443,
    "frp_control_public_port": 8443,
    "frp_control_listen_port": 443,
    "port_start": 6000,
    "port_end": 6098,
    "listen_port": 6099,
    "allocator_public_url": "https://203.0.113.10:6099/enroll",
    "tls_ca_cert": sys.argv[3],
    "client_installer_url": "https://example.test/bootstrap-client.sh",
    "enrollments_dir": str(enroll),
    "bootstrap_dir": str(bootstrap),
    "registry_file": str(registry),
}, indent=2) + "\n")
registry.write_text(json.dumps({
    "schema_version": 2,
    "reserved": [],
    "clients": {},
}, indent=2) + "\n")
PY
cat >"$TREE/etc/drlink/version" <<'EOF'
PROJECT_VERSION=2.4.0
FRP_VERSION=0.71.0
EOF

python3 -u - "$ROOT" "$WORKDIR" "$TREE" "$CTL" <<'PY' || fail "PTY create-confirm driver failed"
import os, pty, re, select, sys, time
from pathlib import Path

root, work, tree, ctl = sys.argv[1:5]
env = os.environ.copy()
env["TERM"] = "xterm"
env["PYTHONUNBUFFERED"] = "1"
env["HOME"] = str(Path(work) / "home")
env["FRP_CTL_TEST_ROOT"] = tree
env["FRP_CTL_FORCE_DRLINK"] = "1"
env["FRP_CTL_CMD_NAME"] = "drlink"
env["FRP_CTL_BIN_DIR"] = str(Path(root) / "tools")
env["FRP_SKIP_SYSTEMD"] = "1"
env.pop("FRP_CTL_TEST_INPUT", None)
env.pop("FRP_CTL_DRY_RUN", None)

CONFIRM = b"Create this client setup? [Y/n]:"
PROMPT = b"drlink> "

def run_session(answers_after_confirm, label):
    master, slave = pty.openpty()
    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.setsid()
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        if slave > 2:
            os.close(slave)
        os.execve(ctl, [ctl], env)
    os.close(slave)
    buf = b""

    def read_until(pred, timeout=8.0):
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([master], [], [], max(0.05, end - time.time()))
            if not r:
                continue
            try:
                chunk = os.read(master, 8192)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if pred(buf):
                return True
        return pred(buf)

    def send(data):
        os.write(master, data)

    if not read_until(lambda b: PROMPT in b, timeout=6.0):
        os.kill(pid, 9)
        raise SystemExit("%s: no initial prompt: %r" % (label, buf[-400:]))

    # Guided Zero-Touch: method -> Linux -> name -> blank note -> SSH only -> optional user -> default port
    send(b"create zero-touch\n")
    steps = [
        (b"Installation method", b"1\n"),
        (b"Platform", b"1\n"),
        (b"Managed Host name:", b"pty-confirm\n"),
        (b"Description", b"\n"),
        (b"SSH only", b"1\n"),
        (b"SSH username [optional]:", b"aella\n"),
        (b"SSH port", b"\n"),
    ]
    for needle, reply in steps:
        if not read_until(lambda b, n=needle: n in b, timeout=6.0):
            os.kill(pid, 9)
            raise SystemExit("%s: missing %r in %r" % (label, needle, buf[-600:]))
        send(reply)

    if not read_until(lambda b: CONFIRM in b, timeout=8.0):
        os.kill(pid, 9)
        raise SystemExit("%s: missing confirm prompt: %r" % (label, buf[-800:]))
    send(answers_after_confirm)
    read_until(lambda b: b.count(PROMPT) >= 2, timeout=8.0)
    send(b"exit\n")
    time.sleep(0.25)
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    text = buf.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    collapsed = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    same = "Create this client setup? [Y/n]: drlink>" in collapsed.replace(" ", " ")
    # Also catch prompt glued with optional spaces but no newline.
    glued = bool(re.search(r"Create this client setup\? \[Y/n\]: *drlink>", collapsed))
    # Confirm the REPL prompt after the confirm line starts on a new line.
    new_line = bool(re.search(r"Create this client setup\? \[Y/n\]:.*\n(?:.*\n)*drlink>", collapsed))
    Path(work, label + ".out").write_text(collapsed, encoding="utf-8")
    return {
        "label": label,
        "same": same or glued,
        "new_line": new_line,
        "created": "Zero-touch client command" in collapsed or "Client setup created" in collapsed
        or "Enrollment ID:" in collapsed,
        "text": collapsed,
    }

results = [
    run_session(b"Y\n", "confirm-Y"),
    run_session(b"\n", "confirm-default"),
]
for item in results:
    if item["same"]:
        raise SystemExit("%s: CONFIRM_PROMPT_AND_REPL_SAME_LINE text=%r" % (item["label"], item["text"][-500:]))
    if not item["new_line"]:
        raise SystemExit("%s: REPL_PROMPT_STARTS_NEW_LINE failed text=%r" % (item["label"], item["text"][-500:]))
print("PTY_CONFIRM_Y_NEWLINE=PASS")
print("PTY_CONFIRM_DEFAULT_NEWLINE=PASS")
print("REPL_PROMPT_STARTS_NEW_LINE=PASS")
PY

# Direct (non-REPL) command must stay clean: confirmation skipped on non-TTY,
# and stdout must not grow stray leading/trailing blank-line pairs around the
# one-shot create output.
export FRP_CTL_TEST_ROOT="$TREE"
"$CTL" create enrollment --ttl 1h --client-name direct-fmt >"$WORKDIR/direct.out" 2>"$WORKDIR/direct.err" || true
if grep -q 'Create this client setup? [Y/n]: drlink>' "$WORKDIR/direct.out" "$WORKDIR/direct.err"; then
  fail "direct command glued REPL prompt"
fi
# One-shot create enrollment is non-interactive; it should not print the REPL prompt.
if grep -qE '^drlink>' "$WORKDIR/direct.out"; then
  fail "direct command leaked REPL prompt"
fi
pass "DIRECT_COMMAND_FORMATTING_REGRESSION"

pass "CONFIRM_PROMPT_NEWLINE"
pass "DEFAULT_YES_NEWLINE"
pass "REPL_PROMPT_NEW_LINE"
echo "ALL_PTY_CREATE_CONFIRM_PASS"
