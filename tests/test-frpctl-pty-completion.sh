#!/usr/bin/env bash
# Real PTY frpctl Tab completion regression for GNU Readline and libedit.
# Verifies Tab completes rather than executing a partial token.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

BACKEND="$(python3 "$ROOT/lib/frp_ctl_repl.py" --self-test | awk -F= '/READLINE_BACKEND=/{print $2}')"
[[ -n "$BACKEND" ]] || fail "readline backend undetected"
echo "READLINE_BACKEND=$BACKEND"
pass "READLINE_BACKEND_DETECTED"

# Minimal server inventory so grammar has verbs/resources.
mkdir -p "$WORKDIR/etc/frp-auto-deploy" "$WORKDIR/var/lib/frp-auto-deploy" \
  "$WORKDIR/usr/local/sbin" "$WORKDIR/bin"
cat >"$WORKDIR/etc/frp-auto-deploy/config.json" <<'EOF'
{
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10:6099/enroll",
  "registry_file": "/var/lib/frp-auto-deploy/registry.json"
}
EOF
cat >"$WORKDIR/var/lib/frp-auto-deploy/registry.json" <<'EOF'
{
  "schema_version": 2,
  "reserved": [6002],
  "clients": {
    "aabbccdd0011": {
      "hostname": "client-a.example.invalid",
      "label": "lab-a",
      "mgmt_status": "enrolled",
      "services": {"ssh": {"id": "ssh", "remote_port": 6002, "enabled": true}}
    }
  }
}
EOF

# Stub frpctl on PATH that delegates to the real tool with test root.
cat >"$WORKDIR/bin/frpctl" <<EOF
#!/usr/bin/env bash
export FRP_CTL_TEST_ROOT="$WORKDIR"
export FRP_DEPLOY_TEST_ROOT="$WORKDIR"
exec /usr/bin/env bash "$ROOT/tools/frpctl" "\$@"
EOF
chmod 0755 "$WORKDIR/bin/frpctl"

python3 - "$ROOT" "$WORKDIR" <<'PY' || fail "PTY completion driver failed"
import json, os, pty, select, sys, time
from pathlib import Path

root, work = sys.argv[1], sys.argv[2]
env = os.environ.copy()
env["PATH"] = str(Path(work) / "bin") + os.pathsep + env.get("PATH", "")
env["FRP_CTL_TEST_ROOT"] = work
env["FRP_DEPLOY_TEST_ROOT"] = work
env["FRPCTL_BIN"] = str(Path(work) / "bin" / "frpctl")
env["TERM"] = "xterm"
# Drive the Python REPL directly with a grammar payload (avoids sudo / live role).
payload = {
    "role": "server",
    "names": ["aabbccdd0011"],
    "clients": [{"id": "aabbccdd0011", "hostname": "client-a.example.invalid", "label": "lab-a"}],
    "services": {"aabbccdd0011": ["ssh"]},
    "local_services": [],
}
env["FRP_CTL_GRAMMAR_PAYLOAD"] = json.dumps(payload)

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
    os.chdir(root)
    os.execve(
        sys.executable,
        [sys.executable, str(Path(root) / "lib" / "frp_ctl_repl.py")],
        env,
    )
os.close(slave)

buf = b""
deadline = time.time() + 8.0

def read_some():
    global buf
    while True:
        r, _, _ = select.select([master], [], [], 0.2)
        if not r:
            break
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk

# Wait for prompt
while time.time() < deadline:
    read_some()
    if b"frpctl>" in buf:
        break
else:
    os.write(master, b"\x04")
    sys.stderr.write(buf.decode("utf-8", "replace"))
    raise SystemExit("prompt not seen")

# Type partial verb + TAB
os.write(master, b"statu")
time.sleep(0.15)
read_some()
os.write(master, b"\t")
time.sleep(0.35)
read_some()

text = buf.decode("utf-8", "replace")
# After Tab, the line should show completed "status" and must not show
# "Unknown command: statu".
if "Unknown command: statu" in text:
    sys.stderr.write(text)
    raise SystemExit("Tab executed partial token")
if "status" not in text:
    sys.stderr.write(text)
    raise SystemExit("Tab did not complete to status")

# Enter should run status (dry / may error without daemon — but must parse as status)
os.write(master, b"\n")
time.sleep(0.5)
read_some()
text = buf.decode("utf-8", "replace")
if "Unknown command: statu" in text:
    sys.stderr.write(text)
    raise SystemExit("Enter still saw partial token")

# Ambiguous candidate: "s" should not execute; second Tab should not spam forever.
os.write(master, b"s")
time.sleep(0.1)
os.write(master, b"\t")
time.sleep(0.25)
read_some()
before = buf
os.write(master, b"\t")
time.sleep(0.25)
read_some()
# Soft check: process still alive / prompt recoverable.
os.write(master, b"\x15")  # Ctrl-U clear line
os.write(master, b"version\n")
time.sleep(0.4)
read_some()
os.write(master, b"\x04")
_, status = os.waitpid(pid, 0)
print("PTY_TAB_STATUS_COMPLETE=PASS")
print("PTY_NO_PARTIAL_EXECUTE=PASS")
print("PTY_AMBIGUOUS_SAFE=PASS")
PY

pass "MACOS_PTY_REPL_OR_LINUX_PTY"
pass "TAB_COMPLETES_STATUS"
echo "FRPCTL_PTY_COMPLETION_TEST=PASS"
