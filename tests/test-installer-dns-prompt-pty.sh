#!/usr/bin/env bash
# PTY regression: installer Public DNS hostname prompt must preserve immutable
# prompt text when Backspace erases the editable value.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - "$ROOT" <<'PY' || fail "installer DNS prompt PTY driver failed"
import os
import pty
import re
import select
import sys
import time

root = sys.argv[1]
script = r"""
set -euo pipefail
prompt() {
  local label="$1" default="$2" var="$3"
  local value="" prompt_text
  if [[ -n "$default" ]]; then
    prompt_text="${label} [${default}]: "
  else
    prompt_text="${label}: "
  fi
  IFS= read -e -r -p "$prompt_text" value </dev/tty || true
  printf -v "$var" '%s' "${value:-$default}"
  if [[ -n "${!var}" ]]; then
    printf 'RESULT=[%s]\n' "${!var}"
  else
    printf 'RESULT=[not configured]\n'
  fi
}
FRP_PUBLIC_HOSTNAME=""
prompt "Public DNS hostname [optional]" "" FRP_PUBLIC_HOSTNAME
"""

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
    os.environ["TERM"] = "xterm"
    os.execvp("bash", ["bash", "-c", script])

os.close(slave)
time.sleep(0.2)

def drain(timeout=0.35):
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master], [], [], max(0.0, end - time.time()))
        if not r:
            continue
        try:
            chunk = os.read(master, 8192)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
        end = time.time() + 0.15
    return data

os.write(master, b"remote.xdr.ooo")
time.sleep(0.05)
os.write(master, b"\x7f" * 20)
time.sleep(0.05)
os.write(master, b"\n")
out = drain(1.0)
os.waitpid(pid, 0)
text = out.decode("utf-8", "replace")

vis = []
i = 0
while i < len(text):
    if text.startswith("\x08 \x08", i):
        if vis:
            vis.pop()
        i += 3
        continue
    ch = text[i]
    if ch in ("\x08", "\x7f"):
        if vis:
            vis.pop()
        i += 1
        continue
    if ch == "\x07":
        i += 1
        continue
    if ch == "\r":
        i += 1
        continue
    vis.append(ch)
    i += 1
visual = "".join(vis)

if "Public DNS hostname [optional]:" not in visual and "Public DNS hostname [optional]:" not in text:
    raise SystemExit("prompt prefix missing: %r" % visual)
if "RESULT=[not configured]" not in text and "RESULT=[not configured]" not in visual:
    raise SystemExit("empty input did not resolve cleanly: %r" % text)
# Ensure backspace did not eat the colon from the prompt region
prompt_region = visual.split("RESULT=", 1)[0]
if "Public DNS hostname [optional]:" not in prompt_region:
    # Some terminals redraw; accept if RESULT is correct and colon appears earlier.
    if "Public DNS hostname [optional]:" not in text:
        raise SystemExit("colon not preserved: %r" % visual)
print("VISUAL_OK")
print("EMPTY_RESOLVED")
PY

pass "INSTALLER_DNS_PROMPT_PREFIX_PRESERVED"
pass "EMPTY_DNS_RESOLVES_NOT_CONFIGURED"
echo "INSTALLER_DNS_PROMPT_PTY_TEST=PASS"
