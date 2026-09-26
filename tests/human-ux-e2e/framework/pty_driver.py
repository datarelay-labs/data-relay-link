"""PTY driver for human input behavior tests."""
from __future__ import annotations

import os
import pty
import select
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class PtyResult:
    output: str
    visual: str
    exit_code: int


def _interpret_visual(text: str) -> str:
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
        # Strip simple CSI sequences
        if ch == "\x1b" and i + 1 < len(text) and text[i + 1] == "[":
            j = i + 2
            while j < len(text) and text[j] not in "ABCDEFGHJKSTLfmnshul":
                j += 1
            i = min(j + 1, len(text))
            continue
        vis.append(ch)
        i += 1
    return "".join(vis)


def run_pty_script(
    bash_script: str,
    *,
    feed: Callable[[int], None],
    env: Optional[dict] = None,
    drain_timeout: float = 1.2,
) -> PtyResult:
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
        child_env = {**os.environ, **(env or {}), "TERM": "xterm"}
        os.execvpe("bash", ["bash", "-c", bash_script], child_env)

    os.close(slave)
    time.sleep(0.15)

    def drain(timeout: float = 0.35) -> bytes:
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
            end = time.time() + 0.12
        return data

    # Allow prompt to appear
    pre = drain(0.4)
    feed(master)
    out = pre + drain(drain_timeout)
    _, status = os.waitpid(pid, 0)
    exit_code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status
    text = out.decode("utf-8", "replace")
    return PtyResult(output=text, visual=_interpret_visual(text), exit_code=exit_code)


def feed_bytes(master: int, data: bytes, *, pause: float = 0.04) -> None:
    os.write(master, data)
    time.sleep(pause)


def public_dns_prompt_script() -> str:
    """Minimal replica of installer Public DNS hostname prompt contract."""
    return r"""
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
