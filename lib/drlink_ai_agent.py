#!/usr/bin/env python3
"""Endpoint-side AI operation executor with fail-closed path and exec safety.

This module is installed on Data Relay Link clients. It is not an MCP server.
The server-side MCP Bridge dispatches authorized jobs here over the agent RPC.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from drlink_control_plane import ControlPlaneError, path_allowed, validate_safe_path

MAX_STDOUT_BYTES = 64 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_FILE_BYTES = 1024 * 1024
DEFAULT_EXEC_TIMEOUT = 30


def _bound(data: bytes, limit: int) -> tuple[bytes, bool]:
    if data is None:
        return b"", False
    if len(data) <= limit:
        return data, False
    return data[:limit], True


def _is_unsafe_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    if stat.S_ISDIR(mode) or stat.S_ISREG(mode):
        return False
    return True


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def read_file(path: str, patterns: list[str]) -> dict:
    resolved = validate_safe_path(path, patterns)
    if resolved.is_symlink() or Path(path).is_symlink():
        raise ControlPlaneError("symlink escape denied")
    if _is_unsafe_file(resolved):
        raise ControlPlaneError("special file denied")
    if not resolved.is_file():
        raise ControlPlaneError("not a regular file")
    size = resolved.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ControlPlaneError("file too large")
    data = resolved.read_bytes()
    text, truncated = _bound(data, MAX_FILE_BYTES)
    return {"path": str(resolved), "bytes": len(text), "truncated": truncated, "content_b64": _b64(text)}


def write_file(path: str, content: bytes, patterns: list[str]) -> dict:
    if len(content) > MAX_FILE_BYTES:
        raise ControlPlaneError("payload too large")
    raw = Path(path)
    decoded_ok = path_allowed(str(path), patterns)
    if not decoded_ok:
        # New files: parent must be in scope after canonicalization.
        parent = Path(os.path.realpath(str(raw.parent)))
        if not path_allowed(str(parent / raw.name), patterns) and not path_allowed(str(parent), patterns):
            raise ControlPlaneError("path is outside allowed scope")
    dest_dir = Path(os.path.realpath(str(raw.parent)))
    dest_dir.mkdir(parents=True, exist_ok=True)
    if dest_dir.is_symlink():
        raise ControlPlaneError("symlink escape denied")
    tmp = dest_dir / (".drlink-ai-" + raw.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(str(tmp), flags, 0o600)
    try:
        os.write(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)
    dest = dest_dir / raw.name
    if dest.exists() or dest.is_symlink():
        try:
            st = dest.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                os.unlink(str(tmp))
                raise ControlPlaneError("unsafe overwrite denied")
        except FileNotFoundError:
            pass
    os.replace(str(tmp), str(dest))
    final = Path(os.path.realpath(str(dest)))
    if final.is_symlink() or not path_allowed(str(final), patterns):
        try:
            final.unlink()
        except OSError:
            pass
        raise ControlPlaneError("path is outside allowed scope")
    return {"path": str(final), "bytes": len(content)}


def exec_command(command: str, timeout: int) -> dict:
    timeout = int(timeout or DEFAULT_EXEC_TIMEOUT)
    if timeout < 1:
        timeout = 1
    start = time.monotonic()
    proc = subprocess.Popen(
        ["/bin/sh", "-c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    result = "ALLOW"
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            proc.kill()
        stdout, stderr = proc.communicate()
        code = -9
        result = "TIMEOUT"
    duration_ms = int((time.monotonic() - start) * 1000)
    out, out_trunc = _bound(stdout or b"", MAX_STDOUT_BYTES)
    err, err_trunc = _bound(stderr or b"", MAX_STDERR_BYTES)
    return {
        "result": result if result == "TIMEOUT" else "ALLOW",
        "exit_status": code,
        "duration_ms": duration_ms,
        "stdout": out.decode("utf-8", "replace"),
        "stderr": err.decode("utf-8", "replace"),
        "stdout_truncated": out_trunc,
        "stderr_truncated": err_trunc,
        "fingerprint": _fingerprint(command),
    }


def _fingerprint(command: str) -> str:
    import hashlib

    return hashlib.sha256(command.encode("utf-8")).hexdigest()[:16]


def list_processes() -> dict:
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,user,comm"], text=True, timeout=5)
    except Exception as exc:
        raise ControlPlaneError("process list failed: %s" % exc) from exc
    lines = out.splitlines()[:200]
    return {"lines": lines, "count": len(lines)}


def get_system_info() -> dict:
    uname = os.uname()
    return {
        "sysname": uname.sysname,
        "nodename": uname.nodename,
        "release": uname.release,
        "machine": uname.machine,
    }


def execute_local(capability: str, arguments: dict, *, patterns: list[str], timeout: Optional[int]) -> dict:
    cap = capability
    if cap == "get_system_info":
        return get_system_info()
    if cap == "list_processes":
        return list_processes()
    if cap == "read_file":
        return read_file(arguments.get("path") or arguments.get("operand") or "", patterns)
    if cap in ("write_file", "upload_file"):
        import base64

        content = arguments.get("content")
        if isinstance(content, str) and arguments.get("encoding") == "base64":
            payload = base64.b64decode(content)
        elif isinstance(content, bytes):
            payload = content
        else:
            payload = str(content or "").encode("utf-8")
        return write_file(arguments.get("path") or "", payload, patterns)
    if cap == "download_file":
        return read_file(arguments.get("path") or "", patterns)
    if cap == "exec":
        return exec_command(arguments.get("command") or arguments.get("operand") or "", timeout or DEFAULT_EXEC_TIMEOUT)
    raise ControlPlaneError("unsupported local capability %s" % cap)


def _agent_post(url: str, token: str, body: dict, timeout: float = 10) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
        try:
            return json.loads(payload)
        except Exception:
            raise ControlPlaneError("agent RPC HTTP %s" % exc.code) from exc


class AgentLoop:
    """Poll the MCP Bridge for authorized jobs and execute them locally."""

    def __init__(self, base_url: str, token: str, stop_event: Optional[threading.Event] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.stop_event = stop_event or threading.Event()

    def run_once(self) -> int:
        payload = _agent_post(self.base_url + "/agent/v1/claim", self.token, {"limit": 4})
        jobs = payload.get("jobs") or []
        for job in jobs:
            try:
                result = execute_local(
                    job.get("capability") or "",
                    job.get("arguments") or {},
                    patterns=job.get("patterns") or [],
                    timeout=job.get("timeout"),
                )
            except ControlPlaneError as exc:
                result = {"result": "DENY", "error": str(exc)}
            except Exception as exc:
                result = {"result": "ERROR", "error": str(exc)}
            _agent_post(
                self.base_url + "/agent/v1/complete",
                self.token,
                {"id": job.get("id"), "result": result},
            )
        return len(jobs)

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                pass
            self.stop_event.wait(0.05)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Data Relay Link AI agent (not an MCP server)")
    parser.add_argument("--url", default=os.environ.get("DRLINK_MCP_URL", "http://127.0.0.1:6103"))
    parser.add_argument("--token-file", default=os.environ.get("DRLINK_AI_AGENT_TOKEN_FILE", "/etc/drlink/ai-agent.token"))
    args = parser.parse_args(argv)
    token = os.environ.get("DRLINK_AI_AGENT_TOKEN") or ""
    if not token and args.token_file and os.path.isfile(args.token_file):
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
    if not token:
        raise SystemExit("ERROR: missing AI agent token")
    AgentLoop(args.url, token).run()


if __name__ == "__main__":
    main()
