#!/usr/bin/env python3
"""Endpoint-side AI operation executor with fail-closed path and exec safety."""
from __future__ import annotations

import os
import signal
import stat
import subprocess
import time
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


def read_file(path: str, patterns: list[str]) -> dict:
    resolved = validate_safe_path(path, patterns)
    if resolved.is_symlink() or Path(path).is_symlink():
        # Followed realpath must still be in scope (validate_safe_path). If the
        # original path is a symlink, require the symlink itself to live in-tree
        # AND the target to stay in-tree.
        link_parent = Path(os.path.realpath(str(Path(path).parent)))
        if not path_allowed(str(resolved), patterns) or not path_allowed(str(link_parent), patterns):
            raise ControlPlaneError("symlink escape denied")
        if not path_allowed(str(Path(path).parent / Path(path).name), patterns):
            # original location
            orig = Path(path)
            if not path_allowed(str(orig.parent), patterns):
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
    if not str(path).startswith("/"):
        raise ControlPlaneError("path must be absolute")
    parent = Path(os.path.realpath(str(raw.parent)))
    if not path_allowed(str(parent), patterns) and not path_allowed(str(parent) + "/", patterns):
        # allow writing a new file whose parent matches a /** prefix
        if not path_allowed(str(raw), patterns) and not _parent_in_scope(parent, patterns):
            raise ControlPlaneError("path is outside allowed scope")
    dest_dir = parent
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_dir / (".drlink-ai-" + raw.name + ".tmp")
    tmp.write_bytes(content)
    os.replace(str(tmp), str(dest_dir / raw.name))
    final = Path(os.path.realpath(str(dest_dir / raw.name)))
    if not path_allowed(str(final), patterns):
        try:
            final.unlink()
        except OSError:
            pass
        raise ControlPlaneError("path is outside allowed scope")
    return {"path": str(final), "bytes": len(content)}


def _parent_in_scope(parent: Path, patterns: list[str]) -> bool:
    return path_allowed(str(parent), patterns) or path_allowed(str(parent / ".drlink-scope"), patterns)


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


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
