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

from datetime import datetime, timezone

from drlink_control_plane import ControlPlaneError, path_allowed, validate_safe_path


def _deadline_passed(deadline_at: Optional[str]) -> bool:
    text = str(deadline_at or "").strip()
    if not text:
        return False
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        deadline = datetime.fromisoformat(text)
    except ValueError:
        return False
    now = datetime.now(timezone.utc)
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return now >= deadline

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


# Idle claim polls must not run at interactive rate. A busy poll stays short
# so a queued job is still picked up inside the MCP wait.
AI_AGENT_IDLE_POLL_SECONDS = 2.0
AI_AGENT_BUSY_POLL_SECONDS = 0.05


class AgentLoop:
    """Poll the Server for authorized jobs and execute them locally on this host.

    Production transport uses enrolled management identity against the Server
    management URL (``/v1/ai-jobs/claim|complete``). Bearer token + MCP Bridge
    ``/agent/v1/*`` remains available for hermetic tests.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        *,
        agent_root: Optional[str] = None,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.token = token or ""
        self.agent_root = agent_root
        self.stop_event = stop_event or threading.Event()
        if not self.token and not self.agent_root:
            raise ValueError("AgentLoop requires bearer token or agent_root")

    def _claim(self) -> list:
        if self.agent_root:
            import drlink_mgmt_sync as mgmt

            payload = mgmt.claim_ai_jobs_on_server(root=self.agent_root, limit=4)
            return list(payload.get("jobs") or [])
        payload = _agent_post(self.base_url + "/agent/v1/claim", self.token, {"limit": 4})
        return list(payload.get("jobs") or [])

    def _complete(
        self,
        job_id: str,
        result: dict,
        *,
        claim_token: Optional[str] = None,
        attempt_id: Optional[str] = None,
    ) -> None:
        if self.agent_root:
            import drlink_mgmt_sync as mgmt

            mgmt.complete_ai_job_on_server(
                root=self.agent_root,
                job_id=job_id,
                result=result,
                claim_token=claim_token,
                attempt_id=attempt_id,
            )
            return
        body = {"id": job_id, "result": result}
        if claim_token is not None:
            body["claim_token"] = claim_token
        if attempt_id is not None:
            body["attempt_id"] = attempt_id
        _agent_post(
            self.base_url + "/agent/v1/complete",
            self.token,
            body,
        )

    def run_once(self) -> int:
        jobs = self._claim()
        for job in jobs:
            job_id = job.get("id")
            claim_token = job.get("claim_token")
            attempt_id = job.get("attempt_id")
            if _deadline_passed(job.get("deadline_at")):
                result = {
                    "result": "DENY",
                    "error": "job deadline expired before execution",
                }
                try:
                    self._complete(
                        job_id,
                        result,
                        claim_token=claim_token,
                        attempt_id=attempt_id,
                    )
                except Exception:
                    pass
                continue
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
            try:
                self._complete(
                    job_id,
                    result,
                    claim_token=claim_token,
                    attempt_id=attempt_id,
                )
            except Exception:
                # Keep polling; Server-side job remains running until timeout/retry policy.
                pass
        return len(jobs)

    def run(self) -> None:
        while not self.stop_event.is_set():
            found = 0
            try:
                found = int(self.run_once() or 0)
            except Exception:
                found = 0
            delay = AI_AGENT_BUSY_POLL_SECONDS if found else AI_AGENT_IDLE_POLL_SECONDS
            self.stop_event.wait(delay)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Data Relay Link AI agent (not an MCP server)")
    parser.add_argument(
        "--url",
        default=os.environ.get("DRLINK_MCP_URL", ""),
        help="Optional MCP Bridge base URL for bearer-token test mode",
    )
    parser.add_argument(
        "--token-file",
        default=os.environ.get("DRLINK_AI_AGENT_TOKEN_FILE", "/etc/drlink/ai-agent.token"),
    )
    parser.add_argument(
        "--agent-root",
        default=os.environ.get("DRLINK_AGENT_ROOT", ""),
        help="Agent filesystem root; when set, uses enrolled management identity",
    )
    args = parser.parse_args(argv)
    agent_root = str(args.agent_root or "").strip() or None
    token = os.environ.get("DRLINK_AI_AGENT_TOKEN") or ""
    if not token and args.token_file and os.path.isfile(args.token_file):
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
    # Production default: management identity on the enrolled Agent root.
    if not token:
        if agent_root is None:
            agent_root = "/"
        AgentLoop(agent_root=agent_root).run()
        return
    if not args.url:
        raise SystemExit("ERROR: bearer-token mode requires --url / DRLINK_MCP_URL")
    AgentLoop(args.url, token, agent_root=None).run()


if __name__ == "__main__":
    main()
