#!/usr/bin/env python3
"""Append-only structured audit log for frp-auto-deploy.

Audit failures must not corrupt the primary operation. Callers should treat
write errors as warnings unless they explicitly choose fail-closed.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

AUDIT_SCHEMA = 1
DEFAULT_AUDIT_PATH = "/var/log/drlink/audit.jsonl"
MAX_RECORD_BYTES = 16_384
SECRET_KEY_RE = re.compile(
    r"(ticket|secret|token|password|passwd|private.?key|mac_key|enrollment.?code|"
    r"bootstrap|hmac|auth_token|server_token)",
    re.IGNORECASE,
)
# Value patterns for current bt1.<id>.<secret> tickets and legacy btck.* form.
SECRET_VALUE_RE = re.compile(
    r"(BEGIN [A-Z ]*PRIVATE KEY|"
    r"bt1\.[0-9a-f]{8,}\.[0-9a-f]{16,}|"
    r"btck\.[0-9a-f]{16}\.|"
    r"zt1\.[A-Za-z0-9_-]{16,}|"
    r"enroll-secret-)",
    re.IGNORECASE,
)


def _redact_short_url_paths(text):
    return re.sub(r'(/i/)[^/?\s#]+', r'\1<redacted>', str(text), flags=re.IGNORECASE)


class AuditError(Exception):
    pass


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def audit_path():
    root = os.environ.get("FRP_DEPLOY_TEST_ROOT", "")
    configured = os.environ.get("FRP_AUDIT_LOG", "")
    if configured:
        path = Path(configured)
    else:
        path = Path(DEFAULT_AUDIT_PATH)
    if root:
        text = str(path)
        if text.startswith("/"):
            path = Path(root + text)
        else:
            path = Path(root) / path
    return path


def audit_lock_path():
    path = audit_path()
    return path.parent / (path.name + ".lock")


def _redact(value):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                out[key] = "[REDACTED]"
            else:
                out[key] = _redact(item)
        return out
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    text = _redact_short_url_paths(str(value))
    if SECRET_VALUE_RE.search(text):
        return "[REDACTED]"
    return text


def _atomic_append(path: Path, line: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()
        os.chmod(path, 0o600)
        # Do NOT chmod shared /var/log/drlink parent — clears egress ACL/mask.
    else:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            os.chmod(path, 0o600)
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _with_audit_lock(fn):
    """Serialize emit/rotation with a simple exclusive flock."""
    lock_path = audit_lock_path()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fn()
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def emit(event, actor="local-root", details=None, fail_closed=False, **fields):
    """Write one JSONL audit record. Returns True on success."""
    record = {
        "schema_version": AUDIT_SCHEMA,
        "timestamp": utc_now_iso(),
        "event": str(event),
        "actor": str(actor or "local-root"),
    }
    for key, value in fields.items():
        if value is not None:
            record[key] = value
    if details:
        record["details"] = _redact(details)
    record = _redact(record)
    try:
        def _write():
            rotate_if_needed(
                max_bytes=int(os.environ.get("FRP_AUDIT_ROTATE_BYTES", str(5 * 1024 * 1024))),
                keep=int(os.environ.get("FRP_AUDIT_ROTATE_KEEP", "5")),
            )
            payload = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            if len(payload.encode("utf-8")) > MAX_RECORD_BYTES:
                raise AuditError("audit record too large")
            _atomic_append(audit_path(), payload + "\n")
            return True

        return _with_audit_lock(_write)
    except Exception as exc:
        if fail_closed:
            raise AuditError(str(exc)) from exc
        sys_stderr_warn(f"WARNING: audit log write failed: {exc}")
        return False


def try_emit(event, **kwargs):
    """Emit an audit event; never raise to the caller."""
    try:
        return emit(event, **kwargs)
    except Exception:
        return False


def discover_audit_path(caller_file=None):
    candidates = []
    if caller_file:
        here = Path(caller_file).resolve()
        candidates.append(here.parent.parent / "lib" / "frp_audit.py")
        candidates.append(here.parent.parent / "lib" / "frp-auto-deploy" / "frp_audit.py")
    root = os.environ.get("FRP_DEPLOY_TEST_ROOT", "")
    if root:
        candidates.append(Path(root) / "usr/local/lib/drlink/frp_audit.py")
    candidates.append(Path("/usr/local/lib/drlink/frp_audit.py"))
    here = Path(__file__).resolve()
    candidates.append(here)
    for path in candidates:
        if path.is_file():
            return path
    return None


def emit_from_tool(caller_file, event, **kwargs):
    """Load this module from the repo or installed path, then emit. Never raises."""
    try:
        import importlib.util

        path = discover_audit_path(caller_file)
        if path is None:
            return False
        spec = importlib.util.spec_from_file_location("frp_audit", str(path))
        if spec is None or spec.loader is None:
            return False
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.try_emit(event, **kwargs)
    except Exception:
        return False


def sys_stderr_warn(message):
    import sys

    sys.stderr.write(message + "\n")


def rotate_if_needed(max_bytes=5 * 1024 * 1024, keep=5):
    """Rotate audit.jsonl so at most `keep` rotated files remain (.1 .. .keep)."""
    path = audit_path()
    if not path.is_file() or path.stat().st_size < max_bytes:
        return
    keep = max(1, int(keep))
    oldest = Path(f"{path}.{keep}")
    if oldest.exists():
        oldest.unlink()
    for index in range(keep - 1, 0, -1):
        src = Path(f"{path}.{index}")
        if src.exists():
            src.replace(Path(f"{path}.{index + 1}"))
    path.replace(Path(f"{path}.1"))
    path.touch()
    os.chmod(path, 0o600)


def main(argv=None):
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Append or show frp-auto-deploy audit events")
    parser.add_argument("action", nargs="?", default="tail", choices=["emit", "tail"])
    parser.add_argument("--event")
    parser.add_argument("--actor", default="local-root")
    parser.add_argument("-n", "--lines", type=int, default=50)
    args = parser.parse_args(argv)
    if args.action == "emit":
        if not args.event:
            raise SystemExit("ERROR: --event is required")
        emit(args.event, actor=args.actor)
        return 0
    path = audit_path()
    if not path.is_file():
        sys.stdout.write("(no audit log)\n")
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines[-max(args.lines, 1) :]:
        sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
