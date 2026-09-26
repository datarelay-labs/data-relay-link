#!/usr/bin/env python3
"""Shared control-state locks for backup, restore, and registry writers.

Lock order (mandatory whenever an operation takes multiple locks):

  1. server-lifecycle.lock
  2. control-state.lock
  3. registry.lock

Per-resource locks (access-control.json.lock, egress-control.json.lock,
service-profiles.json.lock, etc.) are taken ONLY after control-state.lock
and must never be acquired in reverse order.

Allocator HTTP writers take only registry.lock (plus an in-process thread
lock). They must never acquire the lifecycle or control-state locks after
registry.lock.

Inside an allocator registry.lock transaction the order is:

  1. threading LOCK
  2. registry.lock (FileLock / flock)
  3. retention cleanup via run_retention_cleanup_locked (no nested flock)
  4. enrollment / bootstrap / nonce filesystem writes

Never reacquire registry.lock through a second fd while it is already held —
Linux flock is not recursive across independent descriptors.

Enrollment pair issuance (bootstrap ticket + enrollment record) writes two
durable files that are only meaningful together, so it takes the full
lifecycle → control-state → registry set via acquire_state_dir_control_locks
and runs retention cleanup with already_locked=True.

Backup and restore take lifecycle then control-state then registry, with a
timeout, so they cannot block network operations indefinitely if a lifecycle
holder is stuck.

durable_replace() lives here for the same reason: authoritative writers need
one agreed answer for how a state file becomes visible, both against other
writers (the locks above) and against a power failure (the parent-directory
fsync).
"""
from __future__ import annotations

import fcntl
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

LIFECYCLE_LOCK_REL = "var/lib/drlink/server-lifecycle.lock"
CONTROL_STATE_LOCK_REL = "var/lib/drlink/control-state.lock"
DEFAULT_TIMEOUT_SEC = 30


class LockTimeout(TimeoutError):
    pass


class ExclusiveFileLock:
    """fcntl exclusive lock with a bounded wait. Released on process death."""

    def __init__(self, path, timeout=DEFAULT_TIMEOUT_SEC):
        self.path = Path(path)
        self.timeout = float(timeout)
        self.fd = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    self.fd = None
                    raise LockTimeout("timed out waiting for %s" % self.path)
                time.sleep(0.05)
            except Exception:
                os.close(self.fd)
                self.fd = None
                raise

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        return False


def lifecycle_lock_path(root):
    return Path(root) / LIFECYCLE_LOCK_REL


def control_state_lock_path(root):
    return Path(root) / CONTROL_STATE_LOCK_REL


def registry_lock_path(root, registry_rel="var/lib/drlink/runtime/client-inventory.json"):
    return (Path(root) / registry_rel).resolve().parent / "registry.lock"


def state_dir_lock_paths(state_dir):
    """Lifecycle / control-state / registry lock files inside a state directory.

    state_dir is the directory that holds registry.json (production:
    /var/lib/drlink). For that directory the three paths are the same inodes
    acquire_control_locks() derives from the deploy root, so writers that only
    know their configured state paths still exclude backup and restore.
    """
    state_dir = Path(state_dir).resolve()
    return (
        state_dir / Path(LIFECYCLE_LOCK_REL).name,
        state_dir / Path(CONTROL_STATE_LOCK_REL).name,
        state_dir / "registry.lock",
    )


def control_root_from_env():
    """Deploy root for lock files: FRP_DEPLOY_TEST_ROOT or live '/'."""
    return Path(os.environ.get("FRP_DEPLOY_TEST_ROOT") or "/")


_TLS = threading.local()


def _held_control_state():
    held = getattr(_TLS, "control_state", None)
    if held is None:
        _TLS.control_state = {}
        held = _TLS.control_state
    return held


def _control_state_key(root):
    return str(control_state_lock_path(root).resolve())


@contextmanager
def acquire_control_state_lock(root, timeout=DEFAULT_TIMEOUT_SEC):
    """Acquire the coarse control-state lock for cross-authority mutations.

    Linux flock is not recursive across independent descriptors. Nested
    in-process callers in the same thread reuse the held lock instead of
    opening a second fd (which would deadlock).
    """
    with _acquire_control_state_lock_path(control_state_lock_path(root), timeout=timeout) as lock:
        yield lock


@contextmanager
def _acquire_control_state_lock_path(lock_path, timeout=DEFAULT_TIMEOUT_SEC):
    key = str(Path(lock_path).resolve())
    held = _held_control_state()
    if key in held:
        yield held[key]
        return
    with ExclusiveFileLock(lock_path, timeout=timeout) as lock:
        held[key] = lock
        try:
            yield lock
        finally:
            held.pop(key, None)


@contextmanager
def mutation_lock(root=None, timeout=None, state_path=None):
    """Control-state lock for authoritative Access/Egress/Profile writers.

    When state_path is provided, the lock file is the sibling
    control-state.lock next to that authoritative JSON (the same inode
    backup/restore use for /var/lib/drlink/control-state.lock).
    """
    if timeout is None:
        timeout = float(os.environ.get("FRP_CONTROL_STATE_LOCK_TIMEOUT") or DEFAULT_TIMEOUT_SEC)
    else:
        timeout = float(timeout)
    if state_path is not None:
        lock_path = Path(state_path).resolve().parent / "control-state.lock"
        with _acquire_control_state_lock_path(lock_path, timeout=timeout) as lock:
            yield lock
        return
    root = Path(root) if root is not None else control_root_from_env()
    with acquire_control_state_lock(root, timeout=timeout) as lock:
        yield lock


@contextmanager
def acquire_control_locks(root, timeout=DEFAULT_TIMEOUT_SEC, registry_rel="var/lib/drlink/runtime/client-inventory.json"):
    """Acquire lifecycle, control-state, then registry. Same order as documented."""
    with ExclusiveFileLock(lifecycle_lock_path(root), timeout=timeout) as life:
        with acquire_control_state_lock(root, timeout=timeout) as ctrl:
            with ExclusiveFileLock(registry_lock_path(root, registry_rel), timeout=timeout) as reg:
                yield (life, ctrl, reg)


@contextmanager
def acquire_state_dir_control_locks(state_dir, timeout=DEFAULT_TIMEOUT_SEC):
    """acquire_control_locks() for callers that only know their state directory.

    Same lock order (lifecycle → control-state → registry) and the same lock
    files, so a multi-file durable write inside state_dir cannot interleave
    with a backup or restore of that directory.
    """
    life_path, _ctrl_path, reg_path = state_dir_lock_paths(state_dir)
    with ExclusiveFileLock(life_path, timeout=timeout) as life:
        with _acquire_control_state_lock_path(_ctrl_path, timeout=timeout) as ctrl:
            with ExclusiveFileLock(reg_path, timeout=timeout) as reg:
                yield (life, ctrl, reg)


def fsync_dir(path):
    """Flush a directory entry to stable storage. True when it took effect.

    Returns False instead of raising on filesystems that do not support it:
    a diagnostic-grade durability gap must not turn an operator command into
    a failure.
    """
    if os.name != "posix":
        return False
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return False
    try:
        os.fsync(fd)
        return True
    except OSError:
        # Some overlay, NFS and FAT mounts reject fsync on a directory fd.
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def durable_replace(tmp, path):
    """os.replace() that also survives a power failure (F16).

    os.replace() is atomic but not durable. Writers already fsync the temp
    file's contents, so the bytes are safe; the directory entry that gives
    those bytes their name is not. After a power failure the rename can be
    lost while the write that preceded it in program order is kept, which
    for authoritative state, secrets, registries and config means reverting
    to a superseded document — or, for a name that never existed before,
    losing the record entirely. Both are semantic corruption, not just a
    stale read.

    Only the parent directory is synced. Callers that create a new name must
    fsync their own temp data first, exactly as they do today.
    """
    path = Path(path)
    os.replace(str(tmp), str(path))
    return fsync_dir(path.parent)
