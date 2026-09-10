#!/usr/bin/env python3
"""Shared control-state locks for backup, restore, and registry writers.

Lock order (mandatory whenever an operation takes both):

  1. server-lifecycle.lock
  2. registry.lock

Allocator HTTP writers take only registry.lock (plus an in-process thread
lock). They must never acquire the lifecycle lock after registry.lock.

Inside an allocator registry.lock transaction the order is:

  1. threading LOCK
  2. registry.lock (FileLock / flock)
  3. retention cleanup via run_retention_cleanup_locked (no nested flock)
  4. enrollment / bootstrap / nonce filesystem writes

Never reacquire registry.lock through a second fd while it is already held —
Linux flock is not recursive across independent descriptors.

Backup and restore take lifecycle then registry, with a timeout, so they
cannot block network operations indefinitely if a lifecycle holder is stuck.
"""
from __future__ import annotations

import fcntl
import os
import time
from contextlib import contextmanager
from pathlib import Path

LIFECYCLE_LOCK_REL = "var/lib/drlink/server-lifecycle.lock"
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


def registry_lock_path(root, registry_rel="var/lib/drlink/registry.json"):
    return (Path(root) / registry_rel).resolve().parent / "registry.lock"


@contextmanager
def acquire_control_locks(root, timeout=DEFAULT_TIMEOUT_SEC, registry_rel="var/lib/drlink/registry.json"):
    """Acquire lifecycle then registry. Same order as documented above."""
    with ExclusiveFileLock(lifecycle_lock_path(root), timeout=timeout) as life:
        with ExclusiveFileLock(registry_lock_path(root, registry_rel), timeout=timeout) as reg:
            yield (life, reg)
