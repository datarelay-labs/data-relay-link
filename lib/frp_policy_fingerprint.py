#!/usr/bin/env python3
"""Policy file identity for hot-reload caches.

Prefer a fingerprint of resolved path + device + inode + size + mtime_ns
instead of mtime alone so atomic replace (new inode, same timestamp on coarse
filesystems) and same-mtime content swaps still trigger reload.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

PolicyFingerprint = Tuple[
    str,  # resolved path
    Optional[int],  # st_dev
    Optional[int],  # st_ino
    Optional[int],  # st_size
    Optional[int],  # st_mtime_ns
]


def policy_file_fingerprint(path: Optional[Path]) -> PolicyFingerprint:
    if path is None:
        return ("", None, None, None, None)
    try:
        resolved = Path(path).resolve()
    except OSError:
        resolved = Path(path)
    try:
        st = resolved.stat()
    except OSError:
        return (str(resolved), None, None, None, None)
    mtime_ns = getattr(st, "st_mtime_ns", None)
    if mtime_ns is None:
        mtime_ns = int(st.st_mtime * 1_000_000_000)
    return (
        str(resolved),
        int(st.st_dev),
        int(st.st_ino),
        int(st.st_size),
        int(mtime_ns),
    )
