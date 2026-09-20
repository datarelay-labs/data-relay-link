#!/usr/bin/env python3
"""Resolve the pinned official MCP SDK interpreter for interop regressions."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]


def resolve_mcp_sdk_python() -> Optional[str]:
    """Return path to a usable MCP SDK python, or None if missing."""
    candidates = []
    env = (os.environ.get("DRLINK_MCP_SDK_PYTHON") or "").strip()
    if env:
        candidates.append(env)
    candidates.append(str(ROOT / ".venv" / "mcp-sdk" / "bin" / "python"))
    # Legacy host path retained only as a last-resort local fallback.
    candidates.append("/tmp/mcp-sdk-venv/bin/python")
    seen = set()
    for path in candidates:
        if not path or path in seen:
            continue
        seen.add(path)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None
