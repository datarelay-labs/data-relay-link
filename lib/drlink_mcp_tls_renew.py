#!/usr/bin/env python3
"""Oneshot MCP TLS renewal entrypoint for systemd timer."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _load():
    here = Path(__file__).resolve().parent
    candidates = [here, Path("/usr/local/lib/drlink")]
    env = os.environ.get("DRLINK_TEST_ROOT")
    if env:
        candidates.insert(0, Path(env) / "usr/local/lib/drlink")
    for path in candidates:
        if (path / "drlink_mcp_tls.py").is_file():
            sys.path.insert(0, str(path))
            break
    import drlink_mcp_tls as mcp_tls  # noqa: E402
    from drlink_control_plane import ControlPlane  # noqa: E402

    return mcp_tls, ControlPlane


def main() -> int:
    mcp_tls, ControlPlane = _load()
    root = os.environ.get("DRLINK_TEST_ROOT") or None
    plane = ControlPlane(root)
    result = mcp_tls.renew_if_due(plane, root, reload=True)
    if result.get("renewed"):
        sys.stdout.write("MCP TLS renewal: renewed\n")
        return 0
    reason = result.get("reason") or "skipped"
    sys.stdout.write("MCP TLS renewal: %s\n" % reason)
    if reason == "failed":
        # Non-zero so journal records failure, but certificate remains valid.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
