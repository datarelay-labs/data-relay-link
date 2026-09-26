#!/usr/bin/env python3
"""Install/run the Data Relay Link MCP Bridge."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _load():
    here = Path(__file__).resolve()
    candidates = [
        here.parent.parent / "lib" / "drlink_mcp_bridge.py",
        Path("/usr/local/lib/drlink") / "drlink_mcp_bridge.py",
    ]
    root = os.environ.get("FRP_DEPLOY_TEST_ROOT") or ""
    if root:
        candidates.insert(0, Path(root) / "usr/local/lib/drlink" / "drlink_mcp_bridge.py")
    import importlib.util

    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location("drlink_mcp_bridge", str(path))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise SystemExit("ERROR: missing drlink_mcp_bridge.py")


if __name__ == "__main__":
    mod = _load()
    raise SystemExit(mod.main(sys.argv[1:]))
