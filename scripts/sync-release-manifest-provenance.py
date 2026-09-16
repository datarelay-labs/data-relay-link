#!/usr/bin/env python3
"""Stamp release-manifest.json provenance from VERSION + exact Git HEAD.

For development/preview trees, git_ref and source_head become the current
40-character HEAD. Stable channel keeps git_ref=vPROJECT_VERSION and requires
source_head to match HEAD (caller still responsible for creating the tag).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from frp_version_identity import (  # noqa: E402
    normalize_channel,
    read_version_file,
    sync_manifest_provenance,
    validate_manifest_dict,
)


def git_head(repo: Path) -> str:
    out = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if len(out) != 40:
        raise SystemExit("ERROR: git rev-parse HEAD did not return a 40-char SHA")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate current provenance without rewriting the manifest",
    )
    parser.add_argument(
        "--allow-dirty-head-mismatch",
        action="store_true",
        help="With --check, report mismatch as warning-only (not used by CI)",
    )
    args = parser.parse_args()

    version = read_version_file(ROOT / "VERSION")
    project = version.get("PROJECT_VERSION", "")
    frp = version.get("FRP_VERSION", "")
    channel = normalize_channel(version.get("RELEASE_CHANNEL", "development"))
    if channel is None:
        print("ERROR: VERSION RELEASE_CHANNEL invalid", file=sys.stderr)
        return 1
    head = git_head(ROOT)
    path = ROOT / "release-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    if args.check:
        errs = []
        if str(data.get("project_version") or "") != project:
            errs.append("project_version mismatch vs VERSION")
        if str(data.get("frp_version") or "") != frp:
            errs.append("frp_version mismatch vs VERSION")
        if normalize_channel(str(data.get("channel") or "")) != channel:
            errs.append("channel mismatch vs VERSION")
        source_head = str(data.get("source_head") or "")
        git_ref = str(data.get("git_ref") or "")
        if not source_head or len(source_head) != 40:
            errs.append("source_head must be a 40-character SHA")
        # A committed file cannot self-describe the commit that contains it.
        # For development/preview, require an immutable SHA ref and treat
        # HEAD equality as best-effort (warn unless STRICT_SOURCE_HEAD=1).
        import os

        strict = os.environ.get("STRICT_SOURCE_HEAD") == "1"
        if source_head.lower() != head.lower():
            msg = "source_head %s != HEAD %s" % (source_head, head)
            if channel == "stable" or strict:
                errs.append(msg)
            else:
                print("WARN: %s (stamped into bundles at build time)" % msg, file=sys.stderr)
        if channel == "stable":
            if git_ref != "v%s" % project:
                errs.append("stable git_ref must be v%s" % project)
        elif channel == "development":
            if not (
                len(git_ref) == 40
                and all(c in "0123456789abcdefABCDEF" for c in git_ref)
            ) and git_ref != "main":
                errs.append("development git_ref must be a 40-char SHA (or explicit main)")
            if git_ref == "v%s" % project:
                errs.append("development must not use future stable tag ref")
        features = data.get("features") or {}
        if features.get("mcp_included") not in (True, False):
            errs.append("features.mcp_included must be boolean")
        errs.extend(validate_manifest_dict(data, require_artifacts=True))
        if errs:
            for e in errs:
                print("ERROR: %s" % e, file=sys.stderr)
            return 1
        print("RELEASE_MANIFEST_PROVENANCE=PASS")
        print("SOURCE_HEAD=%s" % source_head)
        print("CHANNEL=%s" % channel)
        return 0

    sync_manifest_provenance(
        data,
        project_version=project,
        frp_version=frp,
        channel=channel,
        source_head=head,
        mcp_included=True,
    )
    # Stable preparation still uses v-tag git_ref; development uses HEAD.
    if channel != "stable":
        data["git_ref"] = head
    data["immutable_source_ref"] = data["git_ref"]
    note = str(data.get("note") or "")
    marker = "Pretags / development trees pin git_ref and source_head to the exact HEAD SHA"
    if marker not in note:
        data["note"] = (
            (note + " " if note else "")
            + marker
            + "; never advertise a future stable tag before it exists. "
            "features.mcp_included=true after MCP Bridge/AI Access implementation."
        ).strip()
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print("UPDATED release-manifest.json channel=%s source_head=%s" % (channel, head))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
