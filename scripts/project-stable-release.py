#!/usr/bin/env python3
"""Project a stable publication manifest from an already-qualified tag.

The Git tag must already point at PASS1_HEAD == PASS2_HEAD ==
FINAL_QUALIFIED_HEAD. This script does not create a commit, move a tag, or
rewrite the committed manifest. It writes only the explicit --output path.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SHA = __import__("re").compile(r"^[0-9a-fA-F]{40}$")


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def read_version(repo: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (repo / "VERSION").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def placement(repo: Path) -> tuple[str, str, str, list[str]]:
    """Return tag, HEAD, source_head, and errors for tag placement."""
    version = read_version(repo)
    project = version.get("PROJECT_VERSION", "")
    tag = "v%s" % project
    head = git(repo, "rev-parse", "HEAD").stdout.strip().lower()
    parent = git(repo, "rev-parse", "--verify", "HEAD^1").stdout.strip().lower()
    manifest = json.loads((repo / "release-manifest.json").read_text(encoding="utf-8"))
    source_head = str(manifest.get("source_head") or "").lower()
    tag_proc = git(repo, "rev-parse", "--verify", "refs/tags/%s^{commit}" % tag)
    errs: list[str] = []
    if tag_proc.returncode != 0:
        errs.append("tag %s does not exist" % tag)
        return tag, head, source_head, errs
    tag_head = tag_proc.stdout.strip().lower()
    if tag_head != head:
        errs.append(
            "%s points at %s, not FINAL_QUALIFIED_HEAD %s" % (tag, tag_head, head)
        )
    if not parent or source_head != parent or source_head == head:
        errs.append(
            "tagged commit must be the provenance commit whose source_head "
            "is its content parent, not a post-qualification metadata commit"
        )
    return tag, head, source_head, errs


def evidence_errors(evidence: dict, head: str) -> list[str]:
    errs: list[str] = []
    if str(evidence.get("status") or "") != "PASS":
        errs.append("qualification status must be PASS")
    if str(evidence.get("real_e2e") or "").lower() == "pending":
        errs.append("qualification must not use real_e2e=pending")
    heads = {
        "pass1_head": str(evidence.get("pass1_head") or ""),
        "pass2_head": str(evidence.get("pass2_head") or ""),
        "final_qualified_head": str(evidence.get("final_qualified_head") or ""),
    }
    if not all(SHA.fullmatch(value) for value in heads.values()):
        errs.append("PASS1_HEAD, PASS2_HEAD, and FINAL_QUALIFIED_HEAD must be 40-character SHAs")
        return errs
    if len({value.lower() for value in heads.values()}) != 1 or heads["final_qualified_head"].lower() != head:
        errs.append(
            "PASS1_HEAD, PASS2_HEAD, and FINAL_QUALIFIED_HEAD must equal tag HEAD %s"
            % head
        )
    return errs


def project_manifest(repo: Path, evidence: dict) -> dict:
    tag, head, _source, errs = placement(repo)
    errs.extend(evidence_errors(evidence, head))
    if errs:
        raise SystemExit("\n".join("ERROR: %s" % err for err in errs))
    committed = json.loads((repo / "release-manifest.json").read_text(encoding="utf-8"))
    projected = json.loads(json.dumps(committed))
    artifacts = json.loads(json.dumps(committed.get("artifacts") or {}))
    projected["channel"] = "stable"
    projected["git_ref"] = tag
    projected["immutable_source_ref"] = tag
    projected["qualification"] = {
        "status": "PASS",
        "pass1_head": head,
        "pass2_head": head,
        "final_qualified_head": head,
    }
    if projected.get("artifacts") != artifacts:
        raise SystemExit("ERROR: projection changed artifact payload hashes")
    return projected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--evidence", default="", help="PASS1/PASS2 evidence JSON file")
    parser.add_argument("--output", default="", help="Projected manifest path; never the committed file")
    parser.add_argument(
        "--check-tag-placement",
        action="store_true",
        help="Check that an existing vX.Y.Z tag is the qualified provenance HEAD",
    )
    args = parser.parse_args(argv)
    repo = Path(args.root).resolve()
    if args.check_tag_placement:
        _tag, _head, _source, errs = placement(repo)
        if errs:
            for err in errs:
                print("ERROR: %s" % err, file=sys.stderr)
            return 1
        print("TAG_PLACEMENT=PASS")
        return 0
    if not args.evidence or not args.output:
        print("ERROR: --evidence and --output are required", file=sys.stderr)
        return 1
    output = Path(args.output)
    if output.resolve() == (repo / "release-manifest.json").resolve():
        print("ERROR: projection must not rewrite the committed manifest", file=sys.stderr)
        return 1
    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        print("ERROR: evidence must be a JSON object", file=sys.stderr)
        return 1
    try:
        projected = project_manifest(repo, evidence)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 1
        raise
    text = json.dumps(projected, indent=2) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print("STABLE_PROJECTION=PASS")
    print("FINAL_QUALIFIED_HEAD=%s" % projected["qualification"]["final_qualified_head"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
