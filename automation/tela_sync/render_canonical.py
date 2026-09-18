#!/usr/bin/env python3
"""Render canonical Tela knowledge deterministically from OpenSpec."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "knowledge" / "CANONICAL_SOURCE_OF_TRUTH.md"
CONFIG = ROOT / "automation" / "tela_sync" / "config.json"
REQ_RE = re.compile(r"^### Requirement:\s*(.+?)\s*$", re.MULTILINE)

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def section(text: str, heading: str) -> str:
    marker = f"## {heading}"
    start = text.find(marker)
    if start < 0:
        return ""
    body = text[start + len(marker):].lstrip("\n")
    end = re.search(r"^##\s+", body, re.MULTILINE)
    return body[: end.start() if end else None].strip()
def current_specs() -> list[dict]:
    rows = []
    root = ROOT / "openspec" / "specs"
    for spec in sorted(root.glob("*/spec.md")):
        text = read(spec)
        rows.append({
            "capability": spec.parent.name,
            "path": spec.relative_to(ROOT).as_posix(),
            "purpose": section(text, "Purpose"),
            "requirements": REQ_RE.findall(text),
        })
    return rows

def is_product_archive(path: Path) -> bool:
    meta = path / ".openspec.yaml"
    if not meta.is_file():
        return True
    return "skip_specs: true" not in read(meta)

def extract_decisions(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    found = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("### Decision:"):
            index += 1
            continue
        title = line.split(":", 1)[1].strip()
        body = []
        index += 1
        while index < len(lines):
            if lines[index].startswith("### ") or lines[index].startswith("## "):
                break
            body.append(lines[index])
            index += 1
        found.append((title, "\n".join(body).strip()))
    return found

def decision_history() -> list[dict]:
    rows = []
    root = ROOT / "openspec" / "changes" / "archive"
    for archive in sorted(p for p in root.iterdir() if p.is_dir()):
        if not is_product_archive(archive):
            continue
        design = archive / "design.md"
        if not design.is_file():
            continue
        for title, body in extract_decisions(read(design)):
            rows.append({
                "archive": archive.name,
                "path": design.relative_to(ROOT).as_posix(),
                "title": title,
                "body": body,
            })
    return rows

def source_hash(specs: list[dict], decisions: list[dict]) -> str:
    digest = hashlib.sha256()
    paths = [ROOT / item["path"] for item in specs]
    paths += sorted({ROOT / item["path"] for item in decisions})
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()

def render() -> str:
    cfg = json.loads(read(CONFIG))
    specs = current_specs()
    decisions = decision_history()
    digest = source_hash(specs, decisions)
    lines = [
        "# Data Relay Link — Canonical Source of Truth",
        "",
        "> [!IMPORTANT]",
        "> **Authority rule:** OpenSpec is authoritative. Tela is a derived knowledge layer.",
        "> Atlas-generated repository summaries are secondary and may contain legacy terminology.",
        "",
        "<!-- GENERATED FILE: do not hand-edit. -->",
        f"<!-- source_sha256: {digest} -->",
        "",
        "## How AI agents must use this knowledge",
        "",
        "1. Prefer this page and the relevant OpenSpec current spec / archived change.",
        "2. Treat source code and tests as implementation/evidence, not design rationale.",
        "3. Never infer missing WHY from code; report RATIONALE_UNKNOWN when absent.",
        "4. If Tela and OpenSpec disagree, **OpenSpec wins**.",
        "",
        "## Current accepted contract",
        "",
    ]
    for item in specs:
        lines += [f"### {item['capability']}", ""]
        if item["purpose"]:
            lines += [item["purpose"], ""]
        lines += ["**Requirements:**"]
        lines += [f"- {name}" for name in item["requirements"]]
        lines += ["", f"Source: {item['path']}", ""]

    lines += ["## Accepted decision history", ""]
    for item in decisions:
        lines += [f"### {item['title']}", ""]
        if item["body"]:
            lines += [item["body"], ""]
        lines += [f"Source: {item['path']}", ""]

    lines += [
        "## Tela sync metadata",
        "",
        f"- Atlas project: {cfg['atlas_project_id']}",
        f"- Space: {cfg['space_id']}",
        f"- Canonical page: {cfg['canonical_page_id']}",
        f"- Source hash: {digest}",
        "",
        "This file is generated from OpenSpec. Do not maintain it manually.",
        "",
    ]
    return "\n".join(lines)
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    content = render()
    if args.stdout:
        print(content, end="")
        return 0
    if args.check:
        if not args.output.is_file() or read(args.output) != content:
            print(f"STALE: {args.output}")
            return 1
        print(f"CURRENT: {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(f"WROTE: {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
