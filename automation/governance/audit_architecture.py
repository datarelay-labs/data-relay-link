#!/usr/bin/env python3
"""Deterministic OpenSpec / architecture drift audit."""
from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEGACY_TERMS = (
    "Managed Endpoint",
    "Published Service",
    "Service Preset",
    "AI Principal",
    "ordered first-match",
)
CURRENT_DOCS = (
    ROOT / "README.md",
    ROOT / "docs" / "CONTROL_PLANE_ARCHITECTURE.md",
)
HISTORICAL_MARKERS = (
    "legacy",
    "superseded",
    "deprecated",
    "historical",
    "earlier",
    "not authoritative",
)

@dataclass
class Finding:
    severity: str
    code: str
    path: str
    line: int
    detail: str

def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()

def run_projection_check() -> list[Finding]:
    proc = subprocess.run(
        ["python3", "automation/tela_sync/render_canonical.py", "--check"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if proc.returncode == 0:
        return []
    return [Finding("BLOCKING", "CANONICAL_STALE",
                    "knowledge/CANONICAL_SOURCE_OF_TRUTH.md", 0,
                    (proc.stdout + proc.stderr).strip())]
def check_specs() -> list[Finding]:
    findings: list[Finding] = []
    for spec in sorted((ROOT / "openspec" / "specs").glob("*/spec.md")):
        text = spec.read_text(encoding="utf-8")
        if "## Purpose" not in text:
            findings.append(Finding("BLOCKING", "SPEC_PURPOSE_MISSING", rel(spec), 0,
                                    "Current spec has no Purpose section."))
        if "## Requirements" not in text:
            findings.append(Finding("BLOCKING", "SPEC_REQUIREMENTS_MISSING", rel(spec), 0,
                                    "Current spec has no Requirements section."))
        if not re.search(r"^### Requirement:", text, re.MULTILINE):
            findings.append(Finding("BLOCKING", "SPEC_REQUIREMENT_EMPTY", rel(spec), 0,
                                    "Current spec has no normative Requirement entry."))
    return findings

def is_product_archive(path: Path) -> bool:
    meta = path / ".openspec.yaml"
    if not meta.exists():
        return True
    return "skip_specs: true" not in meta.read_text(encoding="utf-8")

def check_decision_rationale() -> list[Finding]:
    findings: list[Finding] = []
    archive_root = ROOT / "openspec" / "changes" / "archive"
    for archive in sorted(p for p in archive_root.iterdir() if p.is_dir()):
        if not is_product_archive(archive):
            continue
        design = archive / "design.md"
        if not design.exists():
            continue
        lines = design.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not line.startswith("### Decision:"):
                continue
            end = len(lines)
            for j in range(i + 1, len(lines)):
                if lines[j].startswith("### ") or lines[j].startswith("## "):
                    end = j
                    break
            body = "\n".join(lines[i + 1:end])
            if "**Rationale:**" not in body and "RATIONALE_UNKNOWN" not in body:
                findings.append(Finding(
                    "BLOCKING", "DECISION_RATIONALE_MISSING", rel(design), i + 1,
                    line.removeprefix("### Decision:").strip(),
                ))
    return findings
def check_current_document_terms() -> list[Finding]:
    findings: list[Finding] = []
    for path in CURRENT_DOCS:
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            lowered = line.lower()
            if any(marker in lowered for marker in HISTORICAL_MARKERS):
                continue
            for term in LEGACY_TERMS:
                if term.lower() in lowered:
                    findings.append(Finding(
                        "DOC_DRIFT", "SUPERSEDED_PUBLIC_TERM", rel(path), lineno,
                        f"{term}: {line.strip()}",
                    ))
    return findings

def collect() -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(run_projection_check())
    findings.extend(check_specs())
    findings.extend(check_decision_rationale())
    findings.extend(check_current_document_terms())
    return findings

def render(findings: list[Finding]) -> str:
    blocking = [f for f in findings if f.severity == "BLOCKING"]
    docs = [f for f in findings if f.severity == "DOC_DRIFT"]
    lines = [
        "# Data Relay Link Architecture / OpenSpec Drift Audit",
        "",
        f"- Blocking findings: **{len(blocking)}**",
        f"- Documentation drift findings: **{len(docs)}**",
        "",
    ]
    if not findings:
        lines += ["**DRIFT_STATUS=PASS**", ""]
        return "\n".join(lines)
    for title, items in (("Blocking findings", blocking), ("Documentation drift", docs)):
        if not items:
            continue
        lines += [f"## {title}", ""]
        for f in items:
            location = f"{f.path}:{f.line}" if f.line else f.path
            lines.append(f"- **{f.code}** — {location} — {f.detail}")
        lines.append("")
    lines += [
        "## Authority",
        "",
        "OpenSpec remains authoritative. This report never rewrites specs or product code.",
        "Documentation drift is tracked for cleanup; blocking findings must be corrected before merge.",
        "",
    ]
    return "\n".join(lines)
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    parser.add_argument("--blocking-only", action="store_true")
    args = parser.parse_args()

    findings = collect()
    report = render(findings)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8")
    print(report, end="")

    blocking = any(f.severity == "BLOCKING" for f in findings)
    doc_drift = any(f.severity == "DOC_DRIFT" for f in findings)
    if blocking:
        return 2
    if doc_drift and not args.blocking_only:
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
