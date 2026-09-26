"""Summary report formatting."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from .types import FindingClass, ScenarioResult, ScenarioStatus


def write_failure_transcript(reports_dir: Path, result: ScenarioResult) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / ("%s.transcript.txt" % result.scenario_id)
    path.write_text(result.transcript or result.error or "", encoding="utf-8")
    return path


def render_summary(results: Iterable[ScenarioResult]) -> str:
    results = list(results)
    counts = Counter(r.status for r in results)
    class_counts = Counter()
    for r in results:
        for f in r.findings:
            class_counts[f.classification] += 1
        if r.status == ScenarioStatus.FAIL and not r.findings:
            class_counts[FindingClass.FUNCTIONAL_FAILURE] += 1

    lines = [
        "Human UX Adversarial E2E",
        "========================",
        "",
        "Scenarios : %d" % len(results),
        "PASS      : %d" % counts[ScenarioStatus.PASS],
        "FAIL      : %d" % counts[ScenarioStatus.FAIL],
        "SKIP      : %d" % counts[ScenarioStatus.SKIP],
        "",
        "Functional failures           : %d" % class_counts[FindingClass.FUNCTIONAL_FAILURE],
        "Contract mismatches           : %d" % class_counts[FindingClass.CONTRACT_MISMATCH],
        "Cross-output inconsistencies  : %d" % class_counts[FindingClass.CROSS_OUTPUT_INCONSISTENCY],
        "Invalid generated guidance    : %d" % class_counts[FindingClass.INVALID_GENERATED_GUIDANCE],
        "Role/context confusion        : %d" % class_counts[FindingClass.ROLE_CONTEXT_CONFUSION],
        "Human UX blocking findings    : %d"
        % (
            class_counts[FindingClass.HUMAN_UX_CONFUSION]
            + sum(1 for r in results for f in r.findings if f.severity.value.startswith("P2-USER"))
        ),
        "",
    ]
    failed = [r for r in results if r.status == ScenarioStatus.FAIL]
    if failed:
        lines.append("FAILED:")
        for r in failed:
            msg = r.findings[0].message if r.findings else (r.error or "failed")
            lines.append("  %s  %s" % (r.scenario_id, msg.splitlines()[0][:120]))
        lines.append("")
    skipped = [r for r in results if r.status == ScenarioStatus.SKIP]
    if skipped:
        lines.append("SKIPPED:")
        for r in skipped:
            lines.append("  %s  %s" % (r.scenario_id, (r.error or "skip").splitlines()[0][:120]))
        lines.append("")
    return "\n".join(lines)
