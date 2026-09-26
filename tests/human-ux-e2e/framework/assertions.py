"""Assertion helpers that produce classified findings instead of bare asserts."""
from __future__ import annotations

import re
from typing import Iterable, Optional

from .types import Finding, FindingClass, Severity


class ScenarioFailure(AssertionError):
    """Raised when a scenario assertion fails."""

    def __init__(self, finding: Finding):
        self.finding = finding
        super().__init__(finding.message)


def fail(
    message: str,
    *,
    classification: FindingClass = FindingClass.FUNCTIONAL_FAILURE,
    severity: Severity = Severity.P1,
    evidence: str = "",
) -> None:
    raise ScenarioFailure(
        Finding(
            classification=classification,
            severity=severity,
            message=message,
            evidence=evidence,
        )
    )


def expect_true(
    cond: bool,
    message: str,
    *,
    classification: FindingClass = FindingClass.FUNCTIONAL_FAILURE,
    severity: Severity = Severity.P1,
    evidence: str = "",
) -> None:
    if not cond:
        fail(message, classification=classification, severity=severity, evidence=evidence)


def expect_contains(
    haystack: str,
    needle: str,
    message: str = "",
    *,
    classification: FindingClass = FindingClass.CONTRACT_MISMATCH,
    severity: Severity = Severity.P1,
) -> None:
    if needle not in (haystack or ""):
        fail(
            message or "Expected substring missing: %r" % needle,
            classification=classification,
            severity=severity,
            evidence=_clip(haystack),
        )


def expect_not_contains(
    haystack: str,
    needle: str,
    message: str = "",
    *,
    classification: FindingClass = FindingClass.CONTRACT_MISMATCH,
    severity: Severity = Severity.P1,
) -> None:
    if needle in (haystack or ""):
        fail(
            message or "Forbidden substring present: %r" % needle,
            classification=classification,
            severity=severity,
            evidence=_clip(haystack),
        )


def expect_re(
    haystack: str,
    pattern: str,
    message: str = "",
    *,
    flags: int = re.IGNORECASE | re.MULTILINE,
    classification: FindingClass = FindingClass.CONTRACT_MISMATCH,
    severity: Severity = Severity.P1,
) -> re.Match:
    m = re.search(pattern, haystack or "", flags)
    if not m:
        fail(
            message or "Pattern not found: %s" % pattern,
            classification=classification,
            severity=severity,
            evidence=_clip(haystack),
        )
    return m


def expect_eq(
    actual,
    expected,
    message: str = "",
    *,
    classification: FindingClass = FindingClass.CROSS_OUTPUT_INCONSISTENCY,
    severity: Severity = Severity.P1,
) -> None:
    if actual != expected:
        fail(
            message or "Values differ: actual=%r expected=%r" % (actual, expected),
            classification=classification,
            severity=severity,
            evidence="actual=%r\nexpected=%r" % (actual, expected),
        )


def expect_any(
    haystack: str,
    needles: Iterable[str],
    message: str = "",
    *,
    classification: FindingClass = FindingClass.CONTRACT_MISMATCH,
    severity: Severity = Severity.P1,
) -> str:
    for n in needles:
        if n in (haystack or ""):
            return n
    fail(
        message or "None of expected substrings found: %r" % list(needles),
        classification=classification,
        severity=severity,
        evidence=_clip(haystack),
    )
    raise AssertionError("unreachable")


def expect_rc(
    rc: int,
    expected: int = 0,
    message: str = "",
    *,
    stdout: str = "",
    stderr: str = "",
) -> None:
    if rc != expected:
        fail(
            message or "Unexpected exit code %s (expected %s)" % (rc, expected),
            classification=FindingClass.FUNCTIONAL_FAILURE,
            severity=Severity.P1,
            evidence=_clip("stdout:\n%s\nstderr:\n%s" % (stdout, stderr)),
        )


def expect_no_mutation_claim(text: str) -> None:
    expect_re(
        text,
        r"No changes were applied",
        message="Expected explicit 'No changes were applied' recovery claim",
        classification=FindingClass.HUMAN_UX_CONFUSION,
        severity=Severity.P2_USER_BLOCKING,
    )


def expect_role_guidance(text: str, *, want_server: bool = False, want_agent: bool = False) -> None:
    lower = (text or "").lower()
    if want_server:
        expect_true(
            "drlink server" in lower or "on the drlink server" in lower,
            "Missing Server role guidance",
            classification=FindingClass.ROLE_CONTEXT_CONFUSION,
            severity=Severity.P1,
            evidence=_clip(text),
        )
    if want_agent:
        expect_true(
            "agent host" in lower,
            "Missing Agent Host role guidance",
            classification=FindingClass.ROLE_CONTEXT_CONFUSION,
            severity=Severity.P1,
            evidence=_clip(text),
        )
    expect_no_mutation_claim(text)


def _clip(text: Optional[str], limit: int = 2400) -> str:
    s = text or ""
    if len(s) <= limit:
        return s
    return s[: limit // 2] + "\n...[truncated]...\n" + s[-limit // 2 :]
