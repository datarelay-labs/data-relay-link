"""Layer 4 — Cross-output consistency validators."""
from __future__ import annotations

from typing import Optional

from .assertions import expect_contains, expect_eq, expect_not_contains, expect_true
from .command_validator import validate_output_guidance, validate_remediation_block
from .extractors import (
    extract_endpoints,
    extract_source_head,
    extract_ssh_hints,
    extract_version_display,
    mentions_agent_host,
)
from .types import Finding, FindingClass, Severity


def assert_public_hostname_preference(
    texts: dict[str, str],
    *,
    public_hostname: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for label, text in texts.items():
        if public_hostname not in (text or "") and "://%s" % public_hostname not in (text or ""):
            # Only fail when a competing private hostname appears.
            if any(bad in (text or "").lower() for bad in ("drlink.local", "localhost")):
                findings.append(
                    Finding(
                        FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                        Severity.P1,
                        "%s prefers private host over configured public hostname %s" % (label, public_hostname),
                        evidence=text[:800],
                    )
                )
    return findings


def assert_endpoint_port_stable(texts: dict[str, str], *, expected_port: int) -> list[Finding]:
    findings: list[Finding] = []
    for label, text in texts.items():
        ports = {ep.port for ep in extract_endpoints(text)}
        # Also SSH -p
        for hint in extract_ssh_hints(text):
            if hint.port is not None:
                ports.add(hint.port)
        if not ports:
            continue
        if expected_port not in ports:
            findings.append(
                Finding(
                    FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                    Severity.P1,
                    "%s does not mention stable endpoint port %s (found %s)" % (label, expected_port, sorted(ports)),
                    evidence=text[:800],
                )
            )
        extras = {p for p in ports if p != expected_port and p not in (443, 80, 6099, 7000, 7500)}
        # Allow unrelated ports; only flag when multiple candidate public service ports conflict.
        serviceish = {p for p in ports if 20000 <= p <= 60000 or p == expected_port}
        if len(serviceish) > 1 and expected_port in serviceish:
            findings.append(
                Finding(
                    FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                    Severity.P1,
                    "%s shows conflicting service ports %s" % (label, sorted(serviceish)),
                    evidence=text[:800],
                )
            )
    return findings


def assert_agent_host_terminology(texts: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for label, text in texts.items():
        if not mentions_agent_host(text):
            # Allow if text is empty/error unrelated
            if "role" in (text or "").lower() or "agent" in (text or "").lower():
                if "managed host" in (text or "").lower() and "agent host" not in (text or "").lower():
                    findings.append(
                        Finding(
                            FindingClass.CONTRACT_MISMATCH,
                            Severity.P2_UX,
                            "%s uses non-canonical agent role terminology" % label,
                            evidence=text[:800],
                        )
                    )
                elif re_search_legacy_client(text):
                    findings.append(
                        Finding(
                            FindingClass.CONTRACT_MISMATCH,
                            Severity.P1,
                            "%s missing 'Agent Host' terminology" % label,
                            evidence=text[:800],
                        )
                    )
    return findings


def re_search_legacy_client(text: str) -> bool:
    import re

    return bool(re.search(r"\b(client host|FRP client|frpc client role)\b", text or "", re.I))


def assert_version_identity(
    texts: dict[str, str],
    *,
    expect_dev_display: bool = True,
    expect_source_head: Optional[str] = None,
) -> list[Finding]:
    findings: list[Finding] = []
    displays = {}
    for label, text in texts.items():
        d = extract_version_display(text)
        if d:
            displays[label] = d
            if expect_dev_display and d == "2.4.0" and "development" in (text or "").lower():
                # Plain 2.4.0 beside development without -dev+gSHA is drift.
                if "-dev+g" not in (text or ""):
                    findings.append(
                        Finding(
                            FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                            Severity.P1,
                            "%s presents plain 2.4.0 under development channel" % label,
                            evidence=text[:800],
                        )
                    )
        if expect_source_head:
            sha = extract_source_head(text)
            if sha and sha != expect_source_head:
                findings.append(
                    Finding(
                        FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                        Severity.P2_UX,
                        "%s Source HEAD mismatch" % label,
                        evidence="got %s expected %s" % (sha, expect_source_head),
                    )
                )
    uniq = set(displays.values())
    if len(uniq) > 1:
        findings.append(
            Finding(
                FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                Severity.P1,
                "Version display identity differs across outputs: %s" % displays,
                evidence=str(displays),
            )
        )
    return findings


def assert_success_compatible_with_doctor(
    success_text: str,
    doctor_text: str,
    *,
    doctor_overall: str,
) -> list[Finding]:
    findings: list[Finding] = []
    success_l = (success_text or "").lower()
    claims_ok = any(
        tok in success_l
        for tok in ("setup complete", "connected", "healthy", "installation complete", "ready")
    )
    if claims_ok and doctor_overall in ("FAIL", "ERROR"):
        # Unexplained product-generated configuration drift is P1.
        if "drift" in (doctor_text or "").lower() or "configuration" in (doctor_text or "").lower():
            findings.append(
                Finding(
                    FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                    Severity.P1,
                    "Installer/workflow claimed success but Doctor returned %s" % doctor_overall,
                    evidence=doctor_text[:1200],
                )
            )
        else:
            findings.append(
                Finding(
                    FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                    Severity.P1,
                    "Success claim incompatible with Doctor overall=%s" % doctor_overall,
                    evidence=doctor_text[:1200],
                )
            )
    return findings


def raise_if_findings(findings: list[Finding]) -> None:
    from .assertions import ScenarioFailure

    if findings:
        # Prefer highest severity
        order = {
            Severity.P0: 0,
            Severity.P1: 1,
            Severity.P2_USER_BLOCKING: 2,
            Severity.P2_UX: 3,
            Severity.P3: 4,
        }
        findings = sorted(findings, key=lambda f: order.get(f.severity, 9))
        raise ScenarioFailure(findings[0])
