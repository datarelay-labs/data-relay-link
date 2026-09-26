"""Product-generated command / URL / SSH hint validator."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .extractors import extract_drlink_commands, extract_ssh_hints, extract_urls
from .types import Finding, FindingClass, Severity


class GuidanceKind(str, Enum):
    DRLINK_COMMAND = "DRLINK_COMMAND"
    SHELL_COMMAND = "SHELL_COMMAND"
    CONNECTION_EXAMPLE = "CONNECTION_EXAMPLE"
    URL = "URL"
    INFORMATION_ONLY = "INFORMATION_ONLY"


@dataclass
class ClassifiedGuidance:
    kind: GuidanceKind
    raw: str
    tokens: list[str] = None


def classify_line(line: str) -> ClassifiedGuidance:
    s = (line or "").strip()
    if not s:
        return ClassifiedGuidance(GuidanceKind.INFORMATION_ONLY, s, [])
    if re.match(r"^https?://", s, re.I):
        return ClassifiedGuidance(GuidanceKind.URL, s, [])
    if re.match(r"^ssh\s+", s, re.I):
        return ClassifiedGuidance(GuidanceKind.CONNECTION_EXAMPLE, s, [])
    if re.match(r"^(?:sudo\s+)?drlink\b", s, re.I) or re.match(
        r"^(show|set|unset|test|system|create|menu|help|\?)\b", s, re.I
    ):
        body = s
        m = re.match(r"^(?:sudo\s+)?drlink\s+(.+)$", s, re.I)
        if m:
            body = m.group(1)
        try:
            tokens = shlex.split(body)
        except ValueError:
            tokens = body.split()
        return ClassifiedGuidance(GuidanceKind.DRLINK_COMMAND, s, tokens)
    if re.match(r"^(curl|wget|bash|systemctl)\b", s, re.I):
        return ClassifiedGuidance(GuidanceKind.SHELL_COMMAND, s, [])
    return ClassifiedGuidance(GuidanceKind.INFORMATION_ONLY, s, [])


def grammar_role(execution_context: str) -> str:
    if execution_context == "DRLINK_SERVER":
        return "server"
    if execution_context == "AGENT_HOST":
        return "client"
    return "both"


def validate_drlink_command(
    cmdline: str,
    *,
    execution_context: str,
    allow_unknown_args: bool = True,
) -> list[Finding]:
    """Validate a product-emitted DRLink command against the public grammar."""
    from frp_ctl_grammar import match

    findings: list[Finding] = []
    classified = classify_line(cmdline if cmdline.startswith("drlink") or cmdline.startswith("sudo")
                               or re.match(r"^(show|set|unset|test|system|create|menu|help|\?)\b", cmdline, re.I)
                               else "drlink " + cmdline)
    if classified.kind != GuidanceKind.DRLINK_COMMAND:
        return findings
    tokens = classified.tokens or []
    if not tokens:
        findings.append(
            Finding(
                FindingClass.INVALID_GENERATED_GUIDANCE,
                Severity.P1,
                "Empty DRLink command in product guidance",
                evidence=cmdline,
            )
        )
        return findings
    # Skip interactive-only roots that are not grammar actions
    if tokens[0] in ("?", "help", "menu"):
        return findings
    role = grammar_role(execution_context)
    result = match(tokens, role=role)
    status = result.get("status")
    if status == "ok":
        return findings
    # Ownership / wrong-role is itself useful guidance when validating *user typed*
    # commands; for product-generated remediation, wrong-role is a defect.
    err = str(result.get("error") or result.get("message") or status)
    if status in ("wrong_role", "ownership", "role"):
        findings.append(
            Finding(
                FindingClass.INVALID_GENERATED_GUIDANCE,
                Severity.P1,
                "Product recommended a command invalid for current role: %s" % cmdline,
                evidence=err,
            )
        )
        return findings
    if status in ("unknown", "incomplete", "error", "invalid"):
        # Some remediation commands include placeholders like <HOST>
        if allow_unknown_args and re.search(r"[<>]|NAME|HOST|FILE", cmdline):
            return findings
        findings.append(
            Finding(
                FindingClass.INVALID_GENERATED_GUIDANCE,
                Severity.P1,
                "Product recommended unparsable/stale command: %s" % cmdline,
                evidence=err or str(result),
            )
        )
    return findings


def validate_output_guidance(
    text: str,
    *,
    execution_context: str,
    expected_public_host: Optional[str] = None,
    expected_port: Optional[int] = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for cmd in extract_drlink_commands(text):
        findings.extend(validate_drlink_command(cmd, execution_context=execution_context))

    for hint in extract_ssh_hints(text):
        if expected_public_host and hint.host not in (expected_public_host,):
            # Allow IP fallback alongside hostname, but flag drlink.local/localhost
            if hint.host.lower() in ("drlink.local", "localhost"):
                findings.append(
                    Finding(
                        FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                        Severity.P1,
                        "SSH hint uses non-public host %r" % hint.host,
                        evidence=hint.raw,
                    )
                )
        if expected_port is not None and hint.port is not None and hint.port != expected_port:
            findings.append(
                Finding(
                    FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                    Severity.P1,
                    "SSH hint port %s != expected endpoint port %s" % (hint.port, expected_port),
                    evidence=hint.raw,
                )
            )
        if hint.user and hint.user.lower() in ("root",) and "optional" not in text.lower():
            # Not automatically a failure — record only when clearly inventing OS user.
            pass

    if expected_public_host:
        for host, port, raw in extract_urls(text):
            if host.lower() in ("drlink.local", "localhost") and expected_public_host.lower() not in (text or "").lower():
                findings.append(
                    Finding(
                        FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                        Severity.P2_UX,
                        "URL uses fallback host while public hostname configured",
                        evidence=raw,
                    )
                )
            if expected_port is not None and port is not None and port != expected_port:
                findings.append(
                    Finding(
                        FindingClass.CROSS_OUTPUT_INCONSISTENCY,
                        Severity.P1,
                        "URL port mismatch",
                        evidence=raw,
                    )
                )
    return findings


def validate_remediation_block(text: str, *, execution_context: str) -> list[Finding]:
    """Validate commands under Next:/Recommended action:/Use:/Run: labels."""
    from .extractors import extract_guidance_lines

    findings: list[Finding] = []
    for line in extract_guidance_lines(text):
        classified = classify_line(line)
        if classified.kind == GuidanceKind.DRLINK_COMMAND:
            findings.extend(validate_drlink_command(line, execution_context=execution_context))
        elif classified.kind == GuidanceKind.CONNECTION_EXAMPLE:
            findings.extend(
                validate_output_guidance(line, execution_context=execution_context)
            )
    return findings
