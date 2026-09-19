"""Shared types for the Human UX Adversarial E2E framework."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class ExecutionContext(str, Enum):
    DRLINK_SERVER = "DRLINK_SERVER"
    AGENT_HOST = "AGENT_HOST"
    EXTERNAL_TEST_CLIENT = "EXTERNAL_TEST_CLIENT"


class InteractionMode(str, Enum):
    WIZARD = "WIZARD"
    ONE_SHOT = "ONE_SHOT"
    PTY = "PTY"
    CONTRACT = "CONTRACT"
    MIXED = "MIXED"


class Layer(str, Enum):
    NORMAL = "NORMAL_WORKFLOW"
    ADVERSARIAL = "ADVERSARIAL_MISUSE"
    PTY = "PTY_HUMAN_INPUT"
    CONSISTENCY = "CROSS_OUTPUT_CONSISTENCY"
    FIRST_TIME_REVIEW = "FIRST_TIME_USER_REVIEW"


class FindingClass(str, Enum):
    FUNCTIONAL_FAILURE = "FUNCTIONAL_FAILURE"
    SECURITY_FAILURE = "SECURITY_FAILURE"
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"
    CROSS_OUTPUT_INCONSISTENCY = "CROSS_OUTPUT_INCONSISTENCY"
    INVALID_GENERATED_GUIDANCE = "INVALID_GENERATED_GUIDANCE"
    ROLE_CONTEXT_CONFUSION = "ROLE_CONTEXT_CONFUSION"
    HUMAN_UX_CONFUSION = "HUMAN_UX_CONFUSION"
    COSMETIC_ONLY = "COSMETIC_ONLY"


class Severity(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2_USER_BLOCKING = "P2-USER-BLOCKING"
    P2_UX = "P2-UX"
    P3 = "P3"


class ScenarioStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class Finding:
    classification: FindingClass
    severity: Severity
    message: str
    evidence: str = ""
    release_blocking: bool = False

    def __post_init__(self) -> None:
        if self.severity in (Severity.P0, Severity.P1, Severity.P2_USER_BLOCKING):
            self.release_blocking = True


@dataclass
class ScenarioResult:
    scenario_id: str
    title: str
    status: ScenarioStatus
    execution_context: ExecutionContext
    interaction_mode: InteractionMode
    layer: Layer
    findings: list[Finding] = field(default_factory=list)
    transcript: str = ""
    duration_s: float = 0.0
    error: str = ""
    extracted: dict[str, Any] = field(default_factory=dict)

    @property
    def release_blocking(self) -> bool:
        return any(f.release_blocking for f in self.findings) or self.status == ScenarioStatus.FAIL


ScenarioFn = Callable[["ScenarioEnv"], None]  # noqa: F821 — forward ref


@dataclass
class ScenarioSpec:
    scenario_id: str
    title: str
    fn: ScenarioFn
    execution_context: ExecutionContext
    interaction_mode: InteractionMode
    layer: Layer
    domain: str = ""
    mandatory: bool = True
    tags: tuple[str, ...] = ()
