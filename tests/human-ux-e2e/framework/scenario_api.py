"""Scenario environment and registration decorator."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .harness import DualRoleHarness, create_agent_only, create_dual_with_mgmt, create_server_only, repo_root
from .state_machine import WorkflowStateMachine
from .transcript import TranscriptRecorder
from .types import ExecutionContext, InteractionMode, Layer, ScenarioSpec

_REGISTRY: list[ScenarioSpec] = []


def scenario(
    scenario_id: str,
    title: str,
    *,
    execution_context: ExecutionContext,
    interaction_mode: InteractionMode,
    layer: Layer,
    domain: str = "",
    mandatory: bool = True,
    tags: tuple[str, ...] = (),
):
    def deco(fn: Callable):
        spec = ScenarioSpec(
            scenario_id=scenario_id,
            title=title,
            fn=fn,
            execution_context=execution_context,
            interaction_mode=interaction_mode,
            layer=layer,
            domain=domain,
            mandatory=mandatory,
            tags=tags,
        )
        _REGISTRY.append(spec)
        fn._hux_spec = spec  # type: ignore[attr-defined]
        return fn

    return deco


def all_scenarios() -> list[ScenarioSpec]:
    return list(_REGISTRY)


@dataclass
class ScenarioEnv:
    """Per-scenario working context."""

    spec: ScenarioSpec
    reports_dir: Path
    verbose: bool = False
    harness: Optional[DualRoleHarness] = None
    sm: WorkflowStateMachine = field(default_factory=WorkflowStateMachine)
    recorder: Optional[TranscriptRecorder] = None
    extracted: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.recorder = TranscriptRecorder(
            scenario_id=self.spec.scenario_id,
            execution_context=self.spec.execution_context.value,
            interaction_mode=self.spec.interaction_mode.value,
        )

    @property
    def repo(self) -> Path:
        return repo_root()

    def ensure_server(self) -> DualRoleHarness:
        if self.harness is None:
            self.harness = create_server_only()
        return self.harness

    def ensure_agent(self) -> DualRoleHarness:
        if self.harness is None:
            self.harness = create_agent_only()
        return self.harness

    def ensure_dual(self) -> DualRoleHarness:
        if self.harness is None or self.harness.mgmt_httpd is None:
            if self.harness is not None:
                self.harness.close()
            self.harness = create_dual_with_mgmt()
        return self.harness

    def close(self) -> None:
        if self.harness is not None:
            self.harness.close()
            self.harness = None
