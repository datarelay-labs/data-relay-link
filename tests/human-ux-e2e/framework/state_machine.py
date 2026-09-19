"""Layer 1 — Normal Workflow state machine model."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, Optional, Set

from .types import ExecutionContext


class WorkflowState(str, Enum):
    FRESH_SERVER = "FRESH_SERVER"
    SERVER_INSTALLED = "SERVER_INSTALLED"
    ENROLLMENT_CREATED = "ENROLLMENT_CREATED"
    AGENT_INSTALLED = "AGENT_INSTALLED"
    AGENT_CONNECTED = "AGENT_CONNECTED"
    REMOTE_SERVICE_CREATED = "REMOTE_SERVICE_CREATED"
    REMOTE_SERVICE_HEALTHY = "REMOTE_SERVICE_HEALTHY"
    REMOTE_ACCESS_CREATED = "REMOTE_ACCESS_CREATED"
    REMOTE_ACCESS_DISABLED = "REMOTE_ACCESS_DISABLED"
    REMOTE_ACCESS_ENABLED = "REMOTE_ACCESS_ENABLED"
    INTERNET_ACCESS_CREATED = "INTERNET_ACCESS_CREATED"
    INTERNET_ACCESS_DISABLED = "INTERNET_ACCESS_DISABLED"
    INTERNET_ACCESS_ENABLED = "INTERNET_ACCESS_ENABLED"
    CONFIG_EXPORTED = "CONFIG_EXPORTED"
    CONFIG_TESTED = "CONFIG_TESTED"
    CONFIG_DIFFED = "CONFIG_DIFFED"
    CONFIG_APPLIED = "CONFIG_APPLIED"
    NO_CHANGE_REAPPLY = "NO_CHANGE_REAPPLY"
    AGENT_PAUSED = "AGENT_PAUSED"
    AGENT_RESUMED = "AGENT_RESUMED"
    AGENT_RESTARTED = "AGENT_RESTARTED"
    CLEANUP = "CLEANUP"


@dataclass(frozen=True)
class Transition:
    source: WorkflowState
    target: WorkflowState
    context: ExecutionContext
    command: str
    interaction_mode: str
    required_inputs: tuple[str, ...] = ()
    expected_mutation: str = ""
    expected_output_tokens: tuple[str, ...] = ()
    valid_next: FrozenSet[str] = frozenset()
    forbidden_next: FrozenSet[str] = frozenset()


# Canonical lifecycle edges used by consistency/role validators.
TRANSITIONS: tuple[Transition, ...] = (
    Transition(
        WorkflowState.FRESH_SERVER,
        WorkflowState.SERVER_INSTALLED,
        ExecutionContext.DRLINK_SERVER,
        "install-server",
        "CONTRACT",
        expected_mutation="server_role",
        valid_next=frozenset({"show status", "show version", "menu", "?"}),
    ),
    Transition(
        WorkflowState.SERVER_INSTALLED,
        WorkflowState.ENROLLMENT_CREATED,
        ExecutionContext.DRLINK_SERVER,
        "create enrollment",
        "WIZARD",
        expected_mutation="enrollment",
        valid_next=frozenset({"show enrollments"}),
        forbidden_next=frozenset({"set remote-service"}),
    ),
    Transition(
        WorkflowState.ENROLLMENT_CREATED,
        WorkflowState.AGENT_INSTALLED,
        ExecutionContext.AGENT_HOST,
        "zero-touch bootstrap",
        "ONE_SHOT",
        expected_mutation="agent_role",
        valid_next=frozenset({"show agent", "show remote-services", "system diagnostics"}),
        forbidden_next=frozenset({"set remote-access", "set internet-access"}),
    ),
    Transition(
        WorkflowState.AGENT_INSTALLED,
        WorkflowState.AGENT_CONNECTED,
        ExecutionContext.AGENT_HOST,
        "show status",
        "ONE_SHOT",
        expected_output_tokens=("Agent Host",),
        valid_next=frozenset({"set remote-service"}),
        forbidden_next=frozenset({"set remote-access"}),
    ),
    Transition(
        WorkflowState.AGENT_CONNECTED,
        WorkflowState.REMOTE_SERVICE_CREATED,
        ExecutionContext.AGENT_HOST,
        "set remote-service",
        "WIZARD",
        expected_mutation="remote_service",
        valid_next=frozenset({"show remote-service", "show remote-services"}),
        forbidden_next=frozenset({"set remote-access"}),
    ),
    Transition(
        WorkflowState.REMOTE_SERVICE_CREATED,
        WorkflowState.REMOTE_SERVICE_HEALTHY,
        ExecutionContext.AGENT_HOST,
        "show remote-service",
        "ONE_SHOT",
        expected_output_tokens=("HEALTHY",),
        valid_next=frozenset({"show remote-service", "system diagnostics"}),
        forbidden_next=frozenset({"set remote-access"}),
    ),
    Transition(
        WorkflowState.REMOTE_SERVICE_HEALTHY,
        WorkflowState.REMOTE_ACCESS_CREATED,
        ExecutionContext.DRLINK_SERVER,
        "set remote-access",
        "WIZARD",
        expected_mutation="remote_access_rule",
        valid_next=frozenset({"show remote-access", "test remote-access"}),
        forbidden_next=frozenset({"set remote-service"}),
    ),
    Transition(
        WorkflowState.REMOTE_ACCESS_CREATED,
        WorkflowState.REMOTE_ACCESS_DISABLED,
        ExecutionContext.DRLINK_SERVER,
        "set remote-access <name> disabled",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.REMOTE_ACCESS_DISABLED,
        WorkflowState.REMOTE_ACCESS_ENABLED,
        ExecutionContext.DRLINK_SERVER,
        "set remote-access <name> enabled",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.REMOTE_ACCESS_ENABLED,
        WorkflowState.INTERNET_ACCESS_CREATED,
        ExecutionContext.DRLINK_SERVER,
        "set internet-access",
        "WIZARD",
        forbidden_next=frozenset({"set remote-service"}),
    ),
    Transition(
        WorkflowState.INTERNET_ACCESS_CREATED,
        WorkflowState.INTERNET_ACCESS_DISABLED,
        ExecutionContext.DRLINK_SERVER,
        "set internet-access <name> disabled",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.INTERNET_ACCESS_DISABLED,
        WorkflowState.INTERNET_ACCESS_ENABLED,
        ExecutionContext.DRLINK_SERVER,
        "set internet-access <name> enabled",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.INTERNET_ACCESS_ENABLED,
        WorkflowState.CONFIG_EXPORTED,
        ExecutionContext.DRLINK_SERVER,
        "system export configuration",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.CONFIG_EXPORTED,
        WorkflowState.CONFIG_TESTED,
        ExecutionContext.DRLINK_SERVER,
        "test configuration",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.CONFIG_TESTED,
        WorkflowState.CONFIG_DIFFED,
        ExecutionContext.DRLINK_SERVER,
        "system diff configuration",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.CONFIG_DIFFED,
        WorkflowState.CONFIG_APPLIED,
        ExecutionContext.DRLINK_SERVER,
        "system apply configuration",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.CONFIG_APPLIED,
        WorkflowState.NO_CHANGE_REAPPLY,
        ExecutionContext.DRLINK_SERVER,
        "system apply configuration",
        "ONE_SHOT",
        expected_output_tokens=("NO CHANGE", "NO_CHANGE"),
    ),
    Transition(
        WorkflowState.NO_CHANGE_REAPPLY,
        WorkflowState.AGENT_PAUSED,
        ExecutionContext.AGENT_HOST,
        "system pause",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.AGENT_PAUSED,
        WorkflowState.AGENT_RESUMED,
        ExecutionContext.AGENT_HOST,
        "system resume",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.AGENT_RESUMED,
        WorkflowState.AGENT_RESTARTED,
        ExecutionContext.AGENT_HOST,
        "system restart",
        "ONE_SHOT",
    ),
    Transition(
        WorkflowState.AGENT_RESTARTED,
        WorkflowState.CLEANUP,
        ExecutionContext.AGENT_HOST,
        "system uninstall",
        "ONE_SHOT",
    ),
)


@dataclass
class WorkflowStateMachine:
    """Tracks operator lifecycle and validates role/command legality."""

    state: WorkflowState = WorkflowState.FRESH_SERVER
    history: list[str] = field(default_factory=list)

    def advance(self, target: WorkflowState, *, via: str = "") -> None:
        self.history.append("%s -> %s (%s)" % (self.state.value, target.value, via))
        self.state = target

    def transition_for(self, source: WorkflowState, target: WorkflowState) -> Optional[Transition]:
        for t in TRANSITIONS:
            if t.source == source and t.target == target:
                return t
        return None

    def forbidden_for_state(self, state: WorkflowState, context: ExecutionContext) -> Set[str]:
        forbidden: Set[str] = set()
        for t in TRANSITIONS:
            if t.source == state or t.target == state:
                if t.context != context:
                    # Cross-context commands belonging to the other role.
                    if context == ExecutionContext.AGENT_HOST:
                        forbidden.update(t.forbidden_next)
                        if t.context == ExecutionContext.DRLINK_SERVER and t.command.startswith("set remote-access"):
                            forbidden.add("set remote-access")
                        if t.context == ExecutionContext.DRLINK_SERVER and t.command.startswith("set internet-access"):
                            forbidden.add("set internet-access")
                    if context == ExecutionContext.DRLINK_SERVER:
                        if "remote-service" in t.command:
                            forbidden.add("set remote-service")
                forbidden.update(t.forbidden_next)
        # Hard role rules always apply.
        if context == ExecutionContext.AGENT_HOST:
            forbidden.update({"set remote-access", "set internet-access", "create enrollment"})
        if context == ExecutionContext.DRLINK_SERVER:
            forbidden.update({"set remote-service", "show agent"})
        return forbidden

    def valid_for_state(self, state: WorkflowState, context: ExecutionContext) -> Set[str]:
        valid: Set[str] = set()
        for t in TRANSITIONS:
            if t.target == state or t.source == state:
                if t.context == context:
                    valid.update(t.valid_next)
                    valid.add(t.command.split("<")[0].strip())
        if context == ExecutionContext.DRLINK_SERVER:
            valid.update({"show status", "show version", "?", "help", "menu"})
        if context == ExecutionContext.AGENT_HOST:
            valid.update(
                {
                    "show status",
                    "show agent",
                    "show remote-services",
                    "system diagnostics",
                    "?",
                    "help",
                    "menu",
                }
            )
        return valid

    def assert_command_legality(self, command: str, context: ExecutionContext) -> Optional[str]:
        """Return an error string if command is forbidden in current state/context."""
        cmd = " ".join(command.strip().split())
        forbidden = self.forbidden_for_state(self.state, context)
        for bad in forbidden:
            if cmd == bad or cmd.startswith(bad + " "):
                return "Command %r forbidden in state=%s context=%s" % (
                    cmd,
                    self.state.value,
                    context.value,
                )
        return None


def lifecycle_states() -> list[str]:
    return [s.value for s in WorkflowState]


def role_matrix() -> Dict[str, Dict[str, str]]:
    """Document which contexts own which mutation families."""
    return {
        "remote-service": {
            "owner": ExecutionContext.AGENT_HOST.value,
            "valid": "set remote-service / show remote-service",
            "invalid_on_server": "set remote-service",
        },
        "remote-access": {
            "owner": ExecutionContext.DRLINK_SERVER.value,
            "valid": "set remote-access / test remote-access",
            "invalid_on_agent": "set remote-access",
        },
        "internet-access": {
            "owner": ExecutionContext.DRLINK_SERVER.value,
            "valid": "set internet-access / test internet-access",
            "invalid_on_agent": "set internet-access",
        },
        "configuration-bundle": {
            "owner": ExecutionContext.DRLINK_SERVER.value,
            "valid": "system export/test/diff/apply configuration",
        },
    }
