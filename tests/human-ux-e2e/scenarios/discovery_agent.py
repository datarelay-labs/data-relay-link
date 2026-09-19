"""Agent discovery scenarios HUX-AGT-001..008."""
from __future__ import annotations

from framework.assertions import expect_any, expect_contains, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, FindingClass, InteractionMode, Layer, Severity


def _agt(env: ScenarioEnv) -> CliSession:
    h = env.ensure_agent()
    return CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)


@scenario(
    "HUX-AGT-001",
    "Agent first launch surfaces Agent Host role",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_001(env: ScenarioEnv) -> None:
    s = _agt(env)
    r = s.run("show", "status")
    expect_true(r.rc == 0, "show status failed on agent", evidence=r.combined)
    expect_contains(
        r.combined,
        "Agent Host",
        message="Operator cannot determine Agent Host role from show status",
        classification=FindingClass.ROLE_CONTEXT_CONFUSION,
        severity=Severity.P1,
    )


@scenario(
    "HUX-AGT-002",
    "Agent ?",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_002(env: ScenarioEnv) -> None:
    s = _agt(env)
    text = s.context_help_question()
    expect_true(len(text.strip()) > 20, "Empty ? help on Agent")
    expect_any(text.lower(), ("remote-service", "show", "system"))


@scenario(
    "HUX-AGT-003",
    "Agent help",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_003(env: ScenarioEnv) -> None:
    s = _agt(env)
    text = s.catalog_help()
    expect_any(text, ("Remote Service", "remote-service", "Agent Host"))


@scenario(
    "HUX-AGT-004",
    "Agent menu shows where Remote Service is created",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_004(env: ScenarioEnv) -> None:
    s = _agt(env)
    text = s.catalog_menu()
    expect_any(text, ("Remote Service", "remote-service", "set remote-service"))
    # Suggested REPL commands should not require redundant leading drlink
    if "sudo drlink set remote-service" in text and "set remote-service" not in text.replace(
        "sudo drlink set remote-service", ""
    ):
        # Soft: shell instructions may use sudo drlink; REPL form should also appear
        expect_any(text, ("set remote-service",), message="Menu lacks REPL-form command")


@scenario(
    "HUX-AGT-005",
    "Agent show status",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_005(env: ScenarioEnv) -> None:
    s = _agt(env)
    r = s.run("show", "status")
    expect_true(r.rc == 0, "show status failed", evidence=r.combined)
    expect_contains(r.combined, "Agent Host")


@scenario(
    "HUX-AGT-006",
    "Agent show agent",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
    tags=("regression", "show-agent"),
)
def hux_agt_006(env: ScenarioEnv) -> None:
    s = _agt(env)
    r = s.run("show", "agent")
    expect_true(r.rc == 0, "show agent failed", evidence=r.combined)
    expect_contains(r.combined, "Role: Agent Host")
    expect_any(r.combined, ("show remote-services", "Remote Service"))


@scenario(
    "HUX-AGT-007",
    "Agent show remote-services",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_007(env: ScenarioEnv) -> None:
    s = _agt(env)
    r = s.run("show", "remote-services")
    expect_true(r.rc == 0, "show remote-services failed", evidence=r.combined)


@scenario(
    "HUX-AGT-008",
    "Agent system diagnostics",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_008(env: ScenarioEnv) -> None:
    s = _agt(env)
    r = s.run("system", "diagnostics")
    # Diagnostics may WARN in fixture without live frpc — must not traceback
    expect_true(
        "Traceback" not in r.combined,
        "system diagnostics produced traceback",
        evidence=r.combined,
    )
    expect_any(r.combined, ("Agent Host", "Data Relay Link", "diagnostic", "PASS", "WARN", "FAIL", "INFO"))
