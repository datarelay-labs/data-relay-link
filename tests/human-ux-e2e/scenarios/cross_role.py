"""Cross-role misuse scenarios HUX-ROLE-001..002."""
from __future__ import annotations

from framework.assertions import expect_role_guidance, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, FindingClass, InteractionMode, Layer, Severity


@scenario(
    "HUX-ROLE-001",
    "Server-only command on Agent Host",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="cross-role",
)
def hux_role_001(env: ScenarioEnv) -> None:
    h = env.ensure_agent()
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    r = s.run("set", "remote-access", "office-ssh")
    text = r.combined
    expect_true(r.rc != 0, "Server command unexpectedly succeeded on Agent", evidence=text)
    expect_true(
        "unknown command" not in text.lower() or "managed on the DRLink Server" in text,
        "Unexplained Unknown command for detectable context mismatch",
        classification=FindingClass.ROLE_CONTEXT_CONFUSION,
        severity=Severity.P1,
        evidence=text,
    )
    expect_role_guidance(text, want_server=True)


@scenario(
    "HUX-ROLE-002",
    "Agent-only command on DRLink Server",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="cross-role",
)
def hux_role_002(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("set", "remote-service", "ssh-access")
    text = r.combined
    expect_true(r.rc != 0, "Agent command unexpectedly succeeded on Server", evidence=text)
    expect_role_guidance(text, want_agent=True)
