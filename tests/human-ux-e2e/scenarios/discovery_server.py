"""Server discovery scenarios HUX-SRV-001..006."""
from __future__ import annotations

from framework.assertions import expect_any, expect_contains, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, InteractionMode, Layer


def _srv(env: ScenarioEnv) -> CliSession:
    h = env.ensure_server()
    return CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)


@scenario(
    "HUX-SRV-001",
    "Server first launch surfaces role",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="server",
)
def hux_srv_001(env: ScenarioEnv) -> None:
    s = _srv(env)
    r = s.run("show", "status")
    expect_true(r.rc == 0, "show status failed on fresh server", evidence=r.combined)
    text = r.combined
    expect_any(
        text,
        ("DRLink Server", "Server", "role"),
        message="Operator cannot determine host role from first show status",
    )


@scenario(
    "HUX-SRV-002",
    "Server ? help",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="server",
)
def hux_srv_002(env: ScenarioEnv) -> None:
    s = _srv(env)
    text = s.context_help_question()
    expect_true(len(text.strip()) > 20, "Empty ? help on Server")
    expect_any(text.lower(), ("show", "set", "system", "remote"), message="? help lacks actionable verbs")


@scenario(
    "HUX-SRV-003",
    "Server help",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="server",
)
def hux_srv_003(env: ScenarioEnv) -> None:
    s = _srv(env)
    text = s.catalog_help()
    expect_true(len(text.strip()) > 20, "Empty help on Server")
    expect_any(text, ("Remote Access", "remote-access", "Managed Host", "Enrollment", "enrollment"))


@scenario(
    "HUX-SRV-004",
    "Server menu discoverability",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="server",
)
def hux_srv_004(env: ScenarioEnv) -> None:
    s = _srv(env)
    text = s.catalog_menu()
    expect_any(text, ("Remote Access", "Internet Access", "remote-access", "internet-access"))
    # Remote Service creation belongs on Agent — menu should not imply Server ownership without guidance
    if "Remote Service" in text or "remote-service" in text:
        expect_any(
            text,
            ("Agent Host", "Agent"),
            message="Server menu mentions Remote Service without Agent Host context",
        )


@scenario(
    "HUX-SRV-005",
    "Server show status",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="server",
)
def hux_srv_005(env: ScenarioEnv) -> None:
    s = _srv(env)
    r = s.run("show", "status")
    expect_true(r.rc == 0, "show status rc!=0", evidence=r.combined)


@scenario(
    "HUX-SRV-006",
    "Server show version",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="server",
)
def hux_srv_006(env: ScenarioEnv) -> None:
    s = _srv(env)
    r = s.run("system", "version")
    if r.rc != 0:
        r = s.run("show", "version")
    expect_true(r.rc == 0, "version command failed", evidence=r.combined)
    expect_any(r.combined, ("2.4", "Data Relay Link", "FRP", "version", "Channel", "Source"))
    env.extracted["version_text"] = r.combined
