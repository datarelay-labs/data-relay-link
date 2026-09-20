#!/usr/bin/env python3
"""AI Access Human UX scenarios HUX-AI-001..006."""
from __future__ import annotations

from framework.assertions import expect_contains, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, InteractionMode, Layer


def _verify(plane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'verified', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.conn.commit()


def _seed_ai(plane) -> None:
    import drlink_v24 as v24

    plane.set_ai_principal("automation-bot", enabled=True)
    _verify(plane, "automation-bot")
    v24.set_network_object(plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True)
    v24.set_permission_object(
        plane, "exec-only", permissions=["command-exec"], oneshot=True
    )


@scenario(
    "HUX-AI-001",
    "Create AI Identity",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="ai-access",
)
def hux_ai_001(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    # Wizard path requires TTY; seed via control-plane public create then show.
    h.server_plane.set_ai_principal("ops-bot", enabled=True)
    r = s.run("show", "ai-identities")
    expect_true(r.rc == 0, "show ai-identities failed", evidence=r.combined)
    expect_contains(r.combined, "ops-bot")


@scenario(
    "HUX-AI-002",
    "Create Permission Object for AI Access",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="ai-access",
)
def hux_ai_002(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run(
        "set",
        "permission-object",
        "host-read",
        "permissions",
        "host-info,process-read",
    )
    expect_true(r.rc == 0, "Permission Object create failed", evidence=r.combined)


@scenario(
    "HUX-AI-003",
    "Create AI Access Rule",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="ai-access",
)
def hux_ai_003(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    _seed_ai(h.server_plane)
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run(
        "set",
        "ai-access",
        "allow-exec",
        "mode",
        "whitelist",
        "source",
        "automation-bot",
        "destination",
        "ubuntu-prod",
        "permission",
        "exec-only",
        "enabled",
    )
    expect_true(r.rc == 0, "AI Access rule create failed", evidence=r.combined)


@scenario(
    "HUX-AI-004",
    "Test AI Access allow path",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="ai-access",
)
def hux_ai_004(env: ScenarioEnv) -> None:
    import drlink_v24 as v24

    h = env.ensure_server()
    _seed_ai(h.server_plane)
    v24.set_ai_access_rule(
        h.server_plane,
        "allow-exec",
        mode="whitelist",
        source="automation-bot",
        destination="ubuntu-prod",
        permission="exec-only",
        enabled=True,
        oneshot=True,
    )
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run(
        "test",
        "ai-access",
        "source",
        "automation-bot",
        "destination",
        "ubuntu-prod",
        "permission",
        "command-exec",
    )
    expect_true(r.rc == 0, "AI Access test failed", evidence=r.combined)
    expect_contains(r.combined.lower(), "allow")


@scenario(
    "HUX-AI-005",
    "Show AI Access unmatched semantics",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="ai-access",
)
def hux_ai_005(env: ScenarioEnv) -> None:
    import drlink_v24 as v24

    h = env.ensure_server()
    _seed_ai(h.server_plane)
    v24.set_ai_access_rule(
        h.server_plane,
        "block-exec",
        mode="blacklist",
        source="automation-bot",
        destination="ubuntu-prod",
        permission="exec-only",
        enabled=True,
        oneshot=True,
    )
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("show", "ai-access")
    expect_true(r.rc == 0, "show ai-access failed", evidence=r.combined)
    expect_contains(r.combined, "Unmatched")
    expect_true("Effective   :" not in r.combined, "misleading Effective label still present", evidence=r.combined)


@scenario(
    "HUX-AI-006",
    "AI Access help lifecycle discoverability",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="ai-access",
)
def hux_ai_006(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("help", "ai-access")
    expect_true(r.rc == 0, "help ai-access failed", evidence=r.combined)
    expect_contains(r.combined, "AI Identity")
    expect_contains(r.combined, "Permission Object")
    expect_contains(r.combined, "set ai-access")
    expect_contains(r.combined, "test ai-access")
    expect_true("AI Principal" not in r.combined, "legacy AI Principal in help", evidence=r.combined)
