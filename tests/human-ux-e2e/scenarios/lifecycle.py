"""Lifecycle scenarios HUX-LIFE-001..006."""
from __future__ import annotations

from framework.assertions import expect_contains, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, InteractionMode, Layer


def _grammar_ok(tokens, role="client"):
    from frp_ctl_grammar import match

    r = match(list(tokens), role=role)
    return r.get("status") == "ok", r


@scenario(
    "HUX-LIFE-001",
    "system pause parses on Agent",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="lifecycle",
)
def hux_life_001(env: ScenarioEnv) -> None:
    ok, r = _grammar_ok(["system", "pause"])
    env.recorder.note(str(r))
    expect_true(ok, "system pause not in public Agent grammar", evidence=str(r))


@scenario(
    "HUX-LIFE-002",
    "system resume parses on Agent",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="lifecycle",
)
def hux_life_002(env: ScenarioEnv) -> None:
    ok, r = _grammar_ok(["system", "resume"])
    expect_true(ok, "system resume not in public Agent grammar", evidence=str(r))


@scenario(
    "HUX-LIFE-003",
    "system restart parses on Agent",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="lifecycle",
)
def hux_life_003(env: ScenarioEnv) -> None:
    ok, r = _grammar_ok(["system", "restart"])
    expect_true(ok, "system restart not in public Agent grammar", evidence=str(r))


@scenario(
    "HUX-LIFE-004",
    "autostart disable/enable parse",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="lifecycle",
)
def hux_life_004(env: ScenarioEnv) -> None:
    ok1, r1 = _grammar_ok(["system", "autostart", "disable"])
    ok2, r2 = _grammar_ok(["system", "autostart", "enable"])
    expect_true(ok1 and ok2, "autostart toggle missing from grammar", evidence="%s / %s" % (r1, r2))


@scenario(
    "HUX-LIFE-005",
    "diagnostics on Agent",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="lifecycle",
)
def hux_life_005(env: ScenarioEnv) -> None:
    h = env.ensure_agent()
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    r = s.run("system", "diagnostics")
    expect_true("Traceback" not in r.combined, "diagnostics traceback", evidence=r.combined)


@scenario(
    "HUX-LIFE-006",
    "Uninstall exits REPL (contract)",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.ADVERSARIAL,
    domain="lifecycle",
    tags=("regression", "uninstall-repl"),
)
def hux_life_006(env: ScenarioEnv) -> None:
    repl = (env.repo / "lib" / "frp_ctl_repl.py").read_text(encoding="utf-8")
    ctl = (env.repo / "tools" / "frpctl").read_text(encoding="utf-8")
    expect_contains(repl, "proc.returncode == 75")
    expect_contains(ctl, "return 75")
    expect_contains(ctl, "Exiting Data Relay Link.")
