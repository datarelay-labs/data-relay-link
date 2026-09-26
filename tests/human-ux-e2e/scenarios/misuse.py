"""Additional misuse / adversarial scenarios."""
from __future__ import annotations

from framework.assertions import expect_any, expect_contains, expect_true, expect_no_mutation_claim
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, InteractionMode, Layer


@scenario(
    "HUX-MISUSE-001",
    "Invalid CIDR rejected with recovery guidance",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="misuse",
)
def hux_misuse_001(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("set", "network-object", "bad-cidr", "type", "cidr", "value", "10.0.0.0/99")
    expect_true(r.rc != 0, "invalid CIDR accepted", evidence=r.combined)
    expect_any(r.combined.lower(), ("cidr", "invalid", "error", "expected"))


@scenario(
    "HUX-MISUSE-002",
    "Invalid IP rejected",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="misuse",
)
def hux_misuse_002(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("set", "network-object", "bad-ip", "type", "ip", "value", "999.1.2.3")
    expect_true(r.rc != 0, "invalid IP accepted", evidence=r.combined)


@scenario(
    "HUX-MISUSE-003",
    "Invalid FQDN rejected",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="misuse",
)
def hux_misuse_003(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("set", "network-object", "bad-fqdn", "type", "fqdn", "value", "-not_a_fqdn")
    expect_true(r.rc != 0, "invalid FQDN accepted", evidence=r.combined)


@scenario(
    "HUX-MISUSE-004",
    "Invalid port rejected",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="misuse",
)
def hux_misuse_004(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("set", "service-object", "bad-port", "type", "tcp", "port", "70000")
    expect_true(r.rc != 0, "invalid port accepted", evidence=r.combined)


@scenario(
    "HUX-MISUSE-005",
    "Duplicate object explained",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="misuse",
)
def hux_misuse_005(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r1 = s.run("set", "network-object", "dup-obj", "type", "ip", "value", "203.0.113.9")
    expect_true(r1.rc == 0, "first create failed", evidence=r1.combined)
    r2 = s.run("set", "network-object", "dup-obj", "type", "ip", "value", "203.0.113.9")
    # Update-in-place may be OK; accidental second distinct object is not.
    # If it fails, must explain duplicate; if succeeds, must be idempotent update.
    if r2.rc != 0:
        expect_any(r2.combined.lower(), ("exist", "duplicate", "already", "conflict"))
    else:
        expect_true("Traceback" not in r2.combined, "duplicate path traceback")


@scenario(
    "HUX-MISUSE-006",
    "Multi-line paste into Wizard Select does not mutate",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.ADVERSARIAL,
    domain="misuse",
)
def hux_misuse_006(env: ScenarioEnv) -> None:
    import shutil
    import tempfile
    from pathlib import Path
    import drlink_v24 as v24
    from drlink_control_plane import ControlPlane
    from drlink_v24_wizard import ScriptedIO, set_wizard_io, run_service_object_wizard

    tmp = tempfile.mkdtemp(prefix="hux-paste-")
    Path(tmp, "etc/drlink").mkdir(parents=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
    plane = ControlPlane(tmp)
    v24.ensure_v2_schema(plane.conn)
    pasted = "show status\nshow remote-services\nsystem diagnostics"
    out: list[str] = []
    set_wizard_io(ScriptedIO([pasted, "c"], out=out))
    try:
        run_service_object_wizard(plane, "paste-svc")
        text = "".join(out)
        env.recorder.output(text)
        expect_contains(text, "DRLink command")
        expect_no_mutation_claim(text)
        expect_true(v24.get_service_object(plane, "paste-svc") is None, "paste mutated state")
    finally:
        set_wizard_io(None)
        plane.close()
        shutil.rmtree(tmp, ignore_errors=True)


@scenario(
    "HUX-MISUSE-007",
    "Misspelled Managed Host",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="misuse",
)
def hux_misuse_007(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("show", "managed-host", "no-such-host-xyz")
    expect_true(r.rc != 0, "missing host should fail", evidence=r.combined)
    expect_any(r.combined.lower(), ("not found", "unknown", "no such", "error", "missing"))
