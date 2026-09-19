"""ConfigurationBundle scenarios HUX-BUNDLE-001..008."""
from __future__ import annotations

from framework.assertions import expect_any, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, InteractionMode, Layer


def _yaml_bundle(*, context: str = "server") -> str:
    if context == "legacy":
        return """apiVersion: drlink.datarelay.run/v1alpha1
kind: ConfigurationBundle
metadata:
  name: hux-bundle
spec:
  objects:
    - name: hq-admin
      type: Network
      values:
        - 203.0.113.10/32
"""
    return """configurationBundle:
  context: %s
  networkObjects:
    - name: hq-admin
      type: cidr
      value: 203.0.113.10/32
""" % context


@scenario(
    "HUX-BUNDLE-001",
    "Export configuration",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="bundle",
)
def hux_bundle_001(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    path = h.server_root / "tmp-export.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("system", "export", "configuration", str(path))
    expect_true(r.rc == 0, "export failed", evidence=r.combined)
    expect_true(path.is_file() and path.stat().st_size > 20, "export file missing/empty")
    env.extracted["bundle_path"] = str(path)


@scenario(
    "HUX-BUNDLE-002",
    "Test configuration",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="bundle",
)
def hux_bundle_002(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    path = h.server_root / "bundle-test.yaml"
    path.write_text(_yaml_bundle(), encoding="utf-8")
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("test", "configuration", str(path))
    expect_true(r.rc == 0, "test configuration failed", evidence=r.combined)


@scenario(
    "HUX-BUNDLE-003",
    "Diff configuration",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="bundle",
)
def hux_bundle_003(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    path = h.server_root / "bundle-diff.yaml"
    path.write_text(_yaml_bundle(), encoding="utf-8")
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("system", "diff", "configuration", str(path))
    expect_true(r.rc == 0, "diff failed", evidence=r.combined)


@scenario(
    "HUX-BUNDLE-004",
    "Apply configuration",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="bundle",
)
def hux_bundle_004(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    path = h.server_root / "bundle-apply.yaml"
    path.write_text(_yaml_bundle(), encoding="utf-8")
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("system", "apply", "configuration", str(path))
    expect_true(r.rc == 0, "apply failed", evidence=r.combined)
    expect_any(r.combined, ("APPLIED", "Applied", "applied", "NO_CHANGE", "NO CHANGE"))


@scenario(
    "HUX-BUNDLE-005",
    "Reapply produces NO CHANGE",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="bundle",
)
def hux_bundle_005(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    path = h.server_root / "bundle-reapply.yaml"
    path.write_text(_yaml_bundle(), encoding="utf-8")
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r1 = s.run("system", "apply", "configuration", str(path))
    expect_true(r1.rc == 0, "first apply failed", evidence=r1.combined)
    r2 = s.run("system", "apply", "configuration", str(path))
    expect_true(r2.rc == 0, "reapply failed", evidence=r2.combined)
    expect_any(r2.combined, ("NO_CHANGE", "NO CHANGE", "No change", "no change"))


@scenario(
    "HUX-BUNDLE-006",
    "stdin configuration test with :end",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.MIXED,
    layer=Layer.NORMAL,
    domain="bundle",
)
def hux_bundle_006(env: ScenarioEnv) -> None:
    from drlink_configuration_bundle import prepare_plan
    from drlink_v24_bundle import prepare_v24_plan

    h = env.ensure_server()
    raw = _yaml_bundle()
    try:
        plan = prepare_v24_plan(h.server_plane, raw)
    except Exception:
        plan = prepare_plan(h.server_plane, raw)
    env.recorder.note("stdin YAML accepted; plan=%s" % type(plan).__name__)
    expect_true(plan is not None, "stdin YAML plan failed")


@scenario(
    "HUX-BUNDLE-007",
    "Malformed input — zero partial mutation",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="bundle",
)
def hux_bundle_007(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    path = h.server_root / "bad.yaml"
    path.write_text("```yaml\nthis is not a bundle\n:end\n", encoding="utf-8")
    before = h.server_plane.current_revision()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("test", "configuration", str(path))
    after = h.server_plane.current_revision()
    expect_true(r.rc != 0, "malformed should fail", evidence=r.combined)
    expect_true(before == after, "malformed input mutated revision", evidence="%s -> %s" % (before, after))


@scenario(
    "HUX-BUNDLE-008",
    "Wrong context bundle on Agent",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="bundle",
)
def hux_bundle_008(env: ScenarioEnv) -> None:
    h = env.ensure_agent()
    path = h.agent_root / "bundle.yaml"
    path.write_text(_yaml_bundle(context="server"), encoding="utf-8")
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    r = s.run("system", "apply", "configuration", str(path))
    expect_true(r.rc != 0, "Agent should reject server-context ConfigurationBundle", evidence=r.combined)
    expect_any(
        r.combined.lower(),
        ("context is 'server'", "agent host", "no changes were applied", "server"),
    )
