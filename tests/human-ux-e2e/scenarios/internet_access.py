"""Internet Access scenarios HUX-IA-001..006."""
from __future__ import annotations

from framework.assertions import expect_any, expect_true, expect_no_mutation_claim
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, InteractionMode, Layer


def _seed(plane):
    import drlink_v24 as v24

    v24.set_network_object(plane, "corp-users", type="cidr", value="10.0.0.0/8", oneshot=True)
    v24.set_network_object(plane, "example-fqdn", type="fqdn", value="example.com", oneshot=True)
    v24.set_service_object(plane, "https", type="tcp", port=443, oneshot=True)


@scenario(
    "HUX-IA-001",
    "Create destination FQDN Network Object",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="internet-access",
)
def hux_ia_001(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run("set", "network-object", "cdn-edge", "type", "fqdn", "value", "cdn.example.com")
    expect_true(r.rc == 0, "FQDN object create failed", evidence=r.combined)


@scenario(
    "HUX-IA-002",
    "Create HTTPS Internet Access rule",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="internet-access",
)
def hux_ia_002(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    _seed(h.server_plane)
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run(
        "set",
        "internet-access",
        "allow-cdn-https",
        "mode",
        "whitelist",
        "source",
        "corp-users",
        "destination",
        "example-fqdn",
        "service",
        "https",
        "enabled",
    )
    expect_true(r.rc == 0, "Internet Access create failed", evidence=r.combined)


@scenario(
    "HUX-IA-003",
    "Internet Access policy test",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="internet-access",
)
def hux_ia_003(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    _seed(h.server_plane)
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    s.run(
        "set",
        "internet-access",
        "ia-test",
        "mode",
        "whitelist",
        "source",
        "corp-users",
        "destination",
        "example-fqdn",
        "service",
        "https",
        "enabled",
    )
    r = s.run(
        "test",
        "internet-access",
        "source",
        "corp-users",
        "destination",
        "example-fqdn",
        "service",
        "https",
    )
    expect_true(r.rc == 0, "test internet-access failed", evidence=r.combined)
    expect_any(r.combined, ("ALLOW", "DENY"))


@scenario(
    "HUX-IA-004",
    "Disable Internet Access rule",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="internet-access",
)
def hux_ia_004(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    _seed(h.server_plane)
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    s.run(
        "set",
        "internet-access",
        "ia-dis",
        "mode",
        "whitelist",
        "source",
        "corp-users",
        "destination",
        "example-fqdn",
        "service",
        "https",
        "enabled",
    )
    r = s.run("set", "internet-access", "ia-dis", "disabled")
    expect_true(r.rc == 0, "disable failed", evidence=r.combined)


@scenario(
    "HUX-IA-005",
    "Enable Internet Access rule",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="internet-access",
)
def hux_ia_005(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    _seed(h.server_plane)
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    s.run(
        "set",
        "internet-access",
        "ia-en",
        "mode",
        "whitelist",
        "source",
        "corp-users",
        "destination",
        "example-fqdn",
        "service",
        "https",
        "disabled",
    )
    r = s.run("set", "internet-access", "ia-en", "enabled")
    expect_true(r.rc == 0, "enable failed", evidence=r.combined)


@scenario(
    "HUX-IA-006",
    "Managed Host invalid as Internet Access destination",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="internet-access",
)
def hux_ia_006(env: ScenarioEnv) -> None:
    h = env.ensure_server()
    import drlink_v24 as v24

    v24.set_network_object(h.server_plane, "corp-users", type="cidr", value="10.0.0.0/8", oneshot=True)
    v24.set_service_object(h.server_plane, "https", type="tcp", port=443, oneshot=True)
    # Register a managed host name and try to use it as destination
    try:
        h.server_plane.upsert_client("cccccccccccccccccccccccccccccccc", label="mh1", hostname="mh1")
    except Exception:
        pass
    s = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    r = s.run(
        "set",
        "internet-access",
        "bad-mh-dst",
        "mode",
        "whitelist",
        "source",
        "corp-users",
        "destination",
        "mh1",
        "service",
        "https",
        "enabled",
    )
    expect_true(r.rc != 0, "Managed Host should be invalid IA destination", evidence=r.combined)
    expect_any(r.combined.lower(), ("managed host", "invalid", "not", "network object", "destination", "error"))
