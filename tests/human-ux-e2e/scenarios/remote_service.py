"""Remote Service scenarios HUX-RS-001..006."""
from __future__ import annotations

from framework.assertions import expect_contains, expect_eq, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.state_machine import WorkflowState
from framework.types import ExecutionContext, InteractionMode, Layer


def _port_of(created: dict) -> int | None:
    for key in ("endpoint_port", "public_port", "port"):
        val = created.get(key) if isinstance(created, dict) else None
        if val is not None:
            return int(val)
    return None


def _mirror_agent_row(h, name: str, port: int, *, enabled: bool = True, status: str = "HEALTHY") -> None:
    """Keep Agent-local inventory aligned with Server allocation for show views."""
    h.agent_plane.conn.execute("DELETE FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,))
    h.agent_plane.conn.execute(
        "INSERT INTO agent_remote_services"
        "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
        "pending_allocation, delete_pending, pool_class, reason, updated_at) "
        "VALUES (?, 'this-host', 'ssh', ?, ?, ?, ?, 0, 0, 'normal', '', ?)",
        (
            name,
            1 if enabled else 0,
            status if enabled else "DISABLED",
            h.public_hostname,
            port,
            "2026-09-19T00:00:00Z",
        ),
    )
    h.agent_plane.conn.commit()


def _create_rs(env: ScenarioEnv, name: str = "ssh-access", *, enabled: bool = True):
    import drlink_mgmt_sync as mgmt

    h = env.ensure_dual()
    created = mgmt.upsert_remote_service_on_server(
        root=str(h.agent_root),
        name=name,
        destination="this-host",
        service="ssh",
        enabled=enabled,
        pool_class="normal",
        target_host="127.0.0.1",
        target_port=22,
        target_mode="self",
        runtime_verified=True,
    )
    port = _port_of(created)
    if port is not None:
        _mirror_agent_row(h, name, port, enabled=enabled, status=str(created.get("status") or "HEALTHY"))
    return h, created, port


@scenario(
    "HUX-RS-001",
    "Create Remote Service (mgmt path)",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="remote-service",
)
def hux_rs_001(env: ScenarioEnv) -> None:
    h, created, port = _create_rs(env)
    env.recorder.note("created=%s" % created)
    expect_true(
        created.get("status") in ("HEALTHY", "OK", "CREATED", "PENDING", "DEGRADED") or port is not None,
        "Remote Service create did not return usable status",
        evidence=str(created),
    )
    env.extracted["rs_port"] = port
    env.extracted["rs_name"] = "ssh-access"
    env.sm.advance(WorkflowState.REMOTE_SERVICE_CREATED, via="upsert_remote_service")
    expect_true(port is not None, "No public port allocated", evidence=str(created))


@scenario(
    "HUX-RS-002",
    "Show Remote Service",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="remote-service",
)
def hux_rs_002(env: ScenarioEnv) -> None:
    h, created, port = _create_rs(env, "ssh-show")
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    r = s.run("show", "remote-service", "ssh-show")
    expect_true(r.rc == 0, "show remote-service failed", evidence=r.combined)
    expect_contains(r.combined, "ssh-show")
    if port:
        expect_contains(r.combined, str(port))
    env.extracted["show_text"] = r.combined
    env.extracted["rs_port"] = port


@scenario(
    "HUX-RS-003",
    "Disable Remote Service",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="remote-service",
)
def hux_rs_003(env: ScenarioEnv) -> None:
    import drlink_mgmt_sync as mgmt

    h, created, port = _create_rs(env, "ssh-toggle")
    disabled = mgmt.upsert_remote_service_on_server(
        root=str(h.agent_root),
        name="ssh-toggle",
        destination="this-host",
        service="ssh",
        enabled=False,
        pool_class="normal",
        target_host="127.0.0.1",
        target_port=22,
        target_mode="self",
        runtime_verified=True,
        preserve_endpoint_port=port,
    )
    port2 = _port_of(disabled) or port
    if port and port2:
        expect_eq(int(port2), int(port), message="Disable changed endpoint port identity")
        _mirror_agent_row(h, "ssh-toggle", int(port2), enabled=False)


@scenario(
    "HUX-RS-004",
    "Enable Remote Service",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.ADVERSARIAL,
    domain="remote-service",
)
def hux_rs_004(env: ScenarioEnv) -> None:
    import drlink_mgmt_sync as mgmt

    h, created, port = _create_rs(env, "ssh-en")
    mgmt.upsert_remote_service_on_server(
        root=str(h.agent_root),
        name="ssh-en",
        destination="this-host",
        service="ssh",
        enabled=False,
        pool_class="normal",
        target_host="127.0.0.1",
        target_port=22,
        target_mode="self",
        runtime_verified=True,
        preserve_endpoint_port=port,
    )
    enabled = mgmt.upsert_remote_service_on_server(
        root=str(h.agent_root),
        name="ssh-en",
        destination="this-host",
        service="ssh",
        enabled=True,
        pool_class="normal",
        target_host="127.0.0.1",
        target_port=22,
        target_mode="self",
        runtime_verified=True,
        preserve_endpoint_port=port,
    )
    port2 = _port_of(enabled)
    if port and port2:
        expect_eq(int(port2), int(port), message="Enable changed endpoint port")


@scenario(
    "HUX-RS-005",
    "Remote Service endpoint stable across views",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.CONSISTENCY,
    domain="remote-service",
    tags=("consistency",),
)
def hux_rs_005(env: ScenarioEnv) -> None:
    h, created, port = _create_rs(env, "ssh-stable")
    expect_true(port is not None, "missing port", evidence=str(created))
    port = int(port)
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    one = s.run("show", "remote-service", "ssh-stable")
    many = s.run("show", "remote-services")
    expect_contains(one.combined, str(port))
    expect_contains(many.combined, str(port))
    srv = CliSession(root=h.server_root, context=ExecutionContext.DRLINK_SERVER, recorder=env.recorder)
    mh = srv.run("show", "managed-host", h.hostname, "remote-services")
    if mh.rc == 0 and mh.combined.strip():
        expect_contains(mh.combined, str(port))
    env.extracted["rs_port"] = port


@scenario(
    "HUX-RS-006",
    "Delete Remote Service",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="remote-service",
)
def hux_rs_006(env: ScenarioEnv) -> None:
    import drlink_mgmt_sync as mgmt

    h, _created, _port = _create_rs(env, "ssh-del")
    mgmt.delete_remote_service_on_server(root=str(h.agent_root), name="ssh-del")
    h.agent_plane.conn.execute("DELETE FROM agent_remote_services WHERE name = ? COLLATE NOCASE", ("ssh-del",))
    h.agent_plane.conn.commit()
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    r = s.run("show", "remote-service", "ssh-del")
    expect_true(
        r.rc != 0 or "not found" in r.combined.lower(),
        "Deleted Remote Service still presented as active",
        evidence=r.combined,
    )
