"""Consistency scenarios HUX-CONS-001..008."""
from __future__ import annotations

from framework.assertions import expect_contains, expect_true
from framework.command_validator import validate_output_guidance, validate_remediation_block
from framework.consistency import (
    assert_agent_host_terminology,
    assert_endpoint_port_stable,
    assert_public_hostname_preference,
    assert_success_compatible_with_doctor,
    assert_version_identity,
    raise_if_findings,
)
from framework.scenario_api import ScenarioEnv, scenario
from framework.session import CliSession
from framework.types import ExecutionContext, InteractionMode, Layer


@scenario(
    "HUX-CONS-001",
    "Public hostname preference",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
    tags=("regression",),
)
def hux_cons_001(env: ScenarioEnv) -> None:
    import frp_server_config as scfg

    host = scfg.resolve_public_endpoint_host(
        {"public_ip": "203.0.113.10", "public_hostname": "remote.xdr.ooo"}
    )
    expect_true(host == "remote.xdr.ooo", "public hostname not preferred", evidence=host)
    host2 = scfg.resolve_public_endpoint_host({"public_ip": "203.0.113.10"})
    expect_true(host2 != "drlink.local", "invented drlink.local", evidence=host2)
    findings = assert_public_hostname_preference(
        {"sample": "Connect: https://remote.xdr.ooo:44300/"},
        public_hostname="remote.xdr.ooo",
    )
    raise_if_findings(findings)


@scenario(
    "HUX-CONS-002",
    "Remote Service port consistency",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
)
def hux_cons_002(env: ScenarioEnv) -> None:
    import drlink_mgmt_sync as mgmt

    h = env.ensure_dual()
    created = mgmt.upsert_remote_service_on_server(
        root=str(h.agent_root),
        name="cons-ssh",
        destination="this-host",
        service="ssh",
        enabled=True,
        pool_class="normal",
        target_host="127.0.0.1",
        target_port=22,
        target_mode="self",
        runtime_verified=True,
    )
    port = created.get("endpoint_port") or created.get("public_port") or created.get("port")
    expect_true(port is not None, "missing endpoint port", evidence=str(created))
    port = int(port)
    # Mirror into Agent inventory for show views.
    h.agent_plane.conn.execute("DELETE FROM agent_remote_services WHERE name = ? COLLATE NOCASE", ("cons-ssh",))
    h.agent_plane.conn.execute(
        "INSERT INTO agent_remote_services"
        "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
        "pending_allocation, delete_pending, pool_class, reason, updated_at) "
        "VALUES ('cons-ssh', 'this-host', 'ssh', 1, 'HEALTHY', ?, ?, 0, 0, 'normal', '', '2026-09-19T00:00:00Z')",
        (h.public_hostname, port),
    )
    h.agent_plane.conn.commit()
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    show = s.run("show", "remote-service", "cons-ssh")
    listing = s.run("show", "remote-services")
    texts = {"show": show.combined, "list": listing.combined, "create": str(created)}
    raise_if_findings(assert_endpoint_port_stable(texts, expected_port=port))


@scenario(
    "HUX-CONS-003",
    "Agent Host terminology across surfaces",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
    tags=("regression",),
)
def hux_cons_003(env: ScenarioEnv) -> None:
    h = env.ensure_agent()
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    status = s.run("show", "status")
    agent = s.run("show", "agent")
    diag = s.run("system", "diagnostics")
    help_text = s.catalog_help()
    texts = {
        "status": status.combined,
        "agent": agent.combined,
        "diagnostics": diag.combined,
        "help": help_text,
    }
    for label, text in texts.items():
        if label in ("status", "agent"):
            expect_contains(text, "Agent Host", message="%s missing Agent Host" % label)
    raise_if_findings(assert_agent_host_terminology(texts))


@scenario(
    "HUX-CONS-004",
    "Version identity consistency",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
    tags=("regression",),
)
def hux_cons_004(env: ScenarioEnv) -> None:
    import frp_version_identity as ident

    d = ident.derive_display_identity(
        project_version="2.4.0",
        channel="development",
        source_head="c2d1792dd5f75a1a69b56ae749633262eff2f4e5",
    )
    expect_true(d["display_identity"] == "2.4.0-dev+gc2d1792", "dev display identity drift", evidence=str(d))
    texts = {
        "derive": d["display_identity"],
        "doctor_sample": "Data Relay Link : 2.4.0-dev+gc2d1792\nChannel: development",
    }
    raise_if_findings(assert_version_identity(texts, expect_dev_display=True))


@scenario(
    "HUX-CONS-005",
    "Doctor health semantics vs success claim",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
)
def hux_cons_005(env: ScenarioEnv) -> None:
    # Synthetic: success claim + Doctor FAIL with config drift must be flagged.
    findings = assert_success_compatible_with_doctor(
        "setup complete — Agent Host connected and healthy",
        "Doctor overall: FAIL\nconfiguration drift detected in frpc.toml",
        doctor_overall="FAIL",
    )
    expect_true(len(findings) == 1, "consistency helper failed to detect success/doctor conflict")
    # Fixture agent diagnostics should not claim healthy success while failing hard on product drift.
    h = env.ensure_agent()
    s = CliSession(root=h.agent_root, context=ExecutionContext.AGENT_HOST, recorder=env.recorder)
    status = s.run("show", "status")
    diag = s.run("system", "diagnostics")
    overall = "FAIL" if "FAIL" in diag.combined.split("overall", 1)[-1][:80] else "PASS"
    if "healthy" in status.combined.lower() and "setup complete" in status.combined.lower():
        raise_if_findings(
            assert_success_compatible_with_doctor(status.combined, diag.combined, doctor_overall=overall)
        )


@scenario(
    "HUX-CONS-006",
    "Recommended commands parse in role grammar",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
    tags=("regression",),
)
def hux_cons_006(env: ScenarioEnv) -> None:
    sample = (
        "Recommended action:\n"
        "  sudo drlink system synchronize\n"
        "Next:\n"
        "  show remote-services\n"
    )
    findings = validate_remediation_block(sample, execution_context="AGENT_HOST")
    raise_if_findings(findings)
    # Doctor-style remediation
    import frp_doctor as doctor

    class R:
        role_label = "Agent Host"
        confidence = "complete"
        project_version = "2.4.0"
        display_identity = "2.4.0-dev+gc2d1792"
        release_channel = "development"
        source_ref = "c2d1792dd5f75a1a69b56ae749633262eff2f4e5"
        source_head = "c2d1792dd5f75a1a69b56ae749633262eff2f4e5"
        frp_version = "0.71.0"
        pinned_frp = "0.71.0"
        bundle_sha256 = "not applicable"
        display = {}
        checks = [
            {
                "id": "client_state_permissions",
                "status": "FAIL",
                "message": "bad",
                "section": "state",
                "recommendation": "sudo drlink system synchronize",
                "detail": "",
            }
        ]

        def counts(self):
            return {"PASS": 0, "WARN": 0, "FAIL": 1, "ERROR": 0, "INFO": 0, "NOT_APPLICABLE": 0}

        def overall(self):
            return "FAIL"

        def recommended_actions(self):
            return ["sudo drlink system synchronize"]

    text = doctor.render_human(R())
    env.recorder.output(text)
    raise_if_findings(validate_output_guidance(text, execution_context="AGENT_HOST"))


@scenario(
    "HUX-CONS-007",
    "SSH connection hint structure",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
    tags=("regression",),
)
def hux_cons_007(env: ScenarioEnv) -> None:
    sample = "ssh -p 42022 <username>@remote.xdr.ooo\n"
    findings = validate_output_guidance(
        sample,
        execution_context="AGENT_HOST",
        expected_public_host="remote.xdr.ooo",
        expected_port=42022,
    )
    raise_if_findings(findings)
    # Source contract for optional username
    src = (env.repo / "lib" / "frp-client-common.sh").read_text(encoding="utf-8")
    expect_contains(src, "or '<username>'")


@scenario(
    "HUX-CONS-008",
    "Zero-Touch endpoint == runtime endpoint contract",
    execution_context=ExecutionContext.EXTERNAL_TEST_CLIENT,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.CONSISTENCY,
    domain="consistency",
    tags=("regression", "zero-touch"),
)
def hux_cons_008(env: ScenarioEnv) -> None:
    import frp_zero_touch as zt

    ticket = "bt1." + ("a" * 16) + "." + ("b" * 64)
    cmd = zt.short_url_command("remote.xdr.ooo", ticket)
    expect_contains(cmd, "https://remote.xdr.ooo/i/")
    expect_true("mktemp" not in cmd, "Zero-Touch regressed to giant opaque shell")
    expect_true("--insecure" not in cmd, "short URL must not disable TLS verify")
