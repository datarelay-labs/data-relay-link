"""Service Object Wizard scenarios HUX-SVC-001..007."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from framework.assertions import expect_contains, expect_not_contains, expect_true
from framework.scenario_api import ScenarioEnv, scenario
from framework.types import ExecutionContext, InteractionMode, Layer


def _run_svc(name: str, answers: list[str]):
    import drlink_v24 as v24
    from drlink_control_plane import ControlPlane
    from drlink_v24_wizard import ScriptedIO, set_wizard_io, run_service_object_wizard

    tmp = tempfile.mkdtemp(prefix="hux-svc-")
    Path(tmp, "etc/drlink").mkdir(parents=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
    plane = ControlPlane(tmp)
    v24.ensure_v2_schema(plane.conn)
    out: list[str] = []
    set_wizard_io(ScriptedIO(answers, out=out))
    try:
        rc = run_service_object_wizard(plane, name)
        text = "".join(out)
        row = v24.get_service_object(plane, name)
        return rc, text, row, tmp, plane
    except Exception:
        set_wizard_io(None)
        plane.close()
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _done(tmp, plane):
    from drlink_v24_wizard import set_wizard_io

    set_wizard_io(None)
    plane.close()
    shutil.rmtree(tmp, ignore_errors=True)


@scenario(
    "HUX-SVC-001",
    "Service Object SSH",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="service-object",
    tags=("regression",),
)
def hux_svc_001(env: ScenarioEnv) -> None:
    rc, text, row, tmp, plane = _run_svc("so-ssh", ["1", "1"])
    env.recorder.output(text)
    try:
        expect_true(rc == 0 and row and int(row["port"]) == 22, "SSH wizard failed", evidence=text)
        expect_contains(text, "SSH")
    finally:
        _done(tmp, plane)


@scenario(
    "HUX-SVC-002",
    "Service Object HTTP",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="service-object",
)
def hux_svc_002(env: ScenarioEnv) -> None:
    rc, text, row, tmp, plane = _run_svc("so-http", ["2", "1"])
    env.recorder.output(text)
    try:
        expect_true(rc == 0 and row and int(row["port"]) == 80, "HTTP wizard failed", evidence=text)
    finally:
        _done(tmp, plane)


@scenario(
    "HUX-SVC-003",
    "Service Object HTTPS",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="service-object",
)
def hux_svc_003(env: ScenarioEnv) -> None:
    rc, text, row, tmp, plane = _run_svc("so-https", ["3", "1"])
    env.recorder.output(text)
    try:
        expect_true(rc == 0 and row and int(row["port"]) == 443, "HTTPS wizard failed", evidence=text)
    finally:
        _done(tmp, plane)


@scenario(
    "HUX-SVC-004",
    "Service Object RDP",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="service-object",
)
def hux_svc_004(env: ScenarioEnv) -> None:
    rc, text, row, tmp, plane = _run_svc("so-rdp", ["4", "1"])
    env.recorder.output(text)
    try:
        expect_true(rc == 0 and row and int(row["port"]) == 3389, "RDP wizard failed", evidence=text)
    finally:
        _done(tmp, plane)


@scenario(
    "HUX-SVC-005",
    "Custom TCP requests a port",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="service-object",
    tags=("regression",),
)
def hux_svc_005(env: ScenarioEnv) -> None:
    # Custom TCP is typically option 5; then port then apply
    rc, text, row, tmp, plane = _run_svc("so-custom", ["5", "8443", "1"])
    env.recorder.output(text)
    try:
        expect_true(rc == 0, "Custom TCP wizard failed", evidence=text)
        expect_true(row is not None and int(row["port"]) == 8443, "Custom TCP port not applied", evidence=text)
        expect_contains(text.lower().replace("fixed tcp", ""), "tcp")  # soft
    finally:
        _done(tmp, plane)


@scenario(
    "HUX-SVC-006",
    "Fixed TCP distinguishable from Custom TCP",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="service-object",
    tags=("regression",),
)
def hux_svc_006(env: ScenarioEnv) -> None:
    rc, text, row, tmp, plane = _run_svc("so-fixed", ["6", "1521", "1"])
    env.recorder.output(text)
    try:
        expect_true(rc == 0, "Fixed TCP wizard failed", evidence=text)
        expect_contains(text, "Fixed TCP")
        expect_contains(text, "Custom TCP")
        expect_true(row is not None, "Fixed TCP object missing")
        row_d = dict(row)
        t = str(row_d.get("type") or "").lower()
        expect_true("fixed" in t or int(row_d["port"]) == 1521, "Fixed TCP type/port unclear", evidence=str(row_d))
    finally:
        _done(tmp, plane)


@scenario(
    "HUX-SVC-007",
    "UDP not exposed in normal public Wizard",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="service-object",
    tags=("regression",),
)
def hux_svc_007(env: ScenarioEnv) -> None:
    rc, text, row, tmp, plane = _run_svc("so-udp-check", ["1", "1"])
    env.recorder.output(text)
    try:
        menu = text.lower().split("service object type", 1)[-1].split("select:", 1)[0]
        expect_not_contains(menu, "udp", message="UDP offered in normal Service Object Wizard")
    finally:
        _done(tmp, plane)
