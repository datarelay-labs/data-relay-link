"""Wizard adversarial scenarios HUX-WIZ-001..008."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from framework.assertions import expect_contains, expect_re, expect_true, expect_no_mutation_claim
from framework.scenario_api import ScenarioEnv, scenario
from framework.types import ExecutionContext, FindingClass, InteractionMode, Layer, Severity


def _plane_with_io(answers: list[str]):
    import drlink_v24 as v24
    from drlink_control_plane import ControlPlane
    from drlink_v24_wizard import ScriptedIO, set_wizard_io

    tmp = tempfile.mkdtemp(prefix="hux-wiz-")
    Path(tmp, "etc/drlink").mkdir(parents=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
    plane = ControlPlane(tmp)
    v24.ensure_v2_schema(plane.conn)
    out: list[str] = []
    set_wizard_io(ScriptedIO(answers, out=out))
    return tmp, plane, out


def _cleanup(tmp, plane):
    from drlink_v24_wizard import set_wizard_io

    set_wizard_io(None)
    try:
        plane.close()
    except Exception:
        pass
    shutil.rmtree(tmp, ignore_errors=True)


@scenario(
    "HUX-WIZ-001",
    "Valid numeric Wizard choice",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.NORMAL,
    domain="wizard",
)
def hux_wiz_001(env: ScenarioEnv) -> None:
    from drlink_v24_wizard import run_service_object_wizard
    import drlink_v24 as v24

    tmp, plane, out = _plane_with_io(["1", "1"])  # SSH + Apply
    env.recorder.note("answers=1,1 (SSH, Apply)")
    try:
        rc = run_service_object_wizard(plane, "office-ssh")
        text = "".join(out)
        env.recorder.output(text)
        expect_true(rc == 0, "Wizard failed for valid choice", evidence=text)
        row = v24.get_service_object(plane, "office-ssh")
        expect_true(row is not None and int(row["port"]) == 22, "SSH service object not created")
    finally:
        _cleanup(tmp, plane)


@scenario(
    "HUX-WIZ-002",
    "Invalid numeric Wizard choice recovers",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.ADVERSARIAL,
    domain="wizard",
)
def hux_wiz_002(env: ScenarioEnv) -> None:
    from drlink_v24_wizard import run_service_object_wizard
    import drlink_v24 as v24

    # 99 invalid, then 1 SSH, then 1 Apply
    tmp, plane, out = _plane_with_io(["99", "1", "1"])
    try:
        rc = run_service_object_wizard(plane, "svc-retry")
        text = "".join(out)
        env.recorder.output(text)
        expect_contains(text, "Invalid selection")
        expect_true(rc == 0, "Should recover after invalid then valid", evidence=text)
        expect_true(v24.get_service_object(plane, "svc-retry") is not None, "Object missing after recovery")
    finally:
        _cleanup(tmp, plane)


@scenario(
    "HUX-WIZ-003",
    "CLI command pasted into Select explains Wizard context",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.ADVERSARIAL,
    domain="wizard",
    tags=("regression", "wizard-wrong-command"),
)
def hux_wiz_003(env: ScenarioEnv) -> None:
    from drlink_v24_wizard import run_service_object_wizard
    import drlink_v24 as v24

    tmp, plane, out = _plane_with_io(["show status", "c"])
    try:
        rc = run_service_object_wizard(plane, "should-not-exist")
        text = "".join(out)
        env.recorder.output(text)
        expect_re(
            text,
            r"menu selection|waiting for a menu|looks like a DRLink command",
            message="Missing Wizard-context explanation for pasted CLI command",
            classification=FindingClass.HUMAN_UX_CONFUSION,
            severity=Severity.P1,
        )
        expect_no_mutation_claim(text)
        expect_true(v24.get_service_object(plane, "should-not-exist") is None, "Unexpected mutation")
        expect_true(rc != 0 or "Cancel" in text or "cancel" in text.lower() or rc == 1, "Expected cancel/abort path")
    finally:
        _cleanup(tmp, plane)


@scenario(
    "HUX-WIZ-004",
    "Blank input on Select",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.ADVERSARIAL,
    domain="wizard",
)
def hux_wiz_004(env: ScenarioEnv) -> None:
    from drlink_v24_wizard import run_service_object_wizard

    tmp, plane, out = _plane_with_io(["", "1", "1"])
    try:
        rc = run_service_object_wizard(plane, "blank-then-ok")
        text = "".join(out)
        env.recorder.output(text)
        expect_contains(text, "Invalid selection")
        expect_true(rc == 0, "Should accept after blank then valid", evidence=text)
    finally:
        _cleanup(tmp, plane)


@scenario(
    "HUX-WIZ-005",
    "Backspace-to-empty semantics (ScriptedIO empty string)",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.PTY,
    domain="wizard",
)
def hux_wiz_005(env: ScenarioEnv) -> None:
    # Scripted equivalent of erasing input to empty then submitting.
    from drlink_v24_wizard import run_service_object_wizard

    tmp, plane, out = _plane_with_io(["", "2", "1"])  # empty, HTTP, Apply
    try:
        rc = run_service_object_wizard(plane, "after-erase")
        text = "".join(out)
        env.recorder.output(text)
        expect_true(rc == 0, "Wizard did not recover from empty input", evidence=text)
    finally:
        _cleanup(tmp, plane)


@scenario(
    "HUX-WIZ-006",
    "Wizard Cancel — no partial mutation",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.ADVERSARIAL,
    domain="wizard",
)
def hux_wiz_006(env: ScenarioEnv) -> None:
    from drlink_v24_wizard import run_service_object_wizard
    import drlink_v24 as v24

    tmp, plane, out = _plane_with_io(["c"])
    try:
        rc = run_service_object_wizard(plane, "cancelled-svc")
        text = "".join(out)
        env.recorder.output(text)
        expect_true(v24.get_service_object(plane, "cancelled-svc") is None, "Cancel leaked object")
        # Product contract: Cancel is a clean abort (rc may be 0) with no mutation.
        expect_true(rc in (0, 1), "Unexpected cancel rc=%s" % rc)
    finally:
        _cleanup(tmp, plane)


@scenario(
    "HUX-WIZ-007",
    "Wizard Ctrl+C / KeyboardInterrupt path",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.ADVERSARIAL,
    domain="wizard",
)
def hux_wiz_007(env: ScenarioEnv) -> None:
    from drlink_v24_wizard import ScriptedIO, set_wizard_io, run_service_object_wizard, WizardCancelled
    import drlink_v24 as v24
    from drlink_control_plane import ControlPlane

    tmp = tempfile.mkdtemp(prefix="hux-wiz-intr-")
    Path(tmp, "etc/drlink").mkdir(parents=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
    plane = ControlPlane(tmp)
    v24.ensure_v2_schema(plane.conn)
    out: list[str] = []

    class BoomIO(ScriptedIO):
        def ask(self, prompt: str) -> str:
            raise KeyboardInterrupt

    set_wizard_io(BoomIO([], out=out))
    try:
        try:
            rc = run_service_object_wizard(plane, "intr-svc")
        except (KeyboardInterrupt, WizardCancelled, EOFError):
            rc = 130
        expect_true(v24.get_service_object(plane, "intr-svc") is None, "Ctrl+C leaked object")
        env.recorder.note("rc=%s no object" % rc)
    finally:
        set_wizard_io(None)
        plane.close()
        shutil.rmtree(tmp, ignore_errors=True)


@scenario(
    "HUX-WIZ-008",
    "Wizard EOF — no partial mutation",
    execution_context=ExecutionContext.DRLINK_SERVER,
    interaction_mode=InteractionMode.WIZARD,
    layer=Layer.ADVERSARIAL,
    domain="wizard",
)
def hux_wiz_008(env: ScenarioEnv) -> None:
    from drlink_v24_wizard import ScriptedIO, set_wizard_io, run_service_object_wizard
    import drlink_v24 as v24
    from drlink_control_plane import ControlPlane

    tmp = tempfile.mkdtemp(prefix="hux-wiz-eof-")
    Path(tmp, "etc/drlink").mkdir(parents=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
    plane = ControlPlane(tmp)
    v24.ensure_v2_schema(plane.conn)
    out: list[str] = []

    class EofIO(ScriptedIO):
        def ask(self, prompt: str) -> str:
            raise EOFError

    set_wizard_io(EofIO([], out=out))
    try:
        try:
            rc = run_service_object_wizard(plane, "eof-svc")
        except EOFError:
            rc = 1
        text = "".join(out)
        env.recorder.output(text)
        expect_true(v24.get_service_object(plane, "eof-svc") is None, "EOF leaked object")
        env.recorder.note("rc=%s" % rc)
    finally:
        set_wizard_io(None)
        plane.close()
        shutil.rmtree(tmp, ignore_errors=True)
