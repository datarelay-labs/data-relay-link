"""PTY human-input scenarios and regression wrappers."""
from __future__ import annotations

import os
import subprocess
import time

from framework.assertions import expect_contains, expect_true
from framework.pty_driver import feed_bytes, public_dns_prompt_script, run_pty_script
from framework.scenario_api import ScenarioEnv, scenario
from framework.types import ExecutionContext, InteractionMode, Layer


@scenario(
    "HUX-PTY-001",
    "Public DNS hostname prompt survives Backspace-to-empty",
    execution_context=ExecutionContext.EXTERNAL_TEST_CLIENT,
    interaction_mode=InteractionMode.PTY,
    layer=Layer.PTY,
    domain="pty",
    tags=("regression", "dns-prompt"),
)
def hux_pty_001(env: ScenarioEnv) -> None:
    def feed(master: int) -> None:
        feed_bytes(master, b"remote.xdr.ooo")
        time.sleep(0.05)
        feed_bytes(master, b"\x7f" * 20)
        time.sleep(0.05)
        feed_bytes(master, b"\n")

    result = run_pty_script(public_dns_prompt_script(), feed=feed)
    env.recorder.keys("type hostname; Backspace x20; Enter")
    env.recorder.output(result.visual)
    expect_contains(result.visual, "Public DNS hostname [optional]:")
    expect_contains(result.output, "RESULT=[not configured]")
    # Prompt label must remain intact (not eaten by backspace)
    expect_true(
        "Public DNS hostname [optional]:" in result.visual,
        "DNS prompt label corrupted by Backspace",
        evidence=result.visual,
    )


@scenario(
    "HUX-PTY-002",
    "Existing installer DNS PTY regression script",
    execution_context=ExecutionContext.EXTERNAL_TEST_CLIENT,
    interaction_mode=InteractionMode.PTY,
    layer=Layer.PTY,
    domain="pty",
    tags=("regression",),
)
def hux_pty_002(env: ScenarioEnv) -> None:
    script = env.repo / "tests" / "test-installer-dns-prompt-pty.sh"
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, cwd=str(env.repo))
    env.recorder.output(proc.stdout + proc.stderr)
    expect_true(proc.returncode == 0, "installer DNS PTY regression failed", evidence=proc.stdout + proc.stderr)


@scenario(
    "HUX-REG-001",
    "Manual E2E findings unit suite",
    execution_context=ExecutionContext.EXTERNAL_TEST_CLIENT,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.NORMAL,
    domain="regressions",
    tags=("regression",),
)
def hux_reg_001(env: ScenarioEnv) -> None:
    proc = subprocess.run(
        ["python3", str(env.repo / "tests" / "test-v24-manual-e2e-findings.py")],
        capture_output=True,
        text=True,
        cwd=str(env.repo),
    )
    env.recorder.output(proc.stdout + proc.stderr)
    expect_true(proc.returncode == 0, "manual E2E findings suite failed", evidence=proc.stdout + proc.stderr)


@scenario(
    "HUX-REG-002",
    "SSH username optionality shell regression",
    execution_context=ExecutionContext.EXTERNAL_TEST_CLIENT,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.NORMAL,
    domain="regressions",
    tags=("regression",),
)
def hux_reg_002(env: ScenarioEnv) -> None:
    proc = subprocess.run(
        ["bash", str(env.repo / "tests" / "test-ssh-explicit-user.sh")],
        capture_output=True,
        text=True,
        cwd=str(env.repo),
    )
    env.recorder.output(proc.stdout + proc.stderr)
    expect_true(proc.returncode == 0, "ssh username regression failed", evidence=proc.stdout + proc.stderr)


@scenario(
    "HUX-REG-003",
    "Zero-Touch bootstrap security/UX regression",
    execution_context=ExecutionContext.EXTERNAL_TEST_CLIENT,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.NORMAL,
    domain="regressions",
    tags=("regression", "zero-touch"),
)
def hux_reg_003(env: ScenarioEnv) -> None:
    proc = subprocess.run(
        ["bash", str(env.repo / "tests" / "test-zero-touch-bootstrap.sh")],
        capture_output=True,
        text=True,
        cwd=str(env.repo),
    )
    env.recorder.output(proc.stdout + proc.stderr)
    expect_true(proc.returncode == 0, "zero-touch bootstrap regression failed", evidence=proc.stdout + proc.stderr)


@scenario(
    "HUX-ZT-001",
    "Zero-Touch short command human trust checks",
    execution_context=ExecutionContext.EXTERNAL_TEST_CLIENT,
    interaction_mode=InteractionMode.CONTRACT,
    layer=Layer.NORMAL,
    domain="zero-touch",
    tags=("regression", "zero-touch"),
)
def hux_zt_001(env: ScenarioEnv) -> None:
    import frp_zero_touch as zt

    ticket = "bt1." + ("c" * 16) + "." + ("d" * 64)
    cmd = zt.short_url_command("remote.xdr.ooo", ticket)
    expect_true(len(cmd) < 200, "Zero-Touch public command not reasonably short", evidence=cmd)
    expect_contains(cmd, "remote.xdr.ooo")
    expect_contains(cmd, ticket)
    expect_true("|" in cmd and "sudo bash" in cmd, "expected pipe-to-sudo-bash form")
    # Pinned CA path still verifies fingerprint
    pkg = zt.encode_zero_touch_package(
        "https://203.0.113.10:6099/enroll",
        "a" * 64,
        ticket,
    )
    pinned = zt.pinned_ca_linux_command(
        "https://203.0.113.10:6099/agent/bootstrap-client.sh",
        "https://203.0.113.10:6099/enroll",
        "a" * 64,
        pkg,
    )
    expect_contains(pinned, "--cacert")
    expect_contains(pinned, "a" * 64)
