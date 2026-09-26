#!/usr/bin/env python3
"""Unit tests for Human UX framework helpers (not full scenarios)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[0]  # tests/
REPO = Path(__file__).resolve().parents[1]  # repo root
HUX = ROOT / "human-ux-e2e"
sys.path.insert(0, str(REPO / "lib"))
sys.path.insert(0, str(HUX))

from framework.command_validator import classify_line, validate_drlink_command  # noqa: E402
from framework.extractors import extract_drlink_commands, extract_ssh_hints  # noqa: E402
from framework.state_machine import WorkflowState, WorkflowStateMachine, role_matrix  # noqa: E402
from framework.transcript import sanitize  # noqa: E402
from framework.types import ExecutionContext  # noqa: E402


class ExtractorTests(unittest.TestCase):
    def test_ssh_hint(self):
        hints = extract_ssh_hints("ssh -p 42022 user@remote.xdr.ooo")
        self.assertEqual(hints[0].port, 42022)
        self.assertEqual(hints[0].host, "remote.xdr.ooo")

    def test_drlink_commands(self):
        text = "Next:\n  sudo drlink system synchronize\nshow remote-services\n"
        cmds = extract_drlink_commands(text)
        self.assertIn("system synchronize", cmds)
        self.assertIn("show remote-services", cmds)


class CommandValidatorTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_line("sudo drlink show status").kind.value, "DRLINK_COMMAND")
        self.assertEqual(classify_line("https://remote.xdr.ooo/i/x").kind.value, "URL")
        self.assertEqual(classify_line("ssh -p 22 u@h").kind.value, "CONNECTION_EXAMPLE")

    def test_validate_synchronize(self):
        findings = validate_drlink_command(
            "sudo drlink system synchronize", execution_context="AGENT_HOST"
        )
        self.assertEqual(findings, [])


class StateMachineTests(unittest.TestCase):
    def test_forbidden_on_agent(self):
        sm = WorkflowStateMachine(state=WorkflowState.REMOTE_SERVICE_HEALTHY)
        err = sm.assert_command_legality("set remote-access office", ExecutionContext.AGENT_HOST)
        self.assertIsNotNone(err)

    def test_role_matrix(self):
        m = role_matrix()
        self.assertEqual(m["remote-service"]["owner"], "AGENT_HOST")
        self.assertEqual(m["remote-access"]["owner"], "DRLINK_SERVER")


class SanitizeTests(unittest.TestCase):
    def test_ticket_redacted(self):
        ticket = "bt1." + ("a" * 16) + "." + ("b" * 64)
        out = sanitize("cmd " + ticket)
        self.assertNotIn(ticket, out)
        self.assertIn("bt1.<REDACTED>", out)

    def test_compact_credential_redacted_in_context(self):
        compact = "AbcdEFghij1234_-KLMNOP"
        url_out = sanitize("curl -fsSL https://remote.xdr.ooo/i/%s|sudo bash" % compact)
        env_out = sanitize("$env:FRP_BOOTSTRAP_TICKET = '%s'" % compact)
        self.assertNotIn(compact, url_out)
        self.assertNotIn(compact, env_out)
        self.assertIn("/i/<REDACTED>", url_out)
        self.assertIn("FRP_BOOTSTRAP_TICKET", env_out)


if __name__ == "__main__":
    unittest.main()
