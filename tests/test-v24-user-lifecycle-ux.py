#!/usr/bin/env python3
"""Packet 5: User lifecycle UX / terminology / coverage.

Public Zero-Touch and policy display wording, AI Access help/workflows, and
MCP user-facing nouns must use frozen v2.4 terms (Managed Host / AI Identity)
without erasing legitimate compatibility aliases.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
import drlink_control_cli as cli
import drlink_v24 as v24
import frp_cli_catalog as catalog


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


class UserLifecycleUxCoverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-p5-ux-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _dispatch(self, args):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.dispatch(list(args), root=self.tmp, plane=self.plane)
        return rc, out.getvalue(), err.getvalue()

    def test_show_remote_access_uses_unmatched_not_effective(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-ssh",
            mode="blacklist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        rc, out, err = self._dispatch(["show", "remote-access"])
        self.assertEqual(rc, 0, err or out)
        self.assertIn("Unmatched   :", out)
        self.assertNotIn("Effective   :", out)
        self.assertIn("BLACKLIST", out)

    def test_show_ai_access_uses_unmatched_not_effective(self):
        self.plane.set_ai_principal("bot", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'bot'"
        )
        self.plane.conn.commit()
        v24.set_network_object(self.plane, "host", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_permission_object(self.plane, "exec", permissions=["command-exec"], oneshot=True)
        v24.set_ai_access_rule(
            self.plane,
            "block",
            mode="blacklist",
            source="bot",
            destination="host",
            permission="exec",
            enabled=True,
            oneshot=True,
        )
        rc, out, err = self._dispatch(["show", "ai-access"])
        self.assertEqual(rc, 0, err or out)
        self.assertIn("Unmatched   :", out)
        self.assertNotIn("Effective   :", out)

    def test_ai_access_help_has_lifecycle_and_v24_nouns(self):
        text = catalog.domain_help("ai-access", "server")
        self.assertIn("Lifecycle:", text)
        self.assertIn("AI Identity", text)
        self.assertIn("Permission Object", text)
        self.assertIn("set ai-access", text)
        self.assertIn("test ai-access", text)
        self.assertNotIn("AI Principal", text)
        self.assertNotIn("Managed Endpoint", text)

    def test_workflow_help_includes_ai_access_lifecycle(self):
        text = catalog.workflow_help("server")
        self.assertIn("AI Access lifecycle", text)
        self.assertIn("set ai-identity", text)
        self.assertIn("Connect a Managed Host", text)
        self.assertNotIn("Connect a new client", text)
        self.assertNotIn("AI Principal", text)

    def test_mcp_bridge_user_facing_terms(self):
        import drlink_mcp_bridge as mcp

        # TOOL_DEFS entries are (name, title, description, props, annotations).
        blob = " ".join(desc for _n, _t, desc, _p, _a in mcp.TOOL_DEFS)
        self.assertIn("Managed Host", blob)
        self.assertNotIn("Managed Endpoint", blob)
        self.assertNotIn("principal may target", blob)

    def test_zero_touch_tools_use_managed_host_wording(self):
        frpctl = (ROOT / "tools" / "frpctl").read_text(encoding="utf-8")
        create = (ROOT / "tools" / "frp-create-client").read_text(encoding="utf-8")
        self.assertIn('echo "Connect a Managed Host"', frpctl)
        self.assertIn('echo "Managed Host details"', frpctl)
        self.assertIn("Managed Host name:", frpctl)
        self.assertNotIn('echo "Connect a new client"', frpctl)
        self.assertNotIn('echo "Client details"', frpctl)
        self.assertIn("Managed Host details", create)
        self.assertIn("Managed Host name:", create)
        self.assertNotIn("Client details", create)


if __name__ == "__main__":
    unittest.main()
