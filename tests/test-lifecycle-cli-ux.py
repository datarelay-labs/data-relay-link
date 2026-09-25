#!/usr/bin/env python3
"""Focused public lifecycle CLI / navigation / leak checks for v2.4.0 closure."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import frp_cli_catalog as catalog  # noqa: E402
import frp_ctl_grammar as grammar  # noqa: E402


class LifecycleCliUx(unittest.TestCase):
    def test_client_system_menu_lifecycle_entries(self):
        agent_labels = [row[1] for row in catalog.navigation_entries("client.agent")]
        for need in ("Pause", "Resume", "Restart", "Autostart"):
            self.assertIn(need, agent_labels)
        system_labels = [row[1] for row in catalog.navigation_entries("client.system")]
        self.assertIn("Uninstall Data Relay Link", system_labels)

    def test_server_system_menu_uninstall(self):
        labels = [row[1] for row in catalog.navigation_entries("server.system")]
        self.assertIn("Uninstall Data Relay Link", labels)

    def test_both_system_menu_has_client_lifecycle_and_uninstall(self):
        labels = [row[1] for row in catalog.navigation_entries("both.system")]
        for need in ("Pause Agent", "Resume Agent", "Uninstall Data Relay Link"):
            self.assertIn(need, labels)

    def test_client_lifecycle_match_actions(self):
        cases = {
            ("system", "pause"): "client_pause",
            ("system", "resume"): "client_resume",
            ("system", "restart"): "client_restart",
            ("system", "autostart"): "client_autostart",
            ("system", "autostart", "enable"): "client_autostart",
            ("system", "autostart", "disable"): "client_autostart",
            ("system", "uninstall"): "system_uninstall",
        }
        for toks, action in cases.items():
            result = grammar.match(list(toks), "client")
            self.assertEqual(result.get("status"), "ok", toks)
            self.assertEqual(result.get("action"), action, toks)

    def test_server_rejects_client_only_lifecycle(self):
        for toks in (
            ["system", "pause"],
            ["system", "resume"],
            ["system", "restart"],
            ["system", "autostart"],
        ):
            result = grammar.match(toks, "server")
            self.assertEqual(result.get("status"), "role", toks)

    def test_server_uninstall_available(self):
        result = grammar.match(["system", "uninstall"], "server")
        self.assertEqual(result.get("action"), "system_uninstall")

    def test_uninstall_help_is_not_destructive(self):
        for flag in ("--help", "-h"):
            result = grammar.match(["system", "uninstall", flag], "server")
            self.assertEqual(result.get("action"), "help", result)
            self.assertEqual(result.get("passthrough"), ["system", "uninstall"])
            client = grammar.match(["system", "uninstall", flag], "client")
            self.assertEqual(client.get("action"), "help", client)

    def test_hidden_legacy_start_stop_still_resolve(self):
        self.assertEqual(grammar.match(["stop"], "client").get("action"), "client_pause")
        self.assertEqual(grammar.match(["start"], "client").get("action"), "client_resume")

    def test_help_system_lists_lifecycle(self):
        text = catalog.domain_help("system", "client") or ""
        for needle in (
            "system pause",
            "system resume",
            "system restart",
            "system autostart",
            "system uninstall",
            "system update product",
        ):
            self.assertIn(needle, text)
        self.assertNotIn("sudo drlink manage", text)
        self.assertNotIn("frp-client set-service", text)

    def test_root_question_not_lifecycle_dump(self):
        text = grammar.context_help([], "client") or ""
        self.assertNotIn("system pause", text)
        self.assertTrue("show" in text or "System" in text or "system" in text.lower())

    def test_tab_children_include_lifecycle(self):
        children = [name for name, _ in catalog.subcommands("system", "client")]
        for need in ("pause", "resume", "restart", "autostart", "uninstall"):
            self.assertIn(need, children)

    def test_no_stale_update_guidance_in_install_client(self):
        text = (ROOT / "install-client.sh").read_text(encoding="utf-8")
        self.assertNotIn("sudo drlink update product", text)
        self.assertIn("sudo drlink system update product", text)
        self.assertNotIn("sudo drlink manage", text)
        self.assertNotIn("partial FRP client", text)

    def test_macos_doc_uses_system_uninstall(self):
        text = (ROOT / "docs/MACOS_CLIENT.md").read_text(encoding="utf-8")
        self.assertIn("sudo drlink system uninstall", text)
        self.assertNotIn("sudo drlink uninstall", text)
        self.assertNotIn("sudo frp-client", text)

    def test_windows_uninstall_guidance_canonical(self):
        text = (ROOT / "windows/tools/FrpClient.ps1").read_text(encoding="utf-8")
        self.assertIn("unset managed-host <HOST>", text)
        self.assertNotIn("unset client <CLIENT>", text)
        self.assertNotIn("drlink client release", text)

    def test_client_uninstall_message_product_identity(self):
        text = (ROOT / "uninstall-client.sh").read_text(encoding="utf-8")
        self.assertIn("Data Relay Link client removed locally", text)
        self.assertNotIn("FRP client removed locally", text)
        self.assertIn("unset managed-host <HOST>", text)
        self.assertNotIn("unset client <CLIENT>", text)

    def test_lifecycle_helpers_under_test_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["FRP_CLIENT_TEST_ROOT"] = tmp
            env["FRP_SKIP_SYSTEMD"] = "1"
            script = r"""
set -euo pipefail
. lib/frp-common.sh
. lib/frp-client-common.sh
export FRP_CLIENT_TEST_RUNTIME=active
export FRP_CLIENT_TEST_AUTOSTART=enabled
frp_client_pause_cmd
frp_client_pause_cmd
frp_client_resume_cmd
frp_client_restart_runtime_cmd
frp_client_autostart_cmd status
frp_client_autostart_cmd enable
frp_client_autostart_cmd disable
"""
            proc = subprocess.run(
                ["bash", "-c", script],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = proc.stdout
            self.assertIn("Client paused.", out)
            self.assertIn("Client is already paused.", out)
            self.assertIn("Client resumed.", out)
            self.assertIn("Client restarted.", out)
            self.assertIn("Autostart :", out)
            self.assertNotIn("frp-client set-service", out)
            self.assertNotIn("systemctl", out)


if __name__ == "__main__":
    unittest.main()
