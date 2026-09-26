#!/usr/bin/env python3
"""Every NAVIGATION_TREE command leaf must resolve to a non-hidden public command."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CATALOG = load("frp_cli_catalog", "lib/frp_cli_catalog.py")


def _command_target(menu_key, entry_id):
    for entry in CATALOG.NAVIGATION_TREE.get(menu_key, ()):
        if entry and entry[0] == entry_id:
            if len(entry) < 5 or entry[3] != "command":
                raise AssertionError("%s %s is not a command leaf" % (menu_key, entry_id))
            return entry[4]
    raise AssertionError("%s missing %s" % (menu_key, entry_id))


BANNED_TARGETS = {
    "add service",
    "apply",
    "discard",
    "sync",
    "create enrollments",
    "create enrollment",
    "create zero-touch",
    "import egress",
    "diff egress",
    "doctor",
    "show upstream",
    "show info",
    "create backup",
}


class NavigationTargetParityTests(unittest.TestCase):
    def test_command_targets_are_public(self):
        failures = []
        for key, entries in CATALOG.NAVIGATION_TREE.items():
            role = "client"
            if key == "server" or key.startswith("server."):
                role = "server"
            elif key == "both" or key.startswith("both."):
                role = "both"
            for entry in entries:
                if len(entry) < 5:
                    continue
                kind, target = entry[3], entry[4]
                if kind != "command" or not target:
                    continue
                if target in BANNED_TARGETS:
                    failures.append("%s: banned target %r" % (key, target))
                    continue
                toks = str(target).split()
                cmd = CATALOG.find(toks)
                if cmd is None:
                    failures.append("%s: unresolved %r" % (key, target))
                    continue
                if cmd.get("hidden"):
                    failures.append("%s: hidden target %r" % (key, target))
                    continue
                check_role = "server" if role == "both" else role
                if not CATALOG.role_allows(cmd["roles"], check_role):
                    # dual-role menus mix server and client leaves.
                    if not (
                        role == "both"
                        and (
                            CATALOG.role_allows(cmd["roles"], "server")
                            or CATALOG.role_allows(cmd["roles"], "client")
                        )
                    ):
                        failures.append(
                            "%s: role mismatch for %r (role=%s)" % (key, target, role)
                        )
        self.assertFalse(failures, "\n".join(failures))

    def test_system_menu_status_targets(self):
        """Server-capable System menus run canonical system status.

        Client-only System Status stays the role-aware show status summary.
        """
        self.assertEqual(
            _command_target("server.system", "server_sys_status"),
            "system status",
        )
        self.assertEqual(
            _command_target("both.system", "both_sys_status"),
            "system status",
        )
        self.assertEqual(
            _command_target("client.system", "client_sys_status"),
            "show status",
        )
        for menu, entry_id in (
            ("server.system", "server_sys_status"),
            ("both.system", "both_sys_status"),
        ):
            target = _command_target(menu, entry_id)
            cmd = CATALOG.find(target.split())
            self.assertIsNotNone(cmd, target)
            self.assertEqual(tuple(cmd["path"]), ("system", "status"))
            self.assertFalse(cmd.get("hidden"))
            internal = CATALOG.to_internal(target.split())
            self.assertEqual(internal[:1], ["server-status"])

    def test_ai_access_log_in_ai_menu(self):
        found = False
        for entry in CATALOG.NAVIGATION_TREE.get("server.ai", ()):
            if entry[0] == "server_ai_log":
                found = True
                self.assertEqual(entry[3], "command")
                self.assertEqual(entry[4], "show ai-access-log")
        self.assertTrue(found, "AI Access Log leaf missing from AI Access menu")


if __name__ == "__main__":
    unittest.main()
