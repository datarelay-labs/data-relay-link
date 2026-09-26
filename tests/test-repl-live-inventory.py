#!/usr/bin/env python3
"""Prove LineEditor passes live inventory into completion_candidates."""
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


REPL = load("frp_ctl_repl", "lib/frp_ctl_repl.py")


class ReplLiveInventoryTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "role": "server",
            "names": ["24cd7856"],
            "clients": [{"id": "24cd7856", "label": "a", "hostname": "h"}],
            "services": {"24cd7856": ["ssh"]},
            "local_services": [],
            "groups": ["edge"],
            "egress": ["vendor-api"],
            "access_lists": ["office"],
            "service_profiles": ["office-ssh"],
            "inventory_warning": False,
        }
        self.editor = REPL.LineEditor(self.payload)

    def _cands(self, line: str):
        trailing = bool(line) and line[-1:] in " \t"
        return self.editor.grammar.completion_candidates(
            line,
            self.editor.role,
            self.editor.names,
            self.editor.services,
            self.editor.local_services,
            trailing=trailing,
            **self.editor._completion_kwargs(),
        )

    def test_editor_retains_inventory_fields(self):
        self.assertEqual(self.editor.egress_profiles, ["vendor-api"])
        self.assertEqual(self.editor.access_lists, ["office"])
        self.assertEqual(self.editor.service_profiles, ["office-ssh"])

    def test_tab_uses_live_inventory(self):
        self.assertIn("24cd7856", self._cands("show managed-host "))
        self.assertIn("24cd7856", self._cands("unset managed-host "))

    def test_mutation_refresh_helper_updates_all_fields(self):
        # Simulate a refreshed payload after create/delete.
        refreshed = dict(self.payload)
        refreshed["names"] = ["24cd7856", "new-host"]
        refreshed["clients"] = list(self.payload["clients"]) + [
            {"id": "new-host", "label": "b", "hostname": "h2"}
        ]
        refreshed["egress"] = ["vendor-api", "new-profile"]
        refreshed["access_lists"] = ["office", "remote"]
        refreshed["service_profiles"] = ["office-ssh", "office-http"]
        self.editor.payload = refreshed
        self.editor.role = refreshed["role"]
        self.editor.names = refreshed["names"]
        self.editor.clients = refreshed["clients"]
        self.editor.services = refreshed["services"]
        self.editor.local_services = refreshed["local_services"]
        self.editor.groups = refreshed["groups"]
        self.editor.egress_profiles = refreshed["egress"]
        self.editor.access_lists = refreshed["access_lists"]
        self.editor.service_profiles = refreshed["service_profiles"]
        self.assertIn("new-host", self._cands("show managed-host "))
        # Delete path
        self.editor.names = ["24cd7856"]
        self.assertNotIn("new-host", self._cands("show managed-host "))

    def test_should_refresh_current_grammar(self):
        self.assertTrue(REPL._should_refresh_inventory(["set", "internet-access", "x"]))
        self.assertTrue(REPL._should_refresh_inventory(["unset", "remote-access", "office"]))
        self.assertTrue(REPL._should_refresh_inventory(["system", "services", "apply"]))
        self.assertFalse(REPL._should_refresh_inventory(["show", "internet-access"]))
        self.assertFalse(REPL._should_refresh_inventory(["test", "internet-access", "1.1.1.1", "a", "443"]))
        self.assertFalse(REPL._should_refresh_inventory(["help", "commands"]))


if __name__ == "__main__":
    unittest.main()
