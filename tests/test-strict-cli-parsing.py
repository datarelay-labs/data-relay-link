#!/usr/bin/env python3
"""CLI-AUDIT-001: canonical no-arg commands reject trailing tokens."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_catalog():
    path = ROOT / "lib" / "frp_cli_catalog.py"
    spec = importlib.util.spec_from_file_location("frp_cli_catalog", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class StrictCliParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = load_catalog()

    def test_status_rejects_garbage(self):
        err = self.cat.strict_error(["status", "garbage"])
        self.assertIsNotNone(err)
        self.assertIn("unexpected argument", err)
        self.assertIn("garbage", err)

    def test_version_rejects_extra(self):
        err = self.cat.strict_error(["version", "abc"])
        self.assertIsNotNone(err)
        self.assertIn("unexpected argument", err)

    def test_egress_enable_rejects_extra(self):
        err = self.cat.strict_error(["egress", "enable", "p", "extra"])
        self.assertIsNotNone(err)
        self.assertIn("unexpected argument", err)

    def test_status_alone_ok(self):
        self.assertIsNone(self.cat.strict_error(["status"]))

    def test_guided_menu_categories(self):
        text = self.cat.render_guided_menu("server")
        self.assertIn("Remote Access", text)
        self.assertIn("Controlled Egress", text)
        self.assertIn("Organize", text)
        self.assertIn("Operate", text)


if __name__ == "__main__":
    unittest.main()
