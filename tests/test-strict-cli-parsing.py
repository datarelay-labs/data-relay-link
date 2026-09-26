#!/usr/bin/env python3
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import frp_cli_catalog as cat  # noqa: E402


class StrictCliParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = cat

    def test_system_version_rejects_extra(self):
        err = self.cat.strict_error(["system", "version", "abc"])
        self.assertIsNotNone(err)
        self.assertIn("unexpected argument", err)

    def test_show_status_rejects_extra(self):
        err = self.cat.strict_error(["show", "status", "extra"])
        self.assertIsNotNone(err)
        self.assertIn("unexpected argument", err)

    def test_status_alone_ok(self):
        self.assertIsNone(self.cat.strict_error(["show", "status"]))

    def test_approve_oauth_optional_identity_arity(self):
        one = ["system", "credential", "approve-oauth", "oap_fixture"]
        two = one + ["plugin-qual"]
        three = two + ["extra"]
        self.assertIsNone(self.cat.strict_error(one))
        self.assertIsNone(self.cat.strict_error(two))
        err = self.cat.strict_error(three)
        self.assertIsNotNone(err)
        self.assertIn("unexpected argument: extra", err)
        cmd = self.cat.find(one)
        self.assertEqual(
            self.cat.usage_line(cmd),
            "system credential approve-oauth <PENDING-ID> [AI-IDENTITY]",
        )

    def test_guided_menu_categories(self):
        text = self.cat.render_guided_menu("server")
        self.assertIn("Managed Hosts", text)
        self.assertIn("Network Objects", text)
        self.assertIn("Service Objects", text)
        self.assertIn("Remote Access", text)
        self.assertIn("Internet Access", text)
        self.assertIn("AI Access", text)
        self.assertIn("System", text)
        self.assertNotIn("Controlled Egress", text)


if __name__ == "__main__":
    unittest.main()
