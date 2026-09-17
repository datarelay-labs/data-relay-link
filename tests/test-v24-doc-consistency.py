#!/usr/bin/env python3
"""Prevent CLI/AI normative docs from drifting away from the v2.4 FINAL Master."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MASTER = ROOT / "docs" / "DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md"
IA = ROOT / "docs" / "Data Relay Link CLI Information Architecture.md"
PRODUCT = ROOT / "docs" / "PRODUCT_MASTER.md"

REQUIRED_SERVER_MENU = (
    "Managed Hosts",
    "Network Objects",
    "Service Objects",
    "Remote Access",
    "Internet Access",
    "AI Access",
    "System",
)

FORBIDDEN_AS_NORMATIVE_ROOT = (
    "1) Clients",
    "├── 1. Clients",
    "## Canonical Server menu\n\n```text\nClients",
)


class DocConsistencyV24(unittest.TestCase):
    def test_master_exists(self):
        self.assertTrue(MASTER.is_file())

    def test_ia_defers_to_master(self):
        text = IA.read_text(encoding="utf-8")
        self.assertIn("DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md", text)
        self.assertIn("the Master wins", text)
        for item in REQUIRED_SERVER_MENU:
            self.assertIn(item, text)
        for bad in FORBIDDEN_AS_NORMATIVE_ROOT:
            self.assertNotIn(bad, text)
        self.assertIn("AI Identity", text)
        self.assertIn("ConfigurationBundle", text)
        self.assertIn("Cancel produces", text)

    def test_product_master_cli_aligned(self):
        text = PRODUCT.read_text(encoding="utf-8")
        self.assertIn("DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md", text)
        for item in REQUIRED_SERVER_MENU:
            self.assertIn(item, text)
        self.assertIn("Fixed TCP is a Service Object subtype", text)
        self.assertIn("UDP Remote Service is not supported", text)
        self.assertIn("AI Identity", text)


if __name__ == "__main__":
    unittest.main()
