#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RENDER = ROOT / "automation" / "tela_sync" / "render_canonical.py"
CANONICAL = ROOT / "knowledge" / "CANONICAL_SOURCE_OF_TRUTH.md"


class TelaKnowledgeSyncTests(unittest.TestCase):
    def test_checked_in_projection_is_current(self):
        proc = subprocess.run(
            ["python3", str(RENDER), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_projection_contains_current_contract_and_decisions(self):
        text = CANONICAL.read_text(encoding="utf-8")
        for token in (
            "### fixed-tcp",
            "### remote-service",
            "Fixed TCP remains a Service Object subtype",
            "ConfigurationBundle atomicity is context-local",
            "Reachability is not configuration validity",
        ):
            self.assertIn(token, text)
    def test_product_projection_excludes_tooling_decisions(self):
        text = CANONICAL.read_text(encoding="utf-8")
        self.assertNotIn("Decision Event is the automation boundary", text)
        self.assertNotIn("Accepted-only gate", text)

    def test_renderer_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            one = Path(tmp) / "one.md"
            two = Path(tmp) / "two.md"
            for output in (one, two):
                proc = subprocess.run(
                    ["python3", str(RENDER), "--output", str(output)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(
                one.read_bytes(),
                two.read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
