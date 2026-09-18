#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "automation" / "governance" / "audit_architecture.py"

class GovernanceTests(unittest.TestCase):
    def test_blocking_audit_passes_current_repository(self):
        proc = subprocess.run(
            ["python3", str(AUDIT), "--blocking-only"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_full_audit_detects_known_documentation_drift(self):
        proc = subprocess.run(
            ["python3", str(AUDIT)],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("SUPERSEDED_PUBLIC_TERM", proc.stdout)
        self.assertIn("README.md", proc.stdout)
        self.assertIn("docs/CONTROL_PLANE_ARCHITECTURE.md", proc.stdout)

    def test_tela_config_contains_no_credentials(self):
        data = json.loads(
            (ROOT / "automation" / "tela_sync" / "config.json").read_text(encoding="utf-8")
        )
        keys = {key.lower() for key in data}
        for forbidden in ("token", "secret", "password", "credential", "api_key"):
            self.assertNotIn(forbidden, keys)

    def test_lint_fetches_release_history(self):
        text = (ROOT / ".github" / "workflows" / "lint.yml").read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", text)

    def test_repository_security_dry_run(self):
        proc = subprocess.run(
            ["bash", "scripts/configure-repository-security.sh", "--dry-run"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for token in ("secret_scanning=enabled", "secret_scanning_push_protection=enabled", "dependabot_security_updates=enabled"):
            self.assertIn(token, proc.stdout)

    def test_branch_protection_dry_run_contains_new_required_contexts(self):
        proc = subprocess.run(
            ["bash", "scripts/configure-main-protection.sh", "--dry-run"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for context in ("openspec", "governance", "security"):
            self.assertIn(f'"{context}"', proc.stdout)
        self.assertIn("BRANCH_PROTECTION_MODE=DRY_RUN", proc.stdout)

if __name__ == "__main__":
    unittest.main()
