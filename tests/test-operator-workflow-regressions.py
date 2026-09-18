#!/usr/bin/env python3
"""Focused operator workflow regressions (S02, F10, enrollment TTL)."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_loader(
        name, loader=importlib.machinery.SourceFileLoader(name, str(path))
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


GRAMMAR = load_module("frp_ctl_grammar", "lib/frp_ctl_grammar.py")
CREATE = load_module("frp_create_client", "tools/frp-create-client")


class EgressStagedWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.env = os.environ.copy()
        self.env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)

        lib = self.root / "usr/local/lib/drlink"
        lib.mkdir(parents=True, exist_ok=True)
        for name in ("frp_egress_control.py", "frp_control_locks.py", "frp_audit.py"):
            shutil.copy2(ROOT / "lib" / name, lib / name)

        sbin = self.root / "usr/local/sbin"
        sbin.mkdir(parents=True, exist_ok=True)
        self.tool = sbin / "frp-egress"
        raise unittest.SkipTest("PRIOR_RELEASE_MIGRATION_TEST: tools/frp-egress removed")
        self.tool.chmod(0o755)

        (self.root / "etc/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/drlink/config.json").write_text(
            json.dumps({"egress_control_file": "/var/lib/drlink/egress-control.json"}) + "\n",
            encoding="utf-8",
        )

        sys.path.insert(0, str(ROOT / "lib"))
        import frp_egress_control as EG  # noqa: E402

        self.EG = EG
        self.cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json"}
        EG.save_egress_state(EG.empty_egress_state(), path=self.root / "var/lib/drlink/egress-control.json")

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _run(self, args):
        return subprocess.run(
            [sys.executable, "-u", str(self.tool), *args],
            env=self.env,
            text=True,
            capture_output=True,
        )

    def test_s02_staged_workflow_preview_while_disabled_then_enable(self):
        """S02: create disabled, stage rules, preview ALLOW, then enable."""
        proc = self._run(["create", "vendor-api", "--description", "Vendor API"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("Created Internet Access profile: vendor-api", proc.stdout)
        self.assertIn("Status         : Disabled", proc.stdout)

        proc = self._run(["add-source", "vendor-api", "203.0.113.10/32"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)

        proc = self._run(
            [
                "add-destination",
                "vendor-api",
                "security.ubuntu.com",
                "443",
                "--protocol",
                "https",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)

        proc = self._run(
            [
                "test",
                "203.0.113.10",
                "security.ubuntu.com",
                "443",
                "--protocol",
                "https",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = proc.stdout
        self.assertIn("Internet Access Check", out)
        self.assertIn("Profile state : Disabled", out)
        self.assertIn("Policy preview : ALLOW", out)
        self.assertIn("Current state  : BLOCKED", out)
        self.assertNotRegex(out, r"(?m)^Decision\s*:\s*ALLOW\s*$")
        self.assertIn("Live connection performed: NO", out)

        proc = self._run(["show", "vendor-api"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("Enabled       : no", proc.stdout)

        proc = self._run(["enable", "vendor-api"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("Internet Access profile enabled", proc.stdout)
        self.assertNotIn("egress profile", proc.stdout.lower())

        proc = self._run(
            [
                "test",
                "203.0.113.10",
                "security.ubuntu.com",
                "443",
                "--protocol",
                "https",
            ]
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        enabled_out = proc.stdout
        self.assertIn("Profile state : Enabled", enabled_out)
        self.assertIn("Decision    : ALLOW", enabled_out)

        proc = self._run(["show", "vendor-api"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("Enabled       : yes", proc.stdout)

        state = self.EG.load_egress_state(cfg=self.cfg)
        profile = next(iter((state.get("egress_profiles") or {}).values()))
        self.assertTrue(profile.get("enabled"))


class GrammarEmptyDescriptionTests(unittest.TestCase):
    def test_f10_empty_description_token_tokenize_and_match(self):
        line = 'group set edge description ""'
        tokens = GRAMMAR.tokenize(line)
        self.assertEqual(tokens, ["group", "set", "edge", "description", ""])

        result = GRAMMAR.match(tokens, "server")
        self.assertEqual(result.get("status"), "ok")
        self.assertEqual(result.get("action"), "set_group")
        self.assertEqual(result.get("group"), "edge")
        self.assertEqual(result.get("property"), "description")
        self.assertEqual(result.get("value"), "")


class EnrollmentTtlWorkflowTests(unittest.TestCase):
    def test_enrollment_ttl_parses_4h(self):
        self.assertEqual(CREATE.parse_enrollment_ttl("4h"), 4 * 3600)


if __name__ == "__main__":
    unittest.main()
