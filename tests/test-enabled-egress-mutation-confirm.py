#!/usr/bin/env python3
"""Enabled egress profile mutation requires confirmation (section 13)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EnabledEgressMutationConfirmTests(unittest.TestCase):
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
        dest = sbin / "frp-egress"
        dest.write_text((ROOT / "tools/frp-egress").read_text(encoding="utf-8"), encoding="utf-8")
        dest.chmod(0o755)
        self.tool = dest
        (self.root / "etc/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/drlink/config.json").write_text(
            json.dumps({"egress_control_file": "/var/lib/drlink/egress-control.json"}) + "\n",
            encoding="utf-8",
        )
        # Create + complete + enable via library.
        sys.path.insert(0, str(ROOT / "lib"))
        import frp_egress_control as EG  # noqa: E402

        self.EG = EG
        self.cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json"}
        EG.save_egress_state(EG.empty_egress_state(), path=self.root / "var/lib/drlink/egress-control.json")

        def create(state):
            return EG.create_profile(state, "vendor-api", enabled=False)

        pid, _ = EG.mutate_egress_state(create, cfg=self.cfg)
        EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "10.0.0.0/24"), cfg=self.cfg)
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, pid, "api.example.com", 443, protocol="https"),
            cfg=self.cfg,
        )
        EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=self.cfg)
        self.pid = pid

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _run(self, args, *, input_text=None):
        return subprocess.run(
            [sys.executable, "-u", str(self.tool), *args],
            env=self.env,
            text=True,
            capture_output=True,
            input=input_text,
        )

    def test_enabled_noninteractive_without_yes_fails(self):
        proc = self._run(["remove-source", "vendor-api", "10.0.0.0/24"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("ENABLED", (proc.stdout + proc.stderr))
        self.assertIn("--yes", (proc.stdout + proc.stderr))

    def test_enabled_with_yes_succeeds(self):
        proc = self._run(["remove-source", "vendor-api", "10.0.0.0/24", "--yes"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        state = self.EG.load_egress_state(cfg=self.cfg)
        profile = state["egress_profiles"][self.pid]
        self.assertEqual(profile.get("sources") or [], [])

    def test_disabled_mutates_without_yes(self):
        self.EG.mutate_egress_state(
            lambda s: self.EG.set_profile_enabled(s, self.pid, False), cfg=self.cfg
        )
        proc = self._run(["remove-source", "vendor-api", "10.0.0.0/24"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)


if __name__ == "__main__":
    unittest.main()
