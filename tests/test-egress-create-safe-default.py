#!/usr/bin/env python3
"""Regression: egress create is DISABLED by default (AUDIT-008)."""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_eg():
    path = ROOT / "lib" / "frp_egress_control.py"
    spec = importlib.util.spec_from_file_location("frp_egress_control", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EG = load_eg()


class EgressCreateSafeDefaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.path = self.root / "var/lib/drlink/egress-control.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        EG.save_egress_state(EG.empty_egress_state(), path=self.path)
        self.cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json"}

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def test_create_profile_requires_enabled_argument(self):
        state = EG.empty_egress_state()
        with self.assertRaises(TypeError):
            EG.create_profile(state, "vendor")  # type: ignore[call-arg]

    def test_backend_disabled_when_enabled_false(self):
        def mut(state):
            return EG.create_profile(state, "vendor", enabled=False)

        pid, rec = EG.mutate_egress_state(mut, cfg=self.cfg)
        self.assertFalse(rec["enabled"])
        EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "203.0.113.10/32"), cfg=self.cfg)
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, pid, "api.example.com", 443, protocol="https"), cfg=self.cfg
        )
        state = EG.load_egress_state(cfg=self.cfg)
        decision = EG.authorize_request(
            state, source_ip="203.0.113.10", hostname="api.example.com", port=443, protocol="https"
        )
        self.assertEqual(decision["decision"], EG.DECISION_DENY)

    def test_cli_create_defaults_disabled(self):
        import subprocess
        import sys

        tool = ROOT / "tools" / "frp-egress"
        env = os.environ.copy()
        env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        libdir = self.root / "usr/local/lib/drlink"
        libdir.mkdir(parents=True, exist_ok=True)
        (libdir / "frp_egress_control.py").write_text(
            (ROOT / "lib/frp_egress_control.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (libdir / "frp_control_locks.py").write_text(
            (ROOT / "lib/frp_control_locks.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        sbin = self.root / "usr/local/sbin"
        sbin.mkdir(parents=True, exist_ok=True)
        dest = sbin / "frp-egress"
        dest.write_text(tool.read_text(encoding="utf-8"), encoding="utf-8")
        dest.chmod(0o755)
        (self.root / "etc/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/drlink/config.json").write_text(
            '{"egress_control_file":"/var/lib/drlink/egress-control.json"}\n',
            encoding="utf-8",
        )
        out = subprocess.check_output(
            [sys.executable, str(dest), "create", "safe-default"],
            env=env,
            text=True,
        )
        self.assertIn("Enabled  : no", out)
        state = EG.load_egress_state(cfg=self.cfg)
        profiles = list((state.get("egress_profiles") or {}).values())
        self.assertEqual(len(profiles), 1)
        self.assertFalse(profiles[0]["enabled"])


if __name__ == "__main__":
    unittest.main()
