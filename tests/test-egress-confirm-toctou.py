#!/usr/bin/env python3
"""F03: egress destructive mutations must pin immutable PROFILE/SOURCE/DEST IDs."""
from __future__ import annotations

import json
import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EgressConfirmToctouTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.env = os.environ.copy()
        self.env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.env["PYTHONUNBUFFERED"] = "1"
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        lib = self.root / "usr/local/lib/drlink"
        lib.mkdir(parents=True, exist_ok=True)
        for name in ("frp_egress_control.py", "frp_control_locks.py", "frp_audit.py", "frp_state_paths.py"):
            src = ROOT / "lib" / name
            if src.is_file():
                shutil.copy2(src, lib / name)
        sbin = self.root / "usr/local/sbin"
        sbin.mkdir(parents=True, exist_ok=True)
        tool = sbin / "frp-egress"
        raise unittest.SkipTest("PRIOR_RELEASE_MIGRATION_TEST: tools/frp-egress removed")
        tool.chmod(0o755)
        self.tool = tool
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
        self.state_path = self.root / "var/lib/drlink/egress-control.json"
        EG.save_egress_state(EG.empty_egress_state(), path=self.state_path)

        def create_a(state):
            return EG.create_profile(state, "alpha", enabled=False)

        def create_b(state):
            return EG.create_profile(state, "beta", enabled=False)

        self.pid_a, _ = EG.mutate_egress_state(create_a, cfg=self.cfg)
        self.pid_b, _ = EG.mutate_egress_state(create_b, cfg=self.cfg)
        EG.mutate_egress_state(lambda s: EG.add_source(s, self.pid_a, "10.0.0.0/24"), cfg=self.cfg)
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, self.pid_a, "a.example.com", 443, protocol="https"),
            cfg=self.cfg,
        )
        EG.mutate_egress_state(lambda s: EG.add_source(s, self.pid_b, "10.1.0.0/24"), cfg=self.cfg)
        EG.mutate_egress_state(
            lambda s: EG.add_destination(s, self.pid_b, "b.example.com", 443, protocol="https"),
            cfg=self.cfg,
        )
        EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, self.pid_a, True), cfg=self.cfg)
        EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, self.pid_b, True), cfg=self.cfg)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _run_pty(self, args, mutate_during_confirm):
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            [sys.executable, "-u", str(self.tool), *args],
            stdin=slave,
            stdout=slave,
            stderr=subprocess.PIPE,
            env=self.env,
            close_fds=True,
        )
        os.close(slave)
        buf = b""
        mutated = False
        deadline = time.time() + 8.0
        try:
            while time.time() < deadline:
                if proc.poll() is not None and not select.select([master], [], [], 0.05)[0]:
                    break
                ready, _, _ = select.select([master], [], [], 0.1)
                if not ready:
                    continue
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                text = buf.decode("utf-8", errors="replace")
                if (not mutated) and ("Continue?" in text or "Profile ID" in text):
                    mutate_during_confirm()
                    mutated = True
                    time.sleep(0.05)
                    os.write(master, b"y\n")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
                self.fail("timed out: %r" % buf.decode("utf-8", errors="replace"))
        finally:
            try:
                os.close(master)
            except OSError:
                pass
        err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        out = buf.decode("utf-8", errors="replace")
        self.assertTrue(mutated, msg="confirmation never reached: out=%r err=%r" % (out, err))
        return proc.returncode, out, err

    def test_rename_name_reuse_during_delete_confirm(self):
        def swap():
            def mut(state):
                state["egress_profiles"][self.pid_a]["name"] = "alpha-old"
                state["egress_profiles"][self.pid_b]["name"] = "alpha"
                return None

            self.EG.mutate_egress_state(mut, cfg=self.cfg)

        rc, out, err = self._run_pty(["delete", "alpha"], swap)
        combined = out + err
        state = self.EG.load_egress_state(cfg=self.cfg)
        self.assertNotIn(self.pid_a, state["egress_profiles"])
        self.assertIn(self.pid_b, state["egress_profiles"])
        self.assertEqual(state["egress_profiles"][self.pid_b]["name"], "alpha")
        self.assertIn(self.pid_a, combined)
        self.assertEqual(rc, 0, msg=combined)

    def test_target_deleted_during_confirm(self):
        def delete_a():
            self.EG.mutate_egress_state(lambda s: self.EG.delete_profile(s, self.pid_a), cfg=self.cfg)

        rc, out, err = self._run_pty(["delete", "alpha"], delete_a)
        combined = out + err
        self.assertNotEqual(rc, 0)
        self.assertIn("Target changed while waiting for confirmation", combined)
        state = self.EG.load_egress_state(cfg=self.cfg)
        self.assertIn(self.pid_b, state["egress_profiles"])

    def test_remove_source_pins_source_id(self):
        state = self.EG.load_egress_state(cfg=self.cfg)
        src_id = state["egress_profiles"][self.pid_a]["sources"][0]["id"]

        def replace_source():
            def mut(s):
                self.EG.remove_source(s, self.pid_a, src_id)
                self.EG.add_source(s, self.pid_a, "10.9.9.0/24", name="moved")
                return None

            self.EG.mutate_egress_state(mut, cfg=self.cfg)

        rc, out, err = self._run_pty(["remove-source", "alpha", "10.0.0.0/24"], replace_source)
        combined = out + err
        self.assertNotEqual(rc, 0)
        self.assertIn("Target changed while waiting for confirmation", combined)


if __name__ == "__main__":
    unittest.main()
