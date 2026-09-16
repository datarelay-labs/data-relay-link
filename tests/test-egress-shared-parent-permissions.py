#!/usr/bin/env python3
"""Cross-feature: access/profiles/audit writers must not chmod shared parents.

Shared parents (``/var/lib/drlink``, ``/var/log/drlink``) carry egress traverse
ACL/group+x. Writers must not reset them to 0700 after mutations.
"""
from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ACL = _load("frp_access_control_xfeat", "lib/frp_access_control.py")
PROF = _load("frp_service_profiles_xfeat", "lib/frp_service_profiles.py")
AUDIT = _load("frp_audit_xfeat", "lib/frp_audit.py")


class SharedParentPermissionPreservation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-xfeat-perm-")
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        os.environ["FRP_SERVER_TEST_ROOT"] = str(self.root)
        self.var_lib = self.root / "var/lib/drlink"
        self.var_log = self.root / "var/log/drlink"
        self.var_lib.mkdir(parents=True)
        self.var_log.mkdir(parents=True)
        (self.var_log / "egress").mkdir(parents=True)
        (self.var_log / "access").mkdir(parents=True)
        # Simulate egress traverse grant via mode 0710 (group+x) on parents.
        os.chmod(self.var_lib, 0o710)
        os.chmod(self.var_log, 0o710)
        self.lib_mode = stat.S_IMODE(self.var_lib.stat().st_mode)
        self.log_mode = stat.S_IMODE(self.var_log.stat().st_mode)

    def tearDown(self):
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
        os.environ.pop("FRP_SERVER_TEST_ROOT", None)
        os.environ.pop("FRP_AUDIT_LOG", None)
        self.tmp.cleanup()

    def _assert_parents_unchanged(self):
        self.assertEqual(
            stat.S_IMODE(self.var_lib.stat().st_mode),
            self.lib_mode,
            "ACCESS/service_profiles must not chmod /var/lib/drlink parent",
        )
        self.assertEqual(
            stat.S_IMODE(self.var_log.stat().st_mode),
            self.log_mode,
            "writers must not chmod /var/log/drlink parent",
        )
        self.assertNotEqual(
            self.lib_mode,
            0o700,
            "fixture parent should not start as 0700 (would hide regression)",
        )

    def test_ACCESS_MUTATION_PRESERVES_EGRESS_STATE_PERMISSIONS(self):
        path = self.var_lib / "access-control.json"
        state = ACL.empty_access_state()
        ACL.save_access_state(state, path=path)
        self._assert_parents_unchanged()
        # Second mutation (inode replace) must still leave parent alone.
        state = ACL.load_access_state(path=path)
        ACL.save_access_state(state, path=path)
        self._assert_parents_unchanged()

    def test_SERVICE_PROFILE_MUTATION_PRESERVES_EGRESS_STATE_PERMISSIONS(self):
        path = self.var_lib / "service-profiles.json"
        state = PROF.empty_profiles_state()
        PROF.save_profiles_state(state, path=path)
        self._assert_parents_unchanged()
        state = PROF.load_profiles_state(path=path)
        PROF.save_profiles_state(state, path=path)
        self._assert_parents_unchanged()

    def test_AUDIT_LOG_CREATE_PRESERVES_EGRESS_LOG_PERMISSIONS(self):
        os.environ["FRP_AUDIT_LOG"] = "/var/log/drlink/audit.jsonl"
        ok = AUDIT.emit("test.event", actor="unit-test", details={"n": 1})
        self.assertTrue(ok)
        audit_path = self.var_log / "audit.jsonl"
        self.assertTrue(audit_path.is_file())
        self._assert_parents_unchanged()

    def test_ACCESS_LOG_CREATE_PRESERVES_EGRESS_LOG_PERMISSIONS(self):
        log_path = self.var_log / "access" / "connections.jsonl"
        ACL.emit_conn_log(
            {
                "client_id": "abcd1234",
                "service_id": "ssh",
                "source_ip": "198.51.100.10",
                "decision": "ALLOW",
                "reason": "ALLOWLIST",
            },
            path=log_path,
        )
        self.assertTrue(log_path.is_file())
        self._assert_parents_unchanged()


if __name__ == "__main__":
    unittest.main()
