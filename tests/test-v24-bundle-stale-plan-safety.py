#!/usr/bin/env python3
"""P0: ConfigurationBundle stale-plan / current-state safety.

Apply must re-diff and recalculate security impact against authoritative state
under a race-safe guard. Stale prepared plans must not:
  - return false NO_CHANGE after concurrent mutation
  - remove the now-last BLACKLIST blocker without current-state confirmation
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ConfirmationRequired, ControlPlane
import drlink_v24 as v24
from drlink_v24_bundle import apply_v24_plan, prepare_v24_plan


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


class BundleStalePlanSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-stale-plan-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ.pop("DRLINK_CONFIRM", None)
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def test_stale_no_change_plan_applies_current_desired_state(self):
        v24.set_network_object(
            self.plane, "office", type="ip", value="198.51.100.10", oneshot=True
        )
        prepared_rev = self.plane.current_revision()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  networkObjects:
    - name: office
      type: ip
      value: 198.51.100.10
""",
        )
        self.assertTrue(plan.no_change)
        self.assertEqual(plan.base_revision, prepared_rev)

        v24.set_network_object(
            self.plane, "office", type="ip", value="198.51.100.20", oneshot=True
        )
        concurrent_rev = self.plane.current_revision()
        self.assertGreater(concurrent_rev, prepared_rev)
        self.assertEqual(
            self.plane._object_values(self.plane.get_object("office")["id"])[:1],
            ["198.51.100.20"],
        )

        result = apply_v24_plan(self.plane, plan)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(
            self.plane._object_values(self.plane.get_object("office")["id"])[:1],
            ["198.51.100.10"],
        )
        self.assertGreater(self.plane.current_revision(), concurrent_rev)

    def test_true_no_change_remains_idempotent(self):
        v24.set_network_object(
            self.plane, "office", type="ip", value="198.51.100.10", oneshot=True
        )
        yaml_text = """configurationBundle:
  context: server
  networkObjects:
    - name: office
      type: ip
      value: 198.51.100.10
"""
        plan = prepare_v24_plan(self.plane, yaml_text)
        self.assertTrue(plan.no_change)
        rev_before = self.plane.current_revision()
        result = apply_v24_plan(self.plane, plan)
        self.assertEqual(result["status"], "NO_CHANGE")
        self.assertEqual(result["revision"], rev_before)
        self.assertEqual(self.plane.current_revision(), rev_before)

    def test_normal_apply_still_applied(self):
        v24.set_network_object(
            self.plane, "office", type="ip", value="198.51.100.10", oneshot=True
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  networkObjects:
    - name: office
      type: ip
      value: 198.51.100.30
""",
        )
        self.assertFalse(plan.no_change)
        result = apply_v24_plan(self.plane, plan)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(
            self.plane._object_values(self.plane.get_object("office")["id"])[:1],
            ["198.51.100.30"],
        )

    def test_stale_plan_cannot_bypass_last_blacklist_confirmation(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.1", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.2", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        for name in ("deny1", "deny2"):
            v24.set_access_rule(
                self.plane,
                "remote",
                name,
                mode="blacklist",
                source="src",
                destination="dst",
                service="ssh",
                enabled=True,
                oneshot=True,
            )

        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    mode: blacklist
    enforcement: enabled
    rules:
      - name: deny1
        source: src
        destination: dst
        service: ssh
        enabled: false
      - name: deny2
        source: src
        destination: dst
        service: ssh
        enabled: true
""",
        )
        self.assertFalse(plan.no_change)
        self.assertEqual(plan.security_impact, [])

        # Concurrent writer disables deny2 with confirmation → deny1 is now last blocker.
        v24.set_access_rule(
            self.plane, "remote", "deny2", enabled=False, oneshot=True, confirm=True
        )
        self.assertTrue(bool(self.plane._get_rule("remote", "deny1")["enabled"]))
        self.assertFalse(bool(self.plane._get_rule("remote", "deny2")["enabled"]))

        rev_before = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            apply_v24_plan(self.plane, plan, confirm=False)
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertTrue(bool(self.plane._get_rule("remote", "deny1")["enabled"]))
        self.assertFalse(bool(self.plane._get_rule("remote", "deny2")["enabled"]))

        # Fresh confirmation against current state is still required and works.
        result = apply_v24_plan(self.plane, plan, confirm=True)
        self.assertEqual(result["status"], "APPLIED")
        self.assertFalse(bool(self.plane._get_rule("remote", "deny1")["enabled"]))

    def test_confirmation_cancel_leaves_state_unchanged(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.1", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.2", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "deny1",
            mode="blacklist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    mode: blacklist
    enforcement: enabled
    rules:
      - name: deny1
        source: src
        destination: dst
        service: ssh
        enabled: false
""",
        )
        self.assertTrue(plan.security_impact)
        rev_before = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired):
            apply_v24_plan(self.plane, plan, confirm=False)
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertTrue(bool(self.plane._get_rule("remote", "deny1")["enabled"]))


if __name__ == "__main__":
    unittest.main()
