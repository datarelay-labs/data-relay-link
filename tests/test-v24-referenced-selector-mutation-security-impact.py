#!/usr/bin/env python3
"""P0: Referenced Object/Group mutations that broaden DENY→ALLOW require confirmation.

Reusable selector edits (Network/Service/Permission Object & Group) referenced by
enabled Access Rules must raise security-impact confirmation on both direct
one-shot and ConfigurationBundle surfaces.
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


def _verify(plane: ControlPlane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'verified', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.conn.commit()


class ReferencedSelectorMutationSecurityImpact(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-ref-selector-impact-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _seed_remote(self):
        v24.set_network_object(
            self.plane, "a", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "b", type="ip", value="198.51.100.11", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "svc", type="tcp", port=22, oneshot=True)
        v24.set_network_group(
            self.plane, "blocked", members=["a", "b"], oneshot=True
        )

    def _seed_internet(self):
        v24.set_network_object(
            self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "web", type="fqdn", value="example.com", oneshot=True
        )
        v24.set_service_object(self.plane, "p1111", type="tcp", port=1111, oneshot=True)
        v24.set_service_object(self.plane, "p2222", type="tcp", port=2222, oneshot=True)
        v24.set_service_group(
            self.plane, "blocked-svcs", members=["p1111", "p2222"], oneshot=True
        )

    def _seed_ai(self):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(
            self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_permission_object(
            self.plane, "exec-only", permissions=["command-exec"], oneshot=True
        )
        v24.set_permission_object(
            self.plane, "info-only", permissions=["host-info"], oneshot=True
        )
        v24.set_permission_group(
            self.plane, "ops", members=["exec-only", "info-only"], oneshot=True
        )

    def test_remote_blacklist_network_group_member_removal_direct_and_bundle(self):
        self._seed_remote()
        v24.set_access_rule(
            self.plane,
            "remote",
            "block",
            mode="blacklist",
            source="blocked",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        before = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="b",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(before.get("result"), "DENY")

        os.environ.pop("DRLINK_CONFIRM", None)
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_network_group(
                self.plane, "blocked", members=["a"], oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev)
        still = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="b",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(still.get("result"), "DENY")

        v24.set_network_group(
            self.plane, "blocked", members=["a"], oneshot=True, confirm=True
        )
        after = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="b",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(after.get("result"), "ALLOW")

        # Restore membership, then Bundle path
        v24.set_network_group(
            self.plane, "blocked", members=["a", "b"], oneshot=True, confirm=True
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  networkGroups:
    - name: blocked
      members: [a]
""",
        )
        self.assertTrue(any("broaden" in t.lower() for t in plan.security_impact))
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired):
            apply_v24_plan(self.plane, plan, confirm=False)
        self.assertEqual(self.plane.current_revision(), rev)
        apply_v24_plan(self.plane, plan, confirm=True)
        after_b = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="b",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(after_b.get("result"), "ALLOW")

    def test_remote_blacklist_network_object_value_mutation(self):
        self._seed_remote()
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-a",
            mode="blacklist",
            source="a",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        before = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="a",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(before.get("result"), "DENY")

        os.environ.pop("DRLINK_CONFIRM", None)
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_network_object(
                self.plane, "a", value="198.51.100.99", oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev)

        v24.set_network_object(
            self.plane, "a", value="198.51.100.99", oneshot=True, confirm=True
        )
        # Old IP leaf no longer matches the mutated object name binding for
        # concrete value tests — recreate object alias for the old address.
        v24.set_network_object(
            self.plane, "old-a", type="ip", value="198.51.100.10", oneshot=True
        )
        # Direct object 'a' now holds a different value; flows using the old
        # IP via a fresh object are ALLOW under BLACKLIST (no rule matches).
        after = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="old-a",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(after.get("result"), "ALLOW")

    def test_internet_blacklist_service_group_and_object(self):
        self._seed_internet()
        v24.set_access_rule(
            self.plane,
            "internet",
            "block-svcs",
            mode="blacklist",
            source="lan",
            destination="web",
            service="blocked-svcs",
            enabled=True,
            oneshot=True,
        )
        before = v24.evaluate_selector_policy(
            self.plane,
            "internet",
            source_name="lan",
            destination_name="web",
            service_name="p2222",
        )
        self.assertEqual(before.get("result"), "DENY")

        os.environ.pop("DRLINK_CONFIRM", None)
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_service_group(
                self.plane, "blocked-svcs", members=["p1111"], oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev)

        with self.assertRaises(ConfirmationRequired):
            v24.set_service_object(
                self.plane, "p2222", type="tcp", port=3333, oneshot=True
            )

        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  serviceGroups:
    - name: blocked-svcs
      members: [p1111]
""",
        )
        self.assertTrue(any("broaden" in t.lower() for t in plan.security_impact))
        apply_v24_plan(self.plane, plan, confirm=True)
        after = v24.evaluate_selector_policy(
            self.plane,
            "internet",
            source_name="lan",
            destination_name="web",
            service_name="p2222",
        )
        self.assertEqual(after.get("result"), "ALLOW")

    def test_ai_blacklist_permission_group_and_object(self):
        self._seed_ai()
        v24.set_ai_access_rule(
            self.plane,
            "deny-ops",
            mode="blacklist",
            source="bot",
            destination="ubuntu-prod",
            permission="ops",
            enabled=True,
            oneshot=True,
        )
        before = v24.authorize_ai_capability_v24(
            self.plane,
            identity="bot",
            destination="ubuntu-prod",
            capability="get_system_info",
        )
        self.assertEqual(str(before.get("action") or "").upper(), "DENY")

        os.environ.pop("DRLINK_CONFIRM", None)
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_permission_group(
                self.plane, "ops", members=["exec-only"], oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev)

        with self.assertRaises(ConfirmationRequired):
            v24.set_permission_object(
                self.plane, "info-only", permissions=["process-read"], oneshot=True
            )

        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  permissionGroups:
    - name: ops
      members: [exec-only]
""",
        )
        self.assertTrue(any("broaden" in t.lower() for t in plan.security_impact))
        apply_v24_plan(self.plane, plan, confirm=True)
        after = v24.authorize_ai_capability_v24(
            self.plane,
            identity="bot",
            destination="ubuntu-prod",
            capability="get_system_info",
        )
        self.assertEqual(str(after.get("action") or "").upper(), "ALLOW")

    def test_whitelist_referenced_group_expansion_requires_confirm(self):
        self._seed_remote()
        v24.set_network_group(
            self.plane, "allowed", members=["a"], oneshot=True
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-grp",
            mode="whitelist",
            source="allowed",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        before = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="b",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(before.get("result"), "DENY")

        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_network_group(
                self.plane, "allowed", members=["a", "b"], oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))

        # Shrink alone does not broaden WHITELIST → no confirmation.
        v24.set_network_group(
            self.plane, "allowed", members=["a", "b"], oneshot=True, confirm=True
        )
        v24.set_network_group(
            self.plane, "allowed", members=["a"], oneshot=True
        )

    def test_semantic_no_change_no_prompt(self):
        self._seed_remote()
        v24.set_access_rule(
            self.plane,
            "remote",
            "block",
            mode="blacklist",
            source="blocked",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        rev = self.plane.current_revision()
        # Same membership / value — no confirmation
        v24.set_network_group(
            self.plane, "blocked", members=["a", "b"], oneshot=True
        )
        v24.set_network_object(
            self.plane, "a", value="198.51.100.10", oneshot=True
        )
        self.assertEqual(self.plane.current_revision(), rev)
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  networkGroups:
    - name: blocked
      members: [a, b]
  networkObjects:
    - name: a
      type: ip
      value: 198.51.100.10
""",
        )
        self.assertEqual(plan.security_impact, [])
        self.assertTrue(plan.no_change or not plan.mutating_changes)


if __name__ == "__main__":
    unittest.main()
