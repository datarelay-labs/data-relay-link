#!/usr/bin/env python3
"""P0: Rule mutations that broaden DENY→ALLOW require security-impact confirmation.

Covers WHITELIST disabled→enabled and BLACKLIST selector narrowing for Remote /
Internet / AI, on both direct one-shot and ConfigurationBundle surfaces.
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


class RuleMutationSecurityImpact(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-rule-mutation-impact-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _seed_remote_objects(self):
        v24.set_network_object(
            self.plane, "src1", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "src2", type="ip", value="198.51.100.11", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "svc", type="tcp", port=22, oneshot=True)
        v24.set_network_group(
            self.plane, "src-grp", members=["src1", "src2"], oneshot=True
        )

    def _seed_internet_objects(self):
        v24.set_network_object(
            self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "lan2", type="ip", value="10.10.10.21", oneshot=True
        )
        v24.set_network_object(
            self.plane, "web", type="fqdn", value="example.com", oneshot=True
        )
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_service_object(self.plane, "http", type="tcp", port=80, oneshot=True)
        v24.set_network_group(
            self.plane, "lan-grp", members=["lan", "lan2"], oneshot=True
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
            self.plane, "read-only", permissions=["host-info"], oneshot=True
        )
        v24.set_permission_group(
            self.plane, "ops", members=["exec-only", "read-only"], oneshot=True
        )

    def test_remote_whitelist_enable_direct_and_bundle(self):
        self._seed_remote_objects()
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-ssh",
            mode="whitelist",
            source="src1",
            destination="dst",
            service="svc",
            enabled=False,
            oneshot=True,
        )
        before = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src1",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(before.get("result"), "DENY")

        os.environ.pop("DRLINK_CONFIRM", None)
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_access_rule(
                self.plane, "remote", "allow-ssh", enabled=True, oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev)
        self.assertFalse(bool(self.plane._get_rule("remote", "allow-ssh")["enabled"]))

        v24.set_access_rule(
            self.plane, "remote", "allow-ssh", enabled=True, oneshot=True, confirm=True
        )
        after = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src1",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(after.get("result"), "ALLOW")

        # Bundle path for a second disabled rule
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-ssh-2",
            source="src1",
            destination="dst",
            service="svc",
            enabled=False,
            oneshot=True,
            confirm=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    rules:
      - name: allow-ssh-2
        source: src1
        destination: dst
        service: svc
        enabled: true
""",
        )
        self.assertTrue(any("broadens" in t.lower() for t in plan.security_impact))
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired):
            apply_v24_plan(self.plane, plan, confirm=False)
        self.assertEqual(self.plane.current_revision(), rev)
        apply_v24_plan(self.plane, plan, confirm=True)
        self.assertTrue(bool(self.plane._get_rule("remote", "allow-ssh-2")["enabled"]))

    def test_internet_whitelist_enable_parity(self):
        self._seed_internet_objects()
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-https",
            mode="whitelist",
            source="lan",
            destination="web",
            service="https",
            enabled=False,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_access_rule(
                self.plane, "internet", "allow-https", enabled=True, oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  internetAccess:
    rules:
      - name: allow-https
        source: lan
        destination: web
        service: https
        enabled: true
""",
        )
        self.assertTrue(any("broadens" in t.lower() for t in plan.security_impact))

    def test_ai_whitelist_enable_parity(self):
        self._seed_ai()
        v24.set_ai_access_rule(
            self.plane,
            "allow-exec",
            mode="whitelist",
            source="bot",
            destination="ubuntu-prod",
            permission="exec-only",
            enabled=False,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_ai_access_rule(
                self.plane, "allow-exec", enabled=True, oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  aiAccess:
    rules:
      - name: allow-exec
        source: bot
        destination: ubuntu-prod
        permission: exec-only
        enabled: true
""",
        )
        self.assertTrue(any("broadens" in t.lower() for t in plan.security_impact))

    def test_remote_blacklist_selector_narrow_direct_and_bundle(self):
        self._seed_remote_objects()
        v24.set_access_rule(
            self.plane,
            "remote",
            "deny-grp",
            mode="blacklist",
            source="src-grp",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        before = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src2",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(before.get("result"), "DENY")

        os.environ.pop("DRLINK_CONFIRM", None)
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_access_rule(
                self.plane, "remote", "deny-grp", source="src1", oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev)
        still = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src2",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(still.get("result"), "DENY")

        v24.set_access_rule(
            self.plane, "remote", "deny-grp", source="src1", oneshot=True, confirm=True
        )
        after = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src2",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(after.get("result"), "ALLOW")

        # Reset to group, then Bundle narrow
        v24.set_access_rule(
            self.plane, "remote", "deny-grp", source="src-grp", oneshot=True, confirm=True
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    rules:
      - name: deny-grp
        source: src1
        destination: dst
        service: svc
        enabled: true
""",
        )
        self.assertTrue(any("broaden" in t.lower() for t in plan.security_impact))
        rev = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired):
            apply_v24_plan(self.plane, plan, confirm=False)
        self.assertEqual(self.plane.current_revision(), rev)
        apply_v24_plan(self.plane, plan, confirm=True)
        view = self.plane._rule_view(self.plane._get_rule("remote", "deny-grp"))
        self.assertEqual((view.get("sources") or [None])[0].lower(), "src1")

    def test_internet_blacklist_service_selector_parity(self):
        self._seed_internet_objects()
        v24.set_service_group(
            self.plane, "web-svc", members=["http", "https"], oneshot=True
        )
        v24.set_access_rule(
            self.plane,
            "internet",
            "deny-web",
            mode="blacklist",
            source="lan-grp",
            destination="web",
            service="web-svc",
            enabled=True,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_access_rule(
                self.plane, "internet", "deny-web", service="https", oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  internetAccess:
    rules:
      - name: deny-web
        source: lan-grp
        destination: web
        service: https
        enabled: true
""",
        )
        self.assertTrue(any("broaden" in t.lower() for t in plan.security_impact))

    def test_ai_blacklist_permission_and_path_narrowing(self):
        self._seed_ai()
        v24.set_ai_access_rule(
            self.plane,
            "deny-ops",
            mode="blacklist",
            source="bot",
            destination="ubuntu-prod",
            permission="ops",
            paths=["/etc", "/var"],
            enabled=True,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_ai_access_rule(
                self.plane, "deny-ops", permission="exec-only", oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        with self.assertRaises(ConfirmationRequired) as ctx2:
            v24.set_ai_access_rule(
                self.plane, "deny-ops", paths=["/etc"], oneshot=True
            )
        self.assertTrue(ctx2.exception.impact.get("access_broadened"))
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  aiAccess:
    rules:
      - name: deny-ops
        source: bot
        destination: ubuntu-prod
        permission: exec-only
        paths:
          - /etc
        enabled: true
""",
        )
        self.assertTrue(any("broaden" in t.lower() for t in plan.security_impact))

    def test_true_semantic_no_change_does_not_prompt(self):
        self._seed_remote_objects()
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-ssh",
            mode="whitelist",
            source="src1",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        # Same selectors / enabled — no confirmation
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-ssh",
            source="src1",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    rules:
      - name: allow-ssh
        source: src1
        destination: dst
        service: svc
        enabled: true
""",
        )
        self.assertTrue(plan.no_change or all(
            c.get("op") == "NO_CHANGE"
            for c in plan.changes
            if c.get("kind") == "remote-access-rule"
        ))
        self.assertEqual(plan.security_impact, [])
        apply_v24_plan(self.plane, plan, confirm=False)

    def test_whitelist_last_rule_disable_still_narrowed_not_broadened(self):
        self._seed_remote_objects()
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-ssh",
            mode="whitelist",
            source="src1",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_access_rule(
                self.plane, "remote", "allow-ssh", enabled=False, oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_narrowed"))
        self.assertFalse(ctx.exception.impact.get("access_broadened"))


if __name__ == "__main__":
    unittest.main()
