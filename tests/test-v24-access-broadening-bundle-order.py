#!/usr/bin/env python3
"""Packet 3: Access-broadening confirmation + Bundle dependency ordering.

Last enabled BLACKLIST rule delete/disable requires the same security-impact
confirmation model as policy disable/reset (Remote / Internet / AI).
Bundle reports direct and indirect broadening, and deletes Permission Group
before member Permission Object in one desired-state apply.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ConfirmationRequired, ControlPlane, ControlPlaneError
import drlink_control_cli as cli
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


class AccessBroadeningBundleOrder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-p3-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _dispatch(self, args):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.dispatch(list(args), root=self.tmp, plane=self.plane)
        return rc, out.getvalue(), err.getvalue()

    def _seed_remote_blacklist(self, rule="block-ssh"):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            rule,
            mode="blacklist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )

    def _seed_internet_blacklist(self, rule="block-https"):
        v24.set_network_object(self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True)
        v24.set_network_object(self.plane, "web", type="fqdn", value="example.com", oneshot=True)
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            rule,
            mode="blacklist",
            source="lan",
            destination="web",
            service="https",
            enabled=True,
            oneshot=True,
        )

    def _seed_ai_blacklist(self, rule="block-exec"):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_permission_object(
            self.plane, "exec-only", permissions=["command-exec"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            rule,
            mode="blacklist",
            source="bot",
            destination="ubuntu-prod",
            permission="exec-only",
            enabled=True,
            oneshot=True,
        )

    def test_last_blacklist_rule_delete_requires_confirm_remote(self):
        self._seed_remote_blacklist()
        os.environ.pop("DRLINK_CONFIRM", None)
        rev_before = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.unset_access_rule(self.plane, "remote", "block-ssh")
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev_before)
        row = self.plane._get_rule("remote", "block-ssh")
        self.assertIsNotNone(row)

    def test_last_blacklist_rule_disable_requires_confirm_remote(self):
        self._seed_remote_blacklist()
        os.environ.pop("DRLINK_CONFIRM", None)
        rev_before = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_access_rule(
                self.plane, "remote", "block-ssh", enabled=False, oneshot=True
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertTrue(bool(self.plane._get_rule("remote", "block-ssh")["enabled"]))

    def test_last_blacklist_rule_delete_internet_and_ai_parity(self):
        self._seed_internet_blacklist()
        self._seed_ai_blacklist()
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx_i:
            v24.unset_access_rule(self.plane, "internet", "block-https")
        self.assertTrue(ctx_i.exception.impact.get("access_broadened"))
        with self.assertRaises(ConfirmationRequired) as ctx_a:
            v24.unset_ai_access_rule(self.plane, "block-exec")
        self.assertTrue(ctx_a.exception.impact.get("access_broadened"))

    def test_last_blacklist_rule_disable_ai_parity(self):
        self._seed_ai_blacklist()
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_ai_access_rule(
                self.plane,
                "block-exec",
                source="bot",
                destination="ubuntu-prod",
                permission="exec-only",
                enabled=False,
                oneshot=True,
            )
        self.assertTrue(ctx.exception.impact.get("access_broadened"))

    def test_cancelled_confirmation_leaves_revision_unchanged_cli(self):
        self._seed_remote_blacklist()
        os.environ.pop("DRLINK_CONFIRM", None)
        rev_before = self.plane.current_revision()
        # Non-TTY cancel path via ConfirmationRequired → _run prints Cancelled
        # Simulate by calling dispatch without confirm; ConfirmationRequired is
        # caught inside _run when raised through CLI, but API path raises.
        # Use empty stdin cancel via _run semantics: env unset + no confirm.
        rc, out, err = self._dispatch(["unset", "remote-access", "block-ssh"])
        # Without TTY, _confirm_from_stdin returns False → cancelled
        self.assertEqual(rc, 0)
        self.assertIn("Cancelled", out)
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertIsNotNone(self.plane._get_rule("remote", "block-ssh"))

    def test_bundle_last_blacklist_rule_delete_reports_impact(self):
        self._seed_remote_blacklist()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    mode: blacklist
    enforcement: enabled
    rules:
      - name: block-ssh
        state: absent
""",
        )
        text = "\n".join(plan.security_impact)
        self.assertIn("broadens", text.lower())
        self.assertIn("last BLACKLIST", text)
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired):
            apply_v24_plan(self.plane, plan)
        self.assertIsNotNone(self.plane._get_rule("remote", "block-ssh"))

    def test_bundle_last_blacklist_rule_disable_reports_impact(self):
        self._seed_internet_blacklist()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  internetAccess:
    mode: blacklist
    enforcement: enabled
    rules:
      - name: block-https
        source: lan
        destination: web
        service: https
        enabled: false
""",
        )
        text = "\n".join(plan.security_impact)
        self.assertIn("broadens", text.lower())
        self.assertIn("last BLACKLIST", text)

    def test_bundle_indirect_po_delete_while_blacklist_referenced_reports_impact(self):
        self._seed_ai_blacklist()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  permissionObjects:
    - name: exec-only
      state: absent
""",
        )
        text = "\n".join(plan.security_impact)
        self.assertIn("broadens", text.lower())
        self.assertIn("exec-only", text)
        # Apply still refuses referenced delete (Packet 1) after confirm
        with self.assertRaises(ControlPlaneError) as ctx:
            apply_v24_plan(self.plane, plan, confirm=True)
        self.assertIn("still referenced", str(ctx.exception).lower())

    def test_bundle_permission_group_and_member_object_delete_ordered(self):
        v24.set_permission_object(
            self.plane, "exec", permissions=["command-exec"], oneshot=True
        )
        v24.set_permission_group(self.plane, "ops", members=["exec"], oneshot=True)
        rev_before = self.plane.current_revision()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  permissionObjects:
    - name: exec
      state: absent
  permissionGroups:
    - name: ops
      state: absent
""",
        )
        ops = [(c["op"], c["kind"], c["name"]) for c in plan.mutating_changes]
        self.assertIn(("DELETE", "permission-object", "exec"), ops)
        self.assertIn(("DELETE", "permission-group", "ops"), ops)
        result = apply_v24_plan(self.plane, plan, confirm=True)
        self.assertEqual(result["status"], "APPLIED")
        self.assertIsNone(v24.get_permission_object(self.plane, "exec"))
        self.assertIsNone(v24.get_permission_group(self.plane, "ops"))
        self.assertGreater(self.plane.current_revision(), rev_before)

    def test_second_blacklist_rule_delete_no_confirm(self):
        self._seed_remote_blacklist("block-a")
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-b",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        # Deleting one of two enabled BLACKLIST rules is not last-rule broadening
        v24.unset_access_rule(self.plane, "remote", "block-a")
        self.assertIsNone(self.plane._get_rule("remote", "block-a"))
        self.assertIsNotNone(self.plane._get_rule("remote", "block-b"))


if __name__ == "__main__":
    unittest.main()
