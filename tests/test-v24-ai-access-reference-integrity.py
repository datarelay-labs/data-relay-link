#!/usr/bin/env python3
"""Packet 1: AI Access reference integrity / fail-open prevention.

Referenced Permission Object / Permission Group / AI Identity must not be
deleted while bound by v2.4 ai_policy_rules. Same-name recreate must not
silently reconnect dangling immutable IDs (rules keep the old ID).
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

from drlink_control_plane import ControlPlane, ControlPlaneError
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


def _seed_blacklist_rule(plane: ControlPlane) -> None:
    plane.set_ai_principal("bot", enabled=True)
    _verify(plane, "bot")
    v24.set_network_object(plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True)
    v24.set_permission_object(
        plane, "exec-only", permissions=["command-exec"], oneshot=True
    )
    v24.set_permission_object(
        plane, "read-only", permissions=["host-info", "process-read"], oneshot=True
    )
    v24.set_permission_group(plane, "ops", members=["exec-only"], oneshot=True)
    v24.set_ai_access_rule(
        plane,
        "block-exec",
        mode="blacklist",
        source="bot",
        destination="ubuntu-prod",
        permission="exec-only",
        enabled=True,
        oneshot=True,
    )


class AiAccessReferenceIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-ai-ref-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_CLASS_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _dispatch(self, args):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.dispatch(list(args), root=self.tmp, plane=self.plane)
        return rc, out.getvalue(), err.getvalue()

    def test_permission_object_delete_while_directly_referenced_rejected(self):
        _seed_blacklist_rule(self.plane)
        before = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(before["result"], "DENY")
        rc, _out, err = self._dispatch(["unset", "permission-object", "exec-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("still referenced", err)
        self.assertIn("ai-access block-exec", err)
        self.assertIsNotNone(v24.get_permission_object(self.plane, "exec-only"))
        after = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(after["result"], "DENY")

    def test_permission_group_delete_while_referenced_rejected(self):
        _seed_blacklist_rule(self.plane)
        v24.set_ai_access_rule(
            self.plane,
            "block-ops",
            mode="blacklist",
            source="bot",
            destination="ubuntu-prod",
            permission="ops",
            enabled=True,
            oneshot=True,
        )
        before = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(before["result"], "DENY")
        rc, _out, err = self._dispatch(["unset", "permission-group", "ops"])
        self.assertNotEqual(rc, 0)
        self.assertIn("still referenced", err)
        self.assertIn("ai-access block-ops", err)
        self.assertIsNotNone(v24.get_permission_group(self.plane, "ops"))
        after = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(after["result"], "DENY")

    def test_ai_identity_delete_while_referenced_rejected(self):
        _seed_blacklist_rule(self.plane)
        before = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(before["result"], "DENY")
        rc, _out, err = self._dispatch(["unset", "ai-identity", "bot"])
        self.assertNotEqual(rc, 0)
        self.assertIn("still referenced", err)
        self.assertIn("ai-access block-exec", err)
        self.assertIsNotNone(self.plane.get_principal("bot"))
        after = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(after["result"], "DENY")

    def test_same_name_recreate_does_not_revive_dangling_rule(self):
        """Immutable-ID semantics: recreating the public name must not reconnect old rules."""
        _seed_blacklist_rule(self.plane)
        row = self.plane.conn.execute(
            "SELECT id, permission_ref_id FROM ai_policy_rules WHERE name = 'block-exec'"
        ).fetchone()
        old_perm_id = row["permission_ref_id"]
        # Simulate a dangling immutable ID (pre-fix fail-open hole) without violating FK:
        # point the rule at a retired ID, then remove the live Permission Object.
        self.plane.conn.execute(
            "UPDATE ai_policy_rules SET permission_ref_id = ? WHERE id = ?",
            ("perm_retired_dangling", row["id"]),
        )
        self.plane.conn.execute(
            "DELETE FROM permission_group_members WHERE permission_object_id = ?", (old_perm_id,)
        )
        self.plane.conn.execute(
            "DELETE FROM permission_object_members WHERE permission_object_id = ?", (old_perm_id,)
        )
        self.plane.conn.execute("DELETE FROM permission_objects WHERE id = ?", (old_perm_id,))
        self.plane.conn.commit()
        dangling = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(dangling["result"], "ALLOW")  # BLACKLIST unmatched => ALLOW
        v24.set_permission_object(
            self.plane, "exec-only", permissions=["command-exec"], oneshot=True
        )
        new_obj = v24.get_permission_object(self.plane, "exec-only")
        self.assertNotEqual(new_obj["id"], old_perm_id)
        self.assertNotEqual(new_obj["id"], "perm_retired_dangling")
        still = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(still["result"], "ALLOW")
        rule = self.plane.conn.execute(
            "SELECT permission_ref_id FROM ai_policy_rules WHERE name = 'block-exec'"
        ).fetchone()
        self.assertEqual(rule["permission_ref_id"], "perm_retired_dangling")


    def test_bundle_referenced_permission_group_delete_rejected_atomically(self):
        _seed_blacklist_rule(self.plane)
        v24.set_ai_access_rule(
            self.plane,
            "block-ops",
            mode="blacklist",
            source="bot",
            destination="ubuntu-prod",
            permission="ops",
            enabled=True,
            oneshot=True,
        )
        before = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(before["result"], "DENY")
        yaml_text = """configurationBundle:
  context: server
  permissionGroups:
    - name: ops
      state: absent
"""
        plan = prepare_v24_plan(self.plane, yaml_text)
        self.assertFalse(plan.no_change)
        with self.assertRaises(ControlPlaneError) as ctx:
            apply_v24_plan(self.plane, plan, confirm=True)
        self.assertIn("still referenced", str(ctx.exception))
        self.assertIsNotNone(v24.get_permission_group(self.plane, "ops"))
        after = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(after["result"], "DENY")

    def test_bundle_referenced_permission_object_delete_rejected_atomically(self):
        _seed_blacklist_rule(self.plane)
        yaml_text = """configurationBundle:
  context: server
  permissionObjects:
    - name: exec-only
      state: absent
"""
        plan = prepare_v24_plan(self.plane, yaml_text)
        with self.assertRaises(ControlPlaneError) as ctx:
            apply_v24_plan(self.plane, plan, confirm=True)
        self.assertIn("still referenced", str(ctx.exception))
        self.assertIsNotNone(v24.get_permission_object(self.plane, "exec-only"))
        after = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(after["result"], "DENY")

    def test_whitelist_remains_fail_closed_when_permission_missing(self):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_permission_object(
            self.plane, "read-only", permissions=["host-info"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            "allow-read",
            mode="whitelist",
            source="bot",
            destination="ubuntu-prod",
            permission="read-only",
            enabled=True,
            oneshot=True,
        )
        allow = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="host-info"
        )
        self.assertEqual(allow["result"], "ALLOW")
        deny = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(deny["result"], "DENY")
        # Deleting the referenced Permission Object must be rejected (no fail-open hole)
        with self.assertRaises(ControlPlaneError):
            v24.unset_permission_object(self.plane, "read-only")
        still = v24.evaluate_ai_access_v24(
            self.plane, identity="bot", destination="ubuntu-prod", permission="host-info"
        )
        self.assertEqual(still["result"], "ALLOW")

    def test_unreferenced_permission_object_delete_allowed(self):
        v24.set_permission_object(
            self.plane, "unused", permissions=["host-info"], oneshot=True
        )
        rc, out, err = self._dispatch(["unset", "permission-object", "unused"])
        self.assertEqual(rc, 0, err)
        self.assertIn("deleted", out.lower())
        self.assertIsNone(v24.get_permission_object(self.plane, "unused"))


if __name__ == "__main__":
    unittest.main()
