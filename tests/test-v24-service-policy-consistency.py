#!/usr/bin/env python3
"""Packet 2: Service Object / Service Group policy consistency.

Referenced Service Object/Group mutations must keep Remote/Internet enforcement
aligned with current definitions. Referenced Service Group delete is rejected.
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


class ServicePolicyConsistency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-svc-pol-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_CLASS_ROOT"] = self.tmp
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

    def _seed_remote_blacklist_ssh(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-ssh",
            mode="blacklist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )

    def _seed_internet_whitelist_https(self):
        v24.set_network_object(self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True)
        v24.set_network_object(self.plane, "github", type="fqdn", value="example.com", oneshot=True)
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-https",
            mode="whitelist",
            source="lan",
            destination="github",
            service="https",
            enabled=True,
            oneshot=True,
        )

    def test_service_object_port_edit_while_referenced_updates_remote_blacklist(self):
        self._seed_remote_blacklist_ssh()
        before_22 = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)
        before_2222 = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 2222)
        self.assertEqual(before_22["action"], "DENY")
        self.assertEqual(before_2222["action"], "ALLOW")
        v24.set_service_object(self.plane, "ssh", type="tcp", port=2222, oneshot=True)
        sobj = v24.get_service_object(self.plane, "ssh")
        self.assertEqual(int(sobj["port"]), 2222)
        after_22 = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)
        after_2222 = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 2222)
        self.assertEqual(after_22["action"], "ALLOW")
        self.assertEqual(after_2222["action"], "DENY")
        # Materialized cache must also move with the object.
        ports = {
            int(r["port"])
            for r in self.plane.conn.execute(
                "SELECT rs.port AS port FROM rule_services rs "
                "JOIN policy_rules pr ON pr.id = rs.rule_id WHERE pr.name = 'block-ssh'"
            )
        }
        self.assertEqual(ports, {2222})

    def test_service_object_port_edit_while_referenced_updates_internet_whitelist(self):
        self._seed_internet_whitelist_https()
        before_443 = self.plane.evaluate_internet_access("10.10.10.20", "example.com", 443, "https")
        before_4443 = self.plane.evaluate_internet_access("10.10.10.20", "example.com", 4443, "tcp")
        self.assertEqual(before_443["action"], "ALLOW")
        self.assertEqual(before_4443["action"], "DENY")
        v24.set_service_object(self.plane, "https", type="tcp", port=4443, oneshot=True)
        after_443 = self.plane.evaluate_internet_access("10.10.10.20", "example.com", 443, "https")
        after_4443 = self.plane.evaluate_internet_access("10.10.10.20", "example.com", 4443, "tcp")
        self.assertEqual(after_443["action"], "DENY")
        self.assertEqual(after_4443["action"], "ALLOW")

    def test_service_group_membership_edit_while_referenced(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_service_group(self.plane, "admin-services", members=["ssh"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-admin",
            mode="blacklist",
            source="src",
            destination="dst",
            service="admin-services",
            enabled=True,
            oneshot=True,
        )
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)["action"],
            "DENY",
        )
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 443)["action"],
            "ALLOW",
        )
        v24.set_service_group(self.plane, "admin-services", members=["https"], oneshot=True)
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)["action"],
            "ALLOW",
        )
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 443)["action"],
            "DENY",
        )

    def test_referenced_service_group_delete_rejected(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_group(self.plane, "admin-services", members=["ssh"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-admin",
            mode="blacklist",
            source="src",
            destination="dst",
            service="admin-services",
            enabled=True,
            oneshot=True,
        )
        before = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)
        self.assertEqual(before["action"], "DENY")
        rc, _out, err = self._dispatch(["unset", "service-group", "admin-services"])
        self.assertNotEqual(rc, 0)
        self.assertIn("still referenced", err)
        self.assertIsNotNone(v24.get_service_group(self.plane, "admin-services"))
        after = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)
        self.assertEqual(after["action"], "DENY")

    def test_bundle_referenced_service_group_delete_rejected(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_group(self.plane, "admin-services", members=["ssh"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-admin",
            mode="blacklist",
            source="src",
            destination="dst",
            service="admin-services",
            enabled=True,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  serviceGroups:
    - name: admin-services
      state: absent
""",
        )
        with self.assertRaises(ControlPlaneError) as ctx:
            apply_v24_plan(self.plane, plan, confirm=True)
        self.assertIn("still referenced", str(ctx.exception))
        self.assertIsNotNone(v24.get_service_group(self.plane, "admin-services"))

    def test_same_name_recreate_after_delete_does_not_reconnect(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_group(self.plane, "admin-services", members=["ssh"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-admin",
            mode="blacklist",
            source="src",
            destination="dst",
            service="admin-services",
            enabled=True,
            oneshot=True,
        )
        row = self.plane.conn.execute(
            "SELECT ref_id FROM rule_service_refs WHERE ref_kind = 'service_group'"
        ).fetchone()
        old_id = row["ref_id"]
        # Simulate dangling immutable ID (delete blocked in product path).
        self.plane.conn.execute(
            "UPDATE rule_service_refs SET ref_id = ? WHERE ref_kind = 'service_group'",
            ("sgrp_retired_dangling",),
        )
        self.plane.conn.execute("DELETE FROM service_group_members WHERE group_id = ?", (old_id,))
        self.plane.conn.execute("DELETE FROM service_groups WHERE id = ?", (old_id,))
        self.plane.conn.commit()
        dangling = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)
        self.assertEqual(dangling["action"], "ALLOW")
        v24.set_service_group(self.plane, "admin-services", members=["ssh"], oneshot=True)
        new_grp = v24.get_service_group(self.plane, "admin-services")
        self.assertNotEqual(new_grp["id"], old_id)
        still = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.20", "tcp", 22)
        self.assertEqual(still["action"], "ALLOW")

    def test_remote_service_unaffected_by_unrelated_service_object_edit(self):
        """Remote Service behavior must not regress from policy rematerialization."""
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_object(self.plane, "web", type="tcp", port=80, oneshot=True)
        # No policy refs; edit must succeed and leave Remote Service catalog untouched.
        before = list(
            self.plane.conn.execute("SELECT name FROM agent_remote_services").fetchall()
        )
        v24.set_service_object(self.plane, "web", type="tcp", port=8080, oneshot=True)
        after = list(
            self.plane.conn.execute("SELECT name FROM agent_remote_services").fetchall()
        )
        self.assertEqual(before, after)
        self.assertEqual(int(v24.get_service_object(self.plane, "web")["port"]), 8080)


if __name__ == "__main__":
    unittest.main()
