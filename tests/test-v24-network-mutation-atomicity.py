#!/usr/bin/env python3
"""P0: Network Object / Network Group one-shot mutation atomicity."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane, ControlPlaneError
import drlink_v24 as v24
from drlink_v24_bundle import apply_v24_plan, prepare_v24_plan

MID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


class NetworkMutationAtomicity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-net-atom-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _member_names(self, group: str) -> list[str]:
        grp = self.plane.get_object_group(group)
        if grp is None:
            return []
        rows = self.plane.conn.execute(
            "SELECT o.name FROM object_group_members m "
            "JOIN objects o ON o.id = m.member_id "
            "WHERE m.group_id = ? AND m.member_kind = 'object' "
            "ORDER BY o.name",
            (grp["id"],),
        ).fetchall()
        return [r["name"] for r in rows]

    def _object_values(self, name: str) -> list[str]:
        obj = self.plane.get_object(name)
        if obj is None:
            return []
        return self.plane._object_values(obj["id"])

    def test_group_edit_partial_members_rolls_back(self):
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "b", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_network_group(self.plane, "office", members=["a"], oneshot=True)
        rev = self.plane.current_revision()

        with self.assertRaises(ControlPlaneError):
            v24.set_network_group(self.plane, "office", members=["b", "missing"], oneshot=True)

        self.assertEqual(self._member_names("office"), ["a"])
        self.assertEqual(self.plane.current_revision(), rev)

    def test_group_edit_does_not_broaden_whitelist(self):
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "b", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.50", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_network_group(self.plane, "office", members=["a"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-office",
            mode="whitelist",
            source="office",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )

        before_b = self.plane.evaluate_remote_access("198.51.100.20", "198.51.100.50", "tcp", 22)
        self.assertEqual(str(before_b.get("action") or before_b.get("effective")).upper(), "DENY")

        with self.assertRaises(ControlPlaneError):
            v24.set_network_group(self.plane, "office", members=["b", "missing"], oneshot=True)

        after_b = self.plane.evaluate_remote_access("198.51.100.20", "198.51.100.50", "tcp", 22)
        self.assertEqual(str(after_b.get("action") or after_b.get("effective")).upper(), "DENY")
        self.assertEqual(self._member_names("office"), ["a"])

    def test_failed_create_leaves_no_group(self):
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        rev = self.plane.current_revision()

        with self.assertRaises(ControlPlaneError):
            v24.set_network_group(self.plane, "new-office", members=["a", "missing"], oneshot=True)

        self.assertIsNone(self.plane.get_object_group("new-office"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_invalid_member_kind_no_partial_change(self):
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "b", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_network_group(self.plane, "office", members=["a"], oneshot=True)
        v24.set_network_group(self.plane, "other", members=["b"], oneshot=True)
        rev = self.plane.current_revision()

        with self.assertRaises(ControlPlaneError):
            v24.set_network_group(self.plane, "office", members=["b", "other"], oneshot=True)

        self.assertEqual(self._member_names("office"), ["a"])
        self.assertEqual(self.plane.current_revision(), rev)

    def test_successful_exact_list_one_revision(self):
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "b", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_network_object(self.plane, "c", type="ip", value="198.51.100.30", oneshot=True)
        v24.set_network_group(self.plane, "office", members=["a"], oneshot=True)
        rev_before = self.plane.current_revision()

        result = v24.set_network_group(self.plane, "office", members=["b", "c"], oneshot=True)
        rev_after = self.plane.current_revision()

        self.assertEqual(self._member_names("office"), ["b", "c"])
        self.assertEqual(rev_after, rev_before + 1)
        self.assertEqual(result.get("revision"), rev_after)

    def test_group_policy_eval_no_regression(self):
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "b", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.50", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_network_group(self.plane, "office", members=["a"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-office",
            mode="whitelist",
            source="office",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        allow_a = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.50", "tcp", 22)
        self.assertEqual(str(allow_a.get("action") or allow_a.get("effective")).upper(), "ALLOW")

        v24.set_network_group(self.plane, "office", members=["b"], oneshot=True)
        deny_a = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.50", "tcp", 22)
        allow_b = self.plane.evaluate_remote_access("198.51.100.20", "198.51.100.50", "tcp", 22)
        self.assertEqual(str(deny_a.get("action") or deny_a.get("effective")).upper(), "DENY")
        self.assertEqual(str(allow_b.get("action") or allow_b.get("effective")).upper(), "ALLOW")

    def test_invalid_create_leaves_no_object_residue(self):
        rev = self.plane.current_revision()
        with self.assertRaises(ControlPlaneError):
            v24.set_network_object(self.plane, "bad-ip", type="ip", value="not-an-ip", oneshot=True)
        self.assertIsNone(self.plane.get_object("bad-ip"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_invalid_edit_retains_previous_value(self):
        v24.set_network_object(self.plane, "host-a", type="ip", value="198.51.100.10", oneshot=True)
        rev = self.plane.current_revision()
        with self.assertRaises(ControlPlaneError):
            v24.set_network_object(self.plane, "host-a", type="ip", value="not-an-ip", oneshot=True)
        self.assertEqual(self._object_values("host-a"), ["198.51.100.10"])
        self.assertEqual(self.plane.current_revision(), rev)

    def test_successful_create_edit_one_revision_each(self):
        rev0 = self.plane.current_revision()
        created = v24.set_network_object(
            self.plane, "host-a", type="ip", value="198.51.100.10", oneshot=True
        )
        rev1 = self.plane.current_revision()
        self.assertEqual(rev1, rev0 + 1)
        self.assertEqual(created.get("revision"), rev1)
        self.assertEqual(self._object_values("host-a"), ["198.51.100.10"])

        updated = v24.set_network_object(
            self.plane, "host-a", type="ip", value="198.51.100.11", oneshot=True
        )
        rev2 = self.plane.current_revision()
        self.assertEqual(rev2, rev1 + 1)
        self.assertEqual(updated.get("revision"), rev2)
        self.assertEqual(self._object_values("host-a"), ["198.51.100.11"])

    def test_managed_host_mutation_rejected(self):
        self.plane.upsert_client(MID, label="ubuntu-prod", hostname="ubuntu-prod")
        rev = self.plane.current_revision()
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_network_object(
                self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True
            )
        self.assertIn("Managed Host", str(ctx.exception))
        self.assertEqual(self.plane.current_revision(), rev)
        obj = self.plane.get_object("ubuntu-prod")
        self.assertIsNotNone(obj)
        self.assertEqual(obj["type"], "managed_endpoint")

    def test_bundle_network_group_atomic(self):
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "b", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_network_group(self.plane, "office", members=["a"], oneshot=True)
        rev = self.plane.current_revision()
        text = """configurationBundle:
  context: server
  networkGroups:
    - name: office
      members: [b, missing]
"""
        with self.assertRaises(Exception):
            plan = prepare_v24_plan(self.plane, text)
            apply_v24_plan(self.plane, plan)
        self.assertEqual(self._member_names("office"), ["a"])
        self.assertEqual(self.plane.current_revision(), rev)

    def test_remote_internet_eval_still_works(self):
        v24.set_network_object(self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True)
        v24.set_network_object(self.plane, "web", type="fqdn", value="example.com", oneshot=True)
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-web",
            mode="whitelist",
            source="lan",
            destination="web",
            service="https",
            enabled=True,
            oneshot=True,
        )
        allow = self.plane.evaluate_internet_access("10.10.10.20", "example.com", 443, "https")
        deny = self.plane.evaluate_internet_access("10.10.10.21", "example.com", 443, "https")
        self.assertEqual(str(allow.get("action") or allow.get("effective")).upper(), "ALLOW")
        self.assertEqual(str(deny.get("action") or deny.get("effective")).upper(), "DENY")


if __name__ == "__main__":
    unittest.main()
