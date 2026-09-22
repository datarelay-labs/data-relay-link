#!/usr/bin/env python3
"""P0: Object/Group public-name namespaces must be unique and fail closed.

Network / Service / Permission paired namespaces reject cross-kind collisions on
create, and public selector resolution fails closed when legacy ambiguity exists.
Immutable Rule bindings remain stable.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane
import drlink_v24 as v24
from drlink_configuration_bundle import BundleError
from drlink_v24_bundle import (
    apply_v24_plan,
    export_configuration_v24,
    prepare_v24_plan,
)


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _seed_base(plane: ControlPlane) -> None:
    v24.set_network_object(plane, "src1", type="ip", value="198.51.100.10", oneshot=True)
    v24.set_network_object(plane, "src2", type="ip", value="198.51.100.11", oneshot=True)
    v24.set_network_object(plane, "dst", type="ip", value="203.0.113.10", oneshot=True)
    v24.set_service_object(plane, "svc", type="tcp", port=443, oneshot=True)


def _force_network_collision(plane: ControlPlane, name: str = "shared") -> None:
    """Seed legacy Object+Group same-name state via SQL (create paths reject)."""
    v24.set_network_group(plane, name, members=["src2"], oneshot=True)
    now = v24.utc_now_iso()
    oid = "obj_force_%s" % name
    plane.conn.execute(
        "INSERT INTO objects(id, name, type, origin, description, status, row_version, "
        "created_at, updated_at) VALUES (?, ?, 'host', 'static', '', 'active', 1, ?, ?)",
        (oid, name, now, now),
    )
    plane.conn.execute(
        "INSERT INTO object_values(object_id, value, normalized) VALUES (?, ?, ?)",
        (oid, "198.51.100.10", "198.51.100.10"),
    )
    plane.conn.commit()


class PublicNameNamespaceAmbiguity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-ns-ambiguity-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        _seed_base(self.plane)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def test_network_object_then_group_create_rejected(self):
        v24.set_network_object(
            self.plane, "shared", type="ip", value="198.51.100.10", oneshot=True
        )
        rev = self.plane.current_revision()
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_network_group(self.plane, "shared", members=["src2"], oneshot=True)
        self.assertIn("already used", str(ctx.exception).lower())
        self.assertIsNone(self.plane.get_object_group("shared"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_network_group_then_object_create_rejected(self):
        v24.set_network_group(self.plane, "shared", members=["src2"], oneshot=True)
        rev = self.plane.current_revision()
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_network_object(
                self.plane, "shared", type="ip", value="198.51.100.10", oneshot=True
            )
        self.assertIn("already used", str(ctx.exception).lower())
        self.assertEqual(self.plane.current_revision(), rev)

    def test_network_case_insensitive_collision_rejected(self):
        v24.set_network_object(
            self.plane, "Shared", type="ip", value="198.51.100.10", oneshot=True
        )
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_network_group(self.plane, "shared", members=["src2"], oneshot=True)
        self.assertIn("already used", str(ctx.exception).lower())

    def test_service_object_group_both_orders_rejected(self):
        v24.set_service_object(self.plane, "svc-shared", type="tcp", port=1111, oneshot=True)
        with self.assertRaises(ControlPlaneError):
            v24.set_service_group(self.plane, "svc-shared", members=["svc"], oneshot=True)
        v24.set_service_group(self.plane, "svc-grp", members=["svc"], oneshot=True)
        with self.assertRaises(ControlPlaneError):
            v24.set_service_object(self.plane, "svc-grp", type="tcp", port=2222, oneshot=True)

    def test_permission_object_group_both_orders_rejected(self):
        v24.set_permission_object(
            self.plane, "perm-shared", permissions=["host-info"], oneshot=True
        )
        v24.set_permission_object(
            self.plane, "perm-file", permissions=["file-read"], oneshot=True
        )
        with self.assertRaises(ControlPlaneError):
            v24.set_permission_group(
                self.plane, "perm-shared", members=["perm-file"], oneshot=True
            )
        v24.set_permission_group(
            self.plane, "perm-grp", members=["perm-file"], oneshot=True
        )
        with self.assertRaises(ControlPlaneError):
            v24.set_permission_object(
                self.plane, "perm-grp", permissions=["host-info"], oneshot=True
            )

    def test_legacy_ambiguity_resolve_fails_closed_not_object_first(self):
        _force_network_collision(self.plane, "shared")
        self.assertTrue(self.plane.get_object("shared"))
        self.assertTrue(self.plane.get_object_group("shared"))
        with self.assertRaises(ControlPlaneError) as ctx:
            self.plane.resolve_ref("shared")
        self.assertIn("ambiguous", str(ctx.exception).lower())
        with self.assertRaises(ControlPlaneError):
            v24.set_access_rule(
                self.plane,
                "remote",
                "deny-shared",
                mode="blacklist",
                source="shared",
                destination="dst",
                service="svc",
                enabled=True,
                oneshot=True,
            )
        # Reproducer must not yield silent src2 ALLOW via Object-first bind.
        self.assertIsNone(self.plane._get_rule("remote", "deny-shared"))

    def test_legacy_immutable_binding_remains_stable(self):
        v24.set_network_group(self.plane, "shared", members=["src2"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "deny-shared",
            mode="blacklist",
            source="shared",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        rule = self.plane._get_rule("remote", "deny-shared")
        refs = self.plane.conn.execute(
            "SELECT ref_kind FROM rule_sources WHERE rule_id = ?", (rule["id"],)
        ).fetchall()
        self.assertEqual([r["ref_kind"] for r in refs], ["group"])
        # Inject legacy Object collision after immutable bind.
        now = v24.utc_now_iso()
        oid = "obj_force_shared2"
        self.plane.conn.execute(
            "INSERT INTO objects(id, name, type, origin, description, status, row_version, "
            "created_at, updated_at) VALUES (?, 'shared', 'host', 'static', '', 'active', 1, ?, ?)",
            (oid, now, now),
        )
        self.plane.conn.execute(
            "INSERT INTO object_values(object_id, value, normalized) VALUES (?, ?, ?)",
            (oid, "198.51.100.10", "198.51.100.10"),
        )
        self.plane.conn.commit()
        e2 = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src2",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(e2.get("result"), "DENY")
        self.assertIn("deny-shared", e2.get("matched_rules") or [])

    def test_service_and_permission_ambiguity_fail_closed(self):
        v24.set_service_object(self.plane, "svc-shared", type="tcp", port=1111, oneshot=True)
        now = v24.utc_now_iso()
        gid = "sgrp_force"
        self.plane.conn.execute(
            "INSERT INTO service_groups(id, name, description, row_version, created_at, updated_at) "
            "VALUES (?, 'svc-shared', '', 1, ?, ?)",
            (gid, now, now),
        )
        sobj = v24.get_service_object(self.plane, "svc")
        self.plane.conn.execute(
            "INSERT INTO service_group_members(group_id, service_object_id) VALUES (?, ?)",
            (gid, sobj["id"]),
        )
        self.plane.conn.commit()
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.resolve_service_ref(self.plane, "svc-shared")
        self.assertIn("ambiguous", str(ctx.exception).lower())

        v24.set_permission_object(
            self.plane, "perm-shared", permissions=["host-info"], oneshot=True
        )
        v24.set_permission_object(
            self.plane, "perm-file", permissions=["file-read"], oneshot=True
        )
        pgid = "pgrp_force"
        self.plane.conn.execute(
            "INSERT INTO permission_groups(id, name, description, row_version, created_at, updated_at) "
            "VALUES (?, 'perm-shared', '', 1, ?, ?)",
            (pgid, now, now),
        )
        pfile = v24.get_permission_object(self.plane, "perm-file")
        self.plane.conn.execute(
            "INSERT INTO permission_group_members(group_id, permission_object_id) VALUES (?, ?)",
            (pgid, pfile["id"]),
        )
        self.plane.conn.commit()
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.resolve_permission_ref(self.plane, "perm-shared")
        self.assertIn("ambiguous", str(ctx.exception).lower())

    def test_bundle_same_document_object_group_rejected(self):
        rev = self.plane.current_revision()
        with self.assertRaises(BundleError) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: server
  networkObjects:
    - name: shared
      type: ip
      value: 198.51.100.10
  networkGroups:
    - name: shared
      members: [src2]
""",
            )
        self.assertIn("ambiguous", str(ctx.exception).lower())
        self.assertEqual(self.plane.current_revision(), rev)

    def test_bundle_retains_legacy_ambiguity_rejected(self):
        _force_network_collision(self.plane, "shared")
        with self.assertRaises(BundleError) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: server
  networkObjects:
    - name: dst
      type: ip
      value: 203.0.113.10
""",
            )
        self.assertIn("ambiguous", str(ctx.exception).lower())

    def test_export_reapply_preserves_unique_namespace(self):
        v24.set_network_group(self.plane, "src-group", members=["src2"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "deny-group",
            mode="blacklist",
            source="src-group",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        exported = export_configuration_v24(self.plane)
        # Fresh plane
        tmp2 = tempfile.mkdtemp(prefix="drlink-ns-reapply-")
        _server_root(tmp2)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = tmp2
        plane2 = ControlPlane(tmp2)
        try:
            plan = prepare_v24_plan(plane2, exported)
            apply_v24_plan(plane2, plan, confirm=True)
            rule = plane2._get_rule("remote", "deny-group")
            refs = plane2.conn.execute(
                "SELECT ref_kind FROM rule_sources WHERE rule_id = ?", (rule["id"],)
            ).fetchall()
            self.assertEqual([r["ref_kind"] for r in refs], ["group"])
            e2 = v24.evaluate_selector_policy(
                plane2,
                "remote",
                source_name="src2",
                destination_name="dst",
                service_name="svc",
            )
            self.assertEqual(e2.get("result"), "DENY")
        finally:
            plane2.close()


if __name__ == "__main__":
    unittest.main()
