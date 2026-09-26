#!/usr/bin/env python3
"""Managed Host is the Remote Access policy identity for this-host services."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
import drlink_runtime_policy as RP
import drlink_upgrade_reconcile as UR
import drlink_v24 as v24

MID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1"


class ManagedHostPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-mh-policy-")
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_network_object(
            self.plane, "office-admin", type="ip", value="198.51.100.10", oneshot=True
        )
        self.plane.upsert_client(
            MID,
            label="real-e2e-al2023",
            hostname="real-e2e-al2023",
            addresses=[{"address": "10.0.19.146", "active": True}],
        )
        self.plane.set_published_service(
            MID,
            "ssh-access",
            service_type="tcp",
            target_mode="self",
            target_host="127.0.0.1",
            target_port=22,
            enabled=True,
            public_port=6011,
        )
        pub = self.plane.conn.execute(
            "SELECT id FROM published_services WHERE name = 'ssh-access'"
        ).fetchone()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO remote_service_meta"
            "(service_id, status, pool_class, service_object_id, destination_name, pending_allocation, delete_pending, reason) "
            "VALUES (?, 'HEALTHY', 'normal', ?, 'this-host', 0, 0, '')",
            (pub["id"], v24.get_service_object(self.plane, "ssh")["id"]),
        )
        self.plane.conn.commit()
        v24.ensure_policy_mode(self.plane, "remote", "whitelist", oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "office-ssh",
            mode="whitelist",
            source="office-admin",
            destination="real-e2e-al2023",
            service="ssh",
            enabled=True,
            oneshot=True,
        )

    def tearDown(self):
        self.plane.close()
        for key in ("DRLINK_CONFIRM", "FRP_DEPLOY_TEST_ROOT"):
            os.environ.pop(key, None)

    def test_REMOTE_ACCESS_MANAGED_HOST_DESTINATION(self):
        cli = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="office-admin",
            destination_name="real-e2e-al2023",
            service_name="ssh",
        )
        self.assertEqual(cli["result"], "ALLOW")
        self.assertIn("office-ssh", cli["matched_rules"])

    def test_REMOTE_ACCESS_THIS_HOST_POLICY_IDENTITY(self):
        dest = RP._destination_for_service(
            self.plane,
            {
                "client_id": MID,
                "target_mode": "self",
                "target_host": "127.0.0.1",
            },
        )
        self.assertEqual(dest, "real-e2e-al2023")
        self.assertNotEqual(dest, "127.0.0.1")
        self.assertEqual(UR.managed_host_policy_name(self.plane, MID), "real-e2e-al2023")

    def test_REMOTE_ACCESS_CLI_RUNTIME_SELECTOR_PARITY(self):
        cli = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="office-admin",
            destination_name="real-e2e-al2023",
            service_name="ssh",
        )
        proxy = RP.expected_proxy_name("real-e2e-al2023", MID, "rs-ssh-access")
        # Enrollment-style published name uses historical id when no meta rs remap...
        # ssh-access has remote_service_meta so proxy id is rs-ssh-access.
        runtime = RP.authorize_remote(
            self.plane, proxy_name=proxy, source_ip="198.51.100.10:9"
        )
        self.assertEqual(cli["result"], "ALLOW")
        self.assertEqual(runtime["decision"], RP.DECISION_ALLOW)
        self.assertEqual(runtime.get("destination"), "real-e2e-al2023")
        deny = RP.authorize_remote(
            self.plane, proxy_name=proxy, source_ip="203.0.113.9:9"
        )
        self.assertEqual(deny["decision"], RP.DECISION_DENY)

    def test_REMOTE_ACCESS_NO_LOOPBACK_WORKAROUND_REQUIRED(self):
        loop = self.plane.get_object("127.0.0.1")
        self.assertIsNone(loop)
        # Rule destination is the Managed Host, not a synthetic loopback Object.
        dests = list(
            self.plane.conn.execute(
                "SELECT o.name, o.type FROM rule_destinations d "
                "JOIN objects o ON o.id = d.ref_id JOIN policy_rules r ON r.id = d.rule_id "
                "WHERE r.name = 'office-ssh'"
            )
        )
        self.assertEqual(len(dests), 1)
        self.assertEqual(dests[0]["name"], "real-e2e-al2023")
        self.assertEqual(dests[0]["type"], "managed_endpoint")

    def test_unset_network_object_rejects_managed_host(self):
        with self.assertRaises(Exception) as ctx:
            v24.unset_network_object(self.plane, "real-e2e-al2023")
        self.assertIn("Managed Host", str(ctx.exception))

    def test_missing_host_projection_does_not_become_loopback(self):
        ep = self.plane.conn.execute(
            "SELECT o.id FROM objects o JOIN managed_endpoints e ON e.object_id = o.id "
            "WHERE e.client_id = ?",
            (MID,),
        ).fetchone()
        self.plane.conn.execute("DELETE FROM managed_endpoints WHERE object_id = ?", (ep["id"],))
        self.plane.conn.execute("DELETE FROM objects WHERE id = ?", (ep["id"],))
        self.plane.conn.commit()
        dest = RP._destination_for_service(
            self.plane,
            {"client_id": MID, "target_mode": "self", "target_host": "127.0.0.1"},
        )
        self.assertEqual(dest, "real-e2e-al2023")
        self.assertNotEqual(dest, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
