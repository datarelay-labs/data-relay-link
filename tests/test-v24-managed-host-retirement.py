#!/usr/bin/env python3
"""Packet 4: Managed Host retirement lifecycle.

Canonical `unset managed-host <HOST>` must complete server-side retirement:
reference-safe rejection, cleanup of published services / port reservations /
endpoint inventory / trust state, and impact confirmation. No raw FK failures.
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

MID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MID2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
MID3 = "cccccccccccccccccccccccccccccccc"


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


class ManagedHostRetirement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-mh-retire-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

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

    def _seed_host(
        self,
        client_id: str,
        label: str,
        *,
        with_service: bool = False,
        connected: bool = True,
        trust: str = "trusted",
    ):
        self.plane.upsert_client(
            client_id,
            label=label,
            hostname=label,
            connected=connected,
            addresses=[{"address": "10.0.0.5", "active": True}],
        )
        if trust != "trusted" or not connected:
            self.plane.conn.execute(
                "UPDATE clients SET trust_status = ?, connected = ? WHERE id = ?",
                (trust, 1 if connected else 0, client_id),
            )
            self.plane.conn.commit()
        if with_service:
            v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
            self.plane.set_published_service(
                client_id,
                "ssh-access",
                service_type="tcp",
                target_mode="self",
                target_host="127.0.0.1",
                target_port=22,
                enabled=True,
                public_port=6011,
            )
            pub = self.plane.conn.execute(
                "SELECT id FROM published_services WHERE client_id = ? AND name = 'ssh-access'",
                (client_id,),
            ).fetchone()
            self.plane.conn.execute(
                "INSERT OR REPLACE INTO remote_service_meta"
                "(service_id, status, pool_class, service_object_id, destination_name, "
                "pending_allocation, delete_pending, reason) "
                "VALUES (?, 'HEALTHY', 'normal', ?, 'this-host', 0, 0, '')",
                (pub["id"], v24.get_service_object(self.plane, "ssh")["id"]),
            )
            # Ensure an active reservation row exists even if allocator skipped insert.
            self.plane.conn.execute(
                "INSERT OR REPLACE INTO port_reservations"
                "(public_port, client_id, service_id, service_name, released, created_at) "
                "VALUES (6011, ?, ?, 'ssh-access', 0, datetime('now'))",
                (client_id, pub["id"]),
            )
            self.plane.conn.commit()

    def test_unreferenced_managed_host_removed(self):
        self._seed_host(MID, "ubuntu-prod")
        rc, out, err = self._dispatch(["unset", "managed-host", "ubuntu-prod"])
        self.assertEqual(rc, 0, err or out)
        self.assertIn("Managed Host removed", out)
        self.assertIsNone(self.plane.get_client("ubuntu-prod"))
        self.assertIsNone(self.plane.get_object("ubuntu-prod"))

    def test_managed_host_with_remote_services_and_reservations_cleaned(self):
        self._seed_host(MID, "ubuntu-prod", with_service=True)
        rc, out, err = self._dispatch(["unset", "managed-host", "ubuntu-prod"])
        self.assertEqual(rc, 0, err or out)
        self.assertIsNone(self.plane.get_client(MID))
        pubs = list(
            self.plane.conn.execute(
                "SELECT id FROM published_services WHERE client_id = ?", (MID,)
            )
        )
        self.assertEqual(pubs, [])
        active = list(
            self.plane.conn.execute(
                "SELECT public_port FROM port_reservations WHERE client_id = ? AND released = 0",
                (MID,),
            )
        )
        self.assertEqual(active, [])
        released = list(
            self.plane.conn.execute(
                "SELECT public_port, released FROM port_reservations WHERE public_port = 6011"
            )
        )
        self.assertTrue(released)
        self.assertEqual(int(released[0]["released"]), 1)
        meta = list(self.plane.conn.execute("SELECT * FROM remote_service_meta"))
        self.assertEqual(meta, [])

    def test_referenced_managed_host_rejected(self):
        self._seed_host(MID, "ubuntu-prod")
        v24.set_network_object(self.plane, "office", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "to-prod",
            mode="whitelist",
            source="office",
            destination="ubuntu-prod",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        rc, out, err = self._dispatch(["unset", "managed-host", "ubuntu-prod"])
        self.assertNotEqual(rc, 0)
        text = (err or out).lower()
        self.assertIn("still referenced", text)
        self.assertIn("remote access", text)
        self.assertIsNotNone(self.plane.get_client("ubuntu-prod"))
        self.assertNotIn("foreign key", text)

    def test_disconnected_revoked_host_removed(self):
        self._seed_host(
            MID2, "stale-host", connected=False, trust="revoked", with_service=True
        )
        rc, out, err = self._dispatch(["unset", "managed-host", "stale-host"])
        self.assertEqual(rc, 0, err or out)
        self.assertIsNone(self.plane.get_client(MID2))
        active = list(
            self.plane.conn.execute(
                "SELECT public_port FROM port_reservations WHERE client_id = ? AND released = 0",
                (MID2,),
            )
        )
        self.assertEqual(active, [])

    def test_no_orphan_reservation_or_trust_residue(self):
        self._seed_host(MID3, "clean-me", with_service=True)
        self.plane.set_client_tag(MID3, "env", "lab")
        self.plane.set_client_group("fleet")
        self.plane.set_client_group_member("fleet", MID3)
        self.plane.unset_managed_host("clean-me", confirm=True)
        self.assertIsNone(self.plane.get_client(MID3))
        self.assertIsNone(self.plane.get_object("clean-me"))
        self.assertEqual(
            list(
                self.plane.conn.execute(
                    "SELECT * FROM published_services WHERE client_id = ?", (MID3,)
                )
            ),
            [],
        )
        self.assertEqual(
            list(
                self.plane.conn.execute(
                    "SELECT * FROM port_reservations WHERE client_id = ? AND released = 0",
                    (MID3,),
                )
            ),
            [],
        )
        self.assertEqual(
            list(
                self.plane.conn.execute(
                    "SELECT * FROM client_tags WHERE client_id = ?", (MID3,)
                )
            ),
            [],
        )
        self.assertEqual(
            list(
                self.plane.conn.execute(
                    "SELECT * FROM client_group_members WHERE client_id = ?", (MID3,)
                )
            ),
            [],
        )
        # Group may remain empty; no client membership residue.
        self.assertIsNotNone(
            self.plane.conn.execute(
                "SELECT id FROM client_groups WHERE name = 'fleet'"
            ).fetchone()
        )

    def test_cancelled_confirmation_leaves_host_unchanged(self):
        self._seed_host(MID, "ubuntu-prod", with_service=True)
        os.environ.pop("DRLINK_CONFIRM", None)
        rev_before = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            self.plane.unset_managed_host("ubuntu-prod")
        self.assertTrue(ctx.exception.impact.get("requires_confirmation"))
        self.assertEqual(ctx.exception.impact.get("kind"), "managed-host-retire")
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertIsNotNone(self.plane.get_client("ubuntu-prod"))
        self.assertTrue(
            list(
                self.plane.conn.execute(
                    "SELECT id FROM published_services WHERE client_id = ?", (MID,)
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
