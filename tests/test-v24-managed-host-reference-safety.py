#!/usr/bin/env python3
"""Priority 8B: Managed Host cross-host Remote Service identity / name-rebinding safety."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane, ControlPlaneError
import drlink_mgmt_sync as mgmt
import drlink_v24 as v24
from drlink_v24_bundle import apply_v24_plan, prepare_v24_plan
import frp_mgmt_auth as MGMT

AGENT_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
AGENT_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
AGENT_C = "cccccccccccccccccccccccccccccccc"
HOST_A = "agent-a"
HOST_B = "database-prod"
HOST_C = "database-prod"


class ManagedHostReferenceSafety(unittest.TestCase):
    def setUp(self):
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-p8b-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-p8b-agt-")
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        Path(self.agent_tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(self.agent_tmp, "etc/frp/client-state.json").write_text(
            '{"machine_id":"%s","hostname":"%s","label":"%s"}\n' % (AGENT_A, HOST_A, HOST_A),
            encoding="utf-8",
        )
        key = Path(self.agent_tmp, "etc/frp/client-identity.key")
        pub = Path(self.agent_tmp, "etc/frp/client-identity.pub")
        MGMT.generate_keypair(key, pub)
        os.chmod(key, 0o600)
        mac = MGMT.new_mac_key()
        mac_path = Path(self.agent_tmp, "etc/frp/client-identity.mac")
        mac_path.write_text(mac, encoding="utf-8")
        os.chmod(mac_path, 0o600)
        Path(self.agent_tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_FAULT_ACTIVATION", None)
        os.environ.pop("DRLINK_MGMT_TOKEN", None)
        os.environ.pop("DRLINK_SERVER_REACHABLE", None)
        self.server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(self.server.conn)
        self.agent = ControlPlane(self.agent_tmp)
        v24.ensure_v2_schema(self.agent.conn)
        for plane in (self.server, self.agent):
            v24.set_service_object(plane, "ssh", type="tcp", port=22, oneshot=True)
            v24.set_service_object(plane, "https", type="tcp", port=443, oneshot=True)
        self.server.upsert_client(
            AGENT_A,
            label=HOST_A,
            hostname=HOST_A,
            addresses=[{"address": "10.0.0.10", "active": True}],
        )
        self.server.upsert_client(
            AGENT_B,
            label=HOST_B,
            hostname="db-b.internal",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(
            AGENT_A, pub.read_text(encoding="utf-8"), mac_key=mac, hostname=HOST_A
        )
        self.httpd, self.base_url, _ = mgmt.start_mgmt_server(
            self.server, verifier=self.verifier
        )
        os.environ["DRLINK_MGMT_URL"] = self.base_url
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base_url, encoding="utf-8"
        )
        # Seed Agent catalog from Server so Managed Host destinations resolve offline-cache-like.
        catalog = mgmt.build_catalog_payload(self.server)
        mgmt.apply_catalog_to_agent(self.agent, catalog)

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.server.close()
        self.agent.close()
        for key in (
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_CONFIRM",
            "DRLINK_FAULT_ACTIVATION",
            "DRLINK_MGMT_URL",
            "DRLINK_MGMT_TOKEN",
            "DRLINK_SERVER_REACHABLE",
        ):
            os.environ.pop(key, None)

    def _agent_row(self, name: str):
        return self.agent.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()

    def _server_meta(self, name: str):
        return self.server.conn.execute(
            "SELECT s.name, s.target_host, s.public_port, m.destination_name, "
            "m.destination_client_id, m.status, m.reason "
            "FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id "
            "WHERE s.client_id = ? AND s.name = ? COLLATE NOCASE AND s.released = 0",
            (AGENT_A, name),
        ).fetchone()

    def test_stable_bind_persists_client_id_and_runtime_target(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        self.assertEqual(row["destination"], HOST_B)
        meta = self._server_meta("db-via-a")
        self.assertEqual(meta["destination_client_id"], AGENT_B)
        self.assertEqual(meta["destination_name"], HOST_B)
        # Runtime target is hostname/address, not the mutable public label alone as authority.
        self.assertIn(meta["target_host"], ("10.0.0.20", "db-b.internal"))

    def test_retirement_blocked_while_referenced(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        before_port = self._server_meta("db-via-a")["public_port"]
        with self.assertRaises(ControlPlaneError) as ctx:
            self.server.unset_managed_host(HOST_B, confirm=True)
        text = str(ctx.exception).lower()
        self.assertIn("still referenced", text)
        self.assertIn("db-via-a", text)
        self.assertIsNotNone(self.server.get_client(AGENT_B))
        meta = self._server_meta("db-via-a")
        self.assertEqual(meta["destination_client_id"], AGENT_B)
        self.assertEqual(meta["public_port"], before_port)

    def test_disabled_remote_service_still_blocks_retirement(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=False,
                oneshot=True,
                root=self.agent_tmp,
            )
        row = self._agent_row("db-via-a")
        self.assertEqual(row["status"], "DISABLED")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        with self.assertRaises(ControlPlaneError) as ctx:
            self.server.unset_managed_host(HOST_B, confirm=True)
        self.assertIn("still referenced", str(ctx.exception).lower())
        self.assertIsNotNone(self.server.get_client(AGENT_B))

    def test_label_rename_same_identity(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        before = self._server_meta("db-via-a")
        self.server.set_client_label(AGENT_B, "database-prod-renamed")
        catalog = mgmt.build_catalog_payload(self.server)
        mgmt.apply_catalog_to_agent(self.agent, catalog)
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination="database-prod",
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        self.assertEqual(row["destination"], "database-prod-renamed")
        meta = self._server_meta("db-via-a")
        self.assertEqual(meta["destination_client_id"], AGENT_B)
        self.assertEqual(meta["public_port"], before["public_port"])

    def test_hostname_update_same_identity(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        before = self._server_meta("db-via-a")
        self.server.upsert_client(
            AGENT_B,
            label=HOST_B,
            hostname="db-b-new.internal",
            addresses=[{"address": "10.0.0.21", "active": True}],
        )
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.synchronize_agent_remote_services(self.agent, root=self.agent_tmp)
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        meta = self._server_meta("db-via-a")
        self.assertEqual(meta["destination_client_id"], AGENT_B)
        self.assertEqual(meta["public_port"], before["public_port"])
        self.assertIn(meta["target_host"], ("10.0.0.21", "db-b-new.internal"))

    def test_missing_bound_identity_degraded(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        # Drop B from Agent catalog only; keep Server row (FK-safe) so the bind
        # remains but local inventory can no longer resolve it.
        self.agent.conn.execute("DELETE FROM agent_object_catalog")
        self.agent.conn.commit()
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            with mock.patch(
                "drlink_v24.sync_agent_catalog_from_server", return_value=0
            ):
                v24.set_remote_service_agent(
                    self.agent,
                    "db-via-a",
                    service="ssh",
                    enabled=True,
                    oneshot=True,
                    root=self.agent_tmp,
                )
        row = self._agent_row("db-via-a")
        self.assertIsNotNone(row)
        self.assertEqual(row["destination_client_id"], AGENT_B)
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("missing", (row["reason"] or "").lower())

    def test_offline_cached_catalog_binds_client_id(self):
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        v24.set_remote_service_agent(
            self.agent,
            "db-via-a",
            destination=HOST_B,
            service="ssh",
            enabled=True,
            oneshot=True,
            root=self.agent_tmp,
            server_reachable=False,
        )
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        self.assertEqual(row["status"], "DEGRADED")

    def test_name_reuse_cannot_rebind(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        # Simulate damaged/missing B1 inventory on the Agent while C1 appears
        # under the same public name. Bound client_id must not follow the label.
        self.agent.conn.execute("DELETE FROM agent_object_catalog")
        self.agent.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) "
            "VALUES ('managed-host', ?, ?, datetime('now'))",
            (
                HOST_C,
                json.dumps(
                    {
                        "id": AGENT_C,
                        "name": HOST_C,
                        "hostname": "db-c.internal",
                        "addresses": ["10.0.0.30"],
                        "connected": True,
                    }
                ),
            ),
        )
        self.agent.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) "
            "VALUES ('network-object', ?, ?, datetime('now'))",
            (
                HOST_C,
                json.dumps(
                    {
                        "name": HOST_C,
                        "type": "managed_endpoint",
                        "client_id": AGENT_C,
                        "values": ["10.0.0.30"],
                        "addresses": ["10.0.0.30"],
                    }
                ),
            ),
        )
        self.agent.conn.commit()
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            with mock.patch(
                "drlink_v24.sync_agent_catalog_from_server", return_value=0
            ):
                v24.set_remote_service_agent(
                    self.agent,
                    "db-via-a",
                    destination="database-prod",
                    service="ssh",
                    enabled=True,
                    oneshot=True,
                    root=self.agent_tmp,
                )
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        self.assertNotEqual(row["destination_client_id"], AGENT_C)
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("missing", (row["reason"] or "").lower())

    def test_stale_catalog_after_server_change_refuses_rebind(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        # Stale Agent catalog still names B under database-prod, while a same-name
        # C exists only as an alternate catalog row that must not capture the bind.
        self.agent.conn.execute("DELETE FROM agent_object_catalog")
        self.agent.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) "
            "VALUES ('managed-host', ?, ?, datetime('now'))",
            (
                HOST_B,
                json.dumps(
                    {
                        "id": AGENT_C,
                        "name": HOST_B,
                        "hostname": "db-c.internal",
                        "addresses": ["10.0.0.30"],
                        "connected": True,
                    }
                ),
            ),
        )
        self.agent.conn.commit()
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            with mock.patch(
                "drlink_v24.sync_agent_catalog_from_server", return_value=0
            ):
                # Force missing B1 inventory while public name maps to C1 in catalog.
                with mock.patch(
                    "drlink_v24._managed_host_inventory_by_client_id",
                    side_effect=lambda plane, cid: (
                        None
                        if cid == AGENT_B
                        else {
                            "id": AGENT_C,
                            "name": HOST_B,
                            "hostname": "db-c.internal",
                            "addresses": ["10.0.0.30"],
                            "connected": True,
                            "source": "catalog",
                        }
                    ),
                ):
                    result = v24.synchronize_agent_remote_services(
                        self.agent, root=self.agent_tmp
                    )
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        self.assertNotEqual(row["destination_client_id"], AGENT_C)
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIsInstance(result, dict)

    def test_explicit_operator_retarget(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        self.server.upsert_client(
            AGENT_C,
            label="database-other",
            hostname="db-c.internal",
            addresses=[{"address": "10.0.0.30", "active": True}],
        )
        catalog = mgmt.build_catalog_payload(self.server)
        mgmt.apply_catalog_to_agent(self.agent, catalog)
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination="database-other",
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_C)
        meta = self._server_meta("db-via-a")
        self.assertEqual(meta["destination_client_id"], AGENT_C)
        self.assertIn(meta["target_host"], ("10.0.0.30", "db-c.internal"))

    def test_bundle_parity_bind_and_omit(self):
        yaml_text = """configurationBundle:
  context: agent
  remoteServices:
    - name: db-via-a
      destination: database-prod
      service: ssh
      enabled: true
"""
        plan = prepare_v24_plan(self.agent, yaml_text)
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            apply_v24_plan(self.agent, plan, confirm=True)
        row = self._agent_row("db-via-a")
        self.assertEqual(row["destination_client_id"], AGENT_B)
        # Omitted destination on API edit leaves the immutable identity unchanged.
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        row2 = self._agent_row("db-via-a")
        self.assertEqual(row2["destination_client_id"], AGENT_B)
        # Explicit Bundle destination edit retargets atomically.
        self.server.upsert_client(
            AGENT_C,
            label="database-other",
            hostname="db-c.internal",
            addresses=[{"address": "10.0.0.30", "active": True}],
        )
        catalog = mgmt.build_catalog_payload(self.server)
        mgmt.apply_catalog_to_agent(self.agent, catalog)
        yaml_retarget = """configurationBundle:
  context: agent
  remoteServices:
    - name: db-via-a
      destination: database-other
      service: ssh
      enabled: true
"""
        plan2 = prepare_v24_plan(self.agent, yaml_retarget)
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            apply_v24_plan(self.agent, plan2, confirm=True)
        row3 = self._agent_row("db-via-a")
        self.assertEqual(row3["destination_client_id"], AGENT_C)

    def test_duplicate_identity_safe_after_label_rename(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination=HOST_B,
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        self.server.set_client_label(AGENT_B, "database-prod-renamed")
        catalog = mgmt.build_catalog_payload(self.server)
        mgmt.apply_catalog_to_agent(self.agent, catalog)
        with self.assertRaises(ControlPlaneError) as ctx:
            with mock.patch("drlink_v24._probe_tcp", return_value=True):
                v24.set_remote_service_agent(
                    self.agent,
                    "db-via-a-dup",
                    destination="database-prod-renamed",
                    service="ssh",
                    enabled=True,
                    oneshot=True,
                    root=self.agent_tmp,
                )
        self.assertIn("already exists", str(ctx.exception).lower())

    def test_self_this_host_unchanged(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "local-ssh",
                destination="this-host",
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        row = self._agent_row("local-ssh")
        self.assertEqual(row["destination_client_id"], AGENT_A)
        meta = self._server_meta("local-ssh")
        self.assertEqual(meta["target_host"], "127.0.0.1")

    def test_non_managed_ip_destination_unchanged(self):
        v24.set_network_object(
            self.server, "leaf", type="ip", value="198.51.100.50", oneshot=True
        )
        catalog = mgmt.build_catalog_payload(self.server)
        mgmt.apply_catalog_to_agent(self.agent, catalog)
        # Also create on agent for local resolve in non-live paths.
        v24.set_network_object(
            self.agent, "leaf", type="ip", value="198.51.100.50", oneshot=True
        )
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "to-leaf",
                destination="leaf",
                service="https",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        row = self._agent_row("to-leaf")
        self.assertIsNone(row["destination_client_id"])
        meta = self._server_meta("to-leaf")
        self.assertEqual(meta["target_host"], "198.51.100.50")
        self.assertIsNone(meta["destination_client_id"])


if __name__ == "__main__":
    unittest.main()
