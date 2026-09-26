#!/usr/bin/env python3
"""P0: Agent↔Server Remote Service distributed atomicity / inverse-state compensation."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane
import drlink_mgmt_sync as mgmt
import drlink_v24 as v24
from drlink_v24_bundle import apply_v24_plan, prepare_v24_plan
import frp_mgmt_auth as MGMT


MACHINE = "aabbccddeeff00112233445566778899"
HOST = "branch-gateway"


class RemoteServiceDistributedAtomicity(unittest.TestCase):
    def setUp(self):
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-rs-atom-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-rs-atom-agt-")
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        Path(self.agent_tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(self.agent_tmp, "etc/frp/client-state.json").write_text(
            '{"machine_id":"%s","hostname":"%s","label":"%s"}\n' % (MACHINE, HOST, HOST),
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
            v24.set_service_object(plane, "db-fixed", type="fixed-tcp", port=1521, oneshot=True)
        self.server.upsert_client(MACHINE, label=HOST, hostname=HOST)
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(
            MACHINE, pub.read_text(encoding="utf-8"), mac_key=mac, hostname=HOST
        )
        self.httpd, self.base_url, _ = mgmt.start_mgmt_server(
            self.server, verifier=self.verifier
        )
        os.environ["DRLINK_MGMT_URL"] = self.base_url
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base_url, encoding="utf-8"
        )

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

    def _server_pub(self, name: str):
        return self.server.conn.execute(
            "SELECT s.name, s.target_port, s.enabled, s.released, s.public_port, "
            "m.status, m.destination_name, so.name AS service_name "
            "FROM published_services s "
            "LEFT JOIN remote_service_meta m ON m.service_id = s.id "
            "LEFT JOIN service_objects so ON so.id = m.service_object_id "
            "WHERE s.client_id = ? AND s.name = ? COLLATE NOCASE "
            "ORDER BY s.released ASC, s.updated_at DESC",
            (MACHINE, name),
        ).fetchone()

    def _create(self, name="svc", service="ssh"):
        return v24.set_remote_service_agent(
            self.agent,
            name,
            destination="this-host",
            service=service,
            enabled=True,
            oneshot=True,
            root=self.agent_tmp,
            server_reachable=True,
        )

    def test_direct_create_activation_failure_no_orphan_server(self):
        os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
        os.environ["DRLINK_FAULT_ACTIVATION"] = "1"
        with self.assertRaises(ControlPlaneError) as ctx:
            self._create("svc-create")
        msg = str(ctx.exception)
        self.assertIn("Previous configuration was restored", msg)
        self.assertIn("No configuration changes remain active", msg)
        self.assertNotIn("RECOVERY_REQUIRED", msg)
        self.assertIsNone(
            self.agent.conn.execute(
                "SELECT 1 FROM agent_remote_services WHERE name = 'svc-create'"
            ).fetchone()
        )
        pub = self._server_pub("svc-create")
        self.assertTrue(pub is None or int(pub["released"] or 0) == 1)

    def test_direct_update_activation_failure_restores_prior_server(self):
        created = self._create("svc")
        prior_port = int(created["view"]["endpoint_port"])
        before = self._server_pub("svc")
        self.assertEqual(int(before["target_port"]), 22)
        self.assertEqual(int(before["public_port"]), prior_port)

        os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
        os.environ["DRLINK_FAULT_ACTIVATION"] = "1"
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_remote_service_agent(
                self.agent,
                "svc",
                destination="this-host",
                service="https",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
                server_reachable=True,
            )
        msg = str(ctx.exception)
        self.assertIn("Previous configuration was restored", msg)
        self.assertIn("No configuration changes remain active", msg)
        self.assertNotIn("RECOVERY_REQUIRED", msg)

        local = self.agent.conn.execute(
            "SELECT service_object, endpoint_port, status FROM agent_remote_services WHERE name = 'svc'"
        ).fetchone()
        self.assertEqual(local["service_object"], "ssh")
        self.assertEqual(int(local["endpoint_port"]), prior_port)

        after = self._server_pub("svc")
        self.assertEqual(int(after["released"] or 0), 0)
        self.assertEqual(int(after["target_port"]), 22)
        self.assertEqual(after["service_name"], "ssh")
        self.assertEqual(int(after["public_port"]), prior_port)

    def test_direct_delete_activation_failure_restores_server(self):
        created = self._create("svc-del")
        prior_port = int(created["view"]["endpoint_port"])
        os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
        os.environ["DRLINK_FAULT_ACTIVATION"] = "1"
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.unset_remote_service_agent(
                self.agent, "svc-del", root=self.agent_tmp, server_reachable=True
            )
        msg = str(ctx.exception)
        self.assertIn("Previous configuration was restored", msg)
        self.assertIn("No configuration changes remain active", msg)

        local = self.agent.conn.execute(
            "SELECT service_object, endpoint_port FROM agent_remote_services WHERE name = 'svc-del'"
        ).fetchone()
        self.assertIsNotNone(local)
        self.assertEqual(local["service_object"], "ssh")
        self.assertEqual(int(local["endpoint_port"]), prior_port)

        after = self._server_pub("svc-del")
        self.assertEqual(int(after["released"] or 0), 0)
        self.assertEqual(int(after["target_port"]), 22)
        self.assertEqual(int(after["public_port"]), prior_port)

    def test_bundle_update_activation_failure_restores_prior_server(self):
        created = self._create("svc")
        prior_port = int(created["view"]["endpoint_port"])
        yaml_text = """configurationBundle:
  context: agent
  remoteServices:
    - name: svc
      destination: this-host
      service: https
      enabled: true
"""
        plan = prepare_v24_plan(self.agent, yaml_text)
        with mock.patch(
            "drlink_v24_runtime.apply_agent_runtime",
            return_value={"ok": False, "error": "injected runtime failure"},
        ):
            os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
            with self.assertRaises(ControlPlaneError) as ctx:
                apply_v24_plan(self.agent, plan, confirm=True)
        msg = str(ctx.exception)
        self.assertIn("Previous configuration was restored", msg)
        self.assertIn("No configuration changes remain active", msg)

        local = self.agent.conn.execute(
            "SELECT service_object, endpoint_port FROM agent_remote_services WHERE name = 'svc'"
        ).fetchone()
        self.assertEqual(local["service_object"], "ssh")
        self.assertEqual(int(local["endpoint_port"]), prior_port)
        after = self._server_pub("svc")
        self.assertEqual(int(after["released"] or 0), 0)
        self.assertEqual(int(after["target_port"]), 22)
        self.assertEqual(int(after["public_port"]), prior_port)

    def test_bundle_delete_activation_failure_restores_server(self):
        created = self._create("svc")
        prior_port = int(created["view"]["endpoint_port"])
        yaml_text = """configurationBundle:
  context: agent
  remoteServices:
    - name: svc
      state: absent
"""
        plan = prepare_v24_plan(self.agent, yaml_text)
        with mock.patch(
            "drlink_v24_runtime.apply_agent_runtime",
            return_value={"ok": False, "error": "injected runtime failure"},
        ):
            os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
            with self.assertRaises(ControlPlaneError) as ctx:
                apply_v24_plan(self.agent, plan, confirm=True)
        msg = str(ctx.exception)
        self.assertIn("Previous configuration was restored", msg)
        self.assertIn("No configuration changes remain active", msg)

        local = self.agent.conn.execute(
            "SELECT service_object, endpoint_port FROM agent_remote_services WHERE name = 'svc'"
        ).fetchone()
        self.assertIsNotNone(local)
        self.assertEqual(int(local["endpoint_port"]), prior_port)
        after = self._server_pub("svc")
        self.assertEqual(int(after["released"] or 0), 0)
        self.assertEqual(int(after["public_port"]), prior_port)

    def test_compensation_failure_reports_recovery_required(self):
        self._create("svc")
        os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
        os.environ["DRLINK_FAULT_ACTIVATION"] = "1"
        with mock.patch(
            "drlink_mgmt_sync.upsert_remote_service_on_server",
            side_effect=[
                # first call is the UPDATE mutation
                {
                    "endpoint_host": "127.0.0.1",
                    "endpoint_port": 6001,
                    "pending_allocation": 0,
                    "status": "DEGRADED",
                    "reason": "Runtime activation pending.",
                },
                # compensation upsert must fail
                Exception("injected compensation failure"),
            ],
        ):
            with self.assertRaises(ControlPlaneError) as ctx:
                v24.set_remote_service_agent(
                    self.agent,
                    "svc",
                    destination="this-host",
                    service="https",
                    enabled=True,
                    oneshot=True,
                    root=self.agent_tmp,
                    server_reachable=True,
                )
        msg = str(ctx.exception)
        self.assertIn("RECOVERY_REQUIRED", msg)
        self.assertIn("PARTIAL", msg)
        self.assertNotIn("No configuration changes remain active", msg)

    def test_successful_create_update_delete_unchanged(self):
        created = self._create("svc-ok")
        port = int(created["view"]["endpoint_port"])
        self.assertEqual(created["view"]["status"], "HEALTHY")
        self.assertEqual(int(self._server_pub("svc-ok")["target_port"]), 22)

        updated = v24.set_remote_service_agent(
            self.agent,
            "svc-ok",
            destination="this-host",
            service="https",
            enabled=True,
            oneshot=True,
            root=self.agent_tmp,
            server_reachable=True,
        )
        self.assertEqual(updated["view"]["status"], "HEALTHY")
        self.assertEqual(int(updated["view"]["endpoint_port"]), port)
        self.assertEqual(int(self._server_pub("svc-ok")["target_port"]), 443)

        v24.unset_remote_service_agent(
            self.agent, "svc-ok", root=self.agent_tmp, server_reachable=True
        )
        self.assertIsNone(
            self.agent.conn.execute(
                "SELECT 1 FROM agent_remote_services WHERE name = 'svc-ok'"
            ).fetchone()
        )
        pub = self._server_pub("svc-ok")
        self.assertTrue(pub is None or int(pub["released"] or 0) == 1)

    def test_offline_create_edit_delete_intact(self):
        os.environ.pop("DRLINK_MGMT_URL", None)
        result = v24.set_remote_service_agent(
            self.agent,
            "offline-svc",
            destination="this-host",
            service="ssh",
            enabled=True,
            oneshot=True,
            root=self.agent_tmp,
            server_reachable=False,
        )
        self.assertEqual(result["view"]["status"], "DEGRADED")
        self.assertIn("unreachable", (result["view"]["reason"] or "").lower())
        v24.set_remote_service_agent(
            self.agent,
            "offline-svc",
            destination="this-host",
            service="https",
            enabled=True,
            oneshot=True,
            root=self.agent_tmp,
            server_reachable=False,
        )
        local = self.agent.conn.execute(
            "SELECT service_object FROM agent_remote_services WHERE name = 'offline-svc'"
        ).fetchone()
        self.assertEqual(local["service_object"], "https")
        v24.unset_remote_service_agent(
            self.agent, "offline-svc", root=self.agent_tmp, server_reachable=False
        )
        tomb = self.agent.conn.execute(
            "SELECT delete_pending FROM agent_remote_services WHERE name = 'offline-svc'"
        ).fetchone()
        self.assertIsNotNone(tomb)
        self.assertEqual(int(tomb["delete_pending"]), 1)

    def test_fixed_tcp_endpoint_pool_unchanged(self):
        created = self._create("fixed-svc", service="db-fixed")
        self.assertIsNotNone(created["view"]["endpoint_port"])
        pub = self._server_pub("fixed-svc")
        self.assertEqual(int(pub["released"] or 0), 0)
        self.assertEqual(int(pub["target_port"]), 1521)
        meta = self.server.conn.execute(
            "SELECT pool_class FROM remote_service_meta m "
            "JOIN published_services s ON s.id = m.service_id "
            "WHERE s.name = 'fixed-svc' AND s.released = 0"
        ).fetchone()
        self.assertEqual(meta["pool_class"], "fixed-tcp")


if __name__ == "__main__":
    unittest.main()
