#!/usr/bin/env python3
"""Agent DEGRADED / runtime failure must converge on Server inventory."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
import drlink_control_cli as cli
import drlink_mgmt_sync as mgmt
import drlink_v24 as v24
import frp_mgmt_auth as MGMT

MACHINE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _write_identity(root: Path, machine_id: str, hostname: str):
    frp = root / "etc/frp"
    frp.mkdir(parents=True, exist_ok=True)
    (frp / "client-state.json").write_text(
        json.dumps(
            {"machine_id": machine_id, "hostname": hostname, "label": hostname},
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (frp / "frpc.toml").write_text("[common]\n", encoding="utf-8")
    key = frp / "client-identity.key"
    pub = frp / "client-identity.pub"
    MGMT.generate_keypair(key, pub)
    os.chmod(key, 0o600)
    mac = MGMT.new_mac_key()
    mac_path = frp / "client-identity.mac"
    mac_path.write_text(mac, encoding="utf-8")
    os.chmod(mac_path, 0o600)
    return key, pub.read_text(encoding="utf-8"), mac


class StatusParityTests(unittest.TestCase):
    def setUp(self):
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-status-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-status-agt-")
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_MGMT_TOKEN", None)
        self.server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(self.server.conn)
        v24.set_service_object(self.server, "ssh", type="tcp", port=22, oneshot=True)
        self.key, self.pub, self.mac = _write_identity(Path(self.agent_tmp), MACHINE, "agent-a")
        self.server.upsert_client(MACHINE, label="agent-a", hostname="agent-a")
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(MACHINE, self.pub, mac_key=self.mac, hostname="agent-a")
        self.httpd, self.base, _ = mgmt.start_mgmt_server(self.server, verifier=self.verifier)
        os.environ["DRLINK_MGMT_URL"] = self.base
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base, encoding="utf-8"
        )
        self.agent = ControlPlane(self.agent_tmp)
        v24.ensure_v2_schema(self.agent.conn)

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.server.close()
        self.agent.close()
        for key in ("DRLINK_SKIP_ACTIVATION", "DRLINK_CONFIRM", "DRLINK_MGMT_URL"):
            os.environ.pop(key, None)

    def _server_status(self, name: str):
        return self.server.conn.execute(
            "SELECT m.status, m.reason, s.public_port FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id WHERE s.name = ?",
            (name,),
        ).fetchone()

    def test_AGENT_DEGRADED_PROPAGATES_TO_SERVER(self):
        created = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            runtime_verified=True,
        )
        self.assertEqual(created["status"], "HEALTHY")
        reported = mgmt.report_remote_service_status_on_server(
            root=self.agent_tmp,
            services=[
                {
                    "name": "ssh-access",
                    "status": "DEGRADED",
                    "reason": "Required Network Object / Managed Host destination 'db-prod' is missing or invalid after reconnect.",
                    "runtime_verified": False,
                }
            ],
        )
        self.assertEqual(reported["count"], 1)
        row = self._server_status("ssh-access")
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("db-prod", row["reason"])

    def test_AGENT_RUNTIME_FAILURE_PROPAGATES_TO_SERVER(self):
        mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            runtime_verified=True,
        )
        mgmt.report_remote_service_status_on_server(
            root=self.agent_tmp,
            services=[
                {
                    "name": "ssh-access",
                    "status": "DEGRADED",
                    "reason": "Runtime activation failed",
                    "runtime_verified": False,
                    "runtime_generation": 4,
                }
            ],
        )
        row = self._server_status("ssh-access")
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("Runtime activation failed", row["reason"])

    def test_SERVER_NEVER_HEALTHY_WITH_MISSING_RUNTIME(self):
        created = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            runtime_verified=False,
        )
        self.assertEqual(created["status"], "DEGRADED")
        # A bare HEALTHY claim without runtime_verified must not be accepted.
        mgmt.report_remote_service_status_on_server(
            root=self.agent_tmp,
            services=[
                {
                    "name": "ssh-access",
                    "status": "HEALTHY",
                    "reason": "",
                    "runtime_verified": False,
                }
            ],
        )
        row = self._server_status("ssh-access")
        self.assertNotEqual(row["status"], "HEALTHY")

    def test_SERVER_AGENT_STATUS_CONVERGENCE_AFTER_SYNC(self):
        mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            runtime_verified=True,
        )
        now = "2026-09-18T00:00:00Z"
        self.agent.conn.execute(
            "INSERT INTO agent_remote_services"
            "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
            "pending_allocation, delete_pending, pool_class, reason, updated_at) "
            "VALUES ('ssh-access', 'this-host', 'ssh', 1, 'DEGRADED', 'drlink.local', 6012, 0, 0, 'normal', "
            "'Required Service Object is missing or invalid after reconnect.', ?)",
            (now,),
        )
        self.agent.conn.commit()
        v24._push_agent_remote_service_status(self.agent, root=self.agent_tmp)
        row = self._server_status("ssh-access")
        self.assertEqual(row["status"], "DEGRADED")

    def test_DEPENDENCY_RESTORED_RECOVERS_TO_HEALTHY(self):
        created = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            runtime_verified=True,
        )
        mgmt.report_remote_service_status_on_server(
            root=self.agent_tmp,
            services=[
                {
                    "name": "ssh-access",
                    "status": "DEGRADED",
                    "reason": "Runtime activation failed",
                    "runtime_verified": False,
                }
            ],
        )
        self.assertEqual(self._server_status("ssh-access")["status"], "DEGRADED")
        acked = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            preserve_endpoint_port=created["endpoint_port"],
            runtime_verified=True,
        )
        self.assertEqual(acked["status"], "HEALTHY")
        self.assertEqual(acked["endpoint_port"], created["endpoint_port"])
        self.assertEqual(self._server_status("ssh-access")["status"], "HEALTHY")


ROCKY8 = "ddddddddddddddddddddddddddddddd1"


class StaleEndpointTruthTests(unittest.TestCase):
    def setUp(self):
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-stale-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-stale-agt-")
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_MGMT_TOKEN", None)
        self.server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(self.server.conn)
        v24.set_service_object(self.server, "ssh", type="tcp", port=22, oneshot=True)
        self.key, self.pub, self.mac = _write_identity(Path(self.agent_tmp), MACHINE, "agent-a")
        self.server.upsert_client(MACHINE, label="agent-a", hostname="agent-a")
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(MACHINE, self.pub, mac_key=self.mac, hostname="agent-a")
        self.httpd, self.base, _ = mgmt.start_mgmt_server(self.server, verifier=self.verifier)
        os.environ["DRLINK_MGMT_URL"] = self.base
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base, encoding="utf-8"
        )
        self.agent = ControlPlane(self.agent_tmp)
        v24.ensure_v2_schema(self.agent.conn)

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.server.close()
        self.agent.close()
        for key in ("DRLINK_SKIP_ACTIVATION", "DRLINK_CONFIRM", "DRLINK_MGMT_URL"):
            os.environ.pop(key, None)

    def _write_registry(self, clients: dict, reserved=None):
        path = Path(self.server_tmp) / "var/lib/drlink/runtime/client-inventory.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "clients": clients,
                    "reserved": list(reserved or []),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def _seed_server_service(self, name, destination, port, status="DEGRADED"):
        now = "2026-09-18T00:00:00Z"
        self.server.set_published_service(
            MACHINE,
            name,
            service_type="tcp",
            target_mode="routed" if destination not in ("this-host", "this_host", "self") else "self",
            target_host="127.0.0.1",
            target_port=22,
            enabled=True,
            public_port=port,
        )
        pub = self.server.conn.execute(
            "SELECT id FROM published_services WHERE client_id = ? AND name = ?",
            (MACHINE, name),
        ).fetchone()
        self.server.conn.execute(
            "INSERT OR REPLACE INTO remote_service_meta"
            "(service_id, status, pool_class, service_object_id, destination_name, pending_allocation, delete_pending, reason) "
            "VALUES (?, ?, 'normal', ?, ?, 0, 0, ?)",
            (
                pub["id"],
                status,
                v24.get_service_object(self.server, "ssh")["id"],
                destination,
                "stale endpoint" if status == "DEGRADED" else "",
            ),
        )
        self.server.conn.execute(
            "INSERT OR REPLACE INTO port_reservations"
            "(public_port, client_id, service_id, service_name, released, created_at) "
            "VALUES (?, ?, ?, ?, 0, ?)",
            (port, MACHINE, pub["id"], name, now),
        )
        self.server.conn.commit()
        return pub

    def _seed_agent_service(self, name, destination, port, status="DEGRADED", pending=0):
        now = "2026-09-18T00:00:00Z"
        self.agent.conn.execute(
            "INSERT INTO agent_remote_services"
            "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
            "pending_allocation, delete_pending, pool_class, reason, updated_at) "
            "VALUES (?, ?, 'ssh', 1, ?, 'drlink.local', ?, ?, 0, 'normal', ?, ?)",
            (name, destination, status, port, pending, "stale endpoint retained locally", now),
        )
        self.agent.conn.commit()

    def _server_row(self, name):
        return self.server.conn.execute(
            "SELECT s.public_port, m.status, m.pending_allocation, m.reason FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id WHERE s.name = ? AND s.released = 0",
            (name,),
        ).fetchone()

    def _agent_row(self, name):
        return self.agent.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name = ?", (name,)
        ).fetchone()

    def _show_agent(self, name):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.dispatch(
                ["show", "remote-service", name], root=self.agent_tmp, plane=self.agent
            )
        self.assertEqual(rc, 0, buf.getvalue())
        return buf.getvalue()

    def test_STALE_ENDPOINT_SERVER_RELEASE_AND_AGENT_CLEAR(self):
        self._write_registry(
            {
                ROCKY8: {
                    "hostname": "real-e2e-rocky8",
                    "label": "real-e2e-rocky8",
                    "services": {
                        "ssh": {
                            "id": "ssh",
                            "preset": "ssh",
                            "remote_port": 6001,
                            "local_ip": "127.0.0.1",
                            "local_port": 22,
                            "enabled": True,
                        }
                    },
                }
            },
            reserved=[6001],
        )
        self._seed_server_service("e2e-net", "db-prod", 6001)
        self._seed_agent_service("e2e-net", "db-prod", 6001)
        before_ports = {
            r[0]
            for r in self.server.conn.execute(
                "SELECT public_port FROM port_reservations WHERE released = 0"
            )
        }
        v24._push_agent_remote_service_status(self.agent, root=self.agent_tmp)
        server = self._server_row("e2e-net")
        self.assertEqual(server["status"], "DEGRADED")
        self.assertIsNone(server["public_port"])
        self.assertEqual(int(server["pending_allocation"]), 1)
        agent = self._agent_row("e2e-net")
        self.assertEqual(agent["status"], "DEGRADED")
        self.assertIsNone(agent["endpoint_port"])
        self.assertEqual(int(agent["pending_allocation"]), 1)
        shown = self._show_agent("e2e-net")
        self.assertIn("DEGRADED", shown)
        self.assertIn("Pending allocation", shown)
        self.assertNotIn("drlink.local:6001", shown)
        after_claimed = {
            r[0]
            for r in self.server.conn.execute(
                "SELECT public_port FROM published_services WHERE released = 0 AND public_port IS NOT NULL"
            )
        }
        self.assertNotIn(6001, after_claimed)
        # Status sync must not mint a replacement while the destination is invalid.
        self.assertIsNone(self._server_row("e2e-net")["public_port"])
        self.assertEqual(before_ports, {6001})

    def test_VALID_ENDPOINT_AGENT_PRESERVE(self):
        created = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            runtime_verified=True,
        )
        port = int(created["endpoint_port"])
        self._write_registry(
            {
                MACHINE: {
                    "hostname": "agent-a",
                    "label": "agent-a",
                    "services": {
                        "ssh-access": {
                            "name": "ssh-access",
                            "remote_port": port,
                            "enabled": True,
                            "v24_remote_service": True,
                        }
                    },
                }
            },
            reserved=[port],
        )
        self._seed_agent_service("ssh-access", "this-host", port, status="HEALTHY", pending=0)
        v24._push_agent_remote_service_status(self.agent, root=self.agent_tmp)
        server = self._server_row("ssh-access")
        self.assertEqual(int(server["public_port"]), port)
        agent = self._agent_row("ssh-access")
        self.assertEqual(int(agent["endpoint_port"]), port)
        self.assertEqual(int(agent["pending_allocation"]), 0)
        shown = self._show_agent("ssh-access")
        # Port preservation is the contract under test; host display follows
        # resolve_public_endpoint_host and must not require invented drlink.local.
        self.assertIn(":%s" % port, shown)
        self.assertNotIn("Pending allocation", shown)

    def test_DEPENDENCY_INVALID_NO_REALLOCATION(self):
        self._write_registry(
            {
                ROCKY8: {
                    "hostname": "real-e2e-rocky8",
                    "services": {
                        "ssh": {"remote_port": 6001, "enabled": True, "local_port": 22}
                    },
                }
            },
            reserved=[6001],
        )
        self._seed_server_service("e2e-net", "db-prod", 6001)
        self._seed_agent_service("e2e-net", "db-prod", 6001)
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        v24.synchronize_agent_remote_services(self.agent, root=self.agent_tmp)
        server = self._server_row("e2e-net")
        self.assertEqual(server["status"], "DEGRADED")
        self.assertIsNone(server["public_port"])
        agent = self._agent_row("e2e-net")
        self.assertIsNone(agent["endpoint_port"])
        self.assertEqual(int(agent["pending_allocation"]), 1)
        claimed = list(
            self.server.conn.execute(
                "SELECT public_port FROM published_services WHERE name = 'e2e-net' "
                "AND released = 0 AND public_port IS NOT NULL"
            )
        )
        self.assertEqual(claimed, [])
        os.environ.pop("DRLINK_SERVER_REACHABLE", None)

    def test_STATUS_RECOVERY_ENDPOINT_SYNC(self):
        self._write_registry(
            {
                ROCKY8: {
                    "hostname": "real-e2e-rocky8",
                    "services": {
                        "ssh": {"remote_port": 6001, "enabled": True, "local_port": 22}
                    },
                }
            },
            reserved=[6001],
        )
        self._seed_server_service("e2e-net", "db-prod", 6001)
        self._seed_agent_service("e2e-net", "db-prod", 6001)
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        v24.synchronize_agent_remote_services(self.agent, root=self.agent_tmp)
        self.assertIsNone(self._agent_row("e2e-net")["endpoint_port"])
        v24.set_network_object(
            self.server, "db-prod", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.synchronize_agent_remote_services(self.agent, root=self.agent_tmp)
        agent = self._agent_row("e2e-net")
        self.assertIsNotNone(agent["endpoint_port"])
        self.assertNotEqual(int(agent["endpoint_port"]), 6001)
        self.assertEqual(int(agent["pending_allocation"]), 0)
        # Restored Network Object is a routed destination that is not listening.
        # Proxy registration success must not be reported as HEALTHY.
        self.assertEqual(agent["status"], "DEGRADED")
        self.assertIn("unreachable", (agent["reason"] or "").lower())
        server = self._server_row("e2e-net")
        self.assertEqual(int(server["public_port"]), int(agent["endpoint_port"]))
        self.assertEqual(server["status"], "DEGRADED")
        shown = self._show_agent("e2e-net")
        self.assertIn("DEGRADED", shown)
        endpoint_host = str(agent["endpoint_host"] or "").strip()
        self.assertTrue(endpoint_host)
        self.assertNotEqual(endpoint_host, "drlink.local")
        self.assertIn("%s:%s" % (endpoint_host, agent["endpoint_port"]), shown)
        os.environ.pop("DRLINK_SERVER_REACHABLE", None)

    def test_AGENT_STATUS_COUNTS_LOCAL_REMOTE_SERVICES(self):
        v24.ensure_v2_schema(self.agent.conn)
        self.agent.conn.execute(
            "INSERT INTO agent_remote_services("
            "name, destination, service_object, enabled, status, pending_allocation, "
            "delete_pending, pool_class, reason, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                "ssh-access",
                "this-host",
                "ssh",
                1,
                "HEALTHY",
                0,
                0,
                "normal",
                "",
                "2026-09-19T00:00:00Z",
            ),
        )
        self.agent.conn.commit()
        out = self.agent.format_status()
        self.assertIn("Role: Agent Host", out)
        # Agent-role status uses single-space alignment for this longer label.
        self.assertIn("Remote Services : 1", out)
        self.assertNotIn("Role: Unknown", out)


class MacosRoleDetectionTests(unittest.TestCase):
    def test_macos_application_support_layout_is_agent(self):
        tmp = tempfile.mkdtemp(prefix="drlink-macos-role-")
        state = Path(tmp) / "Library/Application Support/drlink"
        state.mkdir(parents=True)
        (state / "client-state.json").write_text(
            '{"machine_id":"%s","hostname":"mac-agent"}\n' % MACHINE,
            encoding="utf-8",
        )
        (state / "frpc.toml").write_text("[common]\n", encoding="utf-8")
        self.assertEqual(v24.detect_cli_role(tmp), "agent")
        self.assertEqual(v24.role_label(v24.detect_cli_role(tmp)), "Agent Host")

    def test_macos_env_state_root_is_agent(self):
        tmp = tempfile.mkdtemp(prefix="drlink-macos-env-")
        state = Path(tmp) / "drlink-state"
        state.mkdir(parents=True)
        (state / "client-state.json").write_text("{}\n", encoding="utf-8")
        prev = os.environ.get("FRP_MACOS_STATE_ROOT")
        os.environ["FRP_MACOS_STATE_ROOT"] = str(state)
        try:
            self.assertEqual(v24.detect_cli_role("/nonexistent-root"), "agent")
        finally:
            if prev is None:
                os.environ.pop("FRP_MACOS_STATE_ROOT", None)
            else:
                os.environ["FRP_MACOS_STATE_ROOT"] = prev

    def test_macos_flat_state_resolves_server_endpoint_and_mgmt_url(self):
        tmp = tempfile.mkdtemp(prefix="drlink-macos-ep-")
        state = Path(tmp) / "drlink-state"
        state.mkdir(parents=True)
        (state / "client-state.json").write_text(
            json.dumps(
                {
                    "machine_id": MACHINE,
                    "hostname": "mac-agent",
                    "allocator_url": "https://221.139.249.113:6099/enroll",
                    "frp_server": "221.139.249.113",
                    "frp_server_port": 443,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (state / "frpc.toml").write_text(
            'serverAddr = "221.139.249.113"\nserverPort = 443\n', encoding="utf-8"
        )
        (state / "allocator-ca.crt").write_text("dummy-ca\n", encoding="utf-8")
        (state / "client-identity.key").write_text("dummy-key\n", encoding="utf-8")
        (state / "client-identity.mac").write_text("dummy-mac\n", encoding="utf-8")
        prev = os.environ.get("FRP_MACOS_STATE_ROOT")
        os.environ["FRP_MACOS_STATE_ROOT"] = str(state)
        try:
            self.assertEqual(
                v24.load_agent_server_endpoint("/nonexistent-root"),
                ("221.139.249.113", 443),
            )
            self.assertEqual(
                mgmt.resolve_mgmt_base_url("/nonexistent-root"),
                "https://221.139.249.113:6099",
            )
            self.assertEqual(
                mgmt.allocator_ca_path("/nonexistent-root"),
                state / "allocator-ca.crt",
            )
            ident = v24.load_agent_identity("/nonexistent-root")
            self.assertEqual(ident.get("machine_id"), MACHINE)
            self.assertEqual(
                v24.agent_identity_key_path("/nonexistent-root"),
                state / "client-identity.key",
            )
            self.assertEqual(
                v24.agent_identity_mac_path("/nonexistent-root"),
                state / "client-identity.mac",
            )
            import drlink_v24_runtime as runtime

            loaded = runtime.load_client_state("/nonexistent-root")
            self.assertEqual(loaded.get("machine_id"), MACHINE)
            self.assertEqual(runtime._frpc_toml_path("/nonexistent-root"), state / "frpc.toml")
        finally:
            if prev is None:
                os.environ.pop("FRP_MACOS_STATE_ROOT", None)
            else:
                os.environ["FRP_MACOS_STATE_ROOT"] = prev


if __name__ == "__main__":
    unittest.main()
