#!/usr/bin/env python3
"""Bootstrap services share one identity across Agent catalog and Server status."""
from __future__ import annotations

import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import drlink_mgmt_sync as mgmt  # noqa: E402
import drlink_runtime_policy as RP  # noqa: E402
import drlink_upgrade_reconcile as UR  # noqa: E402
import drlink_v24 as v24  # noqa: E402
from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402

MACHINE = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


class BootstrapCatalogConvergenceTests(unittest.TestCase):
    def setUp(self):
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-boot-agt-")
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-boot-srv-")
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.local_port = int(self.listener.getsockname()[1])
        self._accepting = True

        def _accept_loop():
            while self._accepting:
                try:
                    self.listener.settimeout(0.2)
                    conn, _addr = self.listener.accept()
                except OSError:
                    continue
                try:
                    conn.close()
                except OSError:
                    pass

        self._accept_thread = threading.Thread(target=_accept_loop, daemon=True)
        self._accept_thread.start()
        frp = Path(self.agent_tmp) / "etc/frp"
        frp.mkdir(parents=True)
        (frp / "client-state.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "machine_id": MACHINE,
                    "hostname": "frp-client",
                    "label": "real-e2e-ubuntu24",
                    "public_hostname": "203.0.113.10",
                    "frp_server": "203.0.113.10",
                    "services": {
                        "ssh": {
                            "id": "ssh",
                            "name": "SSH",
                            "preset": "ssh",
                            "local_ip": "127.0.0.1",
                            "local_port": self.local_port,
                            "remote_port": 6000,
                            "enabled": True,
                        }
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text(
            '{"role":"server","public_ip":"203.0.113.10"}\n', encoding="utf-8"
        )
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"

    def tearDown(self):
        self._accepting = False
        self.listener.close()
        for key in ("DRLINK_SKIP_ACTIVATION", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _show(self, root, *tokens):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = dispatch(list(tokens), root=root)
        self.assertEqual(rc, 0, buf.getvalue())
        return buf.getvalue()

    def _fingerprint(self, root):
        plane = ControlPlane(root)
        try:
            revision = plane.current_revision()
            rows = [
                tuple(row)
                for row in plane.conn.execute(
                    "SELECT name, destination, service_object, enabled, status, endpoint_host, "
                    "endpoint_port, pending_allocation, delete_pending, reason "
                    "FROM agent_remote_services ORDER BY name"
                )
            ]
            return revision, rows
        finally:
            plane.close()

    def _read_only_shows(self, root):
        before = self._fingerprint(root)
        status = self._show(root, "show", "status")
        listed = self._show(root, "show", "remote-services")
        agent_view = self._show(root, "show", "agent")
        self.assertEqual(self._fingerprint(root), before)
        self.assertIn("Role: Agent Host", status)
        self.assertIn("Role: Agent Host", agent_view)
        self.assertNotIn("Unknown show resource", agent_view)
        return status, listed, agent_view

    def test_bootstrap_ssh_catalog_and_server_liveness(self):
        cli_src = (ROOT / "lib" / "drlink_v24_cli.py").read_text(encoding="utf-8")
        plane_src = (ROOT / "lib" / "drlink_control_plane.py").read_text(encoding="utf-8")
        self.assertNotIn("project_enrolled_services_into_agent_catalog", cli_src)
        self.assertNotIn("project_enrolled_services_into_agent_catalog", plane_src)

        status, listed, _agent_view = self._read_only_shows(self.agent_tmp)
        self.assertIn("Remote Services : 0", status)
        self.assertNotIn("ssh", listed)

        results = v24.activate_enrolled_services_as_remote_services(root=self.agent_tmp)
        self.assertEqual(len(results), 1)
        view = results[0]["view"]
        self.assertEqual(view["name"], "ssh")
        self.assertEqual(view["endpoint_port"], 6000)
        self.assertEqual(view["status"], "DEGRADED")
        self.assertIn("activation", view["reason"].lower())

        projected = self._fingerprint(self.agent_tmp)
        self.assertEqual(projected[1][0][0], "ssh")
        self.assertEqual(int(projected[1][0][6]), 6000)
        self.assertEqual(projected[1][0][4], "DEGRADED")

        status, listed, _agent_view = self._read_only_shows(self.agent_tmp)
        self.assertEqual(self._fingerprint(self.agent_tmp), projected)
        self.assertIn("Remote Services : 1", status)
        self.assertIn("ssh", listed)
        self.assertIn(":6000", listed)
        self.assertIn("DEGRADED", listed)
        self.assertNotIn("HEALTHY", listed)

        agent = ControlPlane(self.agent_tmp)
        agent.conn.execute("DELETE FROM agent_remote_services")
        agent.conn.commit()
        self.assertEqual(self._fingerprint(self.agent_tmp)[1], [])
        result = v24.synchronize_agent_remote_services(agent, root=self.agent_tmp)
        self.assertEqual(result.get("status"), "OFFLINE")
        self.assertEqual(result.get("projected"), 1)
        row = agent.conn.execute(
            "SELECT name, endpoint_port, status FROM agent_remote_services"
        ).fetchone()
        self.assertEqual(row["name"], "ssh")
        self.assertEqual(int(row["endpoint_port"]), 6000)
        self.assertEqual(row["status"], "DEGRADED")
        agent.close()

    def test_operator_edit_survives_synchronize(self):
        v24.activate_enrolled_services_as_remote_services(root=self.agent_tmp)
        state_path = Path(self.agent_tmp) / "etc/frp/client-state.json"
        state_bytes = state_path.read_bytes()
        agent = ControlPlane(self.agent_tmp)
        agent.conn.execute(
            "UPDATE agent_remote_services SET enabled = 0, status = 'DISABLED', "
            "destination = 'lab-db', service_object = 'postgres', reason = 'operator disabled', "
            "endpoint_port = 6000 WHERE name = 'ssh'"
        )
        agent.conn.commit()
        before = agent.conn.execute(
            "SELECT enabled, status, destination, service_object, endpoint_port, reason, updated_at "
            "FROM agent_remote_services WHERE name = 'ssh'"
        ).fetchone()
        preserved = v24.project_enrolled_services_into_agent_catalog(agent, root=self.agent_tmp)
        self.assertEqual(preserved, [])
        first = v24.synchronize_agent_remote_services(agent, root=self.agent_tmp)
        second = v24.synchronize_agent_remote_services(agent, root=self.agent_tmp)
        self.assertEqual(first.get("status"), "OFFLINE")
        self.assertEqual(second.get("status"), "OFFLINE")
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        try:
            reachable = v24.synchronize_agent_remote_services(agent, root=self.agent_tmp)
        finally:
            os.environ.pop("DRLINK_SERVER_REACHABLE", None)
        self.assertIn(reachable.get("status"), ("SYNCHRONIZED", "DEGRADED", "OFFLINE"))
        after = agent.conn.execute(
            "SELECT enabled, status, destination, service_object, endpoint_port, reason, updated_at "
            "FROM agent_remote_services WHERE name = 'ssh'"
        ).fetchone()
        self.assertEqual(tuple(after), tuple(before))
        self.assertEqual(int(after["enabled"]), 0)
        self.assertEqual(after["status"], "DISABLED")
        self.assertEqual(after["destination"], "lab-db")
        self.assertEqual(after["service_object"], "postgres")
        self.assertEqual(int(after["endpoint_port"]), 6000)
        self.assertEqual(state_path.read_bytes(), state_bytes)
        agent.close()

        server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(server.conn)
        RP.sync_enrolled_client(
            server,
            client_id=MACHINE,
            hostname="frp-client",
            label="real-e2e-ubuntu24",
            services={
                "ssh": {
                    "id": "ssh",
                    "preset": "ssh",
                    "local_ip": "127.0.0.1",
                    "local_port": 22,
                    "remote_port": 6000,
                    "enabled": True,
                }
            },
        )
        stored = server.conn.execute(
            "SELECT s.public_port, s.enabled, m.status FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id WHERE s.name = 'ssh'"
        ).fetchone()
        self.assertEqual(int(stored["public_port"]), 6000)
        self.assertNotEqual(stored["status"], "HEALTHY")

        reported = mgmt.server_report_remote_service_status(
            server,
            mgmt.MgmtAuthContext(MACHINE, {"id": MACHINE}, "nonce", 1, allocator=None),
            {
                "services": [
                    {
                        "name": "ssh",
                        "status": "HEALTHY",
                        "reason": "",
                        "runtime_verified": True,
                    }
                ]
            },
        )
        self.assertEqual(reported["count"], 1)
        self.assertEqual(reported["services"][0]["endpoint_port"], 6000)
        healthy = self._show(self.server_tmp, "show", "managed-host", "real-e2e-ubuntu24", "remote-services")
        self.assertIn("ssh", healthy)
        self.assertIn(":6000", healthy)
        self.assertIn("HEALTHY", healthy)

        server.set_published_service_enabled(MACHINE, "ssh", False)
        disabled = self._show(self.server_tmp, "show", "managed-host", "real-e2e-ubuntu24", "remote-services")
        self.assertIn("DISABLED", disabled)
        self.assertNotIn("HEALTHY", disabled)
        port = server.conn.execute(
            "SELECT public_port FROM published_services WHERE name = 'ssh'"
        ).fetchone()
        self.assertEqual(int(port["public_port"]), 6000)

        server.set_published_service_enabled(MACHINE, "ssh", True)
        server.conn.execute(
            "UPDATE remote_service_meta SET status = 'HEALTHY', reason = '' "
            "WHERE service_id = (SELECT id FROM published_services WHERE name = 'ssh')"
        )
        server.conn.commit()
        server.upsert_client(MACHINE, label="real-e2e-ubuntu24", hostname="frp-client", connected=False)
        offline = self._show(self.server_tmp, "show", "managed-host", "real-e2e-ubuntu24", "remote-services")
        self.assertIn("DEGRADED", offline)
        self.assertNotIn("HEALTHY", offline)
        pub = server.conn.execute(
            "SELECT * FROM published_services WHERE name = 'ssh'"
        ).fetchone()
        meta = server.conn.execute(
            "SELECT * FROM remote_service_meta WHERE service_id = ?", (pub["id"],)
        ).fetchone()
        client = server.conn.execute("SELECT * FROM clients WHERE id = ?", (MACHINE,)).fetchone()
        status, reason, stale = UR.effective_remote_service_status(
            server, pub, meta, {}, registry_available=False
        )
        self.assertEqual(status, "DEGRADED")
        self.assertIn("offline", reason.lower())
        self.assertFalse(stale)
        self.assertEqual(int(pub["public_port"]), 6000)
        self.assertEqual(client["id"], MACHINE)
        server.close()

    def _ssh_operator_row(self, plane):
        return tuple(
            plane.conn.execute(
                "SELECT enabled, destination, service_object, endpoint_port, status, reason "
                "FROM agent_remote_services WHERE name = 'ssh'"
            ).fetchone()
        )

    def test_projection_preserves_operator_state_and_show_is_read_only(self):
        empty = self._fingerprint(self.agent_tmp)
        self._read_only_shows(self.agent_tmp)
        self.assertEqual(self._fingerprint(self.agent_tmp), empty)

        created = v24.activate_enrolled_services_as_remote_services(root=self.agent_tmp)
        self.assertEqual(created[0]["view"]["endpoint_port"], 6000)
        agent = ControlPlane(self.agent_tmp)
        agent.conn.execute(
            "UPDATE agent_remote_services SET enabled = 0, status = 'DISABLED', "
            "destination = 'other-host', service_object = 'tcp', reason = 'operator hold', "
            "endpoint_port = 6000, pending_allocation = 0 WHERE name = 'ssh'"
        )
        agent.conn.commit()
        held = self._ssh_operator_row(agent)
        held_fp = self._fingerprint(self.agent_tmp)
        self.assertEqual(held[0], 0)
        self.assertEqual(held[1], "other-host")
        self.assertEqual(held[2], "tcp")
        self.assertEqual(int(held[3]), 6000)
        self.assertEqual(held[4], "DISABLED")

        self.assertEqual(
            v24.project_enrolled_services_into_agent_catalog(agent, root=self.agent_tmp),
            [],
        )
        self.assertEqual(self._ssh_operator_row(agent), held)
        sync = v24.synchronize_agent_remote_services(agent, root=self.agent_tmp)
        self.assertEqual(sync.get("projected"), 0)
        self.assertEqual(self._ssh_operator_row(agent), held)
        self.assertEqual(
            v24.activate_enrolled_services_as_remote_services(root=self.agent_tmp),
            [],
        )
        self._read_only_shows(self.agent_tmp)
        self.assertEqual(self._ssh_operator_row(agent), held)
        self.assertEqual(self._fingerprint(self.agent_tmp), held_fp)

        state_path = Path(self.agent_tmp) / "etc/frp/client-state.json"
        data = json.loads(state_path.read_text(encoding="utf-8"))
        data["services"]["http"] = {
            "id": "http",
            "preset": "http",
            "local_ip": "127.0.0.1",
            "local_port": self.local_port,
            "remote_port": 6001,
            "enabled": True,
        }
        state_path.write_text(json.dumps(data) + "\n", encoding="utf-8")
        added = v24.project_enrolled_services_into_agent_catalog(agent, root=self.agent_tmp)
        self.assertEqual([item["view"]["name"] for item in added], ["http"])
        self.assertEqual(added[0]["view"]["endpoint_port"], 6001)
        self.assertEqual(self._ssh_operator_row(agent), held)
        replay = v24.synchronize_agent_remote_services(agent, root=self.agent_tmp)
        self.assertEqual(replay.get("projected"), 0)
        self.assertEqual(
            v24.activate_enrolled_services_as_remote_services(root=self.agent_tmp),
            [],
        )
        self._read_only_shows(self.agent_tmp)
        self.assertEqual(self._ssh_operator_row(agent), held)
        names = [
            row["name"]
            for row in agent.conn.execute(
                "SELECT name FROM agent_remote_services ORDER BY name"
            )
        ]
        self.assertEqual(names, ["http", "ssh"])
        http = agent.conn.execute(
            "SELECT status, endpoint_port FROM agent_remote_services WHERE name = 'http'"
        ).fetchone()
        self.assertEqual(http["status"], "DEGRADED")
        self.assertEqual(int(http["endpoint_port"]), 6001)
        agent.close()

    def test_open_local_target_without_relay_verification_stays_degraded(self):
        self._read_only_shows(self.agent_tmp)
        agent = ControlPlane(self.agent_tmp)
        seeded = v24.project_enrolled_services_into_agent_catalog(agent, root=self.agent_tmp)
        self.assertEqual(len(seeded), 1)
        view = seeded[0]["view"]
        self.assertEqual(view["name"], "ssh")
        self.assertEqual(view["endpoint_port"], 6000)
        self.assertNotEqual(view["status"], "HEALTHY")
        self.assertEqual(view["status"], "DEGRADED")
        self.assertIn("activation", view["reason"].lower())

        row = agent.conn.execute(
            "SELECT status, reason, endpoint_port FROM agent_remote_services WHERE name = 'ssh'"
        ).fetchone()
        self.assertEqual(int(row["endpoint_port"]), 6000)
        self.assertEqual(row["status"], "DEGRADED")
        before = self._fingerprint(self.agent_tmp)
        listed = self._show(self.agent_tmp, "show", "remote-services")
        self.assertEqual(self._fingerprint(self.agent_tmp), before)
        self.assertIn(":6000", listed)
        self.assertIn("DEGRADED", listed)
        self.assertNotIn("HEALTHY", listed)

        server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(server.conn)
        RP.sync_enrolled_client(
            server,
            client_id=MACHINE,
            hostname="frp-client",
            label="real-e2e-ubuntu24",
            services={
                "ssh": {
                    "id": "ssh",
                    "preset": "ssh",
                    "local_ip": "127.0.0.1",
                    "local_port": self.local_port,
                    "remote_port": 6000,
                    "enabled": True,
                }
            },
        )
        reported = mgmt.server_report_remote_service_status(
            server,
            mgmt.MgmtAuthContext(MACHINE, {"id": MACHINE}, "nonce", 1, allocator=None),
            {
                "services": [
                    {
                        "name": "ssh",
                        "status": row["status"],
                        "reason": row["reason"],
                        "runtime_verified": row["status"] == "HEALTHY",
                        "endpoint_port": int(row["endpoint_port"]),
                    }
                ]
            },
        )
        self.assertEqual(reported["count"], 1)
        self.assertEqual(reported["services"][0]["endpoint_port"], 6000)
        self.assertNotEqual(reported["services"][0]["status"], "HEALTHY")
        shown = self._show(self.server_tmp, "show", "managed-host", "real-e2e-ubuntu24", "remote-services")
        self.assertIn("ssh", shown)
        self.assertIn(":6000", shown)
        self.assertIn("DEGRADED", shown)
        self.assertNotIn("HEALTHY", shown)
        server.close()

        agent.conn.execute("DELETE FROM agent_remote_services")
        agent.conn.commit()
        backfill = v24.synchronize_agent_remote_services(agent, root=self.agent_tmp)
        self.assertEqual(backfill.get("status"), "OFFLINE")
        self.assertEqual(backfill.get("projected"), 1)
        backfilled = agent.conn.execute(
            "SELECT status, endpoint_port, reason FROM agent_remote_services WHERE name = 'ssh'"
        ).fetchone()
        self.assertEqual(backfilled["status"], "DEGRADED")
        self.assertEqual(int(backfilled["endpoint_port"]), 6000)
        self.assertIn("activation", (backfilled["reason"] or "").lower())
        self.assertNotEqual(backfilled["status"], "HEALTHY")

        agent.conn.execute("DELETE FROM agent_remote_services")
        agent.conn.commit()
        verified = v24.activate_enrolled_services_as_remote_services(
            root=self.agent_tmp, runtime_verified=True
        )
        self.assertEqual(verified[0]["view"]["status"], "HEALTHY")
        self.assertEqual(verified[0]["view"]["endpoint_port"], 6000)
        agent.conn.execute(
            "UPDATE agent_remote_services SET enabled = 1, status = 'DEGRADED', "
            "reason = 'operator edited', endpoint_port = 6000 WHERE name = 'ssh'"
        )
        agent.conn.commit()
        held = self._ssh_operator_row(agent)
        self.assertEqual(
            v24.activate_enrolled_services_as_remote_services(
                root=self.agent_tmp, runtime_verified=True
            ),
            [],
        )
        self.assertEqual(self._ssh_operator_row(agent), held)
        self.assertEqual(held[4], "DEGRADED")
        self.assertEqual(held[5], "operator edited")
        agent.close()


if __name__ == "__main__":
    unittest.main()
