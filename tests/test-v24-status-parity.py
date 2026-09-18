#!/usr/bin/env python3
"""Agent DEGRADED / runtime failure must converge on Server inventory."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
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


if __name__ == "__main__":
    unittest.main()
