#!/usr/bin/env python3
"""v2.4 Remote Service runtime activation + single allocator authority tests."""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "server"))

import drlink_v24 as v24
import drlink_v24_runtime as runtime
from drlink_control_plane import ControlPlane


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class RuntimeRenderTests(unittest.TestCase):
    def test_REMOTE_SERVICE_RUNTIME_RENDER(self):
        text = runtime.render_frpc_toml_text(
            server="203.0.113.9",
            server_port=443,
            token="tok",
            host_id="host-abc",
            services={
                "ssh": {
                    "id": "ssh",
                    "enabled": True,
                    "local_ip": "127.0.0.1",
                    "local_port": 22,
                    "remote_port": 6003,
                },
                "rs-web": {
                    "id": "rs-web",
                    "enabled": True,
                    "local_ip": "127.0.0.1",
                    "local_port": 8080,
                    "remote_port": 6010,
                    "v24_remote_service": True,
                },
            },
        )
        self.assertIn('name = "host-abc-ssh"', text)
        self.assertIn('name = "host-abc-rs-web"', text)
        self.assertIn("remotePort = 6010", text)
        runtime.validate_frpc_toml_text(text)

    def test_proxy_id_stable(self):
        self.assertEqual(runtime.remote_service_proxy_id("Web-API"), "rs-web-api")
        self.assertTrue(runtime.remote_service_proxy_id("x").startswith("rs-"))


class RuntimeApplyRemoveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-rt-")
        frp = Path(self.tmp, "etc/frp")
        frp.mkdir(parents=True)
        _write_json(
            frp / "client-state.json",
            {
                "schema_version": 2,
                "allocator_url": "https://example:6099/enroll",
                "frp_server": "203.0.113.9",
                "frp_server_port": 443,
                "frp_transport": "tcp",
                "hostname": "agent-1",
                "machine_id": "aabbccddeeff00112233445566778899",
                "host_id": "agent-1-aabbccdd",
                "services": {
                    "ssh": {
                        "id": "ssh",
                        "name": "SSH",
                        "preset": "ssh",
                        "protocol": "tcp",
                        "local_ip": "127.0.0.1",
                        "local_port": 22,
                        "remote_port": 6003,
                        "enabled": True,
                        "ssh_user": "ec2-user",
                    }
                },
            },
        )
        (frp / "frpc.toml").write_text(
            'serverAddr = "203.0.113.9"\nserverPort = 443\n\n'
            'auth.method = "token"\nauth.token = "tok"\n\n'
            "transport.tls.enable = true\n\n"
            "[[proxies]]\nname = \"agent-1-aabbccdd-ssh\"\ntype = \"tcp\"\n"
            'localIP = "127.0.0.1"\nlocalPort = 22\nremotePort = 6003\n',
            encoding="utf-8",
        )
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_SKIP_ACTIVATION"] = "0"
        os.environ["FRP_SKIP_SYSTEMD"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?,?,?,?)",
            ("service-object", "web", '{"name":"web","type":"tcp","port":8080}', now),
        )
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_remote_services"
            "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
            "pending_allocation, delete_pending, pool_class, reason, updated_at) "
            "VALUES ('web','agent-1','web',1,'DEGRADED','drlink.local',6010,0,0,'normal','',?)",
            (now,),
        )
        self.plane.conn.commit()

    def tearDown(self):
        self.plane.close()
        for k in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_SKIP_ACTIVATION", "FRP_SKIP_SYSTEMD",
                  "DRLINK_FAULT_RUNTIME_CONFIG", "DRLINK_FAULT_RUNTIME_VERIFY", "DRLINK_FAULT_RUNTIME_RESTART"):
            os.environ.pop(k, None)

    def test_REMOTE_SERVICE_RUNTIME_APPLY(self):
        result = runtime.apply_agent_runtime(self.plane, root=self.tmp)
        self.assertTrue(result["ok"], result)
        text = Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8")
        self.assertIn("rs-web", text)
        self.assertIn("remotePort = 6010", text)
        self.assertIn("remotePort = 6003", text)  # legacy preserved
        state = json.loads(Path(self.tmp, "etc/frp/client-state.json").read_text(encoding="utf-8"))
        self.assertIn("ssh", state["services"])
        self.assertIn("rs-web", state["services"])

    def test_REMOTE_SERVICE_RUNTIME_REMOVE(self):
        runtime.apply_agent_runtime(self.plane, root=self.tmp)
        self.plane.conn.execute("DELETE FROM agent_remote_services WHERE name='web'")
        self.plane.conn.commit()
        result = runtime.apply_agent_runtime(self.plane, root=self.tmp)
        self.assertTrue(result["ok"], result)
        text = Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8")
        self.assertNotIn("rs-web", text)
        self.assertIn("remotePort = 6003", text)

    def test_REMOTE_SERVICE_RUNTIME_ROLLBACK(self):
        os.environ["DRLINK_FAULT_RUNTIME_CONFIG"] = "1"
        before = Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8")
        result = runtime.apply_agent_runtime(self.plane, root=self.tmp)
        self.assertFalse(result["ok"])
        after = Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8")
        self.assertEqual(before, after)

    def test_REMOTE_SERVICE_HEALTHY_REQUIRES_RUNTIME_ACK(self):
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        os.environ["DRLINK_MGMT_MODE"] = "local"
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        # Without skip, runtime would be required; with skip unit tests still allocate.
        # Prove production helper refuses HEALTHY language without runtime when not skipped:
        os.environ["DRLINK_SKIP_ACTIVATION"] = "0"
        # Missing usable token path already present; force verify failure.
        os.environ["DRLINK_FAULT_RUNTIME_VERIFY"] = "1"
        self.plane.conn.execute("DELETE FROM agent_remote_services")
        self.plane.conn.commit()
        # Seed catalog + create via local path
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?,?,?,?)",
            ("service-object", "ssh", '{"name":"ssh","type":"tcp","port":22}', now),
        )
        result = v24.set_remote_service_agent(
            self.plane,
            "needs-runtime",
            destination="this-host",
            service="ssh",
            enabled=True,
            oneshot=True,
            root=self.tmp,
            server_reachable=True,
        )
        self.assertEqual(result["view"]["status"], "DEGRADED")
        self.assertNotEqual(result["view"]["status"], "HEALTHY")


class AllocatorAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-alloc-")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        Path(self.tmp, "etc/drlink").mkdir(parents=True)
        Path(self.tmp, "var/lib/drlink/runtime").mkdir(parents=True)
        _write_json(
            Path(self.tmp, "etc/drlink/config.json"),
            {
                "port_start": 6000,
                "port_end": 6098,
                "tcp_relay_port_start": 6200,
                "tcp_relay_port_end": 6299,
                "allocator_listen_port": 6099,
                "frp_control_listen_port": 443,
                "egress_listen_port": 6102,
                "access_plugin_addr": "127.0.0.1:6101",
            },
        )
        _write_json(
            Path(self.tmp, "var/lib/drlink/runtime/client-inventory.json"),
            {
                "schema_version": 2,
                "reserved": [],
                "clients": {
                    "legacyhost00112233445566778899aabb": {
                        "hostname": "legacy",
                        "services": {
                            "ssh": {
                                "name": "SSH",
                                "protocol": "tcp",
                                "local_ip": "127.0.0.1",
                                "local_port": 22,
                                "remote_port": 6002,
                                "preset": "ssh",
                                "enabled": True,
                                "ssh_user": "root",
                            }
                        },
                    }
                },
            },
        )
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR IGNORE INTO clients(id, label, hostname, status, trust_status, connected, "
            "row_version, created_at, updated_at) VALUES (?,?,?,?,?,?,1,?,?)",
            ("agent1", "agent1", "agent1", "connected", "trusted", 1, now, now),
        )
        self.plane.conn.commit()

    def tearDown(self):
        self.plane.close()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def test_ALLOCATOR_SEES_LEGACY_SERVICE_PORTS(self):
        port = v24.allocate_endpoint_port(self.plane, "agent1", "new-svc", "normal")
        self.assertNotEqual(port, 6002)
        self.assertGreaterEqual(port, 6000)

    def test_ALLOCATOR_SEES_PROTECTED_PORTS(self):
        # Force only protected-adjacent free ports by marking everything used except 6099-ish
        # Protected includes 6099/443/6102/6101 — ensure allocator never returns them.
        for p in range(6000, 6099):
            if p in (6099, 443, 6101, 6102):
                continue
            self.plane.conn.execute(
                "INSERT OR REPLACE INTO port_reservations(public_port, client_id, service_id, service_name, released, created_at) "
                "VALUES (?,?,?,?,0,?)",
                (p, "agent1", "", "hold-%s" % p, v24.utc_now_iso()),
            )
        self.plane.conn.commit()
        with self.assertRaises(v24.ControlPlaneError):
            v24.allocate_endpoint_port(self.plane, "agent1", "overflow", "normal")

    def test_ALLOCATOR_SEES_OS_BOUND_PORTS(self):
        # Bind an otherwise free port and ensure allocator skips it.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 6005))
        sock.listen(1)
        try:
            # Mark 6000-6004 used so next candidate is 6005 then 6006
            for p in range(6000, 6005):
                self.plane.conn.execute(
                    "INSERT OR REPLACE INTO port_reservations(public_port, client_id, service_id, service_name, released, created_at) "
                    "VALUES (?,?,?,?,0,?)",
                    (p, "agent1", "", "hold-%s" % p, v24.utc_now_iso()),
                )
            self.plane.conn.commit()
            port = v24.allocate_endpoint_port(self.plane, "agent1", "after-bound", "normal")
            self.assertNotEqual(port, 6005)
            self.assertEqual(port, 6006)
        finally:
            sock.close()

    def test_ALLOCATOR_USES_EXISTING_REGISTRY(self):
        # Registry owns 6002; sqlite empty → must not pick 6002
        port = v24.allocate_endpoint_port(self.plane, "agent1", "reg-aware", "normal")
        self.assertNotEqual(port, 6002)

    def test_ALLOCATOR_CONCURRENT_UNIQUE_PORTS(self):
        results = []
        errors = []

        def worker(i):
            try:
                p = ControlPlane(self.tmp)
                v24.ensure_v2_schema(p.conn)
                port = v24.allocate_endpoint_port(p, "agent1", "c-%s" % i, "normal")
                results.append(port)
                p.close()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors, errors)
        self.assertEqual(len(results), len(set(results)))


class OfflineRuntimeReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-off-")
        frp = Path(self.tmp, "etc/frp")
        frp.mkdir(parents=True)
        _write_json(
            frp / "client-state.json",
            {
                "schema_version": 2,
                "allocator_url": "https://example:6099/enroll",
                "frp_server": "203.0.113.9",
                "frp_server_port": 443,
                "hostname": "agent-1",
                "machine_id": "aabbccddeeff00112233445566778899",
                "host_id": "agent-1-aabbccdd",
                "services": {},
            },
        )
        (frp / "frpc.toml").write_text(
            'serverAddr = "203.0.113.9"\nserverPort = 443\nauth.method = "token"\n'
            'auth.token = "tok"\ntransport.tls.enable = true\n',
            encoding="utf-8",
        )
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["FRP_SKIP_SYSTEMD"] = "1"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "0"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?,?,?,?)",
            ("service-object", "http", '{"name":"http","type":"tcp","port":80}', now),
        )
        self.plane.conn.commit()

    def tearDown(self):
        self.plane.close()
        for k in ("FRP_DEPLOY_TEST_ROOT", "FRP_SKIP_SYSTEMD", "DRLINK_SKIP_ACTIVATION"):
            os.environ.pop(k, None)

    def test_REMOTE_SERVICE_OFFLINE_CREATE_RUNTIME_RECONCILE(self):
        # Offline create stores DEGRADED without endpoint → runtime must not emit proxy.
        v24.set_remote_service_agent(
            self.plane,
            "offline-new",
            destination="this-host",
            service="http",
            enabled=True,
            oneshot=True,
            root=self.tmp,
            server_reachable=False,
        )
        runtime.apply_agent_runtime(self.plane, root=self.tmp)
        text = Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8")
        self.assertNotIn("rs-offline-new", text)

    def test_REMOTE_SERVICE_DEPENDENCY_INVALIDATION_REMOVES_STALE_RUNTIME(self):
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_remote_services"
            "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
            "pending_allocation, delete_pending, pool_class, reason, updated_at) "
            "VALUES ('stale','agent-1','http',1,'DEGRADED','drlink.local',6011,0,0,'normal',"
            "'Required Service Object ''http'' is missing or invalid after reconnect.',?)",
            (now,),
        )
        self.plane.conn.commit()
        # Seed a stale proxy then reconcile should drop it due to dependency reason.
        state = json.loads(Path(self.tmp, "etc/frp/client-state.json").read_text(encoding="utf-8"))
        state["services"]["rs-stale"] = {
            "id": "rs-stale",
            "local_ip": "127.0.0.1",
            "local_port": 80,
            "remote_port": 6011,
            "enabled": True,
            "v24_remote_service": True,
        }
        _write_json(Path(self.tmp, "etc/frp/client-state.json"), state)
        runtime.apply_agent_runtime(self.plane, root=self.tmp)
        text = Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8")
        self.assertNotIn("rs-stale", text)

    def test_REMOTE_SERVICE_DELETE_CLOSES_RUNTIME_PROXY(self):
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_remote_services"
            "(name, destination, service_object, enabled, status, endpoint_host, endpoint_port, "
            "pending_allocation, delete_pending, pool_class, reason, updated_at) "
            "VALUES ('gone','agent-1','http',1,'HEALTHY','drlink.local',6012,0,0,'normal','',?)",
            (now,),
        )
        self.plane.conn.commit()
        runtime.apply_agent_runtime(self.plane, root=self.tmp)
        self.assertIn("rs-gone", Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8"))
        self.plane.conn.execute("DELETE FROM agent_remote_services WHERE name='gone'")
        self.plane.conn.commit()
        runtime.apply_agent_runtime(self.plane, root=self.tmp)
        self.assertNotIn("rs-gone", Path(self.tmp, "etc/frp/frpc.toml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
