#!/usr/bin/env python3
"""Upgrade reconciliation: registry → canonical SQLite, without wiping live lineage."""
from __future__ import annotations

import json
import os
import subprocess
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
from drlink_v24_runtime import remote_service_proxy_id

IDS = {
    "macos": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
    "rocky9": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1",
    "ubuntu24": "ccccccccccccccccccccccccccccccc1",
    "rocky8": "ddddddddddddddddddddddddddddddd1",
    "al2023": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1",
}
LABELS = {
    "macos": "real-e2e-macos",
    "rocky9": "real-e2e-rocky9",
    "ubuntu24": "real-e2e-ubuntu24",
    "rocky8": "real-e2e-rocky8",
    "al2023": "real-e2e-al2023",
}
PORTS = {
    "ubuntu24": 6000,
    "rocky8": 6001,
    "rocky9": 6002,
    "al2023": 6003,
    "macos": 6004,
}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _legacy_ssh(port: int) -> dict:
    return {
        "id": "ssh",
        "preset": "ssh",
        "local_ip": "127.0.0.1",
        "local_port": 22,
        "remote_port": port,
        "enabled": True,
    }


def realistic_registry() -> dict:
    clients = {}
    for key, mid in IDS.items():
        services = {"ssh": _legacy_ssh(PORTS[key])}
        if key == "al2023":
            services["rs-e2e-ssh"] = {
                "name": "e2e-ssh",
                "remote_port": 6005,
                "local_ip": "127.0.0.1",
                "local_port": 22,
                "v24_remote_service": True,
                "pool_class": "normal",
                "enabled": True,
            }
        clients[mid] = {
            "hostname": LABELS[key],
            "label": LABELS[key],
            "services": services,
        }
    return {"schema_version": 2, "clients": clients, "reserved": [6000, 6001, 6002, 6003, 6004, 6005]}


class UpgradeReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-upgrade-")
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        self.registry = realistic_registry()
        _write_json(
            Path(self.tmp) / "var/lib/drlink/runtime/client-inventory.json",
            self.registry,
        )
        # Canonical SQLite is incomplete: one Agent, no Managed Host objects,
        # a v2.4 Remote Service, and a stale reservation on rocky8's SSH port.
        self.plane.upsert_client(
            IDS["al2023"],
            label="ip-10-0-19-146",
            hostname="ip-10-0-19-146",
        )
        # Drop the Managed Host object created by upsert to match live pre-migration.
        ep = self.plane.conn.execute(
            "SELECT o.id FROM objects o JOIN managed_endpoints e ON e.object_id = o.id "
            "WHERE e.client_id = ?",
            (IDS["al2023"],),
        ).fetchone()
        if ep:
            self.plane.conn.execute("DELETE FROM managed_endpoints WHERE object_id = ?", (ep["id"],))
            self.plane.conn.execute("DELETE FROM objects WHERE id = ?", (ep["id"],))
            self.plane.conn.commit()
        now = "2026-09-18T00:00:00Z"
        self.plane.set_published_service(
            IDS["al2023"],
            "e2e-ssh",
            service_type="tcp",
            target_mode="self",
            target_host="127.0.0.1",
            target_port=22,
            enabled=True,
            public_port=6005,
        )
        pub_ssh = self.plane.conn.execute(
            "SELECT id FROM published_services WHERE name = 'e2e-ssh'"
        ).fetchone()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO remote_service_meta"
            "(service_id, status, pool_class, service_object_id, destination_name, pending_allocation, delete_pending, reason) "
            "VALUES (?, 'HEALTHY', 'normal', ?, 'this-host', 0, 0, '')",
            (pub_ssh["id"], v24.get_service_object(self.plane, "ssh")["id"]),
        )
        self.plane.set_published_service(
            IDS["al2023"],
            "e2e-net",
            service_type="tcp",
            target_mode="routed",
            target_host="db-prod",
            target_port=5432,
            enabled=True,
            public_port=6001,
        )
        pub_net = self.plane.conn.execute(
            "SELECT id FROM published_services WHERE name = 'e2e-net'"
        ).fetchone()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO remote_service_meta"
            "(service_id, status, pool_class, service_object_id, destination_name, pending_allocation, delete_pending, reason) "
            "VALUES (?, 'HEALTHY', 'normal', ?, 'db-prod', 0, 0, '')",
            (pub_net["id"], v24.get_service_object(self.plane, "ssh")["id"]),
        )
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO port_reservations"
            "(public_port, client_id, service_id, service_name, released, created_at) "
            "VALUES (6001, ?, ?, 'e2e-net', 0, ?)",
            (IDS["al2023"], pub_net["id"], now),
        )
        self.plane.conn.commit()

    def tearDown(self):
        self.plane.close()
        for key in ("DRLINK_SKIP_ACTIVATION", "DRLINK_CONFIRM", "FRP_DEPLOY_TEST_ROOT"):
            os.environ.pop(key, None)

    def _apply(self):
        return UR.apply_upgrade_reconciliation(self.plane, self.registry, connected=False)

    def test_UPGRADE_REGISTRY_CLIENT_BACKFILL(self):
        before = self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        self.assertEqual(int(before), 1)
        self._apply()
        after = self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        self.assertEqual(int(after), 5)
        for mid in IDS.values():
            self.assertIsNotNone(
                self.plane.conn.execute("SELECT 1 FROM clients WHERE id = ?", (mid,)).fetchone()
            )

    def test_UPGRADE_MANAGED_HOST_OBJECT_BACKFILL(self):
        before = self.plane.conn.execute(
            "SELECT COUNT(*) FROM objects WHERE type = 'managed_endpoint'"
        ).fetchone()[0]
        self.assertEqual(int(before), 0)
        self._apply()
        after = self.plane.conn.execute(
            "SELECT COUNT(*) FROM objects WHERE type = 'managed_endpoint'"
        ).fetchone()[0]
        self.assertEqual(int(after), 5)

    def test_UPGRADE_MANAGED_HOST_NETWORK_OBJECT_DISCOVERY(self):
        self._apply()
        listed = {row["name"]: row["type"] for row in v24.list_network_objects(self.plane)}
        for label in LABELS.values():
            self.assertEqual(listed.get(label), "Managed Host")
            obj = self.plane.get_object(label)
            self.assertIsNotNone(obj)
            self.assertEqual(obj["type"], "managed_endpoint")

    def test_UPGRADE_V24_RUNTIME_PROJECTION_DEDUP(self):
        # Simulate the already-reproduced bad import of rs-e2e-ssh.
        self.plane.set_published_service(
            IDS["al2023"],
            "rs-e2e-ssh",
            service_type="tcp",
            target_mode="self",
            target_host="127.0.0.1",
            target_port=22,
            enabled=True,
            public_port=6005,
        )
        with self.assertRaises(Exception):
            RP.build_proxy_map(self.plane)
        self._apply()
        dup = self.plane.conn.execute(
            "SELECT 1 FROM published_services WHERE name = 'rs-e2e-ssh' AND released = 0"
        ).fetchone()
        self.assertIsNone(dup)
        canon = self.plane.conn.execute(
            "SELECT public_port FROM published_services WHERE name = 'e2e-ssh' AND released = 0"
        ).fetchone()
        self.assertEqual(int(canon["public_port"]), 6005)
        mapping = RP.build_proxy_map(self.plane)
        proxy = RP.expected_proxy_name(
            LABELS["al2023"], IDS["al2023"], remote_service_proxy_id("e2e-ssh")
        )
        owners = [k for k in mapping if k.endswith("-rs-e2e-ssh") or k == proxy]
        self.assertEqual(len(owners), 1)

    def test_UPGRADE_LEGACY_SERVICE_PRESERVE(self):
        self._apply()
        for key, port in PORTS.items():
            row = self.plane.conn.execute(
                "SELECT public_port, name FROM published_services WHERE client_id = ? AND name = 'ssh' AND released = 0",
                (IDS[key],),
            ).fetchone()
            self.assertIsNotNone(row, key)
            self.assertEqual(int(row["public_port"]), port)

    def test_UPGRADE_PROXY_NAME_COLLISION_NONE(self):
        self._apply()
        mapping = RP.build_proxy_map(self.plane)
        self.assertGreaterEqual(len(mapping), 6)
        self.assertEqual(len(mapping), len(set(mapping)))

    def test_UPGRADE_STALE_PORT_RESERVATION_REPAIR(self):
        self._apply()
        net = self.plane.conn.execute(
            "SELECT s.public_port, m.status FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id WHERE s.name = 'e2e-net'"
        ).fetchone()
        self.assertEqual(net["status"], "DEGRADED")
        self.assertIsNone(net["public_port"])
        stale = self.plane.conn.execute(
            "SELECT 1 FROM port_reservations WHERE public_port = 6001 AND released = 0 "
            "AND service_name = 'e2e-net'"
        ).fetchone()
        self.assertIsNone(stale)
        rocky = self.plane.conn.execute(
            "SELECT public_port FROM published_services WHERE client_id = ? AND name = 'ssh'",
            (IDS["rocky8"],),
        ).fetchone()
        self.assertEqual(int(rocky["public_port"]), 6001)
        problems = UR.invariant_reservations_match_registry(self.plane, self.registry)
        self.assertEqual(problems, [])

    def test_UPGRADE_VALID_ENDPOINT_STABILITY(self):
        self._apply()
        expected = {
            (IDS["ubuntu24"], "ssh", 6000),
            (IDS["rocky8"], "ssh", 6001),
            (IDS["rocky9"], "ssh", 6002),
            (IDS["al2023"], "ssh", 6003),
            (IDS["macos"], "ssh", 6004),
            (IDS["al2023"], "e2e-ssh", 6005),
        }
        for cid, name, port in expected:
            row = self.plane.conn.execute(
                "SELECT public_port FROM published_services WHERE client_id = ? AND name = ? AND released = 0",
                (cid, name),
            ).fetchone()
            self.assertEqual(int(row["public_port"]), port, name)

    def test_UPGRADE_REPEAT_IDEMPOTENCY(self):
        first = self._apply()
        self.assertTrue(first["applied"])
        rev = self.plane.current_revision()
        clients = self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        hosts = self.plane.conn.execute(
            "SELECT COUNT(*) FROM objects WHERE type = 'managed_endpoint'"
        ).fetchone()[0]
        services = self.plane.conn.execute(
            "SELECT COUNT(*) FROM published_services WHERE released = 0"
        ).fetchone()[0]
        second = self._apply()
        self.assertTrue(second["skipped"])
        self.assertEqual(self.plane.current_revision(), rev)
        self.assertEqual(
            self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0], clients
        )
        self.assertEqual(
            self.plane.conn.execute(
                "SELECT COUNT(*) FROM objects WHERE type = 'managed_endpoint'"
            ).fetchone()[0],
            hosts,
        )
        self.assertEqual(
            self.plane.conn.execute(
                "SELECT COUNT(*) FROM published_services WHERE released = 0"
            ).fetchone()[0],
            services,
        )

    def test_UPGRADE_FRESH_ENROLLMENT_NO_DUPLICATE(self):
        fresh = tempfile.mkdtemp(prefix="drlink-fresh-")
        plane = ControlPlane(fresh)
        v24.ensure_v2_schema(plane.conn)
        mid = "ffffffffffffffffffffffffffffff01"
        for _ in range(2):
            RP.sync_enrolled_client(
                plane,
                client_id=mid,
                hostname="fresh-host",
                label="fresh-host",
                services={
                    "ssh": _legacy_ssh(6000),
                    "rs-web": {
                        "name": "web",
                        "v24_remote_service": True,
                        "remote_port": 6010,
                        "local_port": 80,
                    },
                },
            )
        self.assertEqual(plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0], 1)
        self.assertEqual(
            plane.conn.execute(
                "SELECT COUNT(*) FROM objects WHERE type = 'managed_endpoint'"
            ).fetchone()[0],
            1,
        )
        names = [r["name"] for r in plane.conn.execute("SELECT name FROM published_services")]
        self.assertIn("ssh", names)
        self.assertNotIn("rs-web", names)
        plane.close()

    def test_FRESH_AND_UPGRADED_BEHAVIOR_PARITY(self):
        self._apply()
        upgraded = self.plane.get_object("real-e2e-al2023")
        self.assertEqual(upgraded["type"], "managed_endpoint")
        fresh = tempfile.mkdtemp(prefix="drlink-fresh-p-")
        plane = ControlPlane(fresh)
        v24.ensure_v2_schema(plane.conn)
        RP.sync_enrolled_client(
            plane,
            client_id=IDS["al2023"],
            hostname="real-e2e-al2023",
            label="real-e2e-al2023",
            services={"ssh": _legacy_ssh(6003)},
        )
        fresh_obj = plane.get_object("real-e2e-al2023")
        self.assertEqual(fresh_obj["type"], upgraded["type"])
        listed_u = {r["name"]: r["type"] for r in v24.list_network_objects(self.plane)}
        listed_f = {r["name"]: r["type"] for r in v24.list_network_objects(plane)}
        self.assertEqual(listed_u["real-e2e-al2023"], listed_f["real-e2e-al2023"])
        self.assertEqual(listed_f["real-e2e-al2023"], "Managed Host")
        plane.close()

    def test_UPGRADE_PRESERVES_EXISTING_HOSTNAME_AND_HEALTHY_SELF_DEST(self):
        # Live lineage: SQLite hostname is the OS name; registry label is the public MH name.
        self.plane.conn.execute(
            "UPDATE clients SET hostname = 'ip-10-0-19-146', label = 'ip-10-0-19-146' WHERE id = ?",
            (IDS["al2023"],),
        )
        self.plane.conn.execute(
            "UPDATE remote_service_meta SET destination_name = 'ip-10-0-19-146' "
            "WHERE service_id = (SELECT id FROM published_services WHERE name = 'e2e-ssh')"
        )
        self.plane.conn.commit()
        self._apply()
        client = self.plane.conn.execute(
            "SELECT hostname, label FROM clients WHERE id = ?", (IDS["al2023"],)
        ).fetchone()
        self.assertEqual(client["hostname"], "ip-10-0-19-146")
        self.assertEqual(client["label"], "real-e2e-al2023")
        self.assertIsNotNone(self.plane.get_object("real-e2e-al2023"))
        ssh = self.plane.conn.execute(
            "SELECT s.public_port, m.status, m.destination_name FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id WHERE s.name = 'e2e-ssh'"
        ).fetchone()
        self.assertEqual(int(ssh["public_port"]), 6005)
        self.assertEqual(ssh["status"], "HEALTHY")
        self.assertEqual(ssh["destination_name"], "ip-10-0-19-146")

    def test_UPGRADE_RECONCILE_PRESERVES_STALE_LAST_SEEN(self):
        stale = "2026-09-19T08:29:50Z"
        self.plane.conn.execute(
            "UPDATE clients SET last_seen = ?, connected = 1, status = 'connected', "
            "trust_status = 'trusted' WHERE id = ?",
            (stale, IDS["al2023"]),
        )
        self.plane.conn.commit()
        before = self.plane.conn.execute(
            "SELECT * FROM clients WHERE id = ?", (IDS["al2023"],)
        ).fetchone()
        self.assertEqual(before["last_seen"], stale)
        self.assertFalse(self.plane.ai_executor_ready(before))
        self._apply()
        after = self.plane.conn.execute(
            "SELECT * FROM clients WHERE id = ?", (IDS["al2023"],)
        ).fetchone()
        self.assertEqual(after["last_seen"], stale)
        self.assertEqual(after["last_seen"], before["last_seen"])
        self.assertEqual(int(after["connected"]), 1)
        self.assertFalse(self.plane.ai_executor_ready(after))
        self.assertIsNotNone(self.plane.get_object("real-e2e-al2023"))
        fresh = self.plane.conn.execute(
            "SELECT last_seen FROM clients WHERE id = ?", (IDS["macos"],)
        ).fetchone()
        self.assertTrue(fresh["last_seen"])
        self.assertNotEqual(fresh["last_seen"], stale)

    def test_corrupt_registry_does_not_mutate(self):
        bad = {"not": "clients"}
        before = self.plane.current_revision()
        with self.assertRaises(Exception):
            UR.apply_upgrade_reconciliation(self.plane, bad)
        self.assertEqual(self.plane.current_revision(), before)
        self.assertEqual(self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0], 1)


def _extract_ensure_control_plane_python() -> str:
    text = (ROOT / "lib" / "frp-server-upgrade.sh").read_text(encoding="utf-8")
    start = text.index("frp_server_upgrade_ensure_control_plane()")
    chunk = text[start:]
    marker = "<<'PY'"
    py_open = chunk.index(marker) + len(marker)
    py_start = chunk.index("\n", py_open) + 1
    py_end = chunk.index("\nPY\n", py_start)
    return chunk[py_start:py_end]


class UpgradeHookRootTests(unittest.TestCase):
    def test_UPGRADE_HOOK_ROOT_REAL_FS(self):
        from drlink_control_db import deploy_root_from_db_path

        self.assertEqual(deploy_root_from_db_path("/var/lib/drlink/drlink.db"), "/")
        self.assertEqual(deploy_root_from_db_path(Path("/var/lib/drlink/drlink.db")), "/")
        # The previous three-parent walk stopped at /var instead of /.
        self.assertEqual(Path("/var/lib/drlink/drlink.db").parent.parent.parent, Path("/var"))
        src = (ROOT / "lib" / "frp-server-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("deploy_root_from_db_path", src)
        self.assertNotIn("db_path.parent.parent.parent", src)

    def test_UPGRADE_HOOK_ROOT_STAGING_FS(self):
        from drlink_control_db import deploy_root_from_db_path

        self.assertEqual(
            deploy_root_from_db_path("/tmp/test-root/var/lib/drlink/drlink.db"),
            "/tmp/test-root",
        )
        tmp = tempfile.mkdtemp(prefix="drlink-hook-staging-")
        db = Path(tmp) / "var" / "lib" / "drlink" / "drlink.db"
        self.assertEqual(deploy_root_from_db_path(db), tmp)
        self.assertEqual(db.parent.parent.parent, Path(tmp) / "var")

    def test_UPGRADE_HOOK_NO_VAR_VAR_SHADOW_STATE(self):
        tmp = tempfile.mkdtemp(prefix="drlink-hook-novarvar-")
        env_keys = (
            "FRP_DEPLOY_TEST_ROOT",
            "FRP_CTL_TEST_ROOT",
            "FRP_SERVER_TEST_ROOT",
            "DRLINK_TEST_ROOT",
        )
        saved = {key: os.environ.get(key) for key in env_keys}
        for key in env_keys:
            os.environ.pop(key, None)
        plane = ControlPlane(tmp)
        v24.ensure_v2_schema(plane.conn)
        plane.close()
        db = Path(tmp) / "var" / "lib" / "drlink" / "drlink.db"
        self.assertTrue(db.is_file())
        registry = Path(tmp) / "var" / "lib" / "drlink" / "runtime" / "client-inventory.json"
        _write_json(registry, {"schema_version": 2, "clients": {}, "reserved": []})
        py_src = _extract_ensure_control_plane_python()
        self.assertIn("deploy_root_from_db_path", py_src)
        self.assertNotIn("parent.parent.parent", py_src)
        proc = subprocess.run(
            [
                sys.executable,
                "-",
                str(db),
                str(ROOT / "lib" / "drlink_control_db.py"),
                str(ROOT / "lib" / "drlink_control_plane.py"),
            ],
            input=py_src,
            capture_output=True,
            text=True,
            check=False,
        )
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
        self.assertIn("CONTROL_PLANE_ROOT=%s" % tmp, proc.stdout)
        shadow = Path(tmp) / "var" / "var" / "lib" / "drlink"
        self.assertFalse(shadow.exists(), "upgrade hook created shadow state at %s" % shadow)
        self.assertTrue(db.is_file())
        self.assertFalse((Path(tmp) / "var" / "var").exists())


if __name__ == "__main__":
    unittest.main()
