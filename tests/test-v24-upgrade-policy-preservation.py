#!/usr/bin/env python3
"""v2.3 restrictive Remote/Internet policy must survive upgrade reconcile."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane
import drlink_upgrade_reconcile as UR
import drlink_v24 as v24

CLIENT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
LABEL = "legacy-host"


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _registry() -> dict:
    return {
        "schema_version": 2,
        "reserved": [6000],
        "clients": {
            CLIENT: {
                "hostname": LABEL,
                "label": LABEL,
                "services": {
                    "ssh": {
                        "id": "ssh",
                        "preset": "ssh",
                        "local_ip": "127.0.0.1",
                        "local_port": 22,
                        "remote_port": 6000,
                        "enabled": True,
                    }
                },
            }
        },
    }


def _access(*, allow: bool) -> dict:
    if not allow:
        return {"schema_version": 1, "access_lists": {}, "service_access": {}}
    return {
        "schema_version": 1,
        "access_lists": {
            "acl_001122334455": {
                "id": "acl_001122334455",
                "name": "office",
                "description": "",
                "entries": [
                    {
                        "id": "ace_001122334455",
                        "name": "office-host",
                        "cidr": "198.51.100.10/32",
                    }
                ],
            }
        },
        "service_access": {
            CLIENT: {
                "ssh": {
                    "access_mode": "ALLOWLIST",
                    "access_list_id": "acl_001122334455",
                }
            }
        },
    }


def _egress(*, enabled: bool, host: str = "example.com", match: str = "exact") -> dict:
    return {
        "schema_version": 3,
        "tcp_relays": {},
        "egress_profiles": {
            "egp_aabbccddeeff": {
                "id": "egp_aabbccddeeff",
                "name": "lab-egress",
                "description": "restrictive upgrade seed",
                "enabled": enabled,
                "sources": [
                    {
                        "id": "egs_aabbccddeeff",
                        "cidr": "10.20.30.0/24",
                        "description": "lab",
                    }
                ],
                "destinations": [
                    {
                        "id": "egd_aabbccddeeff",
                        "host": host,
                        "port": 443,
                        "protocol": "https",
                        "match": match,
                    }
                ],
                "created_at": "2026-09-21T00:00:00Z",
                "updated_at": "2026-09-21T00:00:00Z",
            }
        },
    }


class UpgradePolicyPreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-upol-")
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        self.registry = _registry()
        UR._MIGRATION_CHECKPOINT = None

    def tearDown(self):
        UR._MIGRATION_CHECKPOINT = None
        try:
            self.plane.close()
        except Exception:
            pass

    def _seed(self, access: dict | None, egress: dict | None) -> None:
        base = Path(self.tmp) / "var/lib/drlink"
        if access is not None:
            _write(base / "access-control.json", access)
        if egress is not None:
            _write(base / "egress-control.json", egress)

    def _apply(self):
        return UR.apply_upgrade_reconciliation(self.plane, self.registry, connected=False)

    def _counts(self) -> tuple[int, int, int]:
        rules = self.plane.conn.execute("SELECT COUNT(*) FROM policy_rules").fetchone()[0]
        nets = self.plane.conn.execute(
            "SELECT COUNT(*) FROM objects WHERE origin != 'managed' AND type != 'managed_endpoint'"
        ).fetchone()[0]
        svcs = self.plane.conn.execute("SELECT COUNT(*) FROM service_objects").fetchone()[0]
        return int(rules), int(nets), int(svcs)

    def test_remote_allowlist_preserved(self):
        self._seed(_access(allow=True), None)
        result = self._apply()
        self.assertTrue(result["applied"])
        allowed = self.plane.evaluate_remote_access("198.51.100.10", LABEL, "tcp", 22)
        denied = self.plane.evaluate_remote_access("203.0.113.99", LABEL, "tcp", 22)
        self.assertEqual(allowed["action"], "ALLOW")
        self.assertEqual(denied["action"], "DENY")
        self.assertNotEqual(denied["reason"], "No Policy (ALLOW)")
        self.assertGreater(
            self.plane.conn.execute(
                "SELECT COUNT(*) FROM policy_rules WHERE plane = 'remote'"
            ).fetchone()[0],
            0,
        )
        row = self.plane.conn.execute(
            "SELECT public_port FROM published_services WHERE client_id = ? AND name = 'ssh'",
            (CLIENT,),
        ).fetchone()
        self.assertEqual(int(row["public_port"]), 6000)
        reserved = self.plane.conn.execute(
            "SELECT 1 FROM port_reservations WHERE public_port = 6000 AND released = 0"
        ).fetchone()
        self.assertIsNotNone(reserved)

    def test_internet_enabled_profile_preserved(self):
        self._seed(_access(allow=False), _egress(enabled=True))
        self._apply()
        match = self.plane.evaluate_internet_access("10.20.30.5", "example.com", 443, "https")
        wrong_src = self.plane.evaluate_internet_access("203.0.113.9", "example.com", 443, "https")
        wrong_dst = self.plane.evaluate_internet_access("10.20.30.5", "other.example", 443, "https")
        self.assertEqual(match["action"], "ALLOW")
        self.assertEqual(wrong_src["action"], "DENY")
        self.assertEqual(wrong_dst["action"], "DENY")
        self.assertNotIn("No Policy (ALLOW)", wrong_src["reason"])
        self.assertGreater(
            self.plane.conn.execute(
                "SELECT COUNT(*) FROM policy_rules WHERE plane = 'internet'"
            ).fetchone()[0],
            0,
        )

    def test_empty_and_disabled_legacy_does_not_invent_policy(self):
        self._seed(_access(allow=False), _egress(enabled=False))
        self._apply()
        self.assertEqual(
            self.plane.conn.execute("SELECT COUNT(*) FROM policy_rules").fetchone()[0],
            0,
        )
        remote = v24.get_access_policy(self.plane, "remote")
        internet = v24.get_access_policy(self.plane, "internet")
        self.assertIsNone(remote["mode"])
        self.assertIsNone(internet["mode"])
        denied_before = self.plane.evaluate_remote_access("203.0.113.99", LABEL, "tcp", 22)
        self.assertEqual(denied_before["action"], "ALLOW")
        self.assertIn("No Policy", denied_before["reason"])
        other = self.plane.evaluate_internet_access("203.0.113.9", "example.com", 443, "https")
        self.assertEqual(other["action"], "ALLOW")

    def test_reconcile_is_idempotent(self):
        self._seed(_access(allow=True), _egress(enabled=True))
        first = self._apply()
        self.assertTrue(first["applied"])
        counts = self._counts()
        rev = self.plane.current_revision()
        second = self._apply()
        self.assertTrue(second["skipped"])
        self.assertEqual(self._counts(), counts)
        self.assertEqual(self.plane.current_revision(), rev)
        self.assertEqual(
            self.plane.evaluate_remote_access("203.0.113.99", LABEL, "tcp", 22)["action"],
            "DENY",
        )
        self.assertEqual(
            self.plane.evaluate_internet_access("10.20.30.5", "example.com", 443, "https")["action"],
            "ALLOW",
        )

    def test_failure_during_migration_does_not_broaden(self):
        self._seed(_access(allow=True), _egress(enabled=True))
        before_clients = self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]

        def boom(stage):
            if stage == "legacy-policy-rule":
                raise ControlPlaneError("injected legacy policy migration failure")

        UR._MIGRATION_CHECKPOINT = boom
        with self.assertRaises(ControlPlaneError):
            self._apply()
        self.assertEqual(
            self.plane.conn.execute("SELECT COUNT(*) FROM policy_rules").fetchone()[0],
            0,
        )
        self.assertIsNone(v24.get_access_policy(self.plane, "remote")["mode"])
        self.assertIsNone(v24.get_access_policy(self.plane, "internet")["mode"])
        self.assertEqual(
            self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
            before_clients,
        )
        denied = self.plane.evaluate_remote_access("198.51.100.10", LABEL, "tcp", 22)
        other = self.plane.evaluate_remote_access("203.0.113.99", LABEL, "tcp", 22)
        self.assertEqual(denied["action"], "DENY")
        self.assertEqual(other["action"], "DENY")
        self.assertIn("not migrated", denied["reason"])
        self.assertNotIn("No Policy (ALLOW)", denied["reason"])

    def test_wildcard_egress_fails_closed(self):
        self._seed(_access(allow=False), _egress(enabled=True, host="*.example.com", match="wildcard"))
        before = self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        with self.assertRaises(ControlPlaneError) as ctx:
            self._apply()
        self.assertIn("wildcard", str(ctx.exception).lower())
        self.assertEqual(
            self.plane.conn.execute("SELECT COUNT(*) FROM policy_rules").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.plane.conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
            before,
        )
        verdict = self.plane.evaluate_internet_access("10.20.30.5", "a.example.com", 443, "https")
        self.assertEqual(verdict["action"], "DENY")
        self.assertNotIn("No Policy (ALLOW)", verdict["reason"])


if __name__ == "__main__":
    unittest.main()
