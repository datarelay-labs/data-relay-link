#!/usr/bin/env python3
"""Focused unit tests for canonical runtime policy adapters."""
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
import drlink_v24 as v24


class RuntimePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-rp-test-")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        self.plane = ControlPlane(self.tmp)
        self.mid = "abcd1234ffffeeeeabcd1234ffffeeee"
        self.plane.set_object_type("office", "network")
        self.plane.set_object_value("office", "198.51.100.0/24")
        self.plane.upsert_client(
            self.mid,
            label="lab",
            hostname="labhost",
            addresses=[{"address": "10.0.0.5", "active": True}],
        )
        self.plane.set_published_service(
            self.mid,
            "ssh",
            service_type="ssh",
            target_mode="self",
            target_host="127.0.0.1",
            target_port=22,
            enabled=True,
            public_port=6001,
        )
        v24.ensure_policy_mode(self.plane, "remote", "whitelist", oneshot=True)
        self.plane.set_rule("remote", "allow-office")
        self.plane.set_rule_source("remote", "allow-office", "office")
        self.plane.set_rule_destination("remote", "allow-office", "lab")
        self.plane.set_rule_service("remote", "allow-office", "tcp", 22)
        self.plane.set_rule_action("remote", "allow-office", "allow")
        self.plane.set_rule_enabled("remote", "allow-office", True)

    def tearDown(self):
        self.plane.close()

    def test_remote_allow_deny(self):
        proxy = RP.expected_proxy_name("labhost", self.mid, "ssh")
        allow = RP.authorize_remote(self.plane, proxy_name=proxy, source_ip="198.51.100.9:1")
        deny = RP.authorize_remote(self.plane, proxy_name=proxy, source_ip="203.0.113.9:1")
        self.assertEqual(allow["decision"], RP.DECISION_ALLOW)
        self.assertEqual(deny["decision"], RP.DECISION_DENY)

    def test_unmapped_proxy_denies(self):
        verdict = RP.authorize_remote(
            self.plane, proxy_name="unknown-proxy", source_ip="198.51.100.9"
        )
        self.assertEqual(verdict["decision"], RP.DECISION_DENY)
        self.assertEqual(verdict["reason"], RP.REASON_UNMAPPED_PROXY)

    def test_enrollment_sync_writes_sqlite(self):
        other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        RP.sync_enrolled_client(
            self.plane,
            client_id=other,
            hostname="edge",
            label="edge1",
            services={
                "web": {
                    "local_ip": "127.0.0.1",
                    "local_port": 80,
                    "remote_port": 6002,
                    "preset": "http",
                    "enabled": True,
                }
            },
        )
        row = self.plane.conn.execute(
            "SELECT * FROM published_services WHERE client_id = ? AND name = 'web'",
            (other,),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(int(row["public_port"]), 6002)
        ep = self.plane.conn.execute(
            "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id "
            "WHERE e.client_id = ?",
            (other,),
        ).fetchone()
        self.assertIsNotNone(ep)

    def test_internet_and_fixed_tcp(self):
        self.plane.set_object_type("api", "fqdn")
        self.plane.set_object_value("api", "example.com")
        v24.ensure_policy_mode(self.plane, "internet", "whitelist", oneshot=True)
        self.plane.set_rule("internet", "allow-api")
        self.plane.set_rule_source("internet", "allow-api", "office")
        self.plane.set_rule_destination("internet", "allow-api", "api")
        self.plane.set_rule_service("internet", "allow-api", "tcp", 443)
        self.plane.set_rule_action("internet", "allow-api", "allow")
        self.plane.set_rule_enabled("internet", "allow-api", True)
        self.plane.set_fixed_tcp(
            "pin", dest_host="example.com", dest_port=443, listen_port=6201, enabled=True
        )
        allow = RP.authorize_internet(
            self.plane, source_ip="198.51.100.9", hostname="example.com", port=443, protocol="https"
        )
        deny = RP.authorize_internet(
            self.plane, source_ip="203.0.113.9", hostname="example.com", port=443, protocol="https"
        )
        fixed = RP.authorize_fixed_tcp(self.plane, relay_id="pin", source_ip="198.51.100.9")
        self.assertEqual(allow["decision"], RP.DECISION_ALLOW)
        self.assertEqual(deny["decision"], RP.DECISION_DENY)
        self.assertEqual(fixed["decision"], RP.DECISION_ALLOW)


if __name__ == "__main__":
    unittest.main()
