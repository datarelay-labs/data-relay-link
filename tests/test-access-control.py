#!/usr/bin/env python3
"""Unit coverage for Access Control Pack helpers."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_acl():
    path = ROOT / "lib" / "frp_access_control.py"
    spec = importlib.util.spec_from_file_location("frp_access_control", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ACL = load_acl()


class AccessControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.access_path = self.root / "access-control.json"
        self.log_path = self.root / "access-conn.jsonl"
        self.state = ACL.empty_access_state()
        self.registry = {
            "schema_version": 2,
            "clients": {
                "machine-aaa": {
                    "label": "alpha",
                    "hostname": "alpha-host",
                    "services": {
                        "ssh": {"remote_port": 6001, "enabled": True},
                        "web": {"remote_port": 6002, "enabled": True},
                    },
                }
            },
            "reserved": [6001, 6002],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_list_duplicate_name(self):
        lid, lst = ACL.create_access_list(self.state, "Office")
        self.assertTrue(lid.startswith("acl_"))
        self.assertEqual(lst["name"], "Office")
        with self.assertRaises(ACL.AccessError):
            ACL.create_access_list(self.state, "office")
        names = [v["name"] for v in self.state["access_lists"].values()]
        self.assertEqual(names, ["Office"])

    def test_cidr_canonicalize_ipv4_ipv6(self):
        self.assertEqual(ACL.canonicalize_cidr("192.0.2.10"), "192.0.2.10/32")
        self.assertEqual(ACL.canonicalize_cidr("192.0.2.0/24"), "192.0.2.0/24")
        self.assertEqual(ACL.canonicalize_cidr("2001:db8::1"), "2001:db8::1/128")
        self.assertEqual(ACL.canonicalize_cidr("2001:db8::/64"), "2001:db8::/64")

    def test_invalid_cidr(self):
        with self.assertRaises(ACL.AccessError):
            ACL.canonicalize_cidr("not-an-ip")
        with self.assertRaises(ACL.AccessError):
            ACL.canonicalize_cidr("192.0.2.0/99")

    def test_duplicate_equivalent_cidr(self):
        lid, _ = ACL.create_access_list(self.state, "Desk")
        ACL.add_source_entry(self.state, lid, "home", "192.0.2.8")
        with self.assertRaises(ACL.AccessError):
            ACL.add_source_entry(self.state, lid, "home2", "192.0.2.8/32")

    def test_ttl_parse_expires_at(self):
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        exp = ACL.parse_ttl("4h", now=now)
        self.assertEqual(exp, now + timedelta(hours=4))
        self.assertEqual(ACL.format_iso(exp), "2026-01-01T16:00:00Z")

    def test_public_allow(self):
        result = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="198.51.100.9",
        )
        self.assertEqual(result["decision"], ACL.DECISION_ALLOW)
        self.assertEqual(result["reason"], ACL.REASON_PUBLIC)

    def test_allowlist_match_and_deny(self):
        lid, _ = ACL.create_access_list(self.state, "Allow")
        ACL.add_source_entry(self.state, lid, "net", "198.51.100.0/24")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        allow = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="198.51.100.20",
        )
        self.assertEqual(allow["decision"], ACL.DECISION_ALLOW)
        self.assertEqual(allow["reason"], ACL.REASON_CIDR_MATCH)
        deny = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="203.0.113.20",
        )
        self.assertEqual(deny["decision"], ACL.DECISION_DENY)
        self.assertEqual(deny["reason"], ACL.REASON_SOURCE_NOT_ALLOWED)

    def test_expired_deny(self):
        lid, _ = ACL.create_access_list(self.state, "Temp")
        past = (ACL.utc_now() - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        ACL.add_source_entry(self.state, lid, "old", "203.0.113.5", expires_at=past)
        # Force allowlist even with only expired entries via direct mutation.
        self.state.setdefault("service_access", {}).setdefault("machine-aaa", {})["ssh"] = {
            "access_mode": ACL.MODE_ALLOWLIST,
            "access_list_id": lid,
        }
        result = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="203.0.113.5",
        )
        self.assertEqual(result["decision"], ACL.DECISION_DENY)
        self.assertEqual(result["reason"], ACL.REASON_ENTRY_EXPIRED)

    def test_missing_list_fail_closed(self):
        self.state.setdefault("service_access", {}).setdefault("machine-aaa", {})["ssh"] = {
            "access_mode": ACL.MODE_ALLOWLIST,
            "access_list_id": "acl_missing",
        }
        result = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="203.0.113.5",
        )
        self.assertEqual(result["decision"], ACL.DECISION_DENY)
        self.assertEqual(result["reason"], ACL.REASON_ACCESS_LIST_MISSING)

    def test_referenced_delete_rejected(self):
        lid, _ = ACL.create_access_list(self.state, "Used")
        ACL.add_source_entry(self.state, lid, "net", "10.0.0.0/8")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        with self.assertRaises(ACL.AccessError) as ctx:
            ACL.delete_access_list(self.state, lid)
        self.assertIn("still referenced", str(ctx.exception))

    def test_empty_allowlist_assign_rejected(self):
        lid, _ = ACL.create_access_list(self.state, "Empty")
        with self.assertRaises(ACL.AccessError) as ctx:
            ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        self.assertIn("No allowed sources", str(ctx.exception))

    def test_release_binding_cleanup_helpers(self):
        lid, _ = ACL.create_access_list(self.state, "Cleanup")
        ACL.add_source_entry(self.state, lid, "net", "10.1.0.0/16")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        ACL.set_service_binding(self.state, "machine-aaa", "web", ACL.MODE_ALLOWLIST, lid)
        self.assertTrue(ACL.clear_service_binding(self.state, "machine-aaa", "ssh"))
        self.assertEqual(
            ACL.get_service_binding(self.state, "machine-aaa", "ssh")["access_mode"],
            ACL.MODE_PUBLIC,
        )
        removed = ACL.clear_client_bindings(self.state, "machine-aaa")
        self.assertEqual(removed, 1)
        self.assertNotIn("machine-aaa", self.state.get("service_access") or {})

    def test_conn_log_allow_deny_without_secrets(self):
        event = {
            "timestamp": ACL.utc_now_iso(),
            "client_id": "machine-aaa",
            "client_label": "alpha",
            "service_id": "ssh",
            "public_port": 6001,
            "source_ip": "198.51.100.1",
            "access_mode": ACL.MODE_PUBLIC,
            "decision": ACL.DECISION_ALLOW,
            "reason": ACL.REASON_PUBLIC,
            "token": "should-not-appear",
            "server_token": "nope",
        }
        ACL.emit_conn_log(event, path=self.log_path)
        deny = dict(event)
        deny["decision"] = ACL.DECISION_DENY
        deny["reason"] = ACL.REASON_SOURCE_NOT_ALLOWED
        ACL.emit_conn_log(deny, path=self.log_path)
        text = self.log_path.read_text(encoding="utf-8")
        self.assertIn('"decision":"ALLOW"', text)
        self.assertIn('"decision":"DENY"', text)
        self.assertNotIn("should-not-appear", text)
        self.assertNotIn("server_token", text)
        self.assertNotIn("nope", text)

    def test_plugin_authorize_path(self):
        lid, _ = ACL.create_access_list(self.state, "Plugin")
        ACL.add_source_entry(self.state, lid, "office", "192.0.2.0/24")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        proxy = ACL.expected_proxy_name("alpha-host", "machine-aaa", "ssh")
        result = ACL.authorize(
            self.state,
            self.registry,
            proxy_name=proxy,
            source_ip="192.0.2.55",
        )
        self.assertEqual(result["decision"], ACL.DECISION_ALLOW)
        self.assertEqual(result["service_id"], "ssh")
        self.assertEqual(result["client_id"], "machine-aaa")

    def test_save_load_roundtrip(self):
        ACL.save_access_state(self.state, path=self.access_path)
        loaded = ACL.load_access_state(path=self.access_path)
        self.assertEqual(loaded["schema_version"], ACL.ACCESS_SCHEMA_VERSION)
        self.assertEqual(loaded["access_lists"], {})


if __name__ == "__main__":
    unittest.main()
