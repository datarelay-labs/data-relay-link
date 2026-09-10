#!/usr/bin/env python3
"""Unit coverage for Access Control Pack helpers."""
from __future__ import annotations

import importlib.util
import json
import os
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

    def test_unmapped_proxy_fail_closed(self):
        """Registered ALLOWLIST service must DENY when proxy_name mapping fails."""
        lid, _ = ACL.create_access_list(self.state, "Mapped")
        ACL.add_source_entry(self.state, lid, "net", "198.51.100.0/24")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        # Correct mapping still allows.
        good = ACL.expected_proxy_name("alpha-host", "machine-aaa", "ssh")
        allow = ACL.authorize(
            self.state,
            self.registry,
            proxy_name=good,
            source_ip="198.51.100.9",
        )
        self.assertEqual(allow["decision"], ACL.DECISION_ALLOW)
        # Drifted/unknown proxy_name must not PUBLIC-bypass ALLOWLIST.
        deny = ACL.authorize(
            self.state,
            self.registry,
            proxy_name="drifted-host-machine-ssh",
            source_ip="198.51.100.9",
        )
        self.assertEqual(deny["decision"], ACL.DECISION_DENY)
        self.assertEqual(deny["reason"], ACL.REASON_UNMAPPED_PROXY)
        self.assertNotEqual(deny["decision"], ACL.DECISION_ALLOW)
        self.assertNotEqual(deny.get("reason"), ACL.REASON_PUBLIC)

    def test_last_usable_source_removal_rejected(self):
        lid, _ = ACL.create_access_list(self.state, "LastOne")
        ACL.add_source_entry(self.state, lid, "only", "203.0.113.10")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        with self.assertRaises(ACL.AccessError) as ctx:
            ACL.remove_source_entry(self.state, lid, "203.0.113.10")
        self.assertIn("empty ALLOWLIST", str(ctx.exception))
        self.assertIn("Use Disable", str(ctx.exception))
        # Previous entry preserved; binding stays ALLOWLIST (no PUBLIC fallback).
        entries = self.state["access_lists"][lid]["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["cidr"], "203.0.113.10/32")
        binding = ACL.get_service_binding(self.state, "machine-aaa", "ssh")
        self.assertEqual(binding["access_mode"], ACL.MODE_ALLOWLIST)

    def test_replace_source_atomic_preserves_on_failure(self):
        lid, _ = ACL.create_access_list(self.state, "Replace")
        ACL.add_source_entry(self.state, lid, "old", "198.51.100.1")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        with self.assertRaises(ACL.AccessError):
            ACL.replace_source_entry(self.state, lid, "198.51.100.1", "bad", "not-an-ip")
        entries = self.state["access_lists"][lid]["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "old")
        self.assertEqual(entries[0]["cidr"], "198.51.100.1/32")
        replaced = ACL.replace_source_entry(
            self.state, lid, "198.51.100.1", "new", "198.51.100.2"
        )
        self.assertEqual(replaced["name"], "new")
        self.assertEqual(replaced["cidr"], "198.51.100.2/32")
        self.assertEqual(len(self.state["access_lists"][lid]["entries"]), 1)

    def test_expired_cleanup_allowed_while_allowlist_empty(self):
        """Expired-only cleanup succeeds; binding stays ALLOWLIST; auth stays DENY."""
        lid, _ = ACL.create_access_list(self.state, "TempOnly")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0)
        ACL.add_source_entry(
            self.state,
            lid,
            "gone",
            "198.51.100.9",
            expires_at=past.isoformat().replace("+00:00", "Z"),
        )
        # Direct mutation: assign ALLOWLIST that already has only expired sources.
        self.state.setdefault("service_access", {}).setdefault("machine-aaa", {})["ssh"] = {
            "access_mode": ACL.MODE_ALLOWLIST,
            "access_list_id": lid,
        }
        removed = ACL.remove_expired_entries(self.state, lid)
        self.assertEqual(len(removed), 1)
        self.assertEqual(self.state["access_lists"][lid]["entries"], [])
        binding = ACL.get_service_binding(self.state, "machine-aaa", "ssh")
        self.assertEqual(binding["access_mode"], ACL.MODE_ALLOWLIST)
        deny = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="198.51.100.9",
        )
        self.assertEqual(deny["decision"], ACL.DECISION_DENY)
        self.assertNotEqual(deny.get("reason"), ACL.REASON_PUBLIC)

    def test_save_load_roundtrip(self):
        ACL.save_access_state(self.state, path=self.access_path)
        loaded = ACL.load_access_state(path=self.access_path)
        self.assertEqual(loaded["schema_version"], ACL.ACCESS_SCHEMA_VERSION)
        self.assertEqual(loaded["access_lists"], {})


    def test_disabled_service_fail_closed_public_and_allowlist(self):
        """AUDIT-004: disabled registry services must DENY regardless of binding."""
        self.registry["clients"]["machine-aaa"]["services"]["ssh"]["enabled"] = False
        # PUBLIC binding path
        result = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="198.51.100.9",
        )
        self.assertEqual(result["decision"], ACL.DECISION_DENY)
        self.assertEqual(result["reason"], ACL.REASON_SERVICE_DISABLED)

        # ALLOWLIST binding path
        lid, _ = ACL.create_access_list(self.state, "DeskNet")
        ACL.add_source_entry(self.state, lid, "desk", "198.51.100.0/24")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        result = ACL.authorize(
            self.state,
            self.registry,
            client_id="machine-aaa",
            service_id="ssh",
            source_ip="198.51.100.9",
        )
        self.assertEqual(result["decision"], ACL.DECISION_DENY)
        self.assertEqual(result["reason"], ACL.REASON_SERVICE_DISABLED)

        # Stale proxy NewUserConn path via proxy_name
        proxy = ACL.expected_proxy_name("alpha-host", "machine-aaa", "ssh")
        result = ACL.authorize(
            self.state,
            self.registry,
            proxy_name=proxy,
            source_ip="198.51.100.9",
        )
        self.assertEqual(result["decision"], ACL.DECISION_DENY)
        self.assertEqual(result["reason"], ACL.REASON_SERVICE_DISABLED)

        # Re-enable restores PUBLIC allow
        self.registry["clients"]["machine-aaa"]["services"]["ssh"]["enabled"] = True
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_PUBLIC, None)
        result = ACL.authorize(
            self.state,
            self.registry,
            proxy_name=proxy,
            source_ip="198.51.100.9",
        )
        self.assertEqual(result["decision"], ACL.DECISION_ALLOW)
        self.assertEqual(result["reason"], ACL.REASON_PUBLIC)

        # Re-enable + matching ALLOWLIST
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        result = ACL.authorize(
            self.state,
            self.registry,
            proxy_name=proxy,
            source_ip="198.51.100.9",
        )
        self.assertEqual(result["decision"], ACL.DECISION_ALLOW)

    def test_proxy_name_collision_fail_closed(self):
        """AUDIT-009: colliding derived proxy names must not last-write-wins."""
        # Same hostname + same first 8 machine-id chars + same service id
        self.registry["clients"]["machineaabb01"] = {
            "label": "one",
            "hostname": "same-host",
            "services": {"ssh": {"remote_port": 6011, "enabled": True}},
        }
        self.registry["clients"]["machineaabb02"] = {
            "label": "two",
            "hostname": "same-host",
            "services": {"ssh": {"remote_port": 6012, "enabled": True}},
        }
        # Prefixes: machineaabb01[:8]=machinea, machineaabb02[:8]=machinea — collision
        with self.assertRaises(ACL.AccessError) as ctx:
            ACL.build_proxy_map(self.registry)
        self.assertIn("collision", str(ctx.exception).lower())

        # Unique names remain usable
        ok_reg = {
            "schema_version": 2,
            "clients": {
                "aaaaaaaa0001": {
                    "hostname": "host-a",
                    "services": {"ssh": {"remote_port": 6001, "enabled": True}},
                },
                "bbbbbbbb0002": {
                    "hostname": "host-b",
                    "services": {"ssh": {"remote_port": 6002, "enabled": True}},
                },
            },
        }
        mapping = ACL.build_proxy_map(ok_reg)
        self.assertEqual(len(mapping), 2)



class PolicyCacheFailClosedTests(unittest.TestCase):
    """PolicyCache must fail closed when authoritative files disappear."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.etc = self.root / "etc" / "frp-auto-deploy"
        self.var = self.root / "var" / "lib" / "frp-auto-deploy"
        self.etc.mkdir(parents=True)
        self.var.mkdir(parents=True)
        self.access_path = self.var / "access-control.json"
        self.registry_path = self.var / "registry.json"
        self.config_path = self.etc / "config.json"
        self.state = ACL.empty_access_state()
        lid, _ = ACL.create_access_list(self.state, "Office")
        ACL.add_source_entry(self.state, lid, "net", "198.51.100.0/24")
        ACL.set_service_binding(self.state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        ACL.save_access_state(self.state, path=self.access_path)
        self.registry = {
            "schema_version": 2,
            "clients": {
                "machine-aaa": {
                    "label": "alpha",
                    "hostname": "alpha-host",
                    "services": {"ssh": {"remote_port": 6001, "enabled": True}},
                }
            },
            "reserved": [6001],
        }
        self.registry_path.write_text(json.dumps(self.registry) + "\n", encoding="utf-8")
        self.config_path.write_text(
            json.dumps(
                {
                    "access_control_file": str(self.access_path),
                    "access_conn_log_file": str(self.var / "access-conn.jsonl"),
                    "registry_file": str(self.registry_path),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.environ["FRP_DEPLOY_TEST_ROOT"] = ""
        plugin_path = ROOT / "server" / "frp-access-plugin.py"
        spec = importlib.util.spec_from_file_location(
            "frp_access_plugin_test", str(plugin_path)
        )
        self.plugin = importlib.util.module_from_spec(spec)
        # Ensure plugin resolves lib next to repo, not missing install root.
        sys.modules.pop("frp_access_control", None)
        spec.loader.exec_module(self.plugin)
        self.cache = self.plugin.PolicyCache(self.config_path)

    def tearDown(self):
        self.tmp.cleanup()

    def _authorize_via_cache(self, source_ip="198.51.100.9"):
        access_state, registry, load_error, _cfg = self.cache.snapshot()
        if load_error is not None:
            return {
                "decision": ACL.DECISION_DENY,
                "reason": ACL.REASON_AUTHORIZATION_ERROR,
                "load_error": load_error,
            }
        proxy = ACL.expected_proxy_name("alpha-host", "machine-aaa", "ssh")
        return ACL.authorize(
            access_state, registry, proxy_name=proxy, source_ip=source_ip
        )

    def test_policy_cache_healthy_allowlist(self):
        access_state, registry, load_error, _cfg = self.cache.snapshot()
        self.assertIsNone(load_error)
        self.assertTrue(self.access_path.exists())
        self.assertTrue(self.registry_path.exists())
        result = self._authorize_via_cache()
        self.assertEqual(result["decision"], ACL.DECISION_ALLOW)

    def test_missing_access_policy_fail_closed_and_recovery(self):
        result = self._authorize_via_cache()
        self.assertEqual(result["decision"], ACL.DECISION_ALLOW)
        backup = self.access_path.read_bytes()
        self.access_path.unlink()
        # Force mtime re-check
        self.cache.access_mtime = object()
        access_state, registry, load_error, _cfg = self.cache.snapshot()
        self.assertIsNotNone(load_error)
        self.assertIn("missing", load_error)
        denied = self._authorize_via_cache()
        self.assertEqual(denied["decision"], ACL.DECISION_DENY)
        self.assertEqual(denied["reason"], ACL.REASON_AUTHORIZATION_ERROR)
        # Restore
        self.access_path.write_bytes(backup)
        self.cache.access_mtime = object()
        access_state, registry, load_error, _cfg = self.cache.snapshot()
        self.assertIsNone(load_error)
        recovered = self._authorize_via_cache()
        self.assertEqual(recovered["decision"], ACL.DECISION_ALLOW)

    def test_missing_registry_fail_closed_and_recovery(self):
        result = self._authorize_via_cache()
        self.assertEqual(result["decision"], ACL.DECISION_ALLOW)
        backup = self.registry_path.read_bytes()
        self.registry_path.unlink()
        self.cache.registry_mtime = object()
        _a, _r, load_error, _cfg = self.cache.snapshot()
        self.assertIsNotNone(load_error)
        self.assertIn("missing", load_error)
        denied = self._authorize_via_cache()
        self.assertEqual(denied["decision"], ACL.DECISION_DENY)
        self.assertEqual(denied["reason"], ACL.REASON_AUTHORIZATION_ERROR)
        self.registry_path.write_bytes(backup)
        self.cache.registry_mtime = object()
        _a, _r, load_error, _cfg = self.cache.snapshot()
        self.assertIsNone(load_error)
        recovered = self._authorize_via_cache()
        self.assertEqual(recovered["decision"], ACL.DECISION_ALLOW)

    def test_healthz_503_when_policy_missing(self):
        from http.client import HTTPConnection
        from threading import Thread
        import time

        handler = self.plugin.make_handler(self.cache, "/access-auth")
        server = self.plugin.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode())
            self.assertTrue(body.get("ok"))
            conn.close()

            self.access_path.unlink()
            self.cache.access_mtime = object()
            time.sleep(0.05)
            conn = HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 503)
            body = json.loads(resp.read().decode())
            self.assertFalse(body.get("ok"))
            self.assertTrue(body.get("error"))
            conn.close()

            # NewUserConn must reject without PUBLIC fallback
            payload = {
                "op": "NewUserConn",
                "content": {
                    "proxy_name": ACL.expected_proxy_name(
                        "alpha-host", "machine-aaa", "ssh"
                    ),
                    "remote_addr": "198.51.100.9:12345",
                },
            }
            raw = json.dumps(payload).encode()
            conn = HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request(
                "POST",
                "/access-auth?op=NewUserConn",
                body=raw,
                headers={"Content-Type": "application/json", "Content-Length": str(len(raw))},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            out = json.loads(resp.read().decode())
            self.assertTrue(out.get("reject"))
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

if __name__ == "__main__":
    unittest.main()
