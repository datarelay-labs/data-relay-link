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
        msg = str(ctx.exception).lower()
        self.assertTrue(
            "still referenced" in msg or "still assigned" in msg,
            msg,
        )
        self.assertIn("unset acl", msg)

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
    """PolicyCache must fail closed when SQLite control plane is unavailable."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        (self.root / "etc" / "drlink").mkdir(parents=True)
        (self.root / "var" / "lib" / "drlink").mkdir(parents=True)
        self.config_path = self.root / "etc" / "drlink" / "config.json"
        self.config_path.write_text(json.dumps({"deployment_mode": "direct"}) + "\n", encoding="utf-8")
        sys.path.insert(0, str(ROOT / "lib"))
        from drlink_control_plane import ControlPlane
        import drlink_runtime_policy as RP
        self.RP = RP
        self.plane = ControlPlane(str(self.root))
        self.mid = "machineaaamachineaaamachineaaa0001"
        self.plane.set_object_type("office", "network")
        self.plane.set_object_value("office", "198.51.100.0/24")
        self.plane.upsert_client(self.mid, label="alpha", hostname="alpha-host",
                                 addresses=[{"address": "10.0.0.5", "active": True}])
        self.plane.set_published_service(
            self.mid, "ssh", service_type="ssh", target_mode="self",
            target_host="127.0.0.1", target_port=22, enabled=True, public_port=6001,
        )
        self.plane.set_rule("remote", "allow-office")
        self.plane.set_rule_source("remote", "allow-office", "office")
        self.plane.set_rule_destination("remote", "allow-office", "alpha")
        self.plane.set_rule_service("remote", "allow-office", "tcp", 22)
        self.plane.set_rule_action("remote", "allow-office", "allow")
        self.plane.set_rule_enabled("remote", "allow-office", True)
        self.plane.close()
        plugin_path = ROOT / "server" / "frp-access-plugin.py"
        spec = importlib.util.spec_from_file_location("frp_access_plugin_test", str(plugin_path))
        self.plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.plugin)
        self.cache = self.plugin.PolicyCache(self.config_path)

    def tearDown(self):
        self.tmp.cleanup()

    def _authorize_via_cache(self, source_ip="198.51.100.9"):
        plane, load_error, _cfg = self.cache.snapshot()
        if load_error is not None or plane is None:
            return {
                "decision": self.RP.DECISION_DENY,
                "reason": self.RP.REASON_DB_UNAVAILABLE,
                "load_error": load_error,
            }
        proxy = self.RP.expected_proxy_name("alpha-host", self.mid, "ssh")
        return self.RP.authorize_remote(plane, proxy_name=proxy, source_ip=source_ip)

    def test_policy_cache_healthy_allowlist(self):
        plane, load_error, _cfg = self.cache.snapshot()
        self.assertIsNone(load_error)
        self.assertIsNotNone(plane)
        result = self._authorize_via_cache()
        self.assertEqual(result["decision"], self.RP.DECISION_ALLOW)

    def test_missing_db_fail_closed(self):
        result = self._authorize_via_cache()
        self.assertEqual(result["decision"], self.RP.DECISION_ALLOW)
        db = self.root / "var" / "lib" / "drlink" / "drlink.db"
        db.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            (self.root / "var" / "lib" / "drlink" / ("drlink.db" + suffix)).unlink(missing_ok=True)
        self.cache.reload(force=True)
        plane, load_error, _cfg = self.cache.snapshot()
        self.assertTrue(load_error or plane is None)
        denied = self._authorize_via_cache()
        self.assertEqual(denied["decision"], self.RP.DECISION_DENY)

    def test_healthz_503_when_policy_missing(self):
        from http.client import HTTPConnection
        from threading import Thread

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
            self.assertEqual(body.get("authority"), "sqlite")
            conn.close()

            db = self.root / "var" / "lib" / "drlink" / "drlink.db"
            db.unlink(missing_ok=True)
            self.cache.reload(force=True)
            conn = HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 503)
            body = json.loads(resp.read().decode())
            self.assertFalse(body.get("ok"))
            conn.close()

            payload = {
                "op": "NewUserConn",
                "content": {
                    "proxy_name": self.RP.expected_proxy_name("alpha-host", self.mid, "ssh"),
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

    def test_concurrent_newuserconn_sqlite_isolation(self):
        """Parallel NewUserConn workers must not share one SQLite connection.

        The pre-fix plugin returned one cached ControlPlane from snapshot()
        and authorized after releasing the cache lock. Threaded workers then
        raised sqlite3.InterfaceError / IndexError and fail-closed rejects.
        """
        import io
        from concurrent.futures import ThreadPoolExecutor
        from contextlib import redirect_stderr
        from http.client import HTTPConnection
        from threading import Thread

        import drlink_v24 as v24
        from drlink_control_plane import ControlPlane

        mode_plane = ControlPlane(str(self.root))
        try:
            v24.ensure_policy_mode(mode_plane, "remote", "whitelist", oneshot=True)
        finally:
            mode_plane.close()
        self.cache.reload(force=True)

        handler = self.plugin.make_handler(self.cache, "/access-auth")
        server = self.plugin.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proxy = self.RP.expected_proxy_name("alpha-host", self.mid, "ssh")
        allow_addr = "198.51.100.9:%s"
        deny_addr = "203.0.113.9:%s"

        def one(index):
            allowed = index % 2 == 0
            remote = (allow_addr if allowed else deny_addr) % (10000 + index)
            payload = {
                "op": "NewUserConn",
                "content": {"proxy_name": proxy, "remote_addr": remote},
            }
            raw = json.dumps(payload).encode()
            last = b"no response"
            for _attempt in range(2):
                conn = HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    conn.request(
                        "POST",
                        "/access-auth?op=NewUserConn",
                        body=raw,
                        headers={"Content-Type": "application/json", "Content-Length": str(len(raw))},
                    )
                    resp = conn.getresponse()
                    body = resp.read()
                    return allowed, resp.status, body
                except Exception as exc:
                    last = repr(exc).encode()
                finally:
                    conn.close()
            return allowed, 0, last

        stderr = io.StringIO()
        try:
            with redirect_stderr(stderr):
                with ThreadPoolExecutor(max_workers=32) as pool:
                    results = list(pool.map(one, range(96)))
        finally:
            server.shutdown()
            server.server_close()

        log = stderr.getvalue()
        self.assertNotIn("InterfaceError", log)
        self.assertNotIn("bad parameter or other API misuse", log)
        self.assertNotIn("tuple index out of range", log)
        self.assertNotIn("NoneType", log)
        for allowed, status, body in results:
            self.assertEqual(status, 200, "%s\n%s" % (body, log))
            out = json.loads(body.decode())
            if allowed:
                self.assertFalse(out.get("reject"), out)
            else:
                self.assertTrue(out.get("reject"), out)
                reason = str(out.get("reject_reason") or "")
                self.assertNotIn("authorization unavailable", reason)
                self.assertNotIn("DB_UNAVAILABLE", reason)



class AccessTtlBoundsTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_max_ttl_is_accepted(self):
        exp = ACL.parse_ttl("%dd" % ACL.TTL_MAX_DAYS, now=self.now)
        self.assertEqual(exp, self.now + timedelta(days=ACL.TTL_MAX_DAYS))

    def test_ttl_above_max_is_rejected(self):
        for value in ("3651d", "87601h", "5256001m", "315360001s"):
            with self.assertRaises(ACL.AccessError) as ctx:
                ACL.parse_ttl(value, now=self.now)
            self.assertIn("3650d", str(ctx.exception))

    def test_giant_ttl_raises_access_error_not_overflow(self):
        for value in ("99999999999999d", "9" * 40 + "h", "9" * 6000 + "s"):
            with self.assertRaises(ACL.AccessError):
                ACL.parse_ttl(value, now=self.now)

    def test_ttl_near_datetime_limit_is_bounded(self):
        # A base close to datetime.max must still fail closed with AccessError.
        near_max = datetime(9999, 12, 30, tzinfo=timezone.utc)
        with self.assertRaises(ACL.AccessError):
            ACL.parse_ttl("30d", now=near_max)

    def test_ttl_zero_and_malformed_still_rejected(self):
        for value in ("0s", "-1d", "", "4x", "d", "1.5h"):
            with self.assertRaises(ACL.AccessError):
                ACL.parse_ttl(value, now=self.now)

    def test_add_source_rejects_oversized_ttl(self):
        state = ACL.empty_access_state()
        lid, _ = ACL.create_access_list(state, "Bounded")
        with self.assertRaises(ACL.AccessError):
            ACL.add_source_entry(state, lid, "forever", "198.51.100.7", ttl="99999999999999d")
        self.assertEqual(state["access_lists"][lid]["entries"], [])


class AccessDescriptionValidationTests(unittest.TestCase):
    def setUp(self):
        self.state = ACL.empty_access_state()

    def test_description_is_trimmed_and_kept(self):
        _lid, record = ACL.create_access_list(self.state, "Office", "  Corp ranges  ")
        self.assertEqual(record["description"], "Corp ranges")

    def test_description_max_length(self):
        ok = "a" * ACL.DESCRIPTION_MAX_LEN
        _lid, record = ACL.create_access_list(self.state, "Long", ok)
        self.assertEqual(len(record["description"]), ACL.DESCRIPTION_MAX_LEN)
        with self.assertRaises(ACL.AccessError):
            ACL.create_access_list(self.state, "TooLong", "a" * (ACL.DESCRIPTION_MAX_LEN + 1))

    def test_create_rejects_control_and_escape_sequences(self):
        bad = (
            "line\nbreak",
            "carriage\rreturn",
            "null\x00byte",
            "bell\x07",
            "tab\tstop",
            "ansi\x1b[31mred\x1b[0m",
            "c1\x9bcsi",
            "del\x7f",
        )
        for value in bad:
            with self.assertRaises(ACL.AccessError):
                ACL.create_access_list(self.state, "Bad", value)
        self.assertEqual(self.state["access_lists"], {})

    def test_update_rejects_control_characters_and_keeps_previous_value(self):
        lid, _ = ACL.create_access_list(self.state, "Office", "clean")
        with self.assertRaises(ACL.AccessError):
            ACL.update_access_list_info(self.state, lid, description="evil\x1b[2J")
        self.assertEqual(self.state["access_lists"][lid]["description"], "clean")
        self.assertEqual(self.state["access_lists"][lid]["name"], "Office")

    def test_rejected_description_does_not_apply_rename(self):
        lid, _ = ACL.create_access_list(self.state, "Office", "clean")
        with self.assertRaises(ACL.AccessError):
            ACL.update_access_list_info(
                self.state, lid, name="Renamed", description="bad\x1b[0m"
            )
        self.assertEqual(self.state["access_lists"][lid]["name"], "Office")

    def test_validate_access_state_rejects_hostile_description(self):
        lid, _ = ACL.create_access_list(self.state, "Office", "clean")
        ACL.validate_access_state(self.state)
        self.state["access_lists"][lid]["description"] = "spoof\r\nACCESS ALLOW"
        with self.assertRaises(ACL.AccessError):
            ACL.validate_access_state(self.state)

    def test_validate_access_state_rejects_oversized_description(self):
        lid, _ = ACL.create_access_list(self.state, "Office")
        self.state["access_lists"][lid]["description"] = "a" * (ACL.DESCRIPTION_MAX_LEN + 1)
        with self.assertRaises(ACL.AccessError):
            ACL.validate_access_state(self.state)

    def test_non_string_description_rejected(self):
        with self.assertRaises(ACL.AccessError):
            ACL.create_access_list(self.state, "Office", {"nested": "object"})


class AccessAuditFieldsTests(unittest.TestCase):
    def test_event_names_cover_documented_mutations(self):
        self.assertEqual(
            set(ACL.ACCESS_AUDIT_EVENTS),
            {
                "access.list.created",
                "access.list.updated",
                "access.list.deleted",
                "access.source.added",
                "access.source.updated",
                "access.source.removed",
                "access.service.assigned",
                "access.service.public",
            },
        )

    def test_unknown_event_is_rejected(self):
        with self.assertRaises(ACL.AccessError):
            ACL.access_audit_fields("access.list.exfiltrated", list_id="acl_1")

    def test_allowed_fields_pass_through(self):
        payload = ACL.access_audit_fields(
            ACL.AUDIT_SOURCE_ADDED,
            list_id="acl_abc",
            list_name="Office",
            entry_id="ace_def",
            entry_name="hq",
            cidr="203.0.113.0/24",
            details={"expires_at": "2026-01-01T00:00:00Z"},
        )
        self.assertEqual(
            payload,
            {
                "list_id": "acl_abc",
                "list_name": "Office",
                "entry_id": "ace_def",
                "entry_name": "hq",
                "cidr": "203.0.113.0/24",
                "details": {"expires_at": "2026-01-01T00:00:00Z"},
            },
        )

    def test_description_and_secret_fields_are_dropped(self):
        payload = ACL.access_audit_fields(
            ACL.AUDIT_LIST_CREATED,
            list_id="acl_abc",
            list_name="Office",
            description="bt1.deadbeef.0123456789abcdef",
            ticket="bt1.deadbeef.0123456789abcdef",
            server_token="s3cr3t",
            details={
                "description": "bt1.deadbeef.0123456789abcdef",
                "enrollment_code": "zt1.AAAAAAAAAAAAAAAAAA",
                "description_length": 12,
            },
        )
        self.assertEqual(
            payload,
            {
                "list_id": "acl_abc",
                "list_name": "Office",
                "details": {"description_length": 12},
            },
        )
        self.assertNotIn("bt1.", json.dumps(payload))

    def test_none_values_and_empty_details_are_omitted(self):
        payload = ACL.access_audit_fields(
            ACL.AUDIT_SERVICE_PUBLIC,
            client_id="machine-aaa",
            service_id="ssh",
            public_port=None,
            details={"previous_mode": None},
        )
        self.assertEqual(payload, {"client_id": "machine-aaa", "service_id": "ssh"})

    def test_audit_payload_survives_redaction_unchanged(self):
        audit_spec = importlib.util.spec_from_file_location(
            "frp_audit_for_access_test", str(ROOT / "lib" / "frp_audit.py")
        )
        audit_mod = importlib.util.module_from_spec(audit_spec)
        audit_spec.loader.exec_module(audit_mod)
        payload = ACL.access_audit_fields(
            ACL.AUDIT_SERVICE_ASSIGNED,
            client_id="machine-aaa",
            service_id="ssh",
            list_id="acl_abc",
            list_name="Office",
            public_port=6001,
            access_mode=ACL.MODE_ALLOWLIST,
            details={"previous_mode": ACL.MODE_PUBLIC},
        )
        self.assertEqual(audit_mod._redact(payload), payload)


if __name__ == "__main__":
    unittest.main()
