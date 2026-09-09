#!/usr/bin/env python3
"""Unit coverage for Service Profiles helpers."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_prof():
    path = ROOT / "lib" / "frp_service_profiles.py"
    spec = importlib.util.spec_from_file_location("frp_service_profiles", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PROF = load_prof()


class ServiceProfilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "service-profiles.json"
        self.state = PROF.empty_profiles_state()

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_state(self):
        self.assertEqual(self.state["schema_version"], 1)
        self.assertEqual(self.state["profiles"], {})

    def test_create_list_show_edit_delete(self):
        pid, rec = PROF.create_profile(
            self.state,
            "office-ssh",
            preset="ssh",
            local_ip="127.0.0.1",
            local_port=22,
            description="desk",
            ssh_user="ubuntu",
        )
        self.assertTrue(pid.startswith("prof_"))
        self.assertEqual(len(pid), len("prof_") + 12)
        self.assertEqual(rec["name"], "office-ssh")
        self.assertEqual(rec["id"], pid)
        rows = PROF.list_profiles(self.state)
        self.assertEqual(len(rows), 1)
        resolved_id, resolved = PROF.resolve_profile(self.state, "office-ssh")
        self.assertEqual(resolved_id, pid)
        self.assertEqual(resolved["ssh_user"], "ubuntu")

        PROF.update_profile(self.state, pid, "target-port", "2222")
        self.assertEqual(self.state["profiles"][pid]["local_port"], 2222)
        # Immutable id: cannot change via update API
        self.assertEqual(self.state["profiles"][pid]["id"], pid)

        deleted_id, name = PROF.delete_profile(self.state, pid)
        self.assertEqual(deleted_id, pid)
        self.assertEqual(name, "office-ssh")
        self.assertEqual(self.state["profiles"], {})

    def test_duplicate_name_rejected(self):
        PROF.create_profile(
            self.state, "Office", preset="http", local_ip="10.0.0.1", local_port=80
        )
        with self.assertRaises(PROF.ProfileError):
            PROF.create_profile(
                self.state, "office", preset="http", local_ip="10.0.0.2", local_port=8080
            )

    def test_forbidden_fields_rejected(self):
        with self.assertRaises(PROF.ProfileError):
            PROF.reject_forbidden_fields({"remote_port": 6001})
        with self.assertRaises(PROF.ProfileError):
            PROF.reject_forbidden_fields({"client_id": "abc"})
        with self.assertRaises(PROF.ProfileError):
            PROF.reject_forbidden_fields({"access_list_id": "acl_1"})

    def test_ssh_requires_user(self):
        with self.assertRaises(PROF.ProfileError):
            PROF.create_profile(
                self.state, "ssh1", preset="ssh", local_ip="127.0.0.1", local_port=22
            )

    def test_profile_to_service_payload(self):
        _pid, rec = PROF.create_profile(
            self.state,
            "web",
            preset="http",
            local_ip="192.0.2.10",
            local_port=8080,
            description="web svc",
        )
        payload = PROF.profile_to_service_payload(rec, service_id="web1", name="Web One")
        self.assertEqual(payload["id"], "web1")
        self.assertEqual(payload["name"], "Web One")
        self.assertEqual(payload["preset"], "http")
        self.assertEqual(payload["local_ip"], "192.0.2.10")
        self.assertEqual(payload["local_port"], 8080)
        self.assertNotIn("remote_port", payload)
        self.assertNotIn("client_id", payload)
        self.assertNotIn("access_list_id", payload)

    def test_health_fields_optional(self):
        pid, rec = PROF.create_profile(
            self.state,
            "healthy",
            preset="https",
            local_ip="127.0.0.1",
            local_port=443,
            health_check={
                "type": "tcp",
                "timeout_seconds": 3,
                "interval_seconds": 10,
                "max_failed": 2,
            },
        )
        self.assertEqual(rec["health_check"]["type"], "tcp")
        payload = PROF.profile_to_service_payload(rec)
        self.assertEqual(payload["health_check"]["type"], "tcp")
        PROF.update_profile(self.state, pid, "health-type", "disabled")
        self.assertNotIn("health_check", self.state["profiles"][pid])

    def test_save_load_roundtrip(self):
        PROF.create_profile(
            self.state,
            "persist",
            preset="custom",
            local_ip="127.0.0.1",
            local_port=9000,
        )
        PROF.save_profiles_state(self.state, path=self.path)
        loaded = PROF.load_profiles_state(path=self.path)
        self.assertEqual(loaded["schema_version"], 1)
        self.assertEqual(len(loaded["profiles"]), 1)
        name = next(iter(loaded["profiles"].values()))["name"]
        self.assertEqual(name, "persist")

    def test_mutate_lock_roundtrip(self):
        PROF.initialize_profiles_state(path=self.path)

        def mut(state):
            return PROF.create_profile(
                state,
                "locked",
                preset="http",
                local_ip="127.0.0.1",
                local_port=80,
            )

        pid, rec = PROF.mutate_profiles_state(mut, path=self.path)
        self.assertTrue(pid.startswith("prof_"))
        loaded = PROF.load_profiles_state(path=self.path)
        self.assertEqual(loaded["profiles"][pid]["name"], "locked")
        self.assertEqual(rec["name"], "locked")

    def test_edit_does_not_imply_service_mutation_contract(self):
        # Profiles are templates: payload generation is a copy at apply time.
        _pid, rec = PROF.create_profile(
            self.state,
            "tmpl",
            preset="http",
            local_ip="127.0.0.1",
            local_port=80,
        )
        before = PROF.profile_to_service_payload(rec, service_id="svc")
        PROF.update_profile(self.state, "tmpl", "target-port", "8080")
        after_profile = self.state["profiles"][_pid]
        # Old payload snapshot remains unchanged (no live inheritance).
        self.assertEqual(before["local_port"], 80)
        self.assertEqual(after_profile["local_port"], 8080)
        after = PROF.profile_to_service_payload(after_profile, service_id="svc2")
        self.assertEqual(after["local_port"], 8080)


if __name__ == "__main__":
    unittest.main()
