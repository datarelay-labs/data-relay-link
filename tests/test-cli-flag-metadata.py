#!/usr/bin/env python3
"""S01: bounded catalog flag metadata for high-priority options."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_catalog():
    path = ROOT / "lib" / "frp_cli_catalog.py"
    spec = importlib.util.spec_from_file_location("frp_cli_catalog", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CatalogFlagMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = load_catalog()

    def _flag(self, path, name):
        cmd = self.cat.find(list(path))
        self.assertIsNotNone(cmd, path)
        return next(f for f in cmd["flags"] if f["name"] == name)

    def test_protocol_has_choices_and_type(self):
        flag = self._flag(("egress", "add-destination"), "--protocol")
        self.assertEqual(flag.get("type"), "enum")
        self.assertEqual(set(flag.get("choices") or ()), {"http", "https", "tcp"})
        explain = self._flag(("egress", "explain"), "--protocol")
        self.assertEqual(explain.get("type"), "enum")
        self.assertEqual(set(explain.get("choices") or ()), {"http", "https", "tcp"})

    def test_service_add_preset_and_profile_metadata(self):
        preset = self._flag(("service", "add"), "--preset")
        profile = self._flag(("service", "add"), "--profile")
        self.assertEqual(preset.get("type"), "enum")
        self.assertEqual(profile.get("type"), "profile")

    def test_health_timeout_metadata(self):
        flag = self._flag(("service-profile", "create"), "--health-timeout")
        self.assertEqual(flag.get("type"), "integer")
        self.assertEqual(flag.get("unit"), "seconds")

    def test_enrollment_ttl_role_and_access_ttl_role(self):
        enroll = self._flag(("enrollment", "create"), "--ttl")
        access = self._flag(("access", "add-source"), "--ttl")
        self.assertEqual(enroll.get("role"), "enrollment")
        self.assertEqual(access.get("role"), "access")
        self.assertEqual(enroll.get("type"), "duration")

    def test_older_than_metadata(self):
        flag = self._flag(("enrollment", "purge"), "--older-than")
        self.assertEqual(flag.get("type"), "integer")
        self.assertEqual(flag.get("unit"), "days")


if __name__ == "__main__":
    unittest.main()
