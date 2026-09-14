#!/usr/bin/env python3
"""S01: bounded catalog flag metadata for high-priority options."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Runtime preset vocabulary (lib/frp_service_profiles.py, tools/frp-client).
SUPPORTED_PRESETS = {"ssh", "http", "https", "custom"}


def load_catalog():
    path = ROOT / "lib" / "frp_cli_catalog.py"
    spec = importlib.util.spec_from_file_location("frp_cli_catalog", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_grammar():
    sys.path.insert(0, str(ROOT / "lib"))
    import frp_ctl_grammar

    return frp_ctl_grammar


class CatalogFlagMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = load_catalog()

    def _flag(self, path, name):
        cmd = self.cat.find(list(path), include_aliases=True)
        self.assertIsNotNone(cmd, path)
        return next(f for f in cmd["flags"] if f["name"] == name)

    def test_protocol_has_choices_and_type(self):
        flag = self._flag(("add", "egress-destination"), "--protocol")
        self.assertEqual(flag.get("type"), "enum")
        self.assertEqual(set(flag.get("choices") or ()), {"http", "https", "tcp"})
        explain = self._flag(("explain", "egress"), "--protocol")
        self.assertEqual(explain.get("type"), "enum")
        self.assertEqual(set(explain.get("choices") or ()), {"http", "https", "tcp"})

    def test_service_add_preset_and_profile_metadata(self):
        preset = self._flag(("add", "service"), "--preset")
        profile = self._flag(("add", "service"), "--profile")
        self.assertEqual(preset.get("type"), "enum")
        self.assertEqual(profile.get("type"), "profile")

    def test_preset_choices_cover_every_supported_preset(self):
        """F02: catalog presets must match the runtime preset vocabulary."""
        for path in (("add", "service"), ("create", "service-profile")):
            flag = self._flag(path, "--preset")
            self.assertEqual(
                set(flag.get("choices") or ()), SUPPORTED_PRESETS, path
            )
            self.assertEqual(flag.get("type"), "enum", path)
            self.assertIn("https", flag.get("description", ""), path)
            self.assertIn("https", flag.get("examples") or (), path)

    def test_preset_validation_accepts_every_supported_preset(self):
        for preset in sorted(SUPPORTED_PRESETS):
            self.assertIsNone(
                self.cat.strict_error(["add", "service", "--preset", preset]), preset
            )
            self.assertIsNone(
                self.cat.strict_error(
                    ["create", "service-profile", "web", "--preset", preset]
                ),
                preset,
            )
        rejected = self.cat.strict_error(["add", "service", "--preset", "ftp"])
        self.assertIsNotNone(rejected)
        self.assertIn("https", rejected)

    def test_preset_metadata_hidden_from_public_completion(self):
        cmd = self.cat.find(["add", "service"])
        preset = next(f for f in cmd["flags"] if f["name"] == "--preset")
        self.assertTrue(preset.get("hidden"))
        self.assertIn("https", preset.get("choices") or ())
        offered = load_grammar().completion_candidates(
            "add service --preset ", "client", [], {}, [], trailing=True
        )
        self.assertEqual(offered, [])

    def test_health_timeout_metadata(self):
        flag = self._flag(("create", "service-profile"), "--health-timeout")
        self.assertEqual(flag.get("type"), "integer")
        self.assertEqual(flag.get("unit"), "seconds")

    def test_enrollment_ttl_role_and_access_ttl_role(self):
        enroll = self._flag(("create", "enrollment"), "--ttl")
        access = self._flag(("add", "access-source"), "--ttl")
        self.assertEqual(enroll.get("role"), "enrollment")
        self.assertEqual(access.get("role"), "access")
        self.assertEqual(enroll.get("type"), "duration")

    def test_older_than_metadata(self):
        flag = self._flag(("delete", "enrollment"), "--older-than")
        self.assertEqual(flag.get("type"), "integer")
        self.assertEqual(flag.get("unit"), "days")


if __name__ == "__main__":
    unittest.main()
