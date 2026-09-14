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

    def test_preset_choices_cover_every_supported_preset(self):
        """F02: catalog presets must match the runtime preset vocabulary."""
        for path in (("service", "add"), ("service-profile", "create")):
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
                self.cat.strict_error(["service", "add", "--preset", preset]), preset
            )
            self.assertIsNone(
                self.cat.strict_error(
                    ["service-profile", "create", "web", "--preset", preset]
                ),
                preset,
            )
        rejected = self.cat.strict_error(["service", "add", "--preset", "ftp"])
        self.assertIsNotNone(rejected)
        self.assertIn("https", rejected)

    def test_preset_help_and_completion_offer_https(self):
        cmd = self.cat.find(["service", "add"])
        self.assertIn("https", self.cat.command_help(cmd))
        offered = load_grammar().completion_candidates(
            "service add --preset ", "client", [], {}, [], trailing=True
        )
        self.assertEqual(set(offered), SUPPORTED_PRESETS)

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
