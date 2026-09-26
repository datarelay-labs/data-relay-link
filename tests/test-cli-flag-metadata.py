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
        explain = self._flag(("test", "internet"), "--protocol")
        self.assertEqual(explain.get("type"), "enum")
        self.assertEqual(set(explain.get("choices") or ()), {"http", "https", "tcp"})

    def test_service_add_preset_and_profile_metadata(self):
        preset = self._flag(("set", "service"), "--preset")
        profile = self._flag(("set", "service"), "--profile")
        self.assertEqual(preset.get("type"), "enum")
        self.assertEqual(profile.get("type"), "profile")

    def test_preset_choices_cover_every_supported_preset(self):
        """F02: catalog presets must match the runtime preset vocabulary."""
        flag = self._flag(("set", "service"), "--preset")
        self.assertEqual(set(flag.get("choices") or ()), SUPPORTED_PRESETS)
        self.assertEqual(flag.get("type"), "enum")
        self.assertIn("https", flag.get("description", ""))
        self.assertIn("https", flag.get("examples") or ())

    def test_preset_validation_accepts_every_supported_preset(self):
        for preset in sorted(SUPPORTED_PRESETS):
            self.assertIsNone(
                self.cat.strict_error(["set", "service", "--preset", preset]), preset
            )
        rejected = self.cat.strict_error(["set", "service", "--preset", "ftp"])
        self.assertIsNotNone(rejected)
        self.assertIn("https", rejected)

    def test_preset_metadata_hidden_from_public_completion(self):
        cmd = self.cat.find(["set", "service"])
        preset = next(f for f in cmd["flags"] if f["name"] == "--preset")
        self.assertTrue(preset.get("hidden"))
        self.assertIn("https", preset.get("choices") or ())
        offered = load_grammar().completion_candidates(
            "set service --preset ", "client", [], {}, [], trailing=True
        )
        self.assertEqual(offered, [])

    def test_enrollment_ttl_role(self):
        enroll = self._flag(("set", "enrollment"), "--ttl")
        self.assertEqual(enroll.get("role"), "enrollment")
        self.assertEqual(enroll.get("type"), "duration")

    def test_older_than_metadata(self):
        flag = self._flag(("unset", "enrollment"), "--older-than")
        self.assertEqual(flag.get("type"), "integer")
        self.assertEqual(flag.get("unit"), "days")


if __name__ == "__main__":
    unittest.main()
