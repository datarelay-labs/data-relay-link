#!/usr/bin/env python3
"""F07: enrollment TTL help examples must match parser semantics."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    path = ROOT / rel
    spec = importlib.util.spec_from_loader(
        name, loader=importlib.machinery.SourceFileLoader(name, str(path))
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


CREATE = load("frp_create_client", "tools/frp-create-client")
CATALOG = load("frp_cli_catalog", "lib/frp_cli_catalog.py")


class EnrollmentTtlHelpTests(unittest.TestCase):
    def test_duration_and_seconds_parse(self):
        self.assertEqual(CREATE.parse_enrollment_ttl("600"), 600)
        self.assertEqual(CREATE.parse_enrollment_ttl("30m"), 30 * 60)
        self.assertEqual(CREATE.parse_enrollment_ttl("1h"), 3600)
        self.assertEqual(CREATE.parse_enrollment_ttl("4h"), 4 * 3600)
        self.assertEqual(CREATE.parse_enrollment_ttl("1d"), 86400)

    def test_invalid_ttl_rejected(self):
        with self.assertRaises(ValueError):
            CREATE.parse_enrollment_ttl("0")
        with self.assertRaises(ValueError):
            CREATE.parse_enrollment_ttl("bad")

    def test_catalog_enrollment_ttl_examples_parse(self):
        cmd = CATALOG.find(["enrollment", "create"])
        self.assertIsNotNone(cmd)
        ttl_flag = next(f for f in cmd["flags"] if f["name"] == "--ttl")
        self.assertEqual(ttl_flag.get("role"), "enrollment")
        for example in ttl_flag.get("examples") or ():
            CREATE.parse_enrollment_ttl(example)

    def test_access_ttl_metavar_differs_by_role(self):
        access = next(
            f for f in CATALOG.find(["access", "add-source"])["flags"] if f["name"] == "--ttl"
        )
        enroll = next(
            f for f in CATALOG.find(["enrollment", "create"])["flags"] if f["name"] == "--ttl"
        )
        self.assertEqual(access.get("role"), "access")
        self.assertEqual(enroll.get("role"), "enrollment")
        self.assertIn("|SECONDS", enroll.get("metavar", ""))

    def test_create_client_epilog_has_no_unparseable_ttl_examples(self):
        text = (ROOT / "tools/frp-create-client").read_text(encoding="utf-8")
        epilog = text.split("epilog=(", 1)[1].split("),", 1)[0]
        ttl_examples = [m.group(1) for m in re.finditer(r"--ttl\s+(\S+)", epilog)]
        self.assertEqual(ttl_examples, [])


if __name__ == "__main__":
    unittest.main()
