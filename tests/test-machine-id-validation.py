#!/usr/bin/env python3
"""Regression: canonical machine_id validation parity (AUDIT-003)."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MID = load("frp_machine_id", "lib/frp_machine_id.py")


class MachineIdValidationTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(MID.validate_machine_id("a" * 127), "a" * 127)
        self.assertEqual(MID.validate_machine_id("a" * 128), "a" * 128)
        with self.assertRaises(MID.MachineIdError):
            MID.validate_machine_id("a" * 129)
        with self.assertRaises(MID.MachineIdError):
            MID.validate_machine_id("a" * 10000)

    def test_forbidden_chars(self):
        for bad in ("ab\rcd", "ab\ncd", "ab/cd", "ab\\cd", "ab\x00cd", "ab\x1fcd", "ab\x7fcd"):
            with self.assertRaises(MID.MachineIdError):
                MID.validate_machine_id(bad)

    def test_required_and_normal(self):
        with self.assertRaises(MID.MachineIdError):
            MID.validate_machine_id("")
        with self.assertRaises(MID.MachineIdError):
            MID.validate_machine_id(None)
        self.assertEqual(MID.validate_machine_id("machine-abcdef012345"), "machine-abcdef012345")
        self.assertTrue(MID.is_valid_machine_id("aabbccddeeff0011"))
        self.assertFalse(MID.is_valid_machine_id("bad/id"))


if __name__ == "__main__":
    unittest.main()
