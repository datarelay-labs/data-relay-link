#!/usr/bin/env python3
"""Policy hot-reload fingerprint (path+dev+ino+size+mtime_ns)."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import frp_policy_fingerprint as FP  # noqa: E402


class PolicyFingerprintTests(unittest.TestCase):
    def test_same_mtime_different_inode_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"a":1}\n', encoding="utf-8")
            fp1 = FP.policy_file_fingerprint(path)
            # Atomic replace: new inode, force identical mtime_ns when possible.
            replacement = Path(tmp) / "policy.json.new"
            replacement.write_text('{"a":2}\n', encoding="utf-8")
            try:
                os.utime(replacement, ns=(fp1[4], fp1[4]))
            except (TypeError, OSError):
                os.utime(replacement, (path.stat().st_mtime, path.stat().st_mtime))
            os.replace(replacement, path)
            fp2 = FP.policy_file_fingerprint(path)
            self.assertNotEqual(fp1, fp2)
            # Inode or size must differ even if mtime_ns coincides.
            self.assertTrue(fp1[2] != fp2[2] or fp1[3] != fp2[3] or fp1[4] != fp2[4])

    def test_content_change_same_size_triggers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"v":"A"}\n', encoding="utf-8")
            fp1 = FP.policy_file_fingerprint(path)
            time.sleep(0.01)
            path.write_text('{"v":"B"}\n', encoding="utf-8")
            fp2 = FP.policy_file_fingerprint(path)
            self.assertNotEqual(fp1, fp2)

    def test_missing_path_stable(self):
        missing = Path("/tmp/drlink-policy-fingerprint-missing-xyz.json")
        fp = FP.policy_file_fingerprint(missing)
        self.assertEqual(fp[1], None)
        self.assertEqual(fp[2], None)


if __name__ == "__main__":
    unittest.main()
