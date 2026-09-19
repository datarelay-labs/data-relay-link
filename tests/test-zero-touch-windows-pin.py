#!/usr/bin/env python3
"""Windows Zero-Touch one-liner must pin the allocator CA, then use it."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import frp_zero_touch as zt


class WindowsPinnedCaCommandTests(unittest.TestCase):
    def test_post_pin_curl_uses_cacert_and_skips_schannel_revocation(self):
        inner = zt.pinned_ca_windows_inner(
            installer_url="https://203.0.113.10:6099/artifacts/agent/bootstrap-client.ps1",
            allocator_url="https://203.0.113.10:6099/enroll",
            ca_sha256="a" * 64,
            ticket="bt1." + ("b" * 16) + "." + ("c" * 64),
            sums_url="https://203.0.113.10:6099/artifacts/SHA256SUMS",
        )
        self.assertIn("--insecure -o $ca", inner)
        self.assertIn("CA fingerprint mismatch", inner)
        self.assertEqual(inner.count("--cacert $ca --ssl-no-revoke"), 2)
        self.assertIn("SHA256SUMS download failed", inner)
        self.assertIn("bootstrap-client.ps1 download failed", inner)
        self.assertNotIn("fatedier", inner.lower())
        self.assertNotIn("raw.githubusercontent.com", inner)
        cmd = zt.pinned_ca_windows_command(
            installer_url="https://203.0.113.10:6099/artifacts/agent/bootstrap-client.ps1",
            allocator_url="https://203.0.113.10:6099/enroll",
            ca_sha256="a" * 64,
            ticket="bt1." + ("b" * 16) + "." + ("c" * 64),
            sums_url="https://203.0.113.10:6099/artifacts/SHA256SUMS",
        )
        self.assertTrue(cmd.startswith("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "))


if __name__ == "__main__":
    unittest.main()
