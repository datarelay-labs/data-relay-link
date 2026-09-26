#!/usr/bin/env python3
"""Windows Zero-Touch one-liner must pin the allocator CA, then use it."""
from __future__ import annotations

import re
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
        self.assertIsNone(re.search(r'(^|[^a-z0-9])(irm|iex)([^a-z0-9]|$)', cmd.lower()))

    def test_compact_windows_path_never_uses_irm_iex(self):
        compact = "A" * 22
        cmd = zt.short_url_windows_command("remote.xdr.ooo", compact)
        script = zt.render_short_url_windows_bootstrap_script(
            "https://203.0.113.10/enroll",
            "ab" * 32,
            compact,
            "https://example.test/artifacts/agent/bootstrap-client.ps1",
        )
        pinned = zt.pinned_ca_windows_command(
            "https://203.0.113.10:6099/artifacts/agent/bootstrap-client.ps1",
            "https://203.0.113.10:6099/enroll",
            "a" * 64,
            compact,
            "https://203.0.113.10:6099/artifacts/SHA256SUMS",
        )
        for text in (cmd, script, pinned):
            lowered = text.lower()
            self.assertIsNone(re.search(r'(^|[^a-z0-9])(irm|iex)([^a-z0-9]|$)', lowered))
            self.assertNotIn("invoke-restmethod", lowered)
            self.assertNotIn("invoke-expression", lowered)
            self.assertIn("powershell.exe", lowered)
            self.assertIn("-file", lowered)
        self.assertIn("DownloadFile", cmd)
        self.assertIn("SHA256", script)
        self.assertIn("DownloadFile", script)
        self.assertIn(compact, cmd)
        linux = zt.short_url_command("remote.xdr.ooo", compact)
        self.assertIn("-fsSL", linux)
        self.assertIn("https://", linux)
        self.assertIn("/i/", linux)
        self.assertTrue(linux.endswith("|sudo bash"))

    def test_strict_launcher_is_420_and_hash_before_execute(self):
        digest = "ab" * 32
        command = zt.windows_strict_launcher("remote.xdr.ooo", "A" * 22, digest)
        self.assertEqual(len(command), 420)
        self.assertIn("curl.exe -fsSLo", command)
        self.assertIn("Get-FileHash", command)
        self.assertIn(digest, command)
        self.assertIn("powershell.exe -NoProfile -ExecutionPolicy Bypass -File", command)
        self.assertNotIn("-Command", command)
        self.assertNotIn("Invoke-Expression", command)
        self.assertIsNone(re.search(r'(^|[^a-z0-9])(irm|iex)([^a-z0-9]|$)', command.lower()))


if __name__ == "__main__":
    unittest.main()
