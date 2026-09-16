#!/usr/bin/env python3
"""First generation of a management identity must be all-or-nothing.

Reserving the final key path with an empty file before generating the material
means any failure — openssl error, disk full, a kill between the two steps —
leaves a zero-byte private key behind. That file is not a usable identity but it
does exist, so the client reports the identity as unusable and every retry is
refused: the client can only be recovered by hand. A failed attempt must instead
leave nothing behind, and a retry must succeed.
"""
from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


MGMT = _load("frp_mgmt_auth_atomicity", ROOT / "lib" / "frp_mgmt_auth.py")


class _FailAtCall:
    """Fail the Nth openssl invocation, mimicking a write/tool failure."""

    def __init__(self, real, fail_on: int):
        self.real = real
        self.fail_on = int(fail_on)
        self.calls = 0

    def __call__(self, args, **kwargs):
        self.calls += 1
        if self.calls == self.fail_on:
            raise RuntimeError("simulated openssl write failure")
        return self.real(args, **kwargs)


class MgmtIdentityFirstGenAtomicity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-mgmt-atomic-")
        self.dir = Path(self.tmp.name) / "identity"
        self.dir.mkdir()
        self.key = self.dir / "client-identity.key"
        self.pub = self.dir / "client-identity.pub"
        self._orig_openssl = MGMT._run_openssl

    def tearDown(self):
        MGMT._run_openssl = self._orig_openssl
        self.tmp.cleanup()

    def _assert_usable_pair(self):
        self.assertTrue(MGMT.validate_private_key(self.key))
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        self.assertEqual(
            self.pub.read_text(encoding="utf-8"),
            MGMT.canonicalize_pubkey_from_private(self.key),
            "published public key must match the private key",
        )

    def _assert_nothing_left_behind(self):
        self.assertFalse(
            self.key.exists(),
            "failed generation left a private-key placeholder that blocks retry",
        )
        self.assertFalse(self.pub.exists(), "failed generation published a public key")
        self.assertEqual(
            sorted(p.name for p in self.dir.iterdir()), [], "temp files left behind"
        )

    def test_failure_during_keygen_leaves_no_placeholder(self):
        MGMT._run_openssl = _FailAtCall(self._orig_openssl, 1)
        with self.assertRaises(RuntimeError):
            MGMT.generate_keypair(self.key, self.pub)
        self._assert_nothing_left_behind()

        # Retry on a healthy system must just work.
        MGMT._run_openssl = self._orig_openssl
        MGMT.generate_keypair(self.key, self.pub)
        self._assert_usable_pair()

    def test_failure_after_key_material_leaves_no_placeholder(self):
        # Second call is the pubout of freshly generated key material: the
        # window where a reserved final path would already exist but be empty.
        MGMT._run_openssl = _FailAtCall(self._orig_openssl, 2)
        with self.assertRaises(RuntimeError):
            MGMT.generate_keypair(self.key, self.pub)
        self._assert_nothing_left_behind()

        MGMT._run_openssl = self._orig_openssl
        MGMT.generate_keypair(self.key, self.pub)
        self._assert_usable_pair()

    def test_zero_byte_key_from_interrupted_run_is_regenerable(self):
        # State an older interrupted run (or a kill) could leave on disk.
        fd = os.open(str(self.key), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        self.assertEqual(self.key.stat().st_size, 0)
        MGMT.generate_keypair(self.key, self.pub)
        self._assert_usable_pair()

    def test_existing_key_with_content_is_never_overwritten(self):
        MGMT.generate_keypair(self.key, self.pub)
        self._assert_usable_pair()
        before_key = self.key.read_bytes()
        before_pub = self.pub.read_bytes()
        with self.assertRaises(FileExistsError):
            MGMT.generate_keypair(self.key, self.pub)
        self.assertEqual(self.key.read_bytes(), before_key)
        self.assertEqual(
            self.pub.read_bytes(),
            before_pub,
            "a refused regeneration must not publish a mismatched public key",
        )

    def test_concurrent_first_generation_publishes_one_consistent_pair(self):
        results: list = []
        lock = threading.Lock()
        start = threading.Barrier(4)

        def run():
            start.wait(30.0)
            try:
                MGMT.generate_keypair(self.key, self.pub)
                outcome = "created"
            except FileExistsError:
                outcome = "refused"
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=run, daemon=True) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60.0)
            self.assertFalse(thread.is_alive())
        self.assertEqual(results.count("created"), 1, "results=%r" % (results,))
        self._assert_usable_pair()
        self.assertEqual(
            sorted(p.name for p in self.dir.iterdir()),
            [self.key.name, self.pub.name],
            "temp files left behind",
        )


if __name__ == "__main__":
    unittest.main()
