#!/usr/bin/env python3
"""F05: nonce capacity eviction must not re-enable still-valid signed replays."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load_mod("frp_port_allocator_f05", ROOT / "server" / "frp-port-allocator.py")


class NonceCapacityReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = self.root / "registry.json"
        self.token = self.root / "server_token"
        self.enrollments = self.root / "enrollments"
        self.enrollments.mkdir()
        self.token.write_text("test-token\n")
        self.cfg = self.root / "config.json"
        self.cfg.write_text(
            json.dumps(
                {
                    "public_ip": "203.0.113.10",
                    "control_port": 443,
                    "port_start": 18300,
                    "port_end": 18320,
                    "listen_host": "127.0.0.1",
                    "listen_port": 6099,
                    "registry_file": str(self.registry),
                    "enrollments_dir": str(self.enrollments),
                    "token_file": str(self.token),
                }
            )
            + "\n"
        )
        MOD.atomic_write_json(self.registry, MOD.empty_registry())
        self.allocator = MOD.Allocator(str(self.cfg))
        self.mid = "a" * 32
        self.now = int(time.time())

    def tearDown(self):
        self.tmp.cleanup()

    def test_capacity_boundary_rejects_full_without_evicting_fresh(self):
        # Fill to cap with fresh nonces.
        for i in range(MOD.MAX_NONCES_PER_CLIENT):
            nonce = "%064x" % i
            err = self.allocator.commit_nonce(self.mid, nonce, self.now)
            self.assertIsNone(err, err)
        # Next commit must fail closed rather than evict a still-valid nonce.
        overflow = "%064x" % MOD.MAX_NONCES_PER_CLIENT
        err = self.allocator.commit_nonce(self.mid, overflow, self.now)
        self.assertEqual(err, "nonce store full; retry later")
        # Oldest still-valid nonce remains replay-blocked.
        oldest = "%064x" % 0
        self.assertEqual(self.allocator.check_nonce(self.mid, oldest, self.now), "replayed request")

    def test_evicted_only_after_skew_horizon(self):
        # Seed max nonces committed far enough in the past that eviction is safe.
        past = self.now - (2 * MOD.MAX_CLOCK_SKEW) - 5
        for i in range(MOD.MAX_NONCES_PER_CLIENT):
            nonce = "%064x" % i
            # Manually age entries by writing expiry = past + TTL
            data = self.allocator.expire_nonces(self.now)
            data["nonces"]["%s:%s" % (self.mid, nonce)] = past + MOD.MGMT_NONCE_TTL
            self.allocator.save_nonces(data)
        # Now a new nonce can be accepted by evicting aged entries.
        err = self.allocator.commit_nonce(self.mid, "%064x" % 9999, self.now)
        self.assertIsNone(err, err)

    def test_same_request_never_accepted_while_time_valid(self):
        nonce = "b" * 64
        self.assertIsNone(self.allocator.commit_nonce(self.mid, nonce, self.now))
        # Fill remaining capacity with newer nonces; must not drop the first.
        for i in range(1, MOD.MAX_NONCES_PER_CLIENT + 5):
            err = self.allocator.commit_nonce(self.mid, "%064x" % i, self.now)
            if err == "nonce store full; retry later":
                break
            self.assertIsNone(err, err)
        self.assertEqual(self.allocator.check_nonce(self.mid, nonce, self.now), "replayed request")
        # Near skew expiry still blocked.
        near = self.now + MOD.MAX_CLOCK_SKEW - 1
        self.assertEqual(self.allocator.check_nonce(self.mid, nonce, near), "replayed request")

    def test_idle_ai_polling_does_not_starve_management(self):
        """Idle claim polls across the replay horizon must leave a management slot.

        Nonces younger than 2*MAX_CLOCK_SKEW cannot be evicted. The previous
        cap of 256 filled during a 2s idle poll and then rejected ordinary
        management commits.
        """
        sys_path = str(ROOT / "lib")
        if sys_path not in sys.path:
            sys.path.insert(0, sys_path)
        import drlink_ai_agent as agent

        interval = float(agent.AI_AGENT_IDLE_POLL_SECONDS)
        self.assertEqual(interval, MOD.AI_IDLE_POLL_SECONDS)
        horizon = 2 * MOD.MAX_CLOCK_SKEW
        polls = int(horizon / interval)
        self.assertGreater(MOD.MAX_NONCES_PER_CLIENT, polls)
        for i in range(polls):
            ts = self.now + int(i * interval)
            err = self.allocator.commit_nonce(self.mid, "%064x" % i, ts)
            self.assertIsNone(err, err)
        end = self.now + int(polls * interval)
        err = self.allocator.commit_nonce(self.mid, "f" * 64, end)
        self.assertIsNone(err, err)
        last = "%064x" % (polls - 1)
        self.assertEqual(self.allocator.check_nonce(self.mid, last, end), "replayed request")
        self.assertEqual(
            MOD.classify_auth_error("nonce store full; retry later"),
            "NONCE_STORE_FULL",
        )


if __name__ == "__main__":
    unittest.main()
