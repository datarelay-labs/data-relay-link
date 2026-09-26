#!/usr/bin/env python3
"""Legacy single-443 Agents must leave private :6099 without re-enrollment."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import drlink_mgmt_sync as mgmt  # noqa: E402


def _write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


def _state(url: str, transport: str, port: int) -> dict:
    return {
        "schema_version": 1,
        "allocator_url": url,
        "frp_server": "203.0.113.10",
        "frp_server_port": port,
        "frp_transport": transport,
        "hostname": "expernet-dp1",
        "machine_id": "aabbccddeeff00112233445566778899",
        "host_id": "expernet-dp1",
        "services": {
            "ssh": {
                "id": "ssh",
                "remote_port": 6003,
                "enabled": True,
                "local_ip": "127.0.0.1",
                "local_port": 22,
            }
        },
    }


class LegacyOriginTests(unittest.TestCase):
    def test_rewrite_rules(self):
        self.assertEqual(
            mgmt.rewrite_legacy_backend_url("https://203.0.113.10:6099/enroll", 443),
            "https://203.0.113.10/enroll",
        )
        self.assertEqual(
            mgmt.rewrite_legacy_backend_url("https://203.0.113.10:6099/enroll", 8443),
            "https://203.0.113.10:8443/enroll",
        )
        self.assertIsNone(mgmt.rewrite_legacy_backend_url("https://203.0.113.10/enroll", 443))
        self.assertIsNone(mgmt.rewrite_legacy_backend_url("https://203.0.113.10:7000/enroll", 443))

    def test_direct_mode_and_repeat_are_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            direct = root / "direct"
            _write(
                direct / "etc/frp/client-state.json",
                json.dumps(_state("https://203.0.113.10:6099/enroll", "tcp", 7000), indent=2) + "\n",
            )
            self.assertFalse(mgmt.migrate_legacy_single443_agent_origin(str(direct)))
            kept = json.loads((direct / "etc/frp/client-state.json").read_text(encoding="utf-8"))
            self.assertEqual(kept["allocator_url"], "https://203.0.113.10:6099/enroll")

            wss = root / "wss"
            _write(
                wss / "etc/frp/client-state.json",
                json.dumps(_state("https://203.0.113.10:6099/enroll", "wss", 443), indent=2) + "\n",
            )
            _write(
                wss / "etc/frp/server-endpoint.json",
                json.dumps({"mgmt_url": "https://203.0.113.10:6099"}) + "\n",
            )
            before_services = json.loads((wss / "etc/frp/client-state.json").read_text(encoding="utf-8"))["services"]
            self.assertTrue(mgmt.migrate_legacy_single443_agent_origin(str(wss)))
            migrated = json.loads((wss / "etc/frp/client-state.json").read_text(encoding="utf-8"))
            self.assertEqual(migrated["allocator_url"], "https://203.0.113.10/enroll")
            self.assertEqual(migrated["machine_id"], "aabbccddeeff00112233445566778899")
            self.assertEqual(migrated["services"], before_services)
            endpoint = json.loads((wss / "etc/frp/server-endpoint.json").read_text(encoding="utf-8"))
            self.assertEqual(endpoint["mgmt_url"], "https://203.0.113.10")
            self.assertFalse(mgmt.migrate_legacy_single443_agent_origin(str(wss)))

            custom = root / "custom"
            _write(
                custom / "etc/frp/client-state.json",
                json.dumps(_state("https://203.0.113.10:6099/enroll", "wss", 8443), indent=2) + "\n",
            )
            self.assertTrue(mgmt.migrate_legacy_single443_agent_origin(str(custom)))
            custom_state = json.loads((custom / "etc/frp/client-state.json").read_text(encoding="utf-8"))
            self.assertEqual(custom_state["allocator_url"], "https://203.0.113.10:8443/enroll")

    def test_failed_commit_restores_every_origin_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "wss"
            state_text = json.dumps(_state("https://203.0.113.10:6099/enroll", "wss", 443), indent=2) + "\n"
            endpoint_text = json.dumps({"mgmt_url": "https://203.0.113.10:6099", "note": "keep"}) + "\n"
            _write(root / "etc/frp/client-state.json", state_text)
            _write(root / "etc/frp/server-endpoint.json", endpoint_text)
            os.environ["DRLINK_MGMT_ORIGIN_MIGRATE_FAIL_AFTER"] = "1"
            try:
                with self.assertRaises(OSError):
                    mgmt.migrate_legacy_single443_agent_origin(str(root))
            finally:
                os.environ.pop("DRLINK_MGMT_ORIGIN_MIGRATE_FAIL_AFTER", None)
            self.assertEqual((root / "etc/frp/client-state.json").read_text(encoding="utf-8"), state_text)
            self.assertEqual((root / "etc/frp/server-endpoint.json").read_text(encoding="utf-8"), endpoint_text)
            self.assertTrue(mgmt.legacy_single443_mgmt_origin_drift(str(root)))

    def test_tcp_on_public_443_repairs_origin_and_direct_port_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / "tcp443"
            _write(
                legacy / "etc/frp/client-state.json",
                json.dumps(_state("https://129.225.184.60:6099/enroll", "tcp", 443), indent=2) + "\n",
            )
            before_services = _state("https://129.225.184.60:6099/enroll", "tcp", 443)["services"]
            self.assertTrue(mgmt.migrate_legacy_single443_agent_origin(str(legacy)))
            migrated = json.loads((legacy / "etc/frp/client-state.json").read_text(encoding="utf-8"))
            self.assertEqual(migrated["allocator_url"], "https://129.225.184.60/enroll")
            self.assertEqual(migrated["frp_transport"], "tcp")
            self.assertEqual(migrated["services"], before_services)
            self.assertFalse(mgmt.migrate_legacy_single443_agent_origin(str(legacy)))
            unlabeled = root / "unlabeled"
            _write(
                unlabeled / "etc/frp/client-state.json",
                json.dumps(
                    {
                        "allocator_url": "https://203.0.113.10:6099/enroll",
                        "frp_server": "203.0.113.10",
                        "frp_server_port": 443,
                        "machine_id": "aabbccddeeff00112233445566778899",
                    },
                    indent=2,
                )
                + "\n",
            )
            unlabeled_before = (unlabeled / "etc/frp/client-state.json").read_bytes()
            self.assertFalse(mgmt.migrate_legacy_single443_agent_origin(str(unlabeled)))
            self.assertEqual((unlabeled / "etc/frp/client-state.json").read_bytes(), unlabeled_before)


def _install_fixture(root: Path, state: dict) -> None:
    _write(root / "usr/local/bin/frpc", "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'frpc version 0.71.0'; exit 0; fi\nexit 0\n", 0o755)
    _write(root / "usr/local/bin/frp-client", "#!/bin/sh\necho old-client\n", 0o755)
    _write(root / "usr/local/lib/drlink/frp-client-common.sh", "old\n", 0o644)
    _write(root / "etc/frp/client-state.json", json.dumps(state, indent=2) + "\n")
    _write(
        root / "etc/frp/frpc.toml",
        'serverAddr = "203.0.113.10"\nserverPort = %s\nauth.method = "token"\nauth.token = "test-frp-token-do-not-use"\n' % state["frp_server_port"],
    )
    _write(root / "etc/frp/access-info.txt", "access\n")
    _write(root / "etc/drlink/allocator-ca.crt", "ca\n")
    _write(root / "etc/drlink/version", "PROJECT_VERSION=1.7.0\nFRP_VERSION=0.71.0\n")
    subprocess.check_call(
        [
            sys.executable,
            str(ROOT / "lib/frp_mgmt_auth.py"),
            "gen-key",
            str(root / "etc/frp/client-identity.key"),
            str(root / "etc/frp/client-identity.pub"),
        ],
        stdout=subprocess.DEVNULL,
    )
    os.chmod(root / "etc/frp/client-identity.key", 0o600)
    _write(root / "etc/frp/client-identity.mac", "aa" * 32 + "\n")


def _update(root: Path, extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["FRP_CLIENT_TEST_ROOT"] = str(root)
    env["FRP_CLIENT_LIB"] = str(ROOT / "lib/frp-client-common.sh")
    env["FRP_CLIENT_SKIP_SERVER_VERSION_GATE"] = "1"
    if extra:
        env.update(extra)
    return subprocess.run(
        [str(ROOT / "tools/frp-client"), "update", "--source", str(ROOT)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


class UpgradeMigrationTests(unittest.TestCase):
    def test_wss_update_converges_and_repeat_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _state("https://203.0.113.10:6099/enroll", "wss", 443)
            _install_fixture(root, state)
            key_before = (root / "etc/frp/client-identity.key").read_bytes()
            first = _update(root)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertIn("converged to single-443", first.stdout)
            migrated = json.loads((root / "etc/frp/client-state.json").read_text(encoding="utf-8"))
            self.assertEqual(migrated["allocator_url"], "https://203.0.113.10/enroll")
            self.assertEqual(migrated["services"]["ssh"]["remote_port"], 6003)
            self.assertEqual((root / "etc/frp/client-identity.key").read_bytes(), key_before)
            digest = (root / "etc/frp/client-state.json").read_bytes()
            second = _update(root)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("Management origin        : unchanged", second.stdout)
            self.assertEqual((root / "etc/frp/client-state.json").read_bytes(), digest)

    def test_direct_update_does_not_rewrite_allocator_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _state("https://203.0.113.10:6099/enroll", "tcp", 7000)
            _install_fixture(root, state)
            before = (root / "etc/frp/client-state.json").read_bytes()
            result = _update(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Management origin        : unchanged", result.stdout)
            self.assertEqual((root / "etc/frp/client-state.json").read_bytes(), before)

    def test_same_bundle_repairs_legacy_origin_then_stays_idle(self):
        bundle = "ab" * 32
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _state("https://203.0.113.10:6099/enroll", "wss", 8443)
            _install_fixture(root, state)
            _write(
                root / "etc/drlink/version",
                "PROJECT_VERSION=2.4.0\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=development\nBUNDLE_SHA256=%s\n" % bundle,
            )
            for name in ("drlink-client.service", "drlink-ai-agent.service"):
                src = ROOT / "client" / name
                dest = root / "etc/systemd/system" / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(src.read_bytes())
            key_before = (root / "etc/frp/client-identity.key").read_bytes()
            services_before = state["services"]
            first = _update(root, {"FRP_BUNDLE_SHA256": bundle})
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertNotIn("Update                    : not needed", first.stdout)
            self.assertIn("converged to single-443", first.stdout)
            migrated = json.loads((root / "etc/frp/client-state.json").read_text(encoding="utf-8"))
            self.assertEqual(migrated["allocator_url"], "https://203.0.113.10:8443/enroll")
            self.assertEqual(migrated["services"], services_before)
            self.assertEqual((root / "etc/frp/client-identity.key").read_bytes(), key_before)
            digest = (root / "etc/frp/client-state.json").read_bytes()
            second = _update(root, {"FRP_BUNDLE_SHA256": bundle})
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("Update                    : not needed", second.stdout)
            self.assertEqual((root / "etc/frp/client-state.json").read_bytes(), digest)

    def test_rollback_restores_origin_files_after_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _state("https://203.0.113.10:6099/enroll", "wss", 443)
            _install_fixture(root, state)
            endpoint = json.dumps({"mgmt_url": "https://203.0.113.10:6099", "note": "keep"}, indent=2) + "\n"
            _write(root / "etc/frp/server-endpoint.json", endpoint)
            state_before = (root / "etc/frp/client-state.json").read_bytes()
            endpoint_before = (root / "etc/frp/server-endpoint.json").read_bytes()
            key_before = (root / "etc/frp/client-identity.key").read_bytes()
            result = _update(root, {"FRP_CLIENT_UPGRADE_HOOK_FAIL": "after-mgmt-origin"})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("UPGRADE_ROLLBACK=PASS", result.stdout + result.stderr)
            self.assertEqual((root / "etc/frp/client-state.json").read_bytes(), state_before)
            self.assertEqual((root / "etc/frp/server-endpoint.json").read_bytes(), endpoint_before)
            self.assertEqual((root / "etc/frp/client-identity.key").read_bytes(), key_before)


if __name__ == "__main__":
    unittest.main()
