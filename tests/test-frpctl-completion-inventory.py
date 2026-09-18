#!/usr/bin/env python3
"""F09: completion inventory pools; public Tab never offers --options."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GRAMMAR = load("frp_ctl_grammar", "lib/frp_ctl_grammar.py")


class CompletionInventoryTests(unittest.TestCase):
    def test_managed_host_completion(self):
        hits = GRAMMAR.completion_candidates(
            "show managed-host ",
            "server",
            ["host-a", "host-b"],
            {},
            [],
            trailing=True,
        )
        self.assertIn("host-a", hits)
        self.assertIn("host-b", hits)

    def test_unset_managed_host_completion(self):
        hits = GRAMMAR.completion_candidates(
            "unset managed-host ",
            "server",
            ["host-a"],
            {},
            [],
            trailing=True,
        )
        self.assertIn("host-a", hits)

    def test_no_public_protocol_flag_completion(self):
        # Public Tab must not complete or advertise --protocol values.
        for line, trailing in (
            ("set internet-destination vendor-api api.example.com 443 --protocol ", True),
            ("set internet-destination vendor-api api.example.com 443 --protocol h", False),
            ("add egress-destination vendor-api api.example.com 443 --protocol ", True),
            ("egress add-destination vendor-api api.example.com 443 --protocol ", True),
        ):
            hits = GRAMMAR.completion_candidates(
                line,
                "server",
                [],
                {},
                [],
                trailing=trailing,
                egress_profiles=["vendor-api"],
            )
            self.assertEqual(hits, [], msg=line)
            self.assertFalse(any(str(h).startswith("-") for h in hits))

    def test_obsolete_internet_profile_not_completed(self):
        hits = GRAMMAR.completion_candidates(
            "show internet-profile ",
            "server",
            [],
            {},
            [],
            trailing=True,
            egress_profiles=["vendor-api", "partner"],
        )
        self.assertEqual(hits, [])


class GrammarPayloadInventoryTests(unittest.TestCase):
    def test_payload_loads_state_inventory(self):
        tmp = tempfile.TemporaryDirectory()
        tree = Path(tmp.name) / "root"
        cfg_dir = tree / "etc/drlink"
        cfg_dir.mkdir(parents=True)
        lib = tree / "var/lib/drlink"
        lib.mkdir(parents=True)
        (lib / "registry.json").write_text('{"clients":{}}\n', encoding="utf-8")
        (lib / "egress-control.json").write_text(
            json.dumps(
                {
                    "egress_profiles": {
                        "ep1": {"name": "vendor-api", "enabled": False},
                    }
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (lib / "access-control.json").write_text(
            json.dumps({"access_lists": {"acl1": {"name": "office"}}}) + "\n",
            encoding="utf-8",
        )
        (lib / "service-profiles.json").write_text(
            json.dumps({"profiles": {"sp1": {"name": "office-ssh"}}}) + "\n",
            encoding="utf-8",
        )
        (cfg_dir / "config.json").write_text(
            json.dumps(
                {
                    "registry_file": str(lib / "registry.json"),
                    "egress_control_file": str(lib / "egress-control.json"),
                    "access_control_file": str(lib / "access-control.json"),
                    "service_profiles_file": str(lib / "service-profiles.json"),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        # Prefer this fixture over any inherited FRP_*_TEST_ROOT from other tests.
        for key in (
            "FRP_CTL_TEST_ROOT",
            "FRP_CLIENT_TEST_ROOT",
            "FRP_SERVER_TEST_ROOT",
            "FRP_ROLE_TEST_ROOT",
            "FRP_UPDATE_ROOT",
            "FRP_UNINSTALL_TEST_ROOT",
        ):
            env.pop(key, None)
        env["FRP_DEPLOY_TEST_ROOT"] = str(tree)
        env["FRP_CTL_TEST_ROOT"] = str(tree)
        import subprocess

        proc = subprocess.run(
            [str(ROOT / "tools" / "frpctl"), "--print-grammar-payload"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn("vendor-api", payload.get("egress") or [])
        self.assertIn("office", payload.get("access_lists") or [])
        self.assertIn("office-ssh", payload.get("service_profiles") or [])
        self.assertFalse(payload.get("inventory_warning"))
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
