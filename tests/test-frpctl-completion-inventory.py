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
    def test_egress_profile_completion(self):
        inv = ["vendor-api", "partner"]
        hits = GRAMMAR.completion_candidates(
            "show egress-profile ",
            "server",
            [],
            {},
            [],
            trailing=True,
            egress_profiles=inv,
        )
        self.assertIn("vendor-api", hits)
        self.assertIn("partner", hits)

    def test_access_list_completion(self):
        inv = ["office", "acl_office"]
        hits = GRAMMAR.completion_candidates(
            "show access-list ",
            "server",
            [],
            {},
            [],
            trailing=True,
            access_lists=inv,
        )
        self.assertIn("office", hits)

    def test_service_profile_completion(self):
        inv = ["office-ssh"]
        hits = GRAMMAR.completion_candidates(
            "show service-profile ",
            "server",
            [],
            {},
            [],
            trailing=True,
            service_profiles=inv,
        )
        self.assertIn("office-ssh", hits)

    def test_no_public_protocol_flag_completion(self):
        # Public Tab must not complete or advertise --protocol values.
        for line, trailing in (
            ("add egress-destination vendor-api api.example.com 443 --protocol ", True),
            ("add egress-destination vendor-api api.example.com 443 --protocol h", False),
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

    def test_add_egress_destination_offers_profiles(self):
        hits = GRAMMAR.completion_candidates(
            "add egress-destination ",
            "server",
            [],
            {},
            [],
            trailing=True,
            egress_profiles=["vendor-api", "partner"],
        )
        self.assertIn("vendor-api", hits)
        self.assertIn("partner", hits)


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
