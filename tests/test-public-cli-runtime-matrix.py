#!/usr/bin/env python3
"""Prove public tokens → match action → dry-run backend argv for key paths."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "tools" / "frpctl"


def load(name, rel):
    import importlib.util

    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GRAMMAR = load("frp_ctl_grammar", "lib/frp_ctl_grammar.py")


def write_server_tree(tree: Path) -> None:
    (tree / "etc/drlink").mkdir(parents=True)
    (tree / "var/lib/drlink").mkdir(parents=True)
    (tree / "usr/local/lib/drlink").mkdir(parents=True)
    cfg = {
        "registry_file": str(tree / "var/lib/drlink/registry.json"),
        "egress_control_file": str(tree / "var/lib/drlink/egress-control.json"),
        "access_control_file": str(tree / "var/lib/drlink/access-control.json"),
        "service_profiles_file": str(tree / "var/lib/drlink/service-profiles.json"),
    }
    (tree / "etc/drlink/config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    (tree / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}}) + "\n", encoding="utf-8"
    )
    (tree / "var/lib/drlink/egress-control.json").write_text(
        json.dumps({"schema_version": 3, "egress_profiles": {}}) + "\n", encoding="utf-8"
    )
    (tree / "var/lib/drlink/access-control.json").write_text(
        json.dumps({"schema_version": 1, "access_lists": {}}) + "\n", encoding="utf-8"
    )
    (tree / "var/lib/drlink/service-profiles.json").write_text(
        json.dumps({"schema_version": 1, "profiles": {}}) + "\n", encoding="utf-8"
    )
    (tree / "etc/drlink/version").write_text(
        "PROJECT_VERSION=2.4.0\nFRP_VERSION=0.71.0\n", encoding="utf-8"
    )


class PublicRuntimeMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tree = Path(cls.tmp.name) / "server"
        write_server_tree(cls.tree)
        cls.env = os.environ.copy()
        cls.env.update(
            {
                "FRP_CTL_FORCE_DRLINK": "1",
                "FRP_CTL_CMD_NAME": "drlink",
                "FRP_CTL_BIN_DIR": str(ROOT / "tools"),
                "FRP_CTL_TEST_ROOT": str(cls.tree),
                "FRP_DEPLOY_TEST_ROOT": str(cls.tree),
                "FRP_CTL_DRY_RUN": "1",
                "FRP_SKIP_SYSTEMD": "1",
                "HOME": str(Path(cls.tmp.name) / "home"),
            }
        )
        Path(cls.env["HOME"]).mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def match(self, *tokens):
        return GRAMMAR.match(list(tokens), "server")

    def dry_run(self, *tokens):
        proc = subprocess.run(
            [str(CTL), *tokens],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        self.assertNotRegex(out, r"usage:\s+frp-", msg=out)
        self.assertNotIn("argparse", out.lower(), msg=out)
        argv = None
        for line in out.splitlines():
            if line.startswith("DISPATCH_ARGV\t"):
                argv = json.loads(line.split("\t", 1)[1])
                break
        return proc.returncode, out, argv

    def test_show_internet_family(self):
        for toks, action in (
            (("show", "internet"), "egress_cmd"),
            (("show", "internet-profile", "vendor-api"), "show_egress_profile"),
            (("show", "access-rule", "office"), "access_cmd"),
            (("show", "service-profile", "office-ssh"), "show_profile"),
        ):
            result = self.match(*toks)
            self.assertEqual(result.get("status"), "ok", result)
            self.assertEqual(result.get("action"), action, result)

    def test_access_source_argv(self):
        result = self.match("set", "access-source", "office", "203.0.113.10")
        self.assertEqual(result["passthrough"][:6], [
            "add-source", "office", "--name", "203.0.113.10", "--source", "203.0.113.10"
        ])
        rc, out, argv = self.dry_run("set", "access-source", "office", "203.0.113.10")
        self.assertEqual(rc, 0, out)
        self.assertEqual(
            argv,
            ["frp-access", "add-source", "office", "--name", "203.0.113.10", "--source", "203.0.113.10"],
        )
        result = self.match("unset", "access-source", "office", "203.0.113.10")
        self.assertEqual(
            result["passthrough"][:4],
            ["remove-source", "office", "--source", "203.0.113.10"],
        )

    def test_internet_destination_protocol_argv(self):
        result = self.match(
            "set", "internet-destination", "vendor-api", "api.example.com", "443", "https"
        )
        self.assertEqual(result.get("protocol"), "https")
        rc, out, argv = self.dry_run(
            "set", "internet-destination", "vendor-api", "api.example.com", "443", "https"
        )
        self.assertEqual(rc, 0, out)
        self.assertEqual(
            argv,
            [
                "frp-egress",
                "add-destination",
                "vendor-api",
                "api.example.com",
                "443",
                "--protocol",
                "https",
            ],
        )

    def test_test_internet_protocol_argv(self):
        result = self.match("test", "internet", "10.0.0.5", "api.example.com", "443")
        self.assertEqual(result["passthrough"], ["explain", "10.0.0.5", "api.example.com", "443"])
        result = self.match(
            "test", "internet", "10.0.0.5", "api.example.com", "443", "https"
        )
        self.assertEqual(
            result["passthrough"],
            ["explain", "10.0.0.5", "api.example.com", "443", "--protocol", "https"],
        )
        rc, out, argv = self.dry_run(
            "test", "internet", "10.0.0.5", "api.example.com", "443", "https"
        )
        self.assertEqual(rc, 0, out)
        self.assertEqual(
            argv,
            [
                "frp-egress",
                "explain",
                "10.0.0.5",
                "api.example.com",
                "443",
                "--protocol",
                "https",
            ],
        )

    def test_fixed_tcp_lifecycle_actions(self):
        result = self.match("set", "fixed-tcp", "vendor-license")
        self.assertEqual(result["action"], "control_plane")
        self.assertEqual(result["tokens"][:3], ["set", "fixed-tcp", "vendor-license"])
        enabled = self.match("set", "fixed-tcp", "vendor-license", "enabled")
        self.assertEqual(enabled["action"], "control_plane")
        disabled = self.match("unset", "fixed-tcp", "vendor-license", "enabled")
        self.assertEqual(disabled["action"], "control_plane")
        deleted = self.match("unset", "fixed-tcp", "vendor-license")
        self.assertEqual(deleted["action"], "control_plane")
        result = self.match("test", "fixed-tcp", "vendor-license", "10.0.0.5")
        self.assertEqual(result["passthrough"], ["tcp", "explain", "vendor-license", "10.0.0.5"])
        rc, out, argv = self.dry_run("test", "fixed-tcp", "vendor-license", "10.0.0.5")
        self.assertEqual(rc, 0, out)
        self.assertEqual(argv, ["frp-egress", "tcp", "explain", "vendor-license", "10.0.0.5"])

    def test_support_bundle_and_export(self):
        self.assertEqual(self.match("system", "support-bundle")["action"], "support_bundle")
        self.assertEqual(
            self.match("system", "support-bundle", "/tmp/x.tgz")["passthrough"],
            ["--output", "/tmp/x.tgz"],
        )
        rc, out, argv = self.dry_run("system", "support-bundle", "/tmp/x.tgz")
        self.assertEqual(rc, 0, out)
        self.assertEqual(argv, ["frp-support-bundle", "--output", "/tmp/x.tgz"])
        result = self.match("system", "export", "internet-profile", "vendor-api", "/tmp/v.json")
        self.assertEqual(
            result["passthrough"],
            ["export", "vendor-api", "--output", "/tmp/v.json"],
        )
        rc, out, argv = self.dry_run(
            "system", "export", "internet-profile", "vendor-api", "/tmp/v.json"
        )
        self.assertEqual(rc, 0, out)
        self.assertEqual(argv, ["frp-egress", "export", "vendor-api", "--output", "/tmp/v.json"])

    def test_cleanup_access_rule_expired(self):
        result = self.match("system", "cleanup", "access-rule", "office", "expired")
        self.assertEqual(result["action"], "access_cmd")
        self.assertEqual(result["passthrough"], ["remove-expired", "office"])
        self.assertTrue(result.get("confirm_expired"))

    def test_service_profile_create_action(self):
        result = self.match("set", "service-profile", "office-ssh")
        self.assertEqual(result["action"], "create_profile")
        self.assertEqual(result["name"], "office-ssh")


if __name__ == "__main__":
    unittest.main()
