#!/usr/bin/env python3
"""Prove public tokens → match action for canonical v2.4 control-plane paths."""
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
    }
    (tree / "etc/drlink/config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    (tree / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}}) + "\n", encoding="utf-8"
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
        return proc.returncode, out

    def test_obsolete_surfaces_rejected(self):
        for toks in (
            ("show", "internet-profile", "vendor-api"),
            ("show", "access-rule", "office"),
            ("show", "service-profile", "office-ssh"),
            ("set", "access-source", "office", "203.0.113.10"),
            ("set", "internet-destination", "vendor-api", "api.example.com", "443", "https"),
            ("set", "service-profile", "office-ssh"),
            ("system", "export", "internet-profile", "vendor-api", "/tmp/v.json"),
            ("system", "cleanup", "access-rule", "office", "expired"),
            ("help", "legacy"),
            ("access", "list"),
            ("egress", "list"),
        ):
            result = self.match(*toks)
            self.assertEqual(result.get("status"), "error", toks)

    def test_canonical_control_plane_actions(self):
        for toks in (
            ("show", "remote-access"),
            ("set", "remote-access", "office"),
            ("show", "internet-access"),
            ("set", "internet-access", "allow-api"),
            ("set", "fixed-tcp", "vendor-license"),
            ("set", "fixed-tcp", "vendor-license", "enabled"),
            ("unset", "fixed-tcp", "vendor-license", "enabled"),
            ("unset", "fixed-tcp", "vendor-license"),
            ("show", "published-services"),
            ("test", "remote-access", "10.0.0.5", "lab", "tcp", "22"),
            ("test", "internet-access", "10.0.0.5", "api.example.com", "443", "https"),
        ):
            result = self.match(*toks)
            self.assertEqual(result.get("status"), "ok", result)
            self.assertEqual(result.get("action"), "control_plane", result)

    def test_support_bundle_still_routes(self):
        self.assertEqual(self.match("system", "support-bundle")["action"], "support_bundle")
        self.assertEqual(
            self.match("system", "support-bundle", "/tmp/x.tgz")["passthrough"],
            ["--output", "/tmp/x.tgz"],
        )
        rc, out = self.dry_run("system", "support-bundle", "/tmp/x.tgz")
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
