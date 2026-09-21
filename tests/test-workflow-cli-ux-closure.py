#!/usr/bin/env python3
"""Compact workflow acceptance for v2.4.0 CLI UX final closure."""
from __future__ import annotations

import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_loader(
        name, loader=importlib.machinery.SourceFileLoader(name, str(path))
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


GRAMMAR = load_module("frp_ctl_grammar_wux", "lib/frp_ctl_grammar.py")
CATALOG = load_module("frp_cli_catalog_wux", "lib/frp_cli_catalog.py")
CREATE = load_module("frp_create_client_wux", "tools/frp-create-client")


def _msg(result):
    return str(result.get("message") or "")


class DiscoveryTests(unittest.TestCase):
    def test_public_set_surface(self):
        names = [n for n, _ in CATALOG.subcommands("set", "server")]
        for required in (
            "network-object",
            "network-group",
            "service-object",
            "service-group",
            "permission-object",
            "permission-group",
            "remote-access",
            "internet-access",
            "ai-identity",
            "ai-access",
            "server",
        ):
            self.assertIn(required, names)
        for banned in (
            "access-rule",
            "access-source",
            "service-access",
            "internet-source",
            "internet-destination",
            "fixed-tcp",
            "object",
            "ai-principal",
            "published-service",
        ):
            self.assertNotIn(banned, names)

    def test_public_test_surface(self):
        names = [n for n, _ in CATALOG.subcommands("test", "server")]
        for required in ("remote-access", "internet-access", "ai-access"):
            self.assertIn(required, names)
        for banned in ("acl", "access", "internet-profile", "service-profile"):
            self.assertNotIn(banned, names)

    def test_no_other_category(self):
        text = _msg(GRAMMAR.match(["set", "?"], "server"))
        self.assertNotIn("\nOther\n", text)
        self.assertIn("Remote Access", text)
        self.assertIn("Internet Access", text)

    def test_incomplete_never_backend_usage(self):
        for cmd in (
            ["set", "acl"],
            ["set", "internet-profile"],
            ["test", "acl"],
            ["show", "acl"],
            ["show", "internet-profile"],
            ["unset", "acl"],
            ["unset", "internet-profile"],
            ["access", "list"],
            ["egress", "list"],
            ["help", "legacy"],
        ):
            result = GRAMMAR.match(cmd, "server")
            self.assertEqual(result.get("status"), "error", cmd)
            msg = _msg(result).lower()
            for leak in ("frp-access", "frp-egress", "frp-profile"):
                self.assertNotIn(leak, msg, cmd)

    def test_set_server_properties_discoverable(self):
        text = _msg(GRAMMAR.match(["set", "server", "?"], "server"))
        for prop in (
            "public-hostname",
            "bootstrap-hostname",
            "installer-url",
            "windows-installer-url",
        ):
            self.assertIn(prop, text)


class WorkflowGrammarTests(unittest.TestCase):
    def test_w3_group_mapping(self):
        r = GRAMMAR.match(["set", "group", "production"], "server")
        self.assertEqual(r.get("status"), "ok")
        self.assertEqual(r.get("action"), "create_group")
        self.assertEqual(r.get("name"), "production")

    def test_w4_remote_access_canonical(self):
        create = GRAMMAR.match(["set", "remote-access", "office-network"], "server")
        self.assertEqual(create.get("status"), "ok")
        self.assertEqual(create.get("action"), "control_plane")
        source = GRAMMAR.match(
            ["set", "remote-access", "office-network", "source", "office"], "server"
        )
        self.assertEqual(source.get("action"), "control_plane")
        test = GRAMMAR.match(
            ["test", "remote-access", "10.10.10.25", "lab", "tcp", "22"], "server"
        )
        self.assertEqual(test.get("action"), "control_plane")
        # Obsolete ACL surface is rejected.
        obsolete = GRAMMAR.match(["set", "acl", "office-network"], "server")
        self.assertEqual(obsolete.get("status"), "error")

    def test_w5_internet_access_canonical(self):
        create = GRAMMAR.match(["set", "internet-access", "ubuntu-update"], "server")
        self.assertEqual(create.get("status"), "ok")
        self.assertEqual(create.get("action"), "control_plane")
        enable = GRAMMAR.match(
            ["set", "internet-access", "ubuntu-update", "enabled"], "server"
        )
        self.assertEqual(enable.get("action"), "control_plane")
        obsolete = GRAMMAR.match(["set", "internet-profile", "ubuntu-update"], "server")
        self.assertEqual(obsolete.get("status"), "error")

    def test_obsolete_compat_rejected(self):
        r = GRAMMAR.match(["set", "access-rule", "office"], "server")
        self.assertEqual(r.get("status"), "error")
        r2 = GRAMMAR.match(["help", "legacy"], "server")
        self.assertEqual(r2.get("status"), "error")


class CreateClientWorkflowTests(unittest.TestCase):
    def test_w2_multi_service_review(self):
        from io import StringIO

        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            CREATE.print_client_configuration(
                "Expernet DP1",
                "-",
                services=[
                    {
                        "preset": "ssh",
                        "name": "SSH",
                        "local_ip": "127.0.0.1",
                        "local_port": 22,
                        "ssh_user": "stellar",
                    },
                    {
                        "preset": "https",
                        "name": "HTTPS",
                        "local_ip": "192.168.122.2",
                        "local_port": 443,
                    },
                ],
            )
        finally:
            sys.stdout = old
        text = buf.getvalue()
        self.assertIn("SSH", text)
        self.assertIn("HTTPS", text)
        self.assertIn("127.0.0.1:22", text)
        self.assertIn("192.168.122.2:443", text)
        self.assertIn("stellar", text)

    def test_enrollment_guidance_canonical(self):
        lines = "\n".join(CREATE._enrollment_track_hints("abc123"))
        self.assertIn("unset enrollment abc123", lines)
        self.assertIn("show enrollments", lines)
        self.assertNotIn("revoke enrollment", lines)
        self.assertNotIn("delete enrollment", lines)

    def test_w10_installer_preflight_404(self):
        class FakeHTTPError(Exception):
            def __init__(self):
                self.code = 404

        with mock.patch("urllib.request.urlopen", side_effect=FakeHTTPError()):
            # Force import path used inside helper.
            import urllib.error

            err = urllib.error.HTTPError(
                "https://example.test/missing", 404, "Not Found", hdrs=None, fp=None
            )
            with mock.patch("urllib.request.urlopen", side_effect=err):
                with self.assertRaises(SystemExit) as caught:
                    CREATE.preflight_installer_url(
                        "https://example.test/missing", label="Client installer"
                    )
        msg = str(caught.exception)
        self.assertIn("404", msg)
        self.assertIn("No enrollment ticket was created", msg)
        self.assertIn("set server installer-url", msg)

    def test_exact_sha_installer_resolve(self):
        alloc = "https://203.0.113.10:6099/enroll"
        expected = "https://203.0.113.10:6099/artifacts/agent/bootstrap-client.sh"
        cfg = {
            "allocator_public_url": alloc,
            "client_installer_url": (
                "https://raw.githubusercontent.com/datarelay-labs/"
                "datarelay-link/v2.4.0/dist/bootstrap-client.sh"
            ),
        }
        url = CREATE.resolve_configured_installer_url(cfg, windows=False)
        self.assertEqual(url, expected)
        self.assertNotIn("raw.githubusercontent.com", url)
        self.assertNotIn("github.com/datarelay-labs", url)
        self.assertNotIn("/v2.4.0/", url)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit):
                CREATE.resolve_configured_installer_url(
                    {
                        "client_installer_url": (
                            "https://raw.githubusercontent.com/datarelay-labs/"
                            "datarelay-link/v2.4.0/dist/bootstrap-client.sh"
                        )
                    },
                    windows=False,
                )
        closed = stderr.getvalue()
        self.assertIn("No changes were applied", closed)
        self.assertNotIn("Traceback", closed)
        self.assertNotIn("raw.githubusercontent.com", closed)


class BackendProductOutputTests(unittest.TestCase):
    """Legacy frp-access/egress CLIs are deleted; assert absence + create-client UX."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.env = os.environ.copy()
        self.env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        (self.root / "etc/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/drlink").mkdir(parents=True, exist_ok=True)
        self.create_client = ROOT / "tools" / "frp-create-client"

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def test_dead_policy_tools_absent(self):
        for name in ("frp-access", "frp-egress", "frp-profile"):
            self.assertFalse((ROOT / "tools" / name).exists(), name)

    def test_guided_menu_has_no_legacy_labels(self):
        for key, entries in CATALOG.NAVIGATION_TREE.items():
            for item in entries:
                label = item[1] if len(item) > 1 else ""
                self.assertNotIn(
                    label,
                    ("ACLs", "Access Lists", "Service Profiles", "Internet Profiles", "Egress Profiles"),
                    "%s -> %s" % (key, label),
                )

    def test_onboarding_missing_enrollments_dir_product_error(self):
        incomplete = self.root / "etc/drlink/config.json"
        incomplete.write_text(
            json.dumps({"public_host": "203.0.113.10", "public_ip": "203.0.113.10"}) + "\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [sys.executable, "-u", str(self.create_client)],
            env=self.env,
            text=True,
            capture_output=True,
        )
        combined = proc.stdout + proc.stderr
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", combined)
        self.assertNotIn("KeyError", combined)
        self.assertIn("Client onboarding cannot continue", combined)
        self.assertIn("enrollments_dir", combined)
        self.assertIn("system diagnostics", combined)

        with self.assertRaises(SystemExit):
            CREATE.require_onboarding_config({"public_host": "x"})


if __name__ == "__main__":
    unittest.main()
