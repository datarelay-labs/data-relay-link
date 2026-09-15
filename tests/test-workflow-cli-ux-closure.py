#!/usr/bin/env python3
"""Compact workflow acceptance for v2.4.0 CLI UX final closure."""
from __future__ import annotations

import importlib.machinery
import importlib.util
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
        self.assertEqual(
            names,
            [
                "client",
                "group",
                "service-profile",
                "acl",
                "internet-profile",
                "fixed-tcp",
                "server",
            ],
        )
        for banned in (
            "enrollment",
            "access-rule",
            "access-source",
            "service-access",
            "internet-source",
            "internet-destination",
        ):
            self.assertNotIn(banned, names)

    def test_public_test_surface(self):
        names = [n for n, _ in CATALOG.subcommands("test", "server")]
        self.assertEqual(names, ["acl", "internet", "fixed-tcp"])
        self.assertNotIn("access", names)

    def test_no_other_category(self):
        text = _msg(GRAMMAR.match(["set", "?"], "server"))
        self.assertNotIn("\nOther\n", text)
        self.assertIn("Access Control", text)
        self.assertIn("Internet Access", text)

    def test_incomplete_never_backend_usage(self):
        for cmd in (
            ["set", "acl"],
            ["set", "internet-profile"],
            ["test", "acl"],
            ["test", "internet"],
            ["test", "fixed-tcp"],
            ["show", "acl"],
            ["show", "internet-profile"],
            ["unset", "acl"],
            ["unset", "internet-profile"],
            ["show", "access-log"],
        ):
            result = GRAMMAR.match(cmd, "server")
            self.assertEqual(result.get("status"), "incomplete", cmd)
            msg = _msg(result).lower()
            self.assertFalse(msg.startswith("usage: frp-"), cmd)
            for leak in ("frp-access", "frp-egress", "frp-profile", "frpc", "frps"):
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

    def test_w4_acl_mapping(self):
        create = GRAMMAR.match(["set", "acl", "office-network"], "server")
        self.assertEqual(create.get("action"), "access_cmd")
        self.assertEqual(create.get("passthrough"), ["create", "office-network"])

        source = GRAMMAR.match(
            ["set", "acl", "office-network", "source", "10.10.10.0/24"], "server"
        )
        self.assertEqual(source.get("action"), "access_cmd")

        assign = GRAMMAR.match(
            ["set", "acl", "office-network", "service", "dp1", "ssh"], "server"
        )
        self.assertEqual(assign.get("action"), "access_cmd")
        self.assertEqual(
            assign.get("passthrough")[:4],
            ["assign", "dp1", "ssh", "office-network"],
        )

        test = GRAMMAR.match(["test", "acl", "dp1", "ssh", "10.10.10.25"], "server")
        self.assertEqual(test.get("action"), "access_cmd")
        self.assertEqual(test.get("passthrough"), ["test", "dp1", "ssh", "10.10.10.25"])

    def test_w5_internet_nested_mapping(self):
        create = GRAMMAR.match(["set", "internet-profile", "ubuntu-update"], "server")
        self.assertEqual(create.get("action"), "create_egress_profile")

        source = GRAMMAR.match(
            ["set", "internet-profile", "ubuntu-update", "source", "10.10.20.0/24"],
            "server",
        )
        self.assertEqual(source.get("action"), "add_egress_source")

        dest = GRAMMAR.match(
            [
                "set",
                "internet-profile",
                "ubuntu-update",
                "destination",
                "archive.ubuntu.com",
                "443",
                "https",
            ],
            "server",
        )
        self.assertEqual(dest.get("action"), "add_egress_destination")

        enable = GRAMMAR.match(
            ["set", "internet-profile", "ubuntu-update", "enabled"], "server"
        )
        self.assertEqual(enable.get("action"), "enable_egress_profile")

    def test_hidden_compat_still_parseable(self):
        r = GRAMMAR.match(["set", "access-rule", "office"], "server")
        self.assertEqual(r.get("status"), "ok")
        self.assertEqual(r.get("action"), "access_cmd")


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
        sha = "0123456789abcdef0123456789abcdef01234567"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc/drlink").mkdir(parents=True)
            (root / "etc/drlink/version").write_text(
                "PROJECT_VERSION=2.4.0\nSOURCE_REF=%s\nRELEASE_CHANNEL=stable\n" % sha,
                encoding="utf-8",
            )
            os.environ["FRP_CTL_TEST_ROOT"] = str(root)
            os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
            try:
                cfg = {
                    "client_installer_url": (
                        "https://raw.githubusercontent.com/datarelay-labs/"
                        "data-relay-link/v2.4.0/dist/bootstrap-client.sh"
                    )
                }
                url = CREATE.resolve_configured_installer_url(cfg, windows=False)
                self.assertIn("/%s/" % sha, url)
                self.assertNotIn("/v2.4.0/", url)
            finally:
                os.environ.pop("FRP_CTL_TEST_ROOT", None)
                os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)


class BackendProductOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.env = os.environ.copy()
        self.env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)

        lib = self.root / "usr/local/lib/drlink"
        lib.mkdir(parents=True, exist_ok=True)
        for name in (
            "frp_egress_control.py",
            "frp_access_control.py",
            "frp_control_locks.py",
            "frp_audit.py",
            "frp_client_registry.py",
        ):
            src = ROOT / "lib" / name
            if src.is_file():
                shutil.copy2(src, lib / name)

        sbin = self.root / "usr/local/sbin"
        sbin.mkdir(parents=True, exist_ok=True)
        for tool in ("frp-egress", "frp-access"):
            path = sbin / tool
            path.write_text((ROOT / "tools" / tool).read_text(encoding="utf-8"), encoding="utf-8")
            path.chmod(0o755)
            setattr(self, tool.replace("-", "_"), path)

        (self.root / "etc/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/drlink").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/drlink/config.json").write_text(
            json.dumps(
                {
                    "egress_control_file": "/var/lib/drlink/egress-control.json",
                    "access_control_file": "/var/lib/drlink/access-control.json",
                    "registry_file": "/var/lib/drlink/registry.json",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        sys.path.insert(0, str(ROOT / "lib"))
        import frp_egress_control as EG  # noqa: E402
        import frp_access_control as ACL  # noqa: E402

        self.EG = EG
        self.ACL = ACL
        EG.save_egress_state(
            EG.empty_egress_state(), path=self.root / "var/lib/drlink/egress-control.json"
        )
        ACL.save_access_state(
            ACL.empty_access_state(), path=self.root / "var/lib/drlink/access-control.json"
        )

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _run(self, tool, args):
        return subprocess.run(
            [sys.executable, "-u", str(tool), *args],
            env=self.env,
            text=True,
            capture_output=True,
        )

    def test_w4_acl_next_steps(self):
        proc = self._run(self.frp_access, ["create", "office-network"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertIn("Created ACL: office-network", out)
        self.assertIn("set acl office-network source", out)
        self.assertIn("set acl office-network service", out)
        self.assertIn("test acl", out)
        self.assertNotIn("Access List", out)
        self.assertNotIn("access-list", out.lower())

    def test_w5_internet_next_steps_and_status(self):
        proc = self._run(self.frp_egress, ["create", "ubuntu-update", "--disabled"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertIn("Created Internet Access profile: ubuntu-update", out)
        self.assertIn("set internet-profile ubuntu-update source", out)
        self.assertIn("test internet", out)
        self.assertIn("set internet-profile ubuntu-update enabled", out)
        self.assertNotIn("egress add-", out)
        self.assertNotIn("create →", out)

        status = self._run(self.frp_egress, ["status"])
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("Internet Access", status.stdout)
        self.assertNotIn("Egress control file", status.stdout)
        self.assertNotIn("Doctor", status.stdout)


if __name__ == "__main__":
    unittest.main()
