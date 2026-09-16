#!/usr/bin/env python3
"""Compact workflow acceptance for v2.4.0 CLI UX final closure."""
from __future__ import annotations

import argparse
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
        for required in (
            "client",
            "object",
            "object-group",
            "client-group",
            "remote-access",
            "internet-access",
            "ai-principal",
            "ai-access",
            "fixed-tcp",
            "server",
        ):
            self.assertIn(required, names)
        for banned in (
            "access-rule",
            "access-source",
            "service-access",
            "internet-source",
            "internet-destination",
        ):
            self.assertNotIn(banned, names)

    def test_public_test_surface(self):
        names = [n for n, _ in CATALOG.subcommands("test", "server")]
        for required in ("acl", "internet", "fixed-tcp", "remote-access", "internet-access", "ai-access"):
            self.assertIn(required, names)
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
            "frp_public_suffix.py",
            "frp_infrastructure_ports.py",
        ):
            src = ROOT / "lib" / name
            if src.is_file():
                shutil.copy2(src, lib / name)
        psl = ROOT / "lib" / "data" / "public_suffix_list.dat"
        if psl.is_file():
            data = lib / "data"
            data.mkdir(parents=True, exist_ok=True)
            shutil.copy2(psl, data / "public_suffix_list.dat")

        sbin = self.root / "usr/local/sbin"
        sbin.mkdir(parents=True, exist_ok=True)
        for tool in ("frp-egress", "frp-access", "frp-create-client"):
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
                    "enrollments_dir": "/var/lib/drlink/enrollments",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (self.root / "var/lib/drlink/registry.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "clients": {
                        "machine-abcdef012345": {
                            "label": "dp1",
                            "hostname": "dp1-host",
                            "services": {"ssh": {"remote_port": 6001, "enabled": True}},
                        }
                    },
                    "reserved": [6001],
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

    def _load_egress_cli(self):
        name = "frp_egress_cli_%s" % self.id().replace(".", "_")
        spec = importlib.util.spec_from_loader(
            name,
            loader=importlib.machinery.SourceFileLoader(name, str(self.frp_egress)),
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    def _assert_no_access_list_leak(self, text):
        lowered = text.lower()
        self.assertNotIn("Access List", text)
        self.assertNotIn("access-list", lowered)
        self.assertNotIn("access lists", lowered)

    def test_w4_acl_next_steps(self):
        proc = self._run(self.frp_access, ["create", "office-network"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = proc.stdout
        self.assertIn("Created ACL: office-network", out)
        self.assertIn("set acl office-network source", out)
        self.assertIn("set acl office-network service", out)
        self.assertIn("test acl", out)
        self._assert_no_access_list_leak(out)

    def test_w4_acl_destructive_and_dependency_terminology(self):
        self.assertEqual(self._run(self.frp_access, ["create", "office-network"]).returncode, 0)
        add = self._run(
            self.frp_access,
            [
                "add-source",
                "office-network",
                "--name",
                "office",
                "--source",
                "10.10.10.0/24",
            ],
        )
        self.assertEqual(add.returncode, 0, add.stderr)
        self._assert_no_access_list_leak(add.stdout + add.stderr)
        assign = self._run(
            self.frp_access, ["assign", "dp1", "ssh", "office-network"]
        )
        self.assertEqual(assign.returncode, 0, assign.stderr)
        self._assert_no_access_list_leak(assign.stdout + assign.stderr)

        delete = self._run(self.frp_access, ["delete", "office-network"])
        self.assertNotEqual(delete.returncode, 0)
        dep = delete.stdout + delete.stderr
        self.assertIn('Cannot delete ACL "office-network"', dep)
        self.assertIn("dp1:ssh", dep)
        self.assertIn("unset acl office-network service dp1 ssh", dep)
        self._assert_no_access_list_leak(dep)
        self.assertNotIn("another Access List", dep)
        self.assertNotIn("Change those services to PUBLIC", dep)

        public = self._run(self.frp_access, ["public", "dp1", "ssh", "--yes"])
        self.assertEqual(public.returncode, 0, public.stderr)
        self.assertIn("Restrict this service with an ACL", public.stdout)
        self.assertIn("set acl <ACL> service", public.stdout)
        self._assert_no_access_list_leak(public.stdout + public.stderr)

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

    def test_w5_internet_disabled_preview_and_enable_terminology(self):
        self.assertEqual(
            self._run(self.frp_egress, ["create", "ubuntu-update", "--disabled"]).returncode, 0
        )
        self.assertEqual(
            self._run(
                self.frp_egress, ["add-source", "ubuntu-update", "10.10.20.0/24"]
            ).returncode,
            0,
        )
        dest = self._run(
            self.frp_egress,
            [
                "add-destination",
                "ubuntu-update",
                "archive.ubuntu.com",
                "443",
                "--protocol",
                "https",
            ],
        )
        self.assertEqual(dest.returncode, 0, dest.stderr)

        mod = self._load_egress_cli()
        cfg = mod.load_cfg()
        args = argparse.Namespace(
            source_ip="10.10.20.25",
            host="archive.ubuntu.com",
            port=443,
            protocol="https",
        )
        public_addr = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        from io import StringIO

        buf = StringIO()
        with mock.patch.object(mod.socket, "getaddrinfo", return_value=public_addr):
            with mock.patch("sys.stdout", buf):
                try:
                    mod.cmd_explain(cfg, args)
                except SystemExit as exc:
                    self.fail("disabled preview should not hard-fail policy: %s" % exc)
        out = buf.getvalue()
        self.assertIn("Profile state : Disabled", out)
        self.assertIn("Policy preview : ALLOW", out)
        self.assertIn("Current state  : BLOCKED", out)
        self.assertIn("set internet-profile ubuntu-update enabled", out)
        self.assertNotRegex(out, r"(?m)^Decision\s*:\s*ALLOW\s*$")
        self.assertNotIn("egress profile", out.lower())

        enable = self._run(self.frp_egress, ["enable", "ubuntu-update"])
        self.assertEqual(enable.returncode, 0, enable.stderr)
        self.assertIn("Internet Access profile enabled", enable.stdout)
        self.assertIn("Profile : ubuntu-update", enable.stdout)
        self.assertIn("Status  : Enabled", enable.stdout)
        self.assertNotIn("egress profile", enable.stdout.lower())

        buf2 = StringIO()
        with mock.patch.object(mod.socket, "getaddrinfo", return_value=public_addr):
            with mock.patch("sys.stdout", buf2):
                try:
                    mod.cmd_explain(cfg, args)
                except SystemExit as exc:
                    self.fail("enabled allow should succeed: %s" % exc)
        enabled_out = buf2.getvalue()
        self.assertIn("Profile state : Enabled", enabled_out)
        self.assertRegex(enabled_out, r"(?m)^Decision\s*:\s*ALLOW\s*$")
        self.assertNotIn("Policy preview : ALLOW", enabled_out)
        self.assertNotIn("Current state  : BLOCKED", enabled_out)

    def test_w6_fixed_tcp_product_output(self):
        self.assertEqual(
            self._run(self.frp_egress, ["create", "vendor-license", "--disabled"]).returncode, 0
        )
        self.assertEqual(
            self._run(
                self.frp_egress, ["add-source", "vendor-license", "10.10.30.0/24"]
            ).returncode,
            0,
        )
        self.assertEqual(
            self._run(
                self.frp_egress,
                [
                    "add-destination",
                    "vendor-license",
                    "license.example.com",
                    "27000",
                    "--protocol",
                    "tcp",
                ],
            ).returncode,
            0,
        )
        create = self._run(
            self.frp_egress,
            [
                "tcp",
                "create",
                "vendor-license",
                "--profile",
                "vendor-license",
                "--destination",
                "license.example.com:27000",
                "--listen-port",
                "6201",
            ],
        )
        self.assertEqual(create.returncode, 0, create.stderr)

        mod = self._load_egress_cli()
        cfg = mod.load_cfg()
        args = argparse.Namespace(selector="vendor-license", source_ip="10.10.30.25")
        public_addr = [(2, 1, 6, "", ("93.184.216.34", 0))]
        from io import StringIO

        buf = StringIO()
        with mock.patch.object(mod.socket, "getaddrinfo", return_value=public_addr):
            with mock.patch("sys.stdout", buf):
                try:
                    mod.cmd_tcp_explain(cfg, args)
                except SystemExit as exc:
                    self.fail("disabled fixed-tcp preview should not fail: %s" % exc)
        out = buf.getvalue()
        self.assertIn("Fixed TCP Check", out)
        self.assertIn("Status      : Disabled", out)
        self.assertIn("Policy preview : ALLOW", out)
        self.assertIn("Current state  : BLOCKED", out)
        self.assertIn("set fixed-tcp vendor-license enabled", out)
        self.assertNotRegex(out, r"(?m)^Decision\s*:\s*ALLOW\s*$")
        for leak in ("Mode: PREVIEW", "Relay ID", "Profile ID", "PROFILE_MATCH"):
            self.assertNotIn(leak, out)

        dns_fail = self._run(
            self.frp_egress,
            [
                "add-destination",
                "vendor-license",
                "no-such-host.invalid",
                "27001",
                "--protocol",
                "tcp",
            ],
        )
        self.assertEqual(dns_fail.returncode, 0, dns_fail.stderr)
        create2 = self._run(
            self.frp_egress,
            [
                "tcp",
                "create",
                "vendor-dns-fail",
                "--profile",
                "vendor-license",
                "--destination",
                "no-such-host.invalid:27001",
                "--listen-port",
                "6202",
            ],
        )
        self.assertEqual(create2.returncode, 0, create2.stderr)
        explained = self._run(
            self.frp_egress, ["tcp", "explain", "vendor-dns-fail", "10.10.30.25"]
        )
        self.assertNotEqual(explained.returncode, 0)
        dns_out = explained.stdout + explained.stderr
        self.assertIn("Fixed TCP Check", dns_out)
        self.assertIn("Status      : Disabled", dns_out)
        self.assertIn("DNS safety     : FAIL", dns_out)
        self.assertIn("Current state  : NOT READY", dns_out)
        self.assertIn("could not be resolved", dns_out.lower())
        for leak in ("Mode: PREVIEW", "Relay ID", "Profile ID", "PROFILE_MATCH"):
            self.assertNotIn(leak, dns_out)

    def test_onboarding_missing_enrollments_dir_product_error(self):
        incomplete = self.root / "etc/drlink/config.json"
        incomplete.write_text(
            json.dumps({"public_host": "203.0.113.10", "public_ip": "203.0.113.10"}) + "\n",
            encoding="utf-8",
        )
        proc = self._run(self.frp_create_client, [])
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
