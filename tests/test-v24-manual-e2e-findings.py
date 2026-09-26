#!/usr/bin/env python3
"""Targeted regressions for Rick's v2.4.0 manual E2E UX/runtime findings."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import drlink_v24 as v24  # noqa: E402
import frp_doctor as doctor  # noqa: E402
import frp_server_config as scfg  # noqa: E402
import frp_version_identity as ident  # noqa: E402
import frp_zero_touch as zt  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_v24_wizard import (  # noqa: E402
    ScriptedIO,
    _looks_like_drlink_command,
    run_service_object_wizard,
    set_wizard_io,
)


class PublicEndpointHostTests(unittest.TestCase):
    def test_prefers_public_hostname(self):
        host = scfg.resolve_public_endpoint_host(
            {"public_ip": "203.0.113.10", "public_hostname": "remote.xdr.ooo"}
        )
        self.assertEqual(host, "remote.xdr.ooo")

    def test_never_invents_drlink_local(self):
        host = scfg.resolve_public_endpoint_host({"public_ip": "203.0.113.10"})
        self.assertEqual(host, "203.0.113.10")
        self.assertNotEqual(host, "drlink.local")


class WizardWrongInputTests(unittest.TestCase):
    def test_detects_pasted_drlink_commands(self):
        self.assertTrue(_looks_like_drlink_command("show status"))
        self.assertTrue(
            _looks_like_drlink_command(
                "show status\nshow agent\nset remote-service ssh-access destination this-host service ssh enabled"
            )
        )
        self.assertFalse(_looks_like_drlink_command("2"))

    def test_service_object_wizard_excludes_udp(self):
        tmp = tempfile.mkdtemp(prefix="drlink-wiz-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        plane = ControlPlane(tmp)
        out: list[str] = []
        set_wizard_io(
            ScriptedIO(
                [
                    "1",  # SSH
                    "1",  # Apply
                ],
                out=out,
            )
        )
        try:
            rc = run_service_object_wizard(plane, "office-ssh")
        finally:
            set_wizard_io(None)
        self.assertEqual(rc, 0)
        text = "".join(out)
        self.assertNotIn("udp", text.lower().split("service object type", 1)[-1].split("select:", 1)[0])
        self.assertIn("SSH", text)
        self.assertIn("Custom TCP", text)
        self.assertIn("Fixed TCP", text)
        row = v24.get_service_object(plane, "office-ssh")
        self.assertEqual(row["type"], "tcp")
        self.assertEqual(int(row["port"]), 22)


class ZeroTouchCommandSecurityTests(unittest.TestCase):
    def test_short_url_preserves_ticket_and_https(self):
        ticket = "bt1." + ("a" * 16) + "." + ("b" * 64)
        cmd = zt.short_url_command("remote.xdr.ooo", ticket)
        self.assertEqual(cmd, "curl -fsSL https://remote.xdr.ooo/i/%s|sudo bash" % ticket)
        self.assertNotIn("mktemp", cmd)
        self.assertNotIn("--insecure", cmd)

    def test_pinned_ca_command_still_verifies_fingerprint(self):
        pkg = zt.encode_zero_touch_package(
            "https://203.0.113.10:6099/enroll",
            "a" * 64,
            "bt1." + ("c" * 16) + "." + ("d" * 64),
        )
        cmd = zt.pinned_ca_linux_command(
            "https://203.0.113.10:6099/agent/bootstrap-client.sh",
            "https://203.0.113.10:6099/enroll",
            "a" * 64,
            pkg,
        )
        self.assertIn("--insecure", cmd)
        self.assertIn("--cacert", cmd)
        self.assertIn("a" * 64, cmd)
        self.assertIn(pkg, cmd)

    def test_short_url_bootstrap_script_keeps_checksum_gate(self):
        ticket = "bt1." + ("e" * 16) + "." + ("f" * 64)
        script = zt.render_short_url_bootstrap_script(
            "https://203.0.113.10:6099/enroll",
            "ab" * 32,
            ticket,
            "https://example.test/dist/bootstrap-client.sh",
        )
        self.assertIn("SHA256", script)
        self.assertIn("mismatch", script)
        self.assertIn("zt1.", script)


class ShowAgentTests(unittest.TestCase):
    def test_format_show_agent_role(self):
        text = v24.format_show_agent(None)
        self.assertIn("Role: Agent Host", text)
        self.assertIn("Agent runtime", text)
        self.assertIn("show remote-services", text)


class DoctorPresentationTests(unittest.TestCase):
    def test_agent_host_terminology_in_detect_role(self):
        tmp = tempfile.mkdtemp(prefix="drlink-doc-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = Path(tmp)
        (root / "etc/frp").mkdir(parents=True)
        (root / "etc/frp/client-state.json").write_text(
            json.dumps({"schema_version": 1, "machine_id": "aabbccddeeff0011", "services": {}}) + "\n",
            encoding="utf-8",
        )
        (root / "etc/frp/frpc.toml").write_text("serverAddr = \"203.0.113.10\"\n", encoding="utf-8")
        (root / "etc/systemd/system").mkdir(parents=True)
        (root / "etc/systemd/system/drlink-client.service").write_text("[Unit]\n", encoding="utf-8")
        (root / "usr/local/bin").mkdir(parents=True)
        (root / "usr/local/bin/frpc").write_text("#!/bin/sh\n", encoding="utf-8")
        paths = doctor.Paths(str(root))
        info = doctor.detect_role(paths)
        self.assertEqual(info["label"], "Agent Host")

    def test_stale_server_markers_do_not_override_agent_role(self):
        tmp = tempfile.mkdtemp(prefix="drlink-doc-stale-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = Path(tmp)
        (root / "etc/frp").mkdir(parents=True)
        (root / "etc/frp/client-state.json").write_text(
            '{"schema_version":1,"services":{}}\n', encoding="utf-8"
        )
        (root / "usr/local/bin").mkdir(parents=True)
        (root / "usr/local/bin/frps").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "usr/local/lib/drlink").mkdir(parents=True)
        (root / "usr/local/lib/drlink/frp-create-client").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "etc/systemd/system").mkdir(parents=True)
        (root / "etc/systemd/system/drlink-server.service").write_text("[Unit]\n", encoding="utf-8")
        (root / "etc/systemd/system/drlink-allocator.service").write_text("[Unit]\n", encoding="utf-8")
        (root / "etc/systemd/system/drlink-client.service").write_text("[Unit]\n", encoding="utf-8")
        (root / "usr/local/bin/frpc").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "etc/frp/frps.toml").write_text("bindPort = 7000\n", encoding="utf-8")
        (root / "etc/frp/server_token").write_text("token-without-registry\n", encoding="utf-8")
        (root / "etc/drlink/pki").mkdir(parents=True)
        (root / "etc/drlink/pki/ca.crt").write_text("cert\n", encoding="utf-8")
        paths = doctor.Paths(str(root))
        info = doctor.detect_role(paths)
        self.assertEqual(info["role"], "client")
        self.assertEqual(info["label"], "Agent Host")
        self.assertNotIn(info["role"], ("dual", "server", "partial_server"))

        (root / "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
        (root / "etc/frp/frps.toml").write_text("bindPort = 7000\n", encoding="utf-8")
        dual = doctor.detect_role(doctor.Paths(str(root)))
        self.assertEqual(dual["role"], "dual")
        self.assertEqual(dual["label"], "DRLink Server + Agent Host")

        import frp_support_bundle as support

        (root / "etc/drlink/config.json").unlink()
        builder = support.BundleBuilder(root)
        stage = builder.collect()
        self.addCleanup(shutil.rmtree, stage, ignore_errors=True)
        meta = json.loads((stage / "meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["role"], "client")
        self.assertEqual(meta["role_label"], "Agent Host")

    def test_strong_evidence_not_file_counts(self):
        tmp = tempfile.mkdtemp(prefix="drlink-doc-strong-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = Path(tmp)
        (root / "etc/frp").mkdir(parents=True)
        (root / "usr/local/bin").mkdir(parents=True)
        (root / "etc/systemd/system").mkdir(parents=True)
        (root / "etc/frp/frpc.toml").write_text('serverAddr = "203.0.113.10"\n', encoding="utf-8")
        (root / "etc/frp/client-identity.key").write_text("fixture-key\n", encoding="utf-8")
        (root / "usr/local/bin/frps").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "etc/systemd/system/drlink-server.service").write_text("[Unit]\n", encoding="utf-8")
        (root / "etc/systemd/system/drlink-allocator.service").write_text("[Unit]\n", encoding="utf-8")
        info = doctor.detect_role(doctor.Paths(str(root)))
        self.assertEqual(info["role"], "client")
        self.assertEqual(info["label"], "Agent Host")

        (root / "etc/frp/server_token").write_text("token\n", encoding="utf-8")
        (root / "var/lib/drlink").mkdir(parents=True)
        (root / "var/lib/drlink/drlink.db").write_text("", encoding="utf-8")
        (root / "usr/local/bin/frpc").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "etc/systemd/system/drlink-client.service").write_text("[Unit]\n", encoding="utf-8")
        dual = doctor.detect_role(doctor.Paths(str(root)))
        self.assertEqual(dual["role"], "dual")
        self.assertEqual(dual["label"], "DRLink Server + Agent Host")

        (root / "etc/frp/frpc.toml").unlink()
        (root / "etc/frp/client-identity.key").unlink()
        server = doctor.detect_role(doctor.Paths(str(root)))
        self.assertEqual(server["role"], "server")
        self.assertEqual(server["label"], "DRLink Server")

        (root / "var/lib/drlink/drlink.db").unlink()
        (root / "var/lib/drlink/registry.json").write_text("{}\n", encoding="utf-8")
        via_registry = doctor.detect_role(doctor.Paths(str(root)))
        self.assertEqual(via_registry["role"], "server")
        self.assertEqual(via_registry["label"], "DRLink Server")

    def test_token_and_frps_toml_remnants_stay_agent(self):
        tmp = tempfile.mkdtemp(prefix="drlink-doc-weak-srv-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = Path(tmp)
        (root / "etc/frp").mkdir(parents=True)
        (root / "etc/systemd/system").mkdir(parents=True)
        (root / "etc/frp/client-state.json").write_text(
            '{"schema_version":1,"services":{}}\n', encoding="utf-8"
        )
        (root / "etc/systemd/system/drlink-client.service").write_text("[Unit]\n", encoding="utf-8")
        (root / "etc/frp/server_token").write_text("leftover-token\n", encoding="utf-8")
        (root / "etc/frp/frps.toml").write_text("bindPort = 7000\n", encoding="utf-8")
        info = doctor.detect_role(doctor.Paths(str(root)))
        self.assertEqual(info["role"], "client")
        self.assertEqual(info["label"], "Agent Host")
        self.assertNotIn(info["role"], ("dual", "server", "partial_server"))

    def test_development_display_identity(self):
        d = ident.derive_display_identity(
            project_version="2.4.0",
            channel="development",
            source_head="c2d1792dd5f75a1a69b56ae749633262eff2f4e5",
        )
        self.assertEqual(d["display_identity"], "2.4.0-dev+gc2d1792")

    def test_diagnostic_labels_not_truncated(self):
        class R:
            role_label = "Agent Host"
            confidence = "complete"
            project_version = "2.4.0"
            display_identity = "2.4.0-dev+gc2d1792"
            release_channel = "development"
            source_ref = "c2d1792dd5f75a1a69b56ae749633262eff2f4e5"
            source_head = "c2d1792dd5f75a1a69b56ae749633262eff2f4e5"
            frp_version = "0.71.0"
            pinned_frp = "0.71.0"
            bundle_sha256 = "not applicable"
            display = {}
            checks = [
                {
                    "id": "client_state_permissions",
                    "status": "FAIL",
                    "message": "bad",
                    "section": "state",
                    "recommendation": "sudo drlink system synchronize",
                    "detail": "",
                },
                {
                    "id": "frp_control_reachability",
                    "status": "WARN",
                    "message": "warn",
                    "section": "network",
                    "recommendation": "",
                    "detail": "",
                },
            ]

            def counts(self):
                return {"PASS": 0, "WARN": 1, "FAIL": 1, "ERROR": 0, "INFO": 0, "NOT_APPLICABLE": 0}

            def overall(self):
                return "FAIL"

            def recommended_actions(self):
                return ["sudo drlink system synchronize"]

        text = doctor.render_human(R())
        self.assertIn("client_state_permissions", text)
        self.assertIn("frp_control_reachability", text)
        self.assertNotIn("client_state_permi ", text)
        self.assertIn("Data Relay Link : 2.4.0-dev+gc2d1792", text)
        self.assertIn("Bundle SHA256   : not applicable", text)
        self.assertIn("sudo drlink system synchronize", text)


class RoleLabelTests(unittest.TestCase):
    def test_role_label_agent_host(self):
        self.assertEqual(v24.role_label("agent"), "Agent Host")


class BootstrapProgressTests(unittest.TestCase):
    def test_build_bundles_emits_progress_echo(self):
        src = (ROOT / "scripts" / "build-bundles.py").read_text(encoding="utf-8")
        self.assertIn('Downloading qualified Data Relay Link installer', src)
        self.assertIn('Installing Data Relay Link Server', src)
        self.assertIn('Installing Data Relay Link Agent Host', src)


class InstallerPromptContractTests(unittest.TestCase):
    def test_prompt_uses_readline_dash_e(self):
        src = (ROOT / "install-server.sh").read_text(encoding="utf-8")
        self.assertIn("read -e -r -p", src)
        self.assertIn("Public DNS hostname: not configured", src)
        self.assertIn("Public URL identity", src)


class UninstallReplExitTests(unittest.TestCase):
    def test_repl_exits_on_code_75(self):
        src = (ROOT / "lib" / "frp_ctl_repl.py").read_text(encoding="utf-8")
        self.assertIn("proc.returncode == 75", src)
        ctl = (ROOT / "tools" / "frpctl").read_text(encoding="utf-8")
        self.assertIn("return 75", ctl)
        self.assertIn("Exiting Data Relay Link.", ctl)


class DoctorRemediationParseTests(unittest.TestCase):
    def test_synchronize_parses_on_agent(self):
        from frp_ctl_grammar import match

        r = match(["system", "synchronize"], role="client")
        self.assertEqual(r.get("status"), "ok")


class ShowAgentGrammarTests(unittest.TestCase):
    def test_show_agent_is_public_on_client(self):
        from frp_ctl_grammar import match, _show_resources

        self.assertIn("agent", _show_resources("client"))
        r = match(["show", "agent"], role="client")
        self.assertEqual(r.get("status"), "ok")


class SshUsernameOptionalTests(unittest.TestCase):
    def test_allocator_accepts_ssh_without_user(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "allocator", ROOT / "server" / "frp-port-allocator.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        got = mod.normalize_service(
            {
                "id": "ssh",
                "name": "SSH",
                "protocol": "tcp",
                "preset": "ssh",
                "local_ip": "127.0.0.1",
                "local_port": 22,
            }
        )
        self.assertNotIn("ssh_user", got)
        text = (ROOT / "server" / "frp-port-allocator.py").read_text(encoding="utf-8")
        self.assertNotIn("if spec['preset'] == 'ssh':", text)
        self.assertIn("spec.get('ssh_user')", text)

    def test_access_info_uses_username_placeholder(self):
        src = (ROOT / "lib" / "frp-client-common.sh").read_text(encoding="utf-8")
        self.assertIn("or '<username>'", src)
        self.assertIn("connection-example metadata", src)
        self.assertNotIn("SSH user (required)", src)


class ZeroTouchActivationContractTests(unittest.TestCase):
    def test_install_client_activates_and_reconciles(self):
        src = (ROOT / "install-client.sh").read_text(encoding="utf-8")
        self.assertIn("activate_enrolled_services_as_remote_services", src)
        self.assertIn("Reconcile frpc.toml from the committed client-state", src)
        self.assertIn("Remote Service not fully activated", src)
        self.assertNotIn("The requested remote service is connected.", src)

    def test_activate_helper_reuses_enrolled_port(self):
        src = (ROOT / "lib" / "drlink_v24.py").read_text(encoding="utf-8")
        self.assertIn("def activate_enrolled_services_as_remote_services", src)
        self.assertIn("enrolled_port", src)
        self.assertIn("Prefer the enrolled public port", src)


class InstalledBackupHelperTests(unittest.TestCase):
    def test_sibling_lib_dir_is_found_before_sbin(self):
        import drlink_control_cli as cli

        tmp = Path(tempfile.mkdtemp(prefix="drlink-dr-tool-"))
        try:
            lib = tmp / "lib"
            lib.mkdir()
            tool = lib / "frp-restore"
            tool.write_text("#!/bin/sh\n", encoding="utf-8")
            found = next(
                path
                for path in cli._server_dr_tool_candidates(
                    "frp-restore", lib / "drlink_control_cli.py"
                )
                if path.is_file()
            )
            self.assertEqual(found, tool)
        finally:
            shutil.rmtree(tmp)


class EgressSnapshotDiagnosisTests(unittest.TestCase):
    def test_locked_parent_is_called_out(self):
        tmp = Path(tempfile.mkdtemp(prefix="drlink-run-"))
        try:
            parent = tmp / "run" / "drlink"
            parent.mkdir(parents=True)
            os.chmod(parent, 0o700)
            detail, remedy = doctor.egress_snapshot_missing_diagnosis(parent)
            self.assertIn("0700", detail)
            self.assertIn("traversal", detail)
            self.assertIn("drlink-egress", remedy)
        finally:
            shutil.rmtree(tmp)

    def test_traversable_parent_keeps_generic_detail(self):
        tmp = Path(tempfile.mkdtemp(prefix="drlink-run-"))
        try:
            parent = tmp / "run" / "drlink"
            parent.mkdir(parents=True)
            os.chmod(parent, 0o755)
            detail, _remedy = doctor.egress_snapshot_missing_diagnosis(parent)
            self.assertEqual(detail, "/run/drlink/egress/effective.json")
        finally:
            shutil.rmtree(tmp)


class EnrollmentHostnameContractTests(unittest.TestCase):
    def test_installer_selects_enrollment_identity(self):
        src = (ROOT / "install-server.sh").read_text(encoding="utf-8")
        self.assertIn("FRP_ENROLLMENT_PUBLIC_HOST", src)
        self.assertIn("Public URL identity", src)
        self.assertIn("frp_format_https_url \"$enrollment_host\"", src)


if __name__ == "__main__":
    unittest.main()
