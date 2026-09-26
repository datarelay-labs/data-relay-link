#!/usr/bin/env python3
"""Public-dispatch regressions for Agent payload completeness and v2.4 AI policy CLI."""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
import drlink_control_cli as cli
import drlink_v24 as v24
from drlink_agent_payload import (
    AGENT_CRITICAL_LINEAGE_FILES,
    AGENT_LIB_FILES,
    agent_source_rels,
)
from drlink_v24_wizard import ScriptedIO, set_wizard_io
import frp_cli_catalog as catalog
import frp_ctl_grammar as grammar


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _agent_root(tmp: str, hostname: str = "ubuntu-prod") -> None:
    Path(tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/frp/client-state.json").write_text(
        '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"%s","label":"%s"}\n'
        % (hostname, hostname),
        encoding="utf-8",
    )
    Path(tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
    Path(tmp, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")


def _seed_policy_objects(plane: ControlPlane) -> None:
    v24.set_network_object(plane, "admin-source", type="ip", value="203.0.113.10", oneshot=True)
    v24.set_network_object(plane, "host1", type="ip", value="198.51.100.21", oneshot=True)
    v24.set_network_object(plane, "github", type="fqdn", value="example.com", oneshot=True)
    v24.set_service_object(plane, "test-http", type="tcp", port=8080, oneshot=True)
    v24.set_service_object(plane, "ssh", type="tcp", port=22, oneshot=True)
    v24.set_service_object(plane, "https", type="tcp", port=443, oneshot=True)


class AgentPayloadCanonical(unittest.TestCase):
    def test_AGENT_BUNDLE_REQUIRED_MODULE_SET(self):
        required = {
            "lib/drlink_control_cli.py",
            "lib/drlink_v24_cli.py",
            "lib/drlink_v24_bundle.py",
            "lib/drlink_v24_wizard.py",
            "lib/drlink_configuration_bundle.py",
            "lib/drlink_control_db.py",
            "lib/drlink_control_plane.py",
            "lib/drlink_mgmt_sync.py",
            "lib/drlink_v24.py",
            "lib/drlink_v24_runtime.py",
            "lib/frp_ctl_grammar.py",
            "lib/frp_cli_catalog.py",
            "lib/frp_cli_final_commands.json",
            "lib/frp_ctl_repl.py",
            "lib/drlink_agent_payload.py",
        }
        rels = set(agent_source_rels())
        missing = sorted(required - rels)
        self.assertEqual(missing, [])
        for rel in required:
            self.assertTrue((ROOT / rel).is_file(), rel)
        for name in AGENT_CRITICAL_LINEAGE_FILES:
            self.assertIn(name, AGENT_LIB_FILES)

    def test_build_bundles_uses_payload_ssot(self):
        text = (ROOT / "scripts/build-bundles.py").read_text(encoding="utf-8")
        self.assertIn("agent_source_rels", text)
        self.assertIn("from drlink_agent_payload import", text)


class AccessPolicyDispatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-ai-parity-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        _seed_policy_objects(self.plane)

    def tearDown(self):
        set_wizard_io(None)
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _run(self, *tokens):
        err = io.StringIO()
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.dispatch(list(tokens), root=self.tmp, plane=self.plane)
        return rc, out.getvalue(), err.getvalue()

    def _view(self, family: str, name: str) -> dict:
        row = self.plane._get_rule(family, name)
        self.assertIsNotNone(row, name)
        return self.plane._rule_view(row)

    def test_REMOTE_ACCESS_FIRST_RULE_MODE_REQUIRED(self):
        rev = self.plane.current_revision()
        rc, _out, err = self._run(
            "set",
            "remote-access",
            "first-rule",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "ssh",
            "enabled",
        )
        self.assertEqual(rc, 1)
        self.assertIn("mode blacklist|whitelist", err)
        self.assertIn("No changes were applied", err)
        self.assertIsNone(self.plane._get_rule("remote", "first-rule"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_INTERNET_ACCESS_FIRST_RULE_MODE_REQUIRED(self):
        rev = self.plane.current_revision()
        rc, _out, err = self._run(
            "set",
            "internet-access",
            "first-rule",
            "source",
            "host1",
            "destination",
            "github",
            "service",
            "https",
            "enabled",
        )
        self.assertEqual(rc, 1)
        self.assertIn("mode blacklist|whitelist", err)
        self.assertIsNone(self.plane._get_rule("internet", "first-rule"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_REMOTE_ACCESS_EXISTING_POLICY_ONESHOT_WITHOUT_MODE(self):
        rc, _out, err = self._run(
            "set",
            "remote-access",
            "seed-rule",
            "mode",
            "whitelist",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "ssh",
            "enabled",
        )
        self.assertEqual(rc, 0, err)
        rc, _out, err = self._run(
            "set",
            "remote-access",
            "second",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "ssh",
            "enabled",
        )
        self.assertEqual(rc, 0, err)
        view = self._view("remote", "second")
        self.assertEqual(view["sources"], ["admin-source"])
        self.assertEqual(view["destinations"], ["host1"])
        self.assertEqual(view["services"], ["tcp/22"])
        self.assertTrue(view["enabled"])
        self.assertEqual(view["action"], "match")
        self.assertEqual(v24.get_access_policy(self.plane, "remote")["mode"], "whitelist")

    def test_INTERNET_ACCESS_EXISTING_POLICY_ONESHOT_WITHOUT_MODE(self):
        rc, _out, err = self._run(
            "set",
            "internet-access",
            "seed-rule",
            "mode",
            "whitelist",
            "source",
            "host1",
            "destination",
            "github",
            "service",
            "https",
            "enabled",
        )
        self.assertEqual(rc, 0, err)
        rc, _out, err = self._run(
            "set",
            "internet-access",
            "second",
            "source",
            "host1",
            "destination",
            "github",
            "service",
            "https",
            "enabled",
        )
        self.assertEqual(rc, 0, err)
        view = self._view("internet", "second")
        self.assertEqual(view["sources"], ["host1"])
        self.assertEqual(view["destinations"], ["github"])
        self.assertEqual(view["services"], ["tcp/443"])
        self.assertTrue(view["enabled"])
        self.assertEqual(view["action"], "match")
        self.assertEqual(v24.get_access_policy(self.plane, "internet")["mode"], "whitelist")

    def test_REMOTE_ACCESS_NO_LEGACY_FALLTHROUGH(self):
        self._run(
            "set",
            "remote-access",
            "first",
            "mode",
            "whitelist",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "ssh",
            "enabled",
        )
        rc, _out, err = self._run(
            "set",
            "remote-access",
            "second",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "ssh",
            "enabled",
        )
        self.assertEqual(rc, 0, err)
        view = self._view("remote", "second")
        self.assertEqual(view["destinations"], ["host1"])
        self.assertEqual(view["services"], ["tcp/22"])
        self.assertTrue(view["enabled"])
        self.assertNotEqual(view["action"], "allow")

    def test_INTERNET_ACCESS_NO_LEGACY_FALLTHROUGH(self):
        self._run(
            "set",
            "internet-access",
            "first",
            "mode",
            "whitelist",
            "source",
            "host1",
            "destination",
            "github",
            "service",
            "https",
            "enabled",
        )
        rc, _out, err = self._run(
            "set",
            "internet-access",
            "second",
            "source",
            "host1",
            "destination",
            "github",
            "service",
            "https",
            "enabled",
        )
        self.assertEqual(rc, 0, err)
        view = self._view("internet", "second")
        self.assertEqual(view["destinations"], ["github"])
        self.assertTrue(view["enabled"])
        self.assertNotEqual(view["action"], "allow")

    def test_REMOTE_ACCESS_PARTIAL_EDIT(self):
        self._run(
            "set",
            "remote-access",
            "block-partner",
            "mode",
            "blacklist",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "ssh",
            "enabled",
        )
        rc, _out, err = self._run("set", "remote-access", "block-partner", "disabled")
        self.assertEqual(rc, 0, err)
        view = self._view("remote", "block-partner")
        self.assertFalse(view["enabled"])
        self.assertEqual(view["sources"], ["admin-source"])
        self.assertEqual(view["destinations"], ["host1"])
        self.assertEqual(view["services"], ["tcp/22"])
        rc, _out, err = self._run("set", "remote-access", "block-partner", "enabled")
        self.assertEqual(rc, 0, err)
        view = self._view("remote", "block-partner")
        self.assertTrue(view["enabled"])
        self.assertEqual(view["sources"], ["admin-source"])

    def test_INTERNET_ACCESS_PARTIAL_EDIT(self):
        self._run(
            "set",
            "internet-access",
            "github-https",
            "mode",
            "whitelist",
            "source",
            "host1",
            "destination",
            "github",
            "service",
            "https",
            "enabled",
        )
        rc, _out, err = self._run("set", "internet-access", "github-https", "disabled")
        self.assertEqual(rc, 0, err)
        view = self._view("internet", "github-https")
        self.assertFalse(view["enabled"])
        self.assertEqual(view["sources"], ["host1"])
        self.assertEqual(view["destinations"], ["github"])
        rc, _out, err = self._run("set", "internet-access", "github-https", "enabled")
        self.assertEqual(rc, 0, err)
        self.assertTrue(self._view("internet", "github-https")["enabled"])

    def test_INCOMPLETE_NEW_RULE_ZERO_MUTATION(self):
        rev = self.plane.current_revision()
        rc, _out, err = self._run(
            "set",
            "remote-access",
            "broken",
            "mode",
            "whitelist",
            "source",
            "admin-source",
            "enabled",
        )
        self.assertEqual(rc, 1)
        self.assertIn("No changes were applied", err)
        self.assertIsNone(self.plane._get_rule("remote", "broken"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_HUMAN_AI_BUNDLE_POLICY_PARITY(self):
        self._run(
            "set",
            "remote-access",
            "seed-rule",
            "mode",
            "whitelist",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "ssh",
            "enabled",
        )
        nos = [r["name"] for r in v24.list_network_objects(self.plane)]
        src_idx = str(nos.index("admin-source") + 1)
        dst_idx = str(nos.index("host1") + 1)
        svcs = [r["name"] for r in self.plane.conn.execute("SELECT name FROM service_objects ORDER BY name")]
        for builtin in ("ssh", "http", "https", "postgres"):
            if builtin not in svcs:
                svcs.append(builtin)
        svc_idx = str(svcs.index("test-http") + 1)
        set_wizard_io(ScriptedIO([src_idx, dst_idx, svc_idx, "y", "1"]))
        rc, _out, err = self._run("set", "remote-access", "human-rule")
        set_wizard_io(None)
        self.assertEqual(rc, 0, err)
        human = self._view("remote", "human-rule")

        rc, _out, err = self._run(
            "set",
            "remote-access",
            "ai-rule",
            "source",
            "admin-source",
            "destination",
            "host1",
            "service",
            "test-http",
            "enabled",
        )
        self.assertEqual(rc, 0, err)
        ai = self._view("remote", "ai-rule")

        bundle = """configurationBundle:
  context: server
  remoteAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: bundle-rule
        source: admin-source
        destination: host1
        service: test-http
        enabled: true
"""
        path = Path(self.tmp, "parity.yaml")
        path.write_text(bundle, encoding="utf-8")
        rc, _out, err = self._run("test", "configuration", str(path))
        self.assertEqual(rc, 0, err)
        rc, _out, err = self._run("system", "diff", "configuration", str(path))
        self.assertEqual(rc, 0, err)
        rc, _out, err = self._run("system", "apply", "configuration", str(path))
        self.assertEqual(rc, 0, err)
        bundle_view = self._view("remote", "bundle-rule")
        for view in (human, ai, bundle_view):
            self.assertEqual(view["sources"], ["admin-source"])
            self.assertEqual(view["destinations"], ["host1"])
            self.assertEqual(view["services"], ["tcp/8080"])
            self.assertTrue(view["enabled"])
            self.assertEqual(view["action"], "match")
        self.assertEqual(v24.get_access_policy(self.plane, "remote")["mode"], "whitelist")


class HelpAndSync(unittest.TestCase):
    def test_PUBLIC_HELP_EXAMPLES_EXECUTABLE(self):
        workflows = catalog.workflow_help("server")
        self.assertIn(
            "set internet-access github-https mode whitelist source ubuntu-prod destination github service https enabled",
            workflows,
        )
        failures = []
        for _title, steps, _note, scope in catalog.WORKFLOWS:
            role = "server" if scope == "server" else ("client" if scope == "agent" else "server")
            for step in steps:
                if "<" in step:
                    continue
                tokens = step.split()
                if tokens[:2] in (["set", "remote-access"], ["set", "internet-access"]) and "mode" in tokens:
                    if "enabled" not in tokens and "disabled" not in tokens:
                        failures.append("incomplete oneshot: %s" % step)
                result = grammar.match(tokens, role=role)
                if result.get("status") in ("unknown", "error"):
                    failures.append("%s -> %s" % (step, result))
        self.assertEqual(failures, [])

        tmp = tempfile.mkdtemp(prefix="drlink-help-ex-")
        _server_root(tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        plane = ControlPlane(tmp)
        try:
            v24.set_network_object(plane, "partner-office", type="ip", value="203.0.113.50", oneshot=True)
            v24.set_network_object(plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True)
            v24.set_network_object(plane, "github", type="fqdn", value="github.com", oneshot=True)
            v24.set_service_object(plane, "ssh", type="tcp", port=22, oneshot=True)
            v24.set_service_object(plane, "https", type="tcp", port=443, oneshot=True)
            err = io.StringIO()
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc1 = cli.dispatch(
                    "set remote-access block-partner mode blacklist source partner-office destination ubuntu-prod service ssh enabled".split(),
                    root=tmp,
                    plane=plane,
                )
                rc2 = cli.dispatch(
                    "set internet-access github-https mode whitelist source ubuntu-prod destination github service https enabled".split(),
                    root=tmp,
                    plane=plane,
                )
            self.assertEqual(rc1, 0, err.getvalue())
            self.assertEqual(rc2, 0, err.getvalue())
        finally:
            plane.close()
            os.environ.pop("DRLINK_CONFIRM", None)

    def test_SERVER_SYSTEM_HELP_ROLE_ACCURATE(self):
        text = catalog.domain_help("system", "server")
        self.assertIn("backup", text.lower())
        self.assertIn("system restore", text)
        rows = dict(catalog.root_rows("server"))
        self.assertIn("backup", rows["system"].lower())

    def test_AGENT_SYSTEM_HELP_ROLE_ACCURATE(self):
        text = catalog.domain_help("system", "client")
        self.assertNotIn("backup", text.lower())
        self.assertNotIn("restore", text.lower())
        self.assertIn("system synchronize", text)
        rows = dict(catalog.root_rows("client"))
        self.assertNotIn("backup", rows["system"].lower())
        self.assertIn("diagnostics", rows["system"].lower())
        resource = catalog.resource_help("system", "client")
        self.assertNotIn("backup", resource.lower())

    def test_SYNC_DEGRADED_ACTIONABLE(self):
        agent = tempfile.mkdtemp(prefix="drlink-sync-cli-")
        _agent_root(agent)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = agent
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        plane = ControlPlane(agent)
        try:
            v24.ensure_v2_schema(plane.conn)
            v24.set_service_object(plane, "postgres", type="tcp", port=5432, oneshot=True)
            now = v24.utc_now_iso()
            plane.conn.execute(
                "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
                ("service-object", "postgres", '{"name":"postgres","type":"tcp","port":5432}', now),
            )
            v24.set_remote_service_agent(
                plane,
                "e2e-net",
                destination="this-host",
                service="postgres",
                enabled=True,
                oneshot=True,
                root=agent,
                server_reachable=True,
            )
            plane.conn.execute("DELETE FROM service_objects WHERE name='postgres'")
            plane.conn.execute(
                "DELETE FROM agent_object_catalog WHERE kind='service-object' AND name='postgres'"
            )
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = cli.dispatch(["system", "synchronize"], root=agent, plane=plane)
            self.assertEqual(rc, 1, err.getvalue())
            text = out.getvalue()
            self.assertIn("Synchronization DEGRADED.", text)
            self.assertIn("Affected:", text)
            self.assertIn("e2e-net", text)
            self.assertIn("show remote-service e2e-net", text)
        finally:
            plane.close()
            os.environ.pop("DRLINK_SERVER_REACHABLE", None)


if __name__ == "__main__":
    unittest.main()
