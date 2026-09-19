#!/usr/bin/env python3
"""v2.4 final-closure regressions for public CLI + live management path."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ConfirmationRequired, ControlPlane
from drlink_configuration_bundle import BundleError
import drlink_v24 as v24
from drlink_v24_bundle import (
    apply_v24_plan,
    export_configuration_v24,
    format_v24_plan,
    prepare_v24_plan,
)
import drlink_mgmt_sync as mgmt
import frp_cli_catalog as catalog


DRLINK = str(ROOT / "tools" / "drlink")


class PublicGrammarClosure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-grammar-")
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"

    def tearDown(self):
        for k in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION"):
            os.environ.pop(k, None)

    def _cli(self, *args):
        return subprocess.run(
            [DRLINK, *args],
            capture_output=True,
            text=True,
            env={**os.environ},
        )

    def test_SERVER_OBJECT_ONESHOT_PUBLIC_GRAMMAR(self):
        r = self._cli("set", "network-object", "office-admin", "type", "ip", "value", "203.0.113.10")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self._cli("show", "network-object", "office-admin")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("office-admin", r.stdout)
        self.assertIn("203.0.113.10", r.stdout)
        r = self._cli("set", "service-object", "dns-udp", "type", "udp", "port", "53")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self._cli("set", "service-object", "legacy-db", "type", "fixed-tcp", "port", "1521")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_SERVER_GROUP_ONESHOT_PUBLIC_GRAMMAR(self):
        self._cli("set", "network-object", "a", "type", "ip", "value", "203.0.113.1")
        self._cli("set", "network-object", "b", "type", "ip", "value", "203.0.113.2")
        r = self._cli("set", "network-group", "g", "members", "a,b")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self._cli("set", "service-object", "http", "type", "tcp", "port", "80")
        self._cli("set", "service-object", "https", "type", "tcp", "port", "443")
        r = self._cli("set", "service-group", "web", "members", "http,https")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_PERMISSION_ONESHOT_PUBLIC_GRAMMAR(self):
        r = self._cli(
            "set",
            "permission-object",
            "read-only",
            "permissions",
            "host-info,process-read,file-read",
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self._cli("set", "permission-group", "operations", "members", "read-only")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_REMOTE_ACCESS_TEST_NAMED_GRAMMAR(self):
        self._cli("set", "network-object", "a", "type", "ip", "value", "198.51.100.10")
        self._cli("set", "network-object", "b", "type", "ip", "value", "198.51.100.20")
        r = self._cli(
            "test",
            "remote-access",
            "source",
            "a",
            "destination",
            "b",
            "service",
            "ssh",
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Remote Access Test", r.stdout)

    def test_INTERNET_ACCESS_TEST_NAMED_GRAMMAR(self):
        self._cli("set", "network-object", "a", "type", "ip", "value", "198.51.100.10")
        self._cli("set", "network-object", "b", "type", "fqdn", "value", "example.com")
        r = self._cli(
            "test",
            "internet-access",
            "source",
            "a",
            "destination",
            "b",
            "service",
            "https",
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Internet Access Test", r.stdout)

    def test_AI_ACCESS_TEST_NAMED_GRAMMAR(self):
        r = self._cli(
            "test",
            "ai-access",
            "source",
            "ai",
            "destination",
            "host",
            "permission",
            "read-only",
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("AI Access Test", r.stdout)

    def test_SYSTEM_UPDATE_AND_INFO_ALIASES_NOT_DEAD_ENDS(self):
        import frp_ctl_grammar as grammar

        cases = (
            (["system", "update", "engine"], "client", "update_frp"),
            (["update", "engine"], "client", "update_frp"),
            (["system", "update", "product"], "client", "update_project"),
            (["update", "product"], "client", "update_project"),
            (["system", "info"], "client", "show_info"),
            (["info"], "client", "show_info"),
            (["show", "info"], "client", "show_info"),
            (["pause"], "client", "client_pause"),
            (["stop"], "client", "client_pause"),
            (["unset", "managed-host", "x"], "server", "control_plane"),
            (["system", "revoke", "client", "x"], "server", "revoke_client"),
        )
        for tokens, role, action in cases:
            result = grammar.match(list(tokens), role=role)
            self.assertEqual(result.get("status"), "ok", tokens)
            self.assertEqual(result.get("action"), action, tokens)
        help_root = grammar.help_text([], "server")
        self.assertIn("help managed-hosts", help_root)
        self.assertNotIn("help clients", help_root)
        compat = grammar.help_text(["clients"], "server")
        self.assertIn("Managed Hosts", compat)


class BundleStrictClosure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-bundle-")
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

    def tearDown(self):
        self.plane.close()
        for k in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION"):
            os.environ.pop(k, None)

    def test_BUNDLE_UNKNOWN_FIELD_REJECT(self):
        with self.assertRaises(BundleError) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: server
  networkObjects:
    - name: src
      type: ip
      value: 198.51.100.10
      totallyUnknown: ignored
""",
            )
        self.assertIn("totallyUnknown", str(ctx.exception))

    def test_BUNDLE_INVALID_ENUM_REJECT(self):
        with self.assertRaises(BundleError) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: server
  serviceObjects:
    - name: x
      type: tcpx
      port: 22
""",
            )
        self.assertIn("tcpx", str(ctx.exception))

    def test_BUNDLE_MISSPELLED_ENABLED_REJECT(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="fqdn", value="example.com", oneshot=True)
        with self.assertRaises(BundleError) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: server
  internetAccess:
    mode: whitelist
    enforcement: enabledd
    rules:
      - name: allow-web
        source: src
        destination: dst
        service: https
        enabeld: false
""",
            )
        text = str(ctx.exception)
        self.assertTrue("enabledd" in text or "enabeld" in text)

    def test_BUNDLE_REQUIRED_FIELD_TEST_FAIL(self):
        with self.assertRaises(BundleError) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: server
  networkObjects:
    - name: broken
      type: ip
""",
            )
        self.assertIn("value", str(ctx.exception).lower())

    def test_BUNDLE_MISSING_REFERENCE_TEST_FAIL(self):
        with self.assertRaises(BundleError) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: server
  internetAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: allow-web
        source: office-prod
        destination: github
        service: https
        enabled: true
""",
            )
        self.assertIn("office-prod", str(ctx.exception))

    def test_SECURITY_IMPACT_DISABLE_ENFORCEMENT(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="fqdn", value="example.com", oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "block",
            mode="blacklist",
            source="src",
            destination="dst",
            service="https",
            enabled=True,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  internetAccess:
    mode: blacklist
    enforcement: disabled
""",
        )
        self.assertTrue(plan.security_impact)
        self.assertTrue(any("broadens" in x.lower() for x in plan.security_impact))

    def test_AI_ACCESS_DIFF_DESTINATION_PERMISSION(self):
        self.plane.set_ai_principal("automation-ai", enabled=True)
        v24.set_network_object(self.plane, "server-a", type="ip", value="203.0.113.1", oneshot=True)
        v24.set_network_object(self.plane, "server-b", type="ip", value="203.0.113.2", oneshot=True)
        v24.set_permission_object(self.plane, "read-only", permissions=["host-info"], oneshot=True)
        v24.set_permission_object(self.plane, "operator", permissions=["host-info", "process-read"], oneshot=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'automation-ai'"
        )
        self.plane.conn.commit()
        v24.set_ai_access_rule(
            self.plane,
            "allow",
            mode="whitelist",
            source="automation-ai",
            destination="server-a",
            permission="read-only",
            enabled=True,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  aiAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: allow
        source: automation-ai
        destination: server-b
        permission: operator
        enabled: true
""",
        )
        self.assertFalse(plan.no_change)
        ops = [c for c in plan.mutating_changes if c["kind"] == "ai-access-rule"]
        self.assertTrue(ops)

    def test_EXPORT_PERMISSION_GROUP_AND_AI_REFS(self):
        self.plane.set_ai_principal("automation-ai", enabled=True)
        v24.set_network_object(self.plane, "h1", type="ip", value="203.0.113.1", oneshot=True)
        v24.set_network_group(self.plane, "production-servers", members=["h1"], oneshot=True)
        v24.set_permission_object(self.plane, "read-only", permissions=["host-info"], oneshot=True)
        v24.set_permission_object(self.plane, "operator", permissions=["process-read"], oneshot=True)
        v24.set_permission_group(self.plane, "operations", members=["read-only", "operator"], oneshot=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'automation-ai'"
        )
        self.plane.conn.commit()
        v24.set_ai_access_rule(
            self.plane,
            "allow",
            mode="whitelist",
            source="automation-ai",
            destination="production-servers",
            permission="operations",
            enabled=True,
            oneshot=True,
        )
        exported = export_configuration_v24(self.plane)
        self.assertIn("permissionGroups:", exported)
        self.assertIn("operations", exported)
        self.assertIn("production-servers", exported)
        self.assertNotIn("destination: '-'", exported)
        self.assertNotIn("permission: '-'", exported)

    def test_SERVER_BUNDLE_FULL_IDEMPOTENCY(self):
        yaml_text = """configurationBundle:
  context: server
  networkObjects:
    - name: office
      type: ip
      value: 203.0.113.10
  networkGroups:
    - name: offices
      members: [office]
  serviceObjects:
    - name: web
      type: tcp
      port: 80
  serviceGroups:
    - name: web-services
      members: [web]
  permissionObjects:
    - name: read-only
      permissions: [host-info]
  permissionGroups:
    - name: ops
      members: [read-only]
"""
        apply_v24_plan(self.plane, prepare_v24_plan(self.plane, yaml_text), confirm=True)
        rev = self.plane.current_revision()
        plan2 = prepare_v24_plan(self.plane, yaml_text)
        self.assertTrue(plan2.no_change, format_v24_plan(plan2))
        apply_v24_plan(self.plane, plan2, confirm=True)
        self.assertEqual(self.plane.current_revision(), rev)


class LiveMgmtPathClosure(unittest.TestCase):
    def setUp(self):
        import frp_mgmt_auth as MGMT

        self.server_tmp = tempfile.mkdtemp(prefix="drlink-mgmt-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-mgmt-agt-")
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
        Path(self.agent_tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
        self.machine_id = "aabbccddeeff00112233445566778899"
        Path(self.agent_tmp, "etc/frp/client-state.json").write_text(
            '{"machine_id":"%s","hostname":"branch-gateway","label":"branch-gateway"}\n'
            % self.machine_id,
            encoding="utf-8",
        )
        key = Path(self.agent_tmp, "etc/frp/client-identity.key")
        pub = Path(self.agent_tmp, "etc/frp/client-identity.pub")
        MGMT.generate_keypair(key, pub)
        os.chmod(key, 0o600)
        mac = MGMT.new_mac_key()
        mac_path = Path(self.agent_tmp, "etc/frp/client-identity.mac")
        mac_path.write_text(mac, encoding="utf-8")
        os.chmod(mac_path, 0o600)
        Path(self.agent_tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_MGMT_TOKEN", None)
        os.environ.pop("DRLINK_SERVER_REACHABLE", None)
        os.environ.pop("DRLINK_MGMT_MODE", None)
        os.environ.pop("DRLINK_MGMT_INSECURE", None)
        self.server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(self.server.conn)
        self.agent = ControlPlane(self.agent_tmp)
        v24.ensure_v2_schema(self.agent.conn)
        v24.set_service_object(self.server, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_object(self.agent, "ssh", type="tcp", port=22, oneshot=True)
        self.server.upsert_client(
            self.machine_id, label="branch-gateway", hostname="branch-gateway"
        )
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(
            self.machine_id,
            pub.read_text(encoding="utf-8"),
            mac_key=mac,
            hostname="branch-gateway",
        )
        self.httpd, self.base_url, _ = mgmt.start_mgmt_server(
            self.server, verifier=self.verifier
        )
        os.environ["DRLINK_MGMT_URL"] = self.base_url
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base_url, encoding="utf-8"
        )

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.server.close()
        self.agent.close()
        for k in (
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_CONFIRM",
            "DRLINK_MGMT_TOKEN",
            "DRLINK_MGMT_URL",
            "DRLINK_MGMT_MODE",
            "DRLINK_SERVER_REACHABLE",
            "DRLINK_MGMT_INSECURE",
        ):
            os.environ.pop(k, None)

    def test_SERVER_ENDPOINT_ALLOCATOR_REAL_PATH(self):
        self.assertTrue(mgmt.use_live_mgmt_path(self.agent_tmp))
        result = v24.set_remote_service_agent(
            self.agent,
            "ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            oneshot=True,
            root=self.agent_tmp,
            server_reachable=True,
        )
        view = result["view"]
        self.assertEqual(view["status"], "HEALTHY")
        self.assertIsNotNone(view["endpoint_port"])
        # Server inventory under Managed Host
        client = self.server.get_client("aabbccddeeff00112233445566778899")
        self.assertIsNotNone(client)
        pub = self.server.conn.execute(
            "SELECT * FROM published_services WHERE client_id = ? AND name = 'ssh-access' AND released = 0",
            (client["id"],),
        ).fetchone()
        self.assertIsNotNone(pub)
        self.assertEqual(int(pub["public_port"]), int(view["endpoint_port"]))
        # Agent local DB must not own a competing reservation for that port unless mirrored intentionally
        local_res = self.agent.conn.execute(
            "SELECT 1 FROM port_reservations WHERE public_port = ? AND released = 0",
            (view["endpoint_port"],),
        ).fetchone()
        self.assertIsNone(local_res)

    def test_AGENT_CATALOG_REAL_SYNC(self):
        v24.set_network_object(self.server, "github", type="fqdn", value="github.com", oneshot=True)
        count = v24.sync_agent_catalog_from_server(self.agent, root=self.agent_tmp)
        self.assertGreater(count, 0)
        payload = v24._catalog_payload(self.agent, "network-object", "github")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["type"], "fqdn")


class HelpTerminologyClosure(unittest.TestCase):
    def test_AGENT_HELP_NO_CLIENT_NOUN(self):
        text = catalog.workflow_help("client")
        self.assertNotIn("Connect a new client", text)
        self.assertNotIn("system backup", text)
        self.assertNotIn("check-engine", text)
        self.assertIn("set remote-service", text)

    def test_ROLE_SPECIFIC_WORKFLOW_HELP(self):
        server = catalog.workflow_help("server")
        self.assertIn("system backup", server)
        self.assertIn("Remote Access", server)
        self.assertNotIn("Permission Objects — not legacy", server)


if __name__ == "__main__":
    unittest.main()
