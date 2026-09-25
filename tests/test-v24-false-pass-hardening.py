#!/usr/bin/env python3
"""Hardening tests that fail on the START_HEAD false-PASS behaviors."""
from __future__ import annotations

import io
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane
import drlink_v24 as v24
import drlink_v24_ai_identity as ai_id
import frp_cli_catalog as catalog


class FalsePassHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-fpass-")
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ.pop("DRLINK_SERVER_REACHABLE", None)
        os.environ.pop("DRLINK_OAUTH_AUTHORIZATION_CODE", None)
        os.environ.pop("DRLINK_OAUTH_CLIENT_SECRET", None)
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

    def tearDown(self):
        self.plane.close()
        for k in (
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_CONFIRM",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_SERVER_REACHABLE",
            "DRLINK_OAUTH_AUTHORIZATION_CODE",
            "DRLINK_OAUTH_CLIENT_SECRET",
        ):
            os.environ.pop(k, None)

    def test_auth_code_production_never_self_approves(self):
        import ast

        tree = ast.parse(Path(ROOT, "lib/drlink_v24_ai_identity.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "verify_authorization_code":
                calls = [
                    n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", "")
                    for n in ast.walk(node)
                    if isinstance(n, (ast.Name, ast.Attribute))
                ]
                self.assertNotIn("approve_oauth_pending", calls)
                break
        else:
            self.fail("verify_authorization_code not found")

    def test_AUTH_CODE_WITHOUT_EXTERNAL_APPROVAL_not_verified(self):
        self.plane.set_ai_principal("claude", enabled=True)
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_authorization_code(self.plane, "claude")
        status = str(self.plane.get_principal("claude")["credential_status"]).lower()
        self.assertNotEqual(status, "verified")

    def test_CLIENT_CREDS_WITHOUT_PROVEN_CREDENTIAL_not_verified(self):
        self.plane.set_ai_principal("custom-ai", enabled=True)
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_client_credentials(self.plane, "custom-ai", client_secret=None)
        status = str(self.plane.get_principal("custom-ai")["credential_status"]).lower()
        self.assertNotEqual(status, "verified")
        import ast

        tree = ast.parse(Path(ROOT, "lib/drlink_v24_ai_identity.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "verify_client_credentials":
                names = []
                for n in ast.walk(node):
                    if isinstance(n, ast.Attribute):
                        names.append(n.attr)
                    elif isinstance(n, ast.Name):
                        names.append(n.id)
                self.assertNotIn("rotate_ai_credential", names)
                break

    def test_AI_IDENTITY_CANCEL_REV_AFTER_equals_before(self):
        from drlink_v24_wizard import ScriptedIO, set_wizard_io
        import drlink_control_cli as cli
        import io
        from contextlib import redirect_stdout

        rev_before = self.plane.current_revision()
        set_wizard_io(ScriptedIO(["1", "cancel"]))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "ai-identity", "claude"], root=self.tmp, plane=self.plane)
        set_wizard_io(None)
        self.assertEqual(rc, 0)
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertIsNone(self.plane.get_principal("claude"))
        self.assertIn("No changes were applied", out.getvalue())

    def test_AGENT_WITH_NO_SERVER_REACHABLE_false(self):
        agent = tempfile.mkdtemp(prefix="drlink-agent-f4-")
        Path(agent, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(agent, "etc/frp/client-state.json").write_text(
            '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"ubuntu-prod","label":"ubuntu-prod"}\n',
            encoding="utf-8",
        )
        Path(agent, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        Path(agent, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
        plane = ControlPlane(agent)
        try:
            os.environ.pop("DRLINK_SERVER_REACHABLE", None)
            self.assertFalse(v24.detect_server_reachable(plane, agent))
            # Local SQLite SELECT 1 must not imply reachability.
            plane.conn.execute("SELECT 1").fetchone()
            self.assertFalse(v24.detect_server_reachable(plane, agent))
        finally:
            plane.close()

    def test_help_workflows_has_no_obsolete_grammar(self):
        text = catalog.workflow_help("server") + "\n" + catalog.workflow_help("client")
        forbidden = [
            "set client",
            "show clients",
            "published-service",
            "Managed Endpoint",
            "Service Preset",
            "set object",
            "action allow",
            "ordered first-match",
            "default DENY",
            "AI Principal",
            "ai-principal",
            "client-group",
        ]
        bad = [tok for tok in forbidden if tok in text]
        self.assertEqual(bad, [], "obsolete workflow grammar: %s" % bad)
        self.assertIn("Connect a Managed Host", text)
        self.assertIn("set remote-service", catalog.workflow_help("client"))
        self.assertIn("Remote Access BLACKLIST", text)
        self.assertIn("Internet Access WHITELIST", text)
        self.assertIn("AI Access lifecycle", text)
        self.assertIn("ConfigurationBundle", text)

    def test_agent_menu_system_hierarchy_parity(self):
        root = catalog.navigation_entries("client")
        labels = [e[1] for e in root]
        self.assertEqual(
            labels,
            ["Remote Services", "Agent", "Configuration", "System", "Help", "Exit"],
        )
        system = catalog.navigation_entries("client.system")
        sys_labels = [e[1] for e in system if e[1] != "Back"]
        self.assertIn("Status", sys_labels)
        self.assertIn("Diagnostics", sys_labels)
        self.assertIn("Support Bundle", sys_labels)
        self.assertIn("Version Information", sys_labels)
        self.assertIn("Updates", sys_labels)
        self.assertIn("Uninstall Data Relay Link", sys_labels)
        # Lifecycle stays under Agent, not System. Show Agent is the read-only
        # identity/runtime view added with the v2.4 Agent Host UX closure.
        agent = catalog.navigation_entries("client.agent")
        agent_labels = [e[1] for e in agent if e[1] != "Back"]
        self.assertEqual(
            agent_labels, ["Show Agent", "Pause", "Resume", "Restart", "Autostart"]
        )
        # No competing root Status/Diagnostics outside System.
        self.assertNotIn("Status", labels)
        self.assertNotIn("Diagnostics", labels)

    def test_public_catalog_omits_legacy_nouns(self):
        legacy = {
            "client-group",
            "client-groups",
            "ai-principal",
            "ai-principals",
            "published-service",
            "published-services",
            "managed-endpoint",
            "managed-endpoints",
            "service-preset",
            "service-presets",
        }
        bad = []
        for cmd in catalog.PUBLIC_COMMANDS:
            if any(tok in legacy for tok in cmd["path"]):
                bad.append(" ".join(cmd["path"]))
        self.assertEqual(bad, [], bad)

    def test_role_labels(self):
        self.assertEqual(v24.role_label("server"), "DRLink Server")
        self.assertEqual(v24.role_label("agent"), "Agent Host")
        self.assertNotEqual(v24.role_label("agent"), "Client")


class CatalogDestinationRevalidate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-cat-")
        Path(self.tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/frp/client-state.json").write_text(
            '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"ubuntu-prod","label":"ubuntu-prod"}\n',
            encoding="utf-8",
        )
        Path(self.tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        Path(self.tmp, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_network_object(self.plane, "db-prod", type="ip", value="198.51.100.20", oneshot=True)
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            (
                "network-object",
                "db-prod",
                '{"name":"db-prod","type":"host","values":["198.51.100.20"]}',
                now,
            ),
        )
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("service-object", "ssh", '{"name":"ssh","type":"tcp","port":22}', now),
        )

    def tearDown(self):
        self.plane.close()
        for k in ("DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION", "DRLINK_SERVER_REACHABLE"):
            os.environ.pop(k, None)

    def test_destination_missing_after_reconnect_degraded(self):
        v24.set_remote_service_agent(
            self.plane,
            "db",
            destination="db-prod",
            service="ssh",
            enabled=True,
            oneshot=True,
            root=self.tmp,
            server_reachable=True,
        )
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        obj = self.plane.get_object("db-prod")
        self.plane.conn.execute("DELETE FROM objects WHERE id = ?", (obj["id"],))
        self.plane.conn.execute(
            "DELETE FROM agent_object_catalog WHERE kind='network-object' AND name='db-prod'"
        )
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        v24.synchronize_agent_remote_services(self.plane, root=self.tmp)
        row = self.plane.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name='db'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("destination", (row["reason"] or "").lower())


class LifecycleConformanceHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-life-")
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

    def tearDown(self):
        self.plane.close()
        for k in (
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_CONFIRM",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_SERVER_REACHABLE",
        ):
            os.environ.pop(k, None)

    def test_network_object_edit_replaces_value_and_policy(self):
        v24.set_network_object(self.plane, "restore-check", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "ubuntu-prod", type="ip", value="198.51.100.8", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.ensure_policy_mode(self.plane, "remote", "whitelist", oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "restore-ssh",
            mode="whitelist",
            source="restore-check",
            destination="ubuntu-prod",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        old = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.8", "tcp", 22)
        self.assertEqual(str(old.get("action") or "").upper(), "ALLOW")
        v24.set_network_object(self.plane, "restore-check", type="ip", value="198.51.100.20", oneshot=True)
        obj = self.plane.get_object("restore-check")
        vals = self.plane._object_values(obj["id"])
        self.assertEqual(vals, ["198.51.100.20"])
        old_after = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.8", "tcp", 22)
        new_after = self.plane.evaluate_remote_access("198.51.100.20", "198.51.100.8", "tcp", 22)
        self.assertNotEqual(str(old_after.get("action") or "").upper(), "ALLOW")
        self.assertEqual(str(new_after.get("action") or "").upper(), "ALLOW")

    def test_relay_unreachable_stays_degraded_after_runtime_ok(self):
        agent = tempfile.mkdtemp(prefix="drlink-relay-")
        Path(agent, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(agent, "etc/frp/client-state.json").write_text(
            '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"ubuntu-prod","label":"ubuntu-prod"}\n',
            encoding="utf-8",
        )
        Path(agent, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        Path(agent, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
        plane = ControlPlane(agent)
        try:
            v24.ensure_v2_schema(plane.conn)
            v24.set_service_object(plane, "tcp-18191", type="tcp", port=18191, oneshot=True)
            v24.set_network_object(plane, "gptaudit-unreachable", type="ip", value="192.0.2.55", oneshot=True)
            now = v24.utc_now_iso()
            plane.conn.execute(
                "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
                ("service-object", "tcp-18191", '{"name":"tcp-18191","type":"tcp","port":18191}', now),
            )
            v24.set_remote_service_agent(
                plane,
                "audit-relay",
                destination="gptaudit-unreachable",
                service="tcp-18191",
                enabled=True,
                oneshot=True,
                root=agent,
                server_reachable=True,
            )
            row = plane.conn.execute(
                "SELECT * FROM agent_remote_services WHERE name='audit-relay'"
            ).fetchone()
            self.assertEqual(row["status"], "DEGRADED")
            self.assertIn("unreachable", (row["reason"] or "").lower())
            self.assertIsNotNone(row["endpoint_port"])
        finally:
            plane.close()

    def test_relay_catalog_ip_object_probes_value_not_name(self):
        agent = tempfile.mkdtemp(prefix="drlink-relay-ip-")
        Path(agent, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(agent, "etc/frp/client-state.json").write_text(
            '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"ubuntu-prod","label":"ubuntu-prod"}\n',
            encoding="utf-8",
        )
        Path(agent, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        Path(agent, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.listen(1)
        plane = ControlPlane(agent)
        try:
            v24.ensure_v2_schema(plane.conn)
            v24.set_service_object(plane, "tcp-loop", type="tcp", port=port, oneshot=True)
            now = v24.utc_now_iso()
            plane.conn.execute(
                "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
                ("service-object", "tcp-loop", '{"name":"tcp-loop","type":"tcp","port":%s}' % port, now),
            )
            plane.conn.execute(
                "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
                (
                    "network-object",
                    "loop-ip",
                    '{"name":"loop-ip","type":"ip","values":["127.0.0.1"]}',
                    now,
                ),
            )
            v24.set_remote_service_agent(
                plane,
                "catalog-relay",
                destination="loop-ip",
                service="tcp-loop",
                enabled=True,
                oneshot=True,
                root=agent,
                server_reachable=True,
            )
            row = plane.conn.execute(
                "SELECT * FROM agent_remote_services WHERE name='catalog-relay'"
            ).fetchone()
            self.assertNotIn("unreachable", (row["reason"] or "").lower())
            self.assertIsNotNone(row["endpoint_port"])
        finally:
            listener.close()
            plane.close()

    def test_disabled_remote_service_reason_not_runtime_pending(self):
        agent = tempfile.mkdtemp(prefix="drlink-dis-")
        Path(agent, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(agent, "etc/frp/client-state.json").write_text(
            '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"ubuntu-prod","label":"ubuntu-prod"}\n',
            encoding="utf-8",
        )
        Path(agent, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        Path(agent, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
        plane = ControlPlane(agent)
        try:
            v24.ensure_v2_schema(plane.conn)
            v24.set_service_object(plane, "ssh", type="tcp", port=22, oneshot=True)
            now = v24.utc_now_iso()
            plane.conn.execute(
                "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
                ("service-object", "ssh", '{"name":"ssh","type":"tcp","port":22}', now),
            )
            v24.set_remote_service_agent(
                plane,
                "ssh-off",
                destination="this-host",
                service="ssh",
                enabled=False,
                oneshot=True,
                root=agent,
                server_reachable=True,
            )
            row = plane.conn.execute(
                "SELECT * FROM agent_remote_services WHERE name='ssh-off'"
            ).fetchone()
            self.assertEqual(row["status"], "DISABLED")
            self.assertFalse(row["enabled"])
            self.assertNotIn("activation", (row["reason"] or "").lower())
            self.assertNotIn("pending", (row["reason"] or "").lower())
        finally:
            plane.close()

    def test_agent_bundle_invalid_second_resource_zero_partial(self):
        agent = tempfile.mkdtemp(prefix="drlink-bun-")
        Path(agent, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(agent, "etc/frp/client-state.json").write_text(
            '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"ubuntu-prod","label":"ubuntu-prod"}\n',
            encoding="utf-8",
        )
        Path(agent, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        Path(agent, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
        plane = ControlPlane(agent)
        try:
            v24.ensure_v2_schema(plane.conn)
            v24.set_service_object(plane, "ssh", type="tcp", port=22, oneshot=True)
            v24.set_service_object(plane, "dns-udp", type="udp", port=53, oneshot=True)
            now = v24.utc_now_iso()
            for name, typ, port in (("ssh", "tcp", 22), ("dns-udp", "udp", 53)):
                plane.conn.execute(
                    "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
                    ("service-object", name, '{"name":"%s","type":"%s","port":%d}' % (name, typ, port), now),
                )
            from drlink_v24_bundle import apply_v24_plan, prepare_v24_plan

            yaml_text = """configurationBundle:
  context: agent
  remoteServices:
    - name: keep-me
      destination: this-host
      service: ssh
      enabled: true
    - name: should-fail
      destination: this-host
      service: dns-udp
      enabled: true
"""
            plan = prepare_v24_plan(plane, yaml_text)
            with self.assertRaises(ControlPlaneError):
                apply_v24_plan(plane, plan, confirm=True)
            row = plane.conn.execute(
                "SELECT * FROM agent_remote_services WHERE name='keep-me'"
            ).fetchone()
            self.assertIsNone(row)
            fail = plane.conn.execute(
                "SELECT * FROM agent_remote_services WHERE name='should-fail'"
            ).fetchone()
            self.assertIsNone(fail)
        finally:
            plane.close()

    def test_sync_degraded_identifies_service(self):
        agent = tempfile.mkdtemp(prefix="drlink-sync-")
        Path(agent, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(agent, "etc/frp/client-state.json").write_text(
            '{"machine_id":"aabbccddeeff00112233445566778899","hostname":"ubuntu-prod","label":"ubuntu-prod"}\n',
            encoding="utf-8",
        )
        Path(agent, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        Path(agent, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
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
            result = v24.synchronize_agent_remote_services(plane, root=agent)
            self.assertEqual(result.get("status"), "DEGRADED")
            names = [a["name"] for a in (result.get("affected") or [])]
            self.assertIn("e2e-net", names)
            text = v24.format_synchronize_result(result)
            self.assertIn("e2e-net", text)
            self.assertIn("show remote-service e2e-net", text)
        finally:
            plane.close()

    def test_catalog_sync_failure_stays_degraded_without_reenrollment(self):
        import drlink_mgmt_sync as mgmt

        agent = tempfile.mkdtemp(prefix="drlink-sync-cat-")
        plane = ControlPlane(agent)
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        orig_live = mgmt.use_live_mgmt_path
        orig_sync = v24.sync_agent_catalog_from_server
        mgmt.use_live_mgmt_path = lambda root=None: True

        def _busy(*_args, **_kwargs):
            raise mgmt.MgmtSyncError(mgmt.AUTH_NONCE_BUSY)

        v24.sync_agent_catalog_from_server = _busy
        try:
            result = v24.synchronize_agent_remote_services(plane, root=agent)
            self.assertEqual(result.get("status"), "DEGRADED")
            detail = str(result.get("runtime_error") or "")
            self.assertIn("temporarily busy", detail)
            self.assertNotIn("may need to be re-enrolled", detail.lower())
            self.assertNotEqual(detail.strip(), mgmt.AUTH_REJECTED.strip())
        finally:
            mgmt.use_live_mgmt_path = orig_live
            v24.sync_agent_catalog_from_server = orig_sync
            os.environ.pop("DRLINK_SERVER_REACHABLE", None)
            os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
            plane.close()

    def test_role_discovery_agent_omits_server_topics(self):
        import frp_cli_catalog as catalog
        import frp_ctl_grammar as grammar

        help_text = catalog.root_help("client")
        self.assertNotIn("help managed-hosts", help_text)
        self.assertNotIn("help internet-access", help_text)
        self.assertIn("help remote-services", help_text)
        overview = catalog.concise_root("client")
        self.assertNotIn("Managed Hosts", overview)
        self.assertNotIn("policies", overview)
        result = grammar.match(["set", "internet-access", "should-fail"], role="client")
        self.assertEqual(result.get("status"), "role")
        self.assertIn("Internet Access policy", result.get("message") or "")
        self.assertIn("DRLink Server", result.get("message") or "")
        result2 = grammar.match(["set", "remote-service", "should-fail"], role="server")
        self.assertEqual(result2.get("status"), "role")
        self.assertIn("Agent Host", result2.get("message") or "")

    def test_wizard_cancel_from_first_step(self):
        from drlink_v24_wizard import ScriptedIO, set_wizard_io
        import drlink_control_cli as cli
        from contextlib import redirect_stdout
        import io

        set_wizard_io(ScriptedIO(["cancel"]))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "network-object", "gptaudit-wizcancel"], root=self.tmp, plane=self.plane)
        set_wizard_io(None)
        self.assertEqual(rc, 0)
        self.assertIn("No changes were applied", out.getvalue())
        self.assertIsNone(self.plane.get_object("gptaudit-wizcancel"))

    def test_wizard_ctrl_c_safe_cancel(self):
        from drlink_v24_wizard import WizardIO, set_wizard_io, run_wizard

        class InterruptIO(WizardIO):
            def write(self, text: str) -> None:
                return None

            def ask(self, prompt: str = "") -> str:
                raise KeyboardInterrupt()

        set_wizard_io(InterruptIO())
        out = io.StringIO()
        from contextlib import redirect_stdout

        with redirect_stdout(out):
            rc = run_wizard(self.plane, "network-object", "ctrlc-obj")
        set_wizard_io(None)
        self.assertEqual(rc, 0)
        self.assertIn("No changes were applied", out.getvalue())
        self.assertNotIn("Traceback", out.getvalue())
        self.assertIsNone(self.plane.get_object("ctrlc-obj"))

    def test_invalid_stdin_bundle_reports_no_changes(self):
        import drlink_control_cli as cli
        from contextlib import redirect_stdout, redirect_stderr

        path = Path(self.tmp, "bad-paste.yaml")
        path.write_text("this is not yaml\n", encoding="utf-8")
        out = io.StringIO()
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(out), redirect_stderr(err):
                cli.dispatch(["system", "apply", "configuration", str(path)], root=self.tmp, plane=self.plane)
        msg = str(ctx.exception)
        self.assertIn("No changes were applied", msg)
        self.assertIsNone(self.plane.get_object("this"))

    def test_state_paths_import(self):
        import frp_state_paths as paths

        names = [spec.path for spec in paths.STATE_PATHS]
        self.assertIn("var/lib/drlink/bootstrap", names)


if __name__ == "__main__":
    unittest.main()
