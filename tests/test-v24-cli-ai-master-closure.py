#!/usr/bin/env python3
"""Closure tests for v2.4 CLI/AI Master remaining gaps (wizards, AI OAuth, agent offline, rollback)."""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane
import drlink_control_cli as cli
import drlink_v24 as v24
from drlink_v24_bundle import apply_v24_plan, prepare_v24_plan
from drlink_v24_wizard import ScriptedIO, set_wizard_io
import drlink_v24_ai_identity as ai_id


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _agent_root(tmp: str, hostname: str = "ubuntu-prod") -> None:
    Path(tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/frp/client-state.json").write_text(
        '{\n  "machine_id": "aabbccddeeff00112233445566778899",\n  "hostname": "%s",\n  "label": "%s"\n}\n'
        % (hostname, hostname),
        encoding="utf-8",
    )
    Path(tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
    Path(tmp, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
    # Remove server role marker if present
    cfg = Path(tmp, "etc/drlink/config.json")
    if cfg.exists():
        cfg.unlink()


class WizardCancelAtomicty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-wiz-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        self.plane.set_object_type("ubuntu-prod", "host")
        self.plane.set_object_value("ubuntu-prod", "198.51.100.10")
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)

    def tearDown(self):
        set_wizard_io(None)
        self.plane.close()
        for k in ("DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION", "DRLINK_WIZARD_ANSWERS", "DRLINK_FAULT_ACTIVATION", "DRLINK_FAULT_ROLLBACK", "DRLINK_SERVER_REACHABLE", "DRLINK_OAUTH_FORCE_FAIL"):
            os.environ.pop(k, None)

    def _rev(self):
        return self.plane.current_revision()

    def test_create_wizard_cancel_no_mutation(self):
        rev = self._rev()
        # type ip, invalid then valid value, review cancel
        set_wizard_io(ScriptedIO(["1", "10.10.999.0", "203.0.113.10", "3"]))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "network-object", "office-admin"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc, 0)
        self.assertIn("No changes were applied", out.getvalue())
        self.assertIsNone(self.plane.get_object("office-admin"))
        self.assertEqual(self._rev(), rev)

    def test_rule_wizard_inline_object_cancel(self):
        rev = self._rev()
        # Policy mode blacklist, source = create network object, then cancel at review
        # Choices: mode=1 blacklist; source=+create NO (index of + Create Network Object);
        # name, type ip, value; destination=ubuntu-prod; service=ssh; enabled=Y; review=Cancel
        nos = [r["name"] for r in v24.list_network_objects(self.plane)]
        # options: existing hosts + create buttons. ubuntu-prod is first.
        # Source step: pick + Create Network Object — after listing existing
        create_idx = str(len(nos) + 1)  # first allow_create
        answers = [
            "1",  # blacklist
            create_idx,  # + Create Network Object
            "office-admin",
            "1",  # ip
            "203.0.113.10",
            "1",  # destination ubuntu-prod (first)
            "1",  # service ssh
            "y",  # enabled
            "3",  # cancel
        ]
        set_wizard_io(ScriptedIO(answers))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "remote-access", "office-ssh"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc, 0)
        self.assertIn("No changes were applied", out.getvalue())
        self.assertIsNone(self.plane.get_object("office-admin"))
        self.assertIsNone(self.plane._get_rule("remote", "office-ssh"))
        pol = v24.get_access_policy(self.plane, "remote")
        self.assertIsNone(pol["mode"])
        self.assertEqual(self._rev(), rev)

    def test_create_wizard_apply_persists(self):
        set_wizard_io(ScriptedIO(["1", "203.0.113.10", "1"]))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "network-object", "office-admin"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc, 0)
        self.assertIsNotNone(self.plane.get_object("office-admin"))

    def test_edit_wizard_cancel(self):
        v24.set_network_object(self.plane, "office-admin", type="ip", value="203.0.113.10", oneshot=True)
        rev = self._rev()
        set_wizard_io(ScriptedIO(["1", "203.0.113.11", "3"]))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "network-object", "office-admin"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc, 0)
        vals = self.plane._object_values(self.plane.get_object("office-admin")["id"])
        self.assertEqual(vals[0], "203.0.113.10")
        self.assertEqual(self._rev(), rev)

    def test_invalid_input_remains_on_step(self):
        set_wizard_io(ScriptedIO(["2", "10.10.999.0/24", "10.10.0.0/16", "1"]))
        out_lines = []
        io_obj = ScriptedIO(["2", "10.10.999.0/24", "10.10.0.0/16", "1"], out=out_lines)
        set_wizard_io(io_obj)
        with redirect_stdout(io.StringIO()):
            rc = cli.dispatch(["set", "network-object", "corp"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc, 0)
        blob = "".join(out_lines)
        self.assertIn("Invalid CIDR", blob)
        obj = self.plane.get_object("corp")
        self.assertIsNotNone(obj)
        self.assertEqual(self.plane._object_values(obj["id"])[0], "10.10.0.0/16")


class AIIdentityOAuth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-ai-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

    def tearDown(self):
        set_wizard_io(None)
        self.plane.close()
        for k in (
            "DRLINK_CONFIRM",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_OAUTH_FORCE_FAIL",
            "DRLINK_OAUTH_CLIENT_SECRET",
            "DRLINK_OAUTH_AUTHORIZATION_CODE",
        ):
            os.environ.pop(k, None)

    def _external_approve(self, session: dict, principal_name: str = "claude") -> str:
        """TEST-only external authorization-server actor."""
        # Immediate code delivery (not the production browser-continue path).
        approved = self.plane.approve_oauth_pending(
            session["pending_id"],
            principal_name=principal_name,
            retain_for_browser=False,
        )
        return approved["code"]

    def test_authorization_code_without_external_approval_not_verified(self):
        self.plane.set_ai_principal("claude", enabled=True)
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_authorization_code(self.plane, "claude")
        row = self.plane.get_principal("claude")
        self.assertNotEqual(str(row["credential_status"]).lower(), "verified")

    def test_authorization_code_success_with_external_approval(self):
        self.plane.set_ai_principal("claude", enabled=True)
        session = ai_id.begin_authorization_code(self.plane, "claude")
        code = self._external_approve(session, "claude")
        result = ai_id.verify_authorization_code(
            self.plane,
            "claude",
            authorization_code=code,
            code_verifier=session["verifier"],
            state=session["state"],
            redirect_uri=session["redirect_uri"],
            resource=session["resource"],
        )
        self.assertEqual(result["auth"], "VERIFIED")
        row = self.plane.get_principal("claude")
        self.assertEqual(str(row["credential_status"]).lower(), "verified")
        dumped = str(result)
        self.assertNotIn("drauth_", dumped)
        self.assertNotIn("drc_", dumped)

    def test_authorization_code_wrong_pkce_fails(self):
        self.plane.set_ai_principal("claude", enabled=True)
        session = ai_id.begin_authorization_code(self.plane, "claude")
        code = self._external_approve(session, "claude")
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_authorization_code(
                self.plane,
                "claude",
                authorization_code=code,
                code_verifier="wrong-verifier-value-not-pkce",
                redirect_uri=session["redirect_uri"],
                resource=session["resource"],
            )

    def test_authorization_code_replay_fails(self):
        self.plane.set_ai_principal("claude", enabled=True)
        session = ai_id.begin_authorization_code(self.plane, "claude")
        code = self._external_approve(session, "claude")
        ai_id.verify_authorization_code(
            self.plane,
            "claude",
            authorization_code=code,
            code_verifier=session["verifier"],
            redirect_uri=session["redirect_uri"],
            resource=session["resource"],
        )
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_authorization_code(
                self.plane,
                "claude",
                authorization_code=code,
                code_verifier=session["verifier"],
                redirect_uri=session["redirect_uri"],
                resource=session["resource"],
            )

    def test_authorization_code_failure(self):
        self.plane.set_ai_principal("claude", enabled=True)
        with self.assertRaises(ControlPlaneError) as ctx:
            ai_id.verify_authorization_code(self.plane, "claude", force_fail=True)
        self.assertIn("verification failed", str(ctx.exception).lower())
        row = self.plane.get_principal("claude")
        self.assertNotEqual(str(row["credential_status"]).lower(), "verified")

    def test_client_credentials_without_secret_not_verified(self):
        self.plane.set_ai_principal("custom-ai", enabled=True)
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_client_credentials(self.plane, "custom-ai", client_secret=None)
        row = self.plane.get_principal("custom-ai")
        self.assertNotEqual(str(row["credential_status"]).lower(), "verified")

    def test_client_credentials_success(self):
        self.plane.set_ai_principal("custom-ai", enabled=True)
        issued = self.plane.rotate_ai_credential("custom-ai")
        secret = issued["token"]
        result = ai_id.verify_client_credentials(self.plane, "custom-ai", client_secret=secret)
        self.assertEqual(result["auth"], "VERIFIED")
        self.assertNotIn("token", result)
        self.assertNotIn(secret, str(result))

    def test_client_credentials_wrong_secret(self):
        self.plane.set_ai_principal("custom-ai", enabled=True)
        self.plane.rotate_ai_credential("custom-ai")
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_client_credentials(
                self.plane, "custom-ai", client_secret="wrong-secret", force_fail=False
            )

    def test_client_credentials_other_client_secret(self):
        self.plane.set_ai_principal("custom-ai", enabled=True)
        self.plane.set_ai_principal("other-ai", enabled=True)
        other = self.plane.rotate_ai_credential("other-ai")
        with self.assertRaises(ControlPlaneError):
            ai_id.verify_client_credentials(
                self.plane, "custom-ai", client_secret=other["token"], force_fail=False
            )

    def test_display_name_alone_not_verified(self):
        self.plane.set_ai_principal("claude", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'pending' WHERE name = 'claude'"
        )
        ev = v24.evaluate_ai_access_v24(
            self.plane, identity="claude", destination="ubuntu-prod", permission="host-info"
        )
        self.assertEqual(ev["auth"], "UNAUTHENTICATED")
        self.assertEqual(ev["result"], "DENY")

    def test_ai_access_requires_verified_even_when_enforcement_disabled(self):
        self.plane.set_ai_principal("claude", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'pending' WHERE name = 'claude'"
        )
        v24.set_network_object(self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_permission_object(self.plane, "read-only", permissions=["host-info"], oneshot=True)
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_ai_access_rule(
                self.plane,
                "r1",
                mode="whitelist",
                source="claude",
                destination="ubuntu-prod",
                permission="read-only",
                enabled=True,
                oneshot=True,
            )
        self.assertIn("VERIFIED", str(ctx.exception))
        session = ai_id.begin_authorization_code(self.plane, "claude")
        code = self._external_approve(session, "claude")
        ai_id.verify_authorization_code(
            self.plane,
            "claude",
            authorization_code=code,
            code_verifier=session["verifier"],
            redirect_uri=session["redirect_uri"],
            resource=session["resource"],
        )
        v24.set_ai_access_rule(
            self.plane,
            "r1",
            mode="whitelist",
            source="claude",
            destination="ubuntu-prod",
            permission="read-only",
            enabled=True,
            oneshot=True,
        )
        v24.set_policy_enforcement(self.plane, "ai", False, confirm=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'pending' WHERE name = 'claude'"
        )
        ev = v24.evaluate_ai_access_v24(
            self.plane, identity="claude", destination="ubuntu-prod", permission="command-exec"
        )
        self.assertEqual(ev["result"], "DENY")
        self.assertEqual(ev["auth"], "UNAUTHENTICATED")

    def test_wizard_ai_identity_auth_code(self):
        class ExternalApproveIO(ScriptedIO):
            def __init__(self, plane, name, answers):
                super().__init__(answers)
                self.plane = plane
                self.name = name

            def ask(self, prompt):
                text = str(prompt or "")
                if "Authorization code" in text:
                    row = self.plane.conn.execute(
                        "SELECT id FROM ai_oauth_pending ORDER BY created_at DESC"
                    ).fetchone()
                    approved = self.plane.approve_oauth_pending(
                        row["id"], principal_name=self.name, retain_for_browser=False
                    )
                    return approved["code"]
                return super().ask(prompt)

        set_wizard_io(ExternalApproveIO(self.plane, "claude", ["1", "y"]))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "ai-identity", "claude"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc, 0)
        self.assertIn("VERIFIED", out.getvalue())
        self.assertEqual(str(self.plane.get_principal("claude")["credential_status"]).lower(), "verified")
        self.assertNotIn("drauth_", out.getvalue())

    def test_wizard_ai_identity_cancel_zero_revision(self):
        rev_before = self.plane.current_revision()
        set_wizard_io(ScriptedIO(["1", "cancel"]))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(["set", "ai-identity", "claude"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc, 0)
        self.assertIn("No changes were applied", out.getvalue())
        self.assertIsNone(self.plane.get_principal("claude"))
        self.assertEqual(self.plane.current_revision(), rev_before)
        oauth_clients = self.plane.conn.execute(
            "SELECT COUNT(*) AS c FROM ai_oauth_clients WHERE client_id = 'claude'"
        ).fetchone()["c"]
        self.assertEqual(oauth_clients, 0)


class AgentBundleOfflineLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-agent-")
        _agent_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        # Seed synchronized catalog + service object
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_object(self.plane, "postgres", type="tcp", port=5432, oneshot=True)
        v24.set_service_object(self.plane, "dns-udp", type="udp", port=53, oneshot=True)
        now = v24.utc_now_iso() if hasattr(v24, "utc_now_iso") else __import__("drlink_control_db", fromlist=["utc_now_iso"]).utc_now_iso()
        for name, typ, port in (("ssh", "tcp", 22), ("postgres", "tcp", 5432)):
            self.plane.conn.execute(
                "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
                ("service-object", name, '{"name":"%s","type":"%s","port":%d}' % (name, typ, port), now),
            )

    def tearDown(self):
        self.plane.close()
        for k in ("DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION", "DRLINK_SERVER_REACHABLE"):
            os.environ.pop(k, None)

    def _apply_bundle(self, yaml_text: str):
        plan = prepare_v24_plan(self.plane, yaml_text)
        return apply_v24_plan(self.plane, plan, confirm=True)

    def test_D1_online_create(self):
        yaml_text = """configurationBundle:
  context: agent
  remoteServices:
    - name: ssh
      destination: this-host
      service: ssh
      enabled: true
"""
        self._apply_bundle(yaml_text)
        row = self.plane.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name = 'ssh'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "HEALTHY")
        self.assertIsNotNone(row["endpoint_port"])

    def test_D2_offline_edit_preserves_endpoint(self):
        self._apply_bundle(
            """configurationBundle:
  context: agent
  remoteServices:
    - name: ssh
      destination: this-host
      service: ssh
      enabled: true
"""
        )
        row = self.plane.conn.execute("SELECT * FROM agent_remote_services WHERE name='ssh'").fetchone()
        port = row["endpoint_port"]
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        # Real offline edit (desired-state change) — not a no-op reapply.
        v24.set_remote_service_agent(
            self.plane,
            "ssh",
            destination="this-host",
            service="ssh",
            enabled=True,
            oneshot=True,
            root=self.tmp,
            server_reachable=False,
        )
        row2 = self.plane.conn.execute("SELECT * FROM agent_remote_services WHERE name='ssh'").fetchone()
        self.assertEqual(row2["endpoint_port"], port)
        self.assertEqual(row2["status"], "DEGRADED")
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        v24.synchronize_agent_remote_services(self.plane, root=self.tmp)
        row3 = self.plane.conn.execute("SELECT * FROM agent_remote_services WHERE name='ssh'").fetchone()
        self.assertEqual(row3["endpoint_port"], port)
        self.assertEqual(row3["status"], "HEALTHY")

    def test_D3_new_while_offline_pending(self):
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        self._apply_bundle(
            """configurationBundle:
  context: agent
  remoteServices:
    - name: db
      destination: this-host
      service: postgres
      enabled: true
"""
        )
        row = self.plane.conn.execute("SELECT * FROM agent_remote_services WHERE name='db'").fetchone()
        self.assertEqual(row["status"], "DEGRADED")
        self.assertTrue(row["pending_allocation"] or row["endpoint_port"] is None)
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        v24.synchronize_agent_remote_services(self.plane, root=self.tmp)
        row2 = self.plane.conn.execute("SELECT * FROM agent_remote_services WHERE name='db'").fetchone()
        self.assertEqual(row2["status"], "HEALTHY")
        self.assertIsNotNone(row2["endpoint_port"])

    def test_D3b_self_machine_id_bypass_not_external_inventory(self):
        """Self destination_client_id == local machine_id is valid without MH inventory;
        any other bound client_id still requires inventory (fail-closed)."""
        self_id = "aabbccddeeff00112233445566778899"
        external_id = "00112233445566778899aabbccddeeff"
        self.assertIsNone(
            v24._destination_dependency_status(
                self.plane,
                "this-host",
                root=self.tmp,
                destination_client_id=self_id,
            )
        )
        reason = v24._destination_dependency_status(
            self.plane,
            "database-prod",
            root=self.tmp,
            destination_client_id=external_id,
        )
        self.assertIsNotNone(reason)
        self.assertIn("missing or invalid after reconnect", reason)
        self.assertIn(external_id[:12], reason)

    def test_D4_offline_delete(self):
        self._apply_bundle(
            """configurationBundle:
  context: agent
  remoteServices:
    - name: ssh
      destination: this-host
      service: ssh
      enabled: true
"""
        )
        port = self.plane.conn.execute(
            "SELECT endpoint_port FROM agent_remote_services WHERE name='ssh'"
        ).fetchone()["endpoint_port"]
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        self._apply_bundle(
            """configurationBundle:
  context: agent
  remoteServices:
    - name: ssh
      state: absent
"""
        )
        # Local desired gone or tombstoned
        row = self.plane.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name='ssh'"
        ).fetchone()
        self.assertTrue(row is None or row["delete_pending"] == 1)
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        v24.synchronize_agent_remote_services(self.plane, root=self.tmp)
        row2 = self.plane.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name='ssh' AND delete_pending = 0"
        ).fetchone()
        self.assertIsNone(row2)
        # Port released — should be reusable
        used = {
            r[0]
            for r in self.plane.conn.execute(
                "SELECT public_port FROM port_reservations WHERE released = 0 AND public_port = ?",
                (port,),
            )
        }
        self.assertEqual(used, set())

    def test_D5_dependency_missing_degraded(self):
        self._apply_bundle(
            """configurationBundle:
  context: agent
  remoteServices:
    - name: db
      destination: this-host
      service: postgres
      enabled: true
"""
        )
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        # Server removes dependency while agent offline — simulate by deleting local service object + catalog
        sobj = v24.get_service_object(self.plane, "postgres")
        self.plane.conn.execute("DELETE FROM service_objects WHERE id = ?", (sobj["id"],))
        self.plane.conn.execute(
            "DELETE FROM agent_object_catalog WHERE kind='service-object' AND name='postgres'"
        )
        os.environ["DRLINK_SERVER_REACHABLE"] = "1"
        v24.synchronize_agent_remote_services(self.plane, root=self.tmp)
        row = self.plane.conn.execute("SELECT * FROM agent_remote_services WHERE name='db'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "DEGRADED")
        self.assertIn("missing", (row["reason"] or "").lower())

    def test_D6_udp_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self._apply_bundle(
                """configurationBundle:
  context: agent
  remoteServices:
    - name: dns
      destination: this-host
      service: dns-udp
      enabled: true
"""
            )
        self.assertIn("UDP", str(ctx.exception))
        self.assertIsNone(
            self.plane.conn.execute("SELECT 1 FROM agent_remote_services WHERE name='dns'").fetchone()
        )

    def test_D7_cross_pool_rejected(self):
        v24.set_service_object(self.plane, "legacy-db", type="fixed-tcp", port=1521, oneshot=True)
        self._apply_bundle(
            """configurationBundle:
  context: agent
  remoteServices:
    - name: app
      destination: this-host
      service: ssh
      enabled: true
"""
        )
        with self.assertRaises(Exception) as ctx:
            v24.set_remote_service_agent(
                self.plane,
                "app",
                destination="this-host",
                service="legacy-db",
                enabled=True,
                oneshot=True,
                root=self.tmp,
                server_reachable=True,
            )
        self.assertIn("Fixed TCP", str(ctx.exception))

    def test_server_sections_rejected_on_agent(self):
        with self.assertRaises(Exception) as ctx:
            prepare_v24_plan(
                self.plane,
                """configurationBundle:
  context: agent
  networkObjects:
    - name: x
      type: ip
      value: 1.2.3.4
  remoteServices:
    - name: ssh
      destination: this-host
      service: ssh
      enabled: true
""",
            )
        self.assertIn("Server section", str(ctx.exception))


class ActivationRollback(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-rb-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        # Activation enabled for these tests
        os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        v24.set_network_object(self.plane, "office", type="ip", value="203.0.113.10", oneshot=True)

    def tearDown(self):
        self.plane.close()
        for k in ("DRLINK_CONFIRM", "DRLINK_FAULT_ACTIVATION", "DRLINK_FAULT_ROLLBACK", "DRLINK_SKIP_ACTIVATION"):
            os.environ.pop(k, None)

    def test_E1_activation_failure_restores(self):
        rev_before = self.plane.current_revision()
        office = self.plane.get_object("office")
        self.assertIsNotNone(office)
        os.environ["DRLINK_FAULT_ACTIVATION"] = "1"
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_network_object(self.plane, "partner", type="ip", value="203.0.113.50", oneshot=True)
        msg = str(ctx.exception)
        self.assertIn("Previous configuration was restored", msg)
        self.assertNotIn("No changes were applied", msg)
        self.assertIsNone(self.plane.get_object("partner"))
        self.assertIsNotNone(self.plane.get_object("office"))
        self.assertEqual(self.plane.current_revision(), rev_before)

    def test_E2_rollback_failure_truthful(self):
        os.environ["DRLINK_FAULT_ACTIVATION"] = "1"
        os.environ["DRLINK_FAULT_ROLLBACK"] = "1"
        with self.assertRaises(ControlPlaneError) as ctx:
            v24.set_network_object(self.plane, "partner", type="ip", value="203.0.113.50", oneshot=True)
        msg = str(ctx.exception)
        self.assertIn("rollback was not fully successful", msg)
        self.assertIn("system diagnostics", msg)
        self.assertNotIn("No changes were applied", msg)
        self.assertNotIn("Previous configuration was restored", msg)


class PublicCliDispatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-pub-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

    def tearDown(self):
        set_wizard_io(None)
        self.plane.close()
        for k in ("DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION"):
            os.environ.pop(k, None)

    def test_public_dispatch_oneshot_and_wizard(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.dispatch(
                ["set", "network-object", "office-admin", "type", "ip", "value", "203.0.113.10"],
                root=self.tmp,
                plane=self.plane,
            )
        self.assertEqual(rc, 0)
        set_wizard_io(ScriptedIO(["1", "203.0.113.20", "1"]))
        with redirect_stdout(io.StringIO()):
            rc2 = cli.dispatch(["set", "network-object", "vpn-admin"], root=self.tmp, plane=self.plane)
        self.assertEqual(rc2, 0)
        self.assertIsNotNone(self.plane.get_object("vpn-admin"))


if __name__ == "__main__":
    unittest.main()
