#!/usr/bin/env python3
"""Priority 8C: strict one-shot parsing + existing-resource partial-edit parity."""
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

from drlink_control_plane import ControlPlane, ControlPlaneError
import drlink_control_cli as cli
import drlink_mgmt_sync as mgmt
import drlink_v24 as v24
import frp_cli_catalog as catalog
import frp_mgmt_auth as MGMT

AGENT_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
AGENT_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _agent_root(tmp: str, machine_id: str = AGENT_A, hostname: str = "agent-a") -> Path:
    Path(tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/frp/client-state.json").write_text(
        '{"machine_id":"%s","hostname":"%s","label":"%s"}\n' % (machine_id, hostname, hostname),
        encoding="utf-8",
    )
    key = Path(tmp, "etc/frp/client-identity.key")
    pub = Path(tmp, "etc/frp/client-identity.pub")
    MGMT.generate_keypair(key, pub)
    os.chmod(key, 0o600)
    mac = MGMT.new_mac_key()
    mac_path = Path(tmp, "etc/frp/client-identity.mac")
    mac_path.write_text(mac, encoding="utf-8")
    os.chmod(mac_path, 0o600)
    Path(tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
    return pub


class OneshotStrictPartialEdit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-p8c-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION"):
            os.environ.pop(key, None)

    def _run(self, *tokens):
        buf = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = cli.dispatch(list(tokens), root=self.tmp, plane=self.plane)
        return rc, buf.getvalue(), err.getvalue()

    def _object_values(self, name: str) -> list[str]:
        obj = self.plane.get_object(name)
        if obj is None:
            return []
        return self.plane._object_values(obj["id"])

    def test_network_object_unknown_field_rejected(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        rev = self.plane.current_revision()
        rc, _out, err = self._run("set", "network-object", "src", "valu", "198.51.100.11")
        self.assertEqual(rc, 1)
        self.assertIn("does not accept 'valu'", err)
        self.assertIn("No changes were applied.", err)
        self.assertEqual(self._object_values("src"), ["198.51.100.10"])
        self.assertEqual(self.plane.current_revision(), rev)

    def test_network_object_duplicate_value_rejected(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        rev = self.plane.current_revision()
        rc, _out, err = self._run(
            "set", "network-object", "src", "value", "198.51.100.11", "value", "198.51.100.12"
        )
        self.assertEqual(rc, 1)
        self.assertIn("Duplicate field 'value'", err)
        self.assertEqual(self._object_values("src"), ["198.51.100.10"])
        self.assertEqual(self.plane.current_revision(), rev)

    def test_network_object_value_only_preserves_type(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        rc, out, err = self._run("set", "network-object", "src", "value", "198.51.100.99")
        self.assertEqual(rc, 0, err)
        self.assertIn("update", out)
        obj = self.plane.get_object("src")
        self.assertEqual(obj["type"], "host")
        self.assertEqual(self._object_values("src"), ["198.51.100.99"])

    def test_network_object_new_incomplete_rejected(self):
        rev = self.plane.current_revision()
        rc, _out, err = self._run("set", "network-object", "new-src", "value", "198.51.100.10")
        self.assertEqual(rc, 1)
        self.assertIn("incomplete", err.lower())
        self.assertIsNone(self.plane.get_object("new-src"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_service_object_unknown_and_duplicate_rejected(self):
        v24.set_service_object(self.plane, "web", type="tcp", port=8080, oneshot=True)
        rev = self.plane.current_revision()
        rc1, _o1, err1 = self._run("set", "service-object", "web", "prt", "8443")
        self.assertEqual(rc1, 1)
        self.assertIn("does not accept 'prt'", err1)
        rc2, _o2, err2 = self._run(
            "set", "service-object", "web", "port", "8443", "port", "9443"
        )
        self.assertEqual(rc2, 1)
        self.assertIn("Duplicate field 'port'", err2)
        row = v24.get_service_object(self.plane, "web")
        self.assertEqual(int(row["port"]), 8080)
        self.assertEqual(self.plane.current_revision(), rev)

    def test_service_object_port_only_preserves_type_and_policy(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.50", oneshot=True)
        v24.set_service_object(self.plane, "web", type="tcp", port=8080, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-web",
            mode="whitelist",
            source="src",
            destination="dst",
            service="web",
            enabled=True,
            oneshot=True,
        )
        before_new = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.50", "tcp", 8443)
        self.assertEqual(str(before_new.get("action") or before_new.get("effective")).upper(), "DENY")

        rc, _out, err = self._run("set", "service-object", "web", "port", "8443")
        self.assertEqual(rc, 0, err)
        row = v24.get_service_object(self.plane, "web")
        self.assertEqual(row["type"], "tcp")
        self.assertEqual(int(row["port"]), 8443)
        after_old = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.50", "tcp", 8080)
        after_new = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.50", "tcp", 8443)
        self.assertEqual(str(after_old.get("action") or after_old.get("effective")).upper(), "DENY")
        self.assertEqual(str(after_new.get("action") or after_new.get("effective")).upper(), "ALLOW")

    def test_service_object_new_incomplete_rejected(self):
        rev = self.plane.current_revision()
        rc, _out, err = self._run("set", "service-object", "new-web", "port", "8080")
        self.assertEqual(rc, 1)
        self.assertIn("incomplete", err.lower())
        self.assertIsNone(v24.get_service_object(self.plane, "new-web"))
        self.assertEqual(self.plane.current_revision(), rev)

    def test_remote_and_internet_duplicate_fields_rejected(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.50", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "r1",
            mode="whitelist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        rev = self.plane.current_revision()
        rc_r, _o_r, err_r = self._run(
            "set",
            "remote-access",
            "r1",
            "source",
            "src",
            "source",
            "src",
        )
        self.assertEqual(rc_r, 1)
        self.assertIn("Duplicate field 'source'", err_r)
        rc_i, _o_i, err_i = self._run(
            "set",
            "internet-access",
            "i1",
            "mode",
            "whitelist",
            "source",
            "src",
            "destination",
            "dst",
            "service",
            "ssh",
            "destination",
            "dst",
            "enabled",
        )
        self.assertEqual(rc_i, 1)
        self.assertIn("Duplicate field 'destination'", err_i)
        self.assertEqual(self.plane.current_revision(), rev)

    def test_ai_access_enable_disable_and_strict_fields(self):
        self.plane.set_ai_principal("bot", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'bot'"
        )
        self.plane.conn.commit()
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.8", oneshot=True)
        v24.set_permission_object(self.plane, "read-only", permissions=["host-info"], oneshot=True)
        v24.set_ai_access_rule(
            self.plane,
            "allow-bot",
            mode="whitelist",
            source="bot",
            destination="dst",
            permission="read-only",
            enabled=True,
            oneshot=True,
        )
        before = self.plane.conn.execute(
            "SELECT enabled, source_identity_id, destination_ref_id, permission_ref_id "
            "FROM ai_policy_rules WHERE name = 'allow-bot'"
        ).fetchone()
        rc, _out, err = self._run("set", "ai-access", "allow-bot", "disabled")
        self.assertEqual(rc, 0, err)
        after = self.plane.conn.execute(
            "SELECT enabled, source_identity_id, destination_ref_id, permission_ref_id "
            "FROM ai_policy_rules WHERE name = 'allow-bot'"
        ).fetchone()
        self.assertEqual(int(after["enabled"]), 0)
        self.assertEqual(after["source_identity_id"], before["source_identity_id"])
        self.assertEqual(after["destination_ref_id"], before["destination_ref_id"])
        self.assertEqual(after["permission_ref_id"], before["permission_ref_id"])

        rev = self.plane.current_revision()
        rc_new, _o_new, err_new = self._run("set", "ai-access", "missing-rule", "enabled")
        self.assertEqual(rc_new, 1)
        self.assertIn("incomplete", err_new.lower())
        rc_unk, _o_unk, err_unk = self._run(
            "set", "ai-access", "allow-bot", "permisison", "read-only"
        )
        self.assertEqual(rc_unk, 1)
        self.assertIn("does not accept 'permisison'", err_unk)
        rc_dup, _o_dup, err_dup = self._run(
            "set", "ai-access", "allow-bot", "source", "bot", "source", "bot"
        )
        self.assertEqual(rc_dup, 1)
        self.assertIn("Duplicate field 'source'", err_dup)
        self.assertEqual(self.plane.current_revision(), rev)

    def test_permission_and_group_unknown_duplicate_rejected(self):
        v24.set_permission_object(self.plane, "read-only", permissions=["host-info"], oneshot=True)
        v24.set_permission_group(self.plane, "ops", members=["read-only"], oneshot=True)
        v24.set_network_object(self.plane, "a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_group(self.plane, "office", members=["a"], oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_group(self.plane, "admin", members=["ssh"], oneshot=True)
        rev = self.plane.current_revision()

        rc_po, _o_po, err_po = self._run(
            "set", "permission-object", "read-only", "permisions", "host-info"
        )
        self.assertEqual(rc_po, 1)
        self.assertIn("does not accept 'permisions'", err_po)

        rc_ng, _o_ng, err_ng = self._run(
            "set", "network-group", "office", "member", "a"
        )
        self.assertEqual(rc_ng, 1)
        self.assertIn("does not accept 'member'", err_ng)

        rc_sg, _o_sg, err_sg = self._run(
            "set", "service-group", "admin", "members", "ssh", "members", "ssh"
        )
        self.assertEqual(rc_sg, 1)
        self.assertIn("Duplicate field 'members'", err_sg)

        rc_pg, _o_pg, err_pg = self._run(
            "set", "permission-group", "ops", "members", "read-only", "extra", "x"
        )
        self.assertEqual(rc_pg, 1)
        self.assertIn("does not accept 'extra'", err_pg)
        self.assertEqual(self.plane.current_revision(), rev)

    def test_contradictory_enabled_disabled_rejected(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.50", oneshot=True)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        rev = self.plane.current_revision()
        rc, _out, err = self._run(
            "set",
            "remote-access",
            "r1",
            "mode",
            "whitelist",
            "source",
            "src",
            "destination",
            "dst",
            "service",
            "ssh",
            "enabled",
            "disabled",
        )
        self.assertEqual(rc, 1)
        self.assertIn("Contradictory or duplicate enabled/disabled", err)
        self.assertEqual(self.plane.current_revision(), rev)

    def test_help_mentions_partial_edit_forms(self):
        text_no = catalog.domain_help("network-objects", role="server")
        text_so = catalog.domain_help("service-objects", role="server")
        text_ai = catalog.domain_help("ai-access", role="server")
        self.assertIn("set network-object <NAME> value <VALUE>", text_no)
        self.assertIn("set service-object <NAME> port <PORT>", text_so)
        self.assertIn("set ai-access <RULE> enabled|disabled", text_ai)


class RemoteServiceStrictPartialEdit(unittest.TestCase):
    def setUp(self):
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-p8c-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-p8c-agt-")
        _server_root(self.server_tmp)
        pub = _agent_root(self.agent_tmp)
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.agent_tmp
        self.server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(self.server.conn)
        self.agent = ControlPlane(self.agent_tmp)
        v24.ensure_v2_schema(self.agent.conn)
        for plane in (self.server, self.agent):
            v24.set_service_object(plane, "ssh", type="tcp", port=22, oneshot=True)
            v24.set_service_object(plane, "https", type="tcp", port=443, oneshot=True)
        self.server.upsert_client(
            AGENT_A,
            label="agent-a",
            hostname="agent-a",
            addresses=[{"address": "10.0.0.10", "active": True}],
        )
        self.server.upsert_client(
            AGENT_B,
            label="database-prod",
            hostname="db-b.internal",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        self.verifier = mgmt.InMemoryMgmtVerifier()
        mac = Path(self.agent_tmp, "etc/frp/client-identity.mac").read_text(encoding="utf-8")
        self.verifier.enroll(
            AGENT_A, pub.read_text(encoding="utf-8"), mac_key=mac, hostname="agent-a"
        )
        self.httpd, self.base_url, _ = mgmt.start_mgmt_server(
            self.server, verifier=self.verifier
        )
        os.environ["DRLINK_MGMT_URL"] = self.base_url
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base_url, encoding="utf-8"
        )
        catalog_payload = mgmt.build_catalog_payload(self.server)
        mgmt.apply_catalog_to_agent(self.agent, catalog_payload)

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.agent.close()
        self.server.close()
        for key in (
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_CONFIRM",
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_MGMT_URL",
            "DRLINK_MGMT_TOKEN",
            "DRLINK_SERVER_REACHABLE",
        ):
            os.environ.pop(key, None)

    def _run_agent(self, *tokens):
        buf = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = cli.dispatch(list(tokens), root=self.agent_tmp, plane=self.agent)
        return rc, buf.getvalue(), err.getvalue()

    def _agent_row(self, name: str):
        return self.agent.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()

    def test_remote_service_unknown_duplicate_rejected_no_mutation(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination="database-prod",
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        before = self._agent_row("db-via-a")
        rev = self.agent.current_revision()
        rc_unk, _o_unk, err_unk = self._run_agent(
            "set", "remote-service", "db-via-a", "destinatino", "database-prod"
        )
        self.assertEqual(rc_unk, 1)
        self.assertIn("does not accept 'destinatino'", err_unk)
        rc_dup, _o_dup, err_dup = self._run_agent(
            "set",
            "remote-service",
            "db-via-a",
            "service",
            "ssh",
            "service",
            "https",
        )
        self.assertEqual(rc_dup, 1)
        self.assertIn("Duplicate field 'service'", err_dup)
        after = self._agent_row("db-via-a")
        self.assertEqual(after["destination_client_id"], before["destination_client_id"])
        self.assertEqual(after["service_object"], before["service_object"])
        self.assertEqual(int(after["enabled"]), int(before["enabled"]))
        self.assertEqual(self.agent.current_revision(), rev)

    def test_remote_service_omitted_fields_preserve_destination_client_id(self):
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            v24.set_remote_service_agent(
                self.agent,
                "db-via-a",
                destination="database-prod",
                service="ssh",
                enabled=True,
                oneshot=True,
                root=self.agent_tmp,
            )
        before = self._agent_row("db-via-a")
        self.assertEqual(before["destination_client_id"], AGENT_B)
        with mock.patch("drlink_v24._probe_tcp", return_value=True):
            rc, _out, err = self._run_agent("set", "remote-service", "db-via-a", "enabled")
        self.assertEqual(rc, 0, err)
        after = self._agent_row("db-via-a")
        self.assertEqual(after["destination_client_id"], AGENT_B)
        self.assertEqual(after["service_object"], "ssh")
        self.assertEqual(int(after["enabled"]), 1)


if __name__ == "__main__":
    unittest.main()
