#!/usr/bin/env python3
"""Targeted CLI/AI user-workflow fixes for v2.4.0 final findings.

Covers:
  - Remote / Internet Access test semantic equivalence (Object identity ≠ match key)
  - Object / Group references subviews
  - Managed Host agent / addresses subviews
  - AI Access rule detail completeness
  - Bundle security-impact merged final state
  - Agent show status runtime visibility
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane, ControlPlaneError
import drlink_control_cli as cli
import drlink_v24 as v24
from drlink_v24_bundle import prepare_v24_plan
import frp_cli_catalog as catalog


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role": "server"}\n', encoding="utf-8")


def _agent_root(tmp: str, hostname: str = "agent-host") -> None:
    Path(tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/frp/client-state.json").write_text(
        '{\n  "machine_id": "aabbccddeeff00112233445566778899",\n'
        '  "hostname": "%s",\n  "label": "%s"\n}\n' % (hostname, hostname),
        encoding="utf-8",
    )
    Path(tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
    Path(tmp, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-wf-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("DRLINK_CONFIRM", "FRP_DEPLOY_TEST_ROOT", "DRLINK_TEST_RUNTIME_UNIT"):
            os.environ.pop(key, None)

    def _run(self, *tokens):
        buf = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = cli.dispatch(list(tokens), root=self.tmp, plane=self.plane)
        return rc, buf.getvalue(), err.getvalue()


class RemoteAccessSemanticParity(_Base):
    def test_user_intent_equivalent_ip_and_service_objects(self):
        # Intent: "Check whether this IP can reach this web service."
        # Rule references Object A / Service A; test uses Object B / Service B
        # with identical runtime values.
        v24.set_network_object(self.plane, "src-a", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "src-b", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst-host", type="ip", value="198.51.100.50", oneshot=True)
        v24.set_service_object(self.plane, "svc-a", type="tcp", port=8443, oneshot=True)
        v24.set_service_object(self.plane, "svc-b", type="tcp", port=8443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-admin-web",
            mode="whitelist",
            source="src-a",
            destination="dst-host",
            service="svc-a",
            enabled=True,
            oneshot=True,
        )
        rc, out, _err = self._run(
            "test",
            "remote-access",
            "source",
            "src-b",
            "destination",
            "dst-host",
            "service",
            "svc-b",
        )
        self.assertEqual(rc, 0)
        self.assertIn("ALLOW", out)
        self.assertIn("allow-admin-web", out)
        # Runtime path agrees
        runtime = self.plane.evaluate_remote_access("198.51.100.10", "198.51.100.50", "tcp", 8443)
        self.assertEqual(runtime["action"], "ALLOW")

    def test_group_source_and_disabled_rule(self):
        v24.set_network_object(self.plane, "office", type="ip", value="203.0.113.10", oneshot=True)
        v24.set_network_object(self.plane, "alias", type="ip", value="203.0.113.10", oneshot=True)
        v24.set_network_group(self.plane, "admins", members=["office"], oneshot=True)
        v24.set_network_object(self.plane, "prod", type="ip", value="198.51.100.8", oneshot=True)
        v24.set_service_object(self.plane, "ssh-alt", type="tcp", port=22, oneshot=True)
        v24.set_service_group(self.plane, "shell", members=["ssh"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "admin-ssh",
            mode="blacklist",
            source="admins",
            destination="prod",
            service="shell",
            enabled=True,
            oneshot=True,
        )
        rc, out, _err = self._run(
            "test",
            "remote-access",
            "source",
            "alias",
            "destination",
            "prod",
            "service",
            "ssh-alt",
        )
        self.assertEqual(rc, 0)
        self.assertIn("DENY", out)
        # Disable matching rule → BLACKLIST no match → ALLOW
        v24.set_access_rule(self.plane, "remote", "admin-ssh", enabled=False, oneshot=False)
        rc2, out2, _err = self._run(
            "test",
            "remote-access",
            "source",
            "alias",
            "destination",
            "prod",
            "service",
            "ssh-alt",
        )
        self.assertEqual(rc2, 0)
        self.assertIn("ALLOW", out2)


class InternetAccessSemanticParity(_Base):
    def test_user_intent_equivalent_fqdn_objects(self):
        # Intent: "Would traffic to example.com be denied?"
        # BLACKLIST references audit-fqdn; test with another-object (same FQDN).
        v24.set_network_object(self.plane, "agent-src", type="ip", value="10.10.10.20", oneshot=True)
        v24.set_network_object(self.plane, "audit-fqdn", type="fqdn", value="example.com", oneshot=True)
        v24.set_network_object(self.plane, "another-object", type="fqdn", value="example.com", oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "block-example",
            mode="blacklist",
            source="agent-src",
            destination="audit-fqdn",
            service="https",
            enabled=True,
            oneshot=True,
        )
        rc_named, out_named, _err = self._run(
            "test",
            "internet-access",
            "source",
            "agent-src",
            "destination",
            "audit-fqdn",
            "service",
            "https",
        )
        rc_alias, out_alias, _err = self._run(
            "test",
            "internet-access",
            "source",
            "agent-src",
            "destination",
            "another-object",
            "service",
            "https",
        )
        self.assertEqual(rc_named, 0)
        self.assertEqual(rc_alias, 0)
        self.assertIn("DENY", out_named)
        self.assertIn("DENY", out_alias)
        runtime = self.plane.evaluate_internet_access("10.10.10.20", "example.com", 443, "https")
        self.assertEqual(runtime["action"], "DENY")

    def test_whitelist_and_equivalent_ip_service(self):
        v24.set_network_object(self.plane, "src-a", type="ip", value="8.8.8.8", oneshot=True)
        v24.set_network_object(self.plane, "src-b", type="ip", value="8.8.8.8", oneshot=True)
        v24.set_network_object(self.plane, "dst-a", type="ip", value="1.1.1.1", oneshot=True)
        v24.set_network_object(self.plane, "dst-b", type="ip", value="1.1.1.1", oneshot=True)
        v24.set_service_object(self.plane, "web-a", type="tcp", port=443, oneshot=True)
        v24.set_service_object(self.plane, "web-b", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-web",
            mode="whitelist",
            source="src-a",
            destination="dst-a",
            service="web-a",
            enabled=True,
            oneshot=True,
        )
        rc, out, _err = self._run(
            "test",
            "internet-access",
            "source",
            "src-b",
            "destination",
            "dst-b",
            "service",
            "web-b",
        )
        self.assertEqual(rc, 0)
        self.assertIn("ALLOW", out)


class ObjectReferenceSubviews(_Base):
    def test_show_references_for_objects_and_groups(self):
        # Intent: "Show me what is using this Service Object before I delete it."
        v24.set_network_object(self.plane, "office", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "prod", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_network_object(self.plane, "ext-site", type="fqdn", value="example.org", oneshot=True)
        v24.set_network_group(self.plane, "admins", members=["office"], oneshot=True)
        v24.set_service_object(self.plane, "web-https", type="tcp", port=443, oneshot=True)
        v24.set_service_group(self.plane, "web", members=["web-https"], oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "rule-a",
            mode="whitelist",
            source="admins",
            destination="prod",
            service="web",
            enabled=True,
            oneshot=True,
        )
        v24.set_access_rule(
            self.plane,
            "internet",
            "rule-b",
            mode="blacklist",
            source="office",
            destination="ext-site",
            service="web-https",
            enabled=True,
            oneshot=True,
        )
        # Catalog must accept references (was: unexpected argument)
        self.assertIsNone(catalog.strict_error(["show", "service-object", "web-https", "references"]))
        self.assertIsNone(catalog.strict_error(["show", "network-object", "office", "references"]))
        self.assertIsNone(catalog.strict_error(["show", "network-group", "admins", "references"]))
        self.assertIsNone(catalog.strict_error(["show", "service-group", "web", "references"]))

        rc, out, _err = self._run("show", "service-object", "web-https", "references")
        self.assertEqual(rc, 0)
        self.assertIn("Internet Access:", out)
        self.assertIn("rule-b", out)
        self.assertIn("Service Groups:", out)
        self.assertIn("web", out)

        rc2, out2, _err = self._run("show", "network-object", "office", "references")
        self.assertEqual(rc2, 0)
        self.assertIn("Network Groups:", out2)
        self.assertIn("admins", out2)

        rc3, out3, _err = self._run("show", "network-group", "admins", "references")
        self.assertEqual(rc3, 0)
        self.assertIn("Remote Access:", out3)
        self.assertIn("rule-a", out3)

        rc4, out4, _err = self._run("show", "service-group", "web", "references")
        self.assertEqual(rc4, 0)
        self.assertIn("Remote Access:", out4)

        rc5, out5, _err = self._run("show", "network-object", "prod", "references")
        # prod is referenced; empty case:
        v24.set_network_object(self.plane, "orphan", type="ip", value="198.51.100.99", oneshot=True)
        rc6, out6, _err = self._run("show", "network-object", "orphan", "references")
        self.assertEqual(rc6, 0)
        self.assertIn("None", out6)


class ManagedHostSubviews(_Base):
    def test_agent_and_addresses_views(self):
        client = self.plane.upsert_client(
            "host-1",
            label="ubuntu-prod",
            hostname="ubuntu-prod",
            connected=True,
            addresses=[
                {
                    "address": "10.0.0.5",
                    "address_family": "ipv4",
                    "interface_name": "eth0",
                    "scope": "private",
                    "active": True,
                }
            ],
        )
        self.assertTrue(client)
        rc, out, _err = self._run("show", "managed-host", "ubuntu-prod", "agent")
        self.assertEqual(rc, 0)
        self.assertIn("Connection", out)
        self.assertIn("Connected", out)
        self.assertIn("Last seen", out)
        self.assertIn("Not reported to Server", out)
        self.assertNotIn("Managed Host: ubuntu-prod\nHostname:", out)

        rc2, out2, _err = self._run("show", "managed-host", "ubuntu-prod", "addresses")
        self.assertEqual(rc2, 0)
        self.assertIn("10.0.0.5", out2)

        rc_bad, _out_bad, err_bad = self._run("show", "managed-host", "ubuntu-prod", "bogus-view")
        self.assertEqual(rc_bad, 1)
        self.assertIn("Unknown Managed Host view", err_bad)


class AIAccessDetail(_Base):
    def test_show_ai_access_includes_destination_and_permission(self):
        self.plane.set_ai_principal("chatgpt-support", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'chatgpt-support'"
        )
        self.plane.conn.commit()
        v24.set_network_object(self.plane, "prod-host", type="ip", value="198.51.100.8", oneshot=True)
        v24.set_permission_object(self.plane, "read-only", permissions=["host-info"], oneshot=True)
        v24.set_ai_access_rule(
            self.plane,
            "support-read",
            mode="whitelist",
            source="chatgpt-support",
            destination="prod-host",
            permission="read-only",
            enabled=True,
            oneshot=True,
        )
        rc, out, _err = self._run("show", "ai-access", "support-read")
        self.assertEqual(rc, 0)
        self.assertIn("AI Access Rule: support-read", out)
        self.assertIn("Source", out)
        self.assertIn("chatgpt-support", out)
        self.assertIn("Destination", out)
        self.assertIn("prod-host", out)
        self.assertIn("Permission", out)
        self.assertIn("read-only", out)
        self.assertIn("Enabled", out)

    def test_partial_edit_enable_disable_updates_only_enabled(self):
        self.plane.set_ai_principal("chatgpt-support", enabled=True)
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'verified' WHERE name = 'chatgpt-support'"
        )
        self.plane.conn.commit()
        v24.set_network_object(self.plane, "prod-host", type="ip", value="198.51.100.8", oneshot=True)
        v24.set_permission_object(self.plane, "read-only", permissions=["host-info"], oneshot=True)
        v24.set_ai_access_rule(
            self.plane,
            "support-read",
            mode="whitelist",
            source="chatgpt-support",
            destination="prod-host",
            permission="read-only",
            enabled=True,
            oneshot=True,
        )
        before = self.plane.conn.execute(
            "SELECT enabled, source_identity_id, destination_ref_id, permission_ref_id "
            "FROM ai_policy_rules WHERE name = 'support-read'"
        ).fetchone()
        rc, _out, err = self._run("set", "ai-access", "support-read", "disabled")
        self.assertEqual(rc, 0, err)
        after = self.plane.conn.execute(
            "SELECT enabled, source_identity_id, destination_ref_id, permission_ref_id "
            "FROM ai_policy_rules WHERE name = 'support-read'"
        ).fetchone()
        self.assertEqual(int(after["enabled"]), 0)
        self.assertEqual(after["source_identity_id"], before["source_identity_id"])
        self.assertEqual(after["destination_ref_id"], before["destination_ref_id"])
        self.assertEqual(after["permission_ref_id"], before["permission_ref_id"])


class BundleSecurityImpact(_Base):
    def test_merged_whitelist_does_not_false_deny_all(self):
        # Authoritative WHITELIST already has enabled Rules; Bundle adds one disabled Rule.
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "existing-allow",
            mode="whitelist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: draft-disabled
        source: src
        destination: dst
        service: https
        enabled: false
""",
        )
        text = "\n".join(plan.security_impact)
        self.assertNotIn("DENY ALL", text)

    def test_real_deny_all_transition_still_warned(self):
        v24.set_network_object(self.plane, "src", type="ip", value="198.51.100.10", oneshot=True)
        v24.set_network_object(self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "only-allow",
            mode="whitelist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: only-allow
        state: absent
""",
        )
        text = "\n".join(plan.security_impact)
        self.assertIn("DENY ALL", text)


class AgentShowStatusRuntime(_Base):
    def test_agent_status_distinguishes_runtime_failure(self):
        # Intent: "Is the Agent actually healthy?"
        self.plane.close()
        self.tmp = tempfile.mkdtemp(prefix="drlink-agent-")
        _agent_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_TEST_RUNTIME_UNIT"] = "failed:start-limit-hit"
        self.plane = ControlPlane(self.tmp)
        out = self.plane.format_status()
        self.assertIn("Control DB", out)
        self.assertIn("Agent Runtime", out)
        self.assertIn("Critical", out)
        self.assertIn("failed", out.lower())
        self.assertIn("Remote Services", out)
        self.assertIn("Server", out)


if __name__ == "__main__":
    unittest.main()
