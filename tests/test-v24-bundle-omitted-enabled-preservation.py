#!/usr/bin/env python3
"""P0: ConfigurationBundle omitted `enabled` must not silently enable resources.

Existing resource + omitted enabled => UNCHANGED (preserve disabled/enabled).
Explicit true/false continues to work. New resources keep default-enabled create.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ConfirmationRequired, ControlPlane
import drlink_v24 as v24
from drlink_v24_bundle import (
    apply_v24_plan,
    export_configuration_v24,
    prepare_v24_plan,
)


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _agent_root(tmp: str, hostname: str = "agent-1") -> None:
    Path(tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/frp/client-state.json").write_text(
        '{\n  "machine_id": "aabbccddeeff00112233445566778899",\n  "hostname": "%s",\n  "label": "%s"\n}\n'
        % (hostname, hostname),
        encoding="utf-8",
    )
    Path(tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
    Path(tmp, "etc/frp/client-identity.key").write_text("x", encoding="utf-8")
    cfg = Path(tmp, "etc/drlink/config.json")
    if cfg.exists():
        cfg.unlink()


def _verify(plane: ControlPlane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'verified', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.conn.commit()


class BundleOmittedEnabledPreservation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-omit-enabled-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in (
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_CONFIRM",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_SERVER_REACHABLE",
        ):
            os.environ.pop(key, None)

    def _seed_remote_whitelist(self):
        v24.set_network_object(
            self.plane, "src1", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "src2", type="ip", value="198.51.100.11", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "svc", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow1",
            mode="whitelist",
            source="src1",
            destination="dst",
            service="svc",
            enabled=False,
            oneshot=True,
        )

    def test_remote_disabled_rule_omitted_enabled_stays_disabled(self):
        self._seed_remote_whitelist()
        before = self.plane._get_rule("remote", "allow1")
        self.assertFalse(bool(before["enabled"]))
        before_eval = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src2",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(before_eval.get("result"), "DENY")

        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    rules:
      - name: allow1
        source: src2
        destination: dst
        service: svc
""",
        )
        impact = "\n".join(plan.security_impact).lower()
        self.assertNotIn("broadens", impact)
        rule_items = [
            c for c in plan.changes if c.get("kind") == "remote-access-rule" and c.get("op") == "SET"
        ]
        self.assertEqual(len(rule_items), 1)
        self.assertFalse(bool(rule_items[0]["item"]["enabled"]))

        result = apply_v24_plan(self.plane, plan)
        self.assertEqual(result["status"], "APPLIED")
        after = self.plane._get_rule("remote", "allow1")
        self.assertFalse(bool(after["enabled"]))
        after_eval = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src2",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(after_eval.get("result"), "DENY")

    def test_internet_disabled_rule_omitted_enabled_stays_disabled(self):
        v24.set_network_object(
            self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "web", type="fqdn", value="example.com", oneshot=True
        )
        v24.set_network_object(
            self.plane, "web2", type="fqdn", value="example.org", oneshot=True
        )
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-web",
            mode="whitelist",
            source="lan",
            destination="web",
            service="https",
            enabled=False,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  internetAccess:
    rules:
      - name: allow-web
        source: lan
        destination: web2
        service: https
""",
        )
        impact = "\n".join(plan.security_impact).lower()
        self.assertNotIn("broadens", impact)
        apply_v24_plan(self.plane, plan)
        row = self.plane._get_rule("internet", "allow-web")
        self.assertFalse(bool(row["enabled"]))
        view = self.plane._rule_view(row)
        self.assertEqual((view.get("destinations") or [None])[0], "web2")

    def test_ai_disabled_rule_omitted_enabled_stays_disabled(self):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(
            self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "ubuntu-dr", type="ip", value="198.51.100.11", oneshot=True
        )
        v24.set_permission_object(
            self.plane, "read-only", permissions=["file-read"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            "allow-read",
            mode="whitelist",
            source="bot",
            destination="ubuntu-prod",
            permission="read-only",
            enabled=False,
            oneshot=True,
        )
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  aiAccess:
    rules:
      - name: allow-read
        source: bot
        destination: ubuntu-dr
        permission: read-only
""",
        )
        impact = "\n".join(plan.security_impact).lower()
        self.assertNotIn("broadens", impact)
        apply_v24_plan(self.plane, plan)
        row = self.plane.conn.execute(
            "SELECT enabled FROM ai_policy_rules WHERE name = ? COLLATE NOCASE",
            ("allow-read",),
        ).fetchone()
        self.assertFalse(bool(row["enabled"]))

    def test_explicit_false_to_true_still_enables(self):
        self._seed_remote_whitelist()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    rules:
      - name: allow1
        source: src1
        destination: dst
        service: svc
        enabled: true
""",
        )
        apply_v24_plan(self.plane, plan)
        self.assertTrue(bool(self.plane._get_rule("remote", "allow1")["enabled"]))
        ev = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src1",
            destination_name="dst",
            service_name="svc",
        )
        self.assertEqual(ev.get("result"), "ALLOW")

    def test_explicit_true_to_false_still_disables_with_confirmation(self):
        v24.set_network_object(
            self.plane, "src", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-ssh",
            mode="blacklist",
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
    rules:
      - name: block-ssh
        source: src
        destination: dst
        service: ssh
        enabled: false
""",
        )
        self.assertTrue(plan.security_impact)
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired):
            apply_v24_plan(self.plane, plan, confirm=False)
        os.environ["DRLINK_CONFIRM"] = "yes"
        apply_v24_plan(self.plane, plan, confirm=True)
        self.assertFalse(bool(self.plane._get_rule("remote", "block-ssh")["enabled"]))

    def test_new_rule_omitted_enabled_defaults_true(self):
        v24.set_network_object(
            self.plane, "src", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: brand-new
        source: src
        destination: dst
        service: ssh
""",
        )
        items = [
            c for c in plan.changes if c.get("kind") == "remote-access-rule" and c.get("op") == "SET"
        ]
        self.assertEqual(len(items), 1)
        self.assertTrue(bool(items[0]["item"]["enabled"]))
        apply_v24_plan(self.plane, plan)
        self.assertTrue(bool(self.plane._get_rule("remote", "brand-new")["enabled"]))

    def test_export_reapply_no_change(self):
        self._seed_remote_whitelist()
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow1",
            source="src1",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )
        exported = export_configuration_v24(self.plane)
        plan = prepare_v24_plan(self.plane, exported)
        kinds = {(c.get("op"), c.get("kind"), c.get("name")) for c in plan.changes}
        self.assertIn(("NO_CHANGE", "remote-access-rule", "allow1"), kinds)
        self.assertTrue(plan.no_change or all(c.get("op") == "NO_CHANGE" for c in plan.changes if "rule" in str(c.get("kind"))))

    def test_agent_remote_service_omitted_enabled_stays_disabled(self):
        self.plane.close()
        self.tmp = tempfile.mkdtemp(prefix="drlink-omit-enabled-agent-")
        _agent_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_remote_service_agent(
            self.plane,
            "pub1",
            destination="this-host",
            service="ssh",
            enabled=False,
            oneshot=True,
            root=self.tmp,
            server_reachable=False,
        )
        before = self.plane.conn.execute(
            "SELECT enabled, service_object FROM agent_remote_services WHERE name = ?",
            ("pub1",),
        ).fetchone()
        self.assertFalse(bool(before["enabled"]))

        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: agent
  remoteServices:
    - name: pub1
      destination: this-host
      service: https
""",
        )
        items = [c for c in plan.changes if c.get("kind") == "remote-service" and c.get("op") == "SET"]
        self.assertEqual(len(items), 1)
        self.assertFalse(bool(items[0]["item"]["enabled"]))
        apply_v24_plan(self.plane, plan)
        after = self.plane.conn.execute(
            "SELECT enabled, service_object FROM agent_remote_services WHERE name = ?",
            ("pub1",),
        ).fetchone()
        self.assertFalse(bool(after["enabled"]))
        self.assertEqual(str(after["service_object"]).lower(), "https")


if __name__ == "__main__":
    unittest.main()
