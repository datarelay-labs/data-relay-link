#!/usr/bin/env python3
"""Priority 8E: last WHITELIST rule disable/delete → DENY ALL outage-safety.

WHITELIST with enforcement ENABLED and zero enabled Rules is effective DENY ALL.
Disabling/deleting the last enabled WHITELIST Rule requires explicit confirmation
with access_narrowed=true (not access broadening). BLACKLIST last-rule
broadening confirmation remains unchanged.
"""
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

from drlink_control_plane import ConfirmationRequired, ControlPlane
import drlink_control_cli as cli
import drlink_v24 as v24
from drlink_v24_bundle import apply_v24_plan, prepare_v24_plan


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _verify(plane: ControlPlane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'verified', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.conn.commit()


class WhitelistLastRuleOutageSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-p8e-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _dispatch(self, args):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.dispatch(list(args), root=self.tmp, plane=self.plane)
        return rc, out.getvalue(), err.getvalue()

    def _seed_remote_whitelist(self, *rules):
        names = rules or ("allow-ssh",)
        v24.set_network_object(
            self.plane, "src", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        for i, rule in enumerate(names):
            v24.set_access_rule(
                self.plane,
                "remote",
                rule,
                mode="whitelist" if i == 0 else None,
                source="src",
                destination="dst",
                service="ssh",
                enabled=True,
                oneshot=True,
            )

    def _seed_internet_whitelist(self, rule="allow-https"):
        v24.set_network_object(
            self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "web", type="fqdn", value="example.com", oneshot=True
        )
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            rule,
            mode="whitelist",
            source="lan",
            destination="web",
            service="https",
            enabled=True,
            oneshot=True,
        )

    def _seed_ai_whitelist(self, rule="allow-exec"):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(
            self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_permission_object(
            self.plane, "exec-only", permissions=["command-exec"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            rule,
            mode="whitelist",
            source="bot",
            destination="ubuntu-prod",
            permission="exec-only",
            enabled=True,
            oneshot=True,
        )

    def _seed_remote_blacklist(self, rule="block-ssh"):
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
            rule,
            mode="blacklist",
            source="src",
            destination="dst",
            service="ssh",
            enabled=True,
            oneshot=True,
        )

    def _assert_narrowing_impact(self, impact: dict):
        self.assertFalse(impact.get("access_broadened"))
        self.assertTrue(impact.get("access_narrowed"))
        self.assertIn("DENY ALL", str(impact.get("warning") or ""))
        self.assertIn("DENY ALL", str(impact.get("after") or ""))

    def test_last_whitelist_rule_disable_requires_confirm_remote(self):
        self._seed_remote_whitelist()
        os.environ.pop("DRLINK_CONFIRM", None)
        rev_before = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.set_access_rule(
                self.plane, "remote", "allow-ssh", enabled=False, oneshot=True
            )
        self._assert_narrowing_impact(ctx.exception.impact)
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertTrue(bool(self.plane._get_rule("remote", "allow-ssh")["enabled"]))

    def test_last_whitelist_rule_delete_requires_confirm_remote(self):
        self._seed_remote_whitelist()
        os.environ.pop("DRLINK_CONFIRM", None)
        rev_before = self.plane.current_revision()
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.unset_access_rule(self.plane, "remote", "allow-ssh")
        self._assert_narrowing_impact(ctx.exception.impact)
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertIsNotNone(self.plane._get_rule("remote", "allow-ssh"))

    def test_last_whitelist_rule_delete_internet_and_ai_parity(self):
        self._seed_internet_whitelist()
        self._seed_ai_whitelist()
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx_i:
            v24.unset_access_rule(self.plane, "internet", "allow-https")
        self._assert_narrowing_impact(ctx_i.exception.impact)
        with self.assertRaises(ConfirmationRequired) as ctx_a:
            v24.unset_ai_access_rule(self.plane, "allow-exec")
        self._assert_narrowing_impact(ctx_a.exception.impact)

    def test_last_whitelist_rule_disable_internet_and_ai_parity(self):
        self._seed_internet_whitelist()
        self._seed_ai_whitelist()
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx_i:
            v24.set_access_rule(
                self.plane, "internet", "allow-https", enabled=False, oneshot=True
            )
        self._assert_narrowing_impact(ctx_i.exception.impact)
        with self.assertRaises(ConfirmationRequired) as ctx_a:
            v24.set_ai_access_rule(
                self.plane,
                "allow-exec",
                source="bot",
                destination="ubuntu-prod",
                permission="exec-only",
                enabled=False,
                oneshot=True,
            )
        self._assert_narrowing_impact(ctx_a.exception.impact)

    def test_cancel_leaves_state_and_revision_unchanged_cli(self):
        self._seed_remote_whitelist()
        os.environ.pop("DRLINK_CONFIRM", None)
        rev_before = self.plane.current_revision()
        rc, out, _err = self._dispatch(["unset", "remote-access", "allow-ssh"])
        self.assertEqual(rc, 0)
        self.assertIn("Cancelled", out)
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertIsNotNone(self.plane._get_rule("remote", "allow-ssh"))
        pol = v24.get_access_policy(self.plane, "remote")
        self.assertEqual(pol["mode"], "whitelist")
        self.assertEqual(str(pol["enforcement"]).lower(), "enabled")

    def test_confirm_yields_zero_enabled_rules_and_deny_all(self):
        self._seed_remote_whitelist()
        rev_before = self.plane.current_revision()
        os.environ["DRLINK_CONFIRM"] = "yes"
        v24.unset_access_rule(self.plane, "remote", "allow-ssh", confirm=True)
        self.assertGreater(self.plane.current_revision(), rev_before)
        self.assertIsNone(self.plane._get_rule("remote", "allow-ssh"))
        pol = v24.get_access_policy(self.plane, "remote")
        self.assertEqual(pol["mode"], "whitelist")
        self.assertEqual(v24._count_blocking_rules(self.plane, "remote"), 0)
        result = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src",
            destination_name="dst",
            service_name="ssh",
        )
        self.assertEqual(result["result"], "DENY")
        self.assertEqual(
            v24.effective_policy_result("whitelist", "enabled", matched=False),
            "DENY",
        )

    def test_confirm_disable_keeps_mode_with_deny_all(self):
        self._seed_internet_whitelist()
        v24.set_access_rule(
            self.plane, "internet", "allow-https", enabled=False, oneshot=True, confirm=True
        )
        row = self.plane._get_rule("internet", "allow-https")
        self.assertIsNotNone(row)
        self.assertFalse(bool(row["enabled"]))
        pol = v24.get_access_policy(self.plane, "internet")
        self.assertEqual(pol["mode"], "whitelist")
        self.assertEqual(v24._count_blocking_rules(self.plane, "internet"), 0)

    def test_second_to_last_does_not_trigger_warning(self):
        self._seed_remote_whitelist("allow-a", "allow-b")
        os.environ.pop("DRLINK_CONFIRM", None)
        # Disabling one of two enabled rules must not require last-rule confirm.
        v24.set_access_rule(
            self.plane, "remote", "allow-a", enabled=False, oneshot=True
        )
        self.assertFalse(bool(self.plane._get_rule("remote", "allow-a")["enabled"]))
        self.assertTrue(bool(self.plane._get_rule("remote", "allow-b")["enabled"]))

    def test_already_disabled_rule_delete_does_not_trigger(self):
        self._seed_remote_whitelist("allow-a", "allow-b")
        v24.set_access_rule(
            self.plane, "remote", "allow-a", enabled=False, oneshot=True, confirm=True
        )
        os.environ.pop("DRLINK_CONFIRM", None)
        # allow-b still enabled → deleting disabled allow-a is not last-rule outage.
        v24.unset_access_rule(self.plane, "remote", "allow-a")
        self.assertIsNone(self.plane._get_rule("remote", "allow-a"))

    def test_enforcement_disabled_does_not_trigger_deny_all_warning(self):
        self._seed_remote_whitelist()
        v24.set_policy_enforcement(self.plane, "remote", False, confirm=True)
        os.environ.pop("DRLINK_CONFIRM", None)
        v24.unset_access_rule(self.plane, "remote", "allow-ssh")
        self.assertIsNone(self.plane._get_rule("remote", "allow-ssh"))
        pol = v24.get_access_policy(self.plane, "remote")
        self.assertEqual(pol["mode"], "whitelist")
        self.assertEqual(str(pol["enforcement"]).lower(), "disabled")

    def test_blacklist_last_rule_broadening_unchanged(self):
        self._seed_remote_blacklist()
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            v24.unset_access_rule(self.plane, "remote", "block-ssh")
        self.assertTrue(ctx.exception.impact.get("access_broadened"))
        self.assertFalse(ctx.exception.impact.get("access_narrowed"))
        self.assertIn("BLACKLIST", str(ctx.exception.impact.get("warning") or ""))

    def test_bundle_whitelist_zero_rules_reports_deny_all_not_broadening(self):
        self._seed_remote_whitelist()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  remoteAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: allow-ssh
        state: absent
""",
        )
        text = "\n".join(plan.security_impact)
        self.assertIn("DENY ALL", text)
        self.assertIn("narrows", text.lower())
        self.assertNotIn("broadens", text.lower())
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            apply_v24_plan(self.plane, plan)
        self.assertFalse(ctx.exception.impact.get("access_broadened"))
        self.assertTrue(ctx.exception.impact.get("access_narrowed"))
        self.assertIsNotNone(self.plane._get_rule("remote", "allow-ssh"))

    def test_bundle_whitelist_disable_to_zero_reports_deny_all(self):
        self._seed_ai_whitelist()
        plan = prepare_v24_plan(
            self.plane,
            """configurationBundle:
  context: server
  aiAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: allow-exec
        source: bot
        destination: ubuntu-prod
        permission: exec-only
        enabled: false
""",
        )
        text = "\n".join(plan.security_impact)
        self.assertIn("DENY ALL", text)
        os.environ.pop("DRLINK_CONFIRM", None)
        with self.assertRaises(ConfirmationRequired) as ctx:
            apply_v24_plan(self.plane, plan)
        self.assertFalse(ctx.exception.impact.get("access_broadened"))
        self.assertTrue(ctx.exception.impact.get("access_narrowed"))


if __name__ == "__main__":
    unittest.main()
