#!/usr/bin/env python3
"""P1 Findings Y+Z: Group policy-test must not report false scalar ALLOW.

Public test/explain expands Group selectors to all leaf members, evaluates
concrete combinations with the same atomic/runtime evaluators, and aggregates
ALLOW only when every member/combination allows. Runtime policy semantics are
unchanged.
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

from drlink_control_plane import ControlPlane
import drlink_control_cli as cli
import drlink_v24 as v24


def _server_root(tmp: str) -> None:
    Path(tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
    Path(tmp, "etc/drlink/config.json").write_text('{"role":"server"}\n', encoding="utf-8")


def _verify(plane: ControlPlane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'verified', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.conn.commit()


class GroupPolicyTestFalseAssurance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-group-test-")
        _server_root(self.tmp)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        self.vendor = Path(self.tmp) / "var" / "lib" / "vendor"
        self.vendor.mkdir(parents=True, exist_ok=True)
        (self.vendor / "app.log").write_text("payload\n", encoding="utf-8")
        self.vendor_glob = str(self.vendor / "**")

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _run(self, *tokens):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.dispatch(list(tokens), root=self.tmp, plane=self.plane)
        return rc, out.getvalue(), err.getvalue()

    def _seed_remote_objects(self) -> None:
        v24.set_network_object(
            self.plane, "src-a", type="ip", value="203.0.113.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "src-b", type="ip", value="203.0.113.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst-a", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst-b", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_network_group(
            self.plane, "srcs", members=["src-b", "src-a"], oneshot=True
        )
        v24.set_network_group(
            self.plane, "dsts", members=["dst-b", "dst-a"], oneshot=True
        )
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_service_group(
            self.plane, "web-or-ssh", members=["https", "ssh"], oneshot=True
        )

    def test_remote_mixed_source_group_not_false_allow(self):
        self._seed_remote_objects()
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-a",
            mode="blacklist",
            source="src-a",
            destination="dst-a",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        group = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="srcs",
            destination_name="dst-a",
            service_name="ssh",
        )
        self.assertEqual(group["result"], "DENY")
        self.assertTrue(group.get("mixed"))
        by_src = {m["source"]: m["result"] for m in group["member_results"]}
        self.assertEqual(by_src["src-a"], "DENY")
        self.assertEqual(by_src["src-b"], "ALLOW")
        self.assertEqual(
            [m["source"] for m in group["member_results"]],
            ["src-a", "src-b"],
        )

        a = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src-a",
            destination_name="dst-a",
            service_name="ssh",
        )
        b = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src-b",
            destination_name="dst-a",
            service_name="ssh",
        )
        self.assertEqual(a["result"], "DENY")
        self.assertEqual(b["result"], "ALLOW")
        self.assertNotIn("member_results", a)

        rc, out, err = self._run(
            "test",
            "remote-access",
            "source",
            "srcs",
            "destination",
            "dst-a",
            "service",
            "ssh",
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("Effective Result:\n  DENY", out)
        self.assertIn("Member Results:", out)
        self.assertIn("source=src-a", out)
        self.assertIn("source=src-b", out)

    def test_remote_mixed_destination_and_service_groups(self):
        self._seed_remote_objects()
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-dst-a-ssh",
            mode="whitelist",
            source="src-a",
            destination="dst-a",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        dest = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src-a",
            destination_name="dsts",
            service_name="ssh",
        )
        self.assertEqual(dest["result"], "DENY")
        self.assertTrue(dest.get("mixed"))
        by_dst = {m["destination"]: m["result"] for m in dest["member_results"]}
        self.assertEqual(by_dst["dst-a"], "ALLOW")
        self.assertEqual(by_dst["dst-b"], "DENY")

        svc = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src-a",
            destination_name="dst-a",
            service_name="web-or-ssh",
        )
        self.assertEqual(svc["result"], "DENY")
        self.assertTrue(svc.get("mixed"))
        by_svc = {m["service"]: m["result"] for m in svc["member_results"]}
        self.assertEqual(by_svc["ssh"], "ALLOW")
        self.assertEqual(by_svc["https"], "DENY")
        self.assertEqual(
            [m["service"] for m in svc["member_results"]],
            ["https", "ssh"],
        )

    def test_remote_unanimous_group_outcomes_and_ordering(self):
        self._seed_remote_objects()
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-a",
            mode="blacklist",
            source="src-a",
            destination="dst-a",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-b",
            source="src-b",
            destination="dst-a",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        deny_all = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="srcs",
            destination_name="dst-a",
            service_name="ssh",
        )
        self.assertEqual(deny_all["result"], "DENY")
        self.assertFalse(deny_all.get("mixed"))
        self.assertTrue(all(m["result"] == "DENY" for m in deny_all["member_results"]))

        v24.reset_access_policy(self.plane, "remote", confirm=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-srcs",
            mode="whitelist",
            source="srcs",
            destination="dst-a",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        allow_all = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="srcs",
            destination_name="dst-a",
            service_name="ssh",
        )
        self.assertEqual(allow_all["result"], "ALLOW")
        self.assertFalse(allow_all.get("mixed"))
        first = [m["source"] for m in allow_all["member_results"]]
        second = [
            m["source"]
            for m in v24.evaluate_selector_policy(
                self.plane,
                "remote",
                source_name="srcs",
                destination_name="dst-a",
                service_name="ssh",
            )["member_results"]
        ]
        self.assertEqual(first, ["src-a", "src-b"])
        self.assertEqual(first, second)

    def test_internet_mixed_source_group_not_false_allow(self):
        v24.set_network_object(
            self.plane, "src-a", type="ip", value="203.0.113.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "src-b", type="ip", value="203.0.113.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "pub-a", type="ip", value="8.8.8.8", oneshot=True
        )
        v24.set_network_object(
            self.plane, "pub-b", type="ip", value="1.1.1.1", oneshot=True
        )
        v24.set_network_group(
            self.plane, "srcs", members=["src-b", "src-a"], oneshot=True
        )
        v24.set_network_group(
            self.plane, "pubs", members=["pub-b", "pub-a"], oneshot=True
        )
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "block-a",
            mode="blacklist",
            source="src-a",
            destination="pub-a",
            service="https",
            enabled=True,
            oneshot=True,
        )
        group = v24.evaluate_selector_policy(
            self.plane,
            "internet",
            source_name="srcs",
            destination_name="pub-a",
            service_name="https",
        )
        self.assertEqual(group["result"], "DENY")
        self.assertTrue(group.get("mixed"))
        by_src = {m["source"]: m["result"] for m in group["member_results"]}
        self.assertEqual(by_src["src-a"], "DENY")
        self.assertEqual(by_src["src-b"], "ALLOW")

        dest = v24.evaluate_selector_policy(
            self.plane,
            "internet",
            source_name="src-b",
            destination_name="pubs",
            service_name="https",
        )
        self.assertEqual(dest["result"], "ALLOW")
        self.assertFalse(dest.get("mixed"))
        self.assertTrue(all(m["result"] == "ALLOW" for m in dest["member_results"]))

        single = v24.evaluate_selector_policy(
            self.plane,
            "internet",
            source_name="src-b",
            destination_name="pub-a",
            service_name="https",
        )
        self.assertEqual(single["result"], "ALLOW")
        self.assertNotIn("member_results", single)

        # Destination Group mixed: allow only pub-a under whitelist.
        v24.reset_access_policy(self.plane, "internet", confirm=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-pub-a",
            mode="whitelist",
            source="src-b",
            destination="pub-a",
            service="https",
            enabled=True,
            oneshot=True,
        )
        mixed_dest = v24.evaluate_selector_policy(
            self.plane,
            "internet",
            source_name="src-b",
            destination_name="pubs",
            service_name="https",
        )
        self.assertEqual(mixed_dest["result"], "DENY")
        self.assertTrue(mixed_dest.get("mixed"))
        by_dst = {m["destination"]: m["result"] for m in mixed_dest["member_results"]}
        self.assertEqual(by_dst["pub-a"], "ALLOW")
        self.assertEqual(by_dst["pub-b"], "DENY")

    def test_ai_mixed_permission_group_not_false_allow(self):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(
            self.plane, "host1", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_permission_object(
            self.plane, "read-only", permissions=["file-read"], oneshot=True
        )
        v24.set_permission_object(
            self.plane, "exec-only", permissions=["command-exec"], oneshot=True
        )
        v24.set_permission_group(
            self.plane, "mixed", members=["exec-only", "read-only"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            "allow-read",
            mode="whitelist",
            source="bot",
            destination="host1",
            permission="read-only",
            enabled=True,
            oneshot=True,
            paths=[self.vendor_glob],
        )

        mixed = v24.test_ai_access_v24(
            self.plane,
            identity="bot",
            destination="host1",
            permission="mixed",
            path=str(self.vendor / "app.log"),
        )
        self.assertEqual(mixed["result"], "DENY")
        self.assertTrue(mixed.get("mixed"))
        by_perm = {m["permission"]: m["result"] for m in mixed["member_results"]}
        self.assertEqual(by_perm["file-read"], "ALLOW")
        self.assertEqual(by_perm["command-exec"], "DENY")
        self.assertEqual(
            [m["permission"] for m in mixed["member_results"]],
            ["command-exec", "file-read"],
        )

        read_only = v24.test_ai_access_v24(
            self.plane,
            identity="bot",
            destination="host1",
            permission="read-only",
            path=str(self.vendor / "app.log"),
        )
        exec_only = v24.test_ai_access_v24(
            self.plane,
            identity="bot",
            destination="host1",
            permission="exec-only",
        )
        self.assertEqual(read_only["result"], "ALLOW")
        self.assertEqual(exec_only["result"], "DENY")
        self.assertNotIn("member_results", read_only)

        rc, out, err = self._run(
            "test",
            "ai-access",
            "source",
            "bot",
            "destination",
            "host1",
            "permission",
            "mixed",
            "path",
            str(self.vendor / "app.log"),
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("Effective Result:\n  DENY", out)
        self.assertIn("Member Results:", out)
        self.assertIn("permission=file-read => ALLOW", out)
        self.assertIn("permission=command-exec => DENY", out)

    def test_ai_permission_group_unanimous_and_file_path_fail_closed(self):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(
            self.plane, "host1", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_permission_object(
            self.plane, "read-only", permissions=["file-read"], oneshot=True
        )
        v24.set_permission_object(
            self.plane, "info-only", permissions=["host-info"], oneshot=True
        )
        v24.set_permission_group(
            self.plane, "ops", members=["info-only", "read-only"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            "allow-ops",
            mode="whitelist",
            source="bot",
            destination="host1",
            permission="ops",
            enabled=True,
            oneshot=True,
            paths=[self.vendor_glob],
        )

        no_path = v24.test_ai_access_v24(
            self.plane,
            identity="bot",
            destination="host1",
            permission="ops",
        )
        self.assertEqual(no_path["result"], "DENY")
        by_perm = {m["permission"]: m for m in no_path["member_results"]}
        self.assertEqual(by_perm["host-info"]["result"], "ALLOW")
        self.assertEqual(by_perm["file-read"]["result"], "DENY")
        self.assertTrue(by_perm["file-read"].get("path_required"))

        in_scope = v24.test_ai_access_v24(
            self.plane,
            identity="bot",
            destination="host1",
            permission="ops",
            path=str(self.vendor / "app.log"),
        )
        self.assertEqual(in_scope["result"], "ALLOW")
        self.assertTrue(all(m["result"] == "ALLOW" for m in in_scope["member_results"]))

        out_of_scope = v24.test_ai_access_v24(
            self.plane,
            identity="bot",
            destination="host1",
            permission="ops",
            path="/etc/passwd",
        )
        self.assertEqual(out_of_scope["result"], "DENY")
        by_perm = {m["permission"]: m["result"] for m in out_of_scope["member_results"]}
        self.assertEqual(by_perm["host-info"], "ALLOW")
        self.assertEqual(by_perm["file-read"], "DENY")

        # Runtime evaluator still uses any-intersection for rule matching; public
        # Permission Group test is the expanded aggregate path above.
        runtime = v24.evaluate_ai_access_v24(
            self.plane,
            identity="bot",
            destination="host1",
            permission="command-exec",
        )
        self.assertEqual(runtime["result"], "DENY")


if __name__ == "__main__":
    unittest.main()
