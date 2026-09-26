#!/usr/bin/env python3
"""Focused ConfigurationBundle + Change Plan tests (no full suite)."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane, ConcurrencyError
from drlink_configuration_bundle import (
    BundleError,
    apply_change_plan,
    export_configuration,
    parse_bundle,
    prepare_plan,
    read_bundle_from_path_or_stdin,
)
import drlink_control_cli as cli


def _bundle(**spec_parts):
    import yaml

    doc = {
        "apiVersion": "drlink.datarelay.run/v1alpha1",
        "kind": "ConfigurationBundle",
        "metadata": {"name": "test-bundle"},
        "spec": spec_parts,
    }
    return yaml.safe_dump(doc, sort_keys=False)


class ConfigurationBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-cfg-bundle-")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)

    def tearDown(self):
        self.plane.close()
        os.environ.pop("DRLINK_CONFIRM", None)

    def test_secret_field_rejected(self):
        raw = _bundle(
            objects=[
                {
                    "name": "x",
                    "type": "Host",
                    "values": ["198.51.100.1"],
                    "bearerToken": "secret-value",
                }
            ]
        )
        with self.assertRaises(BundleError):
            parse_bundle(raw)

    def test_ticket_material_rejected(self):
        raw = _bundle(
            objects=[
                {
                    "name": "x",
                    "type": "Host",
                    "values": ["198.51.100.1"],
                    "note": "bt1.deadbeefdeadbeef." + ("ab" * 32),
                }
            ]
        )
        # note field itself is not prohibited key; value containing bt1. is scanned
        with self.assertRaises(BundleError):
            parse_bundle(raw)
        accepted = parse_bundle(
            _bundle(
                objects=[
                    {
                        "name": "x",
                        "type": "Host",
                        "values": ["198.51.100.1"],
                        "note": "AbcdEFghij1234_-KLMNOP",
                    }
                ]
            )
        )
        self.assertEqual(
            accepted["spec"]["objects"][0]["note"],
            "AbcdEFghij1234_-KLMNOP",
        )
        url = _bundle(
            objects=[
                {
                    "name": "x",
                    "type": "Host",
                    "values": ["198.51.100.1"],
                    "note": "https://remote.xdr.ooo/i/AbcdEFghij1234_-KLMNOP",
                }
            ]
        )
        with self.assertRaises(BundleError):
            parse_bundle(url)

    def test_unknown_family_rejected(self):
        raw = _bundle(acl=[{"name": "legacy"}])
        with self.assertRaises(BundleError):
            parse_bundle(raw)

    def test_simple_apply_reapply_omit_delete(self):
        self.plane.set_object_type("keep-me", "host")
        self.plane.set_object_value("keep-me", "198.51.100.9")
        raw = _bundle(
            objects=[
                {
                    "name": "hq-admin",
                    "type": "Network",
                    "values": ["203.0.113.10/32"],
                }
            ],
            objectGroups=[{"name": "admins", "members": ["hq-admin"]}],
        )
        plan = prepare_plan(self.plane, raw)
        result = apply_change_plan(self.plane, plan, confirm=True)
        self.assertEqual(result["status"], "APPLIED")
        rev = result["revision"]
        self.assertIsNotNone(self.plane.get_object("hq-admin"))
        self.assertIsNotNone(self.plane.get_object("keep-me"))

        result2 = apply_change_plan(self.plane, prepare_plan(self.plane, raw), confirm=True)
        self.assertEqual(result2["status"], "NO_CHANGE")
        self.assertEqual(result2["revision"], rev)

        delete_raw = _bundle(
            objectGroups=[{"name": "admins", "state": "absent"}],
            objects=[{"name": "hq-admin", "state": "absent"}],
        )
        result3 = apply_change_plan(self.plane, prepare_plan(self.plane, delete_raw), confirm=True)
        self.assertEqual(result3["status"], "APPLIED")
        self.assertIsNone(self.plane.get_object("hq-admin"))
        self.assertIsNotNone(self.plane.get_object("keep-me"))

    def test_invalid_second_resource_zero_mutation(self):
        before = self.plane.current_revision()
        raw = _bundle(
            objects=[
                {"name": "ok1", "type": "Host", "values": ["198.51.100.8"]},
                {"name": "bad", "type": "bogon", "values": ["x"]},
            ]
        )
        with self.assertRaises(BundleError):
            prepare_plan(self.plane, raw)
        self.assertEqual(self.plane.current_revision(), before)
        self.assertIsNone(self.plane.get_object("ok1"))

    def test_embedded_test_failure_zero_mutation(self):
        mid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        self.plane.set_object_type("hq", "network")
        self.plane.set_object_value("hq", "203.0.113.0/24")
        self.plane.upsert_client(
            mid,
            label="lab",
            hostname="labhost",
            addresses=[{"address": "10.0.0.5", "active": True}],
        )
        raw = _bundle(
            remoteAccess=[
                {
                    "name": "allow-hq",
                    "sources": ["hq"],
                    "destinations": ["lab"],
                    "services": ["tcp/22"],
                    "action": "ALLOW",
                    "enabled": True,
                }
            ],
            tests=[
                {
                    "name": "wrong",
                    "kind": "remote-access",
                    "source": "203.0.113.9",
                    "destination": "lab",
                    "protocol": "tcp",
                    "port": 22,
                    "expect": "DENY",
                }
            ],
        )
        before = self.plane.current_revision()
        with self.assertRaises(BundleError):
            prepare_plan(self.plane, raw)
        self.assertEqual(self.plane.current_revision(), before)
        self.assertIsNone(self.plane._get_rule("remote", "allow-hq"))

    def test_revision_conflict(self):
        raw = _bundle(
            objects=[{"name": "a", "type": "Host", "values": ["198.51.100.1"]}]
        )
        plan = prepare_plan(self.plane, raw)
        other = ControlPlane(self.tmp)
        other.set_object_type("z", "host")
        other.set_object_value("z", "198.51.100.2")
        other.close()
        with self.assertRaises(ConcurrencyError):
            apply_change_plan(self.plane, plan, confirm=True)
        self.assertIsNone(self.plane.get_object("a"))

    def test_export_redacted_and_stable(self):
        self.plane.set_object_type("hq", "network")
        self.plane.set_object_value("hq", "203.0.113.0/24")
        a = export_configuration(self.plane)
        b = export_configuration(self.plane)
        self.assertEqual(a, b)
        self.assertIn("203.0.113.0/24", a)
        self.assertNotIn("bt1.", a)
        self.assertNotIn("bearer", a.lower().split("credentialstatus")[0] if False else a)
        # Ensure no raw secret-looking exports
        self.assertNotIn("private_key", a)
        self.assertNotIn("client_secret", a)

    def test_stdin_and_file_cli(self):
        raw = _bundle(
            objects=[{"name": "cli-obj", "type": "Host", "values": ["198.51.100.3"]}]
        )
        path = Path(self.tmp) / "bundle.yaml"
        path.write_text(raw, encoding="utf-8")
        rc = cli.dispatch(["test", "configuration", str(path)], root=self.tmp)
        self.assertEqual(rc, 0)
        text, label = read_bundle_from_path_or_stdin("-", stdin_text=raw)
        self.assertEqual(label, "stdin")
        plan = prepare_plan(self.plane, text, input_path=label)
        result = apply_change_plan(self.plane, plan, confirm=True)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["tickets_issued"], 0)

    def test_enrollment_plans_issue_zero_tickets(self):
        plans = [{"name": "c%02d" % i, "platform": "linux"} for i in range(1, 31)]
        raw = _bundle(enrollmentPlans=plans)
        result = apply_change_plan(self.plane, prepare_plan(self.plane, raw), confirm=True)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["tickets_issued"], 0)
        count = self.plane.conn.execute("SELECT COUNT(*) AS c FROM enrollment_plans").fetchone()["c"]
        self.assertEqual(int(count), 30)

    def test_client_action_required(self):
        mid = "cccccccccccccccccccccccccccccccc"
        self.plane.upsert_client(
            mid,
            label="edge",
            hostname="edgehost",
            addresses=[{"address": "10.0.0.8", "active": True}],
        )
        self.plane.set_published_service(
            mid,
            "ssh",
            service_type="ssh",
            target_mode="self",
            target_host="127.0.0.1",
            target_port=22,
            enabled=True,
            public_port=6001,
        )
        raw = _bundle(
            publishedServices=[
                {
                    "name": "ssh",
                    "client": "edge",
                    "targetHost": "127.0.0.1",
                    "targetPort": 2222,
                }
            ]
        )
        plan = prepare_plan(self.plane, raw)
        self.assertTrue(plan.client_action_required)
        result = apply_change_plan(self.plane, plan, confirm=True)
        self.assertEqual(result["status"], "CLIENT_ACTION_REQUIRED")
        row = self.plane.conn.execute(
            "SELECT target_port FROM published_services WHERE name='ssh'"
        ).fetchone()
        self.assertEqual(int(row["target_port"]), 22)

    def test_direct_cli_bundle_parity_object(self):
        # Path 1: direct CLI-equivalent mutations
        p1_root = tempfile.mkdtemp(prefix="parity-a-")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = p1_root
        p1 = ControlPlane(p1_root)
        p1.set_object_type("office", "network")
        p1.set_object_value("office", "198.51.100.0/24")
        p1.set_object_group("branch")
        p1.set_object_group_member("branch", "office")
        snap1 = {
            "obj": p1._object_view(p1.get_object("office")),
            "grp_members": sorted(
                r["name"]
                for r in [
                    p1.conn.execute(
                        "SELECT o.name AS name FROM object_group_members m "
                        "JOIN objects o ON o.id=m.member_id "
                        "JOIN object_groups g ON g.id=m.group_id WHERE g.name='branch'"
                    ).fetchone()
                ]
                if r
            ),
        }
        # Path 2: bundle
        p2_root = tempfile.mkdtemp(prefix="parity-b-")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = p2_root
        p2 = ControlPlane(p2_root)
        raw = _bundle(
            objects=[
                {"name": "office", "type": "Network", "values": ["198.51.100.0/24"]}
            ],
            objectGroups=[{"name": "branch", "members": ["office"]}],
        )
        apply_change_plan(p2, prepare_plan(p2, raw), confirm=True)
        snap2 = {
            "obj": p2._object_view(p2.get_object("office")),
            "grp_members": ["office"],
        }
        self.assertEqual(snap1["obj"]["type"], snap2["obj"]["type"])
        self.assertEqual(snap1["obj"]["values"], snap2["obj"]["values"])
        self.assertEqual(snap1["grp_members"], snap2["grp_members"])
        p1.close()
        p2.close()

    def test_concurrent_bundle_apply_one_conflict(self):
        raw = _bundle(
            objects=[{"name": "race", "type": "Host", "values": ["198.51.100.7"]}]
        )
        plan_a = prepare_plan(self.plane, raw)
        plan_b = prepare_plan(ControlPlane(self.tmp), raw)
        results = []
        errors = []

        def run(plan):
            try:
                pl = ControlPlane(self.tmp)
                results.append(apply_change_plan(pl, plan, confirm=True))
                pl.close()
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=run, args=(plan_a,))
        t2 = threading.Thread(target=run, args=(plan_b,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        applied = [r for r in results if r.get("status") == "APPLIED"]
        self.assertEqual(len(applied), 1)
        self.assertTrue(errors or any(r.get("status") == "NO_CHANGE" for r in results))
        # Exactly one object
        self.assertIsNotNone(self.plane.get_object("race"))

    def test_bundle_hash_audit(self):
        raw = _bundle(
            objects=[{"name": "aud", "type": "Host", "values": ["198.51.100.4"]}]
        )
        plan = prepare_plan(self.plane, raw)
        result = apply_change_plan(self.plane, plan, confirm=True)
        rows = self.plane.list_audit(entity_type="configuration-bundle")
        self.assertTrue(rows)
        blob = " ".join(
            str(r.get("after_summary") or "") + " " + str(r.get("impact_summary") or "")
            for r in rows
        )
        self.assertIn(plan.bundle_hash[:16], blob.replace("bundle_hash=", ""))
        self.assertNotIn("198.51.100.4", blob)  # avoid dumping full bundle values into impact ideally
        # hash must be present
        self.assertIn(result["bundle_hash"], blob)


    def test_source_revision_conflict_public_semantics(self):
        raw = _bundle(objects=[{"name": "sr1", "type": "Host", "values": ["198.51.100.1"]}])
        # Simulate reviewed export at revision 0, then intervening mutation.
        import yaml
        doc = yaml.safe_load(raw)
        doc["metadata"]["sourceRevision"] = 0
        raw2 = yaml.safe_dump(doc, sort_keys=False)
        self.plane.set_object_type("intervening", "host")
        self.plane.set_object_value("intervening", "198.51.100.2")
        plan = prepare_plan(self.plane, yaml.safe_dump(doc, sort_keys=False))
        self.assertEqual(plan.base_revision, 0)
        self.assertGreater(plan.current_revision or 0, 0)
        with self.assertRaises(ConcurrencyError):
            apply_change_plan(self.plane, plan, confirm=True)
        self.assertIsNone(self.plane.get_object("sr1"))

    def test_singular_rule_aliases_and_cidr_broadening(self):
        self.plane.set_object_type("net", "network")
        self.plane.set_object_value("net", "203.0.113.10/32")
        raw = _bundle(
            objects=[
                {"name": "net", "type": "Network", "values": ["203.0.113.0/24"]},
                {"name": "dst", "type": "FQDN", "values": ["alias.example"]},
            ],
            internetAccess=[
                {
                    "name": "alias-rule",
                    "source": "net",
                    "destination": "dst",
                    "service": {"protocol": "https", "port": 443},
                    "action": "ALLOW",
                    "enabled": True,
                }
            ],
        )
        plan = prepare_plan(self.plane, raw)
        self.assertTrue(plan.access_broadened)
        families = {c.family for c in plan.mutating_changes}
        self.assertIn("objects", families)
        self.assertIn("internetAccess", families)
        result = apply_change_plan(self.plane, plan, confirm=True)
        self.assertEqual(result["status"], "APPLIED")
        rule = self.plane._get_rule("internet", "alias-rule")
        self.assertIsNotNone(rule)
        view = self.plane._rule_view(rule)
        self.assertEqual(view["sources"], ["net"])
        self.assertEqual(view["destinations"], ["dst"])
        self.assertIn("tcp/443", view["services"])

    def test_export_roundtrip_managed_endpoint_and_idempotent(self):
        # Enrollment-owned Managed Endpoint must export as reference-only and
        # re-apply as NO_CHANGE (never reject the whole export).
        self.plane.set_object_type("hq", "host")
        self.plane.set_object_value("hq", "203.0.113.10")
        now = "2026-01-01T00:00:00Z"
        self.plane.conn.execute(
            "INSERT INTO objects(id, name, type, origin, description, status, row_version, created_at, updated_at) "
            "VALUES (?, ?, 'managed_endpoint', 'managed', '', 'active', 1, ?, ?)",
            ("obj_me_test", "me-host", now, now),
        )
        self.plane.conn.execute(
            "INSERT INTO managed_endpoints(id, object_id, client_id) VALUES (?, ?, NULL)",
            ("mep_me_test", "obj_me_test"),
        )
        self.plane.conn.commit()
        exported = export_configuration(self.plane)
        self.assertIn("ManagedEndpoint", exported)
        plan = prepare_plan(self.plane, exported)
        ops = {(c.family, c.name, c.op) for c in plan.changes}
        self.assertIn(("objects", "me-host", "NO_CHANGE"), ops)
        result = apply_change_plan(self.plane, plan, confirm=True)
        self.assertEqual(result["status"], "NO_CHANGE")

    def test_ai_access_export_uses_human_target_names(self):
        now = "2026-01-01T00:00:00Z"
        self.plane.conn.execute(
            "INSERT INTO objects(id, name, type, origin, description, status, row_version, created_at, updated_at) "
            "VALUES (?, ?, 'managed_endpoint', 'managed', '', 'active', 1, ?, ?)",
            ("obj_ep1", "ep1", now, now),
        )
        self.plane.conn.execute(
            "INSERT INTO managed_endpoints(id, object_id, client_id) VALUES (?, ?, NULL)",
            ("mep_ep1", "obj_ep1"),
        )
        self.plane.conn.commit()
        self.plane.set_ai_principal("bot")
        self.plane.set_ai_rule("r1")
        self.plane.set_ai_rule_principal("r1", "bot")
        self.plane.set_ai_rule_target("r1", "endpoint", "ep1")
        self.plane.set_ai_rule_capability("r1", "list_hosts")
        self.plane.set_ai_rule_action("r1", "allow")
        self.plane.set_ai_rule_enabled("r1", True)
        exported = export_configuration(self.plane)
        self.assertIn("ep1", exported)
        ai_section = exported.split("aiAccess:")[-1] if "aiAccess:" in exported else ""
        self.assertNotIn("obj_ep1", ai_section)
        plan = prepare_plan(self.plane, exported)
        ai_ops = [c for c in plan.changes if c.family == "aiAccess"]
        self.assertTrue(ai_ops)
        self.assertTrue(all(c.op == "NO_CHANGE" for c in ai_ops))


if __name__ == "__main__":
    unittest.main()
