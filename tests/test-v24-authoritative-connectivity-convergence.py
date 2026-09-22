#!/usr/bin/env python3
"""P0: authoritative Object/Policy state must equal runtime connectivity projection.

Covers the common fail-open class across Findings Q/R/S/T/V/W/X:
Service Object / Network Object / Managed Host / Fixed TCP mutations must not
leave BLACKLIST unmatched ALLOW against stale published targets.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
import drlink_mgmt_sync as mgmt
import drlink_runtime_policy as RP
import drlink_upgrade_reconcile as UR
import drlink_v24 as v24
from drlink_v24_runtime import remote_service_proxy_id
import frp_mgmt_auth as MGMT

OWNER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEST_MH = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _auth(mid: str = OWNER) -> mgmt.MgmtAuthContext:
    return mgmt.MgmtAuthContext(mid, {"id": mid}, "nonce", 1, allocator=None)


class AuthoritativeConnectivityConvergence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-authz-conv-")
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        self.plane.upsert_client(
            OWNER,
            label="relay-a",
            hostname="relay-a",
            addresses=[{"address": "10.0.0.10", "active": True}],
        )
        v24.set_network_object(
            self.plane, "blocked-src", type="ip", value="198.51.100.9", oneshot=True
        )
        v24.ensure_policy_mode(self.plane, "remote", "blacklist", oneshot=True)
        v24.ensure_policy_mode(self.plane, "internet", "blacklist", oneshot=True)

    def tearDown(self):
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_CONFIRM", "DRLINK_SKIP_ACTIVATION"):
            os.environ.pop(key, None)

    def _proxy(self, name: str) -> str:
        return RP.expected_proxy_name("relay-a", OWNER, remote_service_proxy_id(name))

    def _ready(self):
        # SKIP_ACTIVATION suppresses automatic compile; publish generations for authorize.
        self.plane.compile_runtime()

    def test_service_object_port_edit_converges_and_keeps_blacklist_deny(self):
        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="db.expected.invalid", oneshot=True
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-db",
            mode="blacklist",
            source="blocked-src",
            destination="db-target",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        result = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-db",
                "destination": "db-target",
                "service": "ssh",
                "enabled": True,
                "target_host": "wrong.invalid",
                "target_port": 2222,
                "runtime_verified": True,
            },
        )
        self.assertEqual(result["target_port"], 22)
        self.assertEqual(result["target_host"], "db.expected.invalid")
        self.assertEqual(result["status"], "HEALTHY")
        self._ready()

        before = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-db"), source_ip="198.51.100.9"
        )
        self.assertEqual(before["decision"], RP.DECISION_DENY)

        v24.set_service_object(self.plane, "ssh", type="tcp", port=2222, oneshot=True)
        pub = self.plane.conn.execute(
            "SELECT target_port, target_host FROM published_services WHERE name='svc-db'"
        ).fetchone()
        self.assertEqual(int(pub["target_port"]), 2222)
        self._ready()
        after = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-db"), source_ip="198.51.100.9"
        )
        self.assertEqual(after["decision"], RP.DECISION_DENY)
        eval_result = self.plane.evaluate_remote_access(
            "198.51.100.9", "db.expected.invalid", "tcp", 2222
        )
        self.assertEqual(str(eval_result.get("action") or "").upper(), "DENY")

    def test_server_rejects_or_derives_contradictory_agent_target(self):
        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="expected.invalid", oneshot=True
        )
        result = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-mismatch",
                "destination": "db-target",
                "service": "ssh",
                "enabled": True,
                "target_host": "other.invalid",
                "target_port": 2222,
                "runtime_verified": True,
            },
        )
        self.assertEqual(result["target_host"], "expected.invalid")
        self.assertEqual(result["target_port"], 22)
        pub = self.plane.conn.execute(
            "SELECT target_host, target_port FROM published_services WHERE name='svc-mismatch'"
        ).fetchone()
        self.assertEqual(pub["target_host"], "expected.invalid")
        self.assertEqual(int(pub["target_port"]), 22)

    def test_network_object_edit_converges_routed_target_and_blacklist(self):
        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="old.invalid", oneshot=True
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-db",
            mode="blacklist",
            source="blocked-src",
            destination="db-target",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-db",
                "destination": "db-target",
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self._ready()
        before = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-db"), source_ip="198.51.100.9"
        )
        self.assertEqual(before["decision"], RP.DECISION_DENY)

        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="new.invalid", oneshot=True
        )
        pub = self.plane.conn.execute(
            "SELECT target_host FROM published_services WHERE name='svc-db'"
        ).fetchone()
        self.assertEqual(pub["target_host"], "new.invalid")
        self._ready()
        after = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-db"), source_ip="198.51.100.9"
        )
        self.assertEqual(after["decision"], RP.DECISION_DENY)
        stale = self.plane.evaluate_remote_access(
            "198.51.100.9", "old.invalid", "tcp", 22
        )
        # Stale host must not remain the live projection; policy for old host may
        # no longer match, but authorize_remote uses the rematerialized target.
        self.assertNotEqual(pub["target_host"], "old.invalid")
        self.assertEqual(str(stale.get("action") or "").upper(), "ALLOW")

    def test_stale_projection_is_not_healthy_and_not_authorized(self):
        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="expected.invalid", oneshot=True
        )
        mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-db",
                "destination": "db-target",
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.plane.conn.execute(
            "UPDATE published_services SET target_host = 'other.invalid' WHERE name='svc-db'"
        )
        self.plane.conn.commit()
        pub = self.plane.conn.execute(
            "SELECT * FROM published_services WHERE name='svc-db'"
        ).fetchone()
        meta = self.plane.conn.execute(
            "SELECT * FROM remote_service_meta WHERE service_id = ?", (pub["id"],)
        ).fetchone()
        status, reason, _ = UR.effective_remote_service_status(
            self.plane, pub, meta, {}, registry_available=False
        )
        self.assertEqual(status, "DEGRADED")
        self.assertIn("diverges", reason.lower())
        self._ready()
        verdict = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-db"), source_ip="198.51.100.9"
        )
        self.assertEqual(verdict["decision"], RP.DECISION_DENY)
        self.assertEqual(verdict["reason"], "AUTHORITATIVE_TARGET_MISMATCH")

    def test_managed_host_address_churn_converges_routed_target(self):
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-dbhost",
            mode="blacklist",
            source="blocked-src",
            destination="db-host",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        result = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-dbhost",
                "destination": "db-host",
                "destination_client_id": DEST_MH,
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.assertEqual(result["target_host"], "10.0.0.20")
        self._ready()
        before = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-dbhost"), source_ip="198.51.100.9"
        )
        self.assertEqual(before["decision"], RP.DECISION_DENY)

        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.21", "active": True}],
        )
        pub = self.plane.conn.execute(
            "SELECT target_host FROM published_services WHERE name='svc-dbhost'"
        ).fetchone()
        self.assertEqual(pub["target_host"], "10.0.0.21")
        self._ready()
        after = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-dbhost"), source_ip="198.51.100.9"
        )
        self.assertEqual(after["decision"], RP.DECISION_DENY)

    def test_fixed_tcp_object_edit_keeps_internet_blacklist_deny(self):
        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="old.invalid", oneshot=True
        )
        self.plane.set_fixed_tcp(
            "db-relay",
            destination_object="db-target",
            dest_port=22,
            listen_port=6201,
            enabled=True,
        )
        v24.set_access_rule(
            self.plane,
            "internet",
            "block-db",
            mode="blacklist",
            source="blocked-src",
            destination="db-target",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        self._ready()
        before = RP.authorize_fixed_tcp(
            self.plane, relay_id="db-relay", source_ip="198.51.100.9"
        )
        self.assertEqual(before["decision"], RP.DECISION_DENY)

        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="new.invalid", oneshot=True
        )
        row = self.plane.conn.execute(
            "SELECT dest_host FROM fixed_tcp WHERE name='db-relay'"
        ).fetchone()
        self.assertEqual(row["dest_host"], "new.invalid")
        self._ready()
        after = RP.authorize_fixed_tcp(
            self.plane, relay_id="db-relay", source_ip="198.51.100.9"
        )
        self.assertEqual(after["decision"], RP.DECISION_DENY)
        self.assertEqual(after["hostname"], "new.invalid")

    def test_managed_host_destination_rejects_other_host_client_id(self):
        other = "cccccccccccccccccccccccccccccccc"
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        self.plane.upsert_client(
            other,
            label="other-host",
            hostname="other-host",
            addresses=[{"address": "10.0.0.30", "active": True}],
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-dbhost",
            mode="blacklist",
            source="blocked-src",
            destination="db-host",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        with self.assertRaises(mgmt.MgmtSyncError) as ctx:
            mgmt.server_upsert_remote_service(
                self.plane,
                _auth(),
                {
                    "name": "svc-bad-bind",
                    "destination": "db-host",
                    "destination_client_id": other,
                    "service": "ssh",
                    "enabled": True,
                    "runtime_verified": True,
                },
            )
        self.assertIn("does not match", str(ctx.exception).lower())
        pub = self.plane.conn.execute(
            "SELECT id FROM published_services WHERE name='svc-bad-bind' AND released=0"
        ).fetchone()
        self.assertIsNone(pub)

    def test_managed_host_destination_rejects_owner_client_id_self_bypass(self):
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-dbhost",
            mode="blacklist",
            source="blocked-src",
            destination="db-host",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        with self.assertRaises(mgmt.MgmtSyncError) as ctx:
            mgmt.server_upsert_remote_service(
                self.plane,
                _auth(),
                {
                    "name": "svc-owner-bypass",
                    "destination": "db-host",
                    "destination_client_id": OWNER,
                    "service": "ssh",
                    "enabled": True,
                    "runtime_verified": True,
                    "target_host": "127.0.0.1",
                    "target_mode": "self",
                },
            )
        self.assertIn("does not match", str(ctx.exception).lower())

    def test_contradictory_binding_rows_fail_closed_and_blacklist_stays_deny(self):
        other = "cccccccccccccccccccccccccccccccc"
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        self.plane.upsert_client(
            other,
            label="other-host",
            hostname="other-host",
            addresses=[{"address": "10.0.0.30", "active": True}],
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-dbhost",
            mode="blacklist",
            source="blocked-src",
            destination="db-host",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        # Seed a contradictory legacy projection that older code would accept.
        result = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-legacy",
                "destination": "db-host",
                "destination_client_id": DEST_MH,
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.assertEqual(result["status"], "HEALTHY")
        self.assertEqual(result["target_host"], "10.0.0.20")
        pub = self.plane.conn.execute(
            "SELECT * FROM published_services WHERE name='svc-legacy'"
        ).fetchone()
        self.plane.conn.execute(
            "UPDATE published_services SET target_host = '10.0.0.30', target_mode = 'routed' "
            "WHERE id = ?",
            (pub["id"],),
        )
        self.plane.conn.execute(
            "UPDATE remote_service_meta SET destination_client_id = ? WHERE service_id = ?",
            (other, pub["id"]),
        )
        self.plane.conn.commit()
        pub = self.plane.conn.execute(
            "SELECT * FROM published_services WHERE name='svc-legacy'"
        ).fetchone()
        meta = self.plane.conn.execute(
            "SELECT * FROM remote_service_meta WHERE service_id = ?", (pub["id"],)
        ).fetchone()
        status, reason, _ = UR.effective_remote_service_status(
            self.plane, pub, meta, {}, registry_available=False
        )
        self.assertEqual(status, "DEGRADED")
        self.assertTrue(reason)
        self._ready()
        verdict = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-legacy"), source_ip="198.51.100.9"
        )
        self.assertEqual(verdict["decision"], RP.DECISION_DENY)
        expected_policy = self.plane.evaluate_remote_access(
            "198.51.100.9", "db-host", "tcp", 22
        )
        self.assertEqual(str(expected_policy.get("action") or "").upper(), "DENY")

    def test_network_object_destination_rejects_managed_host_binding(self):
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        v24.set_network_object(
            self.plane, "db-target", type="fqdn", value="expected.invalid", oneshot=True
        )
        with self.assertRaises(mgmt.MgmtSyncError) as ctx:
            mgmt.server_upsert_remote_service(
                self.plane,
                _auth(),
                {
                    "name": "svc-fqdn",
                    "destination": "db-target",
                    "destination_client_id": DEST_MH,
                    "service": "ssh",
                    "enabled": True,
                    "runtime_verified": True,
                },
            )
        self.assertIn("not valid for network object", str(ctx.exception).lower())

    def test_valid_managed_host_binding_stable_across_label_hostname_address_churn(self):
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host.internal",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-dbhost",
            mode="blacklist",
            source="blocked-src",
            destination="db-host",
            service="ssh",
            enabled=True,
            oneshot=True,
        )
        result = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-stable",
                "destination": "db-host",
                "destination_client_id": DEST_MH,
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.assertEqual(result["destination_client_id"], DEST_MH)
        self.assertEqual(result["target_host"], "10.0.0.20")
        self.assertEqual(result["status"], "HEALTHY")
        before_port = result["endpoint_port"]

        self.plane.set_client_label(DEST_MH, "database-prod-renamed")
        # Stale destination label + correct immutable bind remains accepted.
        result2 = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-stable",
                "destination": "db-host",
                "destination_client_id": DEST_MH,
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.assertEqual(result2["destination_client_id"], DEST_MH)
        self.assertEqual(result2["endpoint_port"], before_port)

        self.plane.upsert_client(
            DEST_MH,
            label="database-prod-renamed",
            hostname="db-host-new.internal",
            addresses=[{"address": "10.0.0.21", "active": True}],
        )
        pub = self.plane.conn.execute(
            "SELECT target_host FROM published_services WHERE name='svc-stable'"
        ).fetchone()
        self.assertEqual(pub["target_host"], "10.0.0.21")
        meta = self.plane.conn.execute(
            "SELECT m.destination_client_id FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id WHERE s.name='svc-stable'"
        ).fetchone()
        self.assertEqual(meta["destination_client_id"], DEST_MH)
        self._ready()
        after = RP.authorize_remote(
            self.plane, proxy_name=self._proxy("svc-stable"), source_ip="198.51.100.9"
        )
        self.assertEqual(after["decision"], RP.DECISION_DENY)

    def test_new_service_rejects_unresolved_destination_with_arbitrary_managed_host_id(self):
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        with self.assertRaises(mgmt.MgmtSyncError) as ctx:
            mgmt.server_upsert_remote_service(
                self.plane,
                _auth(),
                {
                    "name": "svc-stale-alias",
                    "destination": "old-db-label",
                    "destination_client_id": DEST_MH,
                    "service": "ssh",
                    "enabled": True,
                    "runtime_verified": True,
                },
            )
        self.assertIn("missing or invalid", str(ctx.exception).lower())
        pub = self.plane.conn.execute(
            "SELECT id FROM published_services WHERE name='svc-stale-alias' AND released=0"
        ).fetchone()
        self.assertIsNone(pub)

    def test_new_service_rejects_stale_label_even_with_current_managed_host_id(self):
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        with self.assertRaises(mgmt.MgmtSyncError) as ctx:
            mgmt.server_upsert_remote_service(
                self.plane,
                _auth(),
                {
                    "name": "svc-new-stale",
                    "destination": "db-host-old-label",
                    "destination_client_id": DEST_MH,
                    "service": "ssh",
                    "enabled": True,
                    "runtime_verified": True,
                },
            )
        self.assertIn("missing or invalid", str(ctx.exception).lower())
        pub = self.plane.conn.execute(
            "SELECT id FROM published_services WHERE name='svc-new-stale' AND released=0"
        ).fetchone()
        self.assertIsNone(pub)

    def test_existing_service_rename_continuity_requires_server_prior_bind(self):
        other = "cccccccccccccccccccccccccccccccc"
        self.plane.upsert_client(
            DEST_MH,
            label="db-host",
            hostname="db-host",
            addresses=[{"address": "10.0.0.20", "active": True}],
        )
        self.plane.upsert_client(
            other,
            label="other-host",
            hostname="other-host",
            addresses=[{"address": "10.0.0.30", "active": True}],
        )
        created = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-rename",
                "destination": "db-host",
                "destination_client_id": DEST_MH,
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.assertEqual(created["status"], "HEALTHY")
        before_port = created["endpoint_port"]
        self.plane.set_client_label(DEST_MH, "database-prod-renamed")

        # Stale Agent label + Server-proven prior bind remains operable.
        continued = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-rename",
                "destination": "db-host",
                "destination_client_id": DEST_MH,
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.assertEqual(continued["destination_client_id"], DEST_MH)
        self.assertEqual(continued["endpoint_port"], before_port)
        self.assertEqual(continued["target_host"], "10.0.0.20")
        self.assertEqual(continued["status"], "HEALTHY")

        # Omitting Agent destination_client_id still uses Server prior bind.
        omitted = mgmt.server_upsert_remote_service(
            self.plane,
            _auth(),
            {
                "name": "svc-rename",
                "destination": "db-host",
                "service": "ssh",
                "enabled": True,
                "runtime_verified": True,
            },
        )
        self.assertEqual(omitted["destination_client_id"], DEST_MH)
        self.assertEqual(omitted["endpoint_port"], before_port)

        # Different Agent-supplied client ID must not hijack Server prior bind.
        with self.assertRaises(mgmt.MgmtSyncError) as ctx:
            mgmt.server_upsert_remote_service(
                self.plane,
                _auth(),
                {
                    "name": "svc-rename",
                    "destination": "db-host",
                    "destination_client_id": other,
                    "service": "ssh",
                    "enabled": True,
                    "runtime_verified": True,
                },
            )
        self.assertIn("does not match", str(ctx.exception).lower())
        meta = self.plane.conn.execute(
            "SELECT m.destination_client_id, s.public_port, s.target_host "
            "FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id "
            "WHERE s.name='svc-rename' AND s.released=0"
        ).fetchone()
        self.assertEqual(meta["destination_client_id"], DEST_MH)
        self.assertEqual(meta["public_port"], before_port)
        self.assertEqual(meta["target_host"], "10.0.0.20")


class AgentCatalogServiceAuthority(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-agent-cat-")
        Path(self.tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/frp/client-state.json").write_text(
            '{"machine_id":"%s","hostname":"relay-a","label":"relay-a"}\n' % OWNER,
            encoding="utf-8",
        )
        Path(self.tmp, "etc/frp/frpc.toml").write_text("[common]\n", encoding="utf-8")
        key = Path(self.tmp, "etc/frp/client-identity.key")
        pub = Path(self.tmp, "etc/frp/client-identity.pub")
        MGMT.generate_keypair(key, pub)
        os.chmod(key, 0o600)
        mac = MGMT.new_mac_key()
        Path(self.tmp, "etc/frp/client-identity.mac").write_text(mac, encoding="utf-8")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_SERVER_REACHABLE"] = "0"
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        # Local seeded Service Object shadows Server truth unless catalog wins.
        v24.set_service_object(self.plane, "ssh", type="tcp", port=22, oneshot=True)
        now = v24.utc_now_iso()
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) "
            "VALUES (?, ?, ?, ?)",
            ("service-object", "ssh", '{"name":"ssh","type":"tcp","port":2222}', now),
        )
        self.plane.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) "
            "VALUES (?, ?, ?, ?)",
            (
                "network-object",
                "db-target",
                '{"name":"db-target","type":"fqdn","values":["db.expected.invalid"]}',
                now,
            ),
        )
        self.plane.conn.commit()

    def tearDown(self):
        self.plane.close()
        for key in (
            "FRP_DEPLOY_TEST_ROOT",
            "DRLINK_CONFIRM",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_SERVER_REACHABLE",
        ):
            os.environ.pop(key, None)

    def test_agent_prefers_synced_service_object_over_local_seed(self):
        v24.set_remote_service_agent(
            self.plane,
            "svc-existing",
            destination="this-host",
            service="ssh",
            enabled=True,
            oneshot=True,
            root=self.tmp,
            server_reachable=False,
        )
        row = self.plane.conn.execute(
            "SELECT * FROM agent_remote_services WHERE name='svc-existing'"
        ).fetchone()
        self.assertIsNotNone(row)
        body = v24._agent_remote_service_mgmt_snapshot(
            self.plane, row, host_name="relay-a", root=self.tmp
        )
        self.assertEqual(int(body["target_port"]), 2222)


if __name__ == "__main__":
    unittest.main()
