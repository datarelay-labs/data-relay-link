#!/usr/bin/env python3
"""Time-bounded Managed Host liveness for public CLI and MCP."""
from __future__ import annotations

import io
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_db import utc_now_iso  # noqa: E402
from drlink_ai_agent import (  # noqa: E402
    AI_AGENT_BUSY_POLL_SECONDS,
    AI_AGENT_IDLE_POLL_SECONDS,
)
from drlink_control_plane import (  # noqa: E402
    MANAGED_HOST_LIVENESS_REFRESH_SECONDS,
    MANAGED_HOST_LIVENESS_SECONDS,
    ControlPlane,
    ControlPlaneError,
)
from drlink_mcp_bridge import MCPBridge  # noqa: E402
import drlink_v24 as v24  # noqa: E402
import drlink_v24_cli as cli  # noqa: E402

STALE_SEEN = "2026-09-19T08:29:50Z"
HOST = "Expernet"
MACHINE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _verify(plane: ControlPlane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'active', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.commit_if_autonomous()


class ManagedHostLivenessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-liveness-")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_AI_TEST_LOCAL_EXEC", None)
        os.environ.pop("DRLINK_AI_TEST_LOCAL_AGENTS", None)
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        self.plane = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.plane.conn)
        self.plane.upsert_client(MACHINE, label=HOST, hostname="expernet-dp1", connected=True)
        self.plane.upsert_client(OTHER, label="other-host", hostname="other", connected=True)
        self._age(MACHINE, STALE_SEEN, connected=1, status="connected", trust="trusted")
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        self.principal = self.plane.get_principal("bot")
        v24.set_permission_object(
            self.plane, "read-only", permissions=["host-info"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            "allow-info",
            mode="whitelist",
            source="bot",
            destination=HOST,
            permission="read-only",
            enabled=True,
            oneshot=True,
        )
        self.bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)

    def tearDown(self):
        self.bridge.close()
        self.plane.close()
        for key in ("FRP_DEPLOY_TEST_ROOT", "DRLINK_TEST_ROOT", "DRLINK_CONFIRM"):
            os.environ.pop(key, None)

    def _age(self, client_id, last_seen, *, connected, status, trust):
        self.plane.conn.execute(
            "UPDATE clients SET last_seen = ?, connected = ?, status = ?, trust_status = ? WHERE id = ?",
            (last_seen, connected, status, trust, client_id),
        )
        self.plane.commit_if_autonomous()

    def _client(self, client_id):
        return self.plane.conn.execute(
            "SELECT * FROM clients WHERE id = ?", (client_id,)
        ).fetchone()

    def _show(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.handle_show(self.plane, list(args))
        return buf.getvalue()

    def test_connected_host_without_ai_worker_stays_online(self):
        row = self._client(MACHINE)
        self.assertEqual(int(row["connected"]), 1)
        self.assertEqual(row["status"], "connected")
        self.assertEqual(row["last_seen"], STALE_SEEN)
        self.assertFalse(self.plane.ai_executor_ready(row))
        self.assertEqual(self.plane.ai_executor_status(row), "not_ready")
        self.assertEqual(self.plane.managed_host_connectivity(row), "connected")
        listed = self._show("managed-hosts")
        self.assertIn("%s expernet-dp1 connected" % HOST, listed)
        self.assertNotIn("%s expernet-dp1 disconnected" % HOST, listed)
        overview = self._show("managed-host", HOST)
        self.assertIn("Status: connected", overview)
        self.assertIn("Agent: Connected", overview)
        self.assertIn("AI executor: not_ready", overview)
        agent = self._show("managed-host", HOST, "agent")
        self.assertIn("Connection   : Connected", agent)
        self.assertIn("Host status  : connected", agent)
        self.assertIn("AI executor  : not_ready", agent)
        listed_hosts = self.bridge.call_tool(self.principal, "list_hosts", {})
        text = listed_hosts["content"][0]["text"]
        self.assertIn(HOST, text)
        self.assertIn('"connectivity": "connected"', text)
        self.assertIn('"ai_executor": "not_ready"', text)
        self.assertNotIn('"connectivity": "disconnected"', text)
        fresh = self._client(OTHER)
        self.assertTrue(self.plane.client_effectively_connected(fresh))
        self.assertIn("other-host other connected", listed)

    def test_stale_dispatch_fails_closed_without_job_timeout(self):
        started = time.monotonic()
        result = self.bridge.call_tool(
            self.principal, "get_system_info", {"endpoint": HOST}
        )
        elapsed = time.monotonic() - started
        text = result["content"][0]["text"]
        self.assertLess(elapsed, 2.0)
        self.assertIn("Authorization: ALLOW", text)
        self.assertIn("endpoint unavailable", text)
        self.assertNotIn("TIMEOUT", text)
        queued = self.plane.conn.execute("SELECT COUNT(*) FROM ai_jobs").fetchone()[0]
        self.assertEqual(int(queued), 0)

    def test_claim_and_complete_refresh_liveness_without_reviving_revoked(self):
        self.assertFalse(self.plane.client_effectively_connected(self._client(MACHINE)))
        self.plane.claim_ai_jobs(MACHINE, limit=1)
        self.assertTrue(self.plane.client_effectively_connected(self._client(MACHINE)))
        self.assertLessEqual(
            MANAGED_HOST_LIVENESS_SECONDS,
            120,
        )
        self._age(MACHINE, STALE_SEEN, connected=1, status="connected", trust="trusted")
        job_id = self.plane.enqueue_ai_job(
            principal_id=self.principal["id"],
            endpoint_object_id=self.plane.get_object(HOST)["id"],
            client_id=MACHINE,
            capability="get_system_info",
            arguments={},
            patterns=[],
            timeout=5,
        )
        claimed = self.plane.claim_ai_jobs(MACHINE, limit=4)
        match = next(item for item in claimed if item["id"] == job_id)
        self._age(MACHINE, STALE_SEEN, connected=1, status="connected", trust="trusted")
        self.plane.complete_ai_job(
            job_id,
            MACHINE,
            {"result": "ALLOW"},
            claim_token=match["claim_token"],
            attempt_id=match["attempt_id"],
        )
        refreshed = self._client(MACHINE)
        self.assertNotEqual(refreshed["last_seen"], STALE_SEEN)
        self.assertTrue(self.plane.client_effectively_connected(refreshed))
        self.assertEqual(
            self.plane.get_ai_job(job_id)["status"],
            "done",
        )
        self._age(OTHER, STALE_SEEN, connected=1, status="connected", trust="revoked")
        with self.assertRaises(ControlPlaneError):
            self.plane.claim_ai_jobs(OTHER, limit=1)
        revoked = self._client(OTHER)
        self.assertEqual(revoked["last_seen"], STALE_SEEN)
        self.assertEqual(revoked["trust_status"], "revoked")
        self.assertFalse(self.plane.client_effectively_connected(revoked))
        with self.assertRaises(ControlPlaneError):
            self.plane.complete_ai_job(
                job_id,
                OTHER,
                {"result": "ALLOW"},
                claim_token=match["claim_token"],
                attempt_id=match["attempt_id"],
            )

    def test_metadata_upsert_does_not_revive_stale_liveness(self):
        before = self._client(MACHINE)
        self.plane.upsert_client(
            MACHINE, label=HOST, hostname="expernet-dp1", connected=True
        )
        after = self._client(MACHINE)
        self.assertEqual(after["last_seen"], STALE_SEEN)
        self.assertEqual(after["last_seen"], before["last_seen"])
        self.assertFalse(self.plane.ai_executor_ready(after))
        self.assertEqual(int(after["connected"]), 1)
        self.assertEqual(self.plane.managed_host_connectivity(after), "connected")

    def test_repeated_claim_polls_do_not_rewrite_liveness(self):
        before_flag = int(self._client(MACHINE)["connected"])
        self.plane.claim_ai_jobs(MACHINE, limit=1)
        first = self._client(MACHINE)
        self.assertEqual(int(first["connected"]), before_flag)
        self.plane.claim_ai_jobs(MACHINE, limit=1)
        self.plane.refresh_managed_host_liveness(MACHINE)
        second = self._client(MACHINE)
        self.assertEqual(second["last_seen"], first["last_seen"])
        self.assertEqual(int(second["row_version"]), int(first["row_version"]))
        self.assertLess(MANAGED_HOST_LIVENESS_REFRESH_SECONDS, MANAGED_HOST_LIVENESS_SECONDS)
        self.assertGreaterEqual(AI_AGENT_IDLE_POLL_SECONDS, 1.0)
        self.assertLess(AI_AGENT_IDLE_POLL_SECONDS, MANAGED_HOST_LIVENESS_SECONDS)
        self.assertLessEqual(AI_AGENT_BUSY_POLL_SECONDS, 0.2)

    def test_explicit_disconnect_is_not_reported_as_stale(self):
        self._age(MACHINE, utc_now_iso(), connected=0, status="disconnected", trust="trusted")
        row = self._client(MACHINE)
        self.assertEqual(self.plane.managed_host_connectivity(row), "disconnected")
        self.assertFalse(self.plane.ai_executor_ready(row))

    def test_fresh_upsert_stays_inside_liveness_bound(self):
        seen = self._client(OTHER)["last_seen"]
        self.assertTrue(seen)
        self.assertNotEqual(seen, STALE_SEEN)
        self.assertTrue(seen <= utc_now_iso())
        self.assertTrue(self.plane.client_effectively_connected(self._client(OTHER)))


if __name__ == "__main__":
    unittest.main()
