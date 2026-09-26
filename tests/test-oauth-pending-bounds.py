#!/usr/bin/env python3
"""P1-OAUTH-2: pending authorization admission sweep and finite live caps."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import (  # noqa: E402
    OAUTH_PENDING_MAX_GLOBAL,
    OAUTH_PENDING_MAX_PER_CLIENT,
    OAUTH_PENDING_MAX_PER_SOURCE,
    OAUTH_PENDING_TTL,
    ControlPlane,
    OAuthPendingCapacityError,
)
from drlink_mcp_bridge import (  # noqa: E402
    OAUTH_AUTHORIZE_RATE_LIMIT,
    OAUTH_AUTHORIZE_RATE_WINDOW_S,
    MCPBridge,
    make_handler,
    trusted_oauth_source,
)

REDIRECT = "http://127.0.0.1/callback"
CHALLENGE = "pending-bounds-challenge"
RESOURCE = "drlink://ai"


def free_port() -> int:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _past() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=5)).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


class OAuthPendingBoundsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-oauth-pending-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_OAUTH_AUTO_APPROVE", None)
        self.plane = ControlPlane(self.tmp)
        self._stage("agent-a")

    def tearDown(self):
        self.plane.close()
        os.environ.pop("DRLINK_TEST_ROOT", None)
        os.environ.pop("DRLINK_CONFIRM", None)

    def _stage(self, name: str) -> None:
        dispatch(["set", "ai-principal", name], root=self.tmp)
        dispatch(["set", "ai-principal", name, "enabled"], root=self.tmp)
        dispatch(
            ["system", "credential", "configure", "ai-principal", name, "authentication", "oauth"],
            root=self.tmp,
        )
        dispatch(
            [
                "system",
                "credential",
                "configure",
                "ai-principal",
                name,
                "oauth-redirect",
                REDIRECT,
            ],
            root=self.tmp,
        )
        self.plane.conn.execute(
            "UPDATE ai_principals SET credential_status = 'pending' WHERE name = ?",
            (name,),
        )
        self.plane.conn.commit()

    def _create(self, client: str, state: str = "s", source: str = "") -> dict:
        return self.plane.create_oauth_pending(
            client_id=client,
            redirect_uri=REDIRECT,
            code_challenge=CHALLENGE,
            resource=RESOURCE,
            state=state,
            source=source,
        )

    def _live_ids(self, client: str | None = None) -> list[str]:
        if client is None:
            rows = self.plane.conn.execute("SELECT id, expires_at FROM ai_oauth_pending").fetchall()
        else:
            rows = self.plane.conn.execute(
                "SELECT id, expires_at FROM ai_oauth_pending WHERE client_id = ?",
                (client,),
            ).fetchall()
        return [row["id"] for row in rows if not self.plane._oauth_pending_expired(row)]

    def _fill(self, client: str, n: int) -> list[dict]:
        return [self._create(client, state="fill-%s-%s" % (client, i)) for i in range(n)]

    def _fill_source(self, client: str, source: str, n: int) -> list[dict]:
        return [
            self._create(client, state="src-%s-%s-%s" % (source, client, i), source=source)
            for i in range(n)
        ]

    def _live_ids_for_source(self, source: str) -> list[str]:
        rows = self.plane.conn.execute(
            "SELECT id, expires_at FROM ai_oauth_pending WHERE source_addr = ?",
            (source,),
        ).fetchall()
        return [row["id"] for row in rows if not self.plane._oauth_pending_expired(row)]

    def _insert_raw(self, *, client: str, principal_id: str, expires_at: str, status: str = "pending", code_plain: str = "", pending_id: str | None = None) -> str:
        pending_id = pending_id or ("oap_raw_%s" % secrets_token())
        now = _past()
        self.plane.conn.execute(
            "INSERT INTO ai_oauth_pending(id, principal_id, client_id, redirect_uri, code_challenge, resource, state, "
            "created_at, completion_token, status, expires_at, decision_at, consumed_at, code_plain) "
            "VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, '', '', ?)",
            (
                pending_id,
                principal_id,
                client,
                REDIRECT,
                CHALLENGE,
                RESOURCE,
                now,
                "tok-%s" % pending_id,
                status,
                expires_at,
                code_plain,
            ),
        )
        return pending_id

    def test_expired_rows_reclaimed_with_unused_code(self):
        principal = self.plane.get_principal("agent-a")
        self.assertIsNotNone(principal)
        kept = self._create("agent-a", state="keep")
        expired_code = "drc_expired_unused"
        expired_digest = hashlib.sha256(expired_code.encode("utf-8")).hexdigest()
        other_code = "drc_other_unused"
        other_digest = hashlib.sha256(other_code.encode("utf-8")).hexdigest()
        used_code = "drc_used_keep"
        used_digest = hashlib.sha256(used_code.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        for digest, used_at in (
            (expired_digest, None),
            (other_digest, None),
            (used_digest, now),
        ):
            self.plane.conn.execute(
                "INSERT INTO ai_oauth_codes(code_hash, principal_id, client_id, redirect_uri, code_challenge, "
                "resource, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    digest,
                    principal["id"],
                    "agent-a",
                    REDIRECT,
                    CHALLENGE,
                    RESOURCE,
                    now,
                    used_at,
                    now,
                ),
            )
        expired_id = self._insert_raw(
            client="agent-a",
            principal_id=principal["id"],
            expires_at=_past(),
            status="approved",
            code_plain=expired_code,
        )
        garbage_id = self._insert_raw(
            client="agent-a",
            principal_id=principal["id"],
            expires_at="not-a-timestamp",
        )
        created = self._create("agent-a", state="after-sweep")
        remaining = {
            row["id"]
            for row in self.plane.conn.execute("SELECT id FROM ai_oauth_pending").fetchall()
        }
        self.assertIn(kept["id"], remaining)
        self.assertIn(created["id"], remaining)
        self.assertNotIn(expired_id, remaining)
        self.assertNotIn(garbage_id, remaining)
        self.assertIsNone(
            self.plane.conn.execute(
                "SELECT code_hash FROM ai_oauth_codes WHERE code_hash = ?", (expired_digest,)
            ).fetchone()
        )
        self.assertIsNotNone(
            self.plane.conn.execute(
                "SELECT code_hash FROM ai_oauth_codes WHERE code_hash = ?", (other_digest,)
            ).fetchone()
        )
        self.assertIsNotNone(
            self.plane.conn.execute(
                "SELECT code_hash FROM ai_oauth_codes WHERE code_hash = ?", (used_digest,)
            ).fetchone()
        )
        self.assertFalse(self.plane.conn.in_transaction)

    def test_per_client_cap_and_recovery_after_expiry_and_consumption(self):
        filled = self._fill("agent-a", OAUTH_PENDING_MAX_PER_CLIENT)
        with self.assertRaises(OAuthPendingCapacityError) as ctx:
            self._create("agent-a", state="over")
        self.assertEqual(ctx.exception.scope, "client")
        self.assertEqual(ctx.exception.oauth_error, "temporarily_unavailable")
        self.assertIn("retry after existing requests expire or complete", str(ctx.exception))
        self.assertEqual(len(self._live_ids("agent-a")), OAUTH_PENDING_MAX_PER_CLIENT)

        self.plane.conn.execute(
            "UPDATE ai_oauth_pending SET expires_at = ? WHERE id = ?",
            (_past(), filled[0]["id"]),
        )
        recovered = self._create("agent-a", state="after-expiry")
        self.assertNotIn(filled[0]["id"], self._live_ids("agent-a"))
        self.assertIn(recovered["id"], self._live_ids("agent-a"))
        self.assertEqual(len(self._live_ids("agent-a")), OAUTH_PENDING_MAX_PER_CLIENT)

        victim = recovered["id"]
        self.plane.approve_oauth_pending(victim, retain_for_browser=False)
        self.assertNotIn(victim, self._live_ids("agent-a"))
        after_direct = self._create("agent-a", state="after-direct-approve")
        self.assertEqual(len(self._live_ids("agent-a")), OAUTH_PENDING_MAX_PER_CLIENT)

        browser = after_direct
        self.plane.approve_oauth_pending(browser["id"], retain_for_browser=True)
        done = self.plane.complete_oauth_pending_browser(browser["completion_token"])
        self.assertEqual(done["status"], "approved")
        self.assertTrue(str(done.get("code") or "").startswith("drc_"))
        self._create("agent-a", state="after-browser")
        self.assertEqual(len(self._live_ids("agent-a")), OAUTH_PENDING_MAX_PER_CLIENT)

        denied = self._live_ids("agent-a")[0]
        self.plane.deny_oauth_pending(denied)
        with self.assertRaises(OAuthPendingCapacityError):
            self._create("agent-a", state="denied-still-counts")
        self.plane.conn.execute(
            "UPDATE ai_oauth_pending SET expires_at = ? WHERE id = ?",
            (_past(), denied),
        )
        self._create("agent-a", state="after-denied-expiry")
        self.assertEqual(len(self._live_ids("agent-a")), OAUTH_PENDING_MAX_PER_CLIENT)
        expires = self.plane.conn.execute(
            "SELECT expires_at FROM ai_oauth_pending WHERE state = ?",
            ("after-denied-expiry",),
        ).fetchone()["expires_at"]
        exp = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
        delta = exp - datetime.now(timezone.utc)
        self.assertGreater(delta.total_seconds(), OAUTH_PENDING_TTL - 30)
        self.assertLess(delta.total_seconds(), OAUTH_PENDING_TTL + 30)

    def test_global_cap_leaves_other_client_room_until_global_full(self):
        self._stage("agent-b")
        self._fill("agent-a", OAUTH_PENDING_MAX_PER_CLIENT)
        admitted = self._create("agent-b", state="b-ok")
        self.assertTrue(admitted["id"])
        principal = self.plane.get_principal("agent-b")
        need = OAUTH_PENDING_MAX_GLOBAL - len(self._live_ids())
        for i in range(need):
            self._insert_raw(
                client="bulk-%s" % (i % 7),
                principal_id=principal["id"],
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(seconds=OAUTH_PENDING_TTL)
                ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                pending_id="oap_bulk_%s" % i,
            )
        self.assertEqual(len(self._live_ids()), OAUTH_PENDING_MAX_GLOBAL)
        with self.assertRaises(OAuthPendingCapacityError) as ctx:
            self._create("agent-b", state="b-global")
        self.assertEqual(ctx.exception.scope, "global")
        self.assertEqual(len(self._live_ids()), OAUTH_PENDING_MAX_GLOBAL)

    def test_concurrent_admission_does_not_exceed_caps(self):
        self._stage("agent-b")
        workers = OAUTH_PENDING_MAX_PER_CLIENT + 8
        barrier = threading.Barrier(workers)
        ok: list[str] = []
        scopes: list[str] = []
        lock = threading.Lock()

        def one(i: int) -> None:
            barrier.wait()
            try:
                pending = self._create("agent-a", state="race-%s" % i)
            except OAuthPendingCapacityError as exc:
                with lock:
                    scopes.append(exc.scope)
                return
            with lock:
                ok.append(pending["id"])

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(one, range(workers)))
        self.assertEqual(len(ok), OAUTH_PENDING_MAX_PER_CLIENT)
        self.assertEqual(len(scopes), workers - OAUTH_PENDING_MAX_PER_CLIENT)
        self.assertTrue(all(scope == "client" for scope in scopes))
        self.assertEqual(len(self._live_ids("agent-a")), OAUTH_PENDING_MAX_PER_CLIENT)

        principal = self.plane.get_principal("agent-a")
        room = 4
        have = len(self._live_ids())
        for i in range(OAUTH_PENDING_MAX_GLOBAL - have - room):
            self._insert_raw(
                client="bulk-g-%s" % i,
                principal_id=principal["id"],
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(seconds=OAUTH_PENDING_TTL)
                ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                pending_id="oap_grace_%s" % i,
            )
        self.assertEqual(OAUTH_PENDING_MAX_GLOBAL - len(self._live_ids()), room)
        racers = room + 6
        barrier2 = threading.Barrier(racers)
        ok2: list[str] = []
        scopes2: list[str] = []

        def two(i: int) -> None:
            barrier2.wait()
            try:
                pending = self._create("agent-b", state="global-race-%s" % i)
            except OAuthPendingCapacityError as exc:
                with lock:
                    scopes2.append(exc.scope)
                return
            with lock:
                ok2.append(pending["id"])

        with ThreadPoolExecutor(max_workers=racers) as pool:
            list(pool.map(two, range(racers)))
        self.assertEqual(len(ok2), room)
        self.assertEqual(len(scopes2), racers - room)
        self.assertTrue(all(scope == "global" for scope in scopes2))
        self.assertEqual(len(self._live_ids()), OAUTH_PENDING_MAX_GLOBAL)

    def test_source_cap_across_clients_recovers_after_expiry(self):
        self._stage("agent-b")
        self._stage("agent-c")
        source = "198.51.100.9"
        other = "198.51.100.10"
        self._fill_source("agent-a", source, OAUTH_PENDING_MAX_PER_CLIENT)
        filled_b = self._fill_source("agent-b", source, OAUTH_PENDING_MAX_PER_CLIENT)
        self.assertEqual(OAUTH_PENDING_MAX_PER_CLIENT * 2, OAUTH_PENDING_MAX_PER_SOURCE)
        with self.assertRaises(OAuthPendingCapacityError) as ctx:
            self._create("agent-c", state="same-source-over", source=source)
        self.assertEqual(ctx.exception.scope, "source")
        self.assertEqual(ctx.exception.oauth_error, "temporarily_unavailable")
        admitted = self._create("agent-c", state="other-source", source=other)
        self.assertTrue(admitted["id"])
        self.assertEqual(
            len(self._live_ids_for_source(source)),
            OAUTH_PENDING_MAX_PER_SOURCE,
        )
        self.plane.conn.execute(
            "UPDATE ai_oauth_pending SET expires_at = ? WHERE id = ?",
            (_past(), filled_b[0]["id"]),
        )
        recovered = self._create("agent-c", state="after-source-expiry", source=source)
        self.assertIn(recovered["id"], self._live_ids_for_source(source))
        self.assertEqual(
            len(self._live_ids_for_source(source)),
            OAUTH_PENDING_MAX_PER_SOURCE,
        )
        stored = self.plane.conn.execute(
            "SELECT source_addr FROM ai_oauth_pending WHERE id = ?",
            (recovered["id"],),
        ).fetchone()["source_addr"]
        self.assertEqual(stored, source)

    def test_forwarded_headers_do_not_retarget_non_loopback_source(self):
        spoofed = {"X-Forwarded-For": "198.51.100.9", "X-Real-IP": "198.51.100.8"}
        self.assertEqual(trusted_oauth_source("203.0.113.10", spoofed), "203.0.113.10")
        self.assertEqual(trusted_oauth_source("127.0.0.1", spoofed), "198.51.100.9")
        self.assertEqual(
            trusted_oauth_source("127.0.0.1", {"X-Forwarded-For": "not-an-ip"}),
            "127.0.0.1",
        )
        self.assertEqual(trusted_oauth_source("::1", {"X-Real-IP": "2001:db8::1"}), "2001:db8::1")

    def test_authorize_http_rate_limit_same_source_distinct_source_recovers(self):
        self._stage("agent-b")
        port = free_port()
        bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(bridge))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        bridge.listen_host = "127.0.0.1"
        bridge.listen_port = port

        def authorize(client: str, state: str, forwarded: str | None = None) -> int:
            query = urllib.parse.urlencode(
                {
                    "client_id": client,
                    "redirect_uri": REDIRECT,
                    "code_challenge": CHALLENGE,
                    "code_challenge_method": "S256",
                    "resource": bridge.canonical_resource(),
                    "state": state,
                }
            )
            url = "http://127.0.0.1:%s/oauth/authorize?%s" % (port, query)
            headers = {}
            if forwarded:
                headers["X-Forwarded-For"] = forwarded
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                body = json.loads(exc.read().decode("utf-8"))
                self.assertEqual(body["error"], "temporarily_unavailable")
                return exc.code

        try:
            codes = [
                authorize("agent-a", "burst-%s" % i)
                for i in range(OAUTH_AUTHORIZE_RATE_LIMIT)
            ]
            self.assertTrue(all(code == 200 for code in codes))
            self.assertEqual(authorize("agent-b", "same-source-next"), 429)
            self.assertEqual(len(self._live_ids()), OAUTH_AUTHORIZE_RATE_LIMIT)
            self.assertEqual(len(self._live_ids("agent-b")), 0)
            distinct = authorize("agent-b", "other-source", forwarded="198.51.100.20")
            self.assertEqual(distinct, 200)
            self.assertEqual(len(self._live_ids("agent-b")), 1)
            key = "authorize:127.0.0.1"
            self.assertIn(key, bridge._rate_hits)
            bridge._rate_hits[key][0] = 0
            self.assertGreater(OAUTH_AUTHORIZE_RATE_WINDOW_S, 0)
            recovered = authorize("agent-b", "after-window")
            self.assertEqual(recovered, 200)
            self.assertEqual(len(self._live_ids_for_source("127.0.0.1")), OAUTH_AUTHORIZE_RATE_LIMIT + 1)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_authorize_http_returns_stable_capacity_error(self):
        self._fill("agent-a", OAUTH_PENDING_MAX_PER_CLIENT)
        port = free_port()
        bridge = MCPBridge(root=self.tmp, plane=self.plane, auto_agents=False)
        httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(bridge))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        bridge.listen_host = "127.0.0.1"
        bridge.listen_port = port
        try:
            query = urllib.parse.urlencode(
                {
                    "client_id": "agent-a",
                    "redirect_uri": REDIRECT,
                    "code_challenge": CHALLENGE,
                    "code_challenge_method": "S256",
                    "resource": bridge.canonical_resource(),
                    "state": "http-cap",
                }
            )
            url = "http://127.0.0.1:%s/oauth/authorize?%s" % (port, query)
            try:
                urllib.request.urlopen(url, timeout=10)
                self.fail("expected capacity failure")
            except urllib.error.HTTPError as exc:
                body = json.loads(exc.read().decode("utf-8"))
                self.assertEqual(exc.code, 503)
            self.assertEqual(body["error"], "temporarily_unavailable")
            self.assertIn("retry after existing requests expire or complete", body["error_description"])
            self.assertEqual(len(self._live_ids("agent-a")), OAUTH_PENDING_MAX_PER_CLIENT)
        finally:
            httpd.shutdown()
            httpd.server_close()


def secrets_token() -> str:
    import secrets

    return secrets.token_hex(4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
