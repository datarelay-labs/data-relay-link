#!/usr/bin/env python3
"""v2.4 management API ECDSA authentication, replay, ownership, and TLS tests."""
from __future__ import annotations

import io
import json
import os
import ssl
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
import drlink_mgmt_sync as mgmt
import drlink_v24 as v24
import frp_mgmt_auth as MGMT
import frp_pki


MACHINE_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MACHINE_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _write_identity(root: Path, machine_id: str, hostname: str):
    frp = root / "etc/frp"
    frp.mkdir(parents=True, exist_ok=True)
    (frp / "client-state.json").write_text(
        json.dumps(
            {"machine_id": machine_id, "hostname": hostname, "label": hostname},
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (frp / "frpc.toml").write_text("[common]\n", encoding="utf-8")
    key = frp / "client-identity.key"
    pub = frp / "client-identity.pub"
    MGMT.generate_keypair(key, pub)
    os.chmod(key, 0o600)
    mac = MGMT.new_mac_key()
    mac_path = frp / "client-identity.mac"
    mac_path.write_text(mac, encoding="utf-8")
    os.chmod(mac_path, 0o600)
    return key, pub.read_text(encoding="utf-8"), mac


def _signed_headers(key, machine_id, body, op, method, path, ts=None, nonce=None):
    ts = int(ts if ts is not None else time.time())
    nonce = nonce or MGMT.new_nonce()
    message = MGMT.signed_message(
        machine_id, body, ts, nonce, op=op, method=method, path=path
    )
    signature = MGMT.sign_message(key, message)
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Machine-Id": machine_id,
        "X-Timestamp": str(ts),
        "X-Mgmt-Nonce": nonce,
        "X-Mgmt-Signature": signature,
        "X-Mgmt-Auth": "1",
    }, ts, nonce, signature


class MgmtApiAuthTests(unittest.TestCase):
    def setUp(self):
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-mgmt-auth-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-mgmt-auth-agt-")
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_MGMT_TOKEN", None)
        os.environ.pop("DRLINK_MGMT_INSECURE", None)
        self.server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(self.server.conn)
        v24.set_service_object(self.server, "ssh", type="tcp", port=22, oneshot=True)
        self.key_a, self.pub_a, self.mac_a = _write_identity(
            Path(self.agent_tmp), MACHINE_A, "agent-a"
        )
        self.server.upsert_client(MACHINE_A, label="agent-a", hostname="agent-a")
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(MACHINE_A, self.pub_a, mac_key=self.mac_a, hostname="agent-a")
        self.httpd, self.base, _ = mgmt.start_mgmt_server(
            self.server, verifier=self.verifier
        )
        os.environ["DRLINK_MGMT_URL"] = self.base
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base, encoding="utf-8"
        )

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.server.close()
        for k in (
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_CONFIRM",
            "DRLINK_MGMT_URL",
            "DRLINK_MGMT_TOKEN",
            "DRLINK_MGMT_INSECURE",
        ):
            os.environ.pop(k, None)

    def _snapshot(self):
        hosts = list(self.server.conn.execute("SELECT id FROM clients"))
        ports = list(
            self.server.conn.execute(
                "SELECT public_port FROM port_reservations WHERE released = 0"
            )
        )
        services = list(
            self.server.conn.execute(
                "SELECT id FROM published_services WHERE released = 0"
            )
        )
        return {
            "hosts": len(hosts),
            "ports": len(ports),
            "services": len(services),
            "rev": self.server.current_revision(),
        }

    def _http(self, method, path, headers=None, body=b"", timeout=3):
        req = urllib.request.Request(
            self.base + path,
            data=body if method != "GET" else None,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw.decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                payload = {"error": raw.decode("utf-8", errors="replace")}
            return exc.code, payload

    def _create_body(self, name="ssh-access", **extra):
        payload = {
            "name": name,
            "destination": "this-host",
            "service": "ssh",
            "enabled": True,
            "pool_class": "normal",
            "target_host": "127.0.0.1",
            "target_port": 22,
            "target_mode": "self",
        }
        payload.update(extra)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def test_MGMT_AUTH_MISSING_SIGNATURE_REJECT(self):
        before = self._snapshot()
        code, payload = self._http(
            "GET",
            "/v1/catalog",
            headers={"X-Machine-Id": MACHINE_A},
        )
        self.assertEqual(code, 403)
        self.assertNotIn("networkObjects", payload)
        self.assertEqual(self._snapshot(), before)

    def test_MGMT_AUTH_INVALID_SIGNATURE_REJECT(self):
        before = self._snapshot()
        body = self._create_body()
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        headers["X-Mgmt-Signature"] = "not-a-signature"
        code, payload = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code, 403)
        self.assertEqual(self._snapshot(), before)

    def test_MGMT_AUTH_UNKNOWN_MACHINE_REJECT(self):
        before = self._snapshot()
        other_dir = Path(tempfile.mkdtemp(prefix="drlink-unknown-"))
        key, pub, mac = _write_identity(other_dir, "nonexistent-host", "ghost")
        body = b""
        headers, *_ = _signed_headers(
            key,
            "nonexistent-host",
            body,
            MGMT.MGMT_OP_CATALOG_READ,
            "GET",
            "/v1/catalog",
        )
        code, payload = self._http("GET", "/v1/catalog", headers=headers, body=body)
        self.assertEqual(code, 403)
        self.assertIn("not enrolled", payload.get("error", "").lower() + "unknown")
        self.assertEqual(self._snapshot(), before)
        self.assertIsNone(self.server.get_client("nonexistent-host"))

    def test_UNKNOWN_AGENT_NOT_AUTO_CREATED(self):
        before = self._snapshot()
        code, _payload = self._http(
            "POST",
            "/v1/remote-services",
            headers={
                "X-Drlink-Machine-Id": "brand-new-host",
                "X-Drlink-Hostname": "evil",
                "Content-Type": "application/json",
            },
            body=self._create_body("pwned"),
        )
        self.assertEqual(code, 403)
        after = self._snapshot()
        self.assertEqual(after, before)
        self.assertIsNone(self.server.get_client("brand-new-host"))

    def test_MGMT_AUTH_REVOKED_AGENT_REJECT(self):
        self.verifier.revoke(MACHINE_A)
        before = self._snapshot()
        for method, path, body, op in (
            ("GET", "/v1/catalog", b"", MGMT.MGMT_OP_CATALOG_READ),
            (
                "POST",
                "/v1/remote-services",
                self._create_body(),
                MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            ),
            (
                "DELETE",
                "/v1/remote-services/ssh-access",
                b"",
                MGMT.MGMT_OP_REMOTE_SERVICE_DELETE,
            ),
        ):
            headers, *_ = _signed_headers(
                self.key_a, MACHINE_A, body, op, method, path
            )
            code, payload = self._http(method, path, headers=headers, body=body)
            self.assertEqual(code, 403, payload)
            self.assertEqual(payload.get("error_class"), "REVOKED")
            self.assertIn("revoked", payload.get("error", "").lower())
        self.assertEqual(self._snapshot(), before)

    def test_MGMT_AUTH_WRONG_AGENT_KEY_REJECT(self):
        other = Path(tempfile.mkdtemp(prefix="drlink-other-key-"))
        key_b, pub_b, mac_b = _write_identity(other, MACHINE_B, "agent-b")
        before = self._snapshot()
        body = self._create_body()
        headers, *_ = _signed_headers(
            key_b,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        code, _payload = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code, 403)
        self.assertEqual(self._snapshot(), before)

    def test_MGMT_AUTH_TIMESTAMP_MISSING_REJECT(self):
        body = b""
        headers, *_ = _signed_headers(
            self.key_a, MACHINE_A, body, MGMT.MGMT_OP_CATALOG_READ, "GET", "/v1/catalog"
        )
        headers.pop("X-Timestamp")
        code, _payload = self._http("GET", "/v1/catalog", headers=headers, body=body)
        self.assertEqual(code, 403)

    def test_MGMT_AUTH_TIMESTAMP_EXPIRED_REJECT(self):
        body = b""
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_CATALOG_READ,
            "GET",
            "/v1/catalog",
            ts=int(time.time()) - 10_000,
        )
        code, _payload = self._http("GET", "/v1/catalog", headers=headers, body=body)
        self.assertEqual(code, 403)

    def test_MGMT_AUTH_TIMESTAMP_FUTURE_REJECT(self):
        body = b""
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_CATALOG_READ,
            "GET",
            "/v1/catalog",
            ts=int(time.time()) + 10_000,
        )
        code, _payload = self._http("GET", "/v1/catalog", headers=headers, body=body)
        self.assertEqual(code, 403)

    def test_MGMT_AUTH_TIMESTAMP_VALIDATION(self):
        code, payload = self._http(
            "GET",
            "/v1/catalog",
            headers=_signed_headers(
                self.key_a, MACHINE_A, b"", MGMT.MGMT_OP_CATALOG_READ, "GET", "/v1/catalog"
            )[0],
            body=b"",
        )
        self.assertEqual(code, 200)
        self.assertIn("networkObjects", payload)

    def test_MGMT_AUTH_NONCE_REPLAY_REJECT(self):
        body = self._create_body("replay-svc")
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        code1, first = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code1, 200, first)
        port = first.get("endpoint_port")
        rev = self.server.current_revision()
        code2, second = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code2, 403, second)
        self.assertEqual(second.get("error_class"), "REPLAY_REJECTED")
        self.assertEqual(self.server.current_revision(), rev)
        ports = list(
            self.server.conn.execute(
                "SELECT public_port FROM port_reservations WHERE released = 0"
            )
        )
        self.assertEqual(len(ports), 1)
        self.assertEqual(int(ports[0]["public_port"]), int(port))

    def test_MGMT_AUTH_BODY_TAMPER_REJECT(self):
        body = self._create_body("orig")
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        tampered = self._create_body("orig", destination="other-host")
        before = self._snapshot()
        code, _payload = self._http(
            "POST", "/v1/remote-services", headers=headers, body=tampered
        )
        self.assertEqual(code, 403)
        self.assertEqual(self._snapshot(), before)

    def test_MGMT_AUTH_MACHINE_ID_TAMPER_REJECT(self):
        body = self._create_body()
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        headers["X-Machine-Id"] = MACHINE_B
        before = self._snapshot()
        code, _payload = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code, 403)
        self.assertEqual(self._snapshot(), before)

    def test_MGMT_AUTH_OPERATION_TAMPER_REJECT(self):
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            b"",
            MGMT.MGMT_OP_CATALOG_READ,
            "GET",
            "/v1/catalog",
        )
        before = self._snapshot()
        code, payload = self._http(
            "POST",
            "/v1/remote-services",
            headers=headers,
            body=self._create_body("cross-op"),
        )
        self.assertEqual(code, 403)
        self.assertNotIn("endpoint_port", payload)
        self.assertEqual(self._snapshot(), before)

    def test_MGMT_AUTH_CATALOG_VALID_AGENT_PASS(self):
        v24.set_network_object(
            self.server, "github", type="fqdn", value="github.com", oneshot=True
        )
        catalog = mgmt.fetch_server_catalog(root=self.agent_tmp)
        names = [obj["name"] for obj in catalog.get("networkObjects") or []]
        self.assertIn("github", names)

    def test_MGMT_AUTH_REMOTE_SERVICE_CREATE_VALID_AGENT_PASS(self):
        result = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
        )
        # Server reservation alone is not HEALTHY — runtime verification required.
        self.assertEqual(result["status"], "DEGRADED")
        self.assertIsNotNone(result["endpoint_port"])
        self.assertEqual(result["machine_id"], MACHINE_A)
        pub = self.server.conn.execute(
            "SELECT client_id, public_port FROM published_services WHERE name = ? AND released = 0",
            ("ssh-access",),
        ).fetchone()
        self.assertEqual(pub["client_id"], MACHINE_A)
        acked = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
            preserve_endpoint_port=result["endpoint_port"],
            runtime_verified=True,
        )
        self.assertEqual(acked["status"], "HEALTHY")
        self.assertEqual(acked["endpoint_port"], result["endpoint_port"])

    def test_MGMT_AUTH_REMOTE_SERVICE_DELETE_VALID_AGENT_PASS(self):
        mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ssh-access",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
        )
        deleted = mgmt.delete_remote_service_on_server(
            root=self.agent_tmp, name="ssh-access"
        )
        self.assertEqual(deleted["status"], "DELETED")
        remaining = self.server.conn.execute(
            "SELECT 1 FROM published_services WHERE name = ? AND released = 0",
            ("ssh-access",),
        ).fetchone()
        self.assertIsNone(remaining)
        ports = self.server.conn.execute(
            "SELECT 1 FROM port_reservations WHERE released = 0"
        ).fetchone()
        self.assertIsNone(ports)

    def test_UNAUTHENTICATED_REQUEST_NO_PORT_RESERVATION(self):
        before = self._snapshot()
        code, _payload = self._http(
            "POST",
            "/v1/remote-services",
            headers={"X-Machine-Id": MACHINE_A, "Content-Type": "application/json"},
            body=self._create_body("unauth"),
        )
        self.assertEqual(code, 403)
        self.assertEqual(self._snapshot()["ports"], before["ports"])
        self.assertEqual(self._snapshot()["rev"], before["rev"])

    def test_UNAUTHENTICATED_REQUEST_NO_REVISION(self):
        before = self._snapshot()
        self._http(
            "GET",
            "/v1/catalog",
            headers={"X-Drlink-Machine-Id": MACHINE_A},
        )
        self.assertEqual(self.server.current_revision(), before["rev"])

    def test_MGMT_AGENT_OWNERSHIP_ENFORCEMENT(self):
        other = Path(tempfile.mkdtemp(prefix="drlink-agent-b-"))
        key_b, pub_b, mac_b = _write_identity(other, MACHINE_B, "agent-b")
        self.server.upsert_client(MACHINE_B, label="agent-b", hostname="agent-b")
        self.verifier.enroll(MACHINE_B, pub_b, mac_key=mac_b, hostname="agent-b")
        Path(other, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base, encoding="utf-8"
        )
        created = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="owned-by-a",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
        )
        self.assertEqual(created["machine_id"], MACHINE_A)
        body = self._create_body("stolen", machine_id=MACHINE_A)
        headers, *_ = _signed_headers(
            key_b,
            MACHINE_B,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        code, payload = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code, 200, payload)
        self.assertEqual(payload["machine_id"], MACHINE_B)
        pub = self.server.conn.execute(
            "SELECT client_id FROM published_services WHERE name = 'stolen' AND released = 0"
        ).fetchone()
        self.assertEqual(pub["client_id"], MACHINE_B)
        deleted = mgmt.delete_remote_service_on_server(root=str(other), name="owned-by-a")
        self.assertEqual(deleted["status"], "ABSENT")
        still = self.server.conn.execute(
            "SELECT client_id FROM published_services WHERE name = 'owned-by-a' AND released = 0"
        ).fetchone()
        self.assertEqual(still["client_id"], MACHINE_A)

    def test_legacy_machine_id_header_is_not_identity(self):
        before = self._snapshot()
        code, payload = self._http(
            "GET",
            "/v1/catalog",
            headers={"X-Drlink-Machine-Id": MACHINE_A, "X-Drlink-Mgmt-Token": "x"},
        )
        self.assertEqual(code, 403)
        self.assertNotIn("serviceObjects", payload)
        self.assertEqual(self._snapshot(), before)

    def test_cross_delete_path_binding(self):
        mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="keep-me",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
        )
        headers, *_ = _signed_headers(
            self.key_a,
            MACHINE_A,
            b"",
            MGMT.MGMT_OP_REMOTE_SERVICE_DELETE,
            "DELETE",
            "/v1/remote-services/keep-me",
        )
        code, _payload = self._http(
            "DELETE", "/v1/remote-services/other-name", headers=headers, body=b""
        )
        self.assertEqual(code, 403)
        still = self.server.conn.execute(
            "SELECT 1 FROM published_services WHERE name = 'keep-me' AND released = 0"
        ).fetchone()
        self.assertIsNotNone(still)


class MgmtTlsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-mgmt-tls-")
        os.environ.pop("DRLINK_MGMT_INSECURE", None)
        Path(self.tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/frp").mkdir(parents=True, exist_ok=True)
        Path(self.tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.pki = frp_pki.ensure_pki(str(Path(self.tmp) / "pki"), "127.0.0.1")
        ca_dest = Path(self.tmp, "etc/drlink/allocator-ca.crt")
        ca_dest.write_bytes(Path(self.pki["ca_crt"]).read_bytes())
        self.machine_id = MACHINE_A
        self.key, self.pub, self.mac = _write_identity(
            Path(self.tmp), self.machine_id, "tls-agent"
        )
        self.server = ControlPlane(self.tmp)
        v24.ensure_v2_schema(self.server.conn)
        v24.set_service_object(self.server, "ssh", type="tcp", port=22, oneshot=True)
        self.server.upsert_client(self.machine_id, label="tls-agent", hostname="tls-agent")
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(self.machine_id, self.pub, mac_key=self.mac, hostname="tls-agent")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.pki["server_crt"], self.pki["server_key"])
        self.httpd, self.base, _ = mgmt.start_mgmt_server(
            self.server, verifier=self.verifier, ssl_context=ctx
        )
        Path(self.tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base, encoding="utf-8"
        )
        os.environ["DRLINK_MGMT_URL"] = self.base

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.server.close()
        for k in (
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_CONFIRM",
            "DRLINK_MGMT_URL",
            "DRLINK_MGMT_INSECURE",
        ):
            os.environ.pop(k, None)

    def test_MGMT_TLS_DEFAULT_VERIFY(self):
        self.assertFalse(mgmt.mgmt_insecure_tls_enabled())
        catalog = mgmt.fetch_server_catalog(root=self.tmp)
        self.assertIn("serviceObjects", catalog)

    def test_MGMT_TLS_UNTRUSTED_CERT_REJECT(self):
        other = frp_pki.ensure_pki(str(Path(self.tmp) / "other-pki"), "127.0.0.1")
        Path(self.tmp, "etc/drlink/allocator-ca.crt").write_bytes(
            Path(other["ca_crt"]).read_bytes()
        )
        with self.assertRaises(mgmt.MgmtSyncError) as raised:
            mgmt.fetch_server_catalog(root=self.tmp)
        self.assertIn("unreachable", str(raised.exception).lower())
        self.assertFalse(mgmt.mgmt_insecure_tls_enabled())

    def test_MGMT_TLS_NO_AUTOMATIC_INSECURE_FALLBACK(self):
        Path(self.tmp, "etc/drlink/allocator-ca.crt").write_text(
            "not-a-cert\n", encoding="utf-8"
        )
        with self.assertRaises(mgmt.MgmtSyncError):
            mgmt.fetch_server_catalog(root=self.tmp)
        self.assertNotIn(os.environ.get("DRLINK_MGMT_INSECURE", ""), ("1", "yes", "true"))
        src = Path(mgmt.__file__).read_text(encoding="utf-8")
        self.assertNotRegex(src, r"except[\s\S]{0,400}DRLINK_MGMT_INSECURE")

    def test_MGMT_TLS_EXPLICIT_LAB_OVERRIDE(self):
        os.environ["DRLINK_MGMT_INSECURE"] = "1"
        Path(self.tmp, "etc/drlink/allocator-ca.crt").write_text(
            "untrusted\n", encoding="utf-8"
        )
        buf = io.StringIO()
        with redirect_stderr(buf):
            catalog = mgmt.fetch_server_catalog(root=self.tmp)
        self.assertIn("serviceObjects", catalog)
        self.assertIn("management TLS certificate verification is disabled", buf.getvalue())


class MgmtApiErrorClassificationTests(unittest.TestCase):
    """P1: MgmtAuthError stays auth-class; MgmtSyncError/ControlPlaneError stay operational."""

    def setUp(self):
        self.server_tmp = tempfile.mkdtemp(prefix="drlink-mgmt-err-srv-")
        self.agent_tmp = tempfile.mkdtemp(prefix="drlink-mgmt-err-agt-")
        Path(self.server_tmp, "etc/drlink").mkdir(parents=True, exist_ok=True)
        Path(self.server_tmp, "etc/drlink/config.json").write_text(
            '{"role":"server"}\n', encoding="utf-8"
        )
        os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
        os.environ["DRLINK_CONFIRM"] = "yes"
        os.environ.pop("DRLINK_MGMT_TOKEN", None)
        os.environ.pop("DRLINK_MGMT_INSECURE", None)
        os.environ.pop("DRLINK_FAULT_ACTIVATION", None)
        self.server = ControlPlane(self.server_tmp)
        v24.ensure_v2_schema(self.server.conn)
        v24.set_service_object(self.server, "ssh", type="tcp", port=22, oneshot=True)
        self.key, self.pub, self.mac = _write_identity(
            Path(self.agent_tmp), MACHINE_A, "agent-a"
        )
        self.server.upsert_client(MACHINE_A, label="agent-a", hostname="agent-a")
        self.verifier = mgmt.InMemoryMgmtVerifier()
        self.verifier.enroll(MACHINE_A, self.pub, mac_key=self.mac, hostname="agent-a")
        self.httpd, self.base, _ = mgmt.start_mgmt_server(
            self.server, verifier=self.verifier
        )
        os.environ["DRLINK_MGMT_URL"] = self.base
        Path(self.agent_tmp, "etc/frp/server-endpoint.json").write_text(
            '{"mgmt_url":"%s"}\n' % self.base, encoding="utf-8"
        )

    def tearDown(self):
        mgmt.stop_mgmt_server(self.httpd)
        self.server.close()
        for k in (
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_CONFIRM",
            "DRLINK_MGMT_URL",
            "DRLINK_MGMT_TOKEN",
            "DRLINK_MGMT_INSECURE",
            "DRLINK_FAULT_ACTIVATION",
        ):
            os.environ.pop(k, None)

    def _http(self, method, path, headers=None, body=b"", timeout=3):
        req = urllib.request.Request(
            self.base + path,
            data=body if method != "GET" else None,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw.decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                payload = {"error": raw.decode("utf-8", errors="replace")}
            return exc.code, payload

    def _assert_agent_non_auth(self, exc):
        msg = str(exc)
        self.assertNotEqual(msg, mgmt.AUTH_REJECTED)
        self.assertNotIn("re-enrolled", msg.lower())
        self.assertNotIn("management identity has been revoked", msg.lower())

    def test_auth_error_http_remains_auth_class(self):
        body = b"{}"
        headers, *_ = _signed_headers(
            self.key,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        headers["X-Mgmt-Signature"] = "not-a-signature"
        code, payload = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code, 403)
        self.assertEqual(payload.get("error_class"), "AUTH_FAILED")

    def test_revoked_identity_agent_maps_to_auth_guidance(self):
        self.verifier.revoke(MACHINE_A)
        with self.assertRaises(mgmt.MgmtSyncError) as raised:
            mgmt.fetch_server_catalog(root=self.agent_tmp)
        msg = str(raised.exception)
        self.assertIn("revoked", msg.lower())
        self.assertEqual(msg, mgmt.AUTH_REVOKED)

    def test_missing_remote_service_fields_are_non_auth(self):
        body = json.dumps({"name": "only-name"}, separators=(",", ":")).encode("utf-8")
        headers, *_ = _signed_headers(
            self.key,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        code, payload = self._http("POST", "/v1/remote-services", headers=headers, body=body)
        self.assertEqual(code, 400, payload)
        self.assertNotEqual(payload.get("error_class"), "AUTH_FAILED")
        err = str(payload.get("error") or "").lower()
        self.assertIn("required", err)
        self.assertNotIn("re-enroll", err)

    def test_missing_service_object_is_non_auth(self):
        with self.assertRaises(mgmt.MgmtSyncError) as raised:
            mgmt.upsert_remote_service_on_server(
                root=self.agent_tmp,
                name="svc",
                destination="this-host",
                service="no-such-service",
                enabled=True,
                pool_class="normal",
                target_host="127.0.0.1",
                target_port=22,
                target_mode="self",
            )
        self._assert_agent_non_auth(raised.exception)
        self.assertIn("does not exist", str(raised.exception).lower())

    def test_invalid_service_object_port_is_non_auth(self):
        self.server.conn.execute(
            "UPDATE service_objects SET port = 0 WHERE name = 'ssh'"
        )
        self.server.conn.commit()
        with self.assertRaises(mgmt.MgmtSyncError) as raised:
            mgmt.upsert_remote_service_on_server(
                root=self.agent_tmp,
                name="svc",
                destination="this-host",
                service="ssh",
                enabled=True,
                pool_class="normal",
                target_host="127.0.0.1",
                target_port=22,
                target_mode="self",
            )
        self._assert_agent_non_auth(raised.exception)
        self.assertIn("invalid port", str(raised.exception).lower())

    def test_udp_unsupported_is_non_auth(self):
        v24.set_service_object(self.server, "dns", type="udp", port=53, oneshot=True)
        with self.assertRaises(mgmt.MgmtSyncError) as raised:
            mgmt.upsert_remote_service_on_server(
                root=self.agent_tmp,
                name="udp-svc",
                destination="this-host",
                service="dns",
                enabled=True,
                pool_class="normal",
                target_host="127.0.0.1",
                target_port=53,
                target_mode="self",
            )
        self._assert_agent_non_auth(raised.exception)
        self.assertIn("tcp", str(raised.exception).lower())

    def test_pool_class_mismatch_is_non_auth(self):
        with self.assertRaises(mgmt.MgmtSyncError) as raised:
            mgmt.upsert_remote_service_on_server(
                root=self.agent_tmp,
                name="svc",
                destination="this-host",
                service="ssh",
                enabled=True,
                pool_class="fixed-tcp",
                target_host="127.0.0.1",
                target_port=22,
                target_mode="self",
            )
        self._assert_agent_non_auth(raised.exception)
        self.assertIn("pool_class", str(raised.exception).lower())

    def test_allocator_mgmt_sync_error_http_is_non_auth(self):
        class _FailAllocator:
            def reserve_remote_service_endpoint(self, *a, **k):
                raise RuntimeError("pool exhausted")

        body = json.dumps(
            {
                "name": "svc",
                "destination": "this-host",
                "service": "ssh",
                "enabled": True,
                "pool_class": "normal",
                "target_host": "127.0.0.1",
                "target_port": 22,
                "target_mode": "self",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        headers, *_ = _signed_headers(
            self.key,
            MACHINE_A,
            body,
            MGMT.MGMT_OP_REMOTE_SERVICE_SET,
            "POST",
            "/v1/remote-services",
        )
        real_upsert = mgmt.server_upsert_remote_service

        def boom_upsert(plane_arg, auth_arg, data):
            auth_arg.allocator = _FailAllocator()
            return real_upsert(plane_arg, auth_arg, data)

        mgmt.server_upsert_remote_service = boom_upsert
        try:
            code, payload = mgmt.handle_allocator_http(
                self.server,
                "POST",
                "/v1/remote-services",
                headers,
                body,
                verifier=self.verifier,
            )
        finally:
            mgmt.server_upsert_remote_service = real_upsert
        self.assertEqual(code, 400, payload)
        self.assertNotEqual(payload.get("error_class"), "AUTH_FAILED")
        self.assertIn("allocation failed", str(payload.get("error") or "").lower())

    def test_control_plane_error_is_non_auth_not_re_enroll(self):
        os.environ.pop("DRLINK_SKIP_ACTIVATION", None)
        os.environ["DRLINK_FAULT_ACTIVATION"] = "1"
        with self.assertRaises(mgmt.MgmtSyncError) as raised:
            mgmt.upsert_remote_service_on_server(
                root=self.agent_tmp,
                name="svc",
                destination="this-host",
                service="ssh",
                enabled=True,
                pool_class="normal",
                target_host="127.0.0.1",
                target_port=22,
                target_mode="self",
            )
        self._assert_agent_non_auth(raised.exception)
        self.assertIn("Previous configuration was restored", str(raised.exception))

    def test_success_path_unchanged(self):
        result = mgmt.upsert_remote_service_on_server(
            root=self.agent_tmp,
            name="ok-svc",
            destination="this-host",
            service="ssh",
            enabled=True,
            pool_class="normal",
            target_host="127.0.0.1",
            target_port=22,
            target_mode="self",
        )
        self.assertEqual(result.get("name"), "ok-svc")
        self.assertGreater(int(result.get("endpoint_port") or 0), 0)
        catalog = mgmt.fetch_server_catalog(root=self.agent_tmp)
        names = [s.get("name") for s in (catalog.get("serviceObjects") or [])]
        self.assertIn("ssh", names)

    def test_exception_order_mgmt_sync_before_control_plane(self):
        src = Path(mgmt.__file__).read_text(encoding="utf-8")
        # Restrict to the HTTP dispatch handler region.
        region = src[src.index("def handle_allocator_http") :]
        auth_i = region.index("except MgmtAuthError")
        sync_i = region.index("except MgmtSyncError")
        cp_i = region.index("except ControlPlaneError")
        self.assertLess(auth_i, sync_i)
        self.assertLess(sync_i, cp_i)


class SourceAudit(unittest.TestCase):
    def test_no_machine_id_only_allow_path(self):
        src = Path(ROOT, "lib/drlink_mgmt_sync.py").read_text(encoding="utf-8")
        self.assertNotIn("X-Drlink-Machine-Id", src)
        self.assertNotIn("_ensure_managed_host", src)
        self.assertNotIn("_authenticate_request", src)
        self.assertIn("AllocatorMgmtVerifier", src)
        self.assertIn("ecdsa", src.lower() + "ECDSA")
        alloc = Path(ROOT, "server/frp-port-allocator.py").read_text(encoding="utf-8")
        self.assertIn("AllocatorMgmtVerifier(allocator)", alloc)
        self.assertIn("/v1/remote-services-status", alloc)


if __name__ == "__main__":
    unittest.main()
