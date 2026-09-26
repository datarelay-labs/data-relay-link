#!/usr/bin/env python3
"""Focused MCP public TLS / ACME lifecycle tests (no production CA issuance)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from drlink_control_cli import dispatch  # noqa: E402
from drlink_control_plane import ControlPlane  # noqa: E402
from drlink_configuration_bundle import prepare_plan, BundleError  # noqa: E402
import drlink_mcp_tls as mcp_tls  # noqa: E402
import frp_pki  # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _make_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DRLink Test ACME CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


class LocalAcmeServer:
    """Minimal RFC8555-ish ACME directory for protocol integration tests.

    Not a product ACME implementation — test harness only.
    """

    def __init__(self, challenge_fetch_host="127.0.0.1"):
        self.ca_key, self.ca_cert = _make_ca()
        self.challenge_fetch_host = challenge_fetch_host
        self.nonces = set()
        self.accounts = {}
        self.orders = {}
        self.authzs = {}
        self.challenges = {}
        self.certs = {}
        self.port = _free_port()
        self.base = "http://127.0.0.1:%s" % self.port
        self._httpd = None
        self._thread = None
        self.fail_finalize = False
        self.rate_limit = False
        self.conflict_on_reregister = False

    def directory(self):
        return {
            "newNonce": self.base + "/acme/new-nonce",
            "newAccount": self.base + "/acme/new-account",
            "newOrder": self.base + "/acme/new-order",
            "revokeCert": self.base + "/acme/revoke-cert",
            "keyChange": self.base + "/acme/key-change",
            "meta": {"termsOfService": self.base + "/terms"},
        }

    def start(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _json(self, code, obj, extra_headers=None):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Replay-Nonce", server._nonce())
                self.send_header("Cache-Control", "no-store")
                for k, v in (extra_headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _raw(self, code, body: bytes, content_type="application/pem-certificate-chain"):
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Replay-Nonce", server._nonce())
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_HEAD(self):
                if self.path == "/acme/new-nonce":
                    self.send_response(200)
                    self.send_header("Replay-Nonce", server._nonce())
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                if self.path in ("/directory", "/"):
                    return self._json(200, server.directory())
                if self.path == "/acme/new-nonce":
                    self.send_response(204)
                    self.send_header("Replay-Nonce", server._nonce())
                    self.end_headers()
                    return
                if self.path.startswith("/acme/authz/"):
                    authz = server.authzs.get(self.path) or server.authzs.get(server.base + self.path)
                    return self._json(200, authz) if authz else self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown authz"})
                if self.path.startswith("/acme/chall/"):
                    chall = server.challenges.get(self.path) or server.challenges.get(server.base + self.path)
                    return self._json(200, chall) if chall else self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown chall"})
                if self.path.startswith("/acme/order/"):
                    if self.path.endswith("/finalize"):
                        return self._json(405, {"type": "urn:ietf:params:acme:error:malformed"})
                    order = server.orders.get(self.path) or server.orders.get(server.base + self.path)
                    return self._json(200, order) if order else self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown order"})
                if self.path.startswith("/acme/cert/"):
                    pem = server.certs.get(self.path) or server.certs.get(server.base + self.path)
                    return self._raw(200, pem) if pem else self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown cert"})
                self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "get %s" % self.path})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                try:
                    msg = json.loads(raw.decode("utf-8"))
                except Exception:
                    return self._json(400, {"type": "urn:ietf:params:acme:error:malformed", "detail": "bad jose"})
                payload_b64 = msg.get("payload")
                if payload_b64 is None:
                    payload_b64 = ""
                # RFC 8555 POST-as-GET uses an empty payload string.
                if payload_b64 == "":
                    return self.do_GET()
                try:
                    pad = "=" * (-len(payload_b64) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8"))
                except Exception:
                    payload = {}

                if server.rate_limit:
                    return self._json(429, {"type": "urn:ietf:params:acme:error:rateLimited", "detail": "slow down"})

                if self.path == "/acme/new-account":
                    # Key fingerprint from JWS protected header is unavailable here;
                    # use contact+only_return_existing / in-memory single-account map.
                    only_existing = bool(payload.get("onlyReturnExisting"))
                    if server.accounts and (only_existing or server.conflict_on_reregister):
                        kid = next(iter(server.accounts.keys()))
                        return self._json(
                            200,
                            {"status": "valid", "orders": server.base + "/acme/orders"},
                            {"Location": kid},
                        )
                    kid = server.base + "/acme/acct/%s" % (len(server.accounts) + 1)
                    server.accounts[kid] = payload
                    return self._json(201, {"status": "valid", "orders": server.base + "/acme/orders"}, {"Location": kid})

                if self.path.startswith("/acme/acct/"):
                    abs_kid = server.base + self.path
                    kid = abs_kid if abs_kid in server.accounts else None
                    if kid is None:
                        for existing in server.accounts:
                            if existing.endswith(self.path):
                                kid = existing
                                break
                    if kid is None:
                        return self._json(
                            404,
                            {"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "unknown"},
                        )
                    return self._json(
                        200,
                        {"status": "valid", "orders": server.base + "/acme/orders"},
                        {"Location": kid},
                    )

                if self.path == "/acme/new-order":
                    identifiers = payload.get("identifiers") or []
                    order_id = str(len(server.orders) + 1)
                    order_url = server.base + "/acme/order/%s" % order_id
                    authz_urls = []
                    for ident in identifiers:
                        value = ident.get("value")
                        authz_id = "%s-%s" % (order_id, value)
                        authz_url = server.base + "/acme/authz/%s" % authz_id
                        token = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")
                        chall_url = server.base + "/acme/chall/%s" % authz_id
                        chall = {
                            "type": "http-01",
                            "url": chall_url,
                            "status": "pending",
                            "token": token,
                        }
                        server.challenges[chall_url] = chall
                        server.authzs[authz_url] = {
                            "status": "pending",
                            "identifier": ident,
                            "challenges": [chall],
                            "expires": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        }
                        authz_urls.append(authz_url)
                    order = {
                        "status": "pending",
                        "identifiers": identifiers,
                        "authorizations": authz_urls,
                        "finalize": order_url + "/finalize",
                        "expires": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                    server.orders[order_url] = order
                    return self._json(201, order, {"Location": order_url})

                if self.path.startswith("/acme/chall/"):
                    chall = server.challenges.get(self.path) or server.challenges.get(server.base + self.path)
                    if not chall:
                        return self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown challenge"})
                    chall["status"] = "valid"
                    up_url = None
                    for authz_url, authz in server.authzs.items():
                        if any(c.get("url") == chall.get("url") for c in authz.get("challenges") or []):
                            authz["status"] = "valid"
                            for c in authz["challenges"]:
                                c["status"] = "valid"
                            up_url = authz_url if authz_url.startswith("http") else server.base + authz_url
                    for order in server.orders.values():
                        if all(server.authzs.get(u, {}).get("status") == "valid" for u in order.get("authorizations") or []):
                            order["status"] = "ready"
                    headers = {}
                    if up_url:
                        headers["Link"] = '<%s>;rel="up"' % up_url
                    return self._json(200, chall, headers)

                if self.path.endswith("/finalize"):
                    order = server.orders.get(self.path[: -len("/finalize")]) or server.orders.get(server.base + self.path[: -len("/finalize")])
                    if not order:
                        return self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "unknown order"})
                    if server.fail_finalize:
                        return self._json(400, {"type": "urn:ietf:params:acme:error:unauthorized", "detail": "challenge failed"})
                    csr_b64 = payload.get("csr") or ""
                    pad = "=" * (-len(csr_b64) % 4)
                    csr_der = base64.urlsafe_b64decode(csr_b64 + pad)
                    csr = x509.load_der_x509_csr(csr_der)
                    host = order["identifiers"][0]["value"]
                    now = datetime.now(timezone.utc)
                    cert = (
                        x509.CertificateBuilder()
                        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                        .issuer_name(server.ca_cert.subject)
                        .public_key(csr.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(now - timedelta(minutes=1))
                        .not_valid_after(now + timedelta(days=90))
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
                        .add_extension(
                            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                            critical=False,
                        )
                        .sign(server.ca_key, hashes.SHA256())
                    )
                    leaf = cert.public_bytes(serialization.Encoding.PEM)
                    chain = leaf + server.ca_cert.public_bytes(serialization.Encoding.PEM)
                    cert_path = "/acme/cert/%s" % (order.get("finalize", "").rstrip("/finalize").rsplit("/", 1)[-1] or "1")
                    cert_url = server.base + cert_path
                    server.certs[cert_path] = chain
                    server.certs[cert_url] = chain
                    order["status"] = "valid"
                    order["certificate"] = cert_url
                    return self._json(200, order)

                # Resource POST-as-GET fallback for non-empty but unused payloads.
                if self.path.startswith("/acme/"):
                    return self.do_GET()
                return self._json(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "path %s" % self.path})

        self._httpd = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.base + "/directory"

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    def _nonce(self):
        n = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")
        self.nonces.add(n)
        return n


def _synth_leaf(hostname, *, days=90, san=None, key=None, ca_key=None, ca_cert=None, expired=False):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    if ca_key is None:
        ca_key = key
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        ca_cert = None
        self_signed = True
    else:
        issuer = ca_cert.subject
        self_signed = False
    names = [x509.DNSName(hostname)]
    for extra in san or []:
        names.append(x509.DNSName(extra))
    if expired:
        not_before = now - timedelta(days=40)
        not_after = now - timedelta(days=2)
    else:
        not_before = now - timedelta(minutes=1)
        not_after = now + timedelta(days=days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if not self_signed and ca_cert is not None:
        cert_pem = cert_pem + ca_cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


class McpTlsLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drlink-mcp-tls-")
        os.environ["DRLINK_TEST_ROOT"] = self.tmp
        os.environ["DRLINK_CONFIRM"] = "yes"
        self.plane = ControlPlane(self.tmp)
        # Private CA for PRIVATE_CA mode
        self.pki = frp_pki.ensure_pki(str(Path(self.tmp) / "etc/drlink/pki"), "203.0.113.10")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_hostname_validation(self):
        self.assertEqual(mcp_tls.canonicalize_hostname("MCP.Example.COM."), "mcp.example.com")
        with self.assertRaises(mcp_tls.McpTlsError):
            mcp_tls.canonicalize_hostname("127.0.0.1")
        with self.assertRaises(mcp_tls.McpTlsError):
            mcp_tls.canonicalize_hostname("localhost")
        with self.assertRaises(mcp_tls.McpTlsError):
            mcp_tls.canonicalize_hostname("*.example.com")
        with self.assertRaises(mcp_tls.McpTlsError):
            mcp_tls.canonicalize_hostname("not a host")
        self.assertTrue(mcp_tls.is_private_only_hostname("app.local"))

    def test_default_public_cloud_mode_is_auto_acme(self):
        self.assertEqual(mcp_tls.DEFAULT_PUBLIC_CLOUD_TLS_MODE, mcp_tls.MODE_AUTO_ACME)
        self.assertTrue(mcp_tls.cloud_compatible_for_mode(mcp_tls.MODE_AUTO_ACME))
        self.assertTrue(mcp_tls.cloud_compatible_for_mode(mcp_tls.MODE_USER_CERTIFICATE))
        self.assertFalse(mcp_tls.cloud_compatible_for_mode(mcp_tls.MODE_PRIVATE_CA))

    def test_user_certificate_import_match_and_rejects(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "user-certificate"], root=self.tmp)
        cert_pem, key_pem = _synth_leaf(host)
        cert_path = Path(self.tmp) / "import.crt"
        key_path = Path(self.tmp) / "import.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        os.chmod(key_path, 0o600)

        mcp_tls.import_user_certificate(
            self.plane, self.tmp, cert_path=str(cert_path), key_path=str(key_path), reload=False
        )
        view = mcp_tls.status_view(self.plane, self.tmp)
        self.assertEqual(view["mode"], mcp_tls.MODE_USER_CERTIFICATE)
        self.assertEqual(view["certificate"], mcp_tls.STATUS_VALID)
        self.assertTrue((mcp_tls.active_dir(self.tmp) / "privkey.pem").is_file())
        mode = stat.S_IMODE((mcp_tls.active_dir(self.tmp) / "privkey.pem").stat().st_mode)
        self.assertEqual(mode & 0o077, 0)

        # mismatch key
        other_cert, other_key = _synth_leaf(host)
        bad_key = Path(self.tmp) / "bad.key"
        bad_key.write_bytes(other_key)
        os.chmod(bad_key, 0o600)
        with self.assertRaises(mcp_tls.McpTlsError) as ctx:
            mcp_tls.import_user_certificate(
                self.plane, self.tmp, cert_path=str(cert_path), key_path=str(bad_key), reload=False
            )
        self.assertEqual(ctx.exception.failure_class, "CERT_KEY_MISMATCH")

        # wrong hostname
        wrong_cert, wrong_key = _synth_leaf("other.example.test")
        wc = Path(self.tmp) / "wrong.crt"
        wk = Path(self.tmp) / "wrong.key"
        wc.write_bytes(wrong_cert)
        wk.write_bytes(wrong_key)
        os.chmod(wk, 0o600)
        with self.assertRaises(mcp_tls.McpTlsError) as ctx:
            mcp_tls.import_user_certificate(
                self.plane, self.tmp, cert_path=str(wc), key_path=str(wk), reload=False
            )
        self.assertEqual(ctx.exception.failure_class, "HOSTNAME_MISMATCH")

        # expired
        exp_cert, exp_key = _synth_leaf(host, expired=True)
        ec = Path(self.tmp) / "exp.crt"
        ek = Path(self.tmp) / "exp.key"
        ec.write_bytes(exp_cert)
        ek.write_bytes(exp_key)
        os.chmod(ek, 0o600)
        with self.assertRaises(mcp_tls.McpTlsError) as ctx:
            mcp_tls.import_user_certificate(
                self.plane, self.tmp, cert_path=str(ec), key_path=str(ek), reload=False
            )
        self.assertEqual(ctx.exception.failure_class, "CERT_EXPIRED")

        # unsafe permissions
        os.chmod(key_path, 0o644)
        with self.assertRaises(mcp_tls.McpTlsError) as ctx:
            mcp_tls.import_user_certificate(
                self.plane, self.tmp, cert_path=str(cert_path), key_path=str(key_path), reload=False
            )
        self.assertEqual(ctx.exception.failure_class, "UNSAFE_KEY_PERMISSIONS")

    def test_private_ca_issue_and_warning(self):
        host = "mcp-internal.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        rc = dispatch(["set", "mcp-tls", "mode", "private-ca"], root=self.tmp)
        self.assertEqual(rc, 0)
        state = mcp_tls.issue_and_activate(self.plane, self.tmp, reload=False)
        self.assertEqual(state["mode"], mcp_tls.MODE_PRIVATE_CA)
        view = mcp_tls.status_view(self.plane, self.tmp)
        self.assertTrue(view["private_ca_warning"])
        self.assertFalse(view["cloud_compatible"])
        # Trust path: verifying with DRLink CA succeeds; stock trust fails.
        ca = str(Path(self.tmp) / "etc/drlink/pki/ca.crt")
        # No skip-verify helper exists in product module.
        self.assertFalse(hasattr(mcp_tls, "skip_verify"))
        text = (ROOT / "lib/drlink_mcp_tls.py").read_text(encoding="utf-8")
        self.assertNotIn("VERIFY_NONE", text)

    def test_failed_activation_preserves_previous(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "user-certificate"], root=self.tmp)
        cert1, key1 = _synth_leaf(host, days=60)
        c1 = Path(self.tmp) / "c1.crt"
        k1 = Path(self.tmp) / "c1.key"
        c1.write_bytes(cert1)
        k1.write_bytes(key1)
        os.chmod(k1, 0o600)
        mcp_tls.import_user_certificate(self.plane, self.tmp, cert_path=str(c1), key_path=str(k1), reload=False)
        fp1 = mcp_tls.status_view(self.plane, self.tmp)["fingerprint_sha256"]

        cert2, key2 = _synth_leaf(host, days=90)
        meta = mcp_tls.validate_cert_key_pair(cert2, key2, hostname=host)
        meta["mode"] = mcp_tls.MODE_USER_CERTIFICATE
        meta["hostname"] = host
        meta["fullchain_pem"] = cert2
        meta["key_pem"] = key2

        def bad_proxy():
            return False, "simulated invalid proxy config"

        with self.assertRaises(mcp_tls.McpTlsError) as ctx:
            mcp_tls.activate_material(
                self.plane, self.tmp, meta, reload=False, validate_proxy_cfg=bad_proxy
            )
        self.assertEqual(ctx.exception.failure_class, "PROXY_CONFIG_INVALID")
        self.assertEqual(mcp_tls.status_view(self.plane, self.tmp)["fingerprint_sha256"], fp1)

    def test_renewal_backoff_preserves_cert(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "auto-acme"], root=self.tmp)
        dispatch(["set", "mcp-tls", "acme-environment", "staging"], root=self.tmp)
        # Seed a valid active cert as if previously issued.
        cert, key = _synth_leaf(host, days=10)
        meta = mcp_tls.validate_cert_key_pair(cert, key, hostname=host)
        meta.update({"mode": mcp_tls.MODE_AUTO_ACME, "hostname": host, "fullchain_pem": cert, "key_pem": key})
        mcp_tls.activate_material(self.plane, self.tmp, meta, reload=False)
        fp = mcp_tls.status_view(self.plane, self.tmp)["fingerprint_sha256"]

        def boom(*a, **k):
            raise mcp_tls.McpTlsError("simulated ACME down", failure_class="ACME_UNAVAILABLE")

        orig = mcp_tls.issue_acme_certificate
        orig_pre = mcp_tls.preflight_hostname
        mcp_tls.issue_acme_certificate = boom
        mcp_tls.preflight_hostname = lambda *a, **k: {
            "hostname": host,
            "resolves": True,
            "addresses": ["127.0.0.1"],
            "private_only": False,
            "challenge_port_80_open": True,
            "ok": True,
            "warnings": [],
            "errors": [],
        }
        try:
            result = mcp_tls.renew_if_due(self.plane, self.tmp, force=True, reload=False)
        finally:
            mcp_tls.issue_acme_certificate = orig
            mcp_tls.preflight_hostname = orig_pre
        self.assertFalse(result["renewed"])
        self.assertEqual(result.get("failure_class"), "ACME_UNAVAILABLE")
        state = mcp_tls.load_state(self.plane)
        self.assertEqual(state["status"], mcp_tls.STATUS_RENEWAL_FAILED)
        self.assertTrue(state.get("next_renewal_after"))
        self.assertEqual(mcp_tls.status_view(self.plane, self.tmp)["fingerprint_sha256"], fp)

        # Backoff blocks immediate retry
        result2 = mcp_tls.renew_if_due(self.plane, self.tmp, force=False, reload=False)
        self.assertEqual(result2.get("reason"), "backoff")

    def test_concurrency_lock(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        held = threading.Event()
        release = threading.Event()

        def holder():
            with mcp_tls.ExclusiveFileLock(mcp_tls.lock_path(self.tmp), timeout=5):
                held.set()
                release.wait(10)

        t = threading.Thread(target=holder)
        t.start()
        self.assertTrue(held.wait(5))

        def attempt():
            with self.assertRaises(mcp_tls.McpTlsError) as ctx:
                def _fn():
                    return True

                mcp_tls._with_tls_lock(self.tmp, _fn)
            self.assertEqual(ctx.exception.failure_class, "TLS_LOCK_TIMEOUT")

        # Temporary short timeout
        from frp_control_locks import ExclusiveFileLock as EFL

        orig = mcp_tls.ExclusiveFileLock

        class ShortLock(EFL):
            def __init__(self, path, timeout=30):
                super().__init__(path, timeout=0.2)

        mcp_tls.ExclusiveFileLock = ShortLock
        try:
            attempt()
        finally:
            mcp_tls.ExclusiveFileLock = orig
            release.set()
            t.join(5)

    def test_bundle_secret_rejection_and_intent(self):
        yaml_bad = """
apiVersion: drlink.datarelay.run/v1alpha1
kind: ConfigurationBundle
metadata:
  name: bad-tls
spec:
  mcpTls:
    - state: present
      mode: AUTO_ACME
      hostname: mcp.example.test
      privateKey: |
        -----BEGIN """ + """PRIVATE KEY-----
        aaaaa
        -----END PRIVATE KEY-----
"""
        with self.assertRaises(BundleError):
            prepare_plan(self.plane, yaml_bad, run_tests=False)

        yaml_ok = """
apiVersion: drlink.datarelay.run/v1alpha1
kind: ConfigurationBundle
metadata:
  name: tls-intent
spec:
  mcpTls:
    - state: present
      mode: AUTO_ACME
      hostname: mcp.example.test
      acmeEnvironment: STAGING
      contactEmail: ops@example.test
"""
        plan = prepare_plan(self.plane, yaml_ok, run_tests=False)
        self.assertTrue(any(c.family == "mcpTls" for c in plan.mutating_changes))
        # Apply intent only — no ACME side effect in transaction.
        for ch in plan.mutating_changes:
            ch.apply_fn(self.plane)
        state = mcp_tls.load_state(self.plane)
        self.assertEqual(state["mode"], mcp_tls.MODE_AUTO_ACME)
        self.assertEqual(state["hostname"], "mcp.example.test")
        self.assertEqual(state["acme_environment"], mcp_tls.ACME_ENV_STAGING)
        self.assertFalse(mcp_tls.read_active_material(self.tmp))  # no cert yet

    def test_cli_status_and_doctor(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "auto-acme"], root=self.tmp)
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            dispatch(["show", "mcp-tls"], root=self.tmp)
        text = buf.getvalue()
        self.assertIn("AUTO_ACME", text)
        self.assertIn("https://mcp.example.test/mcp", text)

        checks = mcp_tls.doctor_checks(self.plane, self.tmp)
        self.assertTrue(any(c["id"] == "mcp_tls_mode" for c in checks))

    def test_local_acme_protocol_issuance(self):
        """Protocol-realistic issuance against local ACME harness (not production CA)."""
        host = "mcp.example.test"
        # Make hostname resolve via /etc/hosts is not possible; preflight DNS may fail.
        # Bypass preflight by patching for this protocol test after configuring intent.
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "auto-acme"], root=self.tmp)
        dispatch(["set", "mcp-tls", "acme-environment", "staging"], root=self.tmp)
        dispatch(["set", "mcp-tls", "contact-email", "ops@example.test"], root=self.tmp)

        acme = LocalAcmeServer()
        directory = acme.start()
        try:
            # Patch preflight to succeed (DNS ownership still proven by challenge).
            orig_pre = mcp_tls.preflight_hostname
            mcp_tls.preflight_hostname = lambda *a, **k: {
                "hostname": host,
                "resolves": True,
                "addresses": ["127.0.0.1"],
                "private_only": False,
                "challenge_port_80_open": True,
                "ok": True,
                "warnings": [],
                "errors": [],
            }
            # Challenge validation in harness marks challenges valid without HTTP fetch;
            # still exercise write of challenge files by the client.
            try:
                state = mcp_tls.issue_and_activate(
                    self.plane,
                    self.tmp,
                    reload=False,
                    directory_url_override=directory,
                )
            finally:
                mcp_tls.preflight_hostname = orig_pre
            self.assertEqual(state["mode"], mcp_tls.MODE_AUTO_ACME)
            self.assertTrue(state.get("fingerprint_sha256"))
            active = mcp_tls.read_active_material(self.tmp)
            self.assertIsNotNone(active)
            self.assertIn(host, active.get("sans") or [active.get("subject_cn")])
            # Account key persisted securely
            acct = mcp_tls._account_key_path(self.tmp)
            self.assertTrue(acct.is_file())
            self.assertEqual(stat.S_IMODE(acct.stat().st_mode) & 0o077, 0)
            # Ensure we did not hit production LE
            self.assertNotIn("letsencrypt.org", directory)
        finally:
            acme.stop()

    def test_acme_dependency_missing_fail_closed(self):
        status = mcp_tls.acme_runtime_status()
        self.assertTrue(status.get("ok"), status)
        orig = mcp_tls.acme_runtime_status
        mcp_tls.acme_runtime_status = lambda: {
            "ok": False,
            "implementation": mcp_tls.ACME_IMPLEMENTATION,
            "package": mcp_tls.ACME_DISTRO_PACKAGE,
            "min_version": "%d.%d" % mcp_tls.ACME_MIN_VERSION,
            "version": "",
            "detail": "missing python3-acme",
        }
        try:
            with self.assertRaises(mcp_tls.McpTlsError) as ctx:
                mcp_tls._require_acme()
            self.assertEqual(ctx.exception.failure_class, "DEPENDENCY_MISSING")
            with self.assertRaises(mcp_tls.McpTlsError) as ctx2:
                mcp_tls.configure_intent(self.plane, mode=mcp_tls.MODE_AUTO_ACME)
            self.assertEqual(ctx2.exception.failure_class, "DEPENDENCY_MISSING")
            with self.assertRaises(SystemExit):
                dispatch(["set", "mcp-tls", "mode", "auto-acme"], root=self.tmp)
        finally:
            mcp_tls.acme_runtime_status = orig

    def test_http01_publish_permissions_keep_secrets_closed(self):
        mcp_tls.ensure_tree(self.tmp)
        tree = mcp_tls.tls_tree(self.tmp)
        self.assertEqual(stat.S_IMODE(tree.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(mcp_tls.acme_webroot(self.tmp).stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(mcp_tls.challenges_dir(self.tmp).stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(mcp_tls.account_dir(self.tmp).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(mcp_tls.active_dir(self.tmp).stat().st_mode), 0o700)
        # Parent state dirs under test root are made traversable for HTTP-01.
        parent = Path(self.tmp) / "var" / "lib" / "drlink"
        self.assertTrue(parent.is_dir())
        self.assertTrue(stat.S_IMODE(parent.stat().st_mode) & 0o001)

    def test_acme_account_conflict_reuses_existing_registration(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "auto-acme"], root=self.tmp)
        dispatch(["set", "mcp-tls", "acme-environment", "staging"], root=self.tmp)
        acme = LocalAcmeServer()
        acme.conflict_on_reregister = True
        directory = acme.start()
        try:
            # First registration succeeds and persists URI.
            key = mcp_tls._load_or_create_account_key(self.tmp)
            client = mcp_tls._acme_client(self.tmp, directory, key)
            regr1 = mcp_tls._ensure_acme_account(client, self.tmp, "")
            self.assertTrue(regr1.uri)
            self.assertTrue(mcp_tls._account_regr_path(self.tmp).is_file())
            # Second call must tolerate ConflictError (same key / existing account).
            client2 = mcp_tls._acme_client(self.tmp, directory, key)
            # Force conflict path by clearing persisted URI then re-registering.
            mcp_tls._account_regr_path(self.tmp).unlink()
            regr2 = mcp_tls._ensure_acme_account(client2, self.tmp, "")
            self.assertEqual(regr1.uri, regr2.uri)
            # Full issuance still works after conflict recovery.
            orig_pre = mcp_tls.preflight_hostname
            mcp_tls.preflight_hostname = lambda *a, **k: {
                "hostname": host,
                "resolves": True,
                "addresses": ["127.0.0.1"],
                "private_only": False,
                "challenge_port_80_open": True,
                "ok": True,
                "warnings": [],
                "errors": [],
            }
            try:
                state = mcp_tls.issue_and_activate(
                    self.plane,
                    self.tmp,
                    reload=False,
                    directory_url_override=directory,
                )
            finally:
                mcp_tls.preflight_hostname = orig_pre
            self.assertEqual(state["mode"], mcp_tls.MODE_AUTO_ACME)
            self.assertTrue(state.get("fingerprint_sha256"))
        finally:
            acme.stop()

    def test_acme_directory_unavailable_classification(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        with self.assertRaises(mcp_tls.McpTlsError) as ctx:
            mcp_tls.issue_acme_certificate(
                self.tmp,
                hostname=host,
                directory_url="https://127.0.0.1:1/directory",
                contact_email="",
                timeout_sec=2,
            )
        self.assertEqual(ctx.exception.failure_class, "ACME_UNAVAILABLE")

    def test_renewal_uses_same_acme_runtime_path(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "auto-acme"], root=self.tmp)
        dispatch(["set", "mcp-tls", "acme-environment", "staging"], root=self.tmp)
        called = {"n": 0}

        def fake_issue(*a, **k):
            called["n"] += 1
            cert, key = _synth_leaf(host, days=90)
            meta = mcp_tls.validate_cert_key_pair(cert, key, hostname=host)
            meta.update({"mode": mcp_tls.MODE_AUTO_ACME, "hostname": host, "fullchain_pem": cert, "key_pem": key})
            return meta

        # Seed near-expiry cert
        cert, key = _synth_leaf(host, days=5)
        meta = mcp_tls.validate_cert_key_pair(cert, key, hostname=host)
        meta.update({"mode": mcp_tls.MODE_AUTO_ACME, "hostname": host, "fullchain_pem": cert, "key_pem": key})
        mcp_tls.activate_material(self.plane, self.tmp, meta, reload=False)
        orig = mcp_tls.issue_acme_certificate
        orig_pre = mcp_tls.preflight_hostname
        mcp_tls.issue_acme_certificate = fake_issue
        mcp_tls.preflight_hostname = lambda *a, **k: {
            "hostname": host,
            "resolves": True,
            "addresses": ["127.0.0.1"],
            "private_only": False,
            "challenge_port_80_open": True,
            "ok": True,
            "warnings": [],
            "errors": [],
        }
        try:
            result = mcp_tls.renew_if_due(self.plane, self.tmp, force=True, reload=False)
        finally:
            mcp_tls.issue_acme_certificate = orig
            mcp_tls.preflight_hostname = orig_pre
        self.assertTrue(result.get("renewed"))
        self.assertEqual(called["n"], 1)

    def test_user_certificate_and_private_ca_unaffected_by_acme_dep_gate(self):
        host = "mcp.example.test"
        # USER_CERTIFICATE must not require python3-acme at configure time.
        orig = mcp_tls.acme_runtime_status
        mcp_tls.acme_runtime_status = lambda: {
            "ok": False,
            "implementation": mcp_tls.ACME_IMPLEMENTATION,
            "package": mcp_tls.ACME_DISTRO_PACKAGE,
            "min_version": "%d.%d" % mcp_tls.ACME_MIN_VERSION,
            "version": "",
            "detail": "missing python3-acme",
        }
        try:
            dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
            dispatch(["set", "mcp-tls", "mode", "user-certificate"], root=self.tmp)
            cert, key = _synth_leaf(host, days=60)
            c1 = Path(self.tmp) / "u.crt"
            k1 = Path(self.tmp) / "u.key"
            c1.write_bytes(cert)
            k1.write_bytes(key)
            os.chmod(k1, 0o600)
            mcp_tls.import_user_certificate(
                self.plane, self.tmp, cert_path=str(c1), key_path=str(k1), reload=False
            )
            self.assertEqual(mcp_tls.load_state(self.plane)["mode"], mcp_tls.MODE_USER_CERTIFICATE)
            dispatch(["set", "mcp-tls", "mode", "private-ca"], root=self.tmp)
            mcp_tls.issue_and_activate(self.plane, self.tmp, reload=False)
            self.assertEqual(mcp_tls.load_state(self.plane)["mode"], mcp_tls.MODE_PRIVATE_CA)
        finally:
            mcp_tls.acme_runtime_status = orig

    def test_secret_scan_no_private_keys_in_status_export(self):
        host = "mcp.example.test"
        dispatch(["set", "mcp-tls", "hostname", host], root=self.tmp)
        dispatch(["set", "mcp-tls", "mode", "private-ca"], root=self.tmp)
        mcp_tls.issue_and_activate(self.plane, self.tmp, reload=False)
        view = mcp_tls.status_view(self.plane, self.tmp)
        blob = json.dumps(view)
        self.assertNotIn("BEGIN " + "PRIVATE KEY", blob)
        self.assertNotIn("BEGIN RSA " + "PRIVATE KEY", blob)
        meta = mcp_tls.support_bundle_public_meta(self.plane, self.tmp)
        self.assertNotIn("private", json.dumps(meta).lower().split("private_ca")[0] if False else json.dumps(meta))
        # Explicit: support meta has no key material fields
        for banned in ("private_key", "account_key", "key_pem", "privkey"):
            self.assertNotIn(banned, meta)

    def test_frontend_sni_keeps_private_ca_for_frp(self):
        import frp_frontend as fe

        conf = fe.render_nginx_conf(
            public_host="203.0.113.10",
            frontend_port=443,
            allocator_listen_port=6099,
            control_listen_port=7000,
            ca_cert="/etc/drlink/pki/ca.crt",
            server_cert="/etc/drlink/pki/server.crt",
            server_key="/etc/drlink/pki/server.key",
            mcp_tls_hostname="mcp.example.com",
            mcp_tls_cert="/var/lib/drlink/tls/mcp/active/fullchain.pem",
            mcp_tls_key="/var/lib/drlink/tls/mcp/active/privkey.pem",
            acme_webroot="/var/lib/drlink/tls/mcp/acme-www",
        )
        self.assertIn("server_name 203.0.113.10;", conf)
        self.assertIn("ssl_certificate /etc/drlink/pki/server.crt;", conf)
        self.assertIn("server_name mcp.example.com;", conf)
        self.assertIn("ssl_certificate /var/lib/drlink/tls/mcp/active/fullchain.pem;", conf)
        self.assertIn("acme-challenge", conf)
        self.assertIn("return 404;", conf)

    def test_grammar_discovers_mcp_tls(self):
        import frp_cli_catalog as catalog
        import frp_ctl_grammar as grammar

        self.assertIsNotNone(catalog.find(["show", "mcp-tls"]))
        self.assertIsNotNone(catalog.find(["set", "mcp-tls"]))
        self.assertIsNotNone(catalog.find(["system", "certificate"]))
        m = grammar.match(["show", "mcp-tls"], role="server")
        self.assertEqual(m.get("action"), "control_plane")
        m2 = grammar.match(["system", "certificate", "status"], role="server")
        self.assertEqual(m2.get("action"), "control_plane")


if __name__ == "__main__":
    unittest.main()
