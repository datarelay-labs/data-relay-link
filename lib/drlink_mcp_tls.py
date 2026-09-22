#!/usr/bin/env python3
"""MCP public TLS certificate lifecycle for Data Relay Link.

Canonical authority for MCP public TLS intent and activation lives here and in
SQLite system_meta (non-secret). Private keys remain filesystem-only under the
DRLink state tree. Generated nginx config is a derived runtime artifact.

TLS modes:
  AUTO_ACME         — publicly trusted cert via standard ACME (default for cloud MCP)
  USER_CERTIFICATE  — operator-imported cert/key/chain
  PRIVATE_CA        — DRLink private CA leaf (internal/test; not cloud-default)

ACME protocol is NOT implemented here. Issuance uses the mature python3-acme
library (Let's Encrypt / Certbot ACME client) against a configurable directory.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from frp_control_locks import ExclusiveFileLock, LockTimeout, durable_replace

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODE_AUTO_ACME = "AUTO_ACME"
MODE_USER_CERTIFICATE = "USER_CERTIFICATE"
MODE_PRIVATE_CA = "PRIVATE_CA"
MODES = (MODE_AUTO_ACME, MODE_USER_CERTIFICATE, MODE_PRIVATE_CA)
DEFAULT_PUBLIC_CLOUD_TLS_MODE = MODE_AUTO_ACME

ACME_ENV_STAGING = "STAGING"
ACME_ENV_PRODUCTION = "PRODUCTION"
ACME_ENVIRONMENTS = (ACME_ENV_STAGING, ACME_ENV_PRODUCTION)

# Let's Encrypt directories (standard ACME; product is not LE-API-specific).
LE_PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

ACME_CHALLENGE_SUPPORTED = ("HTTP-01",)
ACME_DEFAULT_CHALLENGE = "HTTP-01"
ACME_IMPLEMENTATION = "python3-acme"
# Packaged dependency policy: distro python3-acme (Ubuntu 24.04 = 2.9.0;
# EL8 EPEL = 1.22.x). Runtime requires the ClientV2 HTTP-01 surface.
ACME_IMPLEMENTATION_VERSION = "2.9.0"
ACME_MIN_VERSION = (1, 22)
ACME_DISTRO_PACKAGE = "python3-acme"

# Renew when fewer than this many days remain (conservative; avoids rate limits).
RENEWAL_DAYS_BEFORE_EXPIRY = 30
# Backoff after failed renewal attempts (seconds).
RENEWAL_BACKOFF_SCHEDULE = (300, 900, 3600, 14400, 86400)

STATUS_VALID = "VALID"
STATUS_RENEWAL_DUE = "RENEWAL_DUE"
STATUS_RENEWING = "RENEWING"
STATUS_RENEWAL_FAILED = "RENEWAL_FAILED_USING_CURRENT_CERT"
STATUS_EXPIRED = "EXPIRED"
STATUS_INVALID = "INVALID"
STATUS_PENDING = "PENDING_ISSUANCE"
STATUS_ABSENT = "ABSENT"

META_KEY = "mcp_tls"
LOCK_REL = "var/lib/drlink/tls/mcp/mcp-tls.lock"
STATE_TREE_REL = "var/lib/drlink/tls/mcp"

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class McpTlsError(Exception):
    """Operator-facing TLS lifecycle error."""

    def __init__(self, message: str, *, failure_class: str = "TLS_ERROR"):
        super().__init__(message)
        self.failure_class = failure_class


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _root(root: Optional[str | Path] = None) -> Path:
    if root is not None:
        return Path(root)
    env = (os.environ.get("DRLINK_TEST_ROOT") or os.environ.get("FRP_DEPLOY_TEST_ROOT") or "").strip()
    if env:
        return Path(env)
    return Path("/")


def tls_tree(root: Optional[str | Path] = None) -> Path:
    return _root(root) / STATE_TREE_REL


def lock_path(root: Optional[str | Path] = None) -> Path:
    return _root(root) / LOCK_REL


def active_dir(root: Optional[str | Path] = None) -> Path:
    return tls_tree(root) / "active"


def previous_dir(root: Optional[str | Path] = None) -> Path:
    return tls_tree(root) / "previous"


def staging_dir(root: Optional[str | Path] = None) -> Path:
    return tls_tree(root) / "staging"


def account_dir(root: Optional[str | Path] = None) -> Path:
    return tls_tree(root) / "account"


def acme_webroot(root: Optional[str | Path] = None) -> Path:
    """HTTP-01 webroot (nginx root). Challenge files live under .well-known/acme-challenge/."""
    return tls_tree(root) / "acme-www"


def challenges_dir(root: Optional[str | Path] = None) -> Path:
    return acme_webroot(root) / ".well-known" / "acme-challenge"


def ensure_tree(root: Optional[str | Path] = None) -> Path:
    tree = tls_tree(root)
    secret_dirs = {active_dir(root), previous_dir(root), staging_dir(root), account_dir(root)}
    public_dirs = {acme_webroot(root), challenges_dir(root)}
    for path in (
        tree,
        active_dir(root),
        previous_dir(root),
        staging_dir(root),
        account_dir(root),
        acme_webroot(root),
        challenges_dir(root),
    ):
        path.mkdir(parents=True, exist_ok=True)
        # Secrets stay 0700. TLS tree + HTTP-01 webroot must be traversable by
        # the frontend nginx worker (often nobody/www-data) without exposing keys.
        if path in secret_dirs:
            os.chmod(path, 0o700)
        elif path in public_dirs or path == tree:
            os.chmod(path, 0o755)
        else:
            os.chmod(path, 0o700)
    ensure_http01_publish_permissions(root)
    return tree


def _frontend_http_user() -> str:
    """Best-effort nginx worker user for HTTP-01 webroot traversal ACLs."""
    for name in ("www-data", "nginx", "nobody"):
        try:
            import pwd

            pwd.getpwnam(name)
            return name
        except Exception:
            continue
    return ""


def ensure_http01_publish_permissions(root: Optional[str | Path] = None) -> None:
    """Ensure frontend can traverse to the HTTP-01 webroot; secrets stay closed."""
    base = _root(root)
    webroot = acme_webroot(root)
    challenges = challenges_dir(root)
    for path in (webroot, challenges):
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
    # mcp TLS tree itself must be traversable (account/active remain 0700).
    try:
        os.chmod(tls_tree(root), 0o755)
    except OSError:
        pass
    # When operating on the live filesystem root, grant the frontend user
    # execute-only on ancestor state dirs without world-listing secrets.
    if str(base) not in ("/", ""):
        # Test roots: make ancestors traversable under the fake root only.
        for ancestor in (base / "var" / "lib" / "drlink", base / "var" / "lib" / "drlink" / "tls"):
            if ancestor.is_dir():
                try:
                    os.chmod(ancestor, 0o755)
                except OSError:
                    pass
        return
    user = _frontend_http_user()
    ancestors = [
        Path("/var/lib/drlink"),
        Path("/var/lib/drlink/tls"),
        tls_tree(root),
    ]
    if user and shutil.which("setfacl"):
        for ancestor in ancestors:
            if not ancestor.is_dir():
                continue
            try:
                subprocess.run(
                    ["setfacl", "-m", "u:%s:--x" % user, str(ancestor)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                pass
    else:
        # Fallback: other-execute only (no read/list) so nginx can traverse.
        for ancestor in ancestors:
            if not ancestor.is_dir():
                continue
            try:
                mode = stat.S_IMODE(ancestor.stat().st_mode)
                os.chmod(ancestor, mode | 0o011)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Hostname validation / preflight
# ---------------------------------------------------------------------------

def canonicalize_hostname(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise McpTlsError("MCP TLS hostname is required", failure_class="HOSTNAME_INVALID")
    if text.endswith(".") and text.count(".") > 1:
        text = text[:-1]
    try:
        text = text.encode("idna").decode("ascii")
    except Exception as exc:
        raise McpTlsError("MCP TLS hostname IDNA conversion failed", failure_class="HOSTNAME_INVALID") from exc
    text = text.lower()
    if text in ("localhost", "localhost.localdomain"):
        raise McpTlsError("localhost is not valid for MCP public TLS", failure_class="HOSTNAME_INVALID")
    if "*" in text:
        raise McpTlsError("wildcard hostnames are not supported for MCP TLS", failure_class="HOSTNAME_INVALID")
    try:
        ipaddress.ip_address(text)
        raise McpTlsError("raw IP addresses are not valid ACME certificate hostnames", failure_class="HOSTNAME_INVALID")
    except ValueError:
        pass
    if any(ch in text for ch in " /:?#@[]"):
        raise McpTlsError("MCP TLS hostname contains invalid characters", failure_class="HOSTNAME_INVALID")
    if not _HOSTNAME_RE.fullmatch(text):
        raise McpTlsError("MCP TLS hostname is not a valid FQDN", failure_class="HOSTNAME_INVALID")
    labels = text.split(".")
    if any(label.endswith("-") or label.startswith("-") for label in labels):
        raise McpTlsError("MCP TLS hostname labels are malformed", failure_class="HOSTNAME_INVALID")
    # Reject obviously private-only single-label and .local / .internal style names for AUTO_ACME
    # (PRIVATE_CA may still use them when explicitly selected).
    return text


def is_private_only_hostname(hostname: str) -> bool:
    host = canonicalize_hostname(hostname)
    tld = host.rsplit(".", 1)[-1]
    if tld in ("local", "localhost", "internal", "intranet", "lan", "home", "corp", "private"):
        return True
    return False


def preflight_hostname(hostname: str, *, require_public_dns: bool = True) -> dict:
    host = canonicalize_hostname(hostname)
    result: dict[str, Any] = {
        "hostname": host,
        "resolves": False,
        "addresses": [],
        "private_only": is_private_only_hostname(host),
        "challenge_port_80_open": None,
        "ok": True,
        "warnings": [],
        "errors": [],
    }
    if require_public_dns and result["private_only"]:
        result["ok"] = False
        result["errors"].append("hostname appears private-only; AUTO_ACME requires a public DNS name")
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addrs = sorted({item[4][0] for item in infos})
        result["addresses"] = addrs
        result["resolves"] = bool(addrs)
    except socket.gaierror:
        result["ok"] = False
        result["errors"].append("hostname does not resolve")
        return result
    # Port-80 reachability is advisory locally; ACME validation remains authoritative.
    try:
        sock = socket.create_connection((host, 80), timeout=2)
        sock.close()
        result["challenge_port_80_open"] = True
    except OSError:
        result["challenge_port_80_open"] = False
        result["warnings"].append("TCP/80 not reachable from this host; HTTP-01 may fail if externally blocked")
    return result


# ---------------------------------------------------------------------------
# Certificate material helpers (cryptography / openssl)
# ---------------------------------------------------------------------------

def _load_cryptography():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise McpTlsError("python3-cryptography is required for MCP TLS", failure_class="DEPENDENCY_MISSING") from exc
    return x509, hashes, serialization, ec, rsa, NameOID


def fingerprint_pem(cert_pem: bytes | str) -> str:
    x509, hashes, *_rest = _load_cryptography()
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("utf-8")
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.fingerprint(hashes.SHA256()).hex()


def parse_cert_meta(cert_pem: bytes | str) -> dict:
    x509, hashes, serialization, ec, rsa, NameOID = _load_cryptography()
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("utf-8")
    cert = x509.load_pem_x509_certificate(cert_pem)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:
        sans = []
    subject = ""
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            subject = str(attrs[0].value)
    except Exception:
        subject = ""
    issuer = ""
    try:
        attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            issuer = str(attrs[0].value)
        if not issuer:
            issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = cert.issuer.rfc4514_string()
    now = datetime.now(timezone.utc)
    days = int((not_after - now).total_seconds() // 86400)
    return {
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "subject_cn": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "days_remaining": days,
        "sans": sans,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
    }


def _pem_first_cert(blob: bytes | str) -> bytes:
    text = blob.decode("utf-8") if isinstance(blob, (bytes, bytearray)) else str(blob)
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    start = text.find(begin)
    stop = text.find(end, start)
    if start < 0 or stop < 0:
        raise McpTlsError("certificate PEM is missing", failure_class="INVALID_CERT")
    return (text[start : stop + len(end)] + "\n").encode("utf-8")


def validate_cert_key_pair(
    cert_pem: bytes | str,
    key_pem: bytes | str,
    *,
    hostname: str,
    allow_expired: bool = False,
    require_chain: bool = False,
    chain_pem: bytes | str | None = None,
) -> dict:
    x509, hashes, serialization, ec, rsa, NameOID = _load_cryptography()
    host = canonicalize_hostname(hostname)
    if isinstance(cert_pem, str):
        cert_pem_b = cert_pem.encode("utf-8")
    else:
        cert_pem_b = cert_pem
    if isinstance(key_pem, str):
        key_pem_b = key_pem.encode("utf-8")
    else:
        key_pem_b = key_pem
    try:
        cert = x509.load_pem_x509_certificate(cert_pem_b)
    except Exception as exc:
        raise McpTlsError("certificate does not parse as X.509 PEM", failure_class="INVALID_CERT") from exc
    try:
        key = serialization.load_pem_private_key(key_pem_b, password=None)
    except Exception as exc:
        raise McpTlsError("private key does not parse as PEM", failure_class="INVALID_KEY") from exc
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise McpTlsError("RSA private key must be at least 2048 bits", failure_class="INVALID_KEY")
        pub = key.public_key().public_numbers()
        cert_pub = cert.public_key()
        if not isinstance(cert_pub, rsa.RSAPublicKey) or cert_pub.public_numbers() != pub:
            raise McpTlsError("certificate and private key do not match", failure_class="CERT_KEY_MISMATCH")
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        cert_pub = cert.public_key()
        if not isinstance(cert_pub, ec.EllipticCurvePublicKey):
            raise McpTlsError("certificate and private key do not match", failure_class="CERT_KEY_MISMATCH")
        if cert_pub.public_numbers() != key.public_key().public_numbers():
            raise McpTlsError("certificate and private key do not match", failure_class="CERT_KEY_MISMATCH")
    else:
        raise McpTlsError("unsupported private key type", failure_class="INVALID_KEY")

    meta = parse_cert_meta(cert_pem_b)
    if meta["expired"] and not allow_expired:
        raise McpTlsError("certificate is expired", failure_class="CERT_EXPIRED")
    if meta["not_yet_valid"]:
        raise McpTlsError("certificate is not yet valid", failure_class="CERT_NOT_YET_VALID")

    names = set(n.lower() for n in meta["sans"])
    if meta["subject_cn"]:
        names.add(meta["subject_cn"].lower())
    if host not in names:
        raise McpTlsError(
            "certificate hostname does not match intended MCP hostname %s" % host,
            failure_class="HOSTNAME_MISMATCH",
        )

    fullchain = cert_pem_b
    if chain_pem:
        chain_b = chain_pem.encode("utf-8") if isinstance(chain_pem, str) else chain_pem
        # Structural chain parse
        try:
            rest = chain_b
            while b"BEGIN CERTIFICATE" in rest:
                c = _pem_first_cert(rest)
                x509.load_pem_x509_certificate(c)
                idx = rest.find(b"-----END CERTIFICATE-----")
                rest = rest[idx + len(b"-----END CERTIFICATE-----") :]
        except McpTlsError:
            raise
        except Exception as exc:
            raise McpTlsError("certificate chain is structurally invalid", failure_class="INVALID_CHAIN") from exc
        leaf = _pem_first_cert(cert_pem_b).decode("utf-8")
        chain_text = chain_b.decode("utf-8") if isinstance(chain_b, (bytes, bytearray)) else str(chain_pem)
        if leaf.strip() not in chain_text:
            fullchain = (leaf + "\n" + chain_text).encode("utf-8")
        else:
            fullchain = chain_b if isinstance(chain_b, (bytes, bytearray)) else chain_text.encode("utf-8")
    elif require_chain:
        raise McpTlsError("certificate chain is required", failure_class="INVALID_CHAIN")

    meta["fullchain_pem"] = fullchain
    return meta


def _write_secret_file(path: Path, data: bytes | str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    tmp = path.with_name(path.name + ".tmp.%s" % os.getpid())
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    durable_replace(tmp, path)
    os.chmod(path, mode)


def _write_public_file(path: Path, data: bytes | str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    tmp = path.with_name(path.name + ".tmp.%s" % os.getpid())
    tmp.write_bytes(raw)
    os.chmod(tmp, mode)
    durable_replace(tmp, path)


# ---------------------------------------------------------------------------
# Canonical non-secret state (SQLite system_meta via ControlPlane)
# ---------------------------------------------------------------------------

def default_state() -> dict:
    return {
        "mode": "",
        "hostname": "",
        "acme_environment": ACME_ENV_PRODUCTION,
        "acme_directory_url": "",
        "contact_email": "",
        "status": STATUS_ABSENT,
        "renewal_enabled": False,
        "fingerprint_sha256": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_remaining": None,
        "last_success_at": "",
        "last_renewal_at": "",
        "last_failure_class": "",
        "last_failure_at": "",
        "renewal_attempt_count": 0,
        "next_renewal_after": "",
        "pending_intent": None,
        "cloud_compatible": None,
        "private_ca_warning": False,
    }


def load_state(plane) -> dict:
    if plane is None or getattr(plane, "conn", None) is None:
        return default_state()
    row = plane.conn.execute("SELECT value FROM system_meta WHERE key = ?", (META_KEY,)).fetchone()
    state = default_state()
    if not row:
        return state
    try:
        data = json.loads(row["value"])
    except Exception:
        return state
    if not isinstance(data, dict):
        return state
    state.update({k: data[k] for k in state.keys() if k in data})
    return state


def save_state(plane, state: dict, *, commit: bool = True) -> dict:
    payload = default_state()
    payload.update(state or {})
    # Never persist secrets into system_meta.
    for banned in ("private_key", "account_key", "cert_pem", "key_pem", "fullchain_pem"):
        payload.pop(banned, None)
    plane.conn.execute(
        "INSERT OR REPLACE INTO system_meta(key, value) VALUES (?, ?)",
        (META_KEY, json.dumps(payload, sort_keys=True)),
    )
    if commit:
        plane.conn.commit()
    return payload


def acme_directory_for_env(env: str, override: str = "") -> str:
    text = str(override or "").strip()
    if text:
        return text
    env_u = str(env or ACME_ENV_PRODUCTION).strip().upper()
    if env_u == ACME_ENV_STAGING:
        return LE_STAGING_DIRECTORY
    return LE_PRODUCTION_DIRECTORY


def normalize_mode(value: str) -> str:
    text = str(value or "").strip().upper().replace("-", "_")
    aliases = {
        "AUTO": MODE_AUTO_ACME,
        "ACME": MODE_AUTO_ACME,
        "AUTOACME": MODE_AUTO_ACME,
        "USER": MODE_USER_CERTIFICATE,
        "USERCERT": MODE_USER_CERTIFICATE,
        "USER_CERT": MODE_USER_CERTIFICATE,
        "IMPORTED": MODE_USER_CERTIFICATE,
        "PRIVATE": MODE_PRIVATE_CA,
        "PRIVATECA": MODE_PRIVATE_CA,
    }
    text = aliases.get(text, text)
    if text not in MODES:
        raise McpTlsError(
            "TLS mode must be AUTO_ACME, USER_CERTIFICATE, or PRIVATE_CA",
            failure_class="TLS_MODE_INVALID",
        )
    return text


def cloud_compatible_for_mode(mode: str) -> bool:
    return mode in (MODE_AUTO_ACME, MODE_USER_CERTIFICATE)


def compute_status(state: dict, meta: Optional[dict] = None) -> str:
    mode = str(state.get("mode") or "")
    if not mode:
        return STATUS_ABSENT
    if state.get("pending_intent"):
        return STATUS_PENDING
    info = meta
    if info is None and state.get("fingerprint_sha256"):
        info = {
            "days_remaining": state.get("days_remaining"),
            "expired": state.get("status") == STATUS_EXPIRED,
        }
    if not state.get("fingerprint_sha256"):
        return STATUS_ABSENT
    days = None
    if info is not None:
        days = info.get("days_remaining")
        if info.get("expired"):
            return STATUS_EXPIRED
    elif state.get("days_remaining") is not None:
        days = state.get("days_remaining")
    if state.get("last_failure_class") and state.get("status") == STATUS_RENEWAL_FAILED:
        if days is not None and days < 0:
            return STATUS_EXPIRED
        return STATUS_RENEWAL_FAILED
    if days is not None and days < 0:
        return STATUS_EXPIRED
    if days is not None and days <= RENEWAL_DAYS_BEFORE_EXPIRY:
        return STATUS_RENEWAL_DUE
    return STATUS_VALID


# ---------------------------------------------------------------------------
# Audit (non-secret)
# ---------------------------------------------------------------------------

def _audit(plane, action: str, *, hostname: str = "", mode: str = "", result: str = "ok",
           failure_class: str = "", extra: Optional[dict] = None) -> None:
    details = {
        "hostname": hostname,
        "mode": mode,
        "result": result,
        "failure_class": failure_class,
    }
    if extra:
        for key, value in extra.items():
            if key.lower() in ("private_key", "account_key", "key_pem", "token", "secret"):
                continue
            details[key] = value
    try:
        plane.conn.execute(
            "INSERT INTO audit_events(timestamp, revision, actor, action, entity_type, "
            "entity_id, summary, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                plane.current_revision() if hasattr(plane, "current_revision") else None,
                "operator",
                action,
                "mcp_tls",
                hostname or "mcp-tls",
                action,
                json.dumps(details, sort_keys=True),
            ),
        )
        plane.conn.commit()
    except Exception:
        # Audit must not break TLS operations.
        try:
            plane.conn.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Active material I/O
# ---------------------------------------------------------------------------

def read_active_material(root: Optional[str | Path] = None) -> Optional[dict]:
    cert_path = active_dir(root) / "fullchain.pem"
    key_path = active_dir(root) / "privkey.pem"
    meta_path = active_dir(root) / "meta.json"
    if not cert_path.is_file() or not key_path.is_file():
        return None
    cert_pem = cert_path.read_bytes()
    meta = {}
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    parsed = parse_cert_meta(cert_pem)
    parsed.update(meta)
    parsed["cert_path"] = str(cert_path)
    parsed["key_path"] = str(key_path)
    return parsed


def _stage_material(root, fullchain: bytes | str, key_pem: bytes | str, meta: dict) -> Path:
    ensure_tree(root)
    stage = staging_dir(root)
    # Clear staging
    for child in stage.iterdir():
        if child.is_file():
            child.unlink()
    _write_public_file(stage / "fullchain.pem", fullchain, 0o644)
    _write_secret_file(stage / "privkey.pem", key_pem, 0o600)
    public_meta = {
        k: meta.get(k)
        for k in (
            "fingerprint_sha256",
            "issuer",
            "subject_cn",
            "not_before",
            "not_after",
            "days_remaining",
            "sans",
            "mode",
            "hostname",
        )
        if k in meta
    }
    _write_public_file(stage / "meta.json", json.dumps(public_meta, indent=2, sort_keys=True) + "\n", 0o644)
    return stage


def _activate_staged(root) -> None:
    """Atomically move staging → active, preserving previous."""
    ensure_tree(root)
    stage = staging_dir(root)
    active = active_dir(root)
    previous = previous_dir(root)
    if not (stage / "fullchain.pem").is_file() or not (stage / "privkey.pem").is_file():
        raise McpTlsError("staged certificate material is incomplete", failure_class="ACTIVATION_FAILED")
    # Move active → previous (best effort)
    if (active / "fullchain.pem").is_file():
        for child in list(previous.iterdir()):
            if child.is_file():
                child.unlink()
        for name in ("fullchain.pem", "privkey.pem", "meta.json"):
            src = active / name
            if src.is_file():
                shutil.copy2(src, previous / name)
                if name == "privkey.pem":
                    os.chmod(previous / name, 0o600)
    for name in ("fullchain.pem", "privkey.pem", "meta.json"):
        src = stage / name
        if not src.is_file():
            continue
        dst = active / name
        tmp = active / (name + ".new")
        shutil.copy2(src, tmp)
        if name == "privkey.pem":
            os.chmod(tmp, 0o600)
        else:
            os.chmod(tmp, 0o644)
        durable_replace(tmp, dst)
        if name == "privkey.pem":
            os.chmod(dst, 0o600)
    # Clear staging secrets
    for child in stage.iterdir():
        if child.is_file():
            child.unlink()


def restore_previous_on_failure(root) -> bool:
    """If previous material exists, copy it back to active. Returns True if restored."""
    previous = previous_dir(root)
    active = active_dir(root)
    if not (previous / "fullchain.pem").is_file() or not (previous / "privkey.pem").is_file():
        return False
    for name in ("fullchain.pem", "privkey.pem", "meta.json"):
        src = previous / name
        if not src.is_file():
            continue
        dst = active / name
        shutil.copy2(src, dst)
        if name == "privkey.pem":
            os.chmod(dst, 0o600)
    return True


# ---------------------------------------------------------------------------
# ACME (python3-acme)
# ---------------------------------------------------------------------------

def _parse_acme_version(raw: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in str(raw or "").strip().split("."):
        digits = ""
        for ch in token:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def acme_runtime_status() -> dict:
    """Report whether the supported packaged ACME runtime is importable."""
    status = {
        "ok": False,
        "implementation": ACME_IMPLEMENTATION,
        "package": ACME_DISTRO_PACKAGE,
        "min_version": "%d.%d" % ACME_MIN_VERSION,
        "version": "",
        "detail": "",
    }
    try:
        import acme  # noqa: F401
        from acme import challenges, client, messages  # noqa: F401
        import josepy  # noqa: F401
    except ImportError as exc:
        status["detail"] = "missing %s (and josepy): %s" % (ACME_DISTRO_PACKAGE, exc)
        return status
    version = ""
    try:
        from importlib import metadata as importlib_metadata

        version = importlib_metadata.version("acme")
    except Exception:
        version = getattr(acme, "__version__", "") or ""
    status["version"] = str(version or "")
    parsed = _parse_acme_version(status["version"])
    if parsed and parsed < ACME_MIN_VERSION:
        status["detail"] = "python3-acme %s is below supported minimum %s.%s" % (
            status["version"],
            ACME_MIN_VERSION[0],
            ACME_MIN_VERSION[1],
        )
        return status
    status["ok"] = True
    status["detail"] = "python3-acme %s" % (status["version"] or "unknown")
    return status


def _require_acme():
    status = acme_runtime_status()
    if not status.get("ok"):
        raise McpTlsError(
            "AUTO_ACME requires distro package %s (>= %s.%s); %s"
            % (
                ACME_DISTRO_PACKAGE,
                ACME_MIN_VERSION[0],
                ACME_MIN_VERSION[1],
                status.get("detail") or "not installed",
            ),
            failure_class="DEPENDENCY_MISSING",
        )
    return True


def _account_key_path(root) -> Path:
    return account_dir(root) / "account.key"


def _account_regr_path(root) -> Path:
    return account_dir(root) / "regr.json"


def _load_or_create_account_key(root):
    _require_acme()
    import josepy as jose
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ensure_tree(root)
    path = _account_key_path(root)
    if path.is_file():
        raw = path.read_bytes()
        key = serialization.load_pem_private_key(raw, password=None)
        return jose.JWKRSA(key=key)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_secret_file(path, pem, 0o600)
    return jose.JWKRSA(key=key)


def _persist_account_regr(root, regr) -> None:
    """Persist non-secret ACME account URI for reuse (never stores private keys)."""
    ensure_tree(root)
    uri = getattr(regr, "uri", None) or ""
    if not uri:
        return
    payload = {"uri": str(uri)}
    path = _account_regr_path(root)
    _write_public_file(path, json.dumps(payload, indent=2, sort_keys=True) + "\n", 0o644)


def _load_account_regr_uri(root) -> str:
    path = _account_regr_path(root)
    if not path.is_file():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(data, dict):
        return ""
    return str(data.get("uri") or "").strip()


def _acme_client(root, directory_url: str, account_key):
    from acme import client

    net = client.ClientNetwork(account_key, user_agent="DataRelayLink-MCP-TLS/%s" % ACME_IMPLEMENTATION_VERSION)
    try:
        directory = client.ClientV2.get_directory(directory_url, net)
    except Exception as exc:
        raise McpTlsError(
            "ACME directory is unreachable: %s" % directory_url,
            failure_class="ACME_UNAVAILABLE",
        ) from exc
    return client.ClientV2(directory, net)


def _new_registration_message(email: str):
    from acme import messages

    kwargs = {"terms_of_service_agreed": True}
    text = (email or "").strip()
    if text:
        kwargs["email"] = text
    return messages.NewRegistration.from_data(**kwargs)


def _ensure_acme_account(acme_client, root, email: str):
    """Register or bind an existing ACME account for the local account key.

    Compatible with packaged python3-acme on Ubuntu 24.04 (2.9.x) and EL8 EPEL
    (1.22.x): new_account + ConflictError → query_registration(uri).
    """
    from acme import errors, messages

    # Fast path: previously persisted account URI.
    uri = _load_account_regr_uri(root)
    if uri:
        try:
            regr = messages.RegistrationResource(body=messages.Registration(), uri=uri)
            regr = acme_client.query_registration(regr)
            _persist_account_regr(root, regr)
            return regr
        except Exception:
            # Fall through to create / conflict recovery.
            pass

    reg = _new_registration_message(email)
    try:
        regr = acme_client.new_account(reg)
    except errors.ConflictError as exc:
        location = getattr(exc, "location", None) or ""
        if not location:
            raise McpTlsError(
                "ACME account already exists but registration URL was not returned",
                failure_class="ACME_ACCOUNT_FAILED",
            ) from exc
        regr = messages.RegistrationResource(body=messages.Registration(), uri=location)
        try:
            regr = acme_client.query_registration(regr)
        except Exception as query_exc:
            raise McpTlsError(
                "ACME account registration conflict could not be resolved",
                failure_class="ACME_ACCOUNT_FAILED",
            ) from query_exc
    except messages.Error as exc:
        typ = str(getattr(exc, "typ", "") or getattr(exc, "type", "") or "").lower()
        detail = str(getattr(exc, "detail", "") or exc)
        if "invalidcontact" in typ or "invalid contact" in detail.lower():
            raise McpTlsError(
                "ACME contact email was rejected by the CA",
                failure_class="ACME_ACCOUNT_FAILED",
            ) from exc
        raise McpTlsError(
            "ACME account registration failed",
            failure_class="ACME_ACCOUNT_FAILED",
        ) from exc
    except McpTlsError:
        raise
    except Exception as exc:
        raise McpTlsError(
            "ACME account registration failed",
            failure_class="ACME_ACCOUNT_FAILED",
        ) from exc
    _persist_account_regr(root, regr)
    return regr


def _classify_acme_messages_error(exc, *, default: str) -> str:
    typ = str(getattr(exc, "typ", "") or getattr(exc, "type", "") or "").lower()
    detail = str(getattr(exc, "detail", "") or exc).lower()
    blob = "%s %s" % (typ, detail)
    if "ratelimit" in blob or "rate limited" in blob:
        return "ACME_RATE_LIMIT"
    if "unauthorized" in blob or "rejectedidentifier" in blob or "dns" in blob:
        return "ACME_AUTHORIZATION_FAILED"
    if "malformed" in blob:
        return default
    return default


def _write_http01_challenge(root, token: str, validation: str) -> Path:
    ensure_tree(root)
    # ACME HTTP-01 token path is /.well-known/acme-challenge/<token>
    dest = challenges_dir(root) / token
    # Challenge responses are not private keys but must be world-readable for nginx.
    _write_public_file(dest, validation + "\n", 0o644)
    return dest


def _clear_http01_challenges(root) -> None:
    path = challenges_dir(root)
    if not path.is_dir():
        return
    for child in path.iterdir():
        if child.is_file():
            try:
                child.unlink()
            except OSError:
                pass


def issue_acme_certificate(
    root,
    *,
    hostname: str,
    directory_url: str,
    contact_email: str = "",
    timeout_sec: int = 120,
) -> dict:
    """Perform ACME issuance using python3-acme (HTTP-01). No long DB txn here."""
    _require_acme()
    from acme import challenges, errors, messages
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes

    host = canonicalize_hostname(hostname)
    if is_private_only_hostname(host):
        raise McpTlsError("AUTO_ACME rejects private-only hostnames", failure_class="HOSTNAME_INVALID")
    ensure_http01_publish_permissions(root)
    account_key = _load_or_create_account_key(root)
    try:
        acme_client = _acme_client(root, directory_url, account_key)
    except McpTlsError:
        raise
    except Exception as exc:
        raise McpTlsError(
            "ACME directory is unreachable",
            failure_class="ACME_UNAVAILABLE",
        ) from exc
    try:
        _ensure_acme_account(acme_client, root, contact_email)
    except McpTlsError:
        raise
    except Exception as exc:
        raise McpTlsError(
            "ACME account registration failed",
            failure_class="ACME_ACCOUNT_FAILED",
        ) from exc

    # CSR
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(pkey, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    key_pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    try:
        order = acme_client.new_order(csr_pem)
    except messages.Error as exc:
        failure = _classify_acme_messages_error(exc, default="ACME_ORDER_FAILED")
        raise McpTlsError("ACME new order failed", failure_class=failure) from exc
    except Exception as exc:
        msg = str(exc).lower()
        failure = "ACME_ORDER_FAILED"
        if "ratelimit" in msg or "rate limited" in msg:
            failure = "ACME_RATE_LIMIT"
        raise McpTlsError("ACME new order failed", failure_class=failure) from exc

    try:
        for authz in order.authorizations:
            http_chall = None
            for challb in authz.body.challenges:
                if isinstance(challb.chall, challenges.HTTP01):
                    http_chall = challb
                    break
            if http_chall is None:
                raise McpTlsError("ACME server did not offer HTTP-01", failure_class="ACME_CHALLENGE_UNSUPPORTED")
            response, validation = http_chall.response_and_validation(account_key)
            chall_path = str(getattr(http_chall.chall, "path", "") or "")
            if not chall_path:
                raise McpTlsError("ACME HTTP-01 challenge path missing", failure_class="ACME_CHALLENGE_UNSUPPORTED")
            token_s = chall_path.rstrip("/").split("/")[-1]
            _write_http01_challenge(root, token_s, validation)
            acme_client.answer_challenge(http_chall, response)

        deadline = datetime.now() + timedelta(seconds=timeout_sec)
        try:
            order = acme_client.poll_and_finalize(order, deadline=deadline)
        except errors.TimeoutError as exc:
            raise McpTlsError("ACME certificate issuance timed out", failure_class="ACME_TIMEOUT") from exc
        except errors.ValidationError as exc:
            raise McpTlsError(
                "ACME HTTP-01 challenge validation failed",
                failure_class="ACME_AUTHORIZATION_FAILED",
            ) from exc
        except messages.Error as exc:
            failure = _classify_acme_messages_error(exc, default="ACME_AUTHORIZATION_FAILED")
            raise McpTlsError("ACME challenge or finalize failed", failure_class=failure) from exc
        except Exception as exc:
            msg = str(exc).lower()
            failure = "ACME_AUTHORIZATION_FAILED"
            if "ratelimit" in msg or "rate limited" in msg:
                failure = "ACME_RATE_LIMIT"
            raise McpTlsError("ACME challenge or finalize failed", failure_class=failure) from exc
    finally:
        _clear_http01_challenges(root)

    fullchain = order.fullchain_pem
    if not fullchain:
        raise McpTlsError("ACME returned empty certificate chain", failure_class="ACME_ISSUANCE_FAILED")
    meta = validate_cert_key_pair(fullchain, key_pem, hostname=host)
    meta["mode"] = MODE_AUTO_ACME
    meta["hostname"] = host
    meta["fullchain_pem"] = fullchain.encode("utf-8") if isinstance(fullchain, str) else fullchain
    meta["key_pem"] = key_pem
    return meta


# ---------------------------------------------------------------------------
# PRIVATE_CA issuance (reuse DRLink PKI)
# ---------------------------------------------------------------------------

def issue_private_ca_certificate(root, *, hostname: str, pki_dir: Optional[str | Path] = None) -> dict:
    host = canonicalize_hostname(hostname)
    x509, hashes, serialization, ec, rsa, NameOID = _load_cryptography()
    base = Path(pki_dir) if pki_dir else (_root(root) / "etc" / "drlink" / "pki")
    ca_crt = base / "ca.crt"
    ca_key = base / "ca.key"
    if not ca_crt.is_file() or not ca_key.is_file():
        raise McpTlsError(
            "DRLink private CA is not available; install/run server PKI first",
            failure_class="PRIVATE_CA_MISSING",
        )
    ca_cert = x509.load_pem_x509_certificate(ca_crt.read_bytes())
    ca_private = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(pkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_private, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fullchain = cert_pem + ca_crt.read_bytes()
    meta = validate_cert_key_pair(fullchain, key_pem, hostname=host)
    meta["mode"] = MODE_PRIVATE_CA
    meta["hostname"] = host
    meta["fullchain_pem"] = fullchain
    meta["key_pem"] = key_pem
    meta["private_ca_warning"] = True
    return meta


# ---------------------------------------------------------------------------
# Frontend reload / HTTPS health
# ---------------------------------------------------------------------------

def reload_frontend(root: Optional[str | Path] = None) -> None:
    """Graceful nginx reload when a live frontend is present."""
    base = _root(root)
    pid_path = base / "run" / "drlink" / "frontend" / "nginx.pid"
    if not pid_path.is_file():
        # Unit may manage PID; try systemctl when not under test root.
        if str(base) in ("/", ""):
            try:
                subprocess.run(
                    ["systemctl", "reload", "drlink-frontend.service"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except Exception:
                pass
        return
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except Exception as exc:
        raise McpTlsError("frontend PID is unreadable", failure_class="PROXY_RELOAD_FAILED") from exc
    try:
        os.kill(pid, 1)  # SIGHUP
    except ProcessLookupError as exc:
        raise McpTlsError("frontend process is not running", failure_class="PROXY_RELOAD_FAILED") from exc
    except PermissionError as exc:
        raise McpTlsError("insufficient permission to reload frontend", failure_class="PROXY_RELOAD_FAILED") from exc


def verify_mcp_https(
    hostname: str,
    port: int,
    *,
    ca_file: Optional[str] = None,
    timeout: float = 8.0,
) -> dict:
    """Verify TLS handshake + /mcp routing without disabling verification."""
    host = canonicalize_hostname(hostname)
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    # Hostname validation stays enabled.
    try:
        with socket.create_connection((host if ca_file else "127.0.0.1", int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                # Minimal HTTP GET /mcp — expect 401/405/406/200, not connection failure.
                raw_req = (
                    "GET /mcp HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Connection: close\r\n"
                    "\r\n" % host
                ).encode("ascii")
                tls.sendall(raw_req)
                data = tls.recv(1024)
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "failure_class": "HTTPS_CERT_VERIFY_FAILED", "detail": str(exc)}
    except Exception as exc:
        return {"ok": False, "failure_class": "HTTPS_HEALTH_FAILED", "detail": str(exc)}
    if not data.startswith(b"HTTP/"):
        return {"ok": False, "failure_class": "HTTPS_HEALTH_FAILED", "detail": "non-HTTP response"}
    status_line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
    # Any HTTP response from /mcp means routing is alive (auth may challenge).
    return {"ok": True, "status_line": status_line, "peer_cert_present": bool(cert)}


# ---------------------------------------------------------------------------
# High-level configure / issue / import / renew
# ---------------------------------------------------------------------------

def configure_intent(
    plane,
    *,
    mode: Optional[str] = None,
    hostname: Optional[str] = None,
    contact_email: Optional[str] = None,
    acme_environment: Optional[str] = None,
    acme_directory_url: Optional[str] = None,
    actor: str = "operator",
) -> dict:
    """Record non-secret TLS intent. Does not perform ACME network I/O."""
    state = load_state(plane)
    if mode is not None:
        state["mode"] = normalize_mode(mode)
        if state["mode"] == MODE_AUTO_ACME:
            # Fail closed before advertising AUTO_ACME as configured/ready.
            _require_acme()
    if hostname is not None:
        text = str(hostname).strip()
        if text:
            host = canonicalize_hostname(text)
            if state.get("mode") == MODE_AUTO_ACME and is_private_only_hostname(host):
                raise McpTlsError(
                    "AUTO_ACME requires a public DNS hostname",
                    failure_class="HOSTNAME_INVALID",
                )
            state["hostname"] = host
        else:
            state["hostname"] = ""
    if contact_email is not None:
        email = str(contact_email).strip()
        if email and not _EMAIL_RE.fullmatch(email):
            raise McpTlsError("contact email is invalid", failure_class="EMAIL_INVALID")
        state["contact_email"] = email
    if acme_environment is not None:
        env = str(acme_environment).strip().upper()
        if env not in ACME_ENVIRONMENTS:
            raise McpTlsError("acme environment must be STAGING or PRODUCTION", failure_class="ACME_ENV_INVALID")
        state["acme_environment"] = env
    if acme_directory_url is not None:
        state["acme_directory_url"] = str(acme_directory_url).strip()
    state["cloud_compatible"] = cloud_compatible_for_mode(state["mode"]) if state.get("mode") else None
    state["private_ca_warning"] = state.get("mode") == MODE_PRIVATE_CA
    if state.get("mode") == MODE_AUTO_ACME:
        state["renewal_enabled"] = True
    elif state.get("mode") == MODE_USER_CERTIFICATE:
        state["renewal_enabled"] = False
    elif state.get("mode") == MODE_PRIVATE_CA:
        state["renewal_enabled"] = True  # local reissue before expiry
    save_state(plane, state)
    _audit(
        plane,
        "tls_mode_changed" if mode is not None else "tls_intent_configured",
        hostname=state.get("hostname") or "",
        mode=state.get("mode") or "",
        extra={"acme_environment": state.get("acme_environment")},
    )
    return state


def _with_tls_lock(root, fn):
    ensure_tree(root)
    try:
        with ExclusiveFileLock(lock_path(root), timeout=30):
            return fn()
    except LockTimeout as exc:
        raise McpTlsError(
            "another MCP TLS operation is in progress",
            failure_class="TLS_LOCK_TIMEOUT",
        ) from exc


def activate_material(plane, root, meta: dict, *, reload: bool = True, health_port: Optional[int] = None,
                      health_ca: Optional[str] = None, validate_proxy_cfg: Optional[Callable] = None) -> dict:
    """Stage → validate → activate → reload → health. Preserves previous on failure."""
    host = meta.get("hostname") or load_state(plane).get("hostname")
    mode = meta.get("mode") or load_state(plane).get("mode")

    def _do():
        fullchain = meta["fullchain_pem"]
        key_pem = meta["key_pem"]
        _stage_material(root, fullchain, key_pem, meta)
        if validate_proxy_cfg is not None:
            ok, detail = validate_proxy_cfg()
            if not ok:
                # Leave active untouched.
                for child in staging_dir(root).iterdir():
                    if child.is_file():
                        child.unlink()
                raise McpTlsError(
                    "reverse-proxy configuration validation failed: %s" % detail,
                    failure_class="PROXY_CONFIG_INVALID",
                )
        # Snapshot whether we had a prior valid cert
        prior = read_active_material(root)
        try:
            _activate_staged(root)
            if reload:
                reload_frontend(root)
            if health_port:
                ca = health_ca
                if mode == MODE_PRIVATE_CA and not ca:
                    ca = str(_root(root) / "etc" / "drlink" / "pki" / "ca.crt")
                health = verify_mcp_https(host, health_port, ca_file=ca)
                if not health.get("ok"):
                    # Roll back to previous if available
                    if prior and restore_previous_on_failure(root):
                        try:
                            reload_frontend(root)
                        except Exception:
                            pass
                    raise McpTlsError(
                        "post-activation MCP HTTPS health check failed",
                        failure_class=health.get("failure_class") or "HTTPS_HEALTH_FAILED",
                    )
        except McpTlsError:
            raise
        except Exception as exc:
            if prior and restore_previous_on_failure(root):
                try:
                    reload_frontend(root)
                except Exception:
                    pass
            raise McpTlsError(str(exc), failure_class="ACTIVATION_FAILED") from exc

        state = load_state(plane)
        state["mode"] = mode
        state["hostname"] = host
        state["fingerprint_sha256"] = meta["fingerprint_sha256"]
        state["issuer"] = meta.get("issuer") or ""
        state["not_before"] = meta.get("not_before") or ""
        state["not_after"] = meta.get("not_after") or ""
        state["days_remaining"] = meta.get("days_remaining")
        state["status"] = compute_status(state, meta)
        state["last_success_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        state["last_failure_class"] = ""
        state["pending_intent"] = None
        state["cloud_compatible"] = cloud_compatible_for_mode(mode)
        state["private_ca_warning"] = mode == MODE_PRIVATE_CA
        if mode == MODE_AUTO_ACME:
            state["renewal_enabled"] = True
        save_state(plane, state)
        _audit(
            plane,
            "certificate_activated",
            hostname=host,
            mode=mode,
            extra={
                "fingerprint": meta["fingerprint_sha256"],
                "issuer": meta.get("issuer"),
                "not_after": meta.get("not_after"),
            },
        )
        return state

    return _with_tls_lock(root, _do)


def issue_and_activate(plane, root=None, *, reload: bool = True, health_port: Optional[int] = None,
                       health_ca: Optional[str] = None, validate_proxy_cfg: Optional[Callable] = None,
                       directory_url_override: Optional[str] = None) -> dict:
    """Issue (ACME / PRIVATE_CA) outside DB txn, then atomically activate."""
    root = _root(root)
    state = load_state(plane)
    mode = state.get("mode") or ""
    host = state.get("hostname") or ""
    if not mode:
        raise McpTlsError("configure TLS mode before issuance", failure_class="TLS_MODE_REQUIRED")
    if not host:
        raise McpTlsError("configure MCP TLS hostname before issuance", failure_class="HOSTNAME_REQUIRED")
    if mode == MODE_USER_CERTIFICATE:
        raise McpTlsError(
            "USER_CERTIFICATE mode requires system certificate import, not issue",
            failure_class="TLS_MODE_INVALID",
        )

    # Record pending intent without holding ACME in a write txn.
    state["pending_intent"] = {
        "mode": mode,
        "hostname": host,
        "requested_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    state["status"] = STATUS_PENDING
    save_state(plane, state)
    _audit(plane, "acme_issuance_requested" if mode == MODE_AUTO_ACME else "private_ca_issuance_requested",
           hostname=host, mode=mode)

    try:
        if mode == MODE_AUTO_ACME:
            pre = preflight_hostname(host, require_public_dns=True)
            if not pre["ok"]:
                raise McpTlsError("; ".join(pre["errors"]) or "preflight failed", failure_class="ACME_PREFLIGHT_FAILED")
            directory = directory_url_override or acme_directory_for_env(
                state.get("acme_environment") or ACME_ENV_PRODUCTION,
                state.get("acme_directory_url") or "",
            )
            # Guard: never let automated tests silently hit production if env says staging.
            if (state.get("acme_environment") or "").upper() == ACME_ENV_STAGING and "staging" not in directory and not directory_url_override:
                directory = LE_STAGING_DIRECTORY
            meta = issue_acme_certificate(
                root,
                hostname=host,
                directory_url=directory,
                contact_email=state.get("contact_email") or "",
            )
        elif mode == MODE_PRIVATE_CA:
            meta = issue_private_ca_certificate(root, hostname=host)
        else:
            raise McpTlsError("unsupported TLS mode for issue", failure_class="TLS_MODE_INVALID")
    except McpTlsError as exc:
        state = load_state(plane)
        state["pending_intent"] = None
        state["last_failure_class"] = exc.failure_class
        state["last_failure_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        # Keep prior valid cert status if present
        if state.get("fingerprint_sha256"):
            state["status"] = compute_status(state)
        else:
            state["status"] = STATUS_INVALID
        save_state(plane, state)
        _audit(plane, "acme_issuance_failed" if mode == MODE_AUTO_ACME else "certificate_issuance_failed",
               hostname=host, mode=mode, result="failed", failure_class=exc.failure_class)
        raise

    state = activate_material(
        plane,
        root,
        meta,
        reload=reload,
        health_port=health_port,
        health_ca=health_ca,
        validate_proxy_cfg=validate_proxy_cfg,
    )
    _audit(
        plane,
        "acme_issuance_succeeded" if mode == MODE_AUTO_ACME else "certificate_issuance_succeeded",
        hostname=host,
        mode=mode,
        extra={"fingerprint": state.get("fingerprint_sha256"), "issuer": state.get("issuer")},
    )
    return state


def import_user_certificate(
    plane,
    root,
    *,
    cert_path: str,
    key_path: str,
    chain_path: Optional[str] = None,
    reload: bool = True,
    health_port: Optional[int] = None,
    health_ca: Optional[str] = None,
    validate_proxy_cfg: Optional[Callable] = None,
) -> dict:
    root = _root(root)
    state = load_state(plane)
    host = state.get("hostname") or ""
    if not host:
        raise McpTlsError("configure MCP TLS hostname before import", failure_class="HOSTNAME_REQUIRED")
    # Force mode
    state["mode"] = MODE_USER_CERTIFICATE
    save_state(plane, state)

    try:
        cert_pem = Path(cert_path).read_bytes()
        key_pem = Path(key_path).read_bytes()
    except OSError as exc:
        raise McpTlsError("unable to read certificate or key file", failure_class="IMPORT_READ_FAILED") from exc
    # Reject world-readable private keys as unsafe permissions.
    try:
        mode = stat.S_IMODE(Path(key_path).stat().st_mode)
        if mode & 0o077:
            raise McpTlsError(
                "private key file permissions are too open (require 0600 or stricter)",
                failure_class="UNSAFE_KEY_PERMISSIONS",
            )
    except McpTlsError:
        raise
    except OSError:
        pass
    chain_pem = None
    if chain_path:
        try:
            chain_pem = Path(chain_path).read_bytes()
        except OSError as exc:
            raise McpTlsError("unable to read certificate chain file", failure_class="IMPORT_READ_FAILED") from exc

    try:
        meta = validate_cert_key_pair(cert_pem, key_pem, hostname=host, chain_pem=chain_pem)
    except McpTlsError as exc:
        _audit(plane, "certificate_imported", hostname=host, mode=MODE_USER_CERTIFICATE,
               result="failed", failure_class=exc.failure_class)
        raise
    meta["mode"] = MODE_USER_CERTIFICATE
    meta["hostname"] = host
    meta["key_pem"] = key_pem
    if "fullchain_pem" not in meta:
        meta["fullchain_pem"] = cert_pem

    _audit(plane, "certificate_imported", hostname=host, mode=MODE_USER_CERTIFICATE,
           extra={"fingerprint": meta["fingerprint_sha256"]})
    return activate_material(
        plane,
        root,
        meta,
        reload=reload,
        health_port=health_port,
        health_ca=health_ca,
        validate_proxy_cfg=validate_proxy_cfg,
    )


def renew_if_due(
    plane,
    root=None,
    *,
    force: bool = False,
    reload: bool = True,
    health_port: Optional[int] = None,
    validate_proxy_cfg: Optional[Callable] = None,
    directory_url_override: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict:
    """Renew before expiry. On failure keep current valid certificate."""
    root = _root(root)
    state = load_state(plane)
    mode = state.get("mode") or ""
    if mode not in (MODE_AUTO_ACME, MODE_PRIVATE_CA):
        return {"renewed": False, "reason": "renewal_not_applicable", "state": state}
    if not state.get("renewal_enabled") and not force:
        return {"renewed": False, "reason": "renewal_disabled", "state": state}

    now = now or datetime.now(timezone.utc)
    next_after = str(state.get("next_renewal_after") or "").strip()
    if next_after and not force:
        try:
            # Accept Z
            ts = datetime.fromisoformat(next_after.replace("Z", "+00:00"))
            if now < ts:
                return {"renewed": False, "reason": "backoff", "state": state}
        except Exception:
            pass

    days = state.get("days_remaining")
    active = read_active_material(root)
    if active:
        days = active.get("days_remaining")
        state["days_remaining"] = days
    due = force or days is None or int(days) <= RENEWAL_DAYS_BEFORE_EXPIRY
    if not due:
        return {"renewed": False, "reason": "not_due", "state": state}

    state["status"] = STATUS_RENEWING
    save_state(plane, state)
    _audit(plane, "renewal_attempted", hostname=state.get("hostname") or "", mode=mode)

    prior_fp = state.get("fingerprint_sha256")
    try:
        new_state = issue_and_activate(
            plane,
            root,
            reload=reload,
            health_port=health_port,
            validate_proxy_cfg=validate_proxy_cfg,
            directory_url_override=directory_url_override,
        )
        new_state["last_renewal_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        new_state["renewal_attempt_count"] = 0
        new_state["next_renewal_after"] = ""
        save_state(plane, new_state)
        _audit(plane, "renewal_succeeded", hostname=new_state.get("hostname") or "", mode=mode,
               extra={"fingerprint": new_state.get("fingerprint_sha256")})
        return {"renewed": True, "state": new_state}
    except McpTlsError as exc:
        state = load_state(plane)
        # Preserve prior valid certificate identity
        if prior_fp and read_active_material(root):
            state["fingerprint_sha256"] = prior_fp
            state["status"] = STATUS_RENEWAL_FAILED
        else:
            state["status"] = STATUS_EXPIRED if (days is not None and int(days) < 0) else STATUS_INVALID
        attempt = int(state.get("renewal_attempt_count") or 0) + 1
        state["renewal_attempt_count"] = attempt
        delay = RENEWAL_BACKOFF_SCHEDULE[min(attempt - 1, len(RENEWAL_BACKOFF_SCHEDULE) - 1)]
        state["next_renewal_after"] = (now + timedelta(seconds=delay)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        state["last_failure_class"] = exc.failure_class
        state["last_failure_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        save_state(plane, state)
        _audit(plane, "renewal_failed", hostname=state.get("hostname") or "", mode=mode,
               result="failed", failure_class=exc.failure_class)
        return {"renewed": False, "reason": "failed", "failure_class": exc.failure_class, "state": state}


def clear_tls(plane, root=None, *, purge_secrets: bool = False) -> dict:
    root = _root(root)
    state = default_state()
    save_state(plane, state)
    if purge_secrets:
        tree = tls_tree(root)
        if tree.is_dir():
            shutil.rmtree(tree)
    _audit(plane, "certificate_removed", result="ok")
    return state


def status_view(plane, root=None) -> dict:
    root = _root(root)
    state = load_state(plane)
    active = read_active_material(root)
    if active:
        state["fingerprint_sha256"] = active.get("fingerprint_sha256") or state.get("fingerprint_sha256")
        state["issuer"] = active.get("issuer") or state.get("issuer")
        state["not_before"] = active.get("not_before") or state.get("not_before")
        state["not_after"] = active.get("not_after") or state.get("not_after")
        state["days_remaining"] = active.get("days_remaining")
        state["status"] = compute_status(state, active)
    else:
        state["status"] = compute_status(state)
    mode = state.get("mode") or ""
    host = state.get("hostname") or ""
    url = "https://%s/mcp" % host if host else "Not configured"
    return {
        "url": url,
        "mode": mode or "Not configured",
        "hostname": host or "Not configured",
        "certificate": state.get("status") or STATUS_ABSENT,
        "issuer": state.get("issuer") or "—",
        "expires": state.get("not_after") or "—",
        "days_remaining": state.get("days_remaining"),
        "auto_renewal": "ENABLED" if state.get("renewal_enabled") else "DISABLED",
        "fingerprint_sha256": state.get("fingerprint_sha256") or "",
        "acme_environment": state.get("acme_environment") or "",
        "cloud_compatible": cloud_compatible_for_mode(mode) if mode else None,
        "private_ca_warning": mode == MODE_PRIVATE_CA,
        "last_failure_class": state.get("last_failure_class") or "",
        "last_renewal_at": state.get("last_renewal_at") or "",
        "raw": state,
        "active_cert_path": str(active_dir(root) / "fullchain.pem") if active else "",
        "active_key_path": str(active_dir(root) / "privkey.pem") if active else "",
    }


def format_status(view: dict) -> str:
    lines = [
        "MCP Public Access",
        "",
        "URL:",
        "  %s" % view.get("url"),
        "",
        "TLS mode:",
        "  %s" % view.get("mode"),
        "",
        "Certificate:",
        "  %s" % view.get("certificate"),
        "",
        "Issuer:",
        "  %s" % view.get("issuer"),
        "",
        "Expires:",
        "  %s" % view.get("expires"),
        "",
        "Auto renewal:",
        "  %s" % view.get("auto_renewal"),
    ]
    if view.get("private_ca_warning"):
        lines.extend(
            [
                "",
                "Warning:",
                "  This certificate is signed by the Data Relay Link private CA.",
                "  Cloud-hosted Remote MCP clients that do not trust this CA may reject it.",
            ]
        )
    if view.get("last_failure_class"):
        lines.extend(["", "Last failure class:", "  %s" % view.get("last_failure_class")])
    lines.append("")
    return "\n".join(lines)


def doctor_checks(plane, root=None) -> list[dict]:
    """Read-only doctor facts for MCP public TLS."""
    view = status_view(plane, root)
    checks = []
    mode = view.get("mode") or ""
    if mode in ("", "Not configured"):
        checks.append(
            {
                "id": "mcp_tls_configured",
                "status": "INFO",
                "summary": "MCP public TLS is not configured",
                "detail": "Configure with: set mcp-tls hostname <fqdn> && set mcp-tls mode auto-acme",
            }
        )
        return checks
    checks.append(
        {
            "id": "mcp_tls_mode",
            "status": "PASS",
            "summary": "MCP TLS mode is %s" % mode,
            "detail": "hostname=%s cloud_compatible=%s" % (view.get("hostname"), view.get("cloud_compatible")),
        }
    )
    if mode == MODE_AUTO_ACME:
        acme_status = acme_runtime_status()
        checks.append(
            {
                "id": "mcp_tls_acme_dependency",
                "status": "PASS" if acme_status.get("ok") else "FAIL",
                "summary": (
                    "AUTO_ACME runtime dependency is available"
                    if acme_status.get("ok")
                    else "AUTO_ACME runtime dependency is missing"
                ),
                "detail": "%s package=%s version=%s"
                % (
                    acme_status.get("detail") or "",
                    acme_status.get("package"),
                    acme_status.get("version") or "absent",
                ),
            }
        )
    cert_status = view.get("certificate")
    if cert_status == STATUS_VALID:
        st = "PASS"
    elif cert_status in (STATUS_RENEWAL_DUE, STATUS_RENEWAL_FAILED, STATUS_PENDING):
        st = "WARN"
    elif cert_status in (STATUS_EXPIRED, STATUS_INVALID, STATUS_ABSENT):
        st = "FAIL"
    else:
        st = "WARN"
    checks.append(
        {
            "id": "mcp_tls_certificate",
            "status": st,
            "summary": "MCP certificate status is %s" % cert_status,
            "detail": "issuer=%s expires=%s days_remaining=%s fingerprint=%s"
            % (view.get("issuer"), view.get("expires"), view.get("days_remaining"), (view.get("fingerprint_sha256") or "")[:16]),
        }
    )
    if view.get("private_ca_warning"):
        checks.append(
            {
                "id": "mcp_tls_private_ca_warning",
                "status": "WARN",
                "summary": "PRIVATE_CA is not suitable for cloud-hosted Remote MCP by default",
                "detail": "Use AUTO_ACME or USER_CERTIFICATE with a publicly trusted chain for ChatGPT/Claude cloud connectors",
            }
        )
    key_path = view.get("active_key_path") or ""
    if key_path and Path(key_path).is_file():
        mode_bits = stat.S_IMODE(Path(key_path).stat().st_mode)
        if mode_bits & 0o077:
            checks.append(
                {
                    "id": "mcp_tls_key_permissions",
                    "status": "FAIL",
                    "summary": "MCP TLS private key permissions are too open",
                    "detail": "expected 0600 or stricter",
                }
            )
        else:
            checks.append(
                {
                    "id": "mcp_tls_key_permissions",
                    "status": "PASS",
                    "summary": "MCP TLS private key permissions are restrictive",
                    "detail": "mode=%04o" % mode_bits,
                }
            )
    return checks


def support_bundle_public_meta(plane, root=None) -> dict:
    view = status_view(plane, root)
    return {
        "mode": view.get("mode"),
        "hostname": view.get("hostname"),
        "certificate_status": view.get("certificate"),
        "issuer": view.get("issuer"),
        "fingerprint_sha256": view.get("fingerprint_sha256"),
        "not_after": view.get("expires"),
        "days_remaining": view.get("days_remaining"),
        "auto_renewal": view.get("auto_renewal"),
        "acme_environment": view.get("acme_environment"),
        "last_failure_class": view.get("last_failure_class"),
        "cloud_compatible": view.get("cloud_compatible"),
    }


def bundle_intent_from_item(item: dict) -> dict:
    """Extract non-secret TLS intent from a ConfigurationBundle resource item."""
    if not isinstance(item, dict):
        raise McpTlsError("mcpTls resource must be a mapping", failure_class="BUNDLE_INVALID")
    # Reject secrets hard.
    for key in item.keys():
        lk = str(key).lower().replace("-", "_")
        if lk in (
            "privatekey",
            "private_key",
            "accountkey",
            "account_key",
            "certkey",
            "keypem",
            "key_pem",
            "fullchain",
            "privkey",
            "oauthsecret",
            "bearer",
            "staticbearer",
            "dnsapikey",
            "dns_api_key",
            "dnsapisecret",
        ):
            raise McpTlsError(
                "ConfigurationBundle must not contain TLS private material or secrets",
                failure_class="BUNDLE_TLS_SECRET_FORBIDDEN",
            )
    out = {}
    if "mode" in item:
        out["mode"] = normalize_mode(item["mode"])
    if "hostname" in item:
        out["hostname"] = canonicalize_hostname(item["hostname"]) if item["hostname"] else ""
    if "acmeEnvironment" in item or "acme_environment" in item:
        env = str(item.get("acmeEnvironment") or item.get("acme_environment") or "").upper()
        if env not in ACME_ENVIRONMENTS:
            raise McpTlsError("acmeEnvironment must be STAGING or PRODUCTION", failure_class="BUNDLE_INVALID")
        out["acme_environment"] = env
    if "contactEmail" in item or "contact_email" in item:
        out["contact_email"] = str(item.get("contactEmail") or item.get("contact_email") or "").strip()
    if "acmeDirectoryUrl" in item or "acme_directory_url" in item:
        out["acme_directory_url"] = str(item.get("acmeDirectoryUrl") or item.get("acme_directory_url") or "").strip()
    return out
