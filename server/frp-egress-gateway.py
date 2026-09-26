#!/usr/bin/env python3
"""Data Relay Link Internet Access HTTP/HTTPS forward proxy gateway.

Agentless clients use HTTP_PROXY / HTTPS_PROXY. Policy is evaluated from the
SQLite control plane (Internet Access rules). Default DENY, fail-closed.
Application TLS is never terminated.

v1 model (intentionally small/strict):
- HTTP: absolute-form http:// URI only; one request per connection; protocol=http
- HTTPS: CONNECT + TLS ClientHello SNI binding for ALL https policy ports
- ECH (RFC 9849 encrypted_client_hello / 0xfe0d) → DENY (no TLS interception)
- Policy compile snapshot + generation; Option B session revalidation
- No TLS interception, chunked request bodies, Expect:100-continue, or SOCKS
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import select
import socket
import socketserver
import sys
import tempfile
import traceback
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

ROOT = os.environ.get("FRP_DEPLOY_TEST_ROOT", "")

MAX_REQUEST_LINE = 8192
MAX_HEADER_BYTES = 65536
MAX_HEADERS = 100
MAX_CONTENT_LENGTH = 64 * 1024 * 1024
CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 120.0
HAPPY_EYEBALLS_DELAY = 0.25
MAX_CONNECT_CANDIDATES = 8
# Global budget for concurrent outbound connect attempts (Happy Eyeballs fan-out).
OUTBOUND_CONNECT_ATTEMPTS = int(
    os.environ.get("FRP_EGRESS_OUTBOUND_CONNECT_ATTEMPTS", "64")
)
_OUTBOUND_CONNECT_SEM = threading.BoundedSemaphore(max(1, OUTBOUND_CONNECT_ATTEMPTS))
CLIENT_HEADER_TIMEOUT = 30.0
CLIENT_BODY_TIMEOUT = 60.0
CLIENT_HELLO_TIMEOUT = 10.0
MAX_CLIENT_HELLO = 16384
DEFAULT_MAX_CONCURRENT = 256
DEFAULT_PER_SOURCE_LIMIT = 32
DEFAULT_DNS_PENDING_LIMIT = 64
DEFAULT_DNS_WORKERS = 8
DNS_TIMEOUT = 5.0
DNS_POSITIVE_TTL = 30.0
DNS_NEGATIVE_TTL = 10.0
AUDIT_HOSTNAME_REDACTED = "<invalid-or-redacted>"
STREAM_BUF = 65536
BODY_MEMORY_THRESHOLD = 256 * 1024  # larger bodies spool to disk before connect
# Aggregate disk/memory spool budget across concurrent requests (inode/disk safety).
DEFAULT_SPOOL_BUDGET_BYTES = 512 * 1024 * 1024
DEFAULT_PER_SOURCE_SPOOL_BYTES = 128 * 1024 * 1024
RELAY_BUF = 65536
RELAY_MAX_BUFFER = 256 * 1024
# RFC 9849 — TLS Encrypted Client Hello (ECH). Extension type encrypted_client_hello=0xfe0d.
# Reference: https://www.rfc-editor.org/rfc/rfc9849.html (IANA tls-extensiontype-values).
TLS_EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
SESSION_REVALIDATE_INTERVAL = 2.0


def _load_module(name: str, rel: str):
    import importlib.util

    existing = sys.modules.get(name)
    if existing is not None and getattr(existing, "__file__", None):
        return existing
    here = Path(__file__).resolve()
    candidates = [
        here.parent.parent / "lib" / rel,
        Path("/usr/local/lib/drlink") / rel,
    ]
    if ROOT:
        candidates.insert(1, Path(ROOT) / "usr/local/lib/drlink" / rel)
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location(name, str(path))
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            return mod
    raise SystemExit("ERROR: missing %s" % rel)


EG = _load_module("frp_egress_control", "frp_egress_control.py")
FP = _load_module("frp_policy_fingerprint", "frp_policy_fingerprint.py")


RT = _load_module("frp_egress_runtime", "frp_egress_runtime.py")

# Re-export shared runtime primitives (tests mutate gateway module globals).
audit_safe_hostname = RT.audit_safe_hostname
default_resolve = RT.default_resolve
default_connect = RT.default_connect
DnsResolver = RT.DnsResolver
PolicyCache = RT.PolicyCache
CONNECT_TIMEOUT = RT.CONNECT_TIMEOUT
IDLE_TIMEOUT = RT.IDLE_TIMEOUT
HAPPY_EYEBALLS_DELAY = RT.HAPPY_EYEBALLS_DELAY
MAX_CONNECT_CANDIDATES = RT.MAX_CONNECT_CANDIDATES
OUTBOUND_CONNECT_ATTEMPTS = RT.OUTBOUND_CONNECT_ATTEMPTS
_OUTBOUND_CONNECT_SEM = RT._OUTBOUND_CONNECT_SEM
DEFAULT_DNS_PENDING_LIMIT = RT.DEFAULT_DNS_PENDING_LIMIT
DEFAULT_DNS_WORKERS = RT.DEFAULT_DNS_WORKERS
DNS_TIMEOUT = RT.DNS_TIMEOUT
DNS_POSITIVE_TTL = RT.DNS_POSITIVE_TTL
DNS_NEGATIVE_TTL = RT.DNS_NEGATIVE_TTL
RELAY_BUF = RT.RELAY_BUF
RELAY_MAX_BUFFER = RT.RELAY_MAX_BUFFER
SESSION_REVALIDATE_INTERVAL = RT.SESSION_REVALIDATE_INTERVAL
AUDIT_HOSTNAME_REDACTED = RT.AUDIT_HOSTNAME_REDACTED


def happy_eyeballs_connect(
    connect_fn,
    validated_ips,
    port,
    hostname,
    *,
    total_timeout=None,
    stagger=None,
):
    """Gateway wrapper so tests can mutate module-level HE budget/sem."""
    return RT.happy_eyeballs_connect(
        connect_fn,
        validated_ips,
        port,
        hostname,
        total_timeout=CONNECT_TIMEOUT if total_timeout is None else total_timeout,
        stagger=HAPPY_EYEBALLS_DELAY if stagger is None else stagger,
        max_candidates=MAX_CONNECT_CANDIDATES,
        connect_sem=_OUTBOUND_CONNECT_SEM,
    )



class GatewayState:
    def __init__(
        self,
        cache: PolicyCache,
        *,
        resolve_fn: Callable[[str], list[str]] = default_resolve,
        connect_fn: Callable[..., socket.socket] = default_connect,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        per_source_limit: int = DEFAULT_PER_SOURCE_LIMIT,
        dns_pending_limit: int = DEFAULT_DNS_PENDING_LIMIT,
        dns_worker_limit: int = DEFAULT_DNS_WORKERS,
        spool_budget_bytes: int = DEFAULT_SPOOL_BUDGET_BYTES,
        per_source_spool_bytes: int = DEFAULT_PER_SOURCE_SPOOL_BYTES,
    ):
        self.cache = cache
        self.resolve_fn = resolve_fn
        self.connect_fn = connect_fn
        self.max_concurrent = max_concurrent
        self.per_source_limit = per_source_limit
        self.dns_pending_limit = dns_pending_limit
        self.dns_worker_limit = dns_worker_limit
        self.spool_budget_bytes = max(0, int(spool_budget_bytes))
        self.per_source_spool_bytes = max(0, int(per_source_spool_bytes))
        if self.spool_budget_bytes < MAX_CONTENT_LENGTH:
            # Keep at least one max-sized request representable unless explicitly
            # set lower (tests may inject tiny budgets).
            pass
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._active = 0
        self._lock = threading.Lock()
        self.shutting_down = False
        self._per_source: dict[str, int] = {}
        self._sessions: dict[str, dict] = {}
        self._spool_used = 0
        self._spool_per_source: dict[str, int] = {}
        self.dns = DnsResolver(
            resolve_fn=resolve_fn,
            pending_limit=dns_pending_limit,
            worker_limit=dns_worker_limit,
            timeout=DNS_TIMEOUT,
        )

    def try_reserve_spool(self, source_ip: str, size: int) -> bool:
        """Reserve aggregate + per-source spool budget. size must be >= 0."""
        if size < 0:
            return False
        if size == 0:
            return True
        with self._lock:
            src_used = self._spool_per_source.get(source_ip, 0)
            if self._spool_used + size > self.spool_budget_bytes:
                return False
            if src_used + size > self.per_source_spool_bytes:
                return False
            self._spool_used += size
            self._spool_per_source[source_ip] = src_used + size
            return True

    def release_spool(self, source_ip: str, size: int) -> None:
        if size <= 0:
            return
        with self._lock:
            self._spool_used = max(0, self._spool_used - size)
            src_used = self._spool_per_source.get(source_ip, 0) - size
            if src_used <= 0:
                self._spool_per_source.pop(source_ip, None)
            else:
                self._spool_per_source[source_ip] = src_used

    def try_acquire(self) -> bool:
        if self.shutting_down:
            return False
        return self._sem.acquire(blocking=False)

    def release(self) -> None:
        self._sem.release()

    def bump_active(self, delta: int) -> int:
        with self._lock:
            self._active += delta
            return self._active

    def try_acquire_source(self, source_ip: str) -> bool:
        with self._lock:
            cur = int(self._per_source.get(source_ip, 0))
            if cur >= int(self.per_source_limit):
                return False
            self._per_source[source_ip] = cur + 1
            return True

    def release_source(self, source_ip: str) -> None:
        with self._lock:
            cur = int(self._per_source.get(source_ip, 0))
            if cur <= 1:
                self._per_source.pop(source_ip, None)
            else:
                self._per_source[source_ip] = cur - 1

    def register_session(self, session: dict) -> None:
        with self._lock:
            self._sessions[session["session_id"]] = session

    def unregister_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def update_session_generation(self, session_id: str, generation: int) -> None:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is not None:
                sess["policy_generation"] = int(generation)



def _send_simple_sock(sock: socket.socket, code: int, reason: str, body: bytes = b"") -> None:
    try:
        header = (
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "Proxy-Connection: close\r\n"
            "\r\n"
            % (code, reason, len(body))
        ).encode("ascii", errors="strict")
        sock.sendall(header + body)
    except OSError:
        pass


_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _header_name_valid(name: str) -> bool:
    """Validate header field-names as RFC 7230 tokens (tchar) before upstream I/O."""
    if not name:
        return False
    for ch in name:
        o = ord(ch)
        if o <= 0x1F or o == 0x7F or ch in " \t:" or o >= 0x80:
            return False
    return bool(_HEADER_NAME_RE.match(name))


def _header_value_safe(value: str) -> bool:
    """Reject CR/LF/NUL/C0 (except HTAB)/DEL/C1 controls in header values."""
    for ch in value:
        o = ord(ch)
        if o == 0 or o == 0x7F:
            return False
        if o < 0x20 and ch != "\t":
            return False
        if 0x80 <= o <= 0x9F:
            return False
    return True


def _read_until_double_crlf(sock: socket.socket, limit: int) -> bytes:
    sock.settimeout(CLIENT_HEADER_TIMEOUT)
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) > limit:
            raise EG.EgressError("request headers too large")
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > limit:
            raise EG.EgressError("request headers too large")
    return bytes(buf)


def _parse_request(raw: bytes) -> tuple[str, str, str, dict[str, str], bytes]:
    if not raw or b"\r\n\r\n" not in raw:
        raise EG.EgressError("incomplete request")
    if b"\x00" in raw.split(b"\r\n\r\n", 1)[0]:
        raise EG.EgressError("NUL in request")
    head, rest = raw.split(b"\r\n\r\n", 1)
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EG.EgressError("non-ASCII request headers") from exc
    if "\n" in text.replace("\r\n", ""):
        # Bare LF / obs-fold ambiguity — fail closed.
        raise EG.EgressError("bare LF in headers")
    lines = text.split("\r\n")
    if not lines or len(lines) > MAX_HEADERS + 1:
        raise EG.EgressError("too many headers")
    request_line = lines[0]
    if len(request_line.encode("ascii")) > MAX_REQUEST_LINE:
        raise EG.EgressError("request line too long")
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise EG.EgressError("malformed request line")
    method, target, version = parts
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise EG.EgressError("unsupported HTTP version")
    if any(ch.isspace() for ch in method) or not method.isalpha():
        raise EG.EgressError("invalid method")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            raise EG.EgressError("malformed header")
        # obs-fold / multiline continuation starts with SP/HTAB.
        if line[0] in (" ", "\t"):
            raise EG.EgressError("folded header not allowed")
        if ":" not in line:
            raise EG.EgressError("malformed header")
        name, value = line.split(":", 1)
        # Reject "Host : example.com" (whitespace before colon) — do not normalize.
        if name != name.strip():
            raise EG.EgressError("whitespace in header name not allowed")
        if not _header_name_valid(name):
            raise EG.EgressError("malformed header name")
        if not _header_value_safe(value):
            raise EG.EgressError("unsafe header value")
        key = name.lower()
        if key in headers:
            if key in ("host", "content-length", "transfer-encoding", "expect", "connection"):
                raise EG.EgressError("duplicate sensitive header: %s" % key)
        headers[key] = value.lstrip(" ")
        if not _header_value_safe(headers[key]):
            raise EG.EgressError("unsafe header value")
    return method.upper(), target, version, headers, rest


def _parse_content_length(headers: dict[str, str]) -> Optional[int]:
    """Validate Content-Length / Transfer-Encoding before any upstream I/O.

    v1: Transfer-Encoding (including chunked) is rejected. Exactly one CL when body
    framing is present. Returns None when no body is declared (length 0).
    """
    te = headers.get("transfer-encoding")
    cl = headers.get("content-length")
    if te is not None:
        raise EG.EgressError("Transfer-Encoding not supported")
    if cl is None:
        return None
    text = cl.strip()
    if not text or not text.isdigit() or text != str(int(text)):
        # Reject negatives, plus signs, whitespace forms, non-decimal.
        if text.startswith("-") or not text.isdigit():
            raise EG.EgressError("invalid Content-Length")
        raise EG.EgressError("invalid Content-Length")
    try:
        value = int(text, 10)
    except ValueError as exc:
        raise EG.EgressError("invalid Content-Length") from exc
    if value < 0:
        raise EG.EgressError("negative Content-Length")
    if value > MAX_CONTENT_LENGTH:
        raise EG.EgressError("Content-Length too large")
    return value


def _expect_100_continue(headers: dict[str, str]) -> bool:
    expect = headers.get("expect")
    if expect is None:
        return False
    return expect.strip().lower() == "100-continue"


def _absolute_uri_authority(target: str, headers: dict[str, str]) -> tuple[str, int, str]:
    """Return (hostname, port, path_query) for absolute-form HTTP proxy requests.

    v1 supports http:// only. Absolute-form https:// is rejected (use CONNECT).
    """
    lower = target.lower()
    if lower.startswith("https://"):
        raise EG.EgressError("absolute-form https URI not supported; use CONNECT")
    if not lower.startswith("http://"):
        raise EG.EgressError("proxy requests must use absolute-form http URI")
    try:
        parts = urlsplit(target)
        if parts.username is not None or parts.password is not None:
            raise EG.EgressError("userinfo is not allowed in URI")
        if not parts.hostname:
            raise EG.EgressError("missing hostname in URI")
        if "@" in (parts.netloc or ""):
            raise EG.EgressError("userinfo is not allowed in URI")
        host_header = headers.get("host")
        if not host_header:
            raise EG.EgressError("missing Host header")

        default_port = 80
        try:
            uri_port = parts.port if parts.port is not None else default_port
        except ValueError as exc:
            raise EG.EgressError("malformed URI port") from exc
        uri_host = EG.normalize_authority_host(parts.hostname)
        uri_port = EG.validate_port(uri_port)

        if ":" in host_header and not host_header.startswith("["):
            hdr_host, hdr_port = EG.parse_authority_host_port(host_header, default_port=uri_port)
        elif host_header.startswith("["):
            hdr_host, hdr_port = EG.parse_authority_host_port(host_header, default_port=uri_port)
        else:
            hdr_host = EG.normalize_authority_host(host_header)
            hdr_port = uri_port

        if hdr_host != uri_host or int(hdr_port) != int(uri_port):
            raise EG.EgressError("URI authority and Host header disagree")

        path = parts.path or "/"
        if parts.query:
            path = path + "?" + parts.query
        return uri_host, uri_port, path
    except EG.EgressError:
        raise
    except (ValueError, TypeError, UnicodeError) as exc:
        raise EG.EgressError("malformed URI") from exc


# Connection tokens that would strip framing/routing headers → reject (400).
_CONNECTION_CRITICAL_TOKENS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
    }
)


def _connection_hop_headers(headers: dict[str, str]) -> set[str]:
    """Build hop-by-hop strip set; reject Connection tokens that nominate framing headers."""
    hop = {
        "proxy-connection",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "expect",
    }
    # Collect all Connection header values (dict may already collapse duplicates).
    conn_values: list[str] = []
    conn = headers.get("connection")
    if conn:
        conn_values.append(conn)
    for key, value in headers.items():
        if key == "connection" and value not in conn_values:
            conn_values.append(value)
    for raw in conn_values:
        for token in raw.split(","):
            name = token.strip().lower()
            if not name:
                continue
            if name in _CONNECTION_CRITICAL_TOKENS:
                raise EG.EgressError(
                    "Connection header must not nominate %s" % name
                )
            hop.add(name)
    return hop


class _BodySpool:
    """Exact Content-Length body held in memory or a private tempfile.

    Full body is received before DNS/connect (incomplete → no upstream I/O),
    but RSS stays bounded for large uploads via disk spooling.
    """

    __slots__ = ("_mem", "_path", "size")

    def __init__(self):
        self._mem: Optional[bytes] = None
        self._path: Optional[str] = None
        self.size = 0

    def close(self) -> None:
        self._mem = None
        if self._path:
            try:
                os.unlink(self._path)
            except OSError:
                pass
            self._path = None

    def send_to(self, upstream: socket.socket) -> None:
        if self.size == 0:
            return
        if self._mem is not None:
            offset = 0
            while offset < len(self._mem):
                upstream.sendall(self._mem[offset : offset + STREAM_BUF])
                offset += STREAM_BUF
            return
        assert self._path is not None
        with open(self._path, "rb") as fh:
            while True:
                chunk = fh.read(STREAM_BUF)
                if not chunk:
                    break
                upstream.sendall(chunk)


def _spool_exact_body(
    sock: socket.socket, body_prefix: bytes, content_length: int
) -> _BodySpool:
    """Receive exactly content_length bytes before any upstream connect."""
    if content_length < 0:
        raise EG.EgressError("invalid Content-Length")
    if len(body_prefix) > content_length:
        raise EG.EgressError("request body exceeds Content-Length")
    spool = _BodySpool()
    spool.size = content_length
    if content_length == 0:
        spool._mem = b""
        return spool
    use_disk = content_length > BODY_MEMORY_THRESHOLD
    sock.settimeout(CLIENT_BODY_TIMEOUT)
    try:
        if not use_disk:
            if len(body_prefix) == content_length:
                spool._mem = body_prefix
                return spool
            chunks = [body_prefix] if body_prefix else []
            got = len(body_prefix)
            while got < content_length:
                chunk = sock.recv(min(STREAM_BUF, content_length - got))
                if not chunk:
                    raise EG.EgressError("incomplete request body")
                chunks.append(chunk)
                got += len(chunk)
            spool._mem = b"".join(chunks)
            return spool
        fd, path = tempfile.mkstemp(prefix="drlink-egress-body-")
        spool._path = path
        with os.fdopen(fd, "wb") as fh:
            if body_prefix:
                fh.write(body_prefix)
            got = len(body_prefix)
            while got < content_length:
                chunk = sock.recv(min(STREAM_BUF, content_length - got))
                if not chunk:
                    raise EG.EgressError("incomplete request body")
                fh.write(chunk)
                got += len(chunk)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return spool
    except Exception:
        spool.close()
        raise


def _read_exact_body(sock: socket.socket, body_prefix: bytes, content_length: int) -> bytes:
    """Compatibility helper: exact body as bytes (small requests / unit tests)."""
    spool = _spool_exact_body(sock, body_prefix, content_length)
    try:
        if spool._mem is not None:
            return spool._mem
        assert spool._path is not None
        with open(spool._path, "rb") as fh:
            return fh.read()
    finally:
        spool.close()


def _stream_request_body(
    client: socket.socket,
    upstream: socket.socket,
    body_prefix: bytes,
    content_length: int,
) -> None:
    """Stream exactly content_length bytes client→upstream (post-connect path).

    Prefer _spool_exact_body before connect for incomplete-body fail-closed.
    """
    if content_length < 0:
        raise EG.EgressError("invalid Content-Length")
    if len(body_prefix) > content_length:
        raise EG.EgressError("request body exceeds Content-Length")
    remaining = content_length
    if body_prefix:
        upstream.sendall(body_prefix)
        remaining -= len(body_prefix)
    client.settimeout(CLIENT_BODY_TIMEOUT)
    while remaining > 0:
        chunk = client.recv(min(STREAM_BUF, remaining))
        if not chunk:
            raise EG.EgressError("incomplete request body")
        if len(chunk) > remaining:
            raise EG.EgressError("request body exceeds Content-Length")
        upstream.sendall(chunk)
        remaining -= len(chunk)


def _new_ids() -> tuple[str, str]:
    import secrets
    return secrets.token_hex(8), secrets.token_hex(8)


def _authorize_policy_only(
    gw: GatewayState,
    *,
    source_ip: str,
    hostname: str,
    port: int,
    method: str,
    protocol: str,
    connection_id: Optional[str] = None,
    candidate_ips: Optional[list[str]] = None,
) -> tuple[dict, Optional[dict]]:
    """Authorize against canonical Internet Access policy without DNS/connect I/O."""
    _plane, load_error, cfg, _snap = gw.cache.snapshot()
    if not hasattr(gw.cache, "authorize"):
        decision = {
            "decision": EG.DECISION_DENY,
            "reason": "CONTROL_PLANE_UNAVAILABLE",
            "detail": load_error or "SQLite control plane authorize unavailable",
            "authorized_candidates": [],
            "candidate_ips": list(candidate_ips or []),
        }
    else:
        decision = gw.cache.authorize(
            source_ip=source_ip,
            hostname=hostname,
            port=port,
            protocol=protocol,
            method=method,
            candidate_ips=candidate_ips,
        )
    decision["method"] = method
    decision["timestamp"] = EG.utc_now_iso()
    if connection_id:
        decision["connection_id"] = connection_id
    return decision, cfg


def _authorize_and_connect(
    gw: GatewayState,
    *,
    source_ip: str,
    hostname: str,
    port: int,
    method: str,
    protocol: str,
    connection_id: Optional[str] = None,
) -> tuple[Optional[socket.socket], dict]:
    """Resolve once (if needed) → policy with candidates → connect only authorized set."""
    _plane, load_error, cfg, _snap = gw.cache.snapshot()
    del _plane, load_error, _snap

    is_literal = False
    try:
        lit = ipaddress.ip_address(str(hostname).strip())
        is_literal = True
        host_token = lit.compressed
    except ValueError:
        host_token = hostname

    if is_literal:
        try:
            if EG.is_unsafe_destination_ip(ipaddress.ip_address(host_token)):
                decision = {
                    "decision": EG.DECISION_DENY,
                    "reason": EG.REASON_UNSAFE_DESTINATION,
                    "outcome": EG.AUDIT_DNS_UNSAFE,
                    "hostname": host_token,
                    "port": port,
                    "method": method,
                    "timestamp": EG.utc_now_iso(),
                    "authorized_candidates": [],
                    "candidate_ips": [],
                }
                if connection_id:
                    decision["connection_id"] = connection_id
                EG.emit_conn_log(decision, cfg=cfg)
                return None, decision
            validated = EG.validate_resolved_addresses([host_token])
        except EG.EgressError:
            decision = {
                "decision": EG.DECISION_DENY,
                "reason": EG.REASON_UNSAFE_DESTINATION,
                "outcome": EG.AUDIT_DNS_UNSAFE,
                "hostname": host_token,
                "port": port,
                "method": method,
                "timestamp": EG.utc_now_iso(),
                "authorized_candidates": [],
                "candidate_ips": [],
            }
            if connection_id:
                decision["connection_id"] = connection_id
            EG.emit_conn_log(decision, cfg=cfg)
            return None, decision
    else:
        try:
            validated = gw.dns.resolve_validated(host_token)
        except EG.EgressError as exc:
            decision = {
                "decision": EG.DECISION_DENY,
                "hostname": host_token,
                "port": port,
                "method": method,
                "timestamp": EG.utc_now_iso(),
                "authorized_candidates": [],
                "candidate_ips": [],
            }
            if connection_id:
                decision["connection_id"] = connection_id
            msg = str(exc).lower()
            if "pending limit" in msg:
                decision["reason"] = EG.REASON_RESOURCE_LIMIT
                decision["outcome"] = EG.AUDIT_RESOURCE_LIMIT
            elif "unsafe" in msg:
                decision["reason"] = EG.REASON_DNS_UNSAFE
                decision["outcome"] = EG.AUDIT_DNS_UNSAFE
            elif "dns" in msg or "resolution" in msg or "no addresses" in msg or "timeout" in msg:
                decision["reason"] = EG.REASON_DNS_FAILURE
                decision["outcome"] = EG.AUDIT_DNS_FAILURE
            else:
                decision["reason"] = EG.REASON_UNSAFE_DESTINATION
                decision["outcome"] = EG.AUDIT_DNS_UNSAFE
            EG.emit_conn_log(decision, cfg=cfg)
            return None, decision
        except OSError:
            decision = {
                "decision": EG.DECISION_DENY,
                "reason": EG.REASON_DNS_FAILURE,
                "outcome": EG.AUDIT_DNS_FAILURE,
                "hostname": host_token,
                "port": port,
                "method": method,
                "timestamp": EG.utc_now_iso(),
                "authorized_candidates": [],
                "candidate_ips": [],
            }
            if connection_id:
                decision["connection_id"] = connection_id
            EG.emit_conn_log(decision, cfg=cfg)
            return None, decision

    decision, cfg = _authorize_policy_only(
        gw,
        source_ip=source_ip,
        hostname=host_token,
        port=port,
        method=method,
        protocol=protocol,
        connection_id=connection_id,
        candidate_ips=validated,
    )
    if decision.get("decision") != EG.DECISION_ALLOW:
        decision["outcome"] = EG.AUDIT_POLICY_DENY
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision

    connect_ips = list(decision.get("authorized_candidates") or [])
    if not connect_ips:
        decision = dict(decision)
        decision["decision"] = EG.DECISION_DENY
        decision["reason"] = EG.REASON_DESTINATION_NOT_ALLOWED
        decision["outcome"] = EG.AUDIT_POLICY_DENY
        decision["timestamp"] = EG.utc_now_iso()
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision

    # DNS rebinding resistance: connect only the policy-validated candidate set.
    decision["candidate_ips"] = list(validated)
    decision["authorized_candidates"] = connect_ips
    return _connect_authorized(gw, decision, hostname=host_token, port=port, connect_ips=connect_ips, cfg=cfg)


def _connect_authorized(
    gw: GatewayState,
    decision: dict,
    *,
    hostname: str,
    port: int,
    connect_ips: list[str],
    cfg: Optional[dict] = None,
) -> tuple[Optional[socket.socket], dict]:
    """Connect only to already-authorized candidate IPs (no re-resolve)."""
    try:
        sock = happy_eyeballs_connect(
            gw.connect_fn, connect_ips, port, hostname, total_timeout=CONNECT_TIMEOUT
        )
        decision["outcome"] = EG.AUDIT_CONNECTED
        EG.emit_conn_log(decision, cfg=cfg)
        return sock, decision
    except OSError:
        decision = dict(decision)
        decision["decision"] = EG.DECISION_DENY
        decision["reason"] = EG.REASON_CONNECT_FAILURE
        decision["outcome"] = EG.AUDIT_CONNECT_FAILURE
        decision["timestamp"] = EG.utc_now_iso()
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision


def _connect_after_authorize(
    gw: GatewayState,
    decision: dict,
    *,
    hostname: str,
    port: int,
    cfg: Optional[dict] = None,
) -> tuple[Optional[socket.socket], dict]:
    """Compatibility wrapper: resolve then filter by authorized candidates if present."""
    authorized = list(decision.get("authorized_candidates") or [])
    if authorized:
        return _connect_authorized(
            gw, decision, hostname=hostname, port=port, connect_ips=authorized, cfg=cfg
        )
    try:
        validated = gw.dns.resolve_validated(hostname)
    except EG.EgressError as exc:
        decision = dict(decision)
        decision["decision"] = EG.DECISION_DENY
        msg = str(exc).lower()
        if "pending limit" in msg:
            decision["reason"] = EG.REASON_RESOURCE_LIMIT
            decision["outcome"] = EG.AUDIT_RESOURCE_LIMIT
        elif "unsafe" in msg:
            decision["reason"] = EG.REASON_DNS_UNSAFE
            decision["outcome"] = EG.AUDIT_DNS_UNSAFE
        elif "dns" in msg or "resolution" in msg or "no addresses" in msg or "timeout" in msg:
            decision["reason"] = EG.REASON_DNS_FAILURE
            decision["outcome"] = EG.AUDIT_DNS_FAILURE
        else:
            decision["reason"] = EG.REASON_UNSAFE_DESTINATION
            decision["outcome"] = EG.AUDIT_DNS_UNSAFE
        decision["timestamp"] = EG.utc_now_iso()
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision
    except OSError:
        decision = dict(decision)
        decision["decision"] = EG.DECISION_DENY
        decision["reason"] = EG.REASON_DNS_FAILURE
        decision["outcome"] = EG.AUDIT_DNS_FAILURE
        decision["timestamp"] = EG.utc_now_iso()
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision

    return _connect_authorized(
        gw, decision, hostname=hostname, port=port, connect_ips=validated, cfg=cfg
    )


def _parse_tls_client_hello_sni(buf: bytes) -> tuple[str, Optional[str]]:
    """Parse buffered TLS bytes for ClientHello SNI.

    Returns:
      ('incomplete', None) — need more bytes
      ('ok', sni_or_None) — complete ClientHello; sni may be None if extension absent
      ('error', reason) — malformed TLS
    """
    if len(buf) < 5:
        return "incomplete", None
    # Reassemble handshake message from one or more TLS records.
    pos = 0
    handshake = bytearray()
    while True:
        if len(buf) < pos + 5:
            return "incomplete", None
        content_type = buf[pos]
        # version = buf[pos+1:pos+3]
        record_len = int.from_bytes(buf[pos + 3 : pos + 5], "big")
        if record_len > 16384:
            return "error", "TLS record too large"
        if len(buf) < pos + 5 + record_len:
            return "incomplete", None
        if content_type != 0x16:  # Handshake
            return "error", "expected TLS handshake record"
        fragment = buf[pos + 5 : pos + 5 + record_len]
        pos += 5 + record_len
        handshake.extend(fragment)
        if len(handshake) < 4:
            continue
        msg_type = handshake[0]
        msg_len = int.from_bytes(handshake[1:4], "big")
        if msg_type != 0x01:
            return "error", "expected ClientHello"
        if len(handshake) < 4 + msg_len:
            continue
        if len(handshake) > 4 + msg_len:
            # Trailing data inside records beyond one handshake — fail closed.
            return "error", "extra handshake data"
        body = bytes(handshake[4 : 4 + msg_len])
        return _extract_sni_from_client_hello_body(body)

    return "incomplete", None


def _extract_sni_from_client_hello_body(body: bytes) -> tuple[str, Optional[str]]:
    try:
        if len(body) < 34:
            return "error", "ClientHello too short"
        idx = 0
        # client_version(2) + random(32)
        idx += 34
        if idx >= len(body):
            return "error", "truncated ClientHello"
        session_id_len = body[idx]
        idx += 1 + session_id_len
        if idx + 2 > len(body):
            return "error", "truncated ClientHello"
        cipher_len = int.from_bytes(body[idx : idx + 2], "big")
        idx += 2 + cipher_len
        if idx >= len(body):
            return "error", "truncated ClientHello"
        comp_len = body[idx]
        idx += 1 + comp_len
        if idx == len(body):
            # No extensions
            return "ok", None
        if idx + 2 > len(body):
            return "error", "truncated ClientHello extensions"
        ext_total = int.from_bytes(body[idx : idx + 2], "big")
        idx += 2
        if idx + ext_total > len(body):
            return "error", "truncated ClientHello extensions"
        end = idx + ext_total
        sni_value = None
        while idx + 4 <= end:
            ext_type = int.from_bytes(body[idx : idx + 2], "big")
            ext_len = int.from_bytes(body[idx + 2 : idx + 4], "big")
            idx += 4
            if idx + ext_len > end:
                return "error", "truncated extension"
            ext_data = body[idx : idx + ext_len]
            idx += ext_len
            if ext_type == TLS_EXT_ENCRYPTED_CLIENT_HELLO:
                # RFC 9849 Encrypted ClientHello — destination identity cannot
                # be verified under strict HTTPS policy without interception.
                return "error", "ECH present"
            if ext_type == 0x0000:  # server_name
                if sni_value is not None:
                    return "error", "duplicate SNI"
                if len(ext_data) < 2:
                    return "error", "invalid SNI"
                list_len = int.from_bytes(ext_data[0:2], "big")
                if list_len + 2 != len(ext_data):
                    return "error", "invalid SNI list length"
                p = 2
                found = None
                while p < len(ext_data):
                    if p + 3 > len(ext_data):
                        return "error", "invalid SNI entry"
                    name_type = ext_data[p]
                    name_len = int.from_bytes(ext_data[p + 1 : p + 3], "big")
                    p += 3
                    if p + name_len > len(ext_data):
                        return "error", "invalid SNI name"
                    if name_type == 0:
                        if found is not None:
                            return "error", "ambiguous SNI"
                        try:
                            found = ext_data[p : p + name_len].decode("ascii")
                        except UnicodeDecodeError:
                            return "error", "non-ASCII SNI"
                    p += name_len
                sni_value = found
        if idx != end:
            return "error", "extension length mismatch"
        return "ok", sni_value
    except (IndexError, ValueError, TypeError):
        return "error", "malformed ClientHello"


def _read_and_validate_client_hello(
    client: socket.socket,
    *,
    expected_hostname: str,
    initial: bytes = b"",
) -> tuple[Optional[bytes], Optional[str], Optional[str]]:
    """Buffer ClientHello, validate SNI == expected_hostname.

    Returns (raw_bytes, observed_sni, error_reason).
    On success error_reason is None and raw_bytes must be forwarded unchanged.
    """
    client.settimeout(CLIENT_HELLO_TIMEOUT)
    buf = bytearray(initial)
    deadline = time.monotonic() + CLIENT_HELLO_TIMEOUT
    while True:
        status, detail = _parse_tls_client_hello_sni(bytes(buf))
        if status == "ok":
            sni = detail
            expected_is_ip = False
            try:
                expected_ip = ipaddress.ip_address(str(expected_hostname).strip())
                expected_is_ip = True
            except ValueError:
                expected_ip = None
            if expected_is_ip:
                # IP-literal CONNECT: SNI may be absent or equal the same IP.
                # Do not require FQDN canonicalization (FQDN SNI binding stays unchanged).
                if not sni:
                    return bytes(buf), None, None
                try:
                    observed_ip = ipaddress.ip_address(str(sni).strip())
                except ValueError:
                    return None, sni, "SNI mismatch"
                if observed_ip != expected_ip:
                    return None, sni, "SNI mismatch"
                return bytes(buf), observed_ip.compressed, None
            if not sni:
                return None, None, "missing SNI"
            try:
                observed, _ = EG.canonicalize_hostname(sni, allow_wildcard=False)
            except EG.EgressError:
                return None, sni, "invalid SNI hostname"
            if observed != expected_hostname:
                return None, observed, "SNI mismatch"
            return bytes(buf), observed, None
        if status == "error":
            return None, None, detail or "invalid ClientHello"
        if len(buf) >= MAX_CLIENT_HELLO:
            return None, None, "ClientHello too large"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, None, "ClientHello timeout"
        client.settimeout(min(CLIENT_HELLO_TIMEOUT, max(0.05, remaining)))
        try:
            chunk = client.recv(min(4096, MAX_CLIENT_HELLO - len(buf)))
        except socket.timeout:
            return None, None, "ClientHello timeout"
        except OSError:
            return None, None, "ClientHello read error"
        if not chunk:
            return None, None, "ClientHello truncated"
        buf.extend(chunk)


def _session_still_authorized(gw: GatewayState, session: dict) -> bool:
    """Option B: re-authorize against current SQLite Internet Access policy only."""
    if not hasattr(gw.cache, "authorize"):
        return False
    decision = gw.cache.authorize(
        source_ip=session["source_ip"],
        hostname=session["hostname"],
        port=int(session["port"]),
        protocol=session["protocol"],
        method=session.get("method") or "CONNECT",
        candidate_ips=session.get("authorized_candidates") or session.get("candidate_ips"),
    )
    if decision.get("decision") == EG.DECISION_ALLOW:
        prev = list(session.get("authorized_candidates") or [])
        now = list(decision.get("authorized_candidates") or [])
        if prev and not set(prev).intersection(now):
            return False
        gen = decision.get("policy_generation")
        if gen is not None:
            gw.update_session_generation(session["session_id"], int(gen))
            session["policy_generation"] = int(gen)
        if now:
            session["authorized_candidates"] = now
        return True
    return False


def _relay_bidirectional(
    client: socket.socket,
    upstream: socket.socket,
    *,
    gw: Optional[GatewayState] = None,
    session: Optional[dict] = None,
    cfg: Optional[dict] = None,
) -> str:
    """Bidirectional relay with backpressure and Option B revalidation."""
    return RT.relay_bidirectional(
        client,
        upstream,
        cache=gw.cache if gw is not None else None,
        session=session,
        cfg=cfg,
        update_generation=gw.update_session_generation if gw is not None else None,
        revalidate_interval=SESSION_REVALIDATE_INTERVAL,
        idle_timeout=IDLE_TIMEOUT,
        authorize_fn=(lambda: _session_still_authorized(gw, session))
        if gw is not None and session is not None
        else None,
    )


def _relay_upstream_response(client: socket.socket, upstream: socket.socket) -> None:
    """One-request HTTP model: only forward upstream → client; never client → upstream.

    Client write half-close (SHUT_WR) is normal after a single request and must not
    busy-spin: once client read-side EOF is observed, stop polling the client fd.
    Idle timeout is evaluated whenever select returns with no ready descriptors.
    """
    client.setblocking(False)
    upstream.setblocking(False)
    u2c = bytearray()
    upstream_open_r = True
    client_open_r = True
    client_open_w = True
    last_data = time.monotonic()
    try:
        while True:
            if not upstream_open_r and not u2c:
                return
            rlist = []
            wlist = []
            # Detect pipelined second request — read & discard, do not forward.
            # After client EOF, omit client from the read set so idle timeout can fire.
            if client_open_r:
                rlist.append(client)
            if upstream_open_r and len(u2c) < RELAY_MAX_BUFFER and client_open_w:
                rlist.append(upstream)
            if u2c and client_open_w:
                wlist.append(client)
            if not rlist and not wlist:
                # Upstream still open but silent and client already EOF: wait on
                # error set only so the idle deadline can still advance.
                _, _, errored = select.select([], [], [client, upstream], 1.0)
                if errored:
                    return
                if time.monotonic() - last_data > IDLE_TIMEOUT:
                    return
                continue
            readable, writable, errored = select.select(
                rlist, wlist, [client, upstream], 1.0
            )
            if errored:
                return
            if not readable and not writable:
                if time.monotonic() - last_data > IDLE_TIMEOUT:
                    return
                continue
            for sock in readable:
                if sock is client:
                    try:
                        extra = sock.recv(RELAY_BUF)
                    except BlockingIOError:
                        continue
                    except OSError:
                        return
                    if not extra:
                        client_open_r = False
                        continue
                    # Extra client bytes after the single request: drop & close write to upstream.
                    try:
                        upstream.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    data = sock.recv(RELAY_BUF)
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if not data:
                    upstream_open_r = False
                    continue
                last_data = time.monotonic()
                u2c.extend(data)
            for sock in writable:
                if sock is not client or not u2c:
                    continue
                try:
                    sent = sock.send(u2c)
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if sent:
                    del u2c[:sent]
                    last_data = time.monotonic()
            if not upstream_open_r and not u2c and client_open_w:
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                client_open_w = False
                return
    finally:
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass


def _deny_sni(
    gw: GatewayState,
    *,
    source_ip: str,
    hostname: str,
    port: int,
    reason: str,
    observed_sni: Optional[str],
    client: socket.socket,
    upstream: socket.socket,
) -> None:
    state, load_error, cfg, _snap = gw.cache.snapshot()
    del state, load_error, _snap
    event = {
        "timestamp": EG.utc_now_iso(),
        "source_ip": source_ip,
        "hostname": audit_safe_hostname(hostname),
        "port": port,
        "protocol": EG.PROTOCOL_HTTPS,
        "method": "CONNECT",
        "decision": EG.DECISION_DENY,
        "reason": reason,
        "outcome": EG.AUDIT_POST_CONNECT_TLS_IDENTITY_DENY,
    }
    if observed_sni is not None:
        event["observed_sni"] = audit_safe_hostname(observed_sni)
    EG.emit_conn_log(event, cfg=cfg)
    try:
        upstream.close()
    except OSError:
        pass
    try:
        client.close()
    except OSError:
        pass


def handle_client(gw: GatewayState, request: socket.socket, client_address) -> None:
    # Concurrency is bounded in ThreadedTCPServer.process_request before the
    # worker thread is created. Do not re-acquire gw._sem here (deadlock).
    source_ip = str(client_address[0])
    if not gw.try_acquire_source(source_ip):
        _state, _err, cfg, _snap = gw.cache.snapshot()
        EG.emit_conn_log(
            {
                "timestamp": EG.utc_now_iso(),
                "source_ip": source_ip,
                "decision": EG.DECISION_DENY,
                "reason": EG.REASON_RESOURCE_LIMIT,
                "outcome": EG.AUDIT_RESOURCE_LIMIT,
            },
            cfg=cfg,
        )
        try:
            _send_simple_sock(request, 503, "Service Unavailable", b"source limit\n")
        finally:
            try:
                request.close()
            except OSError:
                pass
        return
    gw.bump_active(1)
    try:
        _handle_client_inner(gw, request, client_address)
    except Exception:
        # Internal faults are fail-closed. A SQLite/runtime error is not a
        # client syntax error; swallowing it as HTTP 400 hides the cause.
        sys.stderr.write("[drlink-egress] internal failure; fail-closed\n")
        traceback.print_exc(file=sys.stderr)
        try:
            _send_simple_sock(request, 403, "Forbidden", b"authorization unavailable\n")
        except Exception:
            pass
    finally:
        gw.bump_active(-1)
        gw.release_source(source_ip)
        try:
            request.close()
        except OSError:
            pass


def _handle_client_inner(gw: GatewayState, request: socket.socket, client_address) -> None:
    source_ip = str(client_address[0])
    connection_id, _ = _new_ids()
    try:
        raw = _read_until_double_crlf(request, MAX_HEADER_BYTES)
        method, target, version, headers, body_prefix = _parse_request(raw)
    except EG.EgressError:
        _send_simple_sock(request, 400, "Bad Request", b"bad request\n")
        return
    except OSError:
        return

    if method == "CONNECT":
        try:
            host, port = EG.parse_authority_host_port(target)
        except EG.EgressError:
            state, load_error, cfg, _snap = gw.cache.snapshot()
            del state, load_error, _snap
            EG.emit_conn_log(
                {
                    "timestamp": EG.utc_now_iso(),
                    "connection_id": connection_id,
                    "source_ip": source_ip,
                    "hostname": AUDIT_HOSTNAME_REDACTED,
                    "port": None,
                    "method": "CONNECT",
                    "decision": EG.DECISION_DENY,
                    "reason": EG.REASON_MALFORMED_REQUEST,
                },
                cfg=cfg,
            )
            _send_simple_sock(request, 400, "Bad Request", b"bad connect\n")
            return
        # HTTPS policy: CONNECT + ClientHello SNI binding on ALL https ports.
        upstream, decision = _authorize_and_connect(
            gw,
            source_ip=source_ip,
            hostname=host,
            port=port,
            method="CONNECT",
            protocol=EG.PROTOCOL_HTTPS,
            connection_id=connection_id,
        )
        if upstream is None:
            reason = decision.get("reason")
            if reason == EG.REASON_RESOURCE_LIMIT:
                code, label = 503, "Service Unavailable"
            elif reason in (EG.REASON_DNS_FAILURE, EG.REASON_CONNECT_FAILURE):
                code, label = 502, "Bad Gateway"
            else:
                code, label = 403, "Forbidden"
            _send_simple_sock(request, code, label, b"denied\n")
            return
        try:
            request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            upstream.close()
            return

        raw_hello, observed, err = _read_and_validate_client_hello(
            request, expected_hostname=host, initial=body_prefix
        )
        if err is not None:
            # Post-CONNECT identity failures share one explicit deny reason.
            # SNI is validated only after HTTP 200 Connection Established.
            _deny_sni(
                gw,
                source_ip=source_ip,
                hostname=host,
                port=port,
                reason=EG.REASON_POST_CONNECT_TLS_IDENTITY_DENY,
                observed_sni=observed,
                client=request,
                upstream=upstream,
            )
            return
        try:
            upstream.sendall(raw_hello)
        except OSError:
            upstream.close()
            return

        session_id = _new_ids()[1]
        session = {
            "session_id": session_id,
            "connection_id": connection_id,
            "source_ip": source_ip,
            "hostname": host,
            "port": port,
            "protocol": EG.PROTOCOL_HTTPS,
            "method": "CONNECT",
            "profile_id": decision.get("profile_id"),
            "policy_generation": int(decision.get("policy_generation") or 0),
            "candidate_ips": list(decision.get("candidate_ips") or []),
            "authorized_candidates": list(decision.get("authorized_candidates") or []),
            "start_time": time.time(),
        }
        gw.register_session(session)
        try:
            _state, _err, cfg, _snap = gw.cache.snapshot()
            outcome = _relay_bidirectional(request, upstream, gw=gw, session=session, cfg=cfg)
            # POLICY_REVOKED already emitted a correlated deny record inside relay.
            if outcome != EG.AUDIT_POLICY_REVOKED and cfg is not None:
                EG.emit_conn_log(
                    {
                        "timestamp": EG.utc_now_iso(),
                        "connection_id": connection_id,
                        "session_id": session_id,
                        "source_ip": source_ip,
                        "hostname": host,
                        "port": port,
                        "protocol": EG.PROTOCOL_HTTPS,
                        "method": "CONNECT",
                        "profile_id": decision.get("profile_id"),
                        "decision": EG.DECISION_ALLOW,
                        "reason": decision.get("reason"),
                        "outcome": outcome,
                        "policy_generation": session.get("policy_generation"),
                        "session_duration_ms": int(
                            max(0.0, (time.time() - float(session["start_time"])) * 1000.0)
                        ),
                    },
                    cfg=cfg,
                )
        finally:
            gw.unregister_session(session_id)
        return

    # HTTP forward proxy methods
    if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        _send_simple_sock(request, 405, "Method Not Allowed", b"method not allowed\n")
        return

    # Framing validation BEFORE authorize/connect/upstream send.
    try:
        if _expect_100_continue(headers):
            raise EG.EgressError("Expect: 100-continue not supported")
        content_length = _parse_content_length(headers)
        host, port, path = _absolute_uri_authority(target, headers)
        # Reject Connection tokens that would strip Host/CL/TE before any upstream I/O.
        _connection_hop_headers(headers)
        if content_length is None:
            if body_prefix:
                raise EG.EgressError("body without Content-Length")
            content_length = 0
        elif len(body_prefix) > content_length:
            raise EG.EgressError("request body exceeds Content-Length")
    except EG.EgressError:
        state, load_error, cfg, _snap = gw.cache.snapshot()
        del state, load_error, _snap
        EG.emit_conn_log(
            {
                "timestamp": EG.utc_now_iso(),
                "connection_id": connection_id,
                "source_ip": source_ip,
                "hostname": AUDIT_HOSTNAME_REDACTED,
                "port": None,
                "method": method,
                "decision": EG.DECISION_DENY,
                "reason": EG.REASON_MALFORMED_REQUEST,
                "outcome": EG.AUDIT_POLICY_DENY,
            },
            cfg=cfg,
        )
        _send_simple_sock(request, 400, "Bad Request", b"bad request\n")
        return

    # Authorize BEFORE consuming/spooling any remaining body so unauthorized
    # clients cannot force large disk/memory spool or slow-body DoS.
    decision, cfg = _authorize_policy_only(
        gw,
        source_ip=source_ip,
        hostname=host,
        port=port,
        method=method,
        protocol=EG.PROTOCOL_HTTP,
        connection_id=connection_id,
    )
    if decision.get("decision") != EG.DECISION_ALLOW:
        decision["outcome"] = EG.AUDIT_POLICY_DENY
        EG.emit_conn_log(decision, cfg=cfg)
        reason = decision.get("reason")
        if reason == EG.REASON_RESOURCE_LIMIT:
            code, label = 503, "Service Unavailable"
        else:
            code, label = 403, "Forbidden"
        _send_simple_sock(request, code, label, b"denied\n")
        return

    # Allowed: receive the exact body BEFORE DNS/connect so incomplete bodies
    # never create upstream I/O. Large bodies spool to a private tempfile.
    spool: Optional[_BodySpool] = None
    spool_reserved = 0
    if not gw.try_reserve_spool(source_ip, content_length):
        EG.emit_conn_log(
            {
                "timestamp": EG.utc_now_iso(),
                "connection_id": connection_id,
                "source_ip": source_ip,
                "hostname": host,
                "port": port,
                "method": method,
                "decision": EG.DECISION_DENY,
                "reason": EG.REASON_RESOURCE_LIMIT,
                "outcome": EG.AUDIT_RESOURCE_LIMIT,
            },
            cfg=cfg,
        )
        _send_simple_sock(request, 503, "Service Unavailable", b"spool budget exceeded\n")
        return
    spool_reserved = content_length
    try:
        try:
            spool = _spool_exact_body(request, body_prefix, content_length)
        except EG.EgressError:
            state, load_error, cfg2, _snap = gw.cache.snapshot()
            del state, load_error, _snap
            EG.emit_conn_log(
                {
                    "timestamp": EG.utc_now_iso(),
                    "connection_id": connection_id,
                    "source_ip": source_ip,
                    "hostname": host,
                    "port": port,
                    "method": method,
                    "decision": EG.DECISION_DENY,
                    "reason": EG.REASON_MALFORMED_REQUEST,
                    "outcome": EG.AUDIT_POLICY_DENY,
                },
                cfg=cfg2,
            )
            _send_simple_sock(request, 400, "Bad Request", b"bad request\n")
            return

        upstream, decision = _connect_after_authorize(
            gw, decision, hostname=host, port=port, cfg=cfg
        )
        if upstream is None:
            if spool is not None:
                spool.close()
                spool = None
            reason = decision.get("reason")
            if reason == EG.REASON_RESOURCE_LIMIT:
                code, label = 503, "Service Unavailable"
            elif reason in (EG.REASON_DNS_FAILURE, EG.REASON_CONNECT_FAILURE):
                code, label = 502, "Bad Gateway"
            else:
                code, label = 403, "Forbidden"
            _send_simple_sock(request, code, label, b"denied\n")
            return

        hop_by_hop = _connection_hop_headers(headers)
        out_headers = []
        for key, value in headers.items():
            if key in hop_by_hop:
                continue
            out_headers.append("%s: %s" % (key, value))
        if "host" not in headers:
            out_headers.append(
                "Host: %s" % (host if port == 80 else "%s:%d" % (host, port))
            )
        out_headers.append("Connection: close")
        req = "%s %s %s\r\n%s\r\n\r\n" % (method, path, version, "\r\n".join(out_headers))
        try:
            upstream.sendall(req.encode("ascii", errors="strict"))
            assert spool is not None
            spool.send_to(upstream)
            _relay_upstream_response(request, upstream)
        except EG.EgressError:
            try:
                upstream.close()
            except OSError:
                pass
            try:
                _send_simple_sock(request, 400, "Bad Request", b"bad request\n")
            except Exception:
                pass
        except OSError:
            try:
                upstream.close()
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
        finally:
            if spool is not None:
                spool.close()
                spool = None
    finally:
        if spool_reserved:
            gw.release_spool(source_ip, spool_reserved)


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, gw: GatewayState):
        self.gw = gw
        # Bound worker creation itself (not only handler-body acquire).
        self.max_concurrent = int(getattr(gw, "max_concurrent", DEFAULT_MAX_CONCURRENT) or DEFAULT_MAX_CONCURRENT)
        self.request_timeout = float(CLIENT_HEADER_TIMEOUT)
        self._slot_sem = threading.BoundedSemaphore(self.max_concurrent)
        super().__init__(server_address, None)

    def process_request(self, request, client_address):
        try:
            request.settimeout(self.request_timeout)
        except (OSError, AttributeError):
            pass
        if not self._slot_sem.acquire(blocking=False):
            try:
                # Best-effort RESOURCE_LIMIT audit (no secrets).
                _state, _err, cfg, _snap = self.gw.cache.snapshot()
                EG.emit_conn_log(
                    {
                        "timestamp": EG.utc_now_iso(),
                        "source_ip": str(client_address[0]),
                        "decision": EG.DECISION_DENY,
                        "reason": EG.REASON_RESOURCE_LIMIT,
                        "outcome": EG.AUDIT_RESOURCE_LIMIT,
                    },
                    cfg=cfg,
                )
            except Exception:
                pass
            try:
                _send_simple_sock(request, 503, "Service Unavailable", b"server busy\n")
            except Exception:
                pass
            try:
                request.close()
            except OSError:
                pass
            return

        def run():
            try:
                self.finish_request(request, client_address)
            except Exception:
                try:
                    self.handle_error(request, client_address)
                finally:
                    try:
                        self.shutdown_request(request)
                    except Exception:
                        pass
            else:
                try:
                    self.shutdown_request(request)
                except Exception:
                    pass
            finally:
                self._slot_sem.release()

        t = threading.Thread(target=run)
        t.daemon = self.daemon_threads
        try:
            t.start()
        except Exception:
            # run() never executes, so its finally-release never happens: give
            # the slot back here or capacity shrinks permanently.
            try:
                self._slot_sem.release()
            except ValueError:
                pass
            try:
                request.close()
            except OSError:
                pass
            return

    def finish_request(self, request, client_address):
        handle_client(self.gw, request, client_address)

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


def _write_effective_config(host: str, port: int, gw: GatewayState) -> None:
    """Least-privilege runtime snapshot — no CA/token/secrets."""
    try:
        # Isolated RuntimeDirectory=drlink/egress (not shared /run/drlink).
        path = EG._rooted("/run/drlink/egress/effective.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        snap = gw.cache.engine.snapshot()
        doc = {
            "listen_addr": host,
            "listen_port": port,
            "max_concurrent": gw.max_concurrent,
            "per_source_limit": gw.per_source_limit,
            "dns_pending_limit": gw.dns_pending_limit,
            "dns_worker_limit": gw.dns_worker_limit,
            "dns_workers_busy": gw.dns.workers_busy,
            "dns_pending": gw.dns.pending_count,
            "egress_control_file": str(gw.cache.path or ""),
            "policy_generation": gw.cache.engine.generation,
            "policy_healthy": bool(snap and snap.healthy),
            "written_at": EG.utc_now_iso(),
        }
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception as exc:
        sys.stderr.write(
            "[drlink-egress] effective snapshot write failed path=%s error=%s\n"
            % (EG._rooted("/run/drlink/egress/effective.json"), exc)
        )
        return


def serve(
    config_path: Path,
    *,
    bind_host: Optional[str] = None,
    bind_port: Optional[int] = None,
    resolve_fn=default_resolve,
    connect_fn=default_connect,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    per_source_limit: int = DEFAULT_PER_SOURCE_LIMIT,
):
    cache = PolicyCache(config_path)
    host, port = EG.listen_bind(cache.cfg)
    if bind_host is not None:
        host = bind_host
    if bind_port is not None:
        port = bind_port
    if host in ("0.0.0.0", "::"):
        sys.stderr.write(
            "[drlink-egress] WARN: listening on %s (prefer an internal address)\n" % host
        )
    gw = GatewayState(
        cache,
        resolve_fn=resolve_fn,
        connect_fn=connect_fn,
        max_concurrent=max_concurrent,
        per_source_limit=per_source_limit,
    )
    server = ThreadedTCPServer((host, port), gw)
    _write_effective_config(host, port, gw)

    def health_thread():
        while not gw.shutting_down:
            cache.reload(force=False)
            _write_effective_config(host, port, gw)
            time.sleep(2)

    threading.Thread(target=health_thread, name="egress-policy-reload", daemon=True).start()
    sys.stderr.write(
        "[drlink-egress] listening on %s:%d policy=%s generation=%s\n"
        % (host, port, cache.path, cache.engine.generation)
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        gw.shutting_down = True
        server.shutdown()
        server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Data Relay Controlled Egress gateway")
    parser.add_argument(
        "--config",
        default="/etc/drlink/config.json",
        help="path to config.json",
    )
    parser.add_argument("--listen-addr", default=None)
    parser.add_argument("--listen-port", type=int, default=None)
    parser.add_argument("--max-concurrent", type=int, default=DEFAULT_MAX_CONCURRENT)
    args = parser.parse_args(argv)
    config_path = Path(ROOT + args.config if ROOT and args.config.startswith("/") else args.config)
    if ROOT and not str(config_path).startswith(ROOT):
        config_path = Path(ROOT + args.config)
    if not config_path.is_file():
        raise SystemExit("ERROR: missing config %s" % config_path)
    serve(
        config_path,
        bind_host=args.listen_addr,
        bind_port=args.listen_port,
        max_concurrent=args.max_concurrent,
    )


if __name__ == "__main__":
    main()
