#!/usr/bin/env python3
"""Data Relay Controlled Egress HTTP/HTTPS forward proxy gateway.

Agentless clients use HTTP_PROXY / HTTPS_PROXY. Policy is evaluated from
egress-control.json (separate from inbound Access Control). Default DENY,
fail-closed. Application TLS is never terminated.

v1 model (intentionally small/strict):
- HTTP: absolute-form http:// URI only; one request per connection; protocol=http
- HTTPS: CONNECT + TLS ClientHello SNI binding for ALL https policy ports
- ECH (RFC 9849 encrypted_client_hello / 0xfe0d) → DENY (no TLS interception)
- Policy compile snapshot + generation; Option B session revalidation
- No TLS interception, chunked request bodies, Expect:100-continue, or SOCKS
"""
from __future__ import annotations

import argparse
import json
import os
import re
import select
import socket
import socketserver
import sys
import tempfile
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
RELAY_BUF = 65536
RELAY_MAX_BUFFER = 256 * 1024
# RFC 9849 — TLS Encrypted Client Hello (ECH). Extension type encrypted_client_hello=0xfe0d.
# Reference: https://www.rfc-editor.org/rfc/rfc9849.html (IANA tls-extensiontype-values).
TLS_EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
SESSION_REVALIDATE_INTERVAL = 2.0


def audit_safe_hostname(hostname: Optional[str] = None) -> str:
    """Return a conn-log-safe hostname; never a raw request-target or URI."""
    host = str(hostname or "").strip()
    if not host or host == AUDIT_HOSTNAME_REDACTED:
        return AUDIT_HOSTNAME_REDACTED
    # Refuse anything that looks like a URI, userinfo, path, or query.
    if any(ch in host for ch in ("/", "?", "#", "@", " ", "\t", "\r", "\n", "\\")):
        return AUDIT_HOSTNAME_REDACTED
    if "://" in host:
        return AUDIT_HOSTNAME_REDACTED
    if len(host) > 253:
        return AUDIT_HOSTNAME_REDACTED
    return host


def _load_module(name: str, rel: str):
    import importlib.util

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
            spec.loader.exec_module(mod)
            return mod
    raise SystemExit("ERROR: missing %s" % rel)


EG = _load_module("frp_egress_control", "frp_egress_control.py")


def default_resolve(hostname: str) -> list[str]:
    """Resolve hostname once via getaddrinfo. Returns unique IP strings."""
    results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    seen = set()
    out = []
    for family, _type, _proto, _canon, sockaddr in results:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def default_connect(ip: str, port: int, hostname: str, timeout: float) -> socket.socket:
    """Connect to an already-validated IP. TCP only — no TLS termination."""
    del hostname  # TCP path must not re-resolve
    addr = (ip, port)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(addr)
    except Exception:
        sock.close()
        raise
    return sock


class DnsResolver:
    """Bounded DNS worker pool with coalescing and validated-only caches.

    Security order is preserved by callers:
      resolve ALL → validate ALL → if ANY unsafe DENY ALL → connect only to validated IPs.

    Resource model:
      - at most ``worker_limit`` getaddrinfo workers
      - at most ``pending_limit`` in-flight hostnames (queued + running)
      - hostname coalescing so concurrent callers share one job
      - caller timeout does NOT free pending/worker budget while the worker runs
        (getaddrinfo is not cancellable)

    Never serves stale-while-revalidate for authorization decisions.
    """

    def __init__(
        self,
        *,
        resolve_fn: Callable[[str], list[str]],
        pending_limit: int = DEFAULT_DNS_PENDING_LIMIT,
        worker_limit: int = DEFAULT_DNS_WORKERS,
        timeout: float = DNS_TIMEOUT,
        positive_ttl: float = DNS_POSITIVE_TTL,
        negative_ttl: float = DNS_NEGATIVE_TTL,
    ):
        self.resolve_fn = resolve_fn
        self.pending_limit = max(1, int(pending_limit))
        self.worker_limit = max(1, int(worker_limit))
        self.timeout = float(timeout)
        self.positive_ttl = float(positive_ttl)
        self.negative_ttl = float(negative_ttl)
        self._lock = threading.Lock()
        self._pending = 0
        self._workers_busy = 0
        self._queue: deque[str] = deque()
        self._inflight: dict[str, threading.Event] = {}
        self._inflight_result: dict[str, object] = {}
        self._pos: dict[str, tuple[float, list[str]]] = {}  # host -> (expires, validated ips)
        self._neg: dict[str, tuple[float, str]] = {}  # host -> (expires, reason)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return self._pending

    @property
    def workers_busy(self) -> int:
        with self._lock:
            return self._workers_busy

    @property
    def positive_cache_size(self) -> int:
        with self._lock:
            return len(self._pos)

    @property
    def negative_cache_size(self) -> int:
        with self._lock:
            return len(self._neg)

    def resolve_validated(self, hostname: str) -> list[str]:
        host = str(hostname).lower().strip()
        now = time.monotonic()
        ev: Optional[threading.Event] = None
        with self._lock:
            neg = self._neg.get(host)
            if neg and neg[0] > now:
                raise EG.EgressError(neg[1])
            if neg and neg[0] <= now:
                self._neg.pop(host, None)
            pos = self._pos.get(host)
            if pos and pos[0] > now:
                return list(pos[1])
            if pos and pos[0] <= now:
                self._pos.pop(host, None)

            if host in self._inflight:
                ev = self._inflight[host]
            else:
                if self._pending >= self.pending_limit:
                    raise EG.EgressError("DNS pending limit reached")
                ev = threading.Event()
                self._inflight[host] = ev
                self._inflight_result.pop(host, None)
                self._pending += 1
                self._queue.append(host)
                self._dispatch_unlocked()

        assert ev is not None
        # Caller timeout is independent of worker lifetime: do not release
        # pending/worker budget here if the Event is not yet set.
        if not ev.wait(timeout=self.timeout + 1.0):
            raise EG.EgressError("DNS resolution timeout")

        with self._lock:
            # Durable caches are authoritative after the Event fires.
            pos = self._pos.get(host)
            if pos and pos[0] > time.monotonic():
                return list(pos[1])
            neg = self._neg.get(host)
            if neg and neg[0] > time.monotonic():
                raise EG.EgressError(neg[1])
            # Extremely narrow race: Event set but caches not yet visible.
            result = self._inflight_result.get(host)
            if isinstance(result, Exception):
                raise result
            if isinstance(result, list):
                return list(result)
        raise EG.EgressError("DNS resolution failed")

    def _dispatch_unlocked(self) -> None:
        while self._queue and self._workers_busy < self.worker_limit:
            host = self._queue.popleft()
            self._workers_busy += 1
            threading.Thread(
                target=self._run_job,
                args=(host,),
                name=f"drlink-dns-{host[:48]}",
                daemon=True,
            ).start()

    def _run_job(self, host: str) -> None:
        err: Optional[BaseException] = None
        validated: Optional[list[str]] = None
        try:
            raw = self.resolve_fn(host)
            validated = EG.validate_resolved_addresses(raw)
        except Exception as exc:  # noqa: BLE001 — surface to waiters fail-closed
            err = exc
        with self._lock:
            self._workers_busy = max(0, self._workers_busy - 1)
            self._pending = max(0, self._pending - 1)
            ev = self._inflight.pop(host, None)
            if err is not None:
                self._neg[host] = (time.monotonic() + self.negative_ttl, str(err))
                if len(self._neg) > 256:
                    for k, _ in sorted(self._neg.items(), key=lambda kv: kv[1][0])[:64]:
                        self._neg.pop(k, None)
            else:
                ips = list(validated or [])
                self._pos[host] = (time.monotonic() + self.positive_ttl, ips)
                if len(self._pos) > 512:
                    for k, _ in sorted(self._pos.items(), key=lambda kv: kv[1][0])[:64]:
                        self._pos.pop(k, None)
            # Never retain _inflight_result after completion — waiters read
            # durable pos/neg caches once the Event is set. This prevents
            # unbounded growth across unique hostnames.
            self._inflight_result.pop(host, None)
            if ev is not None:
                ev.set()
            self._dispatch_unlocked()


def happy_eyeballs_connect(
    connect_fn: Callable[..., socket.socket],
    validated_ips: list[str],
    port: int,
    hostname: str,
    *,
    total_timeout: float = CONNECT_TIMEOUT,
    stagger: float = HAPPY_EYEBALLS_DELAY,
) -> socket.socket:
    """Race validated IPv6/IPv4 candidates only. First success wins; losers closed."""
    if not validated_ips:
        raise OSError("no validated addresses")
    v6 = [ip for ip in validated_ips if ":" in ip]
    v4 = [ip for ip in validated_ips if ":" not in ip]
    ordered = []
    # Prefer one v6 then one v4, then remaining (classic HE-ish).
    while v6 or v4:
        if v6:
            ordered.append(v6.pop(0))
        if v4:
            ordered.append(v4.pop(0))
    # Cap fan-out after full DNS validation; do not weaken validate-all semantics.
    ordered = ordered[:MAX_CONNECT_CANDIDATES]

    winner: dict = {}
    lock = threading.Lock()
    stop = threading.Event()
    threads = []

    def attempt(ip: str, delay: float):
        if delay > 0 and stop.wait(delay):
            return
        if stop.is_set():
            return
        sock = None
        try:
            remaining = max(0.05, total_timeout - delay)
            sock = connect_fn(ip, port, hostname, remaining)
            with lock:
                if "sock" not in winner and not stop.is_set():
                    winner["sock"] = sock
                    sock = None
                    stop.set()
        except OSError as exc:
            with lock:
                winner.setdefault("errors", []).append(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    deadline = time.monotonic() + total_timeout
    for idx, ip in enumerate(ordered):
        delay = idx * stagger
        if time.monotonic() + delay >= deadline:
            break
        t = threading.Thread(target=attempt, args=(ip, delay), daemon=True)
        threads.append(t)
        t.start()

    # Wait until winner or all done / total timeout.
    end = time.monotonic() + total_timeout
    while time.monotonic() < end:
        with lock:
            if "sock" in winner:
                break
        if all(not t.is_alive() for t in threads):
            break
        time.sleep(0.01)
    stop.set()
    for t in threads:
        t.join(timeout=0.2)
    with lock:
        if "sock" in winner:
            return winner["sock"]
        errs = winner.get("errors") or []
    if errs:
        raise errs[-1]
    raise OSError("connect failed")


class PolicyCache:
    """Policy load plane: validate → compile snapshot → generation.

    Invalid reload enters unhealthy fail-closed (all authorize DENY). Last-good
    snapshot is retained for doctor/diagnostics only and is NOT used for live
    authorization while unhealthy.
    """

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.lock = threading.RLock()
        self.mtime = None
        self.path = None
        self.cfg = {}
        self.load_error = "not loaded"
        self.engine = EG.PolicyEngine()
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        with self.lock:
            try:
                self.cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
                self.path = EG.egress_control_path(self.cfg)
                mtime = self.path.stat().st_mtime if self.path.exists() else None
                if not force and mtime == self.mtime and self.load_error is None:
                    snap = self.engine.snapshot()
                    if snap is not None and snap.healthy:
                        return
                if not self.path.exists():
                    self.mtime = mtime
                    self.load_error = "%s missing" % self.path.name
                    self.engine.mark_unhealthy(self.load_error)
                    return
                snap = self.engine.load_from_path(self.path, cfg=self.cfg)
                self.mtime = mtime
                self.load_error = None if snap.healthy else (snap.load_error or "unhealthy")
            except Exception as exc:
                self.load_error = str(exc)
                self.engine.mark_unhealthy(str(exc))

    def snapshot(self):
        """Return (state_or_None, load_error, cfg, policy_snapshot)."""
        with self.lock:
            self.reload(force=False)
            snap = self.engine.snapshot()
            if snap is None or not snap.healthy:
                return None, (self.load_error or "policy unhealthy"), dict(self.cfg), snap
            return dict(snap.state), None, dict(self.cfg), snap


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
    ):
        self.cache = cache
        self.resolve_fn = resolve_fn
        self.connect_fn = connect_fn
        self.max_concurrent = max_concurrent
        self.per_source_limit = per_source_limit
        self.dns_pending_limit = dns_pending_limit
        self.dns_worker_limit = dns_worker_limit
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._active = 0
        self._lock = threading.Lock()
        self.shutting_down = False
        self._per_source: dict[str, int] = {}
        self._sessions: dict[str, dict] = {}
        self.dns = DnsResolver(
            resolve_fn=resolve_fn,
            pending_limit=dns_pending_limit,
            worker_limit=dns_worker_limit,
            timeout=DNS_TIMEOUT,
        )

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
        uri_host, _ = EG.canonicalize_hostname(parts.hostname, allow_wildcard=False)
        uri_port = EG.validate_port(uri_port)

        if ":" in host_header and not host_header.startswith("["):
            hdr_host, hdr_port = EG.parse_authority_host_port(host_header, default_port=uri_port)
        elif host_header.startswith("["):
            hdr_host, hdr_port = EG.parse_authority_host_port(host_header, default_port=uri_port)
        else:
            hdr_host, _ = EG.canonicalize_hostname(host_header, allow_wildcard=False)
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


def _connection_hop_headers(headers: dict[str, str]) -> set[str]:
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
    conn = headers.get("connection")
    if conn:
        for token in conn.split(","):
            name = token.strip().lower()
            if name:
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
) -> tuple[dict, Optional[dict]]:
    """Authorize against compiled policy without DNS/connect/body I/O."""
    state, load_error, cfg, snap = gw.cache.snapshot()
    if snap is not None:
        decision = EG.authorize_against_snapshot(
            snap,
            source_ip=source_ip,
            hostname=hostname,
            port=port,
            protocol=protocol,
            method=method,
        )
    else:
        decision = EG.authorize_request(
            state,
            source_ip=source_ip,
            hostname=hostname,
            port=port,
            protocol=protocol,
            load_error=load_error,
            method=method,
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
    decision, cfg = _authorize_policy_only(
        gw,
        source_ip=source_ip,
        hostname=hostname,
        port=port,
        method=method,
        protocol=protocol,
        connection_id=connection_id,
    )
    if decision.get("decision") != EG.DECISION_ALLOW:
        decision["outcome"] = EG.AUDIT_POLICY_DENY
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision
    return _connect_after_authorize(gw, decision, hostname=hostname, port=port, cfg=cfg)


def _connect_after_authorize(
    gw: GatewayState,
    decision: dict,
    *,
    hostname: str,
    port: int,
    cfg: Optional[dict] = None,
) -> tuple[Optional[socket.socket], dict]:
    """DNS + connect for an already-ALLOW policy decision."""
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

    try:
        sock = happy_eyeballs_connect(
            gw.connect_fn, validated, port, hostname, total_timeout=CONNECT_TIMEOUT
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
    """Option B: re-authorize against current compiled snapshot only."""
    _state, _err, _cfg, snap = gw.cache.snapshot()
    decision = EG.authorize_against_snapshot(
        snap,
        source_ip=session["source_ip"],
        hostname=session["hostname"],
        port=int(session["port"]),
        protocol=session["protocol"],
        method=session.get("method") or "CONNECT",
    )
    if decision.get("decision") == EG.DECISION_ALLOW:
        gen = decision.get("policy_generation")
        if gen is not None:
            gw.update_session_generation(session["session_id"], int(gen))
            session["policy_generation"] = int(gen)
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
    """Bidirectional relay with backpressure and Option B revalidation.

    Returns an audit outcome token.
    """
    client.setblocking(False)
    upstream.setblocking(False)
    c2u = bytearray()
    u2c = bytearray()
    client_open_r = True
    upstream_open_r = True
    client_open_w = True
    upstream_open_w = True
    last_data = time.monotonic()
    last_revalidate = time.monotonic()
    outcome = EG.AUDIT_CLIENT_CLOSED

    def _close_all():
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass

    try:
        while True:
            if gw is not None and session is not None:
                now = time.monotonic()
                if now - last_revalidate >= SESSION_REVALIDATE_INTERVAL:
                    last_revalidate = now
                    snap = gw.cache.engine.snapshot()
                    cur_gen = int(snap.generation) if snap is not None else -1
                    if cur_gen != int(session.get("policy_generation") or -1):
                        if not _session_still_authorized(gw, session):
                            outcome = EG.AUDIT_POLICY_REVOKED
                            if cfg is not None:
                                EG.emit_conn_log(
                                    {
                                        "timestamp": EG.utc_now_iso(),
                                        "connection_id": session.get("connection_id"),
                                        "session_id": session.get("session_id"),
                                        "source_ip": session.get("source_ip"),
                                        "hostname": session.get("hostname"),
                                        "port": session.get("port"),
                                        "protocol": session.get("protocol"),
                                        "method": session.get("method"),
                                        "profile_id": session.get("profile_id"),
                                        "decision": EG.DECISION_DENY,
                                        "reason": EG.REASON_POLICY_REVOKED,
                                        "outcome": EG.AUDIT_POLICY_REVOKED,
                                        "policy_generation": cur_gen,
                                    },
                                    cfg=cfg,
                                )
                            return outcome

            if not client_open_w and not upstream_open_w and not c2u and not u2c:
                return outcome
            if not client_open_r and not upstream_open_r and not c2u and not u2c:
                return outcome

            rlist = []
            wlist = []
            if client_open_r and len(c2u) < RELAY_MAX_BUFFER and upstream_open_w:
                rlist.append(client)
            if upstream_open_r and len(u2c) < RELAY_MAX_BUFFER and client_open_w:
                rlist.append(upstream)
            if c2u and upstream_open_w:
                wlist.append(upstream)
            if u2c and client_open_w:
                wlist.append(client)

            if not rlist and not wlist:
                return outcome

            readable, writable, errored = select.select(
                rlist,
                wlist,
                list({client, upstream}),
                1.0,
            )
            if errored:
                return outcome
            if not readable and not writable:
                if time.monotonic() - last_data > IDLE_TIMEOUT:
                    outcome = EG.AUDIT_IDLE_TIMEOUT
                    return outcome
                continue

            for sock in readable:
                try:
                    data = sock.recv(RELAY_BUF)
                except BlockingIOError:
                    continue
                except OSError:
                    return outcome
                if not data:
                    if sock is client:
                        client_open_r = False
                        # Flush then half-close upstream write.
                        if not c2u and upstream_open_w:
                            try:
                                upstream.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            upstream_open_w = False
                    else:
                        upstream_open_r = False
                        if outcome == EG.AUDIT_CLIENT_CLOSED:
                            outcome = EG.AUDIT_UPSTREAM_CLOSED
                        if not u2c and client_open_w:
                            try:
                                client.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            client_open_w = False
                    continue
                last_data = time.monotonic()
                if sock is client:
                    c2u.extend(data)
                else:
                    u2c.extend(data)

            for sock in writable:
                buf = c2u if sock is upstream else u2c
                if not buf:
                    continue
                try:
                    sent = sock.send(buf)
                except BlockingIOError:
                    continue
                except OSError:
                    return outcome
                if sent:
                    del buf[:sent]
                    last_data = time.monotonic()

            # Complete half-close after draining direction buffers.
            if not client_open_r and not c2u and upstream_open_w:
                try:
                    upstream.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                upstream_open_w = False
            if not upstream_open_r and not u2c and client_open_w:
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                client_open_w = False
    finally:
        _close_all()


def _relay_upstream_response(client: socket.socket, upstream: socket.socket) -> None:
    """One-request HTTP model: only forward upstream → client; never client → upstream."""
    client.setblocking(False)
    upstream.setblocking(False)
    u2c = bytearray()
    upstream_open_r = True
    client_open_w = True
    last_data = time.monotonic()
    try:
        while True:
            if not upstream_open_r and not u2c:
                return
            rlist = []
            wlist = []
            # Detect pipelined second request — read & discard, do not forward.
            rlist.append(client)
            if upstream_open_r and len(u2c) < RELAY_MAX_BUFFER and client_open_w:
                rlist.append(upstream)
            if u2c and client_open_w:
                wlist.append(client)
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
                    # Extra client bytes after the single request: drop & close write to upstream.
                    if extra:
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
        # Worker must never die from unhandled parse/URI exceptions.
        try:
            _send_simple_sock(request, 400, "Bad Request", b"bad request\n")
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
        t.start()

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
    except Exception:
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
