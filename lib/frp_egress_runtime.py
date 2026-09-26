#!/usr/bin/env python3
"""Shared Controlled Egress runtime primitives (DNS / connect / HE / relay).

Used by the HTTP/HTTPS forward-proxy gateway and Fixed TCP Egress runtime.
Internet Access policy authority is the SQLite control plane via
drlink_runtime_policy; destination DNS/SSRF validation remains here.
"""
from __future__ import annotations

import importlib.util
import json
import os
import select
import socket
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional

ROOT = os.environ.get("FRP_DEPLOY_TEST_ROOT", "")

CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 120.0
HAPPY_EYEBALLS_DELAY = 0.25
MAX_CONNECT_CANDIDATES = 8
OUTBOUND_CONNECT_ATTEMPTS = int(
    os.environ.get("FRP_EGRESS_OUTBOUND_CONNECT_ATTEMPTS", "64")
)
_OUTBOUND_CONNECT_SEM = threading.BoundedSemaphore(max(1, OUTBOUND_CONNECT_ATTEMPTS))
DEFAULT_DNS_PENDING_LIMIT = 64
DEFAULT_DNS_WORKERS = 8
DNS_TIMEOUT = 5.0
DNS_POSITIVE_TTL = 30.0
DNS_NEGATIVE_TTL = 10.0
RELAY_BUF = 65536
RELAY_MAX_BUFFER = 256 * 1024
SESSION_REVALIDATE_INTERVAL = 2.0
AUDIT_HOSTNAME_REDACTED = "<invalid-or-redacted>"


def _load_module(name: str, rel: str):
    import sys

    existing = sys.modules.get(name)
    if existing is not None and getattr(existing, "__file__", None):
        return existing
    here = Path(__file__).resolve()
    candidates = [
        here.parent / rel,
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
    raise ImportError("missing %s" % rel)


EG = _load_module("frp_egress_control", "frp_egress_control.py")
FP = _load_module("frp_policy_fingerprint", "frp_policy_fingerprint.py")
try:
    RP = _load_module("drlink_runtime_policy", "drlink_runtime_policy.py")
except ImportError:
    RP = None


def audit_safe_hostname(hostname: Optional[str] = None) -> str:
    """Return a conn-log-safe hostname; never a raw request-target or URI."""
    host = str(hostname or "").strip()
    if not host or host == AUDIT_HOSTNAME_REDACTED:
        return AUDIT_HOSTNAME_REDACTED
    if any(ch in host for ch in ("/", "?", "#", "@", " ", "\t", "\r", "\n", "\\")):
        return AUDIT_HOSTNAME_REDACTED
    if "://" in host:
        return AUDIT_HOSTNAME_REDACTED
    if len(host) > 253:
        return AUDIT_HOSTNAME_REDACTED
    return host


def default_resolve(hostname: str) -> list[str]:
    """Resolve hostname once via getaddrinfo. Returns unique IP strings."""
    results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    seen = set()
    out = []
    for _family, _type, _proto, _canon, sockaddr in results:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def default_connect(ip: str, port: int, hostname: str, timeout: float) -> socket.socket:
    """Connect to an already-validated IP. TCP only — no TLS / no re-resolve."""
    del hostname
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
        self._pos: dict[str, tuple[float, list[str]]] = {}
        self._neg: dict[str, tuple[float, str]] = {}

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
        if not ev.wait(timeout=self.timeout + 1.0):
            raise EG.EgressError("DNS resolution timeout")

        with self._lock:
            pos = self._pos.get(host)
            if pos and pos[0] > time.monotonic():
                return list(pos[1])
            neg = self._neg.get(host)
            if neg and neg[0] > time.monotonic():
                raise EG.EgressError(neg[1])
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
    max_candidates: int = MAX_CONNECT_CANDIDATES,
    connect_sem: Optional[threading.BoundedSemaphore] = None,
) -> socket.socket:
    """Race validated IPv6/IPv4 candidates only. First success wins; losers closed."""
    if not validated_ips:
        raise OSError("no validated addresses")
    sem = connect_sem if connect_sem is not None else _OUTBOUND_CONNECT_SEM
    v6 = [ip for ip in validated_ips if ":" in ip]
    v4 = [ip for ip in validated_ips if ":" not in ip]
    ordered = []
    while v6 or v4:
        if v6:
            ordered.append(v6.pop(0))
        if v4:
            ordered.append(v4.pop(0))
    ordered = ordered[: max(1, int(max_candidates))]

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
        remaining = deadline - time.monotonic()
        if remaining <= 0 or stop.is_set():
            return
        acquired = sem.acquire(timeout=remaining)
        if not acquired:
            with lock:
                winner.setdefault("errors", []).append(
                    OSError("outbound connect attempt budget exhausted")
                )
            return
        try:
            if stop.is_set():
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
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
            sem.release()
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

    end = deadline
    while time.monotonic() < end:
        with lock:
            if "sock" in winner:
                break
        if all(not t.is_alive() for t in threads):
            break
        time.sleep(0.01)
    stop.set()
    # In-flight connects use the same deadline, so a short join releases their
    # outbound-attempt slots before this request returns.
    for t in threads:
        t.join(timeout=1.0)
    with lock:
        if "sock" in winner:
            return winner["sock"]
        errs = winner.get("errors") or []
    if errs:
        raise errs[-1]
    raise OSError("connect failed")


class PolicyCache:
    """Canonical Internet Access policy load plane (SQLite SSOT).

    egress-control.json is not authoritative. Invalid/mismatched control-plane
    reload enters unhealthy fail-closed (all authorize DENY).
    """

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.lock = threading.RLock()
        self.fingerprint = None
        self.mtime = None
        self.path = None
        self.cfg = {}
        self.load_error = "not loaded"
        self.engine = EG.PolicyEngine()
        self._cp = None
        self.plane = None
        self._RP = RP
        if RP is not None:
            try:
                self._cp = RP.ControlPlaneCache(config_path)
            except Exception as exc:
                self.load_error = "control plane unavailable: %s" % exc
        else:
            self.load_error = "control plane unavailable: drlink_runtime_policy missing"
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        with self.lock:
            if self._cp is None or self._RP is None:
                self.engine.mark_unhealthy(self.load_error or "control plane unavailable")
                return
            try:
                self._cp.reload(force=force)
                self.cfg = dict(self._cp.cfg)
                self.plane = self._cp.plane
                self.fingerprint = self._cp.fingerprint
                self.load_error = self._cp.load_error
                if self.load_error or self.plane is None:
                    self.engine.mark_unhealthy(self.load_error or "control plane unavailable")
                    return
                gen = self._RP.generation_status(self.plane, "internet")
                if not gen.get("healthy"):
                    self.load_error = gen.get("error") or "internet policy unhealthy"
                    self.engine.mark_unhealthy(self.load_error)
                    return
                # Keep PolicyEngine generation aligned with DB revision for session revalidation.
                rev = int(gen.get("revision") or 0)
                with self.engine._lock:
                    self.engine._generation = rev
                    self.engine._snapshot = EG.compile_policy_snapshot(
                        {
                            "schema_version": EG.EGRESS_SCHEMA_VERSION,
                            "egress_profiles": {},
                            "tcp_relays": {},
                        },
                        generation=rev,
                        healthy=True,
                    )
                    self.engine._last_good = self.engine._snapshot
                self.path = self._RP.runtime_dir(self.plane.root) / "internet-access.json"
                self.load_error = None
            except Exception as exc:
                self.load_error = str(exc)
                self.engine.mark_unhealthy(str(exc))

    def snapshot(self):
        """Return (plane_or_None, load_error, cfg, policy_snapshot)."""
        with self.lock:
            self.reload(force=False)
            snap = self.engine.snapshot()
            if self.plane is None or self.load_error or snap is None or not snap.healthy:
                return None, (self.load_error or "policy unhealthy"), dict(self.cfg), snap
            return self.plane, None, dict(self.cfg), snap

    def _deny_unhealthy(self, load_error, snap, candidate_ips, reason=None) -> dict:
        return {
            "decision": EG.DECISION_DENY,
            "reason": reason
            or (
                EG.REASON_POLICY_UNHEALTHY
                if hasattr(EG, "REASON_POLICY_UNHEALTHY")
                else "POLICY_UNHEALTHY"
            ),
            "load_error": load_error,
            "policy_generation": snap.generation if snap else None,
            "authorized_candidates": [],
            "candidate_ips": list(candidate_ips or []),
        }

    def authorize(
        self,
        *,
        source_ip: str,
        hostname: str,
        port: int,
        protocol: str,
        method=None,
        candidate_ips=None,
    ) -> dict:
        """Authorize on a request-private SQLite connection. Fail closed.

        The cached plane is shared and is only safe while the cache lock is
        held. authorize_internet runs SQL; using that plane after the lock
        drops raises InterfaceError under concurrent CONNECT and can wedge
        later requests. Callers must not see that as a client syntax error.
        """
        isolated = None
        snap = None
        load_error = None
        try:
            with self.lock:
                self.reload(force=False)
                load_error = self.load_error
                snap = self.engine.snapshot()
                unhealthy = (
                    self.plane is None
                    or self._RP is None
                    or self._cp is None
                    or load_error
                    or snap is None
                    or not snap.healthy
                )
            if unhealthy:
                return self._deny_unhealthy(load_error, snap, candidate_ips)
            isolated, iso_err, _cfg = self._cp.open_isolated()
            if isolated is None:
                return self._deny_unhealthy(
                    iso_err or load_error or "control DB unavailable",
                    snap,
                    candidate_ips,
                )
            decision = self._RP.authorize_internet(
                isolated,
                source_ip=source_ip,
                hostname=hostname,
                port=int(port),
                protocol=protocol,
                candidate_ips=candidate_ips,
            )
            if decision.get("decision") == self._RP.DECISION_ALLOW:
                decision["decision"] = EG.DECISION_ALLOW
            else:
                decision["decision"] = EG.DECISION_DENY
            if method is not None:
                decision["method"] = method
            return decision
        except Exception as exc:
            sys.stderr.write(
                "[drlink-egress] internet authorize failed; fail-closed: %s\n" % exc
            )
            return self._deny_unhealthy(
                str(exc),
                snap,
                candidate_ips,
                reason=EG.REASON_AUTHORIZATION_ERROR
                if hasattr(EG, "REASON_AUTHORIZATION_ERROR")
                else "AUTHORIZATION_ERROR",
            )
        finally:
            if isolated is not None:
                try:
                    isolated.close()
                except Exception:
                    pass


def session_still_authorized(
    *,
    cache: PolicyCache,
    session: dict,
    update_generation: Optional[Callable[[str, int], None]] = None,
) -> bool:
    """Option B: re-authorize against current canonical Internet Access policy."""
    if not hasattr(cache, "authorize"):
        return False
    decision = cache.authorize(
        source_ip=session["source_ip"],
        hostname=session["hostname"],
        port=int(session["port"]),
        protocol=session["protocol"],
        method=session.get("method"),
        candidate_ips=session.get("authorized_candidates") or session.get("candidate_ips"),
    )
    if decision.get("decision") == EG.DECISION_ALLOW:
        # Mid-session: require the previously authorized set to remain eligible.
        prev = list(session.get("authorized_candidates") or [])
        now = list(decision.get("authorized_candidates") or [])
        if prev and not set(prev).intersection(now):
            return False
        gen = decision.get("policy_generation")
        if gen is not None:
            if update_generation is not None:
                update_generation(session["session_id"], int(gen))
            session["policy_generation"] = int(gen)
        if now:
            session["authorized_candidates"] = now
        return True
    return False


def relay_bidirectional(
    client: socket.socket,
    upstream: socket.socket,
    *,
    cache: Optional[PolicyCache] = None,
    session: Optional[dict] = None,
    cfg: Optional[dict] = None,
    update_generation: Optional[Callable[[str, int], None]] = None,
    revalidate_interval: float = SESSION_REVALIDATE_INTERVAL,
    idle_timeout: float = IDLE_TIMEOUT,
    authorize_fn: Optional[Callable[..., bool]] = None,
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

    def _still_ok() -> bool:
        if authorize_fn is not None:
            return bool(authorize_fn())
        if cache is None or session is None:
            return True
        return session_still_authorized(
            cache=cache,
            session=session,
            update_generation=update_generation,
        )

    try:
        while True:
            if cache is not None and session is not None:
                now = time.monotonic()
                if now - last_revalidate >= float(revalidate_interval):
                    last_revalidate = now
                    snap = cache.engine.snapshot()
                    cur_gen = int(snap.generation) if snap is not None else -1
                    if cur_gen != int(session.get("policy_generation") or -1):
                        if not _still_ok():
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
                                        "relay_id": session.get("relay_id"),
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
                if time.monotonic() - last_data > float(idle_timeout):
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
