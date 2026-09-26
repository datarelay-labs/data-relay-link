#!/usr/bin/env python3
"""Data Relay Fixed TCP Egress runtime.

Destination-pinned TCP relay listeners. Policy is evaluated from the
canonical SQLite Internet Access rulebase (Fixed TCP cannot bypass it).

Security model:
- Server-side DNS only
- resolve ALL → validate ALL → if ANY unsafe DENY ALL
- connect only to validated exact IPs (no DNS re-resolve on connect)
- No TLS interception, CONNECT, SOCKS, or client-chosen destination
- Fail closed; Option B session revalidation
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

ROOT = os.environ.get("FRP_DEPLOY_TEST_ROOT", "")

DEFAULT_MAX_CONCURRENT = 256
DEFAULT_PER_SOURCE_LIMIT = 32
DEFAULT_DNS_PENDING_LIMIT = 64
DEFAULT_DNS_WORKERS = 8


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
RT = _load_module("frp_egress_runtime", "frp_egress_runtime.py")
try:
    RP = _load_module("drlink_runtime_policy", "drlink_runtime_policy.py")
except SystemExit:
    RP = None


class TcpEgressState:
    def __init__(
        self,
        cache: RT.PolicyCache,
        *,
        resolve_fn: Callable[[str], list[str]] = RT.default_resolve,
        connect_fn: Callable[..., socket.socket] = RT.default_connect,
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
        self._lock = threading.Lock()
        self._per_source: dict[str, int] = {}
        self._sessions: dict[str, dict] = {}
        self.shutting_down = False
        self.dns = RT.DnsResolver(
            resolve_fn=resolve_fn,
            pending_limit=dns_pending_limit,
            worker_limit=dns_worker_limit,
            timeout=RT.DNS_TIMEOUT,
        )
        self._servers: dict[str, "RelayServer"] = {}
        self._desired: dict[str, tuple[str, int]] = {}

    def try_acquire(self) -> bool:
        if self.shutting_down:
            return False
        return self._sem.acquire(blocking=False)

    def release(self) -> None:
        self._sem.release()

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


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, state: TcpEgressState, relay_id: str):
        self.state = state
        self.relay_id = relay_id
        super().__init__(server_address, _RelayHandler)
        self.request_queue_size = 64

    def process_request(self, request, client_address):
        """Reserve concurrency slots in the accept loop, before any worker.

        ThreadingMixIn starts a thread here and only then runs the handler, so
        an acquire inside the handler bounds concurrent *sessions* while thread
        creation stays unbounded. Admission must precede Thread.start.
        """
        state = self.state
        source_ip = str(client_address[0])
        if not state.try_acquire():
            self._reject(request, source_ip)
            return
        if not state.try_acquire_source(source_ip):
            state.release()
            self._reject(request, source_ip)
            return
        try:
            thread = threading.Thread(
                target=self._serve_admitted, args=(request, client_address)
            )
            thread.daemon = self.daemon_threads
            thread.start()
        except Exception:
            # The worker never runs, so release the reservations it would have
            # freed; otherwise capacity leaks on every failed thread creation.
            state.release_source(source_ip)
            state.release()
            self.shutdown_request(request)

    def _serve_admitted(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def _reject(self, request, source_ip: str) -> None:
        # Last-loaded cfg only: a rejection must not trigger a policy reload in
        # the accept loop, which is exactly where an overload flood lands.
        try:
            cfg = dict(getattr(self.state.cache, "cfg", None) or {})
        except Exception:
            cfg = {}
        EG.emit_conn_log(
            {
                "timestamp": EG.utc_now_iso(),
                "connection_id": _new_ids()[0],
                "source_ip": source_ip,
                "protocol": EG.PROTOCOL_TCP,
                "relay_id": self.relay_id,
                "decision": EG.DECISION_DENY,
                "reason": EG.REASON_RESOURCE_LIMIT,
                "outcome": EG.AUDIT_RESOURCE_LIMIT,
            },
            cfg=cfg,
        )
        self.shutdown_request(request)


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        state: TcpEgressState = self.server.state  # type: ignore[attr-defined]
        relay_id = self.server.relay_id  # type: ignore[attr-defined]
        # RelayServer.process_request already holds both slots for this socket.
        handle_tcp_client(
            state, self.request, self.client_address, relay_id, admitted=True
        )


def _new_ids() -> tuple[str, str]:
    return secrets.token_hex(8), secrets.token_hex(8)


def handle_tcp_client(
    state: TcpEgressState,
    request: socket.socket,
    client_address,
    relay_id: str,
    admitted: bool = False,
) -> None:
    """Relay one accepted TCP connection.

    ``admitted`` means the caller already reserved the global and per-source
    slots (RelayServer does this before starting the worker); this function
    still owns releasing them.
    """
    source_ip = str(client_address[0])
    connection_id, session_id = _new_ids()
    cfg = {}
    upstream = None
    acquired = bool(admitted)
    source_acquired = bool(admitted)
    try:
        if not admitted:
            if not state.try_acquire():
                EG.emit_conn_log(
                    {
                        "timestamp": EG.utc_now_iso(),
                        "connection_id": connection_id,
                        "source_ip": source_ip,
                        "protocol": EG.PROTOCOL_TCP,
                        "relay_id": relay_id,
                        "decision": EG.DECISION_DENY,
                        "reason": EG.REASON_RESOURCE_LIMIT,
                        "outcome": EG.AUDIT_RESOURCE_LIMIT,
                    },
                    cfg=cfg,
                )
                return
            acquired = True
            if not state.try_acquire_source(source_ip):
                EG.emit_conn_log(
                    {
                        "timestamp": EG.utc_now_iso(),
                        "connection_id": connection_id,
                        "source_ip": source_ip,
                        "protocol": EG.PROTOCOL_TCP,
                        "relay_id": relay_id,
                        "decision": EG.DECISION_DENY,
                        "reason": EG.REASON_RESOURCE_LIMIT,
                        "outcome": EG.AUDIT_RESOURCE_LIMIT,
                    },
                    cfg=cfg,
                )
                return
            source_acquired = True

        policy_plane, load_error, cfg, snap = state.cache.snapshot()
        if RP is None or policy_plane is None or load_error is not None:
            decision = {
                "decision": EG.DECISION_DENY,
                "reason": "CONTROL_PLANE_UNAVAILABLE",
                "detail": load_error or "SQLite control plane unavailable",
            }
        else:
            decision = RP.authorize_fixed_tcp(
                policy_plane,
                relay_id=relay_id,
                source_ip=source_ip,
            )
            if decision.get("decision") == RP.DECISION_ALLOW:
                decision["decision"] = EG.DECISION_ALLOW
            else:
                decision["decision"] = EG.DECISION_DENY
        if snap is not None:
            decision["policy_generation"] = snap.generation
        if decision.get("decision") != EG.DECISION_ALLOW:
            EG.emit_conn_log(
                {
                    "timestamp": EG.utc_now_iso(),
                    "connection_id": connection_id,
                    "source_ip": source_ip,
                    "hostname": decision.get("hostname"),
                    "port": decision.get("port"),
                    "protocol": EG.PROTOCOL_TCP,
                    "profile_id": decision.get("profile_id"),
                    "profile_name": decision.get("profile_name"),
                    "relay_id": relay_id,
                    "relay_name": decision.get("relay_name"),
                    "decision": EG.DECISION_DENY,
                    "reason": decision.get("reason"),
                    "outcome": EG.AUDIT_POLICY_DENY,
                    "policy_generation": decision.get("policy_generation"),
                },
                cfg=cfg,
            )
            return

        hostname = decision.get("hostname")
        port = int(decision.get("port"))
        try:
            validated = state.dns.resolve_validated(hostname)
            upstream = RT.happy_eyeballs_connect(
                state.connect_fn,
                validated,
                port,
                hostname,
                total_timeout=RT.CONNECT_TIMEOUT,
            )
            # Exact IP only — never pass hostname to connect for re-resolve.
            peer = upstream.getpeername()
            connected_ip = peer[0]
            if connected_ip not in validated and connected_ip not in {
                ipaddress_compress(ip) for ip in validated
            }:
                raise EG.EgressError("connect target not in validated set")
        except EG.EgressError as exc:
            msg = str(exc).lower()
            if "unsafe" in msg:
                reason, outcome = EG.REASON_DNS_UNSAFE, EG.AUDIT_DNS_UNSAFE
            elif "dns" in msg or "resolution" in msg or "address" in msg:
                reason, outcome = EG.REASON_DNS_FAILURE, EG.AUDIT_DNS_FAILURE
            else:
                reason, outcome = EG.REASON_CONNECT_FAILURE, EG.AUDIT_CONNECT_FAILURE
            EG.emit_conn_log(
                {
                    "timestamp": EG.utc_now_iso(),
                    "connection_id": connection_id,
                    "source_ip": source_ip,
                    "hostname": hostname,
                    "port": port,
                    "protocol": EG.PROTOCOL_TCP,
                    "profile_id": decision.get("profile_id"),
                    "relay_id": relay_id,
                    "decision": EG.DECISION_DENY,
                    "reason": reason,
                    "outcome": outcome,
                    "policy_generation": decision.get("policy_generation"),
                },
                cfg=cfg,
            )
            return
        except OSError:
            EG.emit_conn_log(
                {
                    "timestamp": EG.utc_now_iso(),
                    "connection_id": connection_id,
                    "source_ip": source_ip,
                    "hostname": hostname,
                    "port": port,
                    "protocol": EG.PROTOCOL_TCP,
                    "profile_id": decision.get("profile_id"),
                    "relay_id": relay_id,
                    "decision": EG.DECISION_DENY,
                    "reason": EG.REASON_CONNECT_FAILURE,
                    "outcome": EG.AUDIT_CONNECT_FAILURE,
                    "policy_generation": decision.get("policy_generation"),
                },
                cfg=cfg,
            )
            return

        session = {
            "session_id": session_id,
            "connection_id": connection_id,
            "source_ip": source_ip,
            "hostname": hostname,
            "port": port,
            "protocol": EG.PROTOCOL_TCP,
            "method": None,
            "profile_id": decision.get("profile_id"),
            "relay_id": relay_id,
            "policy_generation": decision.get("policy_generation"),
        }
        state.register_session(session)
        EG.emit_conn_log(
            {
                "timestamp": EG.utc_now_iso(),
                "connection_id": connection_id,
                "session_id": session_id,
                "source_ip": source_ip,
                "hostname": hostname,
                "port": port,
                "protocol": EG.PROTOCOL_TCP,
                "profile_id": decision.get("profile_id"),
                "profile_name": decision.get("profile_name"),
                "relay_id": relay_id,
                "relay_name": decision.get("relay_name"),
                "decision": EG.DECISION_ALLOW,
                "reason": decision.get("reason"),
                "outcome": EG.AUDIT_CONNECTED,
                "policy_generation": decision.get("policy_generation"),
            },
            cfg=cfg,
        )
        try:
            outcome = RT.relay_bidirectional(
                request,
                upstream,
                cache=state.cache,
                session=session,
                cfg=cfg,
                update_generation=state.update_session_generation,
                revalidate_interval=RT.SESSION_REVALIDATE_INTERVAL,
                idle_timeout=RT.IDLE_TIMEOUT,
                authorize_fn=lambda: _session_still_authorized(state, session),
            )
            if outcome != EG.AUDIT_POLICY_REVOKED:
                EG.emit_conn_log(
                    {
                        "timestamp": EG.utc_now_iso(),
                        "connection_id": connection_id,
                        "session_id": session_id,
                        "source_ip": source_ip,
                        "hostname": hostname,
                        "port": port,
                        "protocol": EG.PROTOCOL_TCP,
                        "profile_id": decision.get("profile_id"),
                        "relay_id": relay_id,
                        "decision": EG.DECISION_ALLOW,
                        "reason": decision.get("reason"),
                        "outcome": outcome,
                        "policy_generation": session.get("policy_generation"),
                    },
                    cfg=cfg,
                )
        finally:
            state.unregister_session(session_id)
    finally:
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass
        try:
            request.close()
        except OSError:
            pass
        if source_acquired:
            state.release_source(source_ip)
        if acquired:
            state.release()


def ipaddress_compress(ip: str) -> str:
    import ipaddress

    try:
        return ipaddress.ip_address(ip).compressed
    except ValueError:
        return ip


def _session_still_authorized(state: TcpEgressState, session: dict) -> bool:
    plane, err, _cfg, _snap = state.cache.snapshot()
    if RP is None or plane is None or err is not None:
        return False
    decision = RP.authorize_fixed_tcp(
        plane,
        relay_id=session.get("relay_id") or "",
        source_ip=session["source_ip"],
    )
    if decision.get("decision") != RP.DECISION_ALLOW:
        return False
    gen = decision.get("policy_generation")
    if gen is not None:
        state.update_session_generation(session["session_id"], int(gen))
        session["policy_generation"] = int(gen)
    return True


def _desired_enabled_relays(plane) -> dict[str, tuple[str, int]]:
    desired = {}
    if plane is None or RP is None:
        return desired
    for rid, relay in RP.list_enabled_fixed_tcp(plane).items():
        try:
            addr = str(relay.get("listen_addr") or "0.0.0.0")
            port = int(relay.get("listen_port"))
        except (TypeError, ValueError):
            continue
        desired[str(rid)] = (addr, port)
    return desired


def sync_listeners(state: TcpEgressState) -> None:
    plane, _err, _cfg, _snap = state.cache.snapshot()
    desired = _desired_enabled_relays(plane)
    # Stop removed / re-bound relays.
    for rid, server in list(state._servers.items()):
        want = desired.get(rid)
        have = (server.server_address[0], int(server.server_address[1]))
        if want is None or want != have:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
            state._servers.pop(rid, None)
    # Start newly enabled relays.
    for rid, (addr, port) in desired.items():
        if rid in state._servers:
            continue
        try:
            server = RelayServer((addr, port), state, rid)
            thread = threading.Thread(
                target=server.serve_forever,
                name="drlink-tcp-egress-%s" % rid[:16],
                daemon=True,
            )
            thread.start()
            state._servers[rid] = server
        except OSError as exc:
            sys.stderr.write(
                "ERROR: failed to bind tcp relay %s on %s:%s: %s\n"
                % (rid, addr, port, exc)
            )


def _write_effective(state: TcpEgressState) -> None:
    run_dir = Path(ROOT + "/run/drlink/tcp-egress") if ROOT else Path("/run/drlink/tcp-egress")
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    listeners = []
    for rid, server in state._servers.items():
        listeners.append(
            {
                "relay_id": rid,
                "listen": "%s:%s" % (server.server_address[0], server.server_address[1]),
            }
        )
    snap = state.cache.engine.snapshot()
    doc = {
        "healthy": bool(snap and snap.healthy),
        "load_error": None if (snap and snap.healthy) else (state.cache.load_error or "unhealthy"),
        "policy_generation": int(snap.generation) if snap else None,
        "schema_version": int(snap.schema_version) if snap else None,
        "listeners": listeners,
        "active_sessions": len(state._sessions),
    }
    path = run_dir / "effective.json"
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def serve(config_path: Path) -> None:
    cache = RT.PolicyCache(config_path)
    state = TcpEgressState(cache)
    stop = threading.Event()

    def health_loop():
        while not stop.wait(1.0):
            try:
                cache.reload(force=False)
                sync_listeners(state)
                _write_effective(state)
            except Exception as exc:
                sys.stderr.write("tcp-egress sync error: %s\n" % exc)

    sync_listeners(state)
    _write_effective(state)
    thread = threading.Thread(target=health_loop, name="drlink-tcp-egress-sync", daemon=True)
    thread.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        state.shutting_down = True
        for server in list(state._servers.values()):
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(prog="drlink-tcp-egress")
    parser.add_argument(
        "--config",
        default="/etc/drlink/config.json",
        help="Path to /etc/drlink/config.json",
    )
    args = parser.parse_args(argv)
    config_path = Path(ROOT + args.config) if ROOT and args.config.startswith("/") else Path(args.config)
    if not config_path.is_file():
        raise SystemExit("ERROR: missing config %s" % config_path)
    serve(config_path)


if __name__ == "__main__":
    main()
