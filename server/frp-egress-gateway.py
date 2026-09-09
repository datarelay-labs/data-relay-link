#!/usr/bin/env python3
"""Data Relay Controlled Egress HTTP/HTTPS forward proxy gateway.

Agentless clients use HTTP_PROXY / HTTPS_PROXY. Policy is evaluated from
egress-control.json (separate from inbound Access Control). Default DENY,
fail-closed. Application TLS is never terminated.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

ROOT = os.environ.get("FRP_DEPLOY_TEST_ROOT", "")

MAX_REQUEST_LINE = 8192
MAX_HEADER_BYTES = 65536
MAX_HEADERS = 100
CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 120.0
CLIENT_HEADER_TIMEOUT = 30.0
DEFAULT_MAX_CONCURRENT = 256
RELAY_BUF = 65536


def _load_module(name: str, rel: str):
    import importlib.util

    here = Path(__file__).resolve()
    candidates = [
        here.parent.parent / "lib" / rel,
        Path("/usr/local/lib/frp-auto-deploy") / rel,
    ]
    if ROOT:
        candidates.insert(1, Path(ROOT) / "usr/local/lib/frp-auto-deploy" / rel)
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
    """Connect to an already-validated IP. Sets TLS SNI-friendly TCP only.

    hostname is unused for the TCP connect (rebinding-safe) but retained for
    callers that need to preserve Host semantics at the HTTP layer.
    """
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


class PolicyCache:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.lock = threading.RLock()
        self.mtime = None
        self.state = EG.empty_egress_state()
        self.path = None
        self.cfg = {}
        self.load_error = "not loaded"
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        with self.lock:
            try:
                self.cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
                self.path = EG.egress_control_path(self.cfg)
                mtime = self.path.stat().st_mtime if self.path.exists() else None
                if not force and mtime == self.mtime and self.load_error is None:
                    return
                if not self.path.exists():
                    self.mtime = mtime
                    self.load_error = "%s missing" % self.path.name
                    return
                self.state = EG.load_egress_state(path=self.path, cfg=self.cfg)
                self.mtime = mtime
                self.load_error = None
            except Exception as exc:
                self.load_error = str(exc)

    def snapshot(self):
        with self.lock:
            self.reload(force=False)
            return dict(self.state), self.load_error, dict(self.cfg)


class GatewayState:
    def __init__(
        self,
        cache: PolicyCache,
        *,
        resolve_fn: Callable[[str], list[str]] = default_resolve,
        connect_fn: Callable[..., socket.socket] = default_connect,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    ):
        self.cache = cache
        self.resolve_fn = resolve_fn
        self.connect_fn = connect_fn
        self.max_concurrent = max_concurrent
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._active = 0
        self._lock = threading.Lock()
        self.shutting_down = False

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


def _peer_ip(handler) -> str:
    try:
        addr = handler.client_address[0]
        return str(addr)
    except Exception:
        return ""


def _send_simple(handler, code: int, reason: str, body: bytes = b"") -> None:
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
        handler.request.sendall(header + body)
    except OSError:
        pass


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
    if b"\x00" in raw:
        raise EG.EgressError("NUL in request")
    head, rest = raw.split(b"\r\n\r\n", 1)
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EG.EgressError("non-ASCII request headers") from exc
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
        if not line or ":" not in line:
            raise EG.EgressError("malformed header")
        name, value = line.split(":", 1)
        if name.lower() != name.strip().lower() or any(ch.isspace() for ch in name):
            raise EG.EgressError("malformed header name")
        key = name.strip().lower()
        if key in headers:
            # Duplicate Host / conflicting representation — fail closed for security-sensitive headers.
            if key in ("host", "content-length", "transfer-encoding"):
                raise EG.EgressError("duplicate sensitive header: %s" % key)
        headers[key] = value.lstrip(" ")
    return method.upper(), target, version, headers, rest


def _absolute_uri_authority(target: str, headers: dict[str, str]) -> tuple[str, int, str]:
    """Return (hostname, port, path_query) for absolute-form HTTP proxy requests."""
    if not target.startswith("http://") and not target.startswith("https://"):
        raise EG.EgressError("proxy requests must use absolute-form URI")
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

    default_port = 443 if parts.scheme == "https" else 80
    uri_port = parts.port if parts.port is not None else default_port
    uri_host, _ = EG.canonicalize_hostname(parts.hostname, allow_wildcard=False)
    uri_port = EG.validate_port(uri_port)

    # Host header must agree with URI authority (hostname + effective port).
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


def _authorize_and_connect(
    gw: GatewayState,
    *,
    source_ip: str,
    hostname: str,
    port: int,
    method: str,
) -> tuple[Optional[socket.socket], dict]:
    state, load_error, cfg = gw.cache.snapshot()
    decision = EG.authorize_request(
        state,
        source_ip=source_ip,
        hostname=hostname,
        port=port,
        load_error=load_error,
    )
    decision["method"] = method
    decision["timestamp"] = EG.utc_now_iso()
    EG.emit_conn_log(decision, cfg=cfg)

    if decision.get("decision") != EG.DECISION_ALLOW:
        return None, decision

    # DNS once → validate ALL → connect exact IP (rebinding-safe).
    try:
        resolved = gw.resolve_fn(hostname)
        validated = EG.validate_resolved_addresses(resolved)
    except EG.EgressError as exc:
        decision = dict(decision)
        decision["decision"] = EG.DECISION_DENY
        msg = str(exc).lower()
        if "unsafe" in msg:
            decision["reason"] = EG.REASON_DNS_UNSAFE
        elif "dns" in msg or "resolution" in msg or "no addresses" in msg:
            decision["reason"] = EG.REASON_DNS_FAILURE
        else:
            decision["reason"] = EG.REASON_UNSAFE_DESTINATION
        decision["timestamp"] = EG.utc_now_iso()
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision
    except OSError:
        decision = dict(decision)
        decision["decision"] = EG.DECISION_DENY
        decision["reason"] = EG.REASON_DNS_FAILURE
        decision["timestamp"] = EG.utc_now_iso()
        EG.emit_conn_log(decision, cfg=cfg)
        return None, decision

    last_exc = None
    for ip in validated:
        try:
            sock = gw.connect_fn(ip, port, hostname, CONNECT_TIMEOUT)
            return sock, decision
        except OSError as exc:
            last_exc = exc
            continue
    decision = dict(decision)
    decision["decision"] = EG.DECISION_DENY
    decision["reason"] = EG.REASON_DNS_FAILURE if last_exc else EG.REASON_UNSAFE_DESTINATION
    decision["timestamp"] = EG.utc_now_iso()
    EG.emit_conn_log(decision, cfg=cfg)
    return None, decision


def _relay(client: socket.socket, upstream: socket.socket) -> None:
    client.setblocking(False)
    upstream.setblocking(False)
    sockets = [client, upstream]
    last_data = time.monotonic()
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 1.0)
            if errored:
                break
            if not readable:
                if time.monotonic() - last_data > IDLE_TIMEOUT:
                    break
                continue
            for sock in readable:
                other = upstream if sock is client else client
                try:
                    data = sock.recv(RELAY_BUF)
                except OSError:
                    return
                if not data:
                    # Half-close
                    try:
                        other.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    sockets = [s for s in sockets if s is not sock]
                    if not sockets or (client not in sockets and upstream not in sockets):
                        return
                    if len(sockets) == 1:
                        # Wait briefly for remaining direction then exit
                        continue
                    break
                last_data = time.monotonic()
                try:
                    other.sendall(data)
                except OSError:
                    return
    finally:
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass


def handle_client(gw: GatewayState, request: socket.socket, client_address) -> None:
    if not gw.try_acquire():
        try:
            _send_simple_sock(request, 503, "Service Unavailable", b"too many connections\n")
        finally:
            request.close()
        return
    gw.bump_active(1)
    try:
        source_ip = str(client_address[0])
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
                state, load_error, cfg = gw.cache.snapshot()
                EG.emit_conn_log(
                    {
                        "timestamp": EG.utc_now_iso(),
                        "source_ip": source_ip,
                        "hostname": target,
                        "port": None,
                        "method": "CONNECT",
                        "decision": EG.DECISION_DENY,
                        "reason": EG.REASON_MALFORMED_REQUEST,
                    },
                    cfg=cfg,
                )
                _send_simple_sock(request, 400, "Bad Request", b"bad connect\n")
                return
            upstream, decision = _authorize_and_connect(
                gw, source_ip=source_ip, hostname=host, port=port, method="CONNECT"
            )
            if upstream is None:
                code = 403 if decision.get("reason") != EG.REASON_DNS_FAILURE else 502
                _send_simple_sock(request, code, "Forbidden" if code == 403 else "Bad Gateway", b"denied\n")
                return
            try:
                request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except OSError:
                upstream.close()
                return
            _relay(request, upstream)
            return

        # HTTP forward proxy methods
        if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            _send_simple_sock(request, 405, "Method Not Allowed", b"method not allowed\n")
            return
        try:
            host, port, path = _absolute_uri_authority(target, headers)
        except EG.EgressError:
            state, load_error, cfg = gw.cache.snapshot()
            EG.emit_conn_log(
                {
                    "timestamp": EG.utc_now_iso(),
                    "source_ip": source_ip,
                    "hostname": target[:200],
                    "port": None,
                    "method": method,
                    "decision": EG.DECISION_DENY,
                    "reason": EG.REASON_MALFORMED_REQUEST,
                },
                cfg=cfg,
            )
            _send_simple_sock(request, 400, "Bad Request", b"bad request\n")
            return

        upstream, decision = _authorize_and_connect(
            gw, source_ip=source_ip, hostname=host, port=port, method=method
        )
        if upstream is None:
            code = 403 if decision.get("reason") != EG.REASON_DNS_FAILURE else 502
            _send_simple_sock(request, code, "Forbidden" if code == 403 else "Bad Gateway", b"denied\n")
            return

        # Rebuild request with origin-form target; strip hop-by-hop / proxy-auth.
        hop_by_hop = {
            "proxy-connection",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "proxy-authorization",
            "proxy-authenticate",
        }
        out_headers = []
        for key, value in headers.items():
            if key in hop_by_hop:
                continue
            # Preserve original header casing lightly via title — values already parsed.
            out_headers.append("%s: %s" % (key, value))
        if "host" not in headers:
            out_headers.append("Host: %s" % (host if port in (80, 443) else "%s:%d" % (host, port)))
        out_headers.append("Connection: close")
        req = "%s %s %s\r\n%s\r\n\r\n" % (method, path, version, "\r\n".join(out_headers))
        try:
            upstream.sendall(req.encode("ascii", errors="strict"))
            if body_prefix:
                upstream.sendall(body_prefix)
            # If Content-Length remains, read remaining body from client.
            cl = headers.get("content-length")
            if cl and method not in ("GET", "HEAD"):
                try:
                    total = int(cl)
                except ValueError:
                    upstream.close()
                    _send_simple_sock(request, 400, "Bad Request", b"bad content-length\n")
                    return
                already = len(body_prefix)
                remaining = total - already
                while remaining > 0:
                    chunk = request.recv(min(RELAY_BUF, remaining))
                    if not chunk:
                        break
                    upstream.sendall(chunk)
                    remaining -= len(chunk)
            _relay(request, upstream)
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
        gw.bump_active(-1)
        gw.release()
        try:
            request.close()
        except OSError:
            pass


def _send_simple_sock(sock: socket.socket, code: int, reason: str, body: bytes = b"") -> None:
    try:
        header = (
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n"
            % (code, reason, len(body))
        ).encode("ascii")
        sock.sendall(header + body)
    except OSError:
        pass


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, gw: GatewayState):
        self.gw = gw
        super().__init__(server_address, None)

    def finish_request(self, request, client_address):
        handle_client(self.gw, request, client_address)

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


def serve(
    config_path: Path,
    *,
    bind_host: Optional[str] = None,
    bind_port: Optional[int] = None,
    resolve_fn=default_resolve,
    connect_fn=default_connect,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
):
    cache = PolicyCache(config_path)
    # Prefer CLI/explicit bind; else config.
    host, port = EG.listen_bind(cache.cfg)
    if bind_host is not None:
        host = bind_host
    if bind_port is not None:
        port = bind_port
    gw = GatewayState(
        cache,
        resolve_fn=resolve_fn,
        connect_fn=connect_fn,
        max_concurrent=max_concurrent,
    )
    server = ThreadedTCPServer((host, port), gw)

    def health_thread():
        # Lightweight loopback health endpoint on same process via separate socket is avoided;
        # systemd uses process liveness. Optional /healthz via Unix is not required for v1.
        while not gw.shutting_down:
            cache.reload(force=False)
            time.sleep(2)

    threading.Thread(target=health_thread, name="egress-policy-reload", daemon=True).start()
    sys.stderr.write(
        "[frp-egress-gateway] listening on %s:%d policy=%s\n"
        % (host, port, cache.path)
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
        default="/etc/frp-auto-deploy/config.json",
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
