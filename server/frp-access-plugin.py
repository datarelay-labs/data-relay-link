#!/usr/bin/env python3
"""FRP NewUserConn HTTP plugin for Service Access Lists.

Listens on loopback only. frps POSTs NewUserConn events; this process
returns reject=true/false. ALLOWLIST failures fail closed. Connection
logging is best-effort and never changes the authorization decision.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Compatibility alias for tests / older call sites.
ThreadingHTTPServer = type(
    "ThreadingHTTPServer",
    (ThreadingMixIn, HTTPServer),
    {"daemon_threads": True},
)

ROOT = os.environ.get("FRP_DEPLOY_TEST_ROOT", "")


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


ACL = _load_module("frp_access_control", "frp_access_control.py")
try:
    _BOUNDED = _load_module("frp_bounded_server", "frp_bounded_server.py")
    _BOUNDED_LOAD_ERROR = None
except SystemExit as exc:
    _BOUNDED = None
    _BOUNDED_LOAD_ERROR = str(exc) or "ERROR: missing frp_bounded_server.py"


def _load_registry_validator():
    """Reuse allocator registry schema validation (no soft-empty)."""
    import importlib.util

    here = Path(__file__).resolve()
    candidates = [
        here.parent / "frp-port-allocator.py",
        Path("/usr/local/lib/drlink/frp-port-allocator.py"),
    ]
    if ROOT:
        candidates.insert(1, Path(ROOT) / "usr/local/lib/drlink/frp-port-allocator.py")
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location(
                "frp_port_allocator_validate", str(path)
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.require_registry_v2, mod.validate_registry_invariants
    raise SystemExit("ERROR: missing frp-port-allocator.py for registry validation")


_require_registry_v2, _validate_registry_invariants = _load_registry_validator()

ACCESS_MAX_CONCURRENT = int(os.environ.get("FRP_ACCESS_MAX_CONCURRENT", "32"))
_ACCESS_REQUEST_SLOTS = threading.BoundedSemaphore(ACCESS_MAX_CONCURRENT)


class PolicyCache:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.lock = threading.RLock()
        self.access_mtime = None
        self.registry_mtime = None
        self.access_state = ACL.empty_access_state()
        self.registry = {"schema_version": 2, "clients": {}}
        self.access_path = None
        self.registry_path = None
        self.cfg = {}
        self.load_error = None
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        with self.lock:
            try:
                self.cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
                self.access_path = ACL.access_control_path(self.cfg)
                self.registry_path = ACL.registry_path_from_cfg(self.cfg)
                access_m = self.access_path.stat().st_mtime if self.access_path.exists() else None
                reg_m = self.registry_path.stat().st_mtime if self.registry_path.exists() else None
                if (
                    not force
                    and access_m == self.access_mtime
                    and reg_m == self.registry_mtime
                    and self.load_error is None
                ):
                    return
                # Authoritative policy/registry must be present. Soft-empty would
                # PUBLIC-allow missing bindings; fail closed instead.
                missing = []
                if not self.access_path.exists():
                    missing.append("%s missing" % self.access_path.name)
                if not self.registry_path.exists():
                    missing.append("%s missing" % self.registry_path.name)
                if missing:
                    self.access_mtime = access_m
                    self.registry_mtime = reg_m
                    self.load_error = "; ".join(missing)
                    return
                self.access_state = ACL.load_access_state(path=self.access_path, cfg=self.cfg)
                raw_registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
                # Same canonical invariants as the allocator — never accept a
                # registry the control plane would reject.
                self.registry = _validate_registry_invariants(raw_registry, self.cfg)
                ACL.validate_access_state(self.access_state)
                self.access_mtime = access_m
                self.registry_mtime = reg_m
                self.load_error = None
            except Exception as exc:
                self.load_error = str(exc)

    def snapshot(self):
        with self.lock:
            self.reload(force=False)
            return (
                dict(self.access_state),
                dict(self.registry),
                self.load_error,
                self.cfg,
            )


def make_handler(cache: PolicyCache, plugin_path: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            # Keep journal noise low; authorization events go to access-conn.jsonl.
            sys.stderr.write("[drlink-access] %s - %s\n" % (self.address_string(), fmt % args))

        def _read_json(self):
            raw_len = self.headers.get("Content-Length") or "0"
            try:
                length = int(raw_len)
            except (TypeError, ValueError):
                return None
            if length < 0 or length > 1_048_576:
                return None
            try:
                raw = self.rfile.read(length) if length else b"{}"
            except Exception:
                return None
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None

        def _with_slot(self, fn):
            # Connection-level bounding is enforced by BoundedThreadingMixIn in
            # process_request (before the worker thread is created). Do not
            # acquire a second semaphore here — that would deadlock under load.
            return fn()

        def _send_json(self, code: int, payload: dict):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            def _handle():
                parsed = urlparse(self.path)
                if parsed.path in ("/healthz", "/health"):
                    access_state, registry, load_error, _cfg = cache.snapshot()
                    ok = load_error is None
                    self._send_json(
                        200 if ok else 503,
                        {
                            "ok": ok,
                            "error": load_error,
                            "lists": len(access_state.get("access_lists") or {}),
                            "clients": len((registry.get("clients") or {})),
                        },
                    )
                    return
                self._send_json(404, {"ok": False, "error": "not found"})

            self._with_slot(_handle)

        def do_POST(self):
            def _handle():
                parsed = urlparse(self.path)
                if parsed.path.rstrip("/") != plugin_path.rstrip("/"):
                    self._send_json(404, {"reject": True, "reject_reason": "not found"})
                    return
                query = parse_qs(parsed.query)
                op = (query.get("op") or [""])[0]
                req = self._read_json()
                if not isinstance(req, dict):
                    self._send_json(
                        200,
                        {"reject": True, "reject_reason": "malformed request", "unchange": True},
                    )
                    return
                op = op or str(req.get("op") or "")
                if op != "NewUserConn":
                    # Only NewUserConn is registered; ignore others safely.
                    self._send_json(200, {"reject": False, "unchange": True})
                    return
                content = req.get("content")
                if not isinstance(content, dict):
                    self._send_json(
                        200,
                        {"reject": True, "reject_reason": "malformed content", "unchange": True},
                    )
                    return

                access_state, registry, load_error, cfg = cache.snapshot()
                proxy_name = str(content.get("proxy_name") or "")
                remote_addr = str(content.get("remote_addr") or "")

                if load_error is not None:
                    # Fail closed when authoritative policy cannot be loaded.
                    event = {
                        "timestamp": ACL.utc_now_iso(),
                        "proxy_name": proxy_name,
                        "source_ip": remote_addr,
                        "access_mode": ACL.MODE_ALLOWLIST,
                        "decision": ACL.DECISION_DENY,
                        "reason": ACL.REASON_AUTHORIZATION_ERROR,
                    }
                    ACL.emit_conn_log(event, cfg=cfg)
                    self._send_json(
                        200,
                        {
                            "reject": True,
                            "reject_reason": "authorization unavailable",
                            "unchange": True,
                        },
                    )
                    return

                verdict = ACL.authorize(
                    access_state,
                    registry,
                    proxy_name=proxy_name,
                    source_ip=remote_addr,
                )
                # Logging must not affect allow/deny.
                ACL.emit_conn_log(verdict, cfg=cfg)
                if verdict.get("decision") == ACL.DECISION_ALLOW:
                    self._send_json(200, {"reject": False, "unchange": True})
                else:
                    reason = str(verdict.get("reason") or "denied")
                    self._send_json(
                        200,
                        {"reject": True, "reject_reason": reason, "unchange": True},
                    )

            self._with_slot(_handle)

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Data Relay Link Access Control Plugin (NewUserConn)")
    parser.add_argument(
        "--config",
        default="/etc/drlink/config.json",
        help="server config.json path",
    )
    parser.add_argument("--addr", default="", help="override listen addr host:port")
    parser.add_argument("--path", default="", help="override HTTP path")
    args = parser.parse_args()

    config_path = Path(args.config)
    if ROOT and not str(config_path).startswith(ROOT):
        if str(config_path).startswith("/"):
            config_path = Path(ROOT + str(config_path))
        else:
            config_path = Path(ROOT) / config_path

    cfg = {}
    if config_path.is_file():
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
    listen = args.addr or str(cfg.get("access_plugin_addr") or ACL.DEFAULT_PLUGIN_ADDR)
    plugin_path = args.path or str(cfg.get("access_plugin_path") or ACL.DEFAULT_PLUGIN_PATH)
    if ":" not in listen:
        raise SystemExit("ERROR: access plugin addr must be host:port")
    host, port_s = listen.rsplit(":", 1)
    if host not in ("127.0.0.1", "::1", "localhost"):
        # Product requirement: local-only listener.
        print("WARNING: forcing loopback bind; refusing non-local %s" % host, file=sys.stderr)
        host = "127.0.0.1"
    port = int(port_s)

    cache = PolicyCache(config_path)
    handler = make_handler(cache, plugin_path)
    if _BOUNDED is None:
        raise SystemExit(
            _BOUNDED_LOAD_ERROR or "ERROR: missing frp_bounded_server.py; refusing unbounded server"
        )

    def _reject(request, _client_address):
        try:
            body = b'{"reject":true,"reject_reason":"server busy","unchange":true}'
            response = (
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: close\r\n\r\n"
                % len(body)
                + body
            )
            request.sendall(response)
        except OSError:
            pass

    class AccessServer(_BOUNDED.BoundedThreadingMixIn, HTTPServer):
        max_concurrent = ACCESS_MAX_CONCURRENT
        request_timeout = 30.0
        daemon_threads = True
        reject_callback = staticmethod(_reject)

    server = AccessServer((host, port), handler)
    print("drlink-access listening on http://%s:%s%s" % (host, port, plugin_path), flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()