#!/usr/bin/env python3
"""FRP NewUserConn HTTP plugin for canonical Remote Access policy.

Listens on loopback only. frps POSTs NewUserConn events; this process
returns reject=true/false. SQLite control-plane policy is authoritative.
Connection logging is best-effort and never changes the authorization decision.
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


RP = _load_module("drlink_runtime_policy", "drlink_runtime_policy.py")
# Optional audit helper — logging must never affect allow/deny.
try:
    ACL = _load_module("frp_access_control", "frp_access_control.py")
except SystemExit:
    ACL = None
try:
    _BOUNDED = _load_module("frp_bounded_server", "frp_bounded_server.py")
    _BOUNDED_LOAD_ERROR = None
except SystemExit as exc:
    _BOUNDED = None
    _BOUNDED_LOAD_ERROR = str(exc) or "ERROR: missing frp_bounded_server.py"

ACCESS_MAX_CONCURRENT = int(os.environ.get("FRP_ACCESS_MAX_CONCURRENT", "32"))
_ACCESS_REQUEST_SLOTS = threading.BoundedSemaphore(ACCESS_MAX_CONCURRENT)


class PolicyCache:
    """SQLite-backed Remote Access policy cache (access-control.json is not authority)."""

    def __init__(self, config_path: Path):
        self._inner = RP.ControlPlaneCache(config_path)
        # Test-compat aliases (legacy fingerprint fields unused for authority).
        self.access_fp = None
        self.registry_fp = None
        self.access_mtime = None
        self.registry_mtime = None
        self.access_state = {}
        self.registry = {"schema_version": 2, "clients": {}}
        self.access_path = None
        self.registry_path = None
        self.cfg = {}
        self.load_error = None
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        self._inner.reload(force=force)
        self.cfg = dict(self._inner.cfg)
        self.load_error = self._inner.load_error
        self.fingerprint = self._inner.fingerprint

    def snapshot(self):
        plane, load_error, cfg = self._inner.snapshot()
        self.cfg = dict(cfg)
        self.load_error = load_error
        return plane, load_error, cfg

    def open_isolated(self):
        """Request-private control plane. Caller must close the plane."""
        plane, load_error, cfg = self._inner.open_isolated()
        self.cfg = dict(cfg)
        self.load_error = load_error
        return plane, load_error, cfg


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

        def _close_plane(self, plane):
            if plane is None:
                return
            try:
                plane.close()
            except Exception:
                pass

        def do_GET(self):
            def _handle():
                parsed = urlparse(self.path)
                if parsed.path in ("/healthz", "/health"):
                    plane, load_error, _cfg = cache.open_isolated()
                    try:
                        ok = load_error is None and plane is not None
                        clients = 0
                        services = 0
                        if plane is not None:
                            try:
                                st = plane.status()
                                clients = int(st.get("clients") or 0)
                                services = int(st.get("services") or 0)
                            except Exception:
                                ok = False
                                load_error = load_error or "control DB unhealthy"
                        self._send_json(
                            200 if ok else 503,
                            {
                                "ok": ok,
                                "error": load_error,
                                "clients": clients,
                                "published_services": services,
                                "authority": "sqlite",
                            },
                        )
                    finally:
                        self._close_plane(plane)
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

                plane = None
                proxy_name = str(content.get("proxy_name") or "")
                remote_addr = str(content.get("remote_addr") or "")
                try:
                    plane, load_error, cfg = cache.open_isolated()

                    if load_error is not None or plane is None:
                        # Fail closed when authoritative SQLite policy cannot be loaded.
                        event = {
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "proxy_name": proxy_name,
                            "source_ip": remote_addr,
                            "decision": RP.DECISION_DENY,
                            "reason": RP.REASON_DB_UNAVAILABLE,
                        }
                        if ACL is not None:
                            try:
                                ACL.emit_conn_log(event, cfg=cfg)
                            except Exception:
                                pass
                        self._send_json(
                            200,
                            {
                                "reject": True,
                                "reject_reason": "authorization unavailable",
                                "unchange": True,
                            },
                        )
                        return

                    try:
                        verdict = RP.authorize_remote(
                            plane,
                            proxy_name=proxy_name,
                            source_ip=remote_addr,
                        )
                    except Exception:
                        # A DB/API fault must reject this connection, not drop
                        # the plugin response or fail open.
                        self._send_json(
                            200,
                            {
                                "reject": True,
                                "reject_reason": "authorization unavailable",
                                "unchange": True,
                            },
                        )
                        return
                    # Logging must not affect allow/deny.
                    if ACL is not None:
                        try:
                            ACL.emit_conn_log(verdict, cfg=cfg)
                        except Exception:
                            pass
                    if verdict.get("decision") == RP.DECISION_ALLOW:
                        self._send_json(200, {"reject": False, "unchange": True})
                    else:
                        reason = str(verdict.get("reason") or "denied")
                        self._send_json(
                            200,
                            {"reject": True, "reject_reason": reason, "unchange": True},
                        )
                finally:
                    self._close_plane(plane)

            self._with_slot(_handle)

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Data Relay Link Remote Access Plugin (NewUserConn)")
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