#!/usr/bin/env python3
"""Authenticated Agent↔Server management sync for v2.4 Remote Services.

Server is authoritative for:
  - Network / Service Object catalog subset used by Agents
  - Endpoint allocation / reservation
  - Managed Host Remote Service inventory

Agent stores synchronized runtime/desired state locally and must not mint
authoritative online endpoint reservations when a live management path exists.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import quote, unquote, urlparse

from drlink_control_db import ControlPlaneError, utc_now_iso
import drlink_v24 as v24


class MgmtSyncError(ControlPlaneError):
    """Raised when the Agent↔Server management path fails."""


def resolve_mgmt_base_url(root: Optional[str] = None) -> Optional[str]:
    """Return the Agent→Server management base URL (no trailing slash), or None."""
    forced = str(os.environ.get("DRLINK_MGMT_URL") or "").strip()
    if forced:
        return forced.rstrip("/")
    base = Path(root) if root else Path("/")
    for rel in (
        "etc/frp/server-endpoint.json",
        "var/lib/drlink/server-endpoint.json",
        "etc/drlink/server-endpoint.json",
    ):
        path = base / rel
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for key in ("mgmt_url", "management_url", "allocator_url", "url"):
            url = str(data.get(key) or "").strip()
            if url:
                return _origin_from_url(url)
        host = str(data.get("host") or data.get("server_addr") or "").strip()
        port = data.get("port") or data.get("allocator_port") or data.get("mgmt_port")
        scheme = str(data.get("scheme") or "https").strip() or "https"
        if host and port:
            return "%s://%s:%s" % (scheme, host, int(port))
    state_path = base / "etc/frp/client-state.json"
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = None
        if isinstance(state, dict):
            for key in ("allocator_url", "allocator_public_url", "mgmt_url", "management_url"):
                url = str(state.get(key) or "").strip()
                if url:
                    return _origin_from_url(url)
    return None


def _origin_from_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url.rstrip("/")
    return "%s://%s" % (parsed.scheme, parsed.netloc)


def use_live_mgmt_path(root: Optional[str] = None) -> bool:
    """Whether Agent mutations should traverse the live Server management API.

    Unit/fault-injection may force local allocation with DRLINK_MGMT_MODE=local
    or DRLINK_SERVER_REACHABLE without a configured management URL.
    """
    mode = str(os.environ.get("DRLINK_MGMT_MODE") or "").strip().lower()
    if mode in ("local", "offline", "0", "no", "false"):
        return False
    if mode in ("live", "remote", "1", "yes", "true"):
        return resolve_mgmt_base_url(root) is not None
    if str(os.environ.get("DRLINK_SERVER_REACHABLE") or "").strip() != "":
        # Explicit reachability fault injection without a mgmt URL → local path.
        if resolve_mgmt_base_url(root) is None:
            return False
    return resolve_mgmt_base_url(root) is not None


def _mgmt_token() -> str:
    return str(os.environ.get("DRLINK_MGMT_TOKEN") or "").strip()


def _agent_identity(root: Optional[str] = None) -> dict:
    return v24.load_agent_identity(root)


def _request_json(
    method: str,
    url: str,
    body: Optional[dict] = None,
    *,
    root: Optional[str] = None,
    timeout: float = 8.0,
) -> dict:
    payload = b""
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    token = _mgmt_token()
    if token:
        headers["X-Drlink-Mgmt-Token"] = token
    identity = _agent_identity(root)
    machine_id = str(identity.get("machine_id") or "").strip()
    hostname = str(identity.get("hostname") or identity.get("label") or "").strip()
    if machine_id:
        headers["X-Drlink-Machine-Id"] = machine_id
    if hostname:
        headers["X-Drlink-Hostname"] = hostname
    if body is not None:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=payload if method != "GET" else None, headers=headers, method=method)
    # Lab / self-signed allocator TLS: allow override for disposable E2E.
    ctx = None
    if url.lower().startswith("https://") and str(os.environ.get("DRLINK_MGMT_INSECURE") or "").strip().lower() in (
        "1",
        "yes",
        "true",
    ):
        import ssl

        ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(exc)
        raise MgmtSyncError(
            "ERROR:\nServer management request failed (%s).\n\n%s\n\nNo changes were applied."
            % (exc.code, detail.strip() or exc.reason)
        ) from exc
    except Exception as exc:
        raise MgmtSyncError(
            "ERROR:\nDRLink Server management path is unreachable.\n\n%s\n\nNo changes were applied."
            % exc
        ) from exc
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (TypeError, json.JSONDecodeError) as exc:
        raise MgmtSyncError(
            "ERROR:\nServer management response was not valid JSON.\n\nNo changes were applied."
        ) from exc
    if not isinstance(data, dict):
        raise MgmtSyncError(
            "ERROR:\nServer management response was malformed.\n\nNo changes were applied."
        )
    if data.get("error"):
        raise MgmtSyncError(
            "ERROR:\n%s\n\nNo changes were applied." % data.get("error")
        )
    return data


def fetch_server_catalog(root: Optional[str] = None) -> dict:
    base = resolve_mgmt_base_url(root)
    if not base:
        raise MgmtSyncError(
            "ERROR:\nNo Server management URL is configured for catalog synchronization.\n\n"
            "No changes were applied."
        )
    return _request_json("GET", base + "/v1/catalog", root=root)


def upsert_remote_service_on_server(
    *,
    root: Optional[str] = None,
    name: str,
    destination: str,
    service: str,
    enabled: bool,
    pool_class: str,
    target_host: str,
    target_port: int,
    target_mode: str,
    preserve_endpoint_port: Optional[int] = None,
) -> dict:
    base = resolve_mgmt_base_url(root)
    if not base:
        raise MgmtSyncError(
            "ERROR:\nNo Server management URL is configured for Remote Service allocation.\n\n"
            "No changes were applied."
        )
    body = {
        "name": name,
        "destination": destination,
        "service": service,
        "enabled": bool(enabled),
        "pool_class": pool_class,
        "target_host": target_host,
        "target_port": int(target_port),
        "target_mode": target_mode,
    }
    if preserve_endpoint_port is not None:
        body["preserve_endpoint_port"] = int(preserve_endpoint_port)
    return _request_json("POST", base + "/v1/remote-services", body, root=root)


def delete_remote_service_on_server(*, root: Optional[str] = None, name: str) -> dict:
    base = resolve_mgmt_base_url(root)
    if not base:
        raise MgmtSyncError(
            "ERROR:\nNo Server management URL is configured for Remote Service delete.\n\n"
            "No changes were applied."
        )
    return _request_json("DELETE", base + "/v1/remote-services/" + quote(name, safe=""), root=root)


# ---------------------------------------------------------------------------
# Server-side handlers (ControlPlane authoritative)
# ---------------------------------------------------------------------------


def _authenticate_request(headers) -> tuple[str, str]:
    """Return (machine_id, hostname). Token auth or identity headers."""
    token = _mgmt_token()
    provided = str(headers.get("X-Drlink-Mgmt-Token") or "").strip()
    if token:
        if provided != token:
            raise MgmtSyncError("management authentication failed")
    elif not str(headers.get("X-Drlink-Machine-Id") or "").strip():
        # Allow unsigned lab calls only when token not required and machine id present
        # — fail closed if neither token nor machine id.
        raise MgmtSyncError("management authentication required")
    machine_id = str(headers.get("X-Drlink-Machine-Id") or "unknown").strip()
    hostname = str(headers.get("X-Drlink-Hostname") or machine_id).strip()
    return machine_id, hostname


def build_catalog_payload(plane) -> dict:
    network_objects = []
    for obj in plane.list_objects():
        if obj["type"] not in ("host", "network", "fqdn", "managed_endpoint"):
            continue
        values = plane._object_values(obj["id"])
        network_objects.append(
            {
                "name": obj["name"],
                "type": obj["type"],
                "values": values,
                "origin": obj.get("origin"),
                "generation": int(obj.get("row_version") or obj.get("generation") or 1),
                "id": obj["id"],
            }
        )
    service_objects = []
    for sobj in plane.conn.execute(
        "SELECT id, name, type, port, row_version FROM service_objects ORDER BY name"
    ):
        generation = 1
        try:
            generation = int(sobj["row_version"] or 1)
        except (KeyError, TypeError, ValueError):
            generation = 1
        service_objects.append(
            {
                "id": sobj["id"],
                "name": sobj["name"],
                "type": sobj["type"],
                "port": int(sobj["port"]),
                "generation": generation,
                "pool_class": "fixed-tcp" if sobj["type"] == "fixed-tcp" else "normal",
            }
        )
    managed_hosts = []
    for row in plane.conn.execute(
        "SELECT id, label, hostname, status, connected FROM clients ORDER BY COALESCE(label, hostname, id)"
    ):
        managed_hosts.append(
            {
                "id": row["id"],
                "name": row["label"] or row["hostname"] or row["id"],
                "hostname": row["hostname"],
                "status": row["status"],
                "connected": bool(row["connected"]),
            }
        )
    return {
        "networkObjects": network_objects,
        "serviceObjects": service_objects,
        "managedHosts": managed_hosts,
        "syncedAt": utc_now_iso(),
    }


def apply_catalog_to_agent(plane_db, catalog: dict) -> int:
    """Replace Agent local synchronized catalog from Server payload."""
    now = utc_now_iso()
    plane_db.conn.execute("DELETE FROM agent_object_catalog")
    count = 0
    for obj in catalog.get("networkObjects") or []:
        if not isinstance(obj, dict) or not obj.get("name"):
            continue
        payload = json.dumps(
            {
                "name": obj["name"],
                "type": obj.get("type"),
                "values": obj.get("values") or [],
                "origin": obj.get("origin"),
                "generation": obj.get("generation"),
                "id": obj.get("id"),
            },
            sort_keys=True,
        )
        plane_db.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("network-object", obj["name"], payload, now),
        )
        count += 1
    for sobj in catalog.get("serviceObjects") or []:
        if not isinstance(sobj, dict) or not sobj.get("name"):
            continue
        payload = json.dumps(
            {
                "name": sobj["name"],
                "type": sobj.get("type"),
                "port": sobj.get("port"),
                "generation": sobj.get("generation"),
                "id": sobj.get("id"),
                "pool_class": sobj.get("pool_class"),
            },
            sort_keys=True,
        )
        plane_db.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("service-object", sobj["name"], payload, now),
        )
        count += 1
    for host in catalog.get("managedHosts") or []:
        if not isinstance(host, dict) or not host.get("name"):
            continue
        payload = json.dumps(host, sort_keys=True)
        plane_db.conn.execute(
            "INSERT OR REPLACE INTO agent_object_catalog(kind, name, payload, synced_at) VALUES (?, ?, ?, ?)",
            ("managed-host", host["name"], payload, now),
        )
        count += 1
    plane_db.conn.commit()
    return count


def _ensure_managed_host(plane, machine_id: str, hostname: str) -> dict:
    client = None
    try:
        client = plane.get_client(machine_id)
    except Exception:
        client = None
    if client is None:
        try:
            client = plane.get_client(hostname)
        except Exception:
            client = None
    if client is not None:
        return client

    def ensure():
        now = utc_now_iso()
        plane.conn.execute(
            "INSERT OR IGNORE INTO clients(id, label, hostname, status, trust_status, connected, "
            "row_version, created_at, updated_at) VALUES (?, ?, ?, 'connected', 'trusted', 1, 1, ?, ?)",
            (machine_id, hostname, hostname, now, now),
        )
        # Also ensure managed Network Object representation if helpers exist
        return {"entity": {"type": "client", "id": machine_id, "name": hostname}, "operation": "ensure"}

    plane._mutate("ensure managed host %s" % hostname, "ensure managed host", ensure)
    return plane.get_client(machine_id) or plane.require_client(hostname)


def server_upsert_remote_service(plane, headers, body: dict) -> dict:
    machine_id, hostname = _authenticate_request(headers)
    name = str(body.get("name") or "").strip()
    destination = str(body.get("destination") or "").strip()
    service = str(body.get("service") or "").strip()
    enabled = bool(body.get("enabled", True))
    pool_class = str(body.get("pool_class") or "normal").strip().lower()
    target_host = str(body.get("target_host") or "127.0.0.1").strip()
    target_port = int(body.get("target_port") or 0)
    target_mode = str(body.get("target_mode") or "self").strip()
    preserve = body.get("preserve_endpoint_port")
    if not name or not destination or not service:
        raise MgmtSyncError("Remote Service name, destination, and service are required")
    if target_port < 1 or target_port > 65535:
        raise MgmtSyncError("Invalid target port")
    sobj = v24.get_service_object(plane, service)
    if not sobj:
        raise MgmtSyncError("Service Object '%s' does not exist on the Server" % service)
    if sobj["type"] == "udp":
        raise MgmtSyncError("Remote Service supports TCP and Fixed TCP only")
    expected_pool = "fixed-tcp" if sobj["type"] == "fixed-tcp" else "normal"
    if pool_class not in ("normal", "fixed-tcp"):
        pool_class = expected_pool
    if pool_class != expected_pool:
        raise MgmtSyncError("pool_class does not match Service Object type")

    client = _ensure_managed_host(plane, machine_id, hostname)

    existing = plane.conn.execute(
        "SELECT s.id, s.public_port, m.pool_class FROM published_services s "
        "LEFT JOIN remote_service_meta m ON m.service_id = s.id "
        "WHERE s.client_id = ? AND s.name = ? COLLATE NOCASE AND s.released = 0",
        (client["id"], name),
    ).fetchone()
    if existing and existing["pool_class"] and existing["pool_class"] != pool_class:
        raise MgmtSyncError(
            "The Service type cannot be changed between standard TCP and Fixed TCP "
            "for an existing Remote Service. Delete and recreate the Remote Service."
        )

    endpoint_port = None
    if preserve is not None:
        endpoint_port = int(preserve)
    elif existing and existing["public_port"]:
        endpoint_port = int(existing["public_port"])
    if endpoint_port is None and enabled:
        endpoint_port = v24.allocate_endpoint_port(plane, client["id"], name, pool_class)

    status = "DISABLED" if not enabled else "HEALTHY"
    reason = ""

    def write():
        nested_prev = getattr(plane, "_batch_mode", False)
        plane._batch_mode = True
        try:
            plane.set_published_service(
                client["id"],
                name,
                service_type="tcp",
                target_mode=target_mode,
                target_host=target_host,
                target_port=target_port,
                enabled=enabled,
                public_port=endpoint_port,
            )
            pub = plane.conn.execute(
                "SELECT id FROM published_services WHERE client_id = ? AND name = ?",
                (client["id"], name),
            ).fetchone()
            plane.conn.execute(
                "INSERT OR REPLACE INTO remote_service_meta"
                "(service_id, status, pool_class, service_object_id, destination_name, pending_allocation, delete_pending, reason) "
                "VALUES (?, ?, ?, ?, ?, 0, 0, ?)",
                (
                    pub["id"],
                    status,
                    pool_class,
                    sobj["id"],
                    destination,
                    reason,
                ),
            )
            return {"entity": {"type": "remote-service", "id": name, "name": name}, "operation": "set"}
        finally:
            plane._batch_mode = nested_prev

    plane._mutate("mgmt set remote-service %s" % name, "mgmt set remote service", write)
    endpoint_host = os.environ.get("DRLINK_HOST") or "drlink.local"
    return {
        "name": name,
        "destination": destination,
        "service": service,
        "enabled": enabled,
        "status": status,
        "endpoint_host": endpoint_host,
        "endpoint_port": endpoint_port,
        "pool_class": pool_class,
        "pending_allocation": 0 if endpoint_port is not None else 1,
        "reason": reason,
        "managed_host": hostname,
        "machine_id": machine_id,
        "generation": 1,
    }


def server_delete_remote_service(plane, headers, name: str) -> dict:
    machine_id, hostname = _authenticate_request(headers)
    client = _ensure_managed_host(plane, machine_id, hostname)
    pub = plane.conn.execute(
        "SELECT id, public_port FROM published_services WHERE client_id = ? AND name = ? COLLATE NOCASE AND released = 0",
        (client["id"], name),
    ).fetchone()
    if not pub:
        return {"status": "ABSENT", "name": name}

    def write():
        if pub["public_port"] is not None:
            plane.conn.execute(
                "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
                (pub["public_port"],),
            )
        plane.conn.execute("DELETE FROM remote_service_meta WHERE service_id = ?", (pub["id"],))
        plane.conn.execute(
            "UPDATE published_services SET released = 1, enabled = 0, updated_at = ? WHERE id = ?",
            (utc_now_iso(), pub["id"]),
        )
        return {"entity": {"type": "remote-service", "id": name, "name": name}, "operation": "unset"}

    plane._mutate("mgmt unset remote-service %s" % name, "mgmt unset remote service", write)
    return {"status": "DELETED", "name": name, "released_port": pub["public_port"]}


# ---------------------------------------------------------------------------
# Lightweight HTTP server (tests + optional standalone listener)
# ---------------------------------------------------------------------------


class _MgmtHandler(BaseHTTPRequestHandler):
    plane = None

    def log_message(self, fmt, *args):  # noqa: A003
        return

    def _send(self, code: int, payload: dict):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/v1/catalog":
                _authenticate_request(self.headers)
                self._send(200, build_catalog_payload(self.plane))
                return
            if path == "/healthz":
                self._send(200, {"status": "ok"})
                return
            self._send(404, {"error": "not found"})
        except MgmtSyncError as exc:
            self._send(403, {"error": str(exc).replace("ERROR:\n", "").split("\n\n")[0]})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8") or "{}")
            if path == "/v1/remote-services":
                result = server_upsert_remote_service(self.plane, self.headers, body)
                self._send(200, result)
                return
            self._send(404, {"error": "not found"})
        except MgmtSyncError as exc:
            msg = str(exc)
            if msg.startswith("ERROR:\n"):
                msg = msg[7:].split("\n\n")[0]
            self._send(400, {"error": msg})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_DELETE(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path.startswith("/v1/remote-services/"):
                name = path[len("/v1/remote-services/") :]
                result = server_delete_remote_service(self.plane, self.headers, unquote(name))
                self._send(200, result)
                return
            self._send(404, {"error": "not found"})
        except MgmtSyncError as exc:
            msg = str(exc)
            if msg.startswith("ERROR:\n"):
                msg = msg[7:].split("\n\n")[0]
            self._send(403, {"error": msg})
        except Exception as exc:
            self._send(500, {"error": str(exc)})


def start_mgmt_server(plane, host: str = "127.0.0.1", port: int = 0):
    """Start an in-process management HTTP server. Returns (server, base_url, thread)."""

    class Handler(_MgmtHandler):
        pass

    Handler.plane = plane
    server = socketserver.ThreadingTCPServer((host, port), Handler)
    server.daemon_threads = True
    bound_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://%s:%s" % (host, bound_port), thread


def stop_mgmt_server(server) -> None:
    try:
        server.shutdown()
    except Exception:
        pass
    try:
        server.server_close()
    except Exception:
        pass


def handle_allocator_http(plane, method: str, path: str, headers, body: bytes) -> Optional[tuple[int, dict]]:
    """Optional allocator integration hook.

    Returns (status, payload) when the path is a v2.4 management route, else None.
    """
    parsed = urlparse(path).path
    try:
        if method == "GET" and parsed == "/v1/catalog":
            _authenticate_request(headers)
            return 200, build_catalog_payload(plane)
        if method == "POST" and parsed == "/v1/remote-services":
            data = json.loads(body.decode("utf-8") or "{}") if body else {}
            return 200, server_upsert_remote_service(plane, headers, data)
        if method == "DELETE" and parsed.startswith("/v1/remote-services/"):
            name = unquote(parsed[len("/v1/remote-services/") :])
            return 200, server_delete_remote_service(plane, headers, name)
    except MgmtSyncError as exc:
        msg = str(exc)
        if msg.startswith("ERROR:\n"):
            msg = msg[7:].split("\n\n")[0]
        code = 403 if "auth" in msg.lower() else 400
        return code, {"error": msg}
    except Exception as exc:
        return 500, {"error": str(exc)}
    return None
