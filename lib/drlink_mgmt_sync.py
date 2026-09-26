#!/usr/bin/env python3
"""Authenticated Agent↔Server management sync for v2.4 Remote Services.

Server is authoritative for:
  - Network / Service Object catalog subset used by Agents
  - Endpoint allocation / reservation
  - Managed Host Remote Service inventory

Agent stores synchronized runtime/desired state locally and must not mint
authoritative online endpoint reservations when a live management path exists.

Agent↔Server management operations are authenticated with the enrolled Agent
ECDSA P-256 management identity (timestamp, nonce, operation binding, replay
protection). TLS certificate verification is enabled by default.

DRLINK_MGMT_INSECURE is an explicit lab/test-only override. It is never applied
automatically when certificate validation fails.

DRLINK_MGMT_TOKEN is not a production Agent identity and is ignored by this
path.
"""
from __future__ import annotations

import hmac
import json
import os
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import quote, unquote, urlparse, urlunparse

from drlink_control_db import ControlPlaneError, utc_now_iso
import drlink_v24 as v24
import frp_mgmt_auth as MGMT


class MgmtSyncError(ControlPlaneError):
    """Raised when the Agent↔Server management path fails."""


class MgmtAuthError(MgmtSyncError):
    """Raised when management identity authentication fails."""


AUTH_REJECTED = (
    "ERROR:\nThe DRLink Server rejected the Agent management identity.\n\n"
    "The Agent may need to be re-enrolled.\n\nNo changes were applied."
)
AUTH_REVOKED = (
    "ERROR:\nThe Agent management identity has been revoked.\n\n"
    "Re-enroll this Agent before retrying.\n\nNo changes were applied."
)
AUTH_NONCE_BUSY = (
    "ERROR:\nThe DRLink Server management path is temporarily busy.\n\n"
    "Retry the operation. Do not re-enroll this Agent.\n\nNo changes were applied."
)
TLS_INSECURE_WARNING = (
    "WARNING: management TLS certificate verification is disabled.\n"
)
_INSECURE_FLAGS = ("1", "yes", "true")


class MgmtAuthContext:
    __slots__ = ("machine_id", "client", "nonce", "now", "allocator")

    def __init__(self, machine_id: str, client: dict, nonce: str, now: int, allocator=None):
        self.machine_id = machine_id
        self.client = client if isinstance(client, dict) else {}
        self.nonce = nonce
        self.now = int(now)
        self.allocator = allocator


def resolve_mgmt_base_url(root: Optional[str] = None) -> Optional[str]:
    """Return the Agent→Server management base URL (no trailing slash), or None."""
    forced = str(os.environ.get("DRLINK_MGMT_URL") or "").strip()
    if forced:
        return forced.rstrip("/")
    base = Path(root) if root else Path("/")
    search = [
        base / "etc/frp/server-endpoint.json",
        base / "var/lib/drlink/server-endpoint.json",
        base / "etc/drlink/server-endpoint.json",
    ]
    search.extend(v24._agent_state_file_candidates("etc/frp/server-endpoint.json", "server-endpoint.json", root))
    for path in search:
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
    for state_path in v24._agent_state_file_candidates(
        "etc/frp/client-state.json", "client-state.json", root
    ):
        if not state_path.is_file():
            continue
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


LEGACY_ALLOCATOR_BACKEND_PORT = 6099


def rewrite_legacy_backend_url(url: str, public_port: int) -> Optional[str]:
    """Return url with the private allocator port replaced by the public port.

    None means the URL is not a legacy backend origin and must be left alone.
    Port 443 is omitted so the result matches allocator_public_url.
    """
    text = str(url or "").strip()
    parsed = urlparse(text)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None
    try:
        current = parsed.port
    except ValueError:
        return None
    if current != LEGACY_ALLOCATOR_BACKEND_PORT:
        return None
    try:
        public = int(public_port)
    except (TypeError, ValueError):
        return None
    if public < 1 or public > 65535 or public == LEGACY_ALLOCATOR_BACKEND_PORT:
        return None
    host = parsed.hostname
    if ":" in host:
        host = "[%s]" % host
    netloc = host if public == 443 else "%s:%s" % (host, public)
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def _public_port_for_wss_state(state: dict) -> Optional[int]:
    """Public single-443 port, or None for Direct mode and unlabeled state.

    WSS uses whatever public port is stored. Older single-443 Agents kept the
    default tcp label while frp_server_port was already 443. Missing transport
    and any other tcp control port stay on the private allocator port.
    """
    transport = str(state.get("frp_transport") or "").strip().lower()
    try:
        port = int(state.get("frp_server_port"))
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535 or port == LEGACY_ALLOCATOR_BACKEND_PORT:
        return None
    if transport == "wss":
        return port
    if transport == "tcp" and port == 443:
        return port
    return None


def _rewrite_url_fields(data: dict, public_port: int, keys: tuple[str, ...]) -> bool:
    changed = False
    for key in keys:
        current = data.get(key)
        if not isinstance(current, str) or not current.strip():
            continue
        updated = rewrite_legacy_backend_url(current, public_port)
        if updated and updated != current:
            data[key] = updated
            changed = True
    return changed


def _agent_root(root: Optional[str]) -> Path:
    return Path(root) if root else Path("/")


def _load_json_dict(path: Path) -> Optional[dict]:
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _unique_paths(paths: list[Path]) -> list[Path]:
    seen = set()
    unique = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _client_state_path(root: Optional[str]) -> Optional[Path]:
    base = _agent_root(root)
    for path in v24._agent_state_file_candidates(
        "etc/frp/client-state.json", "client-state.json", str(base) if root else None
    ):
        if _load_json_dict(path) is not None:
            return path
    return None


def _server_endpoint_paths(root: Optional[str]) -> list[Path]:
    base = _agent_root(root)
    paths = [
        base / "etc/frp/server-endpoint.json",
        base / "var/lib/drlink/server-endpoint.json",
        base / "etc/drlink/server-endpoint.json",
    ]
    paths.extend(
        v24._agent_state_file_candidates(
            "etc/frp/server-endpoint.json", "server-endpoint.json", str(base) if root else None
        )
    )
    return [path for path in _unique_paths(paths) if path.is_file()]


def mgmt_origin_state_files(root: Optional[str] = None) -> list[Path]:
    """Files the single-443 origin migration may rewrite."""
    files = []
    state_path = _client_state_path(root)
    if state_path is not None:
        files.append(state_path)
    files.extend(_server_endpoint_paths(root))
    return _unique_paths(files)


def plan_legacy_single443_mgmt_origin(root: Optional[str] = None) -> list[tuple[Path, dict]]:
    """Planned JSON rewrites. Empty for Direct mode and already-public origins."""
    state_path = _client_state_path(root)
    if state_path is None:
        return []
    state = _load_json_dict(state_path)
    if state is None:
        return []
    public_port = _public_port_for_wss_state(state)
    if public_port is None:
        return []
    writes: list[tuple[Path, dict]] = []
    if _rewrite_url_fields(
        state,
        public_port,
        ("allocator_url", "allocator_public_url", "mgmt_url", "management_url"),
    ):
        writes.append((state_path, state))
    for path in _server_endpoint_paths(root):
        loaded = _load_json_dict(path)
        if loaded is None:
            continue
        if _rewrite_url_fields(
            loaded,
            public_port,
            ("mgmt_url", "management_url", "allocator_url", "url"),
        ):
            writes.append((path, loaded))
    return writes


def legacy_single443_mgmt_origin_drift(root: Optional[str] = None) -> bool:
    return bool(plan_legacy_single443_mgmt_origin(root))


def _restore_bytes(path: Path, raw: Optional[bytes], mode: int) -> None:
    if raw is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".restore", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode & 0o777)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _commit_json_files(writes: list[tuple[Path, dict]]) -> None:
    """Replace every planned file, or restore the originals if any replace fails."""
    saved: list[tuple[Path, Optional[bytes], int]] = []
    temps: list[str] = []
    replaced: list[Path] = []
    try:
        for path, data in writes:
            raw = path.read_bytes() if path.is_file() else None
            mode = path.stat().st_mode if path.is_file() else 0o600
            saved.append((path, raw, mode))
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
            temps.append(tmp)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
        for index, (path, _data) in enumerate(writes):
            os.replace(temps[index], path)
            replaced.append(path)
            if (
                os.environ.get("DRLINK_MGMT_ORIGIN_MIGRATE_FAIL_AFTER") == "1"
                and index == 0
            ):
                raise OSError("injected management-origin migration failure")
    except Exception:
        for path, raw, mode in saved:
            if path in replaced or path.is_file():
                _restore_bytes(path, raw, mode)
        raise
    finally:
        for tmp in temps:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def migrate_legacy_single443_agent_origin(root: Optional[str] = None) -> bool:
    """Point an existing single-443 Agent at the public management origin.

    Direct-mode state and unlabeled state are not rewritten. Management
    identity, services, transport, and enrollment fields other than the
    legacy :6099 URL are preserved. All rewritten files commit together.
    A second call is a no-op.
    """
    writes = plan_legacy_single443_mgmt_origin(root)
    if not writes:
        return False
    _commit_json_files(writes)
    return True


def snapshot_mgmt_origin_state(root: Optional[str], dest_dir: str) -> None:
    """Copy the exact bytes of every file the origin migration may rewrite."""
    base = _agent_root(root).resolve()
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    lines = []
    for path in mgmt_origin_state_files(root):
        rel = path.resolve().relative_to(base).as_posix()
        blob = dest / rel
        blob.parent.mkdir(parents=True, exist_ok=True)
        blob.write_bytes(path.read_bytes())
        lines.append("%o %s\n" % (path.stat().st_mode & 0o777, rel))
    (dest / "manifest").write_text("".join(lines), encoding="utf-8")


def mgmt_origin_state_matches(root: Optional[str], dest_dir: str) -> bool:
    dest = Path(dest_dir)
    manifest = dest / "manifest"
    if not manifest.is_file():
        return True
    base = _agent_root(root).resolve()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        _mode_text, rel = line.split(" ", 1)
        target = base / rel
        blob = dest / rel
        if not target.is_file() or not blob.is_file():
            return False
        if target.read_bytes() != blob.read_bytes():
            return False
    return True


def restore_mgmt_origin_state(root: Optional[str], dest_dir: str) -> None:
    """Restore a management-origin snapshot. Missing snapshots are left alone."""
    dest = Path(dest_dir)
    manifest = dest / "manifest"
    if not manifest.is_file():
        return
    base = _agent_root(root).resolve()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        mode_text, rel = line.split(" ", 1)
        target = base / rel
        blob = dest / rel
        if not blob.is_file():
            raise OSError("management-origin snapshot is missing %s" % rel)
        _restore_bytes(target, blob.read_bytes(), int(mode_text, 8))


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


def mgmt_insecure_tls_enabled() -> bool:
    """True only when the explicit lab/test TLS override is set."""
    return str(os.environ.get("DRLINK_MGMT_INSECURE") or "").strip().lower() in _INSECURE_FLAGS


def allocator_ca_path(root: Optional[str] = None) -> Optional[Path]:
    base = Path(root) if root else Path("/")
    for rel in (
        "etc/drlink/allocator-ca.crt",
        "etc/frp/allocator-ca.crt",
        "var/lib/drlink/allocator-ca.crt",
    ):
        path = base / rel
        if path.is_file():
            return path
    for path in v24._agent_state_file_candidates(
        "etc/drlink/allocator-ca.crt", "allocator-ca.crt", root
    ):
        if path.is_file():
            return path
    return None


def _tls_context(url: str, root: Optional[str] = None):
    """Build a TLS context. Production default verifies certificates.

    There is no automatic insecure fallback if verification fails.
    """
    if not str(url).lower().startswith("https://"):
        return None
    if mgmt_insecure_tls_enabled():
        sys.stderr.write(TLS_INSECURE_WARNING)
        sys.stderr.flush()
        return ssl._create_unverified_context()
    ca = allocator_ca_path(root)
    try:
        if ca is not None:
            return ssl.create_default_context(cafile=str(ca))
        return ssl.create_default_context()
    except Exception as exc:
        raise MgmtSyncError(
            "ERROR:\nDRLink Server management TLS trust material is invalid.\n\n"
            "No changes were applied."
        ) from exc


def _agent_identity(root: Optional[str] = None) -> dict:
    return v24.load_agent_identity(root)


def _identity_key_path(root: Optional[str] = None) -> Path:
    path = v24.agent_identity_key_path(root)
    if path is None:
        base = Path(root) if root else Path("/")
        return base / "etc/frp/client-identity.key"
    return path


def _identity_mac_path(root: Optional[str] = None) -> Path:
    path = v24.agent_identity_mac_path(root)
    if path is None:
        base = Path(root) if root else Path("/")
        return base / "etc/frp/client-identity.mac"
    return path


def _canonical_operation(method: str, path: str) -> Optional[tuple[str, str]]:
    parsed = urlparse(path).path or path
    method_u = str(method or "").upper()
    if method_u == "GET" and parsed == "/v1/catalog":
        return MGMT.MGMT_OP_CATALOG_READ, parsed
    if method_u == "POST" and parsed == "/v1/remote-services":
        return MGMT.MGMT_OP_REMOTE_SERVICE_SET, parsed
    if method_u == "POST" and parsed == "/v1/remote-services-status":
        return MGMT.MGMT_OP_REMOTE_SERVICE_STATUS, parsed
    if method_u == "DELETE" and parsed.startswith("/v1/remote-services/"):
        name = parsed[len("/v1/remote-services/") :]
        if not name or "/" in name:
            return None
        return MGMT.MGMT_OP_REMOTE_SERVICE_DELETE, parsed
    if method_u == "POST" and parsed == "/v1/ai-jobs/claim":
        return MGMT.MGMT_OP_AI_JOB_CLAIM, parsed
    if method_u == "POST" and parsed == "/v1/ai-jobs/complete":
        return MGMT.MGMT_OP_AI_JOB_COMPLETE, parsed
    return None


def _sign_request_headers(method: str, url: str, body: bytes, root: Optional[str] = None) -> dict:
    identity = _agent_identity(root)
    machine_id = str(identity.get("machine_id") or "").strip()
    if not machine_id:
        raise MgmtSyncError(AUTH_REJECTED)
    key_path = _identity_key_path(root)
    try:
        MGMT.validate_private_key(key_path)
    except Exception:
        raise MgmtSyncError(AUTH_REJECTED) from None
    parsed = urlparse(url)
    path = parsed.path or "/"
    bound = _canonical_operation(method, path)
    if bound is None:
        raise MgmtSyncError(
            "ERROR:\nUnsupported management operation.\n\nNo changes were applied."
        )
    op, canonical_path = bound
    ts = int(time.time())
    nonce = MGMT.new_nonce()
    message = MGMT.signed_message(
        machine_id, body, ts, nonce, op=op, method=method, path=canonical_path
    )
    signature = MGMT.sign_message(key_path, message)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Machine-Id": machine_id,
        "X-Timestamp": str(ts),
        "X-Mgmt-Nonce": nonce,
        "X-Mgmt-Signature": signature,
        "X-Mgmt-Auth": "1",
    }
    return headers


def _load_response_mac(root: Optional[str] = None) -> str:
    path = _identity_mac_path(root)
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _verify_response_mac(data: dict, root: Optional[str] = None) -> dict:
    """Verify existing management response HMAC when the Agent has a MAC key."""
    mac = _load_response_mac(root)
    if not mac:
        # Test fixtures without enrollment MAC rely on TLS. Production enrolled
        # Agents always have client-identity.mac.
        data.pop("response_hmac", None)
        return data
    received = str(data.pop("response_hmac", "") or "").strip()
    if not received:
        raise MgmtSyncError(
            "ERROR:\nThe DRLink Server management response was not authenticated.\n\n"
            "No changes were applied."
        )
    expected = MGMT.hmac_hex(mac, MGMT.canonical_json(data))
    if not hmac.compare_digest(received, expected):
        raise MgmtSyncError(
            "ERROR:\nThe DRLink Server management response failed integrity verification.\n\n"
            "No changes were applied."
        )
    return data


def _raise_http_auth_error(code: int, detail: str) -> None:
    text = str(detail or "").lower()
    if code in (401, 403) and "revoked" in text:
        raise MgmtSyncError(AUTH_REVOKED)
    if code in (401, 403) and ("nonce store full" in text or "nonce_store_full" in text):
        raise MgmtSyncError(AUTH_NONCE_BUSY)
    if code in (401, 403):
        raise MgmtSyncError(AUTH_REJECTED)
    raise MgmtSyncError(
        "ERROR:\nServer management request failed (%s).\n\n%s\n\nNo changes were applied."
        % (code, (detail or "").strip() or "request rejected")
    )


def _request_json(
    method: str,
    url: str,
    body: Optional[dict] = None,
    *,
    root: Optional[str] = None,
    timeout: float = 8.0,
) -> dict:
    payload = b""
    if body is not None:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = _sign_request_headers(method, url, payload, root=root)
    req = urllib.request.Request(
        url,
        data=payload if method.upper() != "GET" else None,
        headers=headers,
        method=method,
    )
    ctx = _tls_context(url, root)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(exc)
        code = int(exc.code)
        parsed_error = ""
        try:
            payload = json.loads(detail)
            if isinstance(payload, dict):
                parsed_error = str(payload.get("error") or "")
        except Exception:
            parsed_error = ""
        if code in (401, 403):
            _raise_http_auth_error(code, parsed_error or detail)
        raise MgmtSyncError(
            "ERROR:\nServer management request failed (%s).\n\n%s\n\nNo changes were applied."
            % (code, (parsed_error or detail).strip() or exc.reason)
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
        # A 2xx body with an error field is operational, not auth-class.
        # Only HTTP 401/403 (handled above) map to auth/re-enroll guidance.
        raise MgmtSyncError(
            "ERROR:\nServer management request failed.\n\n%s\n\nNo changes were applied."
            % str(data.get("error")).strip()
        )
    return _verify_response_mac(data, root=root)


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
    runtime_verified: bool = False,
    destination_client_id: Optional[str] = None,
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
        "runtime_verified": bool(runtime_verified),
    }
    if destination_client_id:
        body["destination_client_id"] = str(destination_client_id)
    if preserve_endpoint_port is not None:
        body["preserve_endpoint_port"] = int(preserve_endpoint_port)
    return _request_json("POST", base + "/v1/remote-services", body, root=root)


def report_remote_service_status_on_server(
    *,
    root: Optional[str] = None,
    services: list,
) -> dict:
    base = resolve_mgmt_base_url(root)
    if not base:
        raise MgmtSyncError(
            "ERROR:\nNo Server management URL is configured for Remote Service status.\n\n"
            "No changes were applied."
        )
    body = {"services": list(services or [])}
    return _request_json("POST", base + "/v1/remote-services-status", body, root=root)


def delete_remote_service_on_server(*, root: Optional[str] = None, name: str) -> dict:
    base = resolve_mgmt_base_url(root)
    if not base:
        raise MgmtSyncError(
            "ERROR:\nNo Server management URL is configured for Remote Service delete.\n\n"
            "No changes were applied."
        )
    return _request_json(
        "DELETE",
        base + "/v1/remote-services/" + quote(name, safe=""),
        root=root,
    )


def claim_ai_jobs_on_server(*, root: Optional[str] = None, limit: int = 4) -> dict:
    """Claim queued AI jobs for this enrolled Managed Host via management auth."""
    base = resolve_mgmt_base_url(root)
    if not base:
        raise MgmtSyncError(
            "ERROR:\nNo Server management URL is configured for AI job claim.\n\n"
            "No changes were applied."
        )
    return _request_json(
        "POST",
        base + "/v1/ai-jobs/claim",
        {"limit": int(limit)},
        root=root,
    )


def complete_ai_job_on_server(
    *,
    root: Optional[str] = None,
    job_id: str,
    result: dict,
    claim_token: Optional[str] = None,
    attempt_id: Optional[str] = None,
) -> dict:
    """Complete an AI job for this enrolled Managed Host via management auth."""
    base = resolve_mgmt_base_url(root)
    if not base:
        raise MgmtSyncError(
            "ERROR:\nNo Server management URL is configured for AI job completion.\n\n"
            "No changes were applied."
        )
    body = {"id": str(job_id), "result": dict(result or {})}
    if claim_token is not None:
        body["claim_token"] = str(claim_token)
    if attempt_id is not None:
        body["attempt_id"] = str(attempt_id)
    return _request_json(
        "POST",
        base + "/v1/ai-jobs/complete",
        body,
        root=root,
    )


# ---------------------------------------------------------------------------
# Server-side identity verification
# ---------------------------------------------------------------------------


def _public_auth_error(internal: str) -> dict:
    text = str(internal or "").lower()
    if "revoked" in text:
        return {
            "error": "management identity revoked",
            "error_class": "REVOKED",
        }
    if "replay" in text:
        return {
            "error": "management request replayed",
            "error_class": "REPLAY_REJECTED",
        }
    if "nonce store full" in text:
        return {
            "error": "management nonce store full; retry later",
            "error_class": "NONCE_STORE_FULL",
        }
    if "unknown" in text or "not enrolled" in text or "does not have a management identity" in text:
        return {
            "error": "management identity not enrolled",
            "error_class": "AUTH_FAILED",
        }
    return {
        "error": "management authentication failed",
        "error_class": "AUTH_FAILED",
    }


def _status_of(client) -> str:
    if not isinstance(client, dict):
        return "unknown"
    status = client.get("mgmt_status")
    if status in ("enrolled", "revoked", "legacy"):
        return status
    if client.get("mgmt_pubkey"):
        return "enrolled"
    return "unknown"


class AllocatorMgmtVerifier:
    """Production verifier: enrolled ECDSA identity in the allocator registry."""

    def __init__(self, allocator):
        self.allocator = allocator

    def authenticate(self, headers, body, *, op, method, path) -> MgmtAuthContext:
        machine_id = MGMT.extract_machine_id(headers)
        if not machine_id:
            raise MgmtAuthError("missing machine id")
        with self.allocator.registry_lock():
            state = self.allocator.load_registry()
            client = (state.get("clients") or {}).get(machine_id)
            error, now, nonce = self.allocator.verify_mgmt_against_client(
                client, machine_id, headers, body, op=op, method=method, path=path
            )
            if error:
                raise MgmtAuthError(error)
            if not isinstance(client, dict):
                raise MgmtAuthError("unknown client identity")
        return MgmtAuthContext(machine_id, client, nonce, int(now or time.time()), allocator=self.allocator)

    def commit_nonce(self, machine_id, nonce, now):
        with self.allocator.registry_lock():
            return self.allocator.commit_nonce(machine_id, nonce, now)


class InMemoryMgmtVerifier:
    """Test-only enrolled-identity store. Not a production authentication shortcut."""

    def __init__(self, clock=None):
        self.clients = {}
        self.nonces = {}
        self.clock = clock or (lambda: int(time.time()))

    def enroll(self, machine_id: str, pub_pem: str, mac_key: str = "", hostname: str = ""):
        self.clients[str(machine_id)] = {
            "mgmt_pubkey": pub_pem,
            "mgmt_status": "enrolled",
            "mgmt_mac_key": mac_key,
            "hostname": hostname,
        }

    def revoke(self, machine_id: str):
        client = self.clients.get(str(machine_id))
        if client is None:
            return
        client["mgmt_status"] = "revoked"

    def authenticate(self, headers, body, *, op, method, path) -> MgmtAuthContext:
        machine_id = MGMT.extract_machine_id(headers)
        if not machine_id:
            raise MgmtAuthError("missing machine id")
        client = self.clients.get(machine_id)
        now = int(self.clock())
        status = _status_of(client)
        if client is None or status == "unknown":
            raise MgmtAuthError("unknown client identity")
        if status == "revoked":
            raise MgmtAuthError("management identity revoked")
        if status != "enrolled" or not client.get("mgmt_pubkey"):
            raise MgmtAuthError("this client does not have a management identity")
        error, _ts, nonce = MGMT.verify_signed_mgmt_request(
            client["mgmt_pubkey"],
            machine_id,
            headers,
            body,
            op=op,
            method=method,
            path=path,
            now=now,
        )
        if error:
            raise MgmtAuthError(error)
        key = "%s:%s" % (machine_id, nonce)
        if key in self.nonces:
            raise MgmtAuthError("replayed request")
        return MgmtAuthContext(machine_id, client, nonce, now)

    def commit_nonce(self, machine_id, nonce, now):
        key = "%s:%s" % (machine_id, nonce)
        if key in self.nonces:
            return "replayed request"
        self.nonces[key] = int(now) + 900
        return None


def _authenticate_mgmt_api(verifier, headers, body, *, op, method, path) -> MgmtAuthContext:
    if verifier is None:
        raise MgmtAuthError("management authentication required")
    return verifier.authenticate(headers, body, op=op, method=method, path=path)


def _commit_auth_nonce(verifier, auth: MgmtAuthContext) -> None:
    error = verifier.commit_nonce(auth.machine_id, auth.nonce, auth.now)
    if error:
        raise MgmtAuthError(error)


def _with_response_mac(payload: dict, auth: MgmtAuthContext) -> dict:
    mac = str(auth.client.get("mgmt_mac_key") or "").strip()
    if not mac:
        return payload
    out = dict(payload)
    out["response_hmac"] = MGMT.hmac_hex(mac, MGMT.canonical_json(out))
    return out


def _require_managed_host(plane, machine_id: str):
    """Exact enrolled Managed Host lookup. Never creates, never matches hostname."""
    row = plane.conn.execute(
        "SELECT * FROM clients WHERE id = ?", (machine_id,)
    ).fetchone()
    if row is None:
        raise MgmtAuthError("unknown Managed Host")
    trust = str(row["trust_status"] or "")
    if trust and trust != "trusted":
        raise MgmtAuthError("Managed Host is not trusted")
    status = str(row["status"] or "").lower()
    if status in ("retired", "removed", "deleted"):
        raise MgmtAuthError("Managed Host is retired")
    return row


def build_catalog_payload(plane) -> dict:
    network_objects = []
    for obj in plane.list_objects():
        if obj["type"] not in ("host", "network", "fqdn", "managed_endpoint"):
            continue
        values = plane._object_values(obj["id"])
        entry = {
            "name": obj["name"],
            "type": obj["type"],
            "values": values,
            "origin": obj.get("origin"),
            "generation": int(obj.get("row_version") or obj.get("generation") or 1),
            "id": obj["id"],
        }
        if obj["type"] == "managed_endpoint":
            cid = obj.get("client_id")
            if not cid:
                link = plane.conn.execute(
                    "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                    (obj["id"],),
                ).fetchone()
                cid = link["client_id"] if link else None
            if cid:
                entry["client_id"] = cid
            addrs = []
            try:
                addrs = [
                    str(a.get("address") or a)
                    for a in (plane.endpoint_addresses(obj["name"]) or [])
                    if (a.get("address") if isinstance(a, dict) else a)
                ]
            except Exception:
                addrs = []
            if addrs:
                entry["addresses"] = addrs
                if not entry["values"]:
                    entry["values"] = list(addrs)
        network_objects.append(entry)
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
        "SELECT id, label, hostname, status, connected, trust_status FROM clients "
        "ORDER BY COALESCE(label, hostname, id)"
    ):
        ep = plane.conn.execute(
            "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id "
            "WHERE e.client_id = ?",
            (row["id"],),
        ).fetchone()
        addresses = []
        if ep is not None:
            try:
                addresses = [
                    str(a.get("address") or a)
                    for a in (plane.endpoint_addresses(ep["name"]) or [])
                    if (a.get("address") if isinstance(a, dict) else a)
                ]
            except Exception:
                addresses = []
        managed_hosts.append(
            {
                "id": row["id"],
                "name": (ep["name"] if ep else None) or row["label"] or row["hostname"] or row["id"],
                "hostname": row["hostname"],
                "status": row["status"],
                "connected": bool(row["connected"]),
                "trust_status": row["trust_status"],
                "addresses": addresses,
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
        entry = {
            "name": obj["name"],
            "type": obj.get("type"),
            "values": obj.get("values") or [],
            "origin": obj.get("origin"),
            "generation": obj.get("generation"),
            "id": obj.get("id"),
        }
        if obj.get("client_id"):
            entry["client_id"] = obj.get("client_id")
        if obj.get("addresses"):
            entry["addresses"] = obj.get("addresses")
        payload = json.dumps(entry, sort_keys=True)
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
    commit = getattr(plane_db, "commit_if_autonomous", None)
    if callable(commit):
        commit()
    elif not getattr(plane_db, "_batch_mode", False):
        plane_db.conn.commit()
    return count


def server_upsert_remote_service(plane, auth: MgmtAuthContext, body: dict) -> dict:
    machine_id = auth.machine_id
    name = str(body.get("name") or "").strip()
    destination = str(body.get("destination") or "").strip()
    destination_client_id = str(body.get("destination_client_id") or "").strip() or None
    service = str(body.get("service") or "").strip()
    enabled = bool(body.get("enabled", True))
    pool_class = str(body.get("pool_class") or "normal").strip().lower()
    preserve = body.get("preserve_endpoint_port")
    runtime_verified = bool(body.get("runtime_verified", False))
    if not name or not destination or not service:
        raise MgmtSyncError("Remote Service name, destination, and service are required")

    client = _require_managed_host(plane, machine_id)
    host_label = client["label"] or client["hostname"] or machine_id

    existing = plane.conn.execute(
        "SELECT s.id, s.public_port, m.pool_class, m.status, m.destination_client_id FROM published_services s "
        "LEFT JOIN remote_service_meta m ON m.service_id = s.id "
        "WHERE s.client_id = ? AND s.name = ? COLLATE NOCASE AND s.released = 0",
        (client["id"], name),
    ).fetchone()
    agent_supplied_client_id = destination_client_id
    prior_client_id = None
    if existing is not None:
        prior = existing["destination_client_id"] if "destination_client_id" in existing.keys() else None
        if prior:
            prior_client_id = str(prior)

    from drlink_upgrade_reconcile import resolve_authoritative_remote_target

    try:
        # Rename continuity may use prior_client_id only: that value is
        # Server-owned evidence for an existing Remote Service. Agent-supplied
        # destination_client_id alone never establishes a new unresolved bind.
        authoritative = resolve_authoritative_remote_target(
            plane,
            destination=destination,
            owner_client_id=client["id"],
            service_name=service,
            destination_client_id=agent_supplied_client_id,
            server_bound_client_id=prior_client_id,
        )
    except ControlPlaneError as first_exc:
        raise MgmtSyncError(str(first_exc)) from first_exc

    sobj = authoritative["service_object"]
    target_host = str(authoritative["target_host"])
    target_port = int(authoritative["target_port"])
    target_mode = str(authoritative["target_mode"])
    destination_client_id = authoritative.get("destination_client_id")
    expected_pool = "fixed-tcp" if sobj["type"] == "fixed-tcp" else "normal"
    if pool_class not in ("normal", "fixed-tcp"):
        pool_class = expected_pool
    if pool_class != expected_pool:
        raise MgmtSyncError("pool_class does not match Service Object type")

    if existing and existing["pool_class"] and existing["pool_class"] != pool_class:
        raise MgmtSyncError(
            "The Service type cannot be changed between standard TCP and Fixed TCP "
            "for an existing Remote Service. Delete and recreate the Remote Service."
        )

    endpoint_port = None
    proxy_id = None
    if preserve is not None:
        endpoint_port = int(preserve)
    elif existing and existing["public_port"]:
        endpoint_port = int(existing["public_port"])

    allocator = getattr(auth, "allocator", None)
    if endpoint_port is None and not enabled:
        pass
    elif allocator is not None and enabled:
        # Authoritative FRP registry allocation (single allocator authority).
        extra_used = {
            r[0]
            for r in plane.conn.execute(
                "SELECT public_port FROM port_reservations WHERE released = 0 AND public_port IS NOT NULL"
            )
        }
        extra_used |= {
            r[0]
            for r in plane.conn.execute(
                "SELECT public_port FROM published_services WHERE public_port IS NOT NULL AND released = 0"
            )
        }
        try:
            reserved = allocator.reserve_remote_service_endpoint(
                machine_id,
                name,
                pool_class,
                local_ip=target_host,
                local_port=target_port,
                preserve_port=endpoint_port,
                extra_used=extra_used,
            )
        except Exception as exc:
            raise MgmtSyncError("Endpoint allocation failed: %s" % exc) from exc
        endpoint_port = int(reserved["remote_port"])
        proxy_id = reserved.get("proxy_id")
    elif endpoint_port is None and enabled:
        # Test/local path without a live Allocator instance.
        endpoint_port = v24.allocate_endpoint_port(plane, client["id"], name, pool_class)

    if enabled and runtime_verified and endpoint_port is not None:
        try:
            from drlink_upgrade_reconcile import server_destination_reason

            dest_reason = server_destination_reason(
                plane,
                destination,
                owner_client_id=client["id"],
                destination_client_id=destination_client_id,
            )
        except Exception:
            dest_reason = None
        if dest_reason:
            status = "DEGRADED"
            reason = dest_reason
        else:
            status = "HEALTHY"
            reason = ""
    elif not enabled:
        status = "DISABLED"
        reason = ""
    else:
        status = "DEGRADED"
        reason = "Runtime activation pending."

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
                "(service_id, status, pool_class, service_object_id, destination_name, "
                "destination_client_id, pending_allocation, delete_pending, reason) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)",
                (
                    pub["id"],
                    status,
                    pool_class,
                    sobj["id"],
                    destination,
                    destination_client_id,
                    reason,
                ),
            )
            if endpoint_port is not None:
                plane.conn.execute(
                    "INSERT OR REPLACE INTO port_reservations"
                    "(public_port, client_id, service_id, service_name, released, created_at) "
                    "VALUES (?, ?, ?, ?, 0, ?)",
                    (endpoint_port, client["id"], pub["id"], name, utc_now_iso()),
                )
            return {
                "entity": {"type": "remote-service", "id": name, "name": name},
                "operation": "set",
                "after": "agent %s remote-service %s" % (machine_id, name),
            }
        finally:
            plane._batch_mode = nested_prev

    plane._mutate(
        "mgmt set remote-service %s [agent %s]" % (name, machine_id),
        "mgmt set remote service",
        write,
    )
    endpoint_host = "127.0.0.1"
    try:
        import frp_server_config as scfg

        endpoint_host = (
            scfg.resolve_public_endpoint_host(root=getattr(plane, "root", None), fallback="")
            or endpoint_host
        )
    except Exception:
        endpoint_host = os.environ.get("DRLINK_HOST") or endpoint_host
    return {
        "name": name,
        "destination": destination,
        "destination_client_id": destination_client_id,
        "service": service,
        "enabled": enabled,
        "status": status,
        "endpoint_host": endpoint_host,
        "endpoint_port": endpoint_port,
        "pool_class": pool_class,
        "pending_allocation": 0 if endpoint_port is not None else 1,
        "reason": reason,
        "managed_host": host_label,
        "machine_id": machine_id,
        "proxy_id": proxy_id,
        "generation": 1,
        "runtime_verified": runtime_verified,
        "target_host": target_host,
        "target_port": target_port,
        "target_mode": target_mode,
    }


def server_delete_remote_service(plane, auth: MgmtAuthContext, name: str) -> dict:
    machine_id = auth.machine_id
    client = _require_managed_host(plane, machine_id)
    pub = plane.conn.execute(
        "SELECT id, public_port FROM published_services WHERE client_id = ? AND name = ? COLLATE NOCASE AND released = 0",
        (client["id"], name),
    ).fetchone()
    if not pub:
        return {"status": "ABSENT", "name": name}

    allocator = getattr(auth, "allocator", None)
    if allocator is not None:
        try:
            allocator.release_remote_service_endpoint(machine_id, name)
        except Exception:
            pass

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
        return {
            "entity": {"type": "remote-service", "id": name, "name": name},
            "operation": "unset",
            "after": "agent %s remote-service %s" % (machine_id, name),
        }

    plane._mutate(
        "mgmt unset remote-service %s [agent %s]" % (name, machine_id),
        "mgmt unset remote service",
        write,
    )
    return {"status": "DELETED", "name": name, "released_port": pub["public_port"]}


def server_claim_ai_jobs(plane, auth: MgmtAuthContext, body: dict) -> dict:
    """Claim queued AI jobs for the authenticated Managed Host identity only."""
    machine_id = auth.machine_id
    _require_managed_host(plane, machine_id)
    limit = int((body or {}).get("limit") or 4)
    jobs = plane.claim_ai_jobs(machine_id, limit)
    return {"jobs": jobs}


def server_complete_ai_job(plane, auth: MgmtAuthContext, body: dict) -> dict:
    """Complete an AI job belonging to the authenticated Managed Host."""
    machine_id = auth.machine_id
    _require_managed_host(plane, machine_id)
    job_id = str((body or {}).get("id") or "").strip()
    if not job_id:
        raise MgmtSyncError("AI job id is required")
    result = (body or {}).get("result") or {}
    if not isinstance(result, dict):
        raise MgmtSyncError("AI job result must be an object")
    claim_token = (body or {}).get("claim_token")
    attempt_id = (body or {}).get("attempt_id")
    plane.complete_ai_job(
        job_id,
        machine_id,
        result,
        claim_token=claim_token,
        attempt_id=attempt_id,
    )
    return {"ok": True}


def _allocator_registry_state(auth: MgmtAuthContext):
    allocator = getattr(auth, "allocator", None)
    if allocator is None:
        return None
    try:
        with allocator.registry_lock():
            state = allocator.load_registry()
        return state if isinstance(state, dict) else None
    except Exception:
        return None


def _status_registry_owners(plane, auth: MgmtAuthContext) -> tuple[dict, bool]:
    """Return (owners, registry_available).

    When the FRP registry cannot be loaded, ownership checks are skipped so
    a missing registry cannot mass-release valid endpoints.
    """
    from drlink_upgrade_reconcile import load_authoritative_registry, registry_endpoint_owners

    state = _allocator_registry_state(auth)
    if state is None:
        try:
            state, _path, _err = load_authoritative_registry(getattr(plane, "root", None))
        except Exception:
            state = None
    if not isinstance(state, dict):
        return {}, False
    try:
        return registry_endpoint_owners(state), True
    except Exception:
        return {}, False


def _canonical_status_projection(name: str, pub, meta, status: str, reason: str) -> dict:
    endpoint_port = None if pub is None or pub["public_port"] is None else int(pub["public_port"])
    if status == "DEGRADED" and endpoint_port is None:
        pending = 1
    else:
        pending = int((meta["pending_allocation"] if meta is not None else 0) or 0)
    return {
        "name": name,
        "status": status,
        "reason": reason or "",
        "endpoint_port": endpoint_port,
        "pending_allocation": pending,
    }


def server_report_remote_service_status(plane, auth: MgmtAuthContext, body: dict) -> dict:
    """Authenticated Agent runtime/dependency status. Does not allocate ports."""
    from drlink_upgrade_reconcile import (
        effective_remote_service_status,
        _release_stale_port,
    )

    machine_id = auth.machine_id
    client = _require_managed_host(plane, machine_id)
    items = body.get("services") if isinstance(body, dict) else None
    if not isinstance(items, list):
        raise MgmtSyncError("services list is required")
    owners, registry_available = _status_registry_owners(plane, auth)

    updated = []

    def write():
        nested_prev = getattr(plane, "_batch_mode", False)
        plane._batch_mode = True
        try:
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                reported = str(item.get("status") or "").strip().upper()
                if reported not in ("HEALTHY", "DEGRADED", "DISABLED"):
                    continue
                verified = bool(item.get("runtime_verified", False))
                reason = str(item.get("reason") or "").strip()
                generation = item.get("runtime_generation")
                try:
                    generation = int(generation) if generation is not None else None
                except (TypeError, ValueError):
                    generation = None
                pub = plane.conn.execute(
                    "SELECT * FROM published_services WHERE client_id = ? AND name = ? COLLATE NOCASE AND released = 0",
                    (client["id"], name),
                ).fetchone()
                if pub is None:
                    continue
                meta = plane.conn.execute(
                    "SELECT * FROM remote_service_meta WHERE service_id = ?",
                    (pub["id"],),
                ).fetchone()
                if meta is None:
                    plane.conn.execute(
                        "INSERT INTO remote_service_meta"
                        "(service_id, status, pool_class, destination_name, destination_client_id, "
                        "pending_allocation, delete_pending, reason) "
                        "VALUES (?, 'DEGRADED', 'normal', 'this-host', ?, ?, 0, ?)",
                        (
                            pub["id"],
                            pub["client_id"],
                            0 if pub["public_port"] is not None else 1,
                            "Runtime activation pending.",
                        ),
                    )
                    meta = plane.conn.execute(
                        "SELECT * FROM remote_service_meta WHERE service_id = ?",
                        (pub["id"],),
                    ).fetchone()
                status, computed_reason, stale = effective_remote_service_status(
                    plane,
                    pub,
                    meta,
                    owners,
                    agent_runtime={
                        "status": reported,
                        "runtime_verified": verified and reported == "HEALTHY",
                        "reason": reason,
                    },
                    registry_available=registry_available,
                    missing_registry_port_is_stale=False,
                )
                if stale and pub["public_port"] is not None:
                    _release_stale_port(
                        plane,
                        int(pub["public_port"]),
                        pub,
                        meta,
                        computed_reason,
                    )
                    pub = plane.conn.execute(
                        "SELECT * FROM published_services WHERE id = ?", (pub["id"],)
                    ).fetchone()
                    meta = plane.conn.execute(
                        "SELECT * FROM remote_service_meta WHERE service_id = ?",
                        (pub["id"],),
                    ).fetchone()
                    status, computed_reason, _stale = effective_remote_service_status(
                        plane,
                        pub,
                        meta,
                        owners,
                        agent_runtime={
                            "status": reported,
                            "runtime_verified": False,
                            "reason": reason,
                        },
                        registry_available=registry_available,
                        missing_registry_port_is_stale=False,
                    )
                if meta is None:
                    continue
                extra = computed_reason
                if generation is not None and extra:
                    extra = "%s (generation %s)" % (extra, generation)
                projection = _canonical_status_projection(name, pub, meta, status, extra or "")
                pending = int(projection["pending_allocation"])
                if (
                    str(meta["status"] or "") != status
                    or str(meta["reason"] or "") != (extra or "")
                    or int(meta["pending_allocation"] or 0) != pending
                ):
                    plane.conn.execute(
                        "UPDATE remote_service_meta SET status = ?, reason = ?, pending_allocation = ? WHERE service_id = ?",
                        (status, extra or "", pending, pub["id"]),
                    )
                updated.append(projection)
            return {
                "entity": {"type": "remote-service-status", "id": machine_id, "name": machine_id},
                "operation": "status",
                "after": "agent %s status %s" % (machine_id, len(updated)),
            }
        finally:
            plane._batch_mode = nested_prev

    plane._mutate(
        "mgmt remote-service status [agent %s]" % machine_id,
        "mgmt remote service status",
        write,
    )
    return {"updated": updated, "services": updated, "count": len(updated)}


# ---------------------------------------------------------------------------
# Lightweight HTTP server (tests + optional standalone listener)
# ---------------------------------------------------------------------------


class _MgmtHandler(BaseHTTPRequestHandler):
    plane = None
    verifier = None

    def log_message(self, fmt, *args):  # noqa: A003
        return

    def _send(self, code: int, payload: dict):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _dispatch(self, method: str, body: bytes):
        handled = handle_allocator_http(
            self.plane, method, self.path, self.headers, body, verifier=self.verifier
        )
        if handled is None:
            self._send(404, {"error": "not found"})
            return
        self._send(handled[0], handled[1])

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        try:
            self._dispatch("GET", b"")
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_POST(self):  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            self._dispatch("POST", raw)
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_DELETE(self):  # noqa: N802
        try:
            self._dispatch("DELETE", b"")
        except Exception as exc:
            self._send(500, {"error": str(exc)})


def start_mgmt_server(
    plane,
    host: str = "127.0.0.1",
    port: int = 0,
    verifier=None,
    ssl_context=None,
):
    """Start an in-process management HTTP server. Returns (server, base_url, thread)."""

    class Handler(_MgmtHandler):
        pass

    Handler.plane = plane
    Handler.verifier = verifier
    server = socketserver.ThreadingTCPServer((host, port), Handler)
    server.daemon_threads = True
    if ssl_context is not None:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    bound_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    scheme = "https" if ssl_context is not None else "http"
    return server, "%s://%s:%s" % (scheme, host, bound_port), thread


def stop_mgmt_server(server) -> None:
    try:
        server.shutdown()
    except Exception:
        pass
    try:
        server.server_close()
    except Exception:
        pass


def handle_allocator_http(
    plane,
    method: str,
    path: str,
    headers,
    body: bytes,
    verifier=None,
) -> Optional[tuple[int, dict]]:
    """Allocator integration hook.

    Returns (status, payload) when the path is a v2.4 management route, else None.
    Authentication is mandatory. There is no machine-id-only or shared-token path.
    """
    parsed = urlparse(path).path
    bound = _canonical_operation(method, parsed)
    if bound is None:
        return None
    op, canonical_path = bound
    raw = body if body is not None else b""
    try:
        auth = _authenticate_mgmt_api(
            verifier, headers, raw, op=op, method=method.upper(), path=canonical_path
        )
        _require_managed_host(plane, auth.machine_id)
        _commit_auth_nonce(verifier, auth)
        # Claim and complete refresh once inside the control-plane methods.
        # Refreshing here as well doubled the row write on every poll.
        if op not in (MGMT.MGMT_OP_AI_JOB_CLAIM, MGMT.MGMT_OP_AI_JOB_COMPLETE):
            if hasattr(plane, "refresh_managed_host_liveness"):
                plane.refresh_managed_host_liveness(auth.machine_id)
        if method.upper() == "GET" and parsed == "/v1/catalog":
            return 200, _with_response_mac(build_catalog_payload(plane), auth)
        if method.upper() == "POST" and parsed == "/v1/remote-services":
            data = json.loads(raw.decode("utf-8") or "{}") if raw else {}
            if not isinstance(data, dict):
                return 400, {"error": "invalid JSON"}
            result = server_upsert_remote_service(plane, auth, data)
            return 200, _with_response_mac(result, auth)
        if method.upper() == "POST" and parsed == "/v1/remote-services-status":
            data = json.loads(raw.decode("utf-8") or "{}") if raw else {}
            if not isinstance(data, dict):
                return 400, {"error": "invalid JSON"}
            result = server_report_remote_service_status(plane, auth, data)
            return 200, _with_response_mac(result, auth)
        if method.upper() == "DELETE" and parsed.startswith("/v1/remote-services/"):
            name = unquote(parsed[len("/v1/remote-services/") :])
            result = server_delete_remote_service(plane, auth, name)
            return 200, _with_response_mac(result, auth)
        if method.upper() == "POST" and parsed == "/v1/ai-jobs/claim":
            data = json.loads(raw.decode("utf-8") or "{}") if raw else {}
            if not isinstance(data, dict):
                return 400, {"error": "invalid JSON"}
            result = server_claim_ai_jobs(plane, auth, data)
            return 200, _with_response_mac(result, auth)
        if method.upper() == "POST" and parsed == "/v1/ai-jobs/complete":
            data = json.loads(raw.decode("utf-8") or "{}") if raw else {}
            if not isinstance(data, dict):
                return 400, {"error": "invalid JSON"}
            result = server_complete_ai_job(plane, auth, data)
            return 200, _with_response_mac(result, auth)
    except MgmtAuthError as exc:
        return 403, _public_auth_error(str(exc))
    except MgmtSyncError as exc:
        # Must precede ControlPlaneError: MgmtSyncError subclasses it.
        msg = str(exc)
        if msg.startswith("ERROR:\n"):
            msg = msg[7:].split("\n\n")[0]
        return 400, {"error": msg}
    except ControlPlaneError as exc:
        # Operational ControlPlane failures are not auth/re-enroll.
        # Preserve full actionable text (multi-paragraph messages included).
        return 400, {"error": str(exc)}
    except json.JSONDecodeError:
        return 400, {"error": "invalid JSON"}
    except Exception as exc:
        return 500, {"error": str(exc)}
    return None
