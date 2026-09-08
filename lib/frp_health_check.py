#!/usr/bin/env python3
"""Per-service FRP healthCheck thin wrapper (Target Health Check).

Persisted as optional service.health_check. When absent/disabled, omit from
client-state and do not emit healthCheck.* into frpc.toml.
"""
from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import Any, Optional

HEALTH_TYPES = frozenset({"tcp", "http"})
DEFAULT_TIMEOUT_SECONDS = 3
DEFAULT_INTERVAL_SECONDS = 10
DEFAULT_MAX_FAILED = 1
DEFAULT_HTTP_PATH = "/health"

STATUS_N_A = "N/A"
STATUS_HEALTHY = "HEALTHY"
STATUS_UNHEALTHY = "UNHEALTHY"
STATUS_UNKNOWN = "UNKNOWN"

CLIENT_ONLINE = "ONLINE"
CLIENT_OFFLINE = "OFFLINE"
CLIENT_UNKNOWN = "UNKNOWN"

TUNNEL_ONLINE = "ONLINE"
TUNNEL_OFFLINE = "OFFLINE"
TUNNEL_UNKNOWN = "UNKNOWN"


class HealthCheckError(Exception):
    """User-facing health-check validation error."""


def _positive_int(value: Any, field: str) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise HealthCheckError("invalid %s; must be a positive integer" % field) from exc
    if number < 1:
        raise HealthCheckError("invalid %s; must be a positive integer" % field)
    return number


def _normalize_path(value: Any) -> str:
    path = str(value or "").strip()
    if not path.startswith("/") or len(path) > 256:
        raise HealthCheckError("invalid health path; must start with /")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path):
        raise HealthCheckError("invalid health path; must start with /")
    if any(c in path for c in " \\;|&$`'\"<>"):
        raise HealthCheckError("invalid health path; must start with /")
    return path


def normalize_health_check(raw: Any, *, required: bool = False) -> Optional[dict]:
    """Return a normalized health_check dict, or None when disabled/absent."""
    if raw is None or raw is False:
        if required:
            raise HealthCheckError("health_check is required")
        return None
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in ("", "disabled", "none", "off"):
            if required:
                raise HealthCheckError("health_check is required")
            return None
        raise HealthCheckError("invalid health_check; expected an object")
    if not isinstance(raw, dict):
        raise HealthCheckError("invalid health_check; expected an object")
    if not raw:
        if required:
            raise HealthCheckError("health_check is required")
        return None

    type_raw = str(raw.get("type", "") or "").strip().lower()
    if type_raw in ("", "disabled", "none", "off"):
        if required:
            raise HealthCheckError("invalid health type; use tcp, http, or disabled")
        return None
    if type_raw not in HEALTH_TYPES:
        raise HealthCheckError("invalid health type; use tcp, http, or disabled")

    out = {
        "type": type_raw,
        "timeout_seconds": _positive_int(
            raw.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), "health-timeout"
        ),
        "interval_seconds": _positive_int(
            raw.get("interval_seconds", DEFAULT_INTERVAL_SECONDS), "health-interval"
        ),
        "max_failed": _positive_int(
            raw.get("max_failed", DEFAULT_MAX_FAILED), "health-max-failed"
        ),
    }
    if type_raw == "http":
        path = raw.get("path", DEFAULT_HTTP_PATH)
        out["path"] = _normalize_path(path if path not in (None, "") else DEFAULT_HTTP_PATH)
    return out


def default_health_check(health_type: str) -> dict:
    type_raw = str(health_type or "").strip().lower()
    if type_raw not in HEALTH_TYPES:
        raise HealthCheckError("invalid health type; use tcp, http, or disabled")
    out = {
        "type": type_raw,
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "interval_seconds": DEFAULT_INTERVAL_SECONDS,
        "max_failed": DEFAULT_MAX_FAILED,
    }
    if type_raw == "http":
        out["path"] = DEFAULT_HTTP_PATH
    return out


def copy_health_check(src: Any, dest: dict) -> None:
    """Copy normalized health_check from src onto dest when enabled.

    Raises HealthCheckError when present but invalid.
    """
    if not isinstance(src, dict):
        return
    if "health_check" not in src:
        return
    hc = normalize_health_check(src.get("health_check"))
    if hc is None:
        dest.pop("health_check", None)
        return
    dest["health_check"] = hc


def attach_health_check(item: dict, raw: Any) -> None:
    hc = normalize_health_check(raw)
    if hc is None:
        item.pop("health_check", None)
    else:
        item["health_check"] = hc


def health_check_toml_lines(hc: Any) -> list[str]:
    normalized = normalize_health_check(hc)
    if normalized is None:
        return []
    lines = [
        'healthCheck.type = "%s"' % normalized["type"],
        "healthCheck.timeoutSeconds = %d" % int(normalized["timeout_seconds"]),
        "healthCheck.maxFailed = %d" % int(normalized["max_failed"]),
        "healthCheck.intervalSeconds = %d" % int(normalized["interval_seconds"]),
    ]
    if normalized["type"] == "http":
        lines.append('healthCheck.path = "%s"' % normalized["path"])
    return lines


def format_health_config(hc: Any) -> str:
    normalized = normalize_health_check(hc)
    if normalized is None:
        return "disabled"
    parts = [
        normalized["type"],
        "timeout=%ds" % int(normalized["timeout_seconds"]),
        "interval=%ds" % int(normalized["interval_seconds"]),
        "max_failed=%d" % int(normalized["max_failed"]),
    ]
    if normalized["type"] == "http":
        parts.append("path=%s" % normalized["path"])
    return " ".join(parts)


def client_status_label(frpc_active: str) -> str:
    text = str(frpc_active or "").strip().lower()
    if text in ("active", "running"):
        return CLIENT_ONLINE
    if text in ("inactive", "failed", "dead", "stopped"):
        return CLIENT_OFFLINE
    return CLIENT_UNKNOWN


def tunnel_status_label(item: dict) -> str:
    enabled = item.get("enabled", True) is not False
    if not enabled:
        return TUNNEL_OFFLINE
    remote = item.get("remote_port")
    if remote in (None, ""):
        return TUNNEL_UNKNOWN
    try:
        int(remote)
    except (TypeError, ValueError):
        return TUNNEL_UNKNOWN
    return TUNNEL_ONLINE


def probe_target(local_ip: Any, local_port: Any, hc: Any) -> str:
    """One-shot local probe for status/show display only."""
    normalized = normalize_health_check(hc)
    if normalized is None:
        return STATUS_N_A
    host = str(local_ip or "").strip()
    try:
        port = int(local_port)
    except (TypeError, ValueError):
        return STATUS_UNKNOWN
    if not host or port < 1 or port > 65535:
        return STATUS_UNKNOWN
    timeout = float(normalized["timeout_seconds"])
    try:
        if normalized["type"] == "tcp":
            with socket.create_connection((host, port), timeout=timeout):
                return STATUS_HEALTHY
        path = normalized.get("path") or DEFAULT_HTTP_PATH
        url = "http://%s:%d%s" % (host, port, path)
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = int(getattr(resp, "status", 0) or resp.getcode())
            if 200 <= code < 300:
                return STATUS_HEALTHY
            return STATUS_UNHEALTHY
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
        return STATUS_UNHEALTHY
    except urllib.error.HTTPError as exc:
        if 200 <= int(exc.code) < 300:
            return STATUS_HEALTHY
        return STATUS_UNHEALTHY
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (socket.timeout, TimeoutError, ConnectionRefusedError, OSError)):
            return STATUS_UNHEALTHY
        return STATUS_UNKNOWN
    except Exception:
        return STATUS_UNKNOWN


def target_status_label(item: dict) -> str:
    return probe_target(item.get("local_ip"), item.get("local_port"), item.get("health_check"))


def apply_health_property(item: dict, prop: str, value: str) -> None:
    """Apply a set-service health-* property onto item."""
    prop = str(prop or "").strip().lower()
    value = str(value if value is not None else "")

    if prop == "health-type":
        type_raw = value.strip().lower()
        if type_raw == "disabled":
            item.pop("health_check", None)
            return
        if type_raw not in HEALTH_TYPES:
            raise HealthCheckError("invalid health type; use tcp, http, or disabled")
        existing = item.get("health_check")
        if not isinstance(existing, dict) or str(existing.get("type") or "") not in HEALTH_TYPES:
            item["health_check"] = default_health_check(type_raw)
            return
        updated = dict(existing)
        updated["type"] = type_raw
        if type_raw == "http":
            if not str(updated.get("path") or "").startswith("/"):
                updated["path"] = DEFAULT_HTTP_PATH
        else:
            updated.pop("path", None)
        item["health_check"] = normalize_health_check(updated, required=True)
        return

    current = normalize_health_check(item.get("health_check"))
    if current is None:
        raise HealthCheckError("enable health-type (tcp|http) before setting %s" % prop)

    if prop == "health-timeout":
        current["timeout_seconds"] = _positive_int(value, "health-timeout")
    elif prop == "health-interval":
        current["interval_seconds"] = _positive_int(value, "health-interval")
    elif prop == "health-max-failed":
        current["max_failed"] = _positive_int(value, "health-max-failed")
    elif prop == "health-path":
        if current.get("type") != "http":
            raise HealthCheckError("health-path is only valid when health-type is http")
        current["path"] = _normalize_path(value)
    else:
        raise HealthCheckError("unknown service property")
    item["health_check"] = normalize_health_check(current, required=True)


SERVICE_HEALTH_PROPS = (
    "health-type",
    "health-timeout",
    "health-interval",
    "health-max-failed",
    "health-path",
)
