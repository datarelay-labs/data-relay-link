#!/usr/bin/env python3
"""Canonical infrastructure / protected TCP port calculation.

Infrastructure ports must never be allocated as published client service ports.
Configured values are authoritative — do not hard-code exceptions for a single
historical default.

Default Controlled Egress listen is 6102 (outside the default published range
6000-6098). Access plugin defaults to 127.0.0.1:6101.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional, Set

# Outside default published service pool 6000-6098; adjacent to access plugin 6101.
DEFAULT_EGRESS_LISTEN_PORT = 6102
DEFAULT_ACCESS_PLUGIN_ADDR = "127.0.0.1:6101"
DEFAULT_PORT_START = 6000
DEFAULT_PORT_END = 6098
# Fixed TCP Egress relay listeners (dedicated pool; never published client ports).
DEFAULT_TCP_RELAY_PORT_START = 6200
DEFAULT_TCP_RELAY_PORT_END = 6299


def coerce_port(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    text = str(value).strip()
    if not text or not re.fullmatch(r"[0-9]+", text):
        return None
    port = int(text)
    if 1 <= port <= 65535:
        return port
    return None


def parse_host_port(addr: Any, default_port: Optional[int] = None) -> Optional[int]:
    """Extract TCP port from 'host:port' or bare port strings."""
    if addr is None:
        return default_port
    text = str(addr).strip()
    if not text:
        return default_port
    if re.fullmatch(r"[0-9]+", text):
        return coerce_port(text)
    if text.startswith("["):
        # [ipv6]:port
        if "]:" in text:
            return coerce_port(text.rsplit("]:", 1)[-1])
        return default_port
    if ":" in text:
        return coerce_port(text.rsplit(":", 1)[-1])
    return default_port


def cfg_frp_control_listen_port(cfg: Optional[dict]) -> Optional[int]:
    if not cfg:
        return None
    port = coerce_port(cfg.get("frp_control_listen_port"))
    if port is not None:
        return port
    return coerce_port(cfg.get("control_port"))


def cfg_allocator_listen_port(cfg: Optional[dict]) -> Optional[int]:
    if not cfg:
        return None
    port = coerce_port(cfg.get("allocator_listen_port"))
    if port is not None:
        return port
    return coerce_port(cfg.get("listen_port"))


def cfg_egress_listen_port(cfg: Optional[dict]) -> Optional[int]:
    if not cfg:
        return DEFAULT_EGRESS_LISTEN_PORT
    port = coerce_port(cfg.get("egress_listen_port"))
    if port is not None:
        return port
    return DEFAULT_EGRESS_LISTEN_PORT


def cfg_access_plugin_port(cfg: Optional[dict]) -> Optional[int]:
    if not cfg:
        return parse_host_port(DEFAULT_ACCESS_PLUGIN_ADDR)
    addr = cfg.get("access_plugin_addr")
    if addr is None or str(addr).strip() == "":
        return parse_host_port(DEFAULT_ACCESS_PLUGIN_ADDR)
    return parse_host_port(addr)


def cfg_frontend_listen_port(cfg: Optional[dict]) -> Optional[int]:
    """Public frontend listen (single443). Direct mode typically has none."""
    if not cfg:
        return None
    mode = str(cfg.get("deployment_mode") or "direct").strip().lower()
    compact = mode.replace("-", "").replace("_", "")
    if compact not in ("single443", "enterprise", "enterprisesingle443"):
        return None
    port = coerce_port(cfg.get("frontend_listen_port"))
    if port is not None:
        return port
    return coerce_port(cfg.get("frp_control_public_port")) or 443


def tcp_relay_port_range(
    cfg: Optional[dict] = None,
) -> tuple[int, int]:
    """Return inclusive Fixed TCP Egress auto-allocation range."""
    start = DEFAULT_TCP_RELAY_PORT_START
    end = DEFAULT_TCP_RELAY_PORT_END
    if isinstance(cfg, dict):
        raw_start = coerce_port(cfg.get("tcp_relay_port_start"))
        raw_end = coerce_port(cfg.get("tcp_relay_port_end"))
        if raw_start is not None:
            start = raw_start
        if raw_end is not None:
            end = raw_end
    if start > end:
        start, end = end, start
    return start, end


def is_tcp_relay_port(port: int, cfg: Optional[dict] = None) -> bool:
    start, end = tcp_relay_port_range(cfg)
    return start <= int(port) <= end


def infrastructure_ports(cfg: Optional[dict] = None) -> Set[int]:
    """Return the set of TCP ports reserved for Data Relay Link infrastructure."""
    protected: Set[int] = set()
    for port in (
        cfg_allocator_listen_port(cfg),
        cfg_frp_control_listen_port(cfg),
        coerce_port((cfg or {}).get("listen_port")) if cfg else None,
        cfg_egress_listen_port(cfg),
        cfg_access_plugin_port(cfg),
        cfg_frontend_listen_port(cfg),
    ):
        if port is not None:
            protected.add(port)
    return protected


def protected_listen_ports(
    cfg: Optional[dict] = None,
    *,
    extra: Optional[Iterable[int]] = None,
) -> Set[int]:
    """Infrastructure + optional extras that must not be used as TCP relay listeners."""
    protected = set(infrastructure_ports(cfg))
    if extra:
        for port in extra:
            coerced = coerce_port(port)
            if coerced is not None:
                protected.add(coerced)
    return protected


def service_port_range(cfg: Optional[dict] = None) -> tuple[int, int]:
    """Return inclusive published FRP service port range."""
    if not cfg:
        return DEFAULT_PORT_START, DEFAULT_PORT_END
    try:
        start = int(cfg.get("port_start", DEFAULT_PORT_START))
        end = int(cfg.get("port_end", DEFAULT_PORT_END))
    except (TypeError, ValueError):
        return DEFAULT_PORT_START, DEFAULT_PORT_END
    if start > end:
        start, end = end, start
    return start, end


def ranges_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Inclusive range overlap."""
    return int(a_start) <= int(b_end) and int(b_start) <= int(a_end)


def service_range_overlaps_tcp_relay_pool(cfg: Optional[dict] = None) -> bool:
    """True when published service ports collide with the Fixed TCP relay pool."""
    svc_start, svc_end = service_port_range(cfg)
    tcp_start, tcp_end = tcp_relay_port_range(cfg)
    return ranges_overlap(svc_start, svc_end, tcp_start, tcp_end)


def service_tcp_relay_overlap_message(cfg: Optional[dict] = None) -> str:
    svc_start, svc_end = service_port_range(cfg)
    tcp_start, tcp_end = tcp_relay_port_range(cfg)
    return (
        "FRP service port range %s-%s overlaps Fixed TCP Egress pool %s-%s. "
        "Choose a service range that does not intersect the TCP relay listen pool "
        "(default 6200-6299), or reconfigure tcp_relay_port_start/tcp_relay_port_end."
        % (svc_start, svc_end, tcp_start, tcp_end)
    )


def assert_service_range_not_overlapping_tcp_relay_pool(
    cfg: Optional[dict] = None,
) -> None:
    """Fail closed when published service ports collide with Fixed TCP pool."""
    if service_range_overlaps_tcp_relay_pool(cfg):
        raise RuntimeError(service_tcp_relay_overlap_message(cfg))


def port_in_service_range(port: int, cfg: Optional[dict] = None) -> bool:
    start, end = service_port_range(cfg)
    return start <= port <= end


def infrastructure_ports_in_service_range(cfg: Optional[dict] = None) -> Set[int]:
    """Infrastructure ports that currently collide with the published service pool."""
    colliding = set()
    for port in infrastructure_ports(cfg):
        if port_in_service_range(port, cfg):
            colliding.add(port)
    return colliding


def service_owns_port(registry: Optional[dict], port: int) -> Optional[tuple]:
    """Return (machine_id, service_id) if a published service owns *port*."""
    if not registry or not isinstance(registry, dict):
        return None
    target = coerce_port(port)
    if target is None:
        return None
    for mid, client in (registry.get("clients") or {}).items():
        if not isinstance(client, dict):
            continue
        services = client.get("services") or {}
        if not isinstance(services, dict):
            continue
        for sid, svc in services.items():
            if not isinstance(svc, dict):
                continue
            if coerce_port(svc.get("remote_port")) == target:
                return (str(mid), str(sid))
    return None


def egress_port_collision_message(port: int, owner: tuple) -> str:
    mid, sid = owner
    return (
        "Controlled Egress listen port %s is already owned by published service "
        "%s/%s. Refuse to bind or reassign. Migrate the service to another port "
        "or change egress_listen_port before upgrade."
        % (port, mid, sid)
    )


def assert_egress_not_owned_by_service(cfg: Optional[dict], registry: Optional[dict]) -> None:
    """Fail closed if the configured Egress listener is owned by a published service."""
    port = cfg_egress_listen_port(cfg)
    if port is None:
        return
    owner = service_owns_port(registry, port)
    if owner is not None:
        raise RuntimeError(egress_port_collision_message(port, owner))


def default_egress_outside_default_pool() -> bool:
    return not (DEFAULT_PORT_START <= DEFAULT_EGRESS_LISTEN_PORT <= DEFAULT_PORT_END)
