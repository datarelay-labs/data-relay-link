#!/usr/bin/env python3
"""Upgrade reconciliation: FRP registry → canonical SQLite control plane.

The authoritative FRP allocator registry owns enrolled clients and live
endpoint identity. Canonical SQLite is the control/policy projection.

This module backfills missing clients and Managed Host Network Objects,
preserves legacy enrollment services, reconciles v2.4 Remote Service
runtime projections without duplicating them, and repairs stale SQLite
reservations that disagree with registry ownership.

It is idempotent: a second run with equivalent state performs no duplicate
creates and does not reallocate healthy endpoints.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from drlink_control_db import ControlPlaneError, utc_now_iso
from drlink_control_plane import ControlPlane

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
THIS_HOST = {"this-host", "this_host", "self"}
V24_PREFIX = "rs-"


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    text = str(value or "").strip().lower()
    return text in ("1", "true", "yes", "y")


def remote_service_proxy_id(name: str) -> str:
    try:
        from drlink_v24_runtime import remote_service_proxy_id as _proxy_id

        return _proxy_id(name)
    except Exception:
        raw = str(name or "").strip().lower()
        return (V24_PREFIX + raw)[:32] if raw else V24_PREFIX + "svc"


def is_v24_runtime_projection(
    sid: str,
    rec: Optional[dict],
    *,
    plane: Optional[ControlPlane] = None,
    client_id: Optional[str] = None,
) -> bool:
    """True when a registry service is a v2.4 Remote Service runtime projection."""
    rec = rec if isinstance(rec, dict) else {}
    sid_s = str(sid or "").strip()
    if _truthy(rec.get("v24_remote_service")):
        return True
    canonical = str(rec.get("name") or "").strip()
    if canonical and remote_service_proxy_id(canonical) == sid_s:
        if plane is not None and client_id:
            row = plane.conn.execute(
                "SELECT s.id FROM published_services s "
                "JOIN remote_service_meta m ON m.service_id = s.id "
                "WHERE s.client_id = ? AND s.name = ? COLLATE NOCASE AND s.released = 0",
                (client_id, canonical),
            ).fetchone()
            if row is not None:
                return True
        # rs-<name> with an explicit canonical name is still a projection.
        if sid_s.startswith(V24_PREFIX):
            return True
    if sid_s.startswith(V24_PREFIX) and plane is not None and client_id:
        for row in plane.conn.execute(
            "SELECT s.name FROM published_services s "
            "JOIN remote_service_meta m ON m.service_id = s.id "
            "WHERE s.client_id = ? AND s.released = 0",
            (client_id,),
        ):
            if remote_service_proxy_id(row["name"]) == sid_s:
                return True
    return False


def load_authoritative_registry(
    root: Optional[str] = None,
    cfg: Optional[dict] = None,
) -> tuple[Optional[dict], Optional[Path], Optional[str]]:
    """Load registry JSON. Returns (state, path, error). Never mutates."""
    candidates: list[Path] = []
    if cfg and str(cfg.get("registry_file") or "").strip():
        raw = str(cfg.get("registry_file")).strip()
        path = Path(raw)
        if not path.is_absolute():
            base = Path(root) if root else Path("/")
            path = base / raw
        candidates.append(path)
    base = Path(root) if root else Path("/")
    candidates.extend(
        [
            base / "var/lib/drlink/runtime/client-inventory.json",
            base / "var/lib/drlink/registry.json",
        ]
    )
    seen: set[str] = set()
    last_error = None
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            last_error = "registry unreadable at %s: %s" % (path, exc)
            continue
        if not isinstance(data, dict):
            last_error = "registry is not an object at %s" % path
            continue
        if "clients" not in data or not isinstance(data.get("clients"), dict):
            last_error = "registry missing clients object at %s" % path
            continue
        return data, path, None
    if last_error:
        return None, None, last_error
    return None, None, "authoritative registry not found"


def registry_endpoint_owners(registry: dict) -> dict[int, dict]:
    """Map remote_port → {client_id, service_id, rec} for enabled registry services."""
    owners: dict[int, dict] = {}
    for cid, client in (registry.get("clients") or {}).items():
        if not isinstance(client, dict):
            continue
        services = client.get("services") if isinstance(client.get("services"), dict) else {}
        for sid, rec in services.items():
            if not isinstance(rec, dict):
                continue
            if rec.get("enabled") is False:
                continue
            try:
                port = int(rec.get("remote_port"))
            except (TypeError, ValueError):
                continue
            owners[port] = {
                "client_id": str(cid),
                "service_id": str(sid),
                "rec": rec,
                "canonical_name": str(rec.get("name") or sid),
            }
    return owners


def _client_public_name(rec: dict, client_id: str) -> str:
    label = str(rec.get("label") or "").strip()
    hostname = str(rec.get("hostname") or "").strip()
    return label or hostname or str(client_id)[:8]


def _managed_host_row(plane: ControlPlane, client_id: str):
    return plane.conn.execute(
        "SELECT o.id, o.name, o.type, o.origin FROM objects o "
        "JOIN managed_endpoints e ON e.object_id = o.id WHERE e.client_id = ?",
        (client_id,),
    ).fetchone()


def managed_host_policy_name(plane: ControlPlane, client_id: str) -> str:
    """Operator-facing policy identity for a Managed Host. Never loopback."""
    ep = _managed_host_row(plane, client_id)
    if ep and str(ep["name"] or "").strip():
        return str(ep["name"]).strip()
    client = plane.conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client is None:
        return ""
    for candidate in (client["label"], client["hostname"]):
        name = str(candidate or "").strip()
        if not name or name.lower() in LOOPBACK:
            continue
        obj = plane.get_object(name)
        if obj is not None:
            return obj["name"]
        return name
    return str(client["id"] or "")[:8]


def _published_for(plane: ControlPlane, client_id: str, name: str):
    return plane.conn.execute(
        "SELECT * FROM published_services WHERE client_id = ? AND name = ? COLLATE NOCASE AND released = 0",
        (client_id, name),
    ).fetchone()


def _remote_meta(plane: ControlPlane, service_row) -> Optional[Any]:
    if service_row is None:
        return None
    return plane.conn.execute(
        "SELECT * FROM remote_service_meta WHERE service_id = ?",
        (service_row["id"],),
    ).fetchone()


def _sqlite_claimants_for_port(plane: ControlPlane, port: int) -> list[dict]:
    rows = []
    for svc in plane.conn.execute(
        "SELECT * FROM published_services WHERE public_port = ? AND released = 0",
        (port,),
    ):
        meta = _remote_meta(plane, svc)
        rows.append(
            {
                "kind": "published",
                "client_id": svc["client_id"],
                "service_id": svc["id"],
                "service_name": svc["name"],
                "is_remote_service": meta is not None,
                "row": svc,
                "meta": meta,
            }
        )
    for res in plane.conn.execute(
        "SELECT * FROM port_reservations WHERE public_port = ? AND released = 0",
        (port,),
    ):
        rows.append(
            {
                "kind": "reservation",
                "client_id": res["client_id"],
                "service_id": res["service_id"],
                "service_name": res["service_name"],
                "is_remote_service": False,
                "row": res,
                "meta": None,
            }
        )
    return rows


def _semantic_owner_match(
    plane: ControlPlane,
    *,
    client_id: str,
    service_name: str,
    registry_owner: dict,
) -> bool:
    if str(registry_owner.get("client_id") or "") != str(client_id):
        return False
    sid = str(registry_owner.get("service_id") or "")
    canonical = str(registry_owner.get("canonical_name") or sid)
    rec = registry_owner.get("rec") if isinstance(registry_owner.get("rec"), dict) else {}
    if sid == str(service_name) or canonical.lower() == str(service_name).lower():
        return True
    if is_v24_runtime_projection(sid, rec, plane=plane, client_id=client_id):
        if remote_service_proxy_id(service_name) == sid:
            return True
        if canonical.lower() == str(service_name).lower():
            return True
    return False


def server_destination_reason(
    plane: ControlPlane,
    destination: str,
    *,
    owner_client_id: Optional[str] = None,
) -> Optional[str]:
    dest = str(destination or "").strip()
    if not dest:
        return "Remote Service destination is missing."
    if dest.lower() in THIS_HOST:
        return None
    if owner_client_id:
        client = plane.conn.execute(
            "SELECT label, hostname FROM clients WHERE id = ?", (owner_client_id,)
        ).fetchone()
        names = []
        if client:
            names.extend([client["label"], client["hostname"]])
        ep = _managed_host_row(plane, owner_client_id)
        if ep:
            names.append(ep["name"])
        if dest.lower() in {str(n or "").strip().lower() for n in names if str(n or "").strip()}:
            return None
    obj = plane.get_object(dest)
    if obj is not None:
        if obj["type"] == "network":
            return "Required destination '%s' is a CIDR Network Object and is not a valid single target." % dest
        return None
    client = None
    try:
        client = plane.get_client(dest)
    except ControlPlaneError:
        client = None
    if client is not None:
        return None
    return "Required Network Object / Managed Host destination '%s' is missing or invalid." % dest


def server_service_reason(plane: ControlPlane, meta_row) -> Optional[str]:
    if meta_row is None or not meta_row["service_object_id"]:
        return None
    sobj = plane.conn.execute(
        "SELECT * FROM service_objects WHERE id = ?", (meta_row["service_object_id"],)
    ).fetchone()
    if sobj is None:
        return "Required Service Object is missing or invalid."
    if str(sobj["type"] or "").lower() == "udp":
        return "Required Service Object '%s' uses UDP; Remote Service supports TCP and Fixed TCP only." % sobj["name"]
    return None


def effective_remote_service_status(
    plane: ControlPlane,
    pub,
    meta,
    registry_owners: dict[int, dict],
    *,
    agent_runtime: Optional[dict] = None,
) -> tuple[str, str, bool]:
    """Return (status, reason, stale_port).

    stale_port is True when SQLite still claims a port the registry does not
    attribute to this semantic service.
    """
    if pub is None:
        return "DEGRADED", "Published Service is missing.", False
    if not pub["enabled"]:
        return "DISABLED", "", False
    dest = str(meta["destination_name"] if meta else "") or ""
    dest_reason = server_destination_reason(
        plane, dest, owner_client_id=pub["client_id"] if pub else None
    )
    svc_reason = server_service_reason(plane, meta)
    stale_port = False
    ownership_reason = None
    port = pub["public_port"]
    if port is not None:
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = None
        if port_i is not None:
            owner = registry_owners.get(port_i)
            if owner is None:
                ownership_reason = "Authoritative registry does not own this endpoint."
                stale_port = True
            elif not _semantic_owner_match(
                plane,
                client_id=pub["client_id"],
                service_name=pub["name"],
                registry_owner=owner,
            ):
                ownership_reason = (
                    "Authoritative endpoint is owned by another service (%s/%s)."
                    % (owner.get("client_id", "")[:8], owner.get("service_id"))
                )
                stale_port = True
    agent_reason = None
    agent_status = None
    verified = False
    if isinstance(agent_runtime, dict):
        agent_status = str(agent_runtime.get("status") or "").upper()
        verified = bool(agent_runtime.get("runtime_verified"))
        if agent_status not in ("HEALTHY", "DEGRADED", "DISABLED"):
            agent_status = None
        if agent_status == "DEGRADED":
            agent_reason = str(agent_runtime.get("reason") or "Agent runtime activation failed.")
        elif agent_status == "HEALTHY" and not verified:
            agent_reason = "Runtime verification is missing."
            agent_status = "DEGRADED"

    if dest_reason:
        return "DEGRADED", dest_reason, stale_port
    if svc_reason:
        return "DEGRADED", svc_reason, stale_port
    if ownership_reason:
        return "DEGRADED", ownership_reason, stale_port
    if agent_status == "DISABLED":
        return "DISABLED", "", False
    if agent_status == "DEGRADED":
        return "DEGRADED", agent_reason or "Agent reported runtime failure.", False
    if agent_status == "HEALTHY" and verified and port is not None:
        return "HEALTHY", "", False
    stored = str(meta["status"] if meta else "") or ""
    if stored == "HEALTHY" and port is not None:
        return "HEALTHY", "", False
    if stored == "DISABLED":
        return "DISABLED", "", False
    reason = str(meta["reason"] if meta else "") or "Runtime activation pending."
    return "DEGRADED", reason, False


def preview_upgrade_reconciliation(plane: ControlPlane, registry: dict) -> dict:
    clients = registry.get("clients") if isinstance(registry.get("clients"), dict) else {}
    owners = registry_endpoint_owners(registry)
    missing_clients = []
    missing_hosts = []
    legacy_to_import = []
    v24_to_associate = []
    duplicate_projections = []
    stale_reservations = []
    health_repairs = []
    preserved_endpoints = []

    sqlite_ids = {r["id"] for r in plane.conn.execute("SELECT id FROM clients")}
    for cid, rec in clients.items():
        if not isinstance(rec, dict):
            continue
        cid_s = str(cid)
        if cid_s not in sqlite_ids:
            missing_clients.append(cid_s)
        if _managed_host_row(plane, cid_s) is None:
            missing_hosts.append(cid_s)
        services = rec.get("services") if isinstance(rec.get("services"), dict) else {}
        for sid, svc in services.items():
            if not isinstance(svc, dict):
                continue
            if is_v24_runtime_projection(sid, svc, plane=plane, client_id=cid_s):
                canonical = str(svc.get("name") or "").strip() or str(sid)
                if str(sid).startswith(V24_PREFIX):
                    dup = _published_for(plane, cid_s, str(sid))
                    canon = _published_for(plane, cid_s, canonical) if canonical != sid else None
                    if dup is not None and (canon is not None or canonical != sid):
                        if canon is None or dup["id"] != canon["id"]:
                            duplicate_projections.append(
                                {"client_id": cid_s, "name": str(sid), "canonical": canonical}
                            )
                v24_to_associate.append(
                    {
                        "client_id": cid_s,
                        "proxy_id": str(sid),
                        "canonical": canonical,
                        "remote_port": svc.get("remote_port"),
                    }
                )
            else:
                existing = _published_for(plane, cid_s, str(sid))
                if existing is None:
                    legacy_to_import.append(
                        {"client_id": cid_s, "name": str(sid), "rec": svc}
                    )
                else:
                    try:
                        want = int(svc.get("remote_port"))
                    except (TypeError, ValueError):
                        want = None
                    if want is not None:
                        preserved_endpoints.append(
                            {"client_id": cid_s, "name": str(sid), "port": want}
                        )

    for port, owner in owners.items():
        for claim in _sqlite_claimants_for_port(plane, port):
            if claim["kind"] == "reservation" and not claim.get("service_name") and not claim.get("client_id"):
                continue
            name = str(claim.get("service_name") or "")
            cid = str(claim.get("client_id") or "")
            if not cid:
                stale_reservations.append({"port": port, "claim": claim, "owner": owner})
                continue
            if not _semantic_owner_match(
                plane, client_id=cid, service_name=name, registry_owner=owner
            ):
                stale_reservations.append({"port": port, "claim": claim, "owner": owner})

    for pub in plane.conn.execute(
        "SELECT s.* FROM published_services s JOIN remote_service_meta m ON m.service_id = s.id "
        "WHERE s.released = 0"
    ):
        meta = _remote_meta(plane, pub)
        status, reason, stale = effective_remote_service_status(plane, pub, meta, owners)
        stored = str(meta["status"] if meta else "") or ""
        if status != stored or stale:
            health_repairs.append(
                {
                    "name": pub["name"],
                    "client_id": pub["client_id"],
                    "from": stored,
                    "to": status,
                    "reason": reason,
                    "stale_port": stale,
                    "port": pub["public_port"],
                }
            )

    has_work = bool(
        missing_clients
        or missing_hosts
        or legacy_to_import
        or duplicate_projections
        or stale_reservations
        or health_repairs
    )
    return {
        "registry_clients": len(clients),
        "sqlite_clients": len(sqlite_ids),
        "managed_hosts": plane.conn.execute(
            "SELECT COUNT(*) FROM objects WHERE type = 'managed_endpoint'"
        ).fetchone()[0],
        "missing_clients": missing_clients,
        "missing_hosts": missing_hosts,
        "legacy_to_import": legacy_to_import,
        "v24_to_associate": v24_to_associate,
        "duplicate_projections": duplicate_projections,
        "stale_reservations": stale_reservations,
        "health_repairs": health_repairs,
        "preserved_endpoints": preserved_endpoints,
        "has_work": has_work,
        "endpoint_owners": {str(k): v for k, v in owners.items()},
    }


def _observed_addresses(rec: dict) -> list[dict]:
    addresses = []
    observed = rec.get("observed") if isinstance(rec.get("observed"), dict) else {}
    for key in ("source_ip", "last_source_ip"):
        addr = str(observed.get(key) or rec.get(key) or "").strip()
        if addr and addr not in LOOPBACK:
            addresses.append({"address": addr, "active": True})
    return addresses


def _import_legacy_service(plane: ControlPlane, client_id: str, sid: str, rec: dict) -> None:
    enabled = bool(rec.get("enabled", True))
    local_ip = str(rec.get("local_ip") or "127.0.0.1")
    try:
        local_port = int(rec.get("local_port") or 0)
    except (TypeError, ValueError):
        local_port = 0
    remote_port = rec.get("remote_port")
    preset = str(rec.get("preset") or rec.get("service_type") or "tcp").lower()
    stype = preset if preset in ("ssh", "http", "https", "tcp") else "tcp"
    mode = "self"
    target_host = local_ip
    if str(rec.get("target_mode") or "").lower() == "routed":
        mode = "routed"
        target_host = str(rec.get("target_host") or local_ip)
    plane.set_published_service(
        client_id,
        str(sid).strip().lower(),
        service_type=stype,
        target_mode=mode,
        target_host=target_host,
        target_port=local_port or (22 if stype == "ssh" else 0) or None,
        enabled=enabled,
        public_port=int(remote_port) if remote_port is not None else None,
        from_preset=preset if preset in ("ssh", "http", "https", "tcp") else None,
    )
    if remote_port is not None:
        pub = _published_for(plane, client_id, str(sid).strip().lower())
        if pub is not None:
            plane.conn.execute(
                "INSERT OR REPLACE INTO port_reservations"
                "(public_port, client_id, service_id, service_name, released, created_at) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                (int(remote_port), client_id, pub["id"], pub["name"], utc_now_iso()),
            )


def _release_stale_port(plane: ControlPlane, port: int, pub=None, meta=None, reason: str = "") -> None:
    plane.conn.execute(
        "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
        (port,),
    )
    if pub is not None:
        plane.conn.execute(
            "UPDATE published_services SET public_port = NULL, updated_at = ? WHERE id = ?",
            (utc_now_iso(), pub["id"]),
        )
        if meta is not None:
            plane.conn.execute(
                "UPDATE remote_service_meta SET status = 'DEGRADED', pending_allocation = 1, reason = ? "
                "WHERE service_id = ?",
                (reason or "Stale endpoint reservation released.", pub["id"]),
            )


def _apply_health(plane: ControlPlane, pub, meta, status: str, reason: str) -> None:
    if meta is None:
        return
    current = str(meta["status"] or "")
    current_reason = str(meta["reason"] or "")
    pending = 1 if status == "DEGRADED" and pub["public_port"] is None else int(meta["pending_allocation"] or 0)
    if current == status and current_reason == (reason or "") and int(meta["pending_allocation"] or 0) == pending:
        return
    plane.conn.execute(
        "UPDATE remote_service_meta SET status = ?, reason = ?, pending_allocation = ? WHERE service_id = ?",
        (status, reason or "", pending, pub["id"]),
    )


def apply_upgrade_reconciliation(
    plane: ControlPlane,
    registry: dict,
    *,
    connected: bool = False,
) -> dict:
    """Apply a deterministic, transactional reconciliation.

    Raises ControlPlaneError without committing when invariants fail.
    """
    if not isinstance(registry, dict) or not isinstance(registry.get("clients"), dict):
        raise ControlPlaneError("upgrade reconcile: registry is missing a clients object")
    plan = preview_upgrade_reconciliation(plane, registry)
    if not plan["has_work"]:
        return {"ok": True, "applied": False, "skipped": True, "plan": plan}

    def write():
        nested = getattr(plane, "_batch_mode", False)
        plane._batch_mode = True
        try:
            clients = registry.get("clients") or {}
            sqlite_ids = {r["id"] for r in plane.conn.execute("SELECT id FROM clients")}
            for cid, rec in clients.items():
                if not isinstance(rec, dict):
                    continue
                cid_s = str(cid)
                host_missing = _managed_host_row(plane, cid_s) is None
                if cid_s in sqlite_ids and not host_missing:
                    continue
                label = _client_public_name(rec, cid_s)
                existing_row = plane.conn.execute(
                    "SELECT connected FROM clients WHERE id = ?", (cid_s,)
                ).fetchone()
                plane.upsert_client(
                    cid_s,
                    label=label or None,
                    description=str(rec.get("note") or rec.get("description") or "") or None,
                    hostname=None if existing_row else (str(rec.get("hostname") or "") or None),
                    connected=connected if existing_row is None else bool(existing_row["connected"]),
                    addresses=_observed_addresses(rec) or None,
                )

            owners = registry_endpoint_owners(registry)
            for cid, rec in clients.items():
                if not isinstance(rec, dict):
                    continue
                cid_s = str(cid)
                services = rec.get("services") if isinstance(rec.get("services"), dict) else {}
                for sid, svc in services.items():
                    if not isinstance(svc, dict):
                        continue
                    if is_v24_runtime_projection(sid, svc, plane=plane, client_id=cid_s):
                        canonical = str(svc.get("name") or "").strip()
                        if str(sid).startswith(V24_PREFIX) and canonical and canonical.lower() != str(sid).lower():
                            dup = _published_for(plane, cid_s, str(sid))
                            canon = _published_for(plane, cid_s, canonical)
                            if dup is not None and (canon is None or dup["id"] != canon["id"]):
                                plane.conn.execute(
                                    "DELETE FROM remote_service_meta WHERE service_id = ?",
                                    (dup["id"],),
                                )
                                plane.conn.execute(
                                    "DELETE FROM published_services WHERE id = ?",
                                    (dup["id"],),
                                )
                        if canonical:
                            canon = _published_for(plane, cid_s, canonical)
                            try:
                                want = int(svc.get("remote_port"))
                            except (TypeError, ValueError):
                                want = None
                            if canon is not None and want is not None:
                                owner = owners.get(want)
                                if owner and _semantic_owner_match(
                                    plane,
                                    client_id=cid_s,
                                    service_name=canon["name"],
                                    registry_owner=owner,
                                ):
                                    if canon["public_port"] != want:
                                        plane.conn.execute(
                                            "UPDATE published_services SET public_port = ?, updated_at = ? WHERE id = ?",
                                            (want, utc_now_iso(), canon["id"]),
                                        )
                                    plane.conn.execute(
                                        "INSERT OR REPLACE INTO port_reservations"
                                        "(public_port, client_id, service_id, service_name, released, created_at) "
                                        "VALUES (?, ?, ?, ?, 0, ?)",
                                        (want, cid_s, canon["id"], canon["name"], utc_now_iso()),
                                    )
                        continue
                    existing = _published_for(plane, cid_s, str(sid))
                    if existing is None:
                        _import_legacy_service(plane, cid_s, str(sid), svc)
                    else:
                        try:
                            want = int(svc.get("remote_port"))
                        except (TypeError, ValueError):
                            want = None
                        if want is not None and existing["public_port"] != want:
                            owner = owners.get(want)
                            if owner and _semantic_owner_match(
                                plane,
                                client_id=cid_s,
                                service_name=existing["name"],
                                registry_owner=owner,
                            ):
                                plane.conn.execute(
                                    "UPDATE published_services SET public_port = ?, updated_at = ? WHERE id = ?",
                                    (want, utc_now_iso(), existing["id"]),
                                )
                                plane.conn.execute(
                                    "INSERT OR REPLACE INTO port_reservations"
                                    "(public_port, client_id, service_id, service_name, released, created_at) "
                                    "VALUES (?, ?, ?, ?, 0, ?)",
                                    (want, cid_s, existing["id"], existing["name"], utc_now_iso()),
                                )

            # Repair stale SQLite claims against authoritative ownership.
            for port, owner in list(owners.items()):
                for claim in _sqlite_claimants_for_port(plane, port):
                    cid = str(claim.get("client_id") or "")
                    name = str(claim.get("service_name") or "")
                    if cid and _semantic_owner_match(
                        plane, client_id=cid, service_name=name, registry_owner=owner
                    ):
                        continue
                    if claim["kind"] == "reservation":
                        plane.conn.execute(
                            "UPDATE port_reservations SET released = 1 WHERE public_port = ? AND released = 0",
                            (port,),
                        )
                    if claim["kind"] == "published":
                        pub = claim["row"]
                        meta = claim["meta"]
                        reason = server_destination_reason(
                            plane,
                            str(meta["destination_name"] if meta else "") or "",
                            owner_client_id=str(pub["client_id"]),
                        ) or (
                            "Authoritative endpoint is owned by another service."
                        )
                        _release_stale_port(plane, port, pub, meta, reason)

            # Active SQLite reservations with no matching registry owner.
            for res in list(
                plane.conn.execute("SELECT * FROM port_reservations WHERE released = 0")
            ):
                try:
                    port = int(res["public_port"])
                except (TypeError, ValueError):
                    continue
                owner = owners.get(port)
                if owner is None:
                    plane.conn.execute(
                        "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
                        (port,),
                    )
                    continue
                name = str(res["service_name"] or "")
                cid = str(res["client_id"] or "")
                if not cid or not _semantic_owner_match(
                    plane, client_id=cid, service_name=name, registry_owner=owner
                ):
                    plane.conn.execute(
                        "UPDATE port_reservations SET released = 1 WHERE public_port = ?",
                        (port,),
                    )

            owners = registry_endpoint_owners(registry)
            for pub in list(
                plane.conn.execute(
                    "SELECT s.* FROM published_services s "
                    "JOIN remote_service_meta m ON m.service_id = s.id WHERE s.released = 0"
                )
            ):
                meta = _remote_meta(plane, pub)
                status, reason, stale = effective_remote_service_status(plane, pub, meta, owners)
                if stale and pub["public_port"] is not None:
                    _release_stale_port(plane, int(pub["public_port"]), pub, meta, reason)
                    pub = plane.conn.execute(
                        "SELECT * FROM published_services WHERE id = ?", (pub["id"],)
                    ).fetchone()
                    meta = _remote_meta(plane, pub)
                    status, reason, _stale = effective_remote_service_status(plane, pub, meta, owners)
                _apply_health(plane, pub, meta, status, reason)

            from drlink_runtime_policy import build_proxy_map

            build_proxy_map(plane)
            return {
                "entity": {"type": "upgrade-reconcile", "id": "control-plane", "name": "control-plane"},
                "operation": "reconcile",
            }
        finally:
            plane._batch_mode = nested

    result = plane._mutate(
        "system upgrade reconcile",
        "reconcile FRP registry into canonical control plane",
        write,
        compile_runtime=False,
    )
    after = preview_upgrade_reconciliation(plane, registry)
    return {"ok": True, "applied": True, "skipped": False, "plan": plan, "after": after, "result": result}


def reconcile_control_plane(
    plane: ControlPlane,
    *,
    root: Optional[str] = None,
    cfg: Optional[dict] = None,
    connected: bool = False,
) -> dict:
    registry, path, error = load_authoritative_registry(root or getattr(plane, "root", None), cfg)
    if error or registry is None:
        return {
            "ok": False,
            "applied": False,
            "error": error or "authoritative registry not found",
            "path": str(path) if path else "",
        }
    try:
        out = apply_upgrade_reconciliation(plane, registry, connected=connected)
    except ControlPlaneError as exc:
        return {
            "ok": False,
            "applied": False,
            "error": str(exc),
            "path": str(path),
        }
    out["path"] = str(path)
    return out


def reconcile_from_allocator(allocator) -> dict:
    """Server startup / upgrade entry. Never raises into allocator boot."""
    cfg = getattr(allocator, "cfg", None) or {}
    root = None
    try:
        from drlink_runtime_policy import root_from_cfg, open_plane

        root = root_from_cfg(cfg)
        plane = open_plane(cfg, root=root)
    except Exception as exc:
        return {"ok": False, "applied": False, "error": "control plane unavailable: %s" % exc}
    try:
        return reconcile_control_plane(plane, root=root, cfg=cfg, connected=False)
    finally:
        try:
            plane.close()
        except Exception:
            pass


def invariant_reservations_match_registry(plane: ControlPlane, registry: dict) -> list[str]:
    """Return human-readable violations: active SQLite reservation vs registry owner."""
    owners = registry_endpoint_owners(registry)
    problems = []
    for res in plane.conn.execute("SELECT * FROM port_reservations WHERE released = 0"):
        try:
            port = int(res["public_port"])
        except (TypeError, ValueError):
            problems.append("non-integer reservation port %r" % res["public_port"])
            continue
        owner = owners.get(port)
        if owner is None:
            problems.append("active reservation for %s has no registry owner" % port)
            continue
        cid = str(res["client_id"] or "")
        name = str(res["service_name"] or "")
        if not _semantic_owner_match(plane, client_id=cid, service_name=name, registry_owner=owner):
            problems.append(
                "reservation %s sqlite=%s/%s registry=%s/%s"
                % (port, cid[:8], name, str(owner.get("client_id") or "")[:8], owner.get("service_id"))
            )
    return problems
