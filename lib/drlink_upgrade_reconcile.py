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

Restrictive v2.3 Remote Access allowlists and enabled Internet egress
profiles are projected into canonical whitelist policy in the same
transaction. Legacy JSON is not left as the live allow authority.
Unsupported constructs fail the reconcile closed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from drlink_control_db import ControlPlaneError, utc_now_iso
from drlink_control_plane import ControlPlane

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
THIS_HOST = {"this-host", "this_host", "self"}
V24_PREFIX = "rs-"
# Tests may assign a callable(stage: str). Production leaves this unset.
_MIGRATION_CHECKPOINT = None


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
    destination_client_id: Optional[str] = None,
) -> Optional[str]:
    bound = str(destination_client_id or "").strip()
    if bound:
        row = plane.conn.execute("SELECT * FROM clients WHERE id = ?", (bound,)).fetchone()
        if row is None:
            return (
                "Bound Managed Host destination (client_id=%s) is missing or invalid."
                % bound[:12]
            )
        trust = str(row["trust_status"] or "").lower()
        if trust in ("revoked", "untrusted", "denied"):
            return "Bound Managed Host destination is revoked or untrusted."
        status = str(row["status"] or "").lower()
        if status in ("retired", "removed", "deleted"):
            return "Bound Managed Host destination is retired."
        ep = _managed_host_row(plane, bound)
        hostname = str(row["hostname"] or "").strip()
        has_addr = False
        if ep is not None:
            try:
                addrs = plane.endpoint_addresses(ep["name"]) or []
                has_addr = any(
                    (a.get("address") if isinstance(a, dict) else a) for a in addrs
                )
            except Exception:
                has_addr = False
            if not has_addr:
                vals = plane._object_values(ep["id"])
                has_addr = bool(vals)
        if not hostname and not has_addr:
            return (
                "Bound Managed Host '%s' has no usable hostname or address."
                % ((ep["name"] if ep else None) or row["label"] or bound[:12])
            )
        return None
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


def _normalize_target_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.rstrip(".").lower()


def _managed_host_runtime_target(plane: ControlPlane, client_id: str) -> tuple[Optional[str], Optional[str]]:
    """Return (target_host, degraded_reason) for a bound Managed Host client_id."""
    bound = str(client_id or "").strip()
    if not bound:
        return None, "Bound Managed Host destination is missing or invalid."
    row = plane.conn.execute("SELECT * FROM clients WHERE id = ?", (bound,)).fetchone()
    if row is None:
        return None, (
            "Bound Managed Host destination (client_id=%s) is missing or invalid." % bound[:12]
        )
    trust = str(row["trust_status"] or "").lower()
    if trust in ("revoked", "untrusted", "denied"):
        return None, "Bound Managed Host destination is revoked or untrusted."
    status = str(row["status"] or "").lower()
    if status in ("retired", "removed", "deleted"):
        return None, "Bound Managed Host destination is retired."
    ep = _managed_host_row(plane, bound)
    addresses: list[str] = []
    if ep is not None:
        try:
            for item in plane.endpoint_addresses(ep["name"]) or []:
                if isinstance(item, dict):
                    addr = item.get("address")
                    active = bool(item.get("active", True))
                else:
                    addr = item
                    active = True
                text = str(addr or "").strip()
                if text and active:
                    addresses.append(text)
        except Exception:
            addresses = []
        if not addresses:
            addresses = [str(v).strip() for v in plane._object_values(ep["id"]) if str(v or "").strip()]
    hostname = str(row["hostname"] or "").strip()
    if addresses:
        return addresses[0], None
    if hostname and hostname.lower() not in LOOPBACK:
        return hostname, None
    return None, (
        "Bound Managed Host '%s' has no usable hostname or address."
        % ((ep["name"] if ep else None) or row["label"] or bound[:12])
    )


def resolve_authoritative_remote_target(
    plane: ControlPlane,
    *,
    destination: str,
    owner_client_id: str,
    service_name: str,
    destination_client_id: Optional[str] = None,
    server_bound_client_id: Optional[str] = None,
) -> dict:
    """Derive Server-authoritative target_host/target_port for a Remote Service.

    Named Service Object / Network Object / Managed Host references are the
    source of truth. Agent-supplied target snapshots and destination_client_id
    bindings are not trusted when they contradict the named destination.

    Rename/label-drift continuity may use an immutable Managed Host binding only
    when ``server_bound_client_id`` proves a Server-owned prior bind for an
    existing Remote Service. Agent-supplied destination_client_id alone must
    never establish a new binding for an unresolved destination name.
    """
    service = str(service_name or "").strip()
    if not service:
        raise ControlPlaneError("Service Object is required")
    sobj = plane.conn.execute(
        "SELECT * FROM service_objects WHERE name = ? COLLATE NOCASE", (service,)
    ).fetchone()
    if sobj is None:
        raise ControlPlaneError("Service Object '%s' does not exist on the Server" % service)
    if str(sobj["type"] or "").lower() == "udp":
        raise ControlPlaneError("Remote Service supports TCP and Fixed TCP only")
    try:
        target_port = int(sobj["port"])
    except (TypeError, ValueError):
        raise ControlPlaneError("Service Object '%s' has an invalid port" % service)
    if target_port < 1 or target_port > 65535:
        raise ControlPlaneError("Service Object '%s' has an invalid port" % service)

    dest = str(destination or "").strip()
    if not dest:
        raise ControlPlaneError("Remote Service destination is required")
    owner = str(owner_client_id or "").strip()
    supplied = str(destination_client_id or "").strip() or None
    server_bound = str(server_bound_client_id or "").strip() or None
    target_mode = "routed"
    target_host = dest
    bound: Optional[str] = None

    owner_names = set()
    if owner:
        client = plane.conn.execute(
            "SELECT label, hostname FROM clients WHERE id = ?", (owner,)
        ).fetchone()
        if client:
            owner_names.update(
                {
                    str(client["label"] or "").strip().lower(),
                    str(client["hostname"] or "").strip().lower(),
                }
            )
        ep = _managed_host_row(plane, owner)
        if ep and str(ep["name"] or "").strip():
            owner_names.add(str(ep["name"]).strip().lower())
    owner_names.discard("")

    def _routed_from_bound(client_id: str) -> tuple[str, str]:
        resolved, reason = _managed_host_runtime_target(plane, client_id)
        if reason or not resolved:
            raise ControlPlaneError(reason or "Managed Host destination has no usable target")
        return "routed", resolved

    if dest.lower() in THIS_HOST or dest.lower() in owner_names:
        # Self only when the named destination itself is this host / owner alias.
        # destination_client_id == owner alone must not force self.
        if supplied and owner and supplied != owner:
            raise ControlPlaneError(
                "destination_client_id does not match authoritative destination '%s'." % dest
            )
        target_mode = "self"
        target_host = "127.0.0.1"
        bound = owner or None
    else:
        obj = plane.get_object(dest)
        if obj is not None:
            otype = str(obj["type"] or "").lower()
            if otype == "network":
                raise ControlPlaneError(
                    "Required destination '%s' is a CIDR Network Object and is not a valid single target."
                    % dest
                )
            if otype == "managed_endpoint":
                link = plane.conn.execute(
                    "SELECT client_id FROM managed_endpoints WHERE object_id = ?",
                    (obj["id"],),
                ).fetchone()
                derived = str(link["client_id"] if link else "") or None
                if not derived:
                    raise ControlPlaneError(
                        "Managed Host destination '%s' has no immutable client identity." % dest
                    )
                if supplied and supplied != derived:
                    raise ControlPlaneError(
                        "destination_client_id does not match authoritative Managed Host "
                        "destination '%s'." % dest
                    )
                bound = derived
                if bound == owner:
                    target_mode = "self"
                    target_host = "127.0.0.1"
                else:
                    target_mode, target_host = _routed_from_bound(bound)
            else:
                # IP/FQDN/host Network Object: never select a Managed Host via Agent binding.
                if supplied:
                    raise ControlPlaneError(
                        "destination_client_id is not valid for Network Object destination '%s'."
                        % dest
                    )
                vals = [
                    str(v).strip() for v in plane._object_values(obj["id"]) if str(v or "").strip()
                ]
                if not vals:
                    raise ControlPlaneError(
                        "Required Network Object destination '%s' has no address values." % dest
                    )
                bound = None
                target_mode = "routed"
                target_host = vals[0]
        elif server_bound:
            # Rename/label drift continuity is allowed only from Server-owned prior bind.
            if supplied and supplied != server_bound:
                raise ControlPlaneError(
                    "destination_client_id does not match Server-bound destination identity "
                    "for unresolved destination '%s'." % dest
                )
            if owner and server_bound == owner:
                raise ControlPlaneError(
                    "Required Network Object / Managed Host destination '%s' is missing or invalid."
                    % dest
                )
            bound = server_bound
            target_mode, target_host = _routed_from_bound(bound)
        else:
            # Unresolved named dependency: Agent-supplied destination_client_id must
            # never establish a new binding for a new or unproven Remote Service.
            raise ControlPlaneError(
                "Required Network Object / Managed Host destination '%s' is missing or invalid."
                % dest
            )

    return {
        "service_object": sobj,
        "target_port": target_port,
        "target_host": target_host,
        "target_mode": target_mode,
        "destination_client_id": bound,
    }


def server_target_projection_reason(plane: ControlPlane, pub, meta) -> Optional[str]:
    """Fail closed when published connectivity diverges from authoritative refs."""
    if pub is None or meta is None:
        return None
    dest = str(meta["destination_name"] or "").strip()
    dest_cid = None
    try:
        dest_cid = meta["destination_client_id"]
    except (KeyError, IndexError, TypeError):
        dest_cid = None
    sobj = None
    if meta["service_object_id"]:
        sobj = plane.conn.execute(
            "SELECT * FROM service_objects WHERE id = ?", (meta["service_object_id"],)
        ).fetchone()
    service_name = sobj["name"] if sobj is not None else ""
    if not service_name:
        # Bootstrap enrollment stores the target on the published service and
        # has no v2.4 Service Object. That is not a projection failure.
        if str(pub["target_host"] or "").strip() and pub["target_port"]:
            return None
        return "Required Service Object is missing or invalid."
    try:
        stored_bind = str(dest_cid or "").strip() or None
        expected = resolve_authoritative_remote_target(
            plane,
            destination=dest,
            owner_client_id=str(pub["client_id"] or ""),
            service_name=service_name,
            destination_client_id=stored_bind,
            server_bound_client_id=stored_bind,
        )
    except ControlPlaneError as exc:
        return str(exc)
    try:
        actual_port = int(pub["target_port"] or 0)
    except (TypeError, ValueError):
        actual_port = 0
    if actual_port != int(expected["target_port"]):
        return (
            "Published target_port %s diverges from authoritative Service Object port %s."
            % (actual_port, expected["target_port"])
        )
    actual_host = _normalize_target_host(pub["target_host"] or "")
    expect_host = _normalize_target_host(expected["target_host"])
    if actual_host != expect_host:
        return (
            "Published target_host diverges from authoritative destination reference "
            "(%s != %s)." % (actual_host or "(empty)", expect_host or "(empty)")
        )
    expect_cid = str(expected.get("destination_client_id") or "").strip() or None
    actual_cid = str(dest_cid or "").strip() or None
    if actual_cid != expect_cid:
        # Legacy self destinations may omit destination_client_id while still
        # projecting to 127.0.0.1/self. That is not a destination-identity bypass.
        legacy_self_ok = (
            actual_cid is None
            and expect_cid is not None
            and str(expected.get("target_mode") or "").lower() == "self"
            and actual_host in ("127.0.0.1", "::1")
            and str(pub["target_mode"] or "").lower() == "self"
        )
        if not legacy_self_ok:
            return (
                "Published destination_client_id diverges from authoritative destination identity."
            )
    return None


def rematerialize_fixed_tcp_for_object(plane: ControlPlane, object_id: str) -> int:
    """Refresh Fixed TCP dest_host snapshots from the current Network Object value."""
    obj = plane.conn.execute("SELECT * FROM objects WHERE id = ?", (object_id,)).fetchone()
    if obj is None:
        return 0
    vals = [str(v).strip() for v in plane._object_values(object_id) if str(v or "").strip()]
    if not vals:
        return 0
    host = vals[0]
    cur = plane.conn.execute(
        "UPDATE fixed_tcp SET dest_host = ?, row_version = row_version + 1, updated_at = ? "
        "WHERE destination_object_id = ? AND (dest_host IS NULL OR dest_host != ?)",
        (host, utc_now_iso(), object_id, host),
    )
    return int(cur.rowcount or 0)


def rematerialize_published_targets_for_service_object(plane: ControlPlane, sobj_id: str) -> int:
    """Converge published Remote Service target_port to the Service Object port."""
    sobj = plane.conn.execute(
        "SELECT * FROM service_objects WHERE id = ?", (sobj_id,)
    ).fetchone()
    if sobj is None:
        return 0
    port = int(sobj["port"])
    changed = 0
    for row in plane.conn.execute(
        "SELECT s.id, s.target_port FROM published_services s "
        "JOIN remote_service_meta m ON m.service_id = s.id "
        "WHERE m.service_object_id = ? AND s.released = 0",
        (sobj_id,),
    ):
        try:
            current = int(row["target_port"] or 0)
        except (TypeError, ValueError):
            current = 0
        if current == port:
            continue
        plane.conn.execute(
            "UPDATE published_services SET target_port = ?, updated_at = ? WHERE id = ?",
            (port, utc_now_iso(), row["id"]),
        )
        changed += 1
    return changed


def _resolve_published_authoritative_target(plane: ControlPlane, row) -> dict:
    """Resolve authoritative target, repairing contradictory stored bindings."""
    sobj = plane.conn.execute(
        "SELECT name FROM service_objects WHERE id = ?",
        (row["service_object_id"],),
    ).fetchone()
    if sobj is None:
        raise ControlPlaneError("Required Service Object is missing or invalid.")
    stored = str(row["destination_client_id"] or "").strip() or None
    destination = str(row["destination_name"] or "")
    owner = str(row["client_id"] or "")
    try:
        return resolve_authoritative_remote_target(
            plane,
            destination=destination,
            owner_client_id=owner,
            service_name=sobj["name"],
            destination_client_id=stored,
            server_bound_client_id=stored,
        )
    except ControlPlaneError:
        # Contradictory stored bind: re-derive from destination name alone.
        return resolve_authoritative_remote_target(
            plane,
            destination=destination,
            owner_client_id=owner,
            service_name=sobj["name"],
            destination_client_id=None,
            server_bound_client_id=None,
        )


def rematerialize_published_targets_for_destination_name(
    plane: ControlPlane, destination_name: str
) -> int:
    """Converge routed target_host for Network Object destination references."""
    dest = str(destination_name or "").strip()
    if not dest:
        return 0
    changed = 0
    for row in plane.conn.execute(
        "SELECT s.*, m.destination_name, m.destination_client_id, m.service_object_id "
        "FROM published_services s "
        "JOIN remote_service_meta m ON m.service_id = s.id "
        "WHERE m.destination_name = ? COLLATE NOCASE AND s.released = 0",
        (dest,),
    ):
        try:
            expected = _resolve_published_authoritative_target(plane, row)
        except ControlPlaneError:
            plane.conn.execute(
                "UPDATE remote_service_meta SET status = 'DEGRADED', reason = ? WHERE service_id = ?",
                ("Authoritative destination projection is inconsistent.", row["id"]),
            )
            changed += 1
            continue
        expect_cid = expected.get("destination_client_id")
        same_target = (
            _normalize_target_host(row["target_host"] or "")
            == _normalize_target_host(expected["target_host"])
            and int(row["target_port"] or 0) == int(expected["target_port"])
            and str(row["target_mode"] or "").lower() == str(expected["target_mode"]).lower()
        )
        same_bind = (str(row["destination_client_id"] or "").strip() or None) == (
            str(expect_cid or "").strip() or None
        )
        if same_target and same_bind:
            continue
        plane.conn.execute(
            "UPDATE published_services SET target_host = ?, target_port = ?, target_mode = ?, "
            "updated_at = ? WHERE id = ?",
            (
                expected["target_host"],
                int(expected["target_port"]),
                expected["target_mode"],
                utc_now_iso(),
                row["id"],
            ),
        )
        plane.conn.execute(
            "UPDATE remote_service_meta SET destination_client_id = ? WHERE service_id = ?",
            (expect_cid, row["id"]),
        )
        changed += 1
    return changed


def rematerialize_published_targets_for_managed_host(
    plane: ControlPlane, client_id: str
) -> int:
    """Converge routed target_host for Remote Services bound to a Managed Host."""
    bound = str(client_id or "").strip()
    if not bound:
        return 0
    changed = 0
    for row in plane.conn.execute(
        "SELECT s.*, m.destination_name, m.destination_client_id, m.service_object_id "
        "FROM published_services s "
        "JOIN remote_service_meta m ON m.service_id = s.id "
        "WHERE m.destination_client_id = ? AND s.released = 0",
        (bound,),
    ):
        try:
            expected = _resolve_published_authoritative_target(plane, row)
        except ControlPlaneError as exc:
            plane.conn.execute(
                "UPDATE remote_service_meta SET status = 'DEGRADED', reason = ? WHERE service_id = ?",
                (str(exc), row["id"]),
            )
            changed += 1
            continue
        expect_cid = expected.get("destination_client_id")
        same_target = (
            _normalize_target_host(row["target_host"] or "")
            == _normalize_target_host(expected["target_host"])
            and int(row["target_port"] or 0) == int(expected["target_port"])
            and str(row["target_mode"] or "").lower() == str(expected["target_mode"]).lower()
        )
        same_bind = (str(row["destination_client_id"] or "").strip() or None) == (
            str(expect_cid or "").strip() or None
        )
        if same_target and same_bind:
            continue
        plane.conn.execute(
            "UPDATE published_services SET target_host = ?, target_port = ?, target_mode = ?, "
            "updated_at = ? WHERE id = ?",
            (
                expected["target_host"],
                int(expected["target_port"]),
                expected["target_mode"],
                utc_now_iso(),
                row["id"],
            ),
        )
        plane.conn.execute(
            "UPDATE remote_service_meta SET destination_client_id = ? WHERE service_id = ?",
            (expect_cid, row["id"]),
        )
        changed += 1
    return changed


def effective_remote_service_status(
    plane: ControlPlane,
    pub,
    meta,
    registry_owners: dict[int, dict],
    *,
    agent_runtime: Optional[dict] = None,
    registry_available: bool = True,
    missing_registry_port_is_stale: bool = True,
) -> tuple[str, str, bool]:
    """Return (status, reason, stale_port).

    stale_port is True when SQLite still claims a port the registry does not
    attribute to this semantic service.

    When ``registry_available`` is False the FRP registry could not be loaded,
    so ownership is left unchanged rather than treating every port as stale.

    Status synchronization passes ``missing_registry_port_is_stale=False`` so a
    newly allocated port that the allocator has not yet persisted is not
    revoked. Upgrade reconciliation keeps the stricter default.
    """
    if pub is None:
        return "DEGRADED", "Published Service is missing.", False
    if not pub["enabled"]:
        return "DISABLED", "", False
    dest = str(meta["destination_name"] if meta else "") or ""
    dest_cid = None
    if meta is not None:
        try:
            dest_cid = meta["destination_client_id"]
        except (KeyError, IndexError, TypeError):
            dest_cid = None
    dest_reason = server_destination_reason(
        plane,
        dest,
        owner_client_id=pub["client_id"] if pub else None,
        destination_client_id=dest_cid,
    )
    svc_reason = server_service_reason(plane, meta)
    target_reason = server_target_projection_reason(plane, pub, meta)
    stale_port = False
    ownership_reason = None
    port = pub["public_port"]
    if port is not None:
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = None
        if port_i is not None and registry_available:
            owner = registry_owners.get(port_i)
            if owner is None:
                if missing_registry_port_is_stale:
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
    if target_reason:
        return "DEGRADED", target_reason, stale_port
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
        owner = plane.conn.execute(
            "SELECT * FROM clients WHERE id = ?", (pub["client_id"],)
        ).fetchone()
        if owner is None or plane.managed_host_connectivity(owner) != "connected":
            return "DEGRADED", "Managed Host is offline.", False
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


def _checkpoint(stage: str) -> None:
    hook = _MIGRATION_CHECKPOINT
    if hook is not None:
        hook(stage)


def _legacy_policy_error(detail: str) -> ControlPlaneError:
    return ControlPlaneError(
        "Upgrade cannot preserve v2.3 restrictive policy safely.\n\n"
        "%s\n\n"
        "Canonical Remote/Internet Access was not changed.\n"
        "Correct or remove the unsupported legacy construct, then retry the upgrade."
        % detail
    )


def _legacy_state_path(plane: ControlPlane, filename: str) -> Path:
    root = str(getattr(plane, "root", None) or "").strip()
    if root:
        return Path(root) / "var" / "lib" / "drlink" / filename
    return Path("/var/lib/drlink") / filename


def _token(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


def _read_json_object(path: Path, label: str) -> Optional[dict]:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _legacy_policy_error("%s is unreadable or corrupt (%s)." % (label, path.name)) from exc
    if not isinstance(raw, dict):
        raise _legacy_policy_error("%s must be a JSON object." % label)
    return raw


def _parse_expiry(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _active_cidrs(entries: Any, *, label: str) -> list[str]:
    if not isinstance(entries, list):
        raise _legacy_policy_error("%s entries are not a list." % label)
    now = datetime.now(timezone.utc)
    cidrs = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise _legacy_policy_error("%s contains a non-object entry." % label)
        if entry.get("expires_at") not in (None, ""):
            exp = _parse_expiry(entry.get("expires_at"))
            if exp is None or exp > now:
                raise _legacy_policy_error(
                    "%s entry uses a TTL expiry. v2.4 Network Objects cannot preserve it "
                    "without later broadening access." % label
                )
            continue
        raw = str(entry.get("cidr") or "").strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise _legacy_policy_error("%s has an invalid CIDR %r." % (label, raw)) from exc
        cidrs.append(str(net))
    return cidrs


def _service_port(svc: dict) -> Optional[int]:
    raw = svc.get("local_port")
    if raw is None:
        raw = svc.get("target_port")
    if raw is None:
        return None
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _load_access_state(plane: ControlPlane) -> Optional[dict]:
    path = _legacy_state_path(plane, "access-control.json")
    raw = _read_json_object(path, "access-control.json")
    if raw is None:
        return None
    try:
        import frp_access_control as acl

        return acl.require_access_state(path=path)
    except Exception as exc:
        raise _legacy_policy_error("access-control.json is not a supported v2.3 access policy.") from exc


def _load_egress_state(plane: ControlPlane) -> Optional[dict]:
    path = _legacy_state_path(plane, "egress-control.json")
    if not path.is_file():
        return None
    try:
        import frp_egress_control as eg

        return eg.load_egress_state(path, persist_migration=False)
    except Exception as exc:
        raise _legacy_policy_error("egress-control.json is not a supported v2.3 egress policy.") from exc


def _cidr_object_name(cidr: str) -> str:
    return "v23c" + _token(cidr)


def _fqdn_object_name(host: str) -> str:
    return "v23f" + _token(host)


def _service_object_name(port: int) -> str:
    return "v23s" + _token("tcp:%s" % int(port))


def _remote_rule_name(client_id: str, service_id: str, *, public: bool) -> str:
    prefix = "v23p" if public else "v23r"
    return prefix + _token("%s\n%s" % (client_id, service_id))


def _internet_rule_name(profile_id: str, dest_key: str) -> str:
    return "v23i" + _token("%s\n%s" % (profile_id, dest_key))


def _plan_legacy_policy(plane: ControlPlane, registry: dict) -> dict:
    """Describe the canonical projection. Raises when it cannot be exact and safe."""
    access = _load_access_state(plane)
    egress = _load_egress_state(plane)
    clients = registry.get("clients") if isinstance(registry.get("clients"), dict) else {}
    remote_rules = []
    remote_restrictive = False
    if access is not None:
        lists = access.get("access_lists") or {}
        bindings = access.get("service_access") or {}
        restricted = {}
        for mid, services in bindings.items():
            if not isinstance(services, dict):
                raise _legacy_policy_error("service_access[%s] is not an object." % mid)
            for sid, binding in services.items():
                if not isinstance(binding, dict):
                    raise _legacy_policy_error("service binding %s/%s is not an object." % (mid, sid))
                mode = str(binding.get("access_mode") or "PUBLIC").upper()
                if mode == "PUBLIC":
                    continue
                if mode != "ALLOWLIST":
                    raise _legacy_policy_error(
                        "service %s/%s uses unsupported access mode %s." % (mid, sid, mode)
                    )
                remote_restrictive = True
                list_id = binding.get("access_list_id")
                lst = lists.get(list_id) if list_id else None
                if not isinstance(lst, dict):
                    restricted[(str(mid), str(sid).strip().lower())] = []
                    continue
                restricted[(str(mid), str(sid).strip().lower())] = _active_cidrs(
                    lst.get("entries") or [],
                    label="access list %s" % (lst.get("name") or list_id),
                )
        if remote_restrictive:
            for cid, rec in clients.items():
                if not isinstance(rec, dict):
                    continue
                cid_s = str(cid)
                dest = managed_host_policy_name(plane, cid_s) or _client_public_name(rec, cid_s)
                if not dest:
                    raise _legacy_policy_error(
                        "Managed Host for client %s has no policy name to bind Remote Access." % cid_s
                    )
                services = rec.get("services") if isinstance(rec.get("services"), dict) else {}
                for sid, svc in services.items():
                    if not isinstance(svc, dict):
                        continue
                    sid_raw = str(sid).strip().lower()
                    sid_s = sid_raw
                    if is_v24_runtime_projection(sid_raw, svc, plane=plane, client_id=cid_s):
                        canonical = str(svc.get("name") or "").strip().lower()
                        if canonical:
                            sid_s = canonical
                    port = _service_port(svc)
                    if port is None:
                        raise _legacy_policy_error(
                            "published service %s/%s has no local port, so its access policy "
                            "cannot be mapped without guessing." % (cid_s, sid)
                        )
                    stype = str(svc.get("type") or svc.get("service_type") or svc.get("preset") or "tcp").lower()
                    if stype == "udp":
                        raise _legacy_policy_error(
                            "published service %s/%s is UDP. Remote Access cannot represent it "
                            "without changing the frozen v2.4 policy model." % (cid_s, sid)
                        )
                    cidrs = restricted.get((cid_s, sid_raw))
                    if cidrs is None and sid_s != sid_raw:
                        cidrs = restricted.get((cid_s, sid_s))
                    public = cidrs is None
                    if not public and not cidrs:
                        continue
                    sources = ["v23any4", "v23any6"] if public else [_cidr_object_name(c) for c in cidrs]
                    remote_rules.append(
                        {
                            "plane": "remote",
                            "name": _remote_rule_name(cid_s, sid_raw, public=public),
                            "sources": sources,
                            "source_values": ["0.0.0.0/0", "::/0"] if public else list(cidrs),
                            "destination": dest,
                            "service": _service_object_name(port),
                            "port": port,
                        }
                    )
            restricted_ports = {
                (rule["destination"], rule["port"])
                for rule in remote_rules
                if str(rule["name"]).startswith("v23r")
            }
            remote_rules = [
                rule
                for rule in remote_rules
                if not str(rule["name"]).startswith("v23p")
                or (rule["destination"], rule["port"]) not in restricted_ports
            ]
    internet_rules = []
    internet_restrictive = False
    if egress is not None:
        profiles = egress.get("egress_profiles") or {}
        if not isinstance(profiles, dict):
            raise _legacy_policy_error("egress_profiles is not an object.")
        for pid, profile in profiles.items():
            if not isinstance(profile, dict) or not profile.get("enabled"):
                continue
            internet_restrictive = True
            sources = _active_cidrs(
                profile.get("sources") or [],
                label="egress profile %s sources" % (profile.get("name") or pid),
            )
            destinations = profile.get("destinations") or []
            if not isinstance(destinations, list):
                raise _legacy_policy_error(
                    "egress profile %s destinations are not a list." % (profile.get("name") or pid)
                )
            for dest in destinations:
                if not isinstance(dest, dict):
                    raise _legacy_policy_error("egress profile %s has a non-object destination." % pid)
                match = str(dest.get("match") or "exact").lower()
                host = str(dest.get("host") or "").strip().rstrip(".").lower()
                if match != "exact":
                    raise _legacy_policy_error(
                        "egress profile %s destination %s uses match=%s. "
                        "v2.4 FQDN objects are exact-only, so this cannot be migrated "
                        "without broadening or narrowing access."
                        % (profile.get("name") or pid, host or dest.get("id"), match)
                    )
                try:
                    ipaddress.ip_address(host)
                    continue
                except ValueError:
                    pass
                proto = str(dest.get("protocol") or "").strip().lower()
                if proto not in ("http", "https", "tcp"):
                    raise _legacy_policy_error(
                        "egress profile %s destination uses unsupported protocol %s."
                        % (profile.get("name") or pid, proto or "(missing)")
                    )
                try:
                    port = int(dest.get("port"))
                except (TypeError, ValueError):
                    port = 0
                if port < 1 or port > 65535:
                    raise _legacy_policy_error(
                        "egress profile %s destination has an invalid port." % (profile.get("name") or pid)
                    )
                if not host:
                    raise _legacy_policy_error(
                        "egress profile %s destination is missing a hostname." % (profile.get("name") or pid)
                    )
                dest_key = str(dest.get("id") or "%s:%s:%s" % (host, port, proto))
                if not sources:
                    continue
                internet_rules.append(
                    {
                        "plane": "internet",
                        "name": _internet_rule_name(str(pid), dest_key),
                        "sources": [_cidr_object_name(c) for c in sources],
                        "source_values": list(sources),
                        "destination": _fqdn_object_name(host),
                        "destination_value": host,
                        "service": _service_object_name(port),
                        "port": port,
                    }
                )
    return {
        "remote_restrictive": remote_restrictive,
        "internet_restrictive": internet_restrictive,
        "remote_rules": remote_rules,
        "internet_rules": internet_rules,
    }


def _rule_ref_names(plane: ControlPlane, rule_id: str, table: str) -> set[str]:
    names = set()
    for row in plane.conn.execute(
        "SELECT ref_kind, ref_id FROM %s WHERE rule_id = ?" % table, (rule_id,)
    ):
        if row["ref_kind"] == "object":
            obj = plane.conn.execute("SELECT name FROM objects WHERE id = ?", (row["ref_id"],)).fetchone()
            if obj:
                names.add(obj["name"])
        else:
            grp = plane.conn.execute(
                "SELECT name FROM object_groups WHERE id = ?", (row["ref_id"],)
            ).fetchone()
            if grp:
                names.add(grp["name"])
    return names


def _rule_service_name(plane: ControlPlane, rule_id: str) -> str:
    row = plane.conn.execute(
        "SELECT ref_id FROM rule_service_refs WHERE rule_id = ? AND ref_kind = 'service_object'",
        (rule_id,),
    ).fetchone()
    if row is None:
        return ""
    sobj = plane.conn.execute("SELECT name FROM service_objects WHERE id = ?", (row["ref_id"],)).fetchone()
    return str(sobj["name"]) if sobj else ""


def _projection_satisfied(plane: ControlPlane, family: str, rules: list[dict], *, restrictive: bool) -> bool:
    if not restrictive:
        return True
    import drlink_v24 as v24

    pol = v24.get_access_policy(plane, family)
    if pol.get("mode") != "whitelist":
        return False
    if str(pol.get("enforcement") or "enabled").lower() != "enabled":
        return False
    existing = {
        str(row["name"])
        for row in plane.conn.execute("SELECT name FROM policy_rules WHERE plane = ?", (family,))
    }
    wanted = {rule["name"] for rule in rules}
    if existing != wanted:
        return False
    for rule in rules:
        row = plane._get_rule(family, rule["name"])
        if row is None or not row["enabled"]:
            return False
        if _rule_ref_names(plane, row["id"], "rule_sources") != set(rule["sources"]):
            return False
        if _rule_ref_names(plane, row["id"], "rule_destinations") != {rule["destination"]}:
            return False
        if _rule_service_name(plane, row["id"]) != rule["service"]:
            return False
    return True


def legacy_policy_pending(plane: ControlPlane, registry: dict) -> bool:
    """True when restrictive legacy policy is not yet the canonical projection."""
    plan = _plan_legacy_policy(plane, registry)
    if not plan["remote_restrictive"] and not plan["internet_restrictive"]:
        return False
    remote_ok = _projection_satisfied(
        plane, "remote", plan["remote_rules"], restrictive=plan["remote_restrictive"]
    )
    internet_ok = _projection_satisfied(
        plane, "internet", plan["internet_rules"], restrictive=plan["internet_restrictive"]
    )
    return not (remote_ok and internet_ok)


def legacy_restrictive_unmigrated(plane: ControlPlane, family: str) -> bool:
    """Fail-closed latch: restrictive legacy state exists and this plane has no canonical mode.

    Corrupt or unsupported legacy files are treated as unmigrated so evaluation
    cannot fall open to No Policy ALLOW. After a successful projection the plane
    mode is whitelist and this latch is not consulted.
    """
    try:
        if family == "remote":
            access = _load_access_state(plane)
            if access is None:
                return False
            bindings = access.get("service_access") or {}
            for services in bindings.values():
                if not isinstance(services, dict):
                    return True
                for binding in services.values():
                    if isinstance(binding, dict) and str(binding.get("access_mode") or "").upper() == "ALLOWLIST":
                        return True
            return False
        if family == "internet":
            egress = _load_egress_state(plane)
            if egress is None:
                return False
            profiles = egress.get("egress_profiles") or {}
            if not isinstance(profiles, dict):
                return True
            return any(isinstance(p, dict) and p.get("enabled") for p in profiles.values())
    except ControlPlaneError:
        return True
    except Exception:
        return True
    return False


def _ensure_network(plane: ControlPlane, name: str, kind: str, value: str) -> None:
    import drlink_v24 as v24

    v24.set_network_object(plane, name, type=kind, value=value, oneshot=True)


def _ensure_service(plane: ControlPlane, name: str, port: int) -> None:
    import drlink_v24 as v24

    v24.set_service_object(plane, name, type="tcp", port=int(port), oneshot=True)


def _apply_rule_set(plane: ControlPlane, family: str, rules: list[dict], *, restrictive: bool) -> None:
    if not restrictive:
        return
    import drlink_v24 as v24

    pol = v24.get_access_policy(plane, family)
    if pol.get("mode") not in (None, "whitelist"):
        title = "Remote Access" if family == "remote" else "Internet Access"
        raise _legacy_policy_error(
            "%s is already %s. Reset it before upgrading restrictive v2.3 policy into whitelist."
            % (title, str(pol.get("mode")).upper())
        )
    if str(pol.get("enforcement") or "enabled").lower() != "enabled":
        title = "Remote Access" if family == "remote" else "Internet Access"
        raise _legacy_policy_error(
            "%s enforcement is disabled. Re-enable it before upgrading, otherwise "
            "the migrated rules would not be enforced." % title
        )
    existing = {
        str(row["name"])
        for row in plane.conn.execute("SELECT name FROM policy_rules WHERE plane = ?", (family,))
    }
    wanted = {rule["name"] for rule in rules}
    extra = existing - wanted
    if extra:
        title = "Remote Access" if family == "remote" else "Internet Access"
        raise _legacy_policy_error(
            "%s already has rules that are not the v2.3 migration projection (%s)."
            % (title, ", ".join(sorted(extra)))
        )
    if not rules:
        v24.ensure_policy_mode(plane, family, "whitelist", oneshot=True)
        return
    for rule in rules:
        for name, value in zip(rule["sources"], rule["source_values"]):
            _ensure_network(plane, name, "cidr", value)
        if rule["plane"] == "internet":
            _ensure_network(plane, rule["destination"], "fqdn", rule["destination_value"])
        _ensure_service(plane, rule["service"], rule["port"])
        v24.set_access_rule(
            plane,
            family,
            rule["name"],
            mode="whitelist",
            source=rule["sources"][0],
            destination=rule["destination"],
            service=rule["service"],
            enabled=True,
            oneshot=True,
        )
        for extra_source in rule["sources"][1:]:
            plane.set_rule_source(family, rule["name"], extra_source)
        _checkpoint("legacy-policy-rule")


def _apply_legacy_policy(plane: ControlPlane, registry: dict) -> None:
    plan = _plan_legacy_policy(plane, registry)
    if _projection_satisfied(
        plane, "remote", plan["remote_rules"], restrictive=plan["remote_restrictive"]
    ) and _projection_satisfied(
        plane, "internet", plan["internet_rules"], restrictive=plan["internet_restrictive"]
    ):
        return
    _apply_rule_set(plane, "remote", plan["remote_rules"], restrictive=plan["remote_restrictive"])
    _apply_rule_set(plane, "internet", plan["internet_rules"], restrictive=plan["internet_restrictive"])


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
    policy_pending = legacy_policy_pending(plane, registry)
    if not plan["has_work"] and not policy_pending:
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

            _apply_legacy_policy(plane, registry)
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
