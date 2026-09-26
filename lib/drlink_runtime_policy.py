#!/usr/bin/env python3
"""Canonical runtime policy adapters for Data Relay Link packet paths.

SQLite (/var/lib/drlink/drlink.db) is the sole control-plane authority.
Derived artifacts under /var/lib/drlink/runtime/ are non-authoritative caches.
Legacy JSON stores (access-control.json, egress-control.json, registry.json,
service-profiles.json) must not decide live allow/deny.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any, Optional

_LIB_DIR = Path(__file__).resolve().parent
if str(_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(_LIB_DIR))

from drlink_control_db import (
    ControlPlaneError,
    DatabaseCorruptError,
    SchemaTooNewError,
    connect,
    db_path,
    resolve_root,
    runtime_dir,
    utc_now_iso,
)
from drlink_control_plane import ControlPlane

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"

REASON_UNMAPPED_PROXY = "UNMAPPED_PROXY"
REASON_SERVICE_DISABLED = "SERVICE_DISABLED"
REASON_AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
REASON_POLICY_DENY = "POLICY_DENY"
REASON_IMPLICIT_DENY = "IMPLICIT_DENY"
REASON_GENERATION_MISMATCH = "GENERATION_MISMATCH"
REASON_DB_UNAVAILABLE = "DB_UNAVAILABLE"
REASON_RELAY_DISABLED = "RELAY_DISABLED"
REASON_RELAY_MISSING = "RELAY_MISSING"

_HOST_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_host_id_part(hostname: str) -> str:
    return _HOST_SAFE_RE.sub("-", str(hostname or ""))


def expected_host_id(hostname: str, machine_id: str) -> str:
    mid = str(machine_id or "")
    return "%s-%s" % (sanitize_host_id_part(hostname), mid[:8])


def expected_proxy_name(hostname: str, machine_id: str, service_id: str) -> str:
    return "%s-%s" % (expected_host_id(hostname, machine_id), str(service_id).strip().lower())


def root_from_cfg(cfg: Optional[dict] = None) -> Optional[str]:
    env = resolve_root(None)
    if env:
        return env
    for key in ("FRP_DEPLOY_TEST_ROOT", "FRP_CTL_TEST_ROOT", "DRLINK_TEST_ROOT"):
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    if cfg:
        explicit = str(cfg.get("control_plane_root") or cfg.get("deploy_root") or "").strip()
        if explicit:
            return explicit
        db = str(cfg.get("control_db_file") or cfg.get("drlink_db") or "").strip()
        if db:
            path = Path(db)
            # .../var/lib/drlink/drlink.db → deploy root above var/
            parts = path.parts
            if "var" in parts:
                idx = parts.index("var")
                if idx > 0:
                    return str(Path(*parts[:idx])) if idx > 1 else "/"
            parent = path.parent.parent.parent  # drlink → lib → var
            if parent != path:
                return str(parent)
    return None


def open_plane(cfg: Optional[dict] = None, root: Optional[str] = None) -> ControlPlane:
    return ControlPlane(root or root_from_cfg(cfg))


def generation_status(plane: ControlPlane, plane_name: str) -> dict:
    st = plane.status()
    gen = (st.get("generations") or {}).get(plane_name) or {}
    mismatch = bool(st.get("mismatch"))
    if gen.get("status") == "mismatch":
        mismatch = True
    if gen.get("status") == "active" and gen.get("generation") != st.get("revision"):
        mismatch = True
    healthy = bool(st.get("db_healthy")) and not mismatch
    return {
        "healthy": healthy,
        "revision": st.get("revision"),
        "generation": gen.get("generation"),
        "status": gen.get("status"),
        "db_healthy": st.get("db_healthy"),
        "mismatch": mismatch,
        "error": gen.get("error") or ("generation mismatch" if mismatch else ""),
    }


def parse_remote_addr(remote_addr: str) -> str:
    text = str(remote_addr or "").strip()
    if not text:
        raise ControlPlaneError("missing source address")
    if text.startswith("["):
        end = text.find("]")
        if end > 1:
            host = text[1:end]
            return str(ipaddress.ip_address(host))
    if ":" in text and text.count(":") == 1:
        host = text.rsplit(":", 1)[0]
        return str(ipaddress.ip_address(host))
    return str(ipaddress.ip_address(text))


def build_proxy_map(plane: ControlPlane) -> dict[str, dict]:
    """Map FRP proxy_name → published service metadata from SQLite."""
    mapping: dict[str, dict] = {}
    collisions: dict[str, list] = {}
    try:
        from drlink_v24_runtime import remote_service_proxy_id
    except Exception:
        remote_service_proxy_id = None
    for client in plane.conn.execute("SELECT * FROM clients"):
        hostname = client["hostname"] or ""
        mid = client["id"]
        label = client["label"] or ""
        for svc in plane.conn.execute(
            "SELECT * FROM published_services WHERE client_id = ? AND released = 0",
            (mid,),
        ):
            # v2.4 Remote Services use stable rs-<name> runtime ids; enrollment
            # services keep their historical id (== published name).
            sid = str(svc["name"]).strip().lower()
            meta = plane.conn.execute(
                "SELECT * FROM remote_service_meta WHERE service_id = ?",
                (svc["id"],),
            ).fetchone()
            if meta is not None and remote_service_proxy_id is not None:
                sid = remote_service_proxy_id(svc["name"])
            name = expected_proxy_name(hostname, mid, sid)
            entry = {
                "client_id": mid,
                "service_id": sid,
                "public_port": svc["public_port"],
                "client_label": label,
                "hostname": hostname,
                "enabled": bool(svc["enabled"]),
                "target_mode": svc["target_mode"],
                "target_host": svc["target_host"],
                "target_port": int(svc["target_port"] or 0),
                "service_type": svc["service_type"],
                "protocol": "tcp",
                "published_id": svc["id"],
                "destination_name": str(meta["destination_name"] or "") if meta is not None else "",
                "destination_client_id": (
                    str(meta["destination_client_id"] or "").strip() or None
                    if meta is not None
                    else None
                ),
                "service_object_id": meta["service_object_id"] if meta is not None else None,
                "has_remote_meta": meta is not None,
            }
            if name in mapping or name in collisions:
                collisions.setdefault(name, [mapping.pop(name, None)]).append(entry)
                continue
            mapping[name] = entry
    if collisions:
        owners = []
        for name, entries in sorted(collisions.items()):
            parts = []
            for e in entries:
                if not e:
                    continue
                parts.append("%s/%s" % (e.get("client_id"), e.get("service_id")))
            owners.append("%s => %s" % (name, ", ".join(parts)))
        raise ControlPlaneError(
            "derived proxy name collision (fail closed): %s" % "; ".join(owners)
        )
    return mapping


def _destination_for_service(plane: ControlPlane, mapped: dict) -> str:
    mode = str(mapped.get("target_mode") or "self").lower()
    if mode == "routed":
        return str(mapped.get("target_host") or "")
    # SELF: policy identity is the Managed Host, never the backend loopback.
    try:
        from drlink_upgrade_reconcile import managed_host_policy_name

        name = managed_host_policy_name(plane, mapped["client_id"])
        if name:
            return name
    except Exception:
        ep = plane.conn.execute(
            "SELECT o.name FROM objects o JOIN managed_endpoints e ON e.object_id = o.id "
            "WHERE e.client_id = ?",
            (mapped["client_id"],),
        ).fetchone()
        if ep and str(ep["name"] or "").strip():
            return ep["name"]
        client = plane.conn.execute(
            "SELECT label, hostname FROM clients WHERE id = ?",
            (mapped["client_id"],),
        ).fetchone()
        if client:
            for candidate in (client["label"], client["hostname"]):
                text = str(candidate or "").strip()
                if text and text not in ("127.0.0.1", "::1", "localhost"):
                    return text
    # Fail closed: empty destination denies rather than silently becoming loopback.
    return ""


def authorize_remote(
    plane: ControlPlane,
    *,
    proxy_name: str,
    source_ip: str,
) -> dict:
    """Authorize an inbound NewUserConn using canonical Remote Access rules."""
    gen = generation_status(plane, "remote")
    result = {
        "timestamp": None,
        "client_id": None,
        "client_label": None,
        "service_id": None,
        "public_port": None,
        "source_ip": None,
        "decision": DECISION_DENY,
        "reason": REASON_AUTHORIZATION_ERROR,
        "proxy_name": proxy_name,
        "policy_generation": gen.get("generation"),
        "db_revision": gen.get("revision"),
    }
    try:
        result["source_ip"] = parse_remote_addr(source_ip)
    except Exception:
        try:
            result["source_ip"] = str(ipaddress.ip_address(str(source_ip).strip()))
        except Exception:
            result["reason"] = REASON_AUTHORIZATION_ERROR
            return result

    if not gen["healthy"]:
        result["reason"] = REASON_GENERATION_MISMATCH if gen["mismatch"] else REASON_DB_UNAVAILABLE
        return result

    try:
        mapped = build_proxy_map(plane).get(proxy_name)
    except ControlPlaneError as exc:
        result["reason"] = str(exc)
        return result

    if mapped is None:
        result["reason"] = REASON_UNMAPPED_PROXY
        return result

    result["client_id"] = mapped["client_id"]
    result["service_id"] = mapped["service_id"]
    result["public_port"] = mapped.get("public_port")
    result["client_label"] = mapped.get("client_label") or None

    if not mapped.get("enabled", True):
        result["reason"] = REASON_SERVICE_DISABLED
        return result

    # Fail closed when published connectivity diverges from authoritative refs.
    if mapped.get("has_remote_meta"):
        try:
            from drlink_upgrade_reconcile import server_target_projection_reason

            pub = plane.conn.execute(
                "SELECT * FROM published_services WHERE id = ?",
                (mapped.get("published_id"),),
            ).fetchone()
            meta = plane.conn.execute(
                "SELECT * FROM remote_service_meta WHERE service_id = ?",
                (mapped.get("published_id"),),
            ).fetchone()
            mismatch = server_target_projection_reason(plane, pub, meta)
            if mismatch:
                result["destination"] = mapped.get("target_host") or ""
                result["reason"] = "AUTHORITATIVE_TARGET_MISMATCH"
                result["mismatch"] = mismatch
                return result
        except Exception:
            # Authorization must not fail open on projection helper errors.
            result["reason"] = REASON_AUTHORIZATION_ERROR
            return result

    dest = _destination_for_service(plane, mapped)
    result["destination"] = dest
    port = int(mapped.get("target_port") or 0)
    proto = "tcp"
    evaluation = plane.evaluate_remote_access(result["source_ip"], dest, proto, port)
    action = str(evaluation.get("action") or DECISION_DENY).upper()
    result["decision"] = DECISION_ALLOW if action == DECISION_ALLOW else DECISION_DENY
    if evaluation.get("implicit"):
        result["reason"] = REASON_IMPLICIT_DENY
    elif action == DECISION_ALLOW:
        result["reason"] = evaluation.get("reason") or "REMOTE_ACCESS_ALLOW"
    else:
        result["reason"] = evaluation.get("reason") or REASON_POLICY_DENY
    result["evaluation"] = {
        "winner": evaluation.get("winner"),
        "implicit": evaluation.get("implicit"),
        "published": evaluation.get("published"),
    }
    return result


def authorize_internet(
    plane: ControlPlane,
    *,
    source_ip: str,
    hostname: str,
    port: int,
    protocol: str,
    candidate_ips: Optional[list[str]] = None,
) -> dict:
    """Authorize outbound Internet Access using canonical ordered rules.

    When ``candidate_ips`` is provided (runtime path), policy is evaluated at
    candidate granularity and only authorized candidates may be connected.
    Direct IP literals must be authorized by explicit Host/CIDR selectors.
    """
    gen = generation_status(plane, "internet")
    base = {
        "source_ip": source_ip,
        "hostname": hostname,
        "port": int(port),
        "protocol": str(protocol).lower(),
        "decision": DECISION_DENY,
        "reason": REASON_AUTHORIZATION_ERROR,
        "policy_generation": gen.get("generation"),
        "db_revision": gen.get("revision"),
        "is_ip_literal": False,
        "candidate_ips": [],
        "authorized_candidates": [],
        "candidate_results": [],
    }
    if not gen["healthy"]:
        base["reason"] = REASON_GENERATION_MISMATCH if gen["mismatch"] else REASON_DB_UNAVAILABLE
        return base
    try:
        src = str(ipaddress.ip_address(str(source_ip).strip()))
    except ValueError:
        try:
            src = parse_remote_addr(source_ip)
        except Exception:
            base["reason"] = REASON_AUTHORIZATION_ERROR
            return base
    evaluation = plane.evaluate_internet_access(
        src,
        hostname,
        int(port),
        protocol,
        candidate_ips=candidate_ips,
    )
    action = str(evaluation.get("action") or DECISION_DENY).upper()
    base["source_ip"] = src
    base["hostname"] = evaluation.get("destination") or hostname
    base["is_ip_literal"] = bool(evaluation.get("is_ip_literal"))
    base["candidate_ips"] = list(evaluation.get("candidate_ips") or [])
    base["authorized_candidates"] = list(evaluation.get("authorized_candidates") or [])
    base["candidate_results"] = list(evaluation.get("candidate_results") or [])
    # Hostname-only evaluation (no candidates): preserve prior ALLOW/DENY.
    # Candidate evaluation: ALLOW only when authorized_candidates is non-empty
    # (or mode/enforcement already yielded ALLOW with empty list for no-policy).
    if candidate_ips is not None or evaluation.get("is_ip_literal"):
        if action == DECISION_ALLOW and not base["authorized_candidates"]:
            # No-policy / enforcement-disabled authorize all provided candidates.
            if evaluation.get("mode") is None or str(evaluation.get("enforcement") or "").lower() == "disabled":
                base["authorized_candidates"] = list(base["candidate_ips"])
            else:
                action = DECISION_DENY
    base["decision"] = DECISION_ALLOW if action == DECISION_ALLOW else DECISION_DENY
    if evaluation.get("implicit") and action != DECISION_ALLOW:
        base["reason"] = REASON_IMPLICIT_DENY
    elif action == DECISION_ALLOW:
        base["reason"] = evaluation.get("reason") or "INTERNET_ACCESS_ALLOW"
    else:
        base["reason"] = evaluation.get("reason") or REASON_POLICY_DENY
    if evaluation.get("winner"):
        base["rule_name"] = evaluation["winner"].get("name")
        base["rule_position"] = evaluation["winner"].get("display_position")
    return base


def list_enabled_fixed_tcp(plane: ControlPlane) -> dict[str, dict]:
    """Return {id: {name, listen_addr, listen_port, dest_host, dest_port, enabled}}."""
    out = {}
    for row in plane.conn.execute("SELECT * FROM fixed_tcp"):
        if not row["enabled"]:
            continue
        if row["listen_port"] is None:
            continue
        out[row["id"]] = {
            "id": row["id"],
            "name": row["name"],
            "listen_addr": "0.0.0.0",
            "listen_port": int(row["listen_port"]),
            "dest_host": row["dest_host"] or "",
            "dest_port": int(row["dest_port"] or 0),
            "enabled": True,
        }
    return out


def authorize_fixed_tcp(
    plane: ControlPlane,
    *,
    relay_id: str,
    source_ip: str,
) -> dict:
    gen = generation_status(plane, "internet")
    result = {
        "source_ip": source_ip,
        "relay_id": relay_id,
        "decision": DECISION_DENY,
        "reason": REASON_AUTHORIZATION_ERROR,
        "policy_generation": gen.get("generation"),
        "db_revision": gen.get("revision"),
        "hostname": None,
        "port": None,
        "relay_name": None,
    }
    if not gen["healthy"]:
        result["reason"] = REASON_GENERATION_MISMATCH if gen["mismatch"] else REASON_DB_UNAVAILABLE
        return result
    row = plane.conn.execute("SELECT * FROM fixed_tcp WHERE id = ?", (relay_id,)).fetchone()
    if row is None:
        # Allow name lookup for tests/tools
        row = plane.conn.execute(
            "SELECT * FROM fixed_tcp WHERE name = ? COLLATE NOCASE", (relay_id,)
        ).fetchone()
    if row is None:
        result["reason"] = REASON_RELAY_MISSING
        return result
    result["relay_id"] = row["id"]
    result["relay_name"] = row["name"]
    hostname = row["dest_host"] or ""
    # Authoritative destination Object wins over the stored snapshot.
    dest_obj_id = row["destination_object_id"]
    if dest_obj_id:
        vals = [
            str(v).strip()
            for v in plane._object_values(dest_obj_id)
            if str(v or "").strip()
        ]
        if not vals:
            result["reason"] = REASON_AUTHORIZATION_ERROR
            return result
        hostname = vals[0]
        if str(row["dest_host"] or "").strip() != hostname:
            try:
                plane.conn.execute(
                    "UPDATE fixed_tcp SET dest_host = ?, row_version = row_version + 1, "
                    "updated_at = ? WHERE id = ?",
                    (hostname, utc_now_iso(), row["id"]),
                )
                plane.conn.commit()
            except Exception:
                pass
    result["hostname"] = hostname
    result["port"] = int(row["dest_port"] or 0)
    if not row["enabled"]:
        result["reason"] = REASON_RELAY_DISABLED
        return result
    if not result["hostname"] or not result["port"]:
        result["reason"] = REASON_AUTHORIZATION_ERROR
        return result
    policy = authorize_internet(
        plane,
        source_ip=source_ip,
        hostname=result["hostname"],
        port=result["port"],
        protocol="tcp",
    )
    result["decision"] = policy["decision"]
    result["reason"] = policy["reason"]
    result["policy_generation"] = policy.get("policy_generation")
    result["db_revision"] = policy.get("db_revision")
    result["rule_name"] = policy.get("rule_name")
    return result


def sync_enrolled_client(
    plane: ControlPlane,
    *,
    client_id: str,
    hostname: str = "",
    label: str = "",
    description: str = "",
    services: Optional[dict] = None,
    addresses: Optional[list] = None,
    connected: bool = True,
) -> dict:
    """Upsert Client + Managed Endpoint + Published Services after real enrollment.

    Registry JSON must not remain an independent authority; callers should treat
    this SQLite write as the durable inventory commit for the enrollment.
    """
    addresses = addresses or []
    if hostname and not any(a.get("address") == hostname for a in addresses):
        # hostname may be non-IP; only seed IP-looking observed addresses
        try:
            ipaddress.ip_address(hostname)
            addresses = list(addresses) + [{"address": hostname, "active": True}]
        except ValueError:
            pass

    public_label = (label or hostname or "").strip() or None
    plane.upsert_client(
        client_id,
        label=public_label,
        description=description or None,
        hostname=hostname or None,
        connected=connected,
        addresses=addresses or None,
    )

    services = services or {}
    for sid, svc in services.items():
        if not isinstance(svc, dict):
            continue
        try:
            from drlink_upgrade_reconcile import is_v24_runtime_projection

            if is_v24_runtime_projection(sid, svc, plane=plane, client_id=client_id):
                continue
        except Exception:
            if bool(svc.get("v24_remote_service")) or str(sid).startswith("rs-"):
                continue
        enabled = bool(svc.get("enabled", True))
        local_ip = str(svc.get("local_ip") or "127.0.0.1")
        local_port = int(svc.get("local_port") or 0)
        remote_port = svc.get("remote_port")
        preset = str(svc.get("preset") or svc.get("service_type") or "tcp").lower()
        stype = preset if preset in ("ssh", "http", "https", "tcp") else "tcp"
        mode = "self"
        target_host = local_ip
        # Routed targets are explicit non-loopback destinations when marked.
        if str(svc.get("target_mode") or "").lower() == "routed":
            mode = "routed"
            target_host = str(svc.get("target_host") or local_ip)
        service_name = str(sid).strip().lower()
        plane.set_published_service(
            client_id,
            service_name,
            service_type=stype,
            target_mode=mode,
            target_host=target_host,
            target_port=local_port or (22 if stype == "ssh" else 0) or None,
            enabled=enabled,
            public_port=int(remote_port) if remote_port is not None else None,
            from_preset=preset if preset in ("ssh", "http", "https", "tcp") else None,
        )
        if not enabled:
            plane.set_published_service_enabled(client_id, service_name, False)
        pub = plane.conn.execute(
            "SELECT id, enabled, public_port FROM published_services "
            "WHERE client_id = ? AND name = ? AND released = 0",
            (client_id, service_name),
        ).fetchone()
        if pub is not None:
            meta = plane.conn.execute(
                "SELECT service_id FROM remote_service_meta WHERE service_id = ?",
                (pub["id"],),
            ).fetchone()
            if meta is None:
                pub_enabled = bool(pub["enabled"])
                plane.conn.execute(
                    "INSERT INTO remote_service_meta"
                    "(service_id, status, pool_class, destination_name, destination_client_id, "
                    "pending_allocation, delete_pending, reason) "
                    "VALUES (?, ?, 'normal', 'this-host', ?, ?, 0, ?)",
                    (
                        pub["id"],
                        "DISABLED" if not pub_enabled else "DEGRADED",
                        client_id,
                        0 if pub["public_port"] is not None else 1,
                        "" if not pub_enabled else "Runtime activation pending.",
                    ),
                )
                plane.commit_if_autonomous()
    return {"client_id": client_id, "services": len(services)}


class ControlPlaneCache:
    """Thread-safe ControlPlane handle with revision/generation fingerprinting."""

    def __init__(self, config_path: Path):
        self.config_path = Path(config_path)
        self.lock = threading.RLock()
        self.cfg: dict = {}
        self.plane: Optional[ControlPlane] = None
        self.load_error: Optional[str] = "not loaded"
        self.fingerprint: Optional[tuple] = None
        self.reload(force=True)

    def _fingerprint(self, plane: ControlPlane) -> tuple:
        st = plane.status()
        db = db_path(plane.root)
        try:
            stat = db.stat()
            db_fp = (stat.st_ino, stat.st_size, getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1e9)))
        except OSError:
            db_fp = (None, None, None)
        return (st.get("revision"), st.get("mismatch"), db_fp, str(db))

    def reload(self, force: bool = False) -> None:
        with self.lock:
            try:
                self.cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
            except Exception as exc:
                self.load_error = "config unreadable: %s" % exc
                self.plane = None
                return
            try:
                root = root_from_cfg(self.cfg)
                db = db_path(root)
                if not db.is_file():
                    if self.plane is not None:
                        try:
                            self.plane.close()
                        except Exception:
                            pass
                    self.load_error = "control DB missing"
                    self.plane = None
                    self.fingerprint = None
                    return
                if self.plane is None or force:
                    if self.plane is not None:
                        try:
                            self.plane.close()
                        except Exception:
                            pass
                    self.plane = open_plane(self.cfg, root=root)
                fp = self._fingerprint(self.plane)
                if not force and fp == self.fingerprint and self.load_error is None:
                    return
                st = self.plane.status()
                if not st.get("db_healthy"):
                    self.load_error = "control DB unhealthy"
                    self.fingerprint = fp
                    return
                if st.get("mismatch"):
                    self.load_error = "runtime generation mismatch"
                    self.fingerprint = fp
                    return
                self.fingerprint = fp
                self.load_error = None
            except (ControlPlaneError, SchemaTooNewError, DatabaseCorruptError) as exc:
                self.load_error = str(exc)
                self.plane = None
            except Exception as exc:
                self.load_error = str(exc)
                self.plane = None

    def snapshot(self) -> tuple[Optional[ControlPlane], Optional[str], dict]:
        with self.lock:
            self.reload(force=False)
            return self.plane, self.load_error, dict(self.cfg)

    def open_isolated(self) -> tuple[Optional[ControlPlane], Optional[str], dict]:
        """Open a request-private ControlPlane. The caller must close it.

        The cached connection is used only while self.lock is held. Threaded
        NewUserConn workers must not share that connection: SQLite raises
        InterfaceError / IndexError under concurrent use even when
        check_same_thread is false.
        """
        with self.lock:
            self.reload(force=False)
            cfg = dict(self.cfg)
            load_error = self.load_error
            root = self.plane.root if self.plane is not None else None
        if load_error is not None or root is None:
            return None, load_error or "control DB unavailable", cfg
        conn = None
        try:
            conn = connect(root=root, create=False)
            return ControlPlane(root, conn=conn), None, cfg
        except (ControlPlaneError, SchemaTooNewError, DatabaseCorruptError) as exc:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            return None, str(exc), cfg
        except Exception as exc:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            return None, str(exc), cfg
