#!/usr/bin/env python3
"""Agent Remote Service ↔ frpc runtime reconciler.

Desired Agent Remote Services are projected into client-state.json and
frpc.toml, preserving unrelated legacy proxies. HEALTHY requires a successful
runtime apply (unless DRLINK_SKIP_ACTIVATION is set for unit tests).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from drlink_control_db import ControlPlaneError, utc_now_iso

V24_SERVICE_PREFIX = "rs-"
SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")


def remote_service_proxy_id(name: str) -> str:
    """Stable frpc/client-state service id for a v2.4 Remote Service."""
    raw = re.sub(r"[^a-z0-9._-]+", "-", str(name or "").strip().lower()).strip("-._")
    if not raw:
        raw = "svc"
    candidate = (V24_SERVICE_PREFIX + raw)[:32]
    if not SERVICE_ID_RE.fullmatch(candidate):
        candidate = (V24_SERVICE_PREFIX + re.sub(r"[^a-z0-9]+", "", raw) + "x")[:32]
    return candidate


def runtime_should_apply() -> bool:
    return str(os.environ.get("DRLINK_SKIP_ACTIVATION") or "").strip().lower() not in (
        "1",
        "yes",
        "y",
        "true",
    )


def _base(root: Optional[str]) -> Path:
    return Path(root) if root else Path("/")


def _client_state_path(root: Optional[str] = None) -> Path:
    import drlink_v24 as v24

    for path in v24._agent_state_file_candidates(
        "etc/frp/client-state.json", "client-state.json", root
    ):
        if path.is_file():
            return path
    return _base(root) / "etc/frp/client-state.json"


def _frpc_toml_path(root: Optional[str] = None) -> Path:
    import drlink_v24 as v24

    for path in v24._agent_state_file_candidates("etc/frp/frpc.toml", "frpc.toml", root):
        if path.is_file():
            return path
    return _base(root) / "etc/frp/frpc.toml"


def load_client_state(root: Optional[str] = None) -> dict:
    path = _client_state_path(root)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _token_from_toml(path: Path) -> str:
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^\s*auth\.token\s*=\s*"(.*)"\s*$', line)
        if m:
            return m.group(1)
    return ""


def render_frpc_toml_text(
    *,
    server: str,
    server_port: int,
    token: str,
    host_id: str,
    services: dict,
    transport: str = "tcp",
    ca_file: str = "",
) -> str:
    transport = (transport or "tcp").strip().lower() or "tcp"
    lines = [
        'serverAddr = "%s"' % server,
        "serverPort = %s" % int(server_port),
        "",
        'auth.method = "token"',
        'auth.token = "%s"' % token,
        "",
        "transport.tls.enable = true",
    ]
    if transport == "wss":
        lines.extend(
            [
                'transport.protocol = "wss"',
                'transport.tls.trustedCaFile = "%s"' % ca_file,
            ]
        )
    for sid, item in sorted(services.items(), key=lambda kv: str(kv[0])):
        if not isinstance(item, dict):
            continue
        if item.get("enabled", True) is False:
            continue
        remote_port = item.get("remote_port")
        local_port = item.get("local_port")
        local_ip = item.get("local_ip") or "127.0.0.1"
        if remote_port is None or local_port is None:
            continue
        proxy_name = "%s-%s" % (host_id, item.get("id") or sid)
        lines.extend(
            [
                "",
                "[[proxies]]",
                'name = "%s"' % proxy_name,
                'type = "tcp"',
                'localIP = "%s"' % local_ip,
                "localPort = %s" % int(local_port),
                "remotePort = %s" % int(remote_port),
            ]
        )
    return "\n".join(lines) + "\n"


def validate_frpc_toml_text(text: str) -> None:
    if "serverAddr" not in text or "auth.token" not in text:
        raise ControlPlaneError("Generated frpc configuration is missing required fields")
    if "[[proxies]]" in text and "remotePort" not in text:
        raise ControlPlaneError("Generated frpc configuration has proxies without remotePort")


def build_desired_runtime_services(
    plane_db,
    state: dict,
    *,
    root: Optional[str] = None,
) -> dict:
    """Merge legacy client-state services with v2.4 Remote Services."""
    services = {}
    raw = state.get("services") if isinstance(state.get("services"), dict) else {}
    for sid, rec in raw.items():
        if not isinstance(rec, dict):
            continue
        sid_s = str(sid)
        # Drop prior v2.4 projections; rebuild from desired DB.
        if sid_s.startswith(V24_SERVICE_PREFIX) or rec.get("v24_remote_service"):
            continue
        services[sid_s] = dict(rec)
        services[sid_s]["id"] = services[sid_s].get("id") or sid_s

    rows = list(
        plane_db.conn.execute(
            "SELECT * FROM agent_remote_services WHERE delete_pending = 0 ORDER BY name"
        )
    )
    for row in rows:
        name = str(row["name"])
        proxy_id = remote_service_proxy_id(name)
        enabled = bool(row["enabled"]) and str(row["status"] or "") != "DISABLED"
        endpoint_port = row["endpoint_port"]
        reason = str(row["reason"] or "")
        # Dependency / offline pending → do not emit a live proxy.
        if not enabled:
            continue
        if endpoint_port is None or int(row["pending_allocation"] or 0):
            continue
        if "missing" in reason.lower() or "invalid" in reason.lower() or "udp" in reason.lower():
            continue
        # Resolve local target from desired row fields stored at set time via catalog.
        target_host = "127.0.0.1"
        target_port = None
        sobj = None
        try:
            import drlink_v24 as v24

            sobj = v24.get_service_object(plane_db, row["service_object"])
            if sobj is None:
                cat = plane_db.conn.execute(
                    "SELECT payload FROM agent_object_catalog WHERE kind='service-object' AND name=? COLLATE NOCASE",
                    (row["service_object"],),
                ).fetchone()
                if cat:
                    sobj = json.loads(cat["payload"])
            if sobj is not None:
                target_port = int(sobj["port"] if not isinstance(sobj, dict) else sobj.get("port"))
            dest = str(row["destination"] or "")
            identity = v24.load_agent_identity(root)
            host_name = identity.get("hostname") or identity.get("label") or ""
            if dest and host_name and dest.lower() != host_name.lower() and dest.lower() not in (
                "this-host",
                "this_host",
                "self",
            ):
                # Routed destination: local_ip is the destination address.
                obj = plane_db.get_object(dest) if hasattr(plane_db, "get_object") else None
                if obj and obj["type"] in ("host", "fqdn"):
                    vals = plane_db._object_values(obj["id"])
                    if vals:
                        target_host = vals[0]
                else:
                    cat = plane_db.conn.execute(
                        "SELECT payload FROM agent_object_catalog WHERE kind='network-object' AND name=? COLLATE NOCASE",
                        (dest,),
                    ).fetchone()
                    catalog_vals = []
                    if cat:
                        try:
                            payload = json.loads(cat["payload"] or "{}")
                        except (TypeError, ValueError):
                            payload = {}
                        catalog_vals = [str(v) for v in (payload.get("values") or []) if v not in (None, "")]
                    if catalog_vals:
                        target_host = catalog_vals[0]
                    else:
                        target_host = dest
        except Exception:
            pass
        if target_port is None:
            continue
        services[proxy_id] = {
            "id": proxy_id,
            "name": name,
            "preset": "custom",
            "protocol": "tcp",
            "local_ip": target_host,
            "local_port": int(target_port),
            "remote_port": int(endpoint_port),
            "enabled": True,
            "v24_remote_service": True,
            "pool_class": row["pool_class"] or "normal",
        }
    return services


def _restart_frpc(root: Optional[str] = None) -> None:
    if str(os.environ.get("FRP_SKIP_SYSTEMD") or "").strip() == "1":
        return
    if root and str(root).rstrip("/") not in ("", "/"):
        # Disposable test root — do not touch host systemd.
        return
    if str(os.environ.get("DRLINK_FAULT_RUNTIME_RESTART") or "").strip().lower() in (
        "1",
        "yes",
        "y",
        "true",
    ):
        raise ControlPlaneError("frpc reload/restart failed (injected fault)")
    try:
        subprocess.run(
            ["systemctl", "restart", "drlink-client"],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        try:
            subprocess.run(
                ["launchctl", "kickstart", "-k", "system/com.datarelay.drlink.frpc"],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            return
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            raise ControlPlaneError("failed to restart macOS Agent runtime: %s" % detail) from exc
        return
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise ControlPlaneError("failed to restart drlink-client: %s" % detail) from exc


def verify_runtime_proxies(
    *,
    root: Optional[str],
    host_id: str,
    expected: dict,
    toml_text: str,
) -> None:
    if str(os.environ.get("DRLINK_FAULT_RUNTIME_VERIFY") or "").strip().lower() in (
        "1",
        "yes",
        "y",
        "true",
    ):
        raise ControlPlaneError("runtime activation could not be verified")
    v24_names = []
    for sid, rec in expected.items():
        if not isinstance(rec, dict) or rec.get("enabled", True) is False:
            continue
        if not rec.get("v24_remote_service"):
            continue
        proxy_name = "%s-%s" % (host_id, rec.get("id") or sid)
        v24_names.append((proxy_name, int(rec["remote_port"])))
        needle_name = 'name = "%s"' % proxy_name
        needle_port = "remotePort = %s" % int(rec["remote_port"])
        if needle_name not in toml_text or needle_port not in toml_text:
            raise ControlPlaneError(
                "runtime activation could not be verified for proxy '%s'" % proxy_name
            )
    # On a real Agent, confirm frpc did not report start errors for these proxies.
    if (not root or str(root).rstrip("/") in ("", "/")) and v24_names:
        import time

        time.sleep(1.5)
        try:
            out = subprocess.check_output(
                [
                    "journalctl",
                    "-u",
                    "drlink-client",
                    "--since",
                    "90 seconds ago",
                    "--no-pager",
                ],
                text=True,
                timeout=15,
            )
        except Exception:
            out = ""
        for proxy_name, _port in v24_names:
            mentions = [ln for ln in out.splitlines() if proxy_name in ln]
            if not mentions:
                continue
            recent = mentions[-8:]
            if any("start error" in m.lower() for m in recent) and not any(
                "start proxy success" in m.lower() for m in recent
            ):
                raise ControlPlaneError(
                    "runtime activation could not be verified for proxy '%s'"
                    % proxy_name
                )


def apply_agent_runtime(
    plane_db,
    *,
    root: Optional[str] = None,
    names: Optional[list] = None,
) -> dict:
    """Render + apply frpc runtime for desired Remote Services.

    Returns {ok, applied, removed, error, generation}.
    """
    if not runtime_should_apply():
        return {"ok": True, "skipped": True, "applied": [], "removed": [], "generation": 0}

    state = load_client_state(root)
    if not state:
        return {
            "ok": False,
            "applied": [],
            "removed": [],
            "error": "client-state.json is missing; cannot apply Remote Service runtime",
            "generation": 0,
        }

    prev_toml = _frpc_toml_path(root)
    prev_state_path = _client_state_path(root)
    backup_toml = None
    backup_state = None
    try:
        if prev_toml.is_file():
            backup_toml = prev_toml.read_text(encoding="utf-8")
        if prev_state_path.is_file():
            backup_state = prev_state_path.read_text(encoding="utf-8")
    except OSError:
        pass

    desired = build_desired_runtime_services(plane_db, state, root=root)
    if names is not None:
        want = {remote_service_proxy_id(n) for n in names}
        # Still keep legacy + selected; drop other v24 not in names only when names filter set
        # for full reconcile names is None.
        filtered = {}
        for sid, rec in desired.items():
            if not rec.get("v24_remote_service") or sid in want:
                filtered[sid] = rec
        desired = filtered

    host_id = str(state.get("host_id") or "").strip()
    if not host_id:
        machine_id = str(state.get("machine_id") or "")
        hostname = str(state.get("hostname") or "host")
        host_id = "%s-%s" % (hostname, machine_id[:8] if machine_id else "local")

    token = _token_from_toml(prev_toml)
    if not token:
        return {
            "ok": False,
            "applied": [],
            "removed": [],
            "error": "FRP token unavailable; cannot regenerate frpc.toml",
            "generation": 0,
        }

    server = str(state.get("frp_server") or "").strip()
    server_port = int(state.get("frp_server_port") or 0)
    transport = str(state.get("frp_transport") or "tcp").strip().lower() or "tcp"
    if not server or server_port < 1:
        return {
            "ok": False,
            "applied": [],
            "removed": [],
            "error": "frp server endpoint missing from client-state",
            "generation": 0,
        }

    new_state = dict(state)
    new_state["services"] = desired
    new_state["management_only"] = not any(
        isinstance(r, dict) and r.get("enabled", True) is not False for r in desired.values()
    )

    try:
        toml_text = render_frpc_toml_text(
            server=server,
            server_port=server_port,
            token=token,
            host_id=host_id,
            services=desired,
            transport=transport,
        )
        validate_frpc_toml_text(toml_text)
        if str(os.environ.get("DRLINK_FAULT_RUNTIME_CONFIG") or "").strip().lower() in (
            "1",
            "yes",
            "y",
            "true",
        ):
            raise ControlPlaneError("invalid generated runtime config (injected fault)")

        _atomic_write_json(prev_state_path, new_state)
        _atomic_write_text(prev_toml, toml_text)
        _restart_frpc(root)
        verify_runtime_proxies(root=root, host_id=host_id, expected=desired, toml_text=toml_text)
    except Exception as exc:
        # Rollback previous runtime artifacts when possible.
        try:
            if backup_state is not None:
                _atomic_write_text(prev_state_path, backup_state)
            if backup_toml is not None:
                _atomic_write_text(prev_toml, backup_toml)
                _restart_frpc(root)
        except Exception:
            pass
        return {
            "ok": False,
            "applied": [],
            "removed": [],
            "error": str(exc),
            "generation": 0,
        }

    applied = [
        sid
        for sid, rec in desired.items()
        if isinstance(rec, dict) and rec.get("v24_remote_service")
    ]
    generation = int(os.environ.get("DRLINK_RUNTIME_GENERATION") or 0) + 1
    return {
        "ok": True,
        "applied": applied,
        "removed": [],
        "error": "",
        "generation": generation,
        "host_id": host_id,
        "toml": str(prev_toml),
    }


def mark_runtime_status(plane_db, *, ok: bool, reason: str = "", generation: int = 0) -> None:
    now = utc_now_iso()
    if ok:
        # Only promote rows that were waiting on runtime (or already healthy).
        # Never overwrite destination-unreachable or other non-runtime DEGRADED reasons.
        plane_db.conn.execute(
            "UPDATE agent_remote_services SET status = 'HEALTHY', reason = '', updated_at = ? "
            "WHERE delete_pending = 0 AND endpoint_port IS NOT NULL AND pending_allocation = 0 "
            "AND enabled = 1 AND ("
            "  reason = '' OR lower(reason) LIKE 'runtime%' OR lower(reason) LIKE '%activation%'"
            ") AND lower(reason) NOT LIKE '%unreachable%'",
            (now,),
        )
    else:
        brief = reason or "Runtime activation pending or failed"
        if brief.startswith("ERROR:"):
            brief = brief.split("\n", 2)[0]
        plane_db.conn.execute(
            "UPDATE agent_remote_services SET status = CASE WHEN enabled = 0 THEN 'DISABLED' ELSE 'DEGRADED' END, "
            "reason = ?, updated_at = ? WHERE delete_pending = 0 AND enabled = 1 "
            "AND endpoint_port IS NOT NULL AND pending_allocation = 0",
            (brief[:500], now),
        )
    if not getattr(plane_db, "_batch_mode", False):
        commit = getattr(plane_db, "commit_if_autonomous", None)
        if callable(commit):
            commit()
        else:
            plane_db.conn.commit()


def remove_remote_service_from_runtime(
    plane_db,
    name: str,
    *,
    root: Optional[str] = None,
) -> dict:
    """Remove one Remote Service proxy and re-apply runtime."""
    # Desired row may already be deleted; temporarily ensure absence then reconcile.
    return apply_agent_runtime(plane_db, root=root)
