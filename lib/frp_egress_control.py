#!/usr/bin/env python3
"""Controlled Egress policy plane for Data Relay.

LEGACY/MIGRATION state previously: /var/lib/drlink/egress-control.json

Separate from inbound Access Control. Default DENY / fail-closed.
Agentless authorization is source IP/CIDR + FQDN:port allowlists.
"""
from __future__ import annotations

import fcntl
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Schema v3: protocol=http|https|tcp; tcp_relays for Fixed TCP Egress.
# Legacy v1 (port-only) migrates 80→http, 443→https; other ports fail closed.
# v2→v3 adds tcp_relays={} preserving all profile IDs/fields.
EGRESS_SCHEMA_VERSION = 3
EGRESS_SCHEMA_VERSION_V2 = 2
EGRESS_SCHEMA_VERSION_LEGACY = 1
DEFAULT_EGRESS_PATH = "/var/lib/drlink/egress-control.json"
DEFAULT_CONN_LOG_PATH = "/var/log/drlink/egress/connections.jsonl"
LEGACY_CONN_LOG_PATH = "/var/log/drlink/egress-conn.jsonl"

PROTOCOL_HTTP = "http"
PROTOCOL_HTTPS = "https"
PROTOCOL_TCP = "tcp"
VALID_PROTOCOLS = frozenset({PROTOCOL_HTTP, PROTOCOL_HTTPS, PROTOCOL_TCP})
VALID_HTTP_PROTOCOLS = frozenset({PROTOCOL_HTTP, PROTOCOL_HTTPS})

def _default_egress_listen_port() -> int:
    """Resolve the canonical default without requiring package imports.

    Installers and tests often load this file via importlib.util.spec_from_file_location,
    which does not put the sibling lib directory on sys.path.
    """
    try:
        from frp_infrastructure_ports import DEFAULT_EGRESS_LISTEN_PORT as port  # noqa: WPS433
        return int(port)
    except Exception:
        pass
    try:
        import importlib.util
        here = Path(__file__).resolve().parent
        path = here / "frp_infrastructure_ports.py"
        if path.is_file():
            spec = importlib.util.spec_from_file_location(
                "frp_infrastructure_ports", str(path)
            )
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return int(mod.DEFAULT_EGRESS_LISTEN_PORT)
    except Exception:
        pass
    return 6102


DEFAULT_LISTEN_ADDR = "0.0.0.0"
DEFAULT_LISTEN_PORT = _default_egress_listen_port()  # 6102 — outside published pool 6000-6098

PROFILE_ID_PREFIX = "egp_"
PROFILE_ID_HEX_LEN = 12
SOURCE_ID_PREFIX = "egs_"
DEST_ID_PREFIX = "egd_"
RELAY_ID_PREFIX = "etr_"
ENTRY_ID_HEX_LEN = 12

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"

REASON_PROFILE_MATCH = "PROFILE_MATCH"
REASON_NO_MATCHING_PROFILE = "NO_MATCHING_PROFILE"
REASON_SOURCE_NOT_ALLOWED = "SOURCE_NOT_ALLOWED"
REASON_DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
REASON_PROFILE_DISABLED = "PROFILE_DISABLED"
REASON_IP_LITERAL_DENIED = "IP_LITERAL_DENIED"
REASON_POLICY_INVALID = "POLICY_INVALID"
REASON_POLICY_MISSING = "POLICY_MISSING"
REASON_AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
REASON_UNSAFE_DESTINATION = "UNSAFE_DESTINATION"
REASON_DNS_FAILURE = "DNS_FAILURE"
REASON_DNS_UNSAFE = "DNS_UNSAFE"
REASON_MALFORMED_REQUEST = "MALFORMED_REQUEST"
REASON_TLS_SNI_MISMATCH = "TLS_SNI_MISMATCH"
REASON_TLS_CLIENT_HELLO_INVALID = "TLS_CLIENT_HELLO_INVALID"
REASON_POST_CONNECT_TLS_IDENTITY_DENY = "POST_CONNECT_TLS_IDENTITY_DENY"
REASON_PROTOCOL_NOT_ALLOWED = "PROTOCOL_NOT_ALLOWED"
REASON_POLICY_REVOKED = "POLICY_REVOKED"
REASON_RESOURCE_LIMIT = "RESOURCE_LIMIT"
REASON_CONNECT_FAILURE = "CONNECT_FAILURE"
REASON_CLIENT_CLOSED = "CLIENT_CLOSED"
REASON_UPSTREAM_CLOSED = "UPSTREAM_CLOSED"
REASON_IDLE_TIMEOUT = "IDLE_TIMEOUT"
REASON_POLICY_UNHEALTHY = "POLICY_UNHEALTHY"
REASON_RELAY_DISABLED = "RELAY_DISABLED"
REASON_RELAY_NOT_FOUND = "RELAY_NOT_FOUND"
REASON_RELAY_INCOMPLETE = "RELAY_INCOMPLETE"

# Audit outcome vocabulary (connection/session correlated; no payloads/secrets).
AUDIT_CONNECTED = "CONNECTED"
AUDIT_POLICY_DENY = "POLICY_DENY"
AUDIT_DNS_FAILURE = "DNS_FAILURE"
AUDIT_DNS_UNSAFE = "DNS_UNSAFE"
AUDIT_CONNECT_FAILURE = "CONNECT_FAILURE"
AUDIT_TLS_SNI_MISMATCH = "TLS_SNI_MISMATCH"
AUDIT_TLS_CLIENT_HELLO_INVALID = "TLS_CLIENT_HELLO_INVALID"
AUDIT_POST_CONNECT_TLS_IDENTITY_DENY = "POST_CONNECT_TLS_IDENTITY_DENY"
AUDIT_POLICY_REVOKED = "POLICY_REVOKED"
AUDIT_RESOURCE_LIMIT = "RESOURCE_LIMIT"
AUDIT_CLIENT_CLOSED = "CLIENT_CLOSED"
AUDIT_UPSTREAM_CLOSED = "UPSTREAM_CLOSED"
AUDIT_IDLE_TIMEOUT = "IDLE_TIMEOUT"

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DESCRIPTION_MAX_LEN = 1024
HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

CONN_LOG_MAX_BYTES = 5 * 1024 * 1024
CONN_LOG_KEEP = 5

# Destination categories blocked after DNS resolution (SSRF / pivot guard).
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # RFC6598 Shared Address Space / CGNAT (not is_private)
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


class EgressError(Exception):
    """User-facing egress-control error."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def deploy_root() -> str:
    return os.environ.get("FRP_DEPLOY_TEST_ROOT", "")


def _rooted(path: str | Path) -> Path:
    path = Path(path)
    root = deploy_root()
    if not root:
        return path
    text = str(path)
    if text.startswith("/"):
        return Path(root + text)
    return Path(root) / path


def egress_control_path(cfg: Optional[dict] = None) -> Path:
    configured = ""
    if isinstance(cfg, dict):
        configured = str(cfg.get("egress_control_file") or "").strip()
    if not configured:
        configured = os.environ.get("FRP_EGRESS_CONTROL_FILE", "") or DEFAULT_EGRESS_PATH
    return _rooted(configured)


def conn_log_path(cfg: Optional[dict] = None) -> Path:
    configured = ""
    if isinstance(cfg, dict):
        configured = str(cfg.get("egress_conn_log_file") or "").strip()
    if configured:
        return _rooted(configured)
    env = os.environ.get("FRP_EGRESS_CONN_LOG", "").strip()
    if env:
        return _rooted(env)
    path = _rooted(DEFAULT_CONN_LOG_PATH)
    # Default path: prefer new layout; fall back to legacy flat file when present.
    if not path.exists():
        legacy = _rooted(LEGACY_CONN_LOG_PATH)
        if legacy.is_file():
            return legacy
    return path


def listen_bind(cfg: Optional[dict] = None) -> tuple[str, int]:
    host = DEFAULT_LISTEN_ADDR
    port = DEFAULT_LISTEN_PORT
    if isinstance(cfg, dict):
        host = str(cfg.get("egress_listen_addr") or host).strip() or host
        raw_port = cfg.get("egress_listen_port")
        if raw_port is not None and str(raw_port).strip() != "":
            try:
                port = int(raw_port)
            except (TypeError, ValueError) as exc:
                raise EgressError("invalid egress_listen_port") from exc
    env_host = os.environ.get("FRP_EGRESS_LISTEN_ADDR", "").strip()
    env_port = os.environ.get("FRP_EGRESS_LISTEN_PORT", "").strip()
    if env_host:
        host = env_host
    if env_port:
        try:
            port = int(env_port)
        except ValueError as exc:
            raise EgressError("invalid FRP_EGRESS_LISTEN_PORT") from exc
    if port < 1 or port > 65535:
        raise EgressError("egress listen port out of range")
    return host, port


def egress_lock_path(path: Path) -> Path:
    return path.parent / (path.name + ".lock")


_LOCKS = None


def _locks():
    global _LOCKS
    if _LOCKS is None:
        existing = sys.modules.get("frp_control_locks")
        if existing is not None:
            _LOCKS = existing
        else:
            path = Path(__file__).resolve().parent / "frp_control_locks.py"
            spec = importlib.util.spec_from_file_location("frp_control_locks", str(path))
            mod = importlib.util.module_from_spec(spec)
            sys.modules["frp_control_locks"] = mod
            spec.loader.exec_module(mod)
            _LOCKS = mod
    return _LOCKS


def _control_state_mutation_lock(state_path):
    return _locks().mutation_lock(state_path=state_path)


def empty_egress_state() -> dict:
    return {
        "schema_version": EGRESS_SCHEMA_VERSION,
        "egress_profiles": {},
        "tcp_relays": {},
    }


def _egress_uid_gid():
    """Return (uid, gid) for drlink-egress when the account exists."""
    try:
        import pwd
        import grp
    except ImportError:
        return None, None
    try:
        uid = pwd.getpwnam("drlink-egress").pw_uid
    except KeyError:
        return None, None
    try:
        gid = grp.getgrnam("drlink-egress").gr_gid
    except KeyError:
        gid = None
    return uid, gid


def ensure_service_parent_traverse(paths: Optional[list] = None) -> list[str]:
    """Grant drlink-egress traverse-only access on shared runtime and log parents.

    Child mode cannot help when the parent is 0700. systemd
    RuntimeDirectoryMode=0700 also clears ACLs on /run/drlink. Mode 0710 with
    group drlink-egress is execute/traverse without listing. World execute
    (0755) is wider than this account needs. No-op unless running as root.
    """
    repaired: list[str] = []
    if os.geteuid() != 0:
        return repaired
    uid, gid = _egress_uid_gid()
    if uid is None or gid is None:
        return repaired
    if paths is None:
        test_root = os.environ.get("FRP_DEPLOY_TEST_ROOT") or os.environ.get("FRP_SERVER_TEST_ROOT") or ""
        if test_root:
            root = Path(test_root)
            parents = [root / "run/drlink", root / "var/log/drlink"]
        else:
            parents = [Path("/run/drlink"), Path("/var/log/drlink")]
    else:
        parents = [Path(p) for p in paths]
    for directory in parents:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            os.chown(directory, 0, gid)
            os.chmod(directory, 0o710)
            repaired.append(str(directory))
        except OSError as exc:
            sys.stderr.write(
                "[drlink-egress] parent traverse repair failed path=%s error=%s\n"
                % (directory, exc)
            )
            continue
        parent_name = directory.parent.name
        if parent_name == "log":
            child = directory / "egress"
            try:
                child.mkdir(parents=True, exist_ok=True)
                os.chown(child, 0, gid)
                os.chmod(child, 0o770)
            except OSError as exc:
                sys.stderr.write(
                    "[drlink-egress] log dir repair failed path=%s error=%s\n" % (child, exc)
                )
        elif parent_name == "run":
            child = directory / "egress"
            try:
                child.mkdir(parents=True, exist_ok=True)
                os.chown(child, uid, gid)
                os.chmod(child, 0o700)
            except OSError as exc:
                sys.stderr.write(
                    "[drlink-egress] runtime dir repair failed path=%s error=%s\n" % (child, exc)
                )
    return repaired


def _setfacl_user(path: Path, perms: str) -> bool:
    """Apply a named-user ACL for drlink-egress. Returns True on success."""
    try:
        import subprocess
    except ImportError:
        return False
    try:
        proc = subprocess.run(
            ["setfacl", "-m", "u:drlink-egress:%s" % perms, str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return proc.returncode == 0
    except OSError:
        return False


def reapply_egress_runtime_permissions(
    *,
    config_path: Optional[Path] = None,
    control_path: Optional[Path] = None,
    conn_log_path: Optional[Path] = None,
    control_db_path: Optional[Path] = None,
    parents: bool = True,
) -> None:
    """Re-grant drlink-egress the minimum read/write surface after inode replace.

    Mirrors install-server.sh frp_server_ensure_sandbox_dirs file grants:
    prefer named-user ACL; else root:drlink-egress with 0640/0660.
    Never widens CA keys, FRP token, or enrollment secrets.

    Policy file is read-only for the egress service. Connection logging uses a
    service-owned writable subdirectory (``/var/log/drlink/egress``) so rotation
    (rename/unlink/create) works while the shared parent stays traverse-only.
    """
    if os.geteuid() != 0:
        return
    uid, gid = _egress_uid_gid()
    if uid is None:
        return

    etc_proj = Path("/etc/drlink")
    var_lib = Path("/var/lib/drlink")
    var_log = Path("/var/log/drlink")
    run_dir = Path("/run/drlink")
    test_root = os.environ.get("FRP_DEPLOY_TEST_ROOT") or os.environ.get("FRP_SERVER_TEST_ROOT") or ""
    if test_root:
        root = Path(test_root)
        etc_proj = root / "etc/drlink"
        var_lib = root / "var/lib/drlink"
        var_log = root / "var/log/drlink"
        run_dir = root / "run/drlink"

    egress_log_dir = var_log / "egress"
    try:
        egress_log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    if config_path is None:
        config_path = etc_proj / "config.json"
    else:
        config_path = Path(config_path)
    if control_path is None:
        control_path = var_lib / "egress-control.json"
    else:
        control_path = Path(control_path)
    if control_db_path is None:
        control_db_path = var_lib / "drlink.db"
    else:
        control_db_path = Path(control_db_path)
    runtime_dir = var_lib / "runtime"
    if conn_log_path is None:
        conn_log_path = egress_log_dir / "connections.jsonl"
    else:
        conn_log_path = Path(conn_log_path)
        # When a custom log path is under .../egress/, treat that dir as the
        # writable service log directory.
        if conn_log_path.parent.name == "egress":
            egress_log_dir = conn_log_path.parent
            try:
                egress_log_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass

    parent_dirs = []
    if parents:
        for directory in (etc_proj, var_lib, var_log, run_dir):
            if directory.is_dir():
                parent_dirs.append(directory)

    def _acl_grant_file(path: Path, perms: str) -> bool:
        try:
            os.chown(path, 0, 0)
        except OSError:
            pass
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return _setfacl_user(path, perms)

    # Probe ACL support on a real path (parent or target file).
    probe = None
    if parent_dirs:
        probe = parent_dirs[0]
    elif control_path.is_file():
        probe = control_path
    elif config_path.is_file():
        probe = config_path
    elif egress_log_dir.is_dir():
        probe = egress_log_dir
    elif conn_log_path.is_file():
        probe = conn_log_path
    if probe is not None and _setfacl_user(probe, "--x" if probe in parent_dirs else "r--"):
        if probe in parent_dirs:
            for directory in parent_dirs:
                if directory is not probe:
                    _setfacl_user(directory, "--x")
        if egress_log_dir.is_dir():
            # Writable service log dir (rotation needs rename/unlink/create).
            _setfacl_user(egress_log_dir, "rwx")
        if config_path.is_file():
            _acl_grant_file(config_path, "r--")
        if control_path.is_file():
            # Least privilege: egress gateway only reads policy.
            _acl_grant_file(control_path, "r--")
        # SQLite SSOT + sidecars + derived runtime artifacts.
        for path in (
            control_db_path,
            Path(str(control_db_path) + "-wal"),
            Path(str(control_db_path) + "-shm"),
        ):
            if path.is_file():
                _acl_grant_file(path, "r--")
        if runtime_dir.is_dir():
            _setfacl_user(runtime_dir, "r-x")
            for child in runtime_dir.rglob("*"):
                if child.is_file():
                    _acl_grant_file(child, "r--")
                elif child.is_dir():
                    _setfacl_user(child, "r-x")
        if conn_log_path.parent.is_dir():
            try:
                conn_log_path.touch(exist_ok=True)
            except OSError:
                pass
            if conn_log_path.is_file():
                _acl_grant_file(conn_log_path, "rw-")
        return

    if gid is None:
        return
    # Group fallback when setfacl is unavailable.
    for directory in parent_dirs:
        try:
            os.chown(directory, 0, gid)
            os.chmod(directory, 0o710)
        except OSError:
            pass
    if egress_log_dir.is_dir():
        try:
            os.chown(egress_log_dir, 0, gid)
            os.chmod(egress_log_dir, 0o770)
        except OSError:
            pass
    if config_path.is_file():
        try:
            os.chown(config_path, 0, gid)
            os.chmod(config_path, 0o640)
        except OSError:
            pass
    if control_path.is_file():
        try:
            os.chown(control_path, 0, gid)
            os.chmod(control_path, 0o640)
        except OSError:
            pass
    for path in (
        control_db_path,
        Path(str(control_db_path) + "-wal"),
        Path(str(control_db_path) + "-shm"),
    ):
        if path.is_file():
            try:
                os.chown(path, 0, gid)
                os.chmod(path, 0o640)
            except OSError:
                pass
    if runtime_dir.is_dir():
        try:
            os.chown(runtime_dir, 0, gid)
            os.chmod(runtime_dir, 0o750)
        except OSError:
            pass
        for child in runtime_dir.rglob("*"):
            try:
                if child.is_dir():
                    os.chown(child, 0, gid)
                    os.chmod(child, 0o750)
                elif child.is_file():
                    os.chown(child, 0, gid)
                    os.chmod(child, 0o640)
            except OSError:
                pass
    if conn_log_path.parent.is_dir():
        try:
            conn_log_path.touch(exist_ok=True)
            os.chown(conn_log_path, 0, gid)
            os.chmod(conn_log_path, 0o660)
        except OSError:
            pass


def atomic_write_json(path: Path, data: dict, mode: int = 0o600) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        # Inode replacement drops ACLs/group mode. Re-grant egress access for
        # the runtime policy file without widening secret material.
        try:
            if path.name == "egress-control.json" or str(path).endswith("/egress-control.json"):
                reapply_egress_runtime_permissions(control_path=path, parents=True)
            else:
                # Do not chmod parent to 0700 — that clears group-x / ACL mask.
                pass
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


class FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def _new_id(prefix: str) -> str:
    return prefix + secrets.token_hex(ENTRY_ID_HEX_LEN // 2)


_SOURCE_ID_RE = re.compile(r"^%s[0-9a-f]{%d}$" % (re.escape(SOURCE_ID_PREFIX), ENTRY_ID_HEX_LEN))
_DEST_ID_RE = re.compile(r"^%s[0-9a-f]{%d}$" % (re.escape(DEST_ID_PREFIX), ENTRY_ID_HEX_LEN))


def _canonical_entry_id(value, prefix: str) -> str:
    if not isinstance(value, str) or not value:
        raise EgressError("invalid %s entry id" % ("source" if prefix == SOURCE_ID_PREFIX else "destination"))
    if prefix == SOURCE_ID_PREFIX:
        if not _SOURCE_ID_RE.match(value):
            raise EgressError("malformed source entry id: %s" % value)
    elif prefix == DEST_ID_PREFIX:
        if not _DEST_ID_RE.match(value):
            raise EgressError("malformed destination entry id: %s" % value)
    else:
        raise EgressError("invalid entry id prefix")
    return value


def _is_canonical_entry_id(value, prefix: str) -> bool:
    try:
        _canonical_entry_id(value, prefix)
        return True
    except EgressError:
        return False


def _ensure_legacy_entry_id(entry: dict, prefix: str, seen: set[str]) -> None:
    """Preserve valid IDs; generate only on the legacy v1 migration path."""
    current = entry.get("id")
    if _is_canonical_entry_id(current, prefix) and current not in seen:
        seen.add(current)
        return
    new_id = _new_id(prefix)
    while new_id in seen:
        new_id = _new_id(prefix)
    entry["id"] = new_id
    seen.add(new_id)


def _regenerate_entry_ids(profile: dict) -> None:
    """Untrusted/imported identity must not become an unsafe selector."""
    sources = profile.get("sources") or []
    dests = profile.get("destinations") or []
    if isinstance(sources, list):
        profile["sources"] = [dict(src) if isinstance(src, dict) else src for src in sources]
        for src in profile["sources"]:
            if isinstance(src, dict):
                src["id"] = _new_id(SOURCE_ID_PREFIX)
    if isinstance(dests, list):
        profile["destinations"] = [dict(dest) if isinstance(dest, dict) else dest for dest in dests]
        for dest in profile["destinations"]:
            if isinstance(dest, dict):
                dest["id"] = _new_id(DEST_ID_PREFIX)


def validate_profile_name(name: str) -> str:
    text = str(name or "").strip()
    if not text or not NAME_RE.match(text):
        raise EgressError(
            "invalid egress profile name (1-64 chars; letters, digits, ._- "
            "starting with alphanumeric)"
        )
    return text


def canonicalize_cidr(source: str) -> str:
    text = str(source or "").strip()
    if not text:
        raise EgressError("source CIDR/address is required")
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
        else:
            addr = ipaddress.ip_address(text)
            if isinstance(addr, ipaddress.IPv4Address):
                net = ipaddress.ip_network("%s/32" % addr.compressed, strict=False)
            else:
                net = ipaddress.ip_network("%s/128" % addr.compressed, strict=False)
    except ValueError as exc:
        raise EgressError("invalid IP/CIDR: %s" % source) from exc
    return net.with_prefixlen


def validate_port(port: Any) -> int:
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise EgressError("invalid destination port: %s" % port) from exc
    if value < 1 or value > 65535:
        raise EgressError("destination port out of range: %s" % port)
    return value


def _has_control_chars(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def validate_protocol(protocol: Any) -> str:
    text = str(protocol or "").strip().lower()
    if text not in VALID_PROTOCOLS:
        raise EgressError(
            "destination protocol must be http, https, or tcp (got %r)" % protocol
        )
    return text


def validate_http_protocol(protocol: Any) -> str:
    text = validate_protocol(protocol)
    if text not in VALID_HTTP_PROTOCOLS:
        raise EgressError("HTTP gateway protocol must be http or https (got %r)" % protocol)
    return text


def infer_legacy_protocol(port: int) -> str:
    """Safe legacy v1 inference only. Ambiguous ports must fail closed."""
    if port == 80:
        return PROTOCOL_HTTP
    if port == 443:
        return PROTOCOL_HTTPS
    raise EgressError(
        "legacy destination port %s requires explicit protocol migration "
        "(only :80→http and :443→https are auto-migrated)" % port
    )


def _load_psl_module():
    try:
        from frp_public_suffix import (  # noqa: WPS433
            assert_wildcard_public_suffix_safe,
            is_public_suffix,
            psl_metadata,
            load_psl,
        )
        return assert_wildcard_public_suffix_safe, is_public_suffix, psl_metadata, load_psl
    except Exception:
        import importlib.util

        here = Path(__file__).resolve().parent
        path = here / "frp_public_suffix.py"
        if not path.is_file():
            raise EgressError("Public Suffix List helper missing")
        spec = importlib.util.spec_from_file_location("frp_public_suffix", str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return (
            mod.assert_wildcard_public_suffix_safe,
            mod.is_public_suffix,
            mod.psl_metadata,
            mod.load_psl,
        )


def validate_wildcard_public_suffix(policy_host: str) -> None:
    """Reject *.com / *.co.uk / other public-suffix wildcards at policy write/load."""
    assert_safe, _is_ps, _meta, _load = _load_psl_module()
    try:
        _load()
        assert_safe(policy_host)
    except FileNotFoundError as exc:
        raise EgressError(str(exc)) from exc
    except ValueError as exc:
        raise EgressError(str(exc)) from exc


def public_suffix_info() -> dict:
    try:
        _assert, _is_ps, meta, load = _load_psl_module()
        load()
        return meta()
    except Exception as exc:
        return {"error": str(exc)}


def canonicalize_hostname(host: str, *, allow_wildcard: bool = True) -> tuple[str, str]:
    """Return (canonical_ascii_hostname, match_mode).

    match_mode is 'exact' or 'wildcard'.
    Wildcard form is strictly '*.label.label' (single leading '*.' only).
    Rejects trailing-dot ambiguity after strip, empty labels, IP literals,
    userinfo, ports, whitespace, and control characters.

    Wildcard apex non-match: *.example.com never matches example.com itself.
    Public-suffix wildcards (*.com, *.co.uk, …) are rejected when allow_wildcard.
    """
    raw = str(host or "")
    if not raw or _has_control_chars(raw) or any(ch.isspace() for ch in raw):
        raise EgressError("invalid hostname")
    text = raw.strip().lower()
    if text != raw.strip().lower() or text != text.strip():
        raise EgressError("invalid hostname")
    # Trailing dot: strip once for DNS absolute form, then require no further dots at end.
    if text.endswith("."):
        text = text[:-1]
        if not text or text.endswith("."):
            raise EgressError("invalid hostname")
    if not text or "/" in text or "@" in text or "\\" in text or "?" in text or "#" in text:
        raise EgressError("invalid hostname")
    if ":" in text:
        # Port must not be embedded in hostname field.
        raise EgressError("hostname must not include a port")

    match_mode = "exact"
    if text.startswith("*."):
        if not allow_wildcard:
            raise EgressError("wildcard hostnames are not allowed here")
        if text.count("*") != 1:
            raise EgressError("invalid wildcard hostname")
        suffix = text[2:]
        if not suffix or "*" in suffix or suffix.startswith("."):
            raise EgressError("invalid wildcard hostname")
        match_mode = "wildcard"
        ascii_host = _to_idna_ascii(suffix)
        canon = "*." + ascii_host
        validate_wildcard_public_suffix(canon)
        return canon, match_mode

    if "*" in text:
        raise EgressError("invalid hostname")

    # Reject IP literals in FQDN policy fields.
    try:
        ipaddress.ip_address(text)
        raise EgressError("IP literal destinations are not allowed in FQDN policy")
    except ValueError:
        pass
    if text.startswith("[") and text.endswith("]"):
        raise EgressError("IP literal destinations are not allowed in FQDN policy")

    ascii_host = _to_idna_ascii(text)
    return ascii_host, match_mode


def hostname_matches(request_host: str, policy_host: str, match_mode: str) -> bool:
    """Strict wildcard: *.example.com matches a.example.com and a.b.example.com,
    but never example.com itself, evil-example.com, or example.com.evil.org.
    """
    try:
        req, _ = canonicalize_hostname(request_host, allow_wildcard=False)
    except EgressError:
        return False
    pol = str(policy_host or "").lower().strip()
    mode = str(match_mode or "exact").lower()
    if mode == "exact":
        return req == pol
    if mode == "wildcard":
        if not pol.startswith("*."):
            return False
        suffix = pol[2:]
        if not suffix:
            return False
        return req.endswith("." + suffix)
    return False


def _to_idna_ascii(hostname: str) -> str:
    labels = hostname.split(".")
    if not labels or any(label == "" for label in labels):
        raise EgressError("invalid hostname")
    if len(hostname) > 253:
        raise EgressError("hostname too long")
    out = []
    for label in labels:
        if len(label) > 63:
            raise EgressError("invalid hostname label")
        try:
            # stdlib codec — no third-party idna dependency
            encoded = label.encode("idna").decode("ascii").lower()
        except Exception as exc:
            raise EgressError("invalid hostname (IDNA): %s" % hostname) from exc
        if not HOSTNAME_LABEL_RE.match(encoded):
            raise EgressError("invalid hostname label: %s" % label)
        out.append(encoded)
    return ".".join(out)


def is_unsafe_destination_ip(addr: ipaddress._BaseAddress) -> bool:
    """Return True if connecting to this IP would be SSRF/pivot risk."""
    if addr.is_unspecified or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_multicast or addr.is_reserved or addr.is_private:
        return True
    # is_private covers RFC1918 and ULA; still check explicit block list for docs/special.
    for net in _BLOCKED_NETWORKS:
        try:
            if addr in net:
                return True
        except TypeError:
            continue
    # Cloud metadata IPv4 is already in 169.254.0.0/16; keep explicit for clarity.
    if str(addr) == "169.254.169.254":
        return True
    return False


def validate_resolved_addresses(addresses: list[str]) -> list[str]:
    """Validate every candidate IP. Fail closed if any candidate is unsafe or invalid.

    Returns compressed validated addresses (all must be safe).
    """
    if not addresses:
        raise EgressError("DNS resolution returned no addresses")
    validated: list[str] = []
    for item in addresses:
        try:
            addr = ipaddress.ip_address(str(item).strip())
        except ValueError as exc:
            raise EgressError("invalid resolved address: %s" % item) from exc
        if is_unsafe_destination_ip(addr):
            raise EgressError("unsafe destination address: %s" % addr.compressed)
        validated.append(addr.compressed)
    return validated


def parse_authority_host_port(authority: str, *, default_port: Optional[int] = None) -> tuple[str, int]:
    """Parse CONNECT host:port or absolute-URI authority. Fail closed on ambiguity."""
    text = str(authority or "")
    if not text or _has_control_chars(text) or any(ch.isspace() for ch in text):
        raise EgressError("malformed authority")
    if "@" in text:
        raise EgressError("userinfo is not allowed in authority")
    host = ""
    port_text = ""
    if text.startswith("["):
        end = text.find("]")
        if end <= 1:
            raise EgressError("malformed IPv6 authority")
        host = text[1:end]
        rest = text[end + 1 :]
        if rest:
            if not rest.startswith(":") or rest == ":":
                raise EgressError("malformed IPv6 authority")
            port_text = rest[1:]
        elif default_port is None:
            raise EgressError("missing port")
    else:
        if text.count(":") > 1:
            # Ambiguous bare IPv6 without brackets — reject.
            raise EgressError("malformed authority")
        if ":" in text:
            host, port_text = text.rsplit(":", 1)
        else:
            host = text
            if default_port is None:
                raise EgressError("missing port")
    if not host:
        raise EgressError("missing hostname")
    if port_text == "" and default_port is not None:
        port = default_port
    else:
        if not port_text.isdigit() or port_text != str(int(port_text)):
            # Reject leading zeros tricks / overflow / non-decimal.
            if not port_text.isdigit():
                raise EgressError("invalid port")
            # Allow canonical decimal without leading zeros except "0" which is invalid port anyway.
            if len(port_text) > 1 and port_text.startswith("0"):
                raise EgressError("invalid port")
            try:
                port = int(port_text)
            except ValueError as exc:
                raise EgressError("invalid port") from exc
        else:
            if len(port_text) > 1 and port_text.startswith("0"):
                raise EgressError("invalid port")
            port = int(port_text)
    if port < 1 or port > 65535:
        raise EgressError("port out of range")
    # IP literals are parseable; canonical Internet Access policy + safety checks
    # decide whether a literal may proceed (never via implicit FQDN inheritance).
    try:
        return ipaddress.ip_address(host).compressed, port
    except ValueError:
        pass
    canon, _ = canonicalize_hostname(host, allow_wildcard=False)
    return canon, port


def normalize_authority_host(host: str) -> str:
    """Return compressed IP or canonical ASCII hostname for an authority host token."""
    text = str(host or "").strip()
    if not text:
        raise EgressError("missing hostname")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        pass
    canon, _ = canonicalize_hostname(text, allow_wildcard=False)
    return canon


def migrate_egress_state_v1_to_v2(raw: dict) -> dict:
    """Deterministic v1→v2 migration. Ambiguous ports fail closed."""
    if not isinstance(raw, dict):
        raise EgressError("egress-control.json must be a JSON object")
    profiles_in = raw.get("egress_profiles")
    if not isinstance(profiles_in, dict):
        raise EgressError("egress_profiles must be an object")
    profiles_out: dict = {}
    for pid, profile in profiles_in.items():
        if not isinstance(profile, dict):
            raise EgressError("invalid egress profile record: %s" % pid)
        dests_in = profile.get("destinations")
        if not isinstance(dests_in, list):
            raise EgressError("egress profile destinations must be a list: %s" % pid)
        dests_out = []
        for dest in dests_in:
            if not isinstance(dest, dict):
                raise EgressError("invalid destination entry in %s" % pid)
            if "protocol" in dest and dest.get("protocol") not in (None, ""):
                proto = validate_protocol(dest.get("protocol"))
                if proto == PROTOCOL_TCP:
                    raise EgressError(
                        "legacy v1 migration cannot introduce protocol=tcp "
                        "(upgrade to v2 first, then add tcp destinations)"
                    )
                proto = validate_http_protocol(proto)
            else:
                port = validate_port(dest.get("port"))
                proto = infer_legacy_protocol(port)
            entry = dict(dest)
            entry["protocol"] = proto
            dests_out.append(entry)
        sources_in = profile.get("sources")
        if sources_in is None:
            sources_out = []
        elif not isinstance(sources_in, list):
            raise EgressError("egress profile sources must be a list: %s" % pid)
        else:
            sources_out = [dict(src) if isinstance(src, dict) else src for src in sources_in]
        seen_src: set[str] = set()
        for src in sources_out:
            if isinstance(src, dict):
                _ensure_legacy_entry_id(src, SOURCE_ID_PREFIX, seen_src)
        seen_dest: set[str] = set()
        for dest in dests_out:
            _ensure_legacy_entry_id(dest, DEST_ID_PREFIX, seen_dest)
        new_profile = dict(profile)
        new_profile["destinations"] = dests_out
        new_profile["sources"] = sources_out
        profiles_out[pid] = new_profile
    return {
        "schema_version": EGRESS_SCHEMA_VERSION_V2,
        "egress_profiles": profiles_out,
    }


def migrate_egress_state_v2_to_v3(raw: dict) -> dict:
    """Deterministic v2→v3 migration: add tcp_relays={} preserving profiles."""
    if not isinstance(raw, dict):
        raise EgressError("egress-control.json must be a JSON object")
    version = raw.get("schema_version")
    if version != EGRESS_SCHEMA_VERSION_V2:
        raise EgressError("migrate_egress_state_v2_to_v3 requires schema_version=2")
    profiles = raw.get("egress_profiles")
    if not isinstance(profiles, dict):
        raise EgressError("egress_profiles must be an object")
    relays_in = raw.get("tcp_relays")
    if relays_in is None:
        relays_out: dict = {}
    elif isinstance(relays_in, dict):
        # Ambiguous: v2 must not already carry tcp_relays with data.
        if relays_in:
            raise EgressError(
                "schema_version=2 state must not define non-empty tcp_relays "
                "(ambiguous; refuse migration)"
            )
        relays_out = {}
    else:
        raise EgressError("tcp_relays must be an object when present")
    # Deep-copy profiles so IDs/fields are preserved without aliasing.
    profiles_out = json.loads(json.dumps(profiles))
    return {
        "schema_version": EGRESS_SCHEMA_VERSION,
        "egress_profiles": profiles_out,
        "tcp_relays": relays_out,
    }


def migrate_egress_state_to_current(raw: dict) -> dict:
    """Migrate any supported legacy schema to current. Corruption fails closed."""
    if not isinstance(raw, dict):
        raise EgressError("egress-control.json must be a JSON object")
    version = raw.get("schema_version")
    if version == EGRESS_SCHEMA_VERSION:
        return {
            "schema_version": EGRESS_SCHEMA_VERSION,
            "egress_profiles": raw.get("egress_profiles"),
            "tcp_relays": raw.get("tcp_relays") if "tcp_relays" in raw else {},
        }
    if version == EGRESS_SCHEMA_VERSION_V2:
        return migrate_egress_state_v2_to_v3(raw)
    if version == EGRESS_SCHEMA_VERSION_LEGACY:
        return migrate_egress_state_v2_to_v3(migrate_egress_state_v1_to_v2(raw))
    raise EgressError("unsupported egress-control schema_version: %s" % version)


def _parse_egress_state(raw: object, *, migrate: bool = True) -> dict:
    if not isinstance(raw, dict):
        raise EgressError("egress-control.json must be a JSON object")
    version = raw.get("schema_version")
    if version == EGRESS_SCHEMA_VERSION:
        profiles = raw.get("egress_profiles")
        if not isinstance(profiles, dict):
            raise EgressError("egress_profiles must be an object")
        relays = raw.get("tcp_relays")
        if relays is None:
            relays = {}
        if not isinstance(relays, dict):
            raise EgressError("tcp_relays must be an object")
        return {
            "schema_version": EGRESS_SCHEMA_VERSION,
            "egress_profiles": profiles,
            "tcp_relays": relays,
        }
    if version in (EGRESS_SCHEMA_VERSION_LEGACY, EGRESS_SCHEMA_VERSION_V2):
        if not migrate:
            raise EgressError("unsupported egress-control schema_version: %s" % version)
        return migrate_egress_state_to_current(raw)
    raise EgressError("unsupported egress-control schema_version: %s" % version)


def validate_egress_state(state: dict) -> None:
    if not isinstance(state, dict):
        raise EgressError("invalid egress state")
    if state.get("schema_version") != EGRESS_SCHEMA_VERSION:
        raise EgressError("unsupported egress-control schema_version")
    profiles = state.get("egress_profiles")
    if not isinstance(profiles, dict):
        raise EgressError("egress_profiles must be an object")
    relays = state.get("tcp_relays")
    if relays is None:
        state["tcp_relays"] = {}
        relays = state["tcp_relays"]
    if not isinstance(relays, dict):
        raise EgressError("tcp_relays must be an object")
    # Ensure PSL is available before accepting wildcards.
    try:
        validate_wildcard_public_suffix("*.example.com")
    except EgressError as exc:
        if "Public Suffix List missing" in str(exc):
            raise
    names: dict[str, str] = {}
    for pid, profile in profiles.items():
        if not isinstance(pid, str) or not pid.startswith(PROFILE_ID_PREFIX):
            raise EgressError("invalid egress profile id: %s" % pid)
        if not isinstance(profile, dict):
            raise EgressError("invalid egress profile record: %s" % pid)
        if profile.get("id") != pid:
            raise EgressError("egress profile id mismatch: %s" % pid)
        name = validate_profile_name(profile.get("name") or "")
        key = name.lower()
        if key in names:
            raise EgressError("duplicate egress profile name: %s" % name)
        names[key] = pid
        if "enabled" not in profile or not isinstance(profile.get("enabled"), bool):
            raise EgressError("egress profile enabled must be boolean: %s" % pid)
        desc = profile.get("description") or ""
        if not isinstance(desc, str) or len(desc) > DESCRIPTION_MAX_LEN:
            raise EgressError("invalid egress profile description: %s" % pid)
        sources = profile.get("sources")
        destinations = profile.get("destinations")
        if not isinstance(sources, list) or not isinstance(destinations, list):
            raise EgressError("egress profile sources/destinations must be lists: %s" % pid)
        seen_cidrs: set[str] = set()
        seen_source_ids: set[str] = set()
        for src in sources:
            if not isinstance(src, dict):
                raise EgressError("invalid source entry in %s" % pid)
            if "id" not in src:
                raise EgressError("source entry is missing id in %s" % pid)
            sid = _canonical_entry_id(src.get("id"), SOURCE_ID_PREFIX)
            if sid in seen_source_ids:
                raise EgressError("duplicate source entry id in %s: %s" % (pid, sid))
            seen_source_ids.add(sid)
            cidr = canonicalize_cidr(src.get("cidr") or "")
            if cidr in seen_cidrs:
                raise EgressError("duplicate source CIDR in %s: %s" % (pid, cidr))
            seen_cidrs.add(cidr)
        seen_dests: set[tuple[str, int, str, str]] = set()
        seen_dest_ids: set[str] = set()
        for dest in destinations:
            if not isinstance(dest, dict):
                raise EgressError("invalid destination entry in %s" % pid)
            if "id" not in dest:
                raise EgressError("destination entry is missing id in %s" % pid)
            did = _canonical_entry_id(dest.get("id"), DEST_ID_PREFIX)
            if did in seen_dest_ids:
                raise EgressError("duplicate destination entry id in %s: %s" % (pid, did))
            seen_dest_ids.add(did)
            protocol = validate_protocol(dest.get("protocol"))
            allow_wild = protocol != PROTOCOL_TCP
            host, mode = canonicalize_hostname(
                dest.get("host") or "", allow_wildcard=allow_wild
            )
            if protocol == PROTOCOL_TCP and mode != "exact":
                raise EgressError(
                    "tcp destinations require exact FQDN match (no wildcard) in %s" % pid
                )
            port = validate_port(dest.get("port"))
            stored_mode = str(dest.get("match") or mode).lower()
            if stored_mode not in ("exact", "wildcard"):
                raise EgressError("invalid destination match mode in %s" % pid)
            if protocol == PROTOCOL_TCP and stored_mode != "exact":
                raise EgressError(
                    "tcp destinations require match=exact in %s" % pid
                )
            if stored_mode != mode:
                if mode == "wildcard" and stored_mode != "wildcard":
                    raise EgressError("wildcard host requires match=wildcard")
                if mode == "exact" and stored_mode == "wildcard":
                    raise EgressError("exact host cannot use match=wildcard")
            key = (host, port, stored_mode, protocol)
            if key in seen_dests:
                raise EgressError(
                    "duplicate destination in %s: %s:%s/%s" % (pid, host, port, protocol)
                )
            seen_dests.add(key)
            dest["host"] = host
            dest["port"] = port
            dest["match"] = stored_mode
            dest["protocol"] = protocol

    _validate_tcp_relays(state)


_RELAY_ID_RE = re.compile(r"^%s[0-9a-f]{%d}$" % (re.escape(RELAY_ID_PREFIX), ENTRY_ID_HEX_LEN))


def _canonical_relay_id(value) -> str:
    if not isinstance(value, str) or not _RELAY_ID_RE.match(value):
        raise EgressError("malformed tcp relay id: %s" % value)
    return value


def _validate_listen_addr(addr: str) -> str:
    """Accept only addresses RelayServer can bind.

    The Fixed TCP runtime is IPv4 (AF_INET). IPv6 literals, ``::``, and ``*``
    are rejected before policy mutation. There is no v2.4 contract for an
    IPv6 or symbolic wildcard listener.
    """
    text = str(addr or "").strip()
    if not text:
        raise EgressError("listen_addr is required")
    if _has_control_chars(text) or any(ch.isspace() for ch in text):
        raise EgressError("invalid listen_addr")
    if text == "0.0.0.0":
        return "0.0.0.0"
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as exc:
        raise EgressError(
            "unsupported listen_addr: %s (Fixed TCP accepts an IPv4 address or 0.0.0.0)"
            % addr
        ) from exc
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise EgressError(
            "unsupported listen_addr: %s (Fixed TCP accepts an IPv4 address or 0.0.0.0)"
            % addr
        )
    return parsed.compressed


def _validate_tcp_relays(state: dict) -> None:
    relays = state.get("tcp_relays") or {}
    profiles = state.get("egress_profiles") or {}
    if not isinstance(relays, dict):
        raise EgressError("tcp_relays must be an object")
    names: dict[str, str] = {}
    listen_keys: set[tuple[str, int]] = set()
    for rid, relay in relays.items():
        if not isinstance(rid, str) or not rid.startswith(RELAY_ID_PREFIX):
            raise EgressError("invalid tcp relay id: %s" % rid)
        if not isinstance(relay, dict):
            raise EgressError("invalid tcp relay record: %s" % rid)
        if relay.get("id") != rid:
            raise EgressError("tcp relay id mismatch: %s" % rid)
        _canonical_relay_id(rid)
        name = validate_profile_name(relay.get("name") or "")
        key = name.lower()
        if key in names:
            raise EgressError("duplicate tcp relay name: %s" % name)
        names[key] = rid
        if "enabled" not in relay or not isinstance(relay.get("enabled"), bool):
            raise EgressError("tcp relay enabled must be boolean: %s" % rid)
        profile_id = str(relay.get("profile_id") or "")
        destination_id = str(relay.get("destination_id") or "")
        if profile_id not in profiles:
            raise EgressError("tcp relay %s references missing profile %s" % (rid, profile_id))
        profile = profiles[profile_id]
        dest = None
        for entry in profile.get("destinations") or []:
            if isinstance(entry, dict) and entry.get("id") == destination_id:
                dest = entry
                break
        if dest is None:
            raise EgressError(
                "tcp relay %s references missing destination %s" % (rid, destination_id)
            )
        if validate_protocol(dest.get("protocol")) != PROTOCOL_TCP:
            raise EgressError(
                "tcp relay %s destination must use protocol=tcp" % rid
            )
        if str(dest.get("match") or "exact") != "exact":
            raise EgressError("tcp relay %s destination must use match=exact" % rid)
        listen_addr = _validate_listen_addr(relay.get("listen_addr") or DEFAULT_LISTEN_ADDR)
        listen_port = validate_port(relay.get("listen_port"))
        listen_key = (listen_addr, listen_port)
        if listen_key in listen_keys:
            raise EgressError(
                "duplicate tcp relay listen %s:%s" % (listen_addr, listen_port)
            )
        listen_keys.add(listen_key)
        relay["name"] = name
        relay["profile_id"] = profile_id
        relay["destination_id"] = destination_id
        relay["listen_addr"] = listen_addr
        relay["listen_port"] = listen_port


def load_egress_state(
    path: Optional[Path] = None,
    cfg: Optional[dict] = None,
    *,
    persist_migration: bool = True,
) -> dict:
    path = path or egress_control_path(cfg)
    if not path.is_file():
        raise EgressError("egress-control.json is missing: %s" % path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EgressError("egress-control.json is unreadable or corrupt") from exc
    version = raw.get("schema_version") if isinstance(raw, dict) else None
    state = _parse_egress_state(raw, migrate=True)
    validate_egress_state(state)
    if persist_migration and version in (
        EGRESS_SCHEMA_VERSION_LEGACY,
        EGRESS_SCHEMA_VERSION_V2,
    ):
        locks = _locks()
        try:
            with _control_state_mutation_lock(path):
                with FileLock(egress_lock_path(path)):
                    # Re-read under lock to avoid clobbering concurrent writers.
                    try:
                        raw2 = json.loads(path.read_text(encoding="utf-8"))
                    except Exception:
                        raw2 = raw
                    if isinstance(raw2, dict) and raw2.get("schema_version") in (
                        EGRESS_SCHEMA_VERSION_LEGACY,
                        EGRESS_SCHEMA_VERSION_V2,
                    ):
                        migrated = migrate_egress_state_to_current(raw2)
                        validate_egress_state(migrated)
                        atomic_write_json(path, migrated)
                        state = migrated
        except locks.LockTimeout as exc:
            raise EgressError("timed out waiting for control-state lock") from exc
    return state


def require_egress_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    return load_egress_state(path=path, cfg=cfg)


def initialize_egress_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    path = path or egress_control_path(cfg)
    state = empty_egress_state()
    if path.is_file():
        return load_egress_state(path=path, cfg=cfg)
    locks = _locks()
    try:
        with _control_state_mutation_lock(path):
            with FileLock(egress_lock_path(path)):
                if path.is_file():
                    return load_egress_state(path=path, cfg=cfg, persist_migration=False)
                atomic_write_json(path, state)
    except locks.LockTimeout as exc:
        raise EgressError("timed out waiting for control-state lock") from exc
    return state


def save_egress_state(state: dict, path: Optional[Path] = None, cfg: Optional[dict] = None) -> None:
    path = path or egress_control_path(cfg)
    validate_egress_state(state)
    locks = _locks()
    try:
        with _control_state_mutation_lock(path):
            with FileLock(egress_lock_path(path)):
                atomic_write_json(path, state)
    except locks.LockTimeout as exc:
        raise EgressError("timed out waiting for control-state lock") from exc


def mutate_egress_state(mutator, path: Optional[Path] = None, cfg: Optional[dict] = None):
    path = path or egress_control_path(cfg)
    locks = _locks()
    try:
        with _control_state_mutation_lock(path):
            with FileLock(egress_lock_path(path)):
                # persist_migration=False: load may otherwise reacquire FileLock.
                state = load_egress_state(path=path, cfg=cfg, persist_migration=False)
                result = mutator(state)
                validate_egress_state(state)
                atomic_write_json(path, state)
                return result if result is not None else state
    except locks.LockTimeout as exc:
        raise EgressError("timed out waiting for control-state lock") from exc


def resolve_profile(state: dict, selector: str) -> tuple[str, dict]:
    text = str(selector or "").strip()
    if not text:
        raise EgressError("egress profile selector is required")
    profiles = state.get("egress_profiles") or {}
    if text in profiles:
        return text, profiles[text]
    matches = []
    needle = text.lower()
    for pid, profile in profiles.items():
        if str(profile.get("name") or "").lower() == needle:
            matches.append((pid, profile))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise EgressError("ambiguous egress profile name: %s" % selector)
    raise EgressError("egress profile not found: %s" % selector)


def list_profiles(state: dict) -> list[tuple[str, dict]]:
    profiles = state.get("egress_profiles") or {}
    rows = list(profiles.items())
    rows.sort(key=lambda item: str((item[1] or {}).get("name") or item[0]).lower())
    return rows


def create_profile(
    state: dict,
    name: str,
    *,
    description: str = "",
    enabled: bool,
) -> tuple[str, dict]:
    name = validate_profile_name(name)
    desc = str(description or "")
    if len(desc) > DESCRIPTION_MAX_LEN:
        raise EgressError("description too long")
    if enabled:
        raise EgressError(
            "cannot create an enabled egress profile; create disabled, "
            "add at least one source and destination, then enable"
        )
    for _pid, existing in (state.get("egress_profiles") or {}).items():
        if str(existing.get("name") or "").lower() == name.lower():
            raise EgressError("egress profile already exists: %s" % name)
    pid = _new_id(PROFILE_ID_PREFIX)
    now = utc_now_iso()
    record = {
        "id": pid,
        "name": name,
        "description": desc,
        "enabled": False,
        "sources": [],
        "destinations": [],
        "created_at": now,
        "updated_at": now,
    }
    state.setdefault("egress_profiles", {})[pid] = record
    return pid, record


def profile_enable_blockers(profile: dict) -> list[str]:
    """Human-readable reasons a profile cannot be enabled."""
    blockers = []
    sources = profile.get("sources") or []
    destinations = profile.get("destinations") or []
    if not isinstance(sources, list) or not sources:
        blockers.append("no source")
    if not isinstance(destinations, list) or not destinations:
        blockers.append("no destination")
    return blockers


def require_profile_complete_for_enable(profile: dict) -> None:
    blockers = profile_enable_blockers(profile)
    if not blockers:
        return
    raise EgressError(
        "cannot enable incomplete egress profile (%s); "
        "add source and destination, then enable"
        % ", ".join(blockers)
    )


def set_profile_metadata(
    state: dict,
    selector: str,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> tuple[str, dict]:
    pid, profile = resolve_profile(state, selector)
    if name is not None:
        new_name = validate_profile_name(name)
        for other_id, other in (state.get("egress_profiles") or {}).items():
            if other_id == pid:
                continue
            if str(other.get("name") or "").lower() == new_name.lower():
                raise EgressError("egress profile already exists: %s" % new_name)
        profile["name"] = new_name
    if description is not None:
        desc = str(description)
        if len(desc) > DESCRIPTION_MAX_LEN:
            raise EgressError("description too long")
        profile["description"] = desc
    profile["updated_at"] = utc_now_iso()
    return pid, profile


def set_profile_enabled(state: dict, selector: str, enabled: bool) -> tuple[str, dict]:
    pid, profile = resolve_profile(state, selector)
    if enabled:
        require_profile_complete_for_enable(profile)
    profile["enabled"] = bool(enabled)
    profile["updated_at"] = utc_now_iso()
    return pid, profile


def delete_profile(state: dict, selector: str) -> tuple[str, dict]:
    pid, profile = resolve_profile(state, selector)
    for rid, relay in (state.get("tcp_relays") or {}).items():
        if isinstance(relay, dict) and relay.get("profile_id") == pid:
            raise EgressError(
                "cannot delete profile %s while tcp relay %s references it"
                % (profile.get("name") or pid, relay.get("name") or rid)
            )
    del state["egress_profiles"][pid]
    return pid, profile


def add_source(state: dict, selector: str, cidr: str, *, name: str = "") -> tuple[str, dict, dict]:
    pid, profile = resolve_profile(state, selector)
    canon = canonicalize_cidr(cidr)
    for existing in profile.get("sources") or []:
        if canonicalize_cidr(existing.get("cidr") or "") == canon:
            raise EgressError("source already present: %s" % canon)
    entry = {
        "id": _new_id(SOURCE_ID_PREFIX),
        "name": str(name or "").strip(),
        "cidr": canon,
        "created_at": utc_now_iso(),
    }
    profile.setdefault("sources", []).append(entry)
    profile["updated_at"] = utc_now_iso()
    return pid, profile, entry


def remove_source(state: dict, selector: str, source_selector: str) -> tuple[str, dict, dict]:
    pid, profile = resolve_profile(state, selector)
    needle = str(source_selector or "").strip()
    if not needle:
        raise EgressError("source selector is required")
    sources = profile.get("sources") or []
    matches = []
    for idx, entry in enumerate(sources):
        if entry.get("id") == needle:
            matches.append(idx)
            continue
        try:
            if canonicalize_cidr(entry.get("cidr") or "") == canonicalize_cidr(needle):
                matches.append(idx)
                continue
        except EgressError:
            pass
        if str(entry.get("name") or "") == needle:
            matches.append(idx)
    if not matches:
        raise EgressError("source not found: %s" % source_selector)
    if len(matches) > 1:
        raise EgressError("ambiguous source selector: %s" % source_selector)
    removed = sources.pop(matches[0])
    profile["updated_at"] = utc_now_iso()
    return pid, profile, removed


def add_destination(
    state: dict,
    selector: str,
    host: str,
    port: Any,
    *,
    protocol: Any,
) -> tuple[str, dict, dict]:
    pid, profile = resolve_profile(state, selector)
    proto = validate_protocol(protocol)
    allow_wild = proto != PROTOCOL_TCP
    canon_host, match_mode = canonicalize_hostname(host, allow_wildcard=allow_wild)
    if proto == PROTOCOL_TCP and match_mode != "exact":
        raise EgressError("tcp destinations require an exact FQDN (no wildcard)")
    port_i = validate_port(port)
    for existing in profile.get("destinations") or []:
        if (
            str(existing.get("host") or "").lower() == canon_host
            and int(existing.get("port")) == port_i
            and str(existing.get("match") or "exact") == match_mode
            and str(existing.get("protocol") or "").lower() == proto
        ):
            raise EgressError(
                "destination already present: %s:%s/%s" % (canon_host, port_i, proto)
            )
    entry = {
        "id": _new_id(DEST_ID_PREFIX),
        "host": canon_host,
        "port": port_i,
        "match": match_mode,
        "protocol": proto,
        "created_at": utc_now_iso(),
    }
    profile.setdefault("destinations", []).append(entry)
    profile["updated_at"] = utc_now_iso()
    return pid, profile, entry


def remove_destination(state: dict, selector: str, dest_selector: str) -> tuple[str, dict, dict]:
    pid, profile = resolve_profile(state, selector)
    needle = str(dest_selector or "").strip()
    if not needle:
        raise EgressError("destination selector is required")
    destinations = profile.get("destinations") or []
    matches = []
    # Accept id, host:port, or host
    host_part = needle
    port_part = None
    if ":" in needle and not needle.startswith("*."):
        # host:port — but wildcard hosts also contain no colon usually
        try:
            maybe_host, maybe_port = needle.rsplit(":", 1)
            if maybe_port.isdigit():
                host_part = maybe_host
                port_part = int(maybe_port)
        except ValueError:
            pass
    for idx, entry in enumerate(destinations):
        if entry.get("id") == needle:
            matches.append(idx)
            continue
        entry_host = str(entry.get("host") or "")
        entry_port = int(entry.get("port"))
        if port_part is not None:
            try:
                canon, _mode = canonicalize_hostname(host_part, allow_wildcard=True)
            except EgressError:
                continue
            if entry_host == canon and entry_port == port_part:
                matches.append(idx)
        else:
            if entry_host == needle.lower().rstrip(".") or entry.get("id") == needle:
                matches.append(idx)
    # Unique
    matches = sorted(set(matches))
    if not matches:
        raise EgressError("destination not found: %s" % dest_selector)
    if len(matches) > 1:
        raise EgressError("ambiguous destination selector: %s" % dest_selector)
    removed = destinations[matches[0]]
    for rid, relay in (state.get("tcp_relays") or {}).items():
        if (
            isinstance(relay, dict)
            and relay.get("profile_id") == pid
            and relay.get("destination_id") == removed.get("id")
        ):
            raise EgressError(
                "cannot remove destination while tcp relay %s references it"
                % (relay.get("name") or rid)
            )
    removed = destinations.pop(matches[0])
    profile["updated_at"] = utc_now_iso()
    return pid, profile, removed


def source_matches_cidr_list(source_ip: str, sources: list) -> Optional[dict]:
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise EgressError("invalid source IP: %s" % source_ip) from exc
    if not isinstance(sources, list) or not sources:
        return None
    for entry in sources:
        if not isinstance(entry, dict):
            continue
        try:
            net = ipaddress.ip_network(entry.get("cidr") or "", strict=False)
        except ValueError as exc:
            raise EgressError("invalid source CIDR in policy") from exc
        if addr in net:
            return entry
    return None


def destination_matches(
    host: str,
    port: int,
    destinations: list,
    *,
    protocol: str,
) -> Optional[dict]:
    proto = validate_protocol(protocol)
    if not isinstance(destinations, list) or not destinations:
        return None
    for entry in destinations:
        if not isinstance(entry, dict):
            continue
        try:
            if int(entry.get("port")) != int(port):
                continue
        except (TypeError, ValueError):
            continue
        try:
            if validate_protocol(entry.get("protocol")) != proto:
                continue
        except EgressError:
            continue
        if hostname_matches(host, entry.get("host") or "", entry.get("match") or "exact"):
            return entry
    return None


def authorize_request(
    state: Optional[dict],
    *,
    source_ip: str,
    hostname: str,
    port: int,
    protocol: str,
    load_error: Optional[str] = None,
    method: Optional[str] = None,
    preview: bool = False,
) -> dict:
    """Authorize an egress request. Always fail closed.

    protocol must be http|https and must match the wire method semantics:
      - http: absolute-form HTTP forward-proxy only (CONNECT must be denied
        even if host:port otherwise matches an http destination)
      - https: CONNECT + ClientHello SNI binding required at the gateway for
        ALL https ports (not just 443)

    When preview=True, a disabled profile that otherwise matches source,
    destination, and protocol returns ALLOW (prospective policy) without
    mutating live state. Live gateway authorization must pass preview=False.

    Returns dict with decision, reason, profile_id, profile_name, matched_source,
    matched_destination, protocol.
    """
    base = {
        "decision": DECISION_DENY,
        "reason": REASON_AUTHORIZATION_ERROR,
        "profile_id": None,
        "profile_name": None,
        "matched_source": None,
        "matched_destination": None,
        "source_ip": source_ip,
        "hostname": hostname,
        "port": port,
        "protocol": None,
    }
    if load_error is not None:
        base["reason"] = REASON_POLICY_INVALID
        return base
    if state is None:
        base["reason"] = REASON_POLICY_MISSING
        return base
    try:
        proto = validate_protocol(protocol)
        base["protocol"] = proto
        # Method/protocol binding (fail closed). TCP relays have no HTTP method.
        meth = str(method or "").upper().strip()
        if meth and proto != PROTOCOL_TCP:
            if proto == PROTOCOL_HTTP and meth == "CONNECT":
                base["reason"] = REASON_PROTOCOL_NOT_ALLOWED
                return base
            if proto == PROTOCOL_HTTPS and meth != "CONNECT":
                base["reason"] = REASON_PROTOCOL_NOT_ALLOWED
                return base
        if meth and proto == PROTOCOL_TCP and meth in ("CONNECT", "GET", "POST", "PUT"):
            # TCP path never uses HTTP methods; treat as malformed probe.
            base["reason"] = REASON_PROTOCOL_NOT_ALLOWED
            return base
        # Reject IP literal destinations at authorize boundary too.
        try:
            ipaddress.ip_address(str(hostname))
            base["reason"] = REASON_IP_LITERAL_DENIED
            return base
        except ValueError:
            pass
        host, _ = canonicalize_hostname(hostname, allow_wildcard=False)
        port_i = validate_port(port)
        try:
            ipaddress.ip_address(str(source_ip).strip())
        except ValueError:
            base["reason"] = REASON_MALFORMED_REQUEST
            return base

        profiles = list_profiles(state)
        if not profiles:
            base["reason"] = REASON_NO_MATCHING_PROFILE
            return base

        saw_source_match = False
        saw_disabled_with_match = False
        saw_protocol_mismatch = False
        for pid, profile in profiles:
            sources = profile.get("sources") or []
            destinations = profile.get("destinations") or []
            src = source_matches_cidr_list(source_ip, sources)
            if src is None:
                continue
            saw_source_match = True
            dest = destination_matches(host, port_i, destinations, protocol=proto)
            if dest is None:
                # Distinguish host:port match with wrong protocol for clearer deny.
                for candidate in destinations:
                    if not isinstance(candidate, dict):
                        continue
                    try:
                        if int(candidate.get("port")) != port_i:
                            continue
                    except (TypeError, ValueError):
                        continue
                    if hostname_matches(
                        host, candidate.get("host") or "", candidate.get("match") or "exact"
                    ):
                        try:
                            if validate_protocol(candidate.get("protocol")) != proto:
                                saw_protocol_mismatch = True
                        except EgressError:
                            pass
                continue
            if not profile.get("enabled", False):
                if preview:
                    return {
                        "decision": DECISION_ALLOW,
                        "reason": REASON_PROFILE_MATCH,
                        "profile_id": pid,
                        "profile_name": profile.get("name"),
                        "matched_source": src,
                        "matched_destination": dest,
                        "source_ip": source_ip,
                        "hostname": host,
                        "port": port_i,
                        "protocol": proto,
                        "preview": True,
                    }
                saw_disabled_with_match = True
                continue
            return {
                "decision": DECISION_ALLOW,
                "reason": REASON_PROFILE_MATCH,
                "profile_id": pid,
                "profile_name": profile.get("name"),
                "matched_source": src,
                "matched_destination": dest,
                "source_ip": source_ip,
                "hostname": host,
                "port": port_i,
                "protocol": proto,
            }

        if saw_disabled_with_match:
            base["reason"] = REASON_PROFILE_DISABLED
        elif not saw_source_match:
            base["reason"] = REASON_SOURCE_NOT_ALLOWED
        elif saw_protocol_mismatch:
            base["reason"] = REASON_PROTOCOL_NOT_ALLOWED
        else:
            base["reason"] = REASON_DESTINATION_NOT_ALLOWED
        base["hostname"] = host
        base["port"] = port_i
        return base
    except EgressError as exc:
        msg = str(exc)
        if "IP literal" in msg:
            base["reason"] = REASON_IP_LITERAL_DENIED
        elif "protocol" in msg.lower():
            base["reason"] = REASON_PROTOCOL_NOT_ALLOWED
        elif "invalid" in msg.lower() or "malformed" in msg.lower():
            base["reason"] = REASON_MALFORMED_REQUEST
        else:
            base["reason"] = REASON_POLICY_INVALID
        return base
    except Exception:
        base["reason"] = REASON_AUTHORIZATION_ERROR
        return base


_AUDIT_FAIL_LOCK = threading.Lock()
_AUDIT_FAIL_SEEN: set[str] = set()


def _note_conn_log_failure(path: Path, detail: str) -> None:
    """Surface a dropped connection-audit record once per path and cause."""
    key = "%s\0%s" % (path, detail)
    with _AUDIT_FAIL_LOCK:
        if key in _AUDIT_FAIL_SEEN:
            return
        if len(_AUDIT_FAIL_SEEN) > 64:
            _AUDIT_FAIL_SEEN.clear()
        _AUDIT_FAIL_SEEN.add(key)
    sys.stderr.write(
        "[drlink-egress] connection audit unavailable path=%s error=%s\n" % (path, detail)
    )


def emit_conn_log(event: dict, path: Optional[Path] = None, cfg: Optional[dict] = None) -> None:
    """Best-effort connection log. Never raises. Never logs secrets/payloads.

    Lock the log inode itself (fcntl on the open FD). Do not create a sidecar
    ``*.lock`` under the parent directory: production installs make
    ``/var/log/drlink`` traverse-only for ``drlink-egress`` (``--x`` / ``0710``)
    while granting write on the service subdirectory ``egress/`` so rotation
    (rename/unlink/create) can succeed.

    Rotation and append share one exclusive lock on the inode that ``path``
    currently names. Rotating outside the lock lets two writers rotate the same
    log, and lets a writer resolve, open, or append to an inode that is being
    replaced underneath it, which silently drops records.
    """
    try:
        path = Path(path) if path else conn_log_path(cfg)
        # Soft: shared parent mkdir may fail under traverse-only ACL; the
        # service log subdirectory is pre-created at install and is writable.
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        record = {
            "timestamp": event.get("timestamp") or utc_now_iso(),
            "connection_id": event.get("connection_id"),
            "session_id": event.get("session_id"),
            "source_ip": event.get("source_ip"),
            "hostname": event.get("hostname"),
            "port": event.get("port"),
            "protocol": event.get("protocol"),
            "method": event.get("method"),
            "profile_id": event.get("profile_id"),
            "profile_name": event.get("profile_name"),
            "relay_id": event.get("relay_id"),
            "relay_name": event.get("relay_name"),
            "decision": event.get("decision"),
            "reason": event.get("reason"),
            "outcome": event.get("outcome"),
            "policy_generation": event.get("policy_generation"),
        }
        # Optional safe SNI audit field (hostname only — never raw ClientHello).
        observed_sni = event.get("observed_sni")
        if observed_sni is not None:
            record["observed_sni"] = str(observed_sni)[:253]
        # Drop None keys for compact logs.
        record = {k: v for k, v in record.items() if v is not None}
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        fd, created = _open_conn_log_locked(path)
        if fd is None:
            _note_conn_log_failure(path, "open failed")
            return
        try:
            if created:
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass
                try:
                    reapply_egress_runtime_permissions(conn_log_path=path, parents=False)
                except OSError:
                    pass
            if os.fstat(fd).st_size >= CONN_LOG_MAX_BYTES:
                _rotate_conn_log_locked(path, fd)
            os.write(fd, line.encode("utf-8"))
        finally:
            _unlock_close(fd)
    except Exception as exc:
        try:
            failed = path if isinstance(path, Path) else conn_log_path(cfg)
        except Exception:
            failed = Path("connections.jsonl")
        _note_conn_log_failure(failed, str(exc))
        return


def _unlock_close(fd: Optional[int]) -> None:
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _open_conn_log_locked(path: Path, attempts: int = 8) -> tuple[Optional[int], bool]:
    """Open the active log for append, holding LOCK_EX on the *current* inode.

    A lock on an inode that is no longer named ``path`` protects nothing, so
    re-stat after locking and retry if the name moved on (an external logrotate,
    or an operator replacing the file). Returns ``(None, False)`` when the log
    cannot be locked; callers treat that as a dropped best-effort record.
    """
    flags = os.O_WRONLY | os.O_APPEND
    for _ in range(max(1, int(attempts))):
        created = False
        try:
            fd = os.open(str(path), flags)
        except FileNotFoundError:
            try:
                fd = os.open(str(path), flags | os.O_CREAT | os.O_EXCL, 0o600)
                created = True
            except FileExistsError:
                continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if os.fstat(fd).st_ino == os.stat(str(path)).st_ino:
                return fd, created
        except OSError:
            _unlock_close(fd)
            continue
        _unlock_close(fd)
    return None, False


def _rotate_conn_log_locked(path: Path, fd: int) -> None:
    """Shift ``.N`` generations and empty the active log in place.

    Callers must hold LOCK_EX on ``fd``, the inode named by ``path``. Copy then
    truncate, rather than rename plus recreate: the active inode stays the same,
    so writers already queued on this lock keep a valid lock instead of waking
    up on a rotated-away inode and having to queue again. Copying into a temp
    generation first means an interrupted rotation cannot lose the log.
    """
    try:
        for idx in range(CONN_LOG_KEEP, 0, -1):
            src = Path("%s.%d" % (path, idx))
            dst = Path("%s.%d" % (path, idx + 1))
            if idx == CONN_LOG_KEEP and src.is_file():
                try:
                    src.unlink()
                except OSError:
                    pass
            elif src.is_file():
                os.replace(src, dst)
        tmp = Path("%s.rot.%d.tmp" % (path, os.getpid()))
        out = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with open(str(path), "rb") as src_file:
                while True:
                    chunk = src_file.read(256 * 1024)
                    if not chunk:
                        break
                    os.write(out, chunk)
        finally:
            os.close(out)
        os.replace(tmp, Path("%s.1" % path))
        os.ftruncate(fd, 0)
        try:
            reapply_egress_runtime_permissions(conn_log_path=path, parents=False)
        except OSError:
            pass
    except OSError:
        return


class CompiledDestination:
    __slots__ = (
        "host", "port", "protocol", "match", "profile_id",
        "profile_name", "enabled", "destination_id",
    )

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str,
        match: str,
        profile_id: str,
        profile_name: str,
        enabled: bool,
        destination_id: str,
    ):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.match = match
        self.profile_id = profile_id
        self.profile_name = profile_name
        self.enabled = enabled
        self.destination_id = destination_id


class PolicySnapshot:
    """Immutable compiled egress policy.

    Connections authorize only against a PolicySnapshot. When reload fails,
    PolicyEngine marks unhealthy=True and authorize() fails closed for ALL
    traffic (stale ALLOW snapshot is not silently kept as the live deny plane).
    Last-good snapshot may be retained for doctor/diagnostics only.

    Note: plain class (not dataclass) so importlib.spec_from_file_location
    loaders that omit sys.modules registration still work.
    """

    __slots__ = (
        "generation", "schema_version", "healthy", "load_error",
        "state", "exact_index", "wildcard_rules", "compiled_at",
    )

    def __init__(
        self,
        generation: int,
        schema_version: int,
        healthy: bool,
        load_error: Optional[str],
        state: dict,
        exact_index: dict,
        wildcard_rules: tuple,
        compiled_at: Optional[str] = None,
    ):
        self.generation = generation
        self.schema_version = schema_version
        self.healthy = healthy
        self.load_error = load_error
        self.state = state
        self.exact_index = exact_index
        self.wildcard_rules = wildcard_rules
        self.compiled_at = compiled_at if compiled_at is not None else utc_now_iso()


def compile_policy_snapshot(
    state: dict,
    *,
    generation: int,
    load_error: Optional[str] = None,
    healthy: bool = True,
) -> PolicySnapshot:
    if load_error is not None or not healthy:
        return PolicySnapshot(
            generation=generation,
            schema_version=int(state.get("schema_version") or EGRESS_SCHEMA_VERSION),
            healthy=False,
            load_error=load_error or REASON_POLICY_UNHEALTHY,
            state={"schema_version": EGRESS_SCHEMA_VERSION, "egress_profiles": {}, "tcp_relays": {}},
            exact_index={},
            wildcard_rules=(),
        )
    validate_egress_state(state)
    exact: dict = {}
    wildcards: list = []
    for pid, profile in list_profiles(state):
        enabled = bool(profile.get("enabled"))
        pname = str(profile.get("name") or "")
        for dest in profile.get("destinations") or []:
            if not isinstance(dest, dict):
                continue
            compiled = CompiledDestination(
                host=str(dest.get("host") or ""),
                port=int(dest.get("port")),
                protocol=validate_protocol(dest.get("protocol")),
                match=str(dest.get("match") or "exact"),
                profile_id=pid,
                profile_name=pname,
                enabled=enabled,
                destination_id=str(dest.get("id") or ""),
            )
            if compiled.match == "wildcard":
                wildcards.append(compiled)
            else:
                key = (compiled.host, compiled.port, compiled.protocol)
                exact.setdefault(key, []).append(compiled)
    return PolicySnapshot(
        generation=generation,
        schema_version=EGRESS_SCHEMA_VERSION,
        healthy=True,
        load_error=None,
        state=json.loads(json.dumps(state)),  # deep copy via JSON
        exact_index=exact,
        wildcard_rules=tuple(wildcards),
    )


def authorize_against_snapshot(
    snapshot: Optional[PolicySnapshot],
    *,
    source_ip: str,
    hostname: str,
    port: int,
    protocol: str,
    method: Optional[str] = None,
) -> dict:
    if snapshot is None:
        return authorize_request(
            None,
            source_ip=source_ip,
            hostname=hostname,
            port=port,
            protocol=protocol,
            method=method,
            load_error=REASON_POLICY_MISSING,
        )
    if not snapshot.healthy:
        return authorize_request(
            None,
            source_ip=source_ip,
            hostname=hostname,
            port=port,
            protocol=protocol,
            method=method,
            load_error=snapshot.load_error or REASON_POLICY_UNHEALTHY,
        )
    result = authorize_request(
        snapshot.state,
        source_ip=source_ip,
        hostname=hostname,
        port=port,
        protocol=protocol,
        method=method,
    )
    result["policy_generation"] = snapshot.generation
    return result


class PolicyEngine:
    """Load → validate → compile → immutable snapshot → generation bump.

    Invalid reload does NOT keep serving the previous ALLOW snapshot as if the
    new deny/corrupt policy were active. Instead the engine enters unhealthy
    fail-closed: all authorize() calls DENY with POLICY_INVALID/UNHEALTHY until
    a valid policy loads again (new generation).
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._generation = 0
        self._snapshot: Optional[PolicySnapshot] = None
        self._last_good: Optional[PolicySnapshot] = None
        self._mtime = None

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def snapshot(self) -> Optional[PolicySnapshot]:
        with self._lock:
            return self._snapshot

    def last_good(self) -> Optional[PolicySnapshot]:
        with self._lock:
            return self._last_good

    def replace_from_state(self, state: dict) -> PolicySnapshot:
        with self._lock:
            self._generation += 1
            snap = compile_policy_snapshot(state, generation=self._generation, healthy=True)
            self._snapshot = snap
            self._last_good = snap
            return snap

    def mark_unhealthy(self, error: str) -> PolicySnapshot:
        with self._lock:
            self._generation += 1
            snap = compile_policy_snapshot(
                {
                    "schema_version": EGRESS_SCHEMA_VERSION,
                    "egress_profiles": {},
                    "tcp_relays": {},
                },
                generation=self._generation,
                load_error=str(error),
                healthy=False,
            )
            self._snapshot = snap
            return snap

    def load_from_path(self, path: Path, cfg: Optional[dict] = None) -> PolicySnapshot:
        try:
            state = load_egress_state(path=path, cfg=cfg)
            return self.replace_from_state(state)
        except Exception as exc:
            return self.mark_unhealthy(str(exc))


def export_profile(state: dict, selector: str) -> dict:
    """Export one profile as a portable document (no auto-enable on import)."""
    pid, profile = resolve_profile(state, selector)
    validate_egress_state(state)
    doc = {
        "schema_version": EGRESS_SCHEMA_VERSION,
        "export_kind": "egress_profile",
        "exported_at": utc_now_iso(),
        "profile": json.loads(json.dumps(profile)),
    }
    # Exports never force enabled=true on import; stamp intent.
    doc["profile"]["id"] = pid
    return doc


def parse_import_document(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise EgressError("import document must be a JSON object")
    version = raw.get("schema_version")
    if version == EGRESS_SCHEMA_VERSION_LEGACY:
        # Allow wrapping a legacy full state or a single profile-shaped object.
        raise EgressError("legacy schema v1 import requires migrate via full state load")
    if version != EGRESS_SCHEMA_VERSION:
        raise EgressError("unsupported import schema_version: %s" % version)
    profile = raw.get("profile")
    if not isinstance(profile, dict):
        raise EgressError("import document missing profile object")
    # Validate as a transient one-profile state.
    candidate = dict(profile)
    # Imported source/destination identity is untrusted; always mint new IDs.
    _regenerate_entry_ids(candidate)
    pid = candidate.get("id")
    if not isinstance(pid, str) or not pid.startswith(PROFILE_ID_PREFIX):
        pid = _new_id(PROFILE_ID_PREFIX)
    candidate["id"] = pid
    if "enabled" not in candidate:
        candidate["enabled"] = False
    # Import never auto-enables.
    candidate["enabled"] = False
    tmp_state = {
        "schema_version": EGRESS_SCHEMA_VERSION,
        "egress_profiles": {pid: candidate},
        "tcp_relays": {},
    }
    validate_egress_state(tmp_state)
    return candidate


def diff_profiles(current: dict, candidate: dict) -> dict:
    """Structural diff of destinations/sources/metadata (no secrets)."""
    cur_dests = {
        (
            str(d.get("host")),
            int(d.get("port")),
            str(d.get("protocol")),
            str(d.get("match") or "exact"),
        ): d
        for d in (current.get("destinations") or [])
        if isinstance(d, dict)
    }
    new_dests = {
        (
            str(d.get("host")),
            int(d.get("port")),
            str(d.get("protocol")),
            str(d.get("match") or "exact"),
        ): d
        for d in (candidate.get("destinations") or [])
        if isinstance(d, dict)
    }
    cur_srcs = {str(s.get("cidr")) for s in (current.get("sources") or []) if isinstance(s, dict)}
    new_srcs = {str(s.get("cidr")) for s in (candidate.get("sources") or []) if isinstance(s, dict)}
    return {
        "name_current": current.get("name"),
        "name_candidate": candidate.get("name"),
        "destinations_added": sorted(
            ["%s:%s/%s" % (h, p, proto) for (h, p, proto, _m) in (new_dests.keys() - cur_dests.keys())]
        ),
        "destinations_removed": sorted(
            ["%s:%s/%s" % (h, p, proto) for (h, p, proto, _m) in (cur_dests.keys() - new_dests.keys())]
        ),
        "sources_added": sorted(new_srcs - cur_srcs),
        "sources_removed": sorted(cur_srcs - new_srcs),
        "enabled_current": bool(current.get("enabled")),
        "enabled_candidate": False,  # import never auto-enables
    }


def import_profile_into_state(
    state: dict,
    candidate: dict,
    *,
    target_selector: Optional[str] = None,
) -> tuple[str, dict, dict]:
    """Merge validated candidate into state. Always leaves profile disabled."""
    candidate = parse_import_document(
        {"schema_version": EGRESS_SCHEMA_VERSION, "profile": candidate}
    )
    if target_selector:
        pid, current = resolve_profile(state, target_selector)
        diff = diff_profiles(current, candidate)
        current["description"] = str(candidate.get("description") or current.get("description") or "")
        current["sources"] = list(candidate.get("sources") or [])
        current["destinations"] = list(candidate.get("destinations") or [])
        current["enabled"] = False
        current["updated_at"] = utc_now_iso()
        return pid, current, diff
    # Create new profile from candidate name.
    name = validate_profile_name(candidate.get("name") or "")
    pid, record = create_profile(state, name, description=candidate.get("description") or "", enabled=False)
    record["sources"] = list(candidate.get("sources") or [])
    record["destinations"] = list(candidate.get("destinations") or [])
    # parse_import_document already regenerated untrusted entry IDs.
    record["updated_at"] = utc_now_iso()
    validate_egress_state(state)
    return pid, record, diff_profiles({"destinations": [], "sources": [], "enabled": False}, record)


def resolve_destination(profile: dict, dest_selector: str) -> dict:
    needle = str(dest_selector or "").strip()
    if not needle:
        raise EgressError("destination selector is required")
    destinations = profile.get("destinations") or []
    matches = []
    host_part = needle
    port_part = None
    if ":" in needle and not needle.startswith("*."):
        try:
            maybe_host, maybe_port = needle.rsplit(":", 1)
            if maybe_port.isdigit():
                host_part = maybe_host
                port_part = int(maybe_port)
        except ValueError:
            pass
    for entry in destinations:
        if not isinstance(entry, dict):
            continue
        if entry.get("id") == needle:
            matches.append(entry)
            continue
        entry_host = str(entry.get("host") or "")
        entry_port = int(entry.get("port"))
        if port_part is not None:
            try:
                canon, _mode = canonicalize_hostname(host_part, allow_wildcard=True)
            except EgressError:
                continue
            if entry_host == canon and entry_port == port_part:
                matches.append(entry)
        elif entry_host == needle.lower().rstrip("."):
            matches.append(entry)
    by_id = {m["id"]: m for m in matches}
    if not by_id:
        raise EgressError("destination not found: %s" % dest_selector)
    if len(by_id) > 1:
        raise EgressError("ambiguous destination selector: %s" % dest_selector)
    return next(iter(by_id.values()))


def list_tcp_relays(state: dict) -> list[tuple[str, dict]]:
    relays = state.get("tcp_relays") or {}
    rows = list(relays.items())
    rows.sort(key=lambda item: str((item[1] or {}).get("name") or item[0]).lower())
    return rows


def resolve_tcp_relay(state: dict, selector: str) -> tuple[str, dict]:
    text = str(selector or "").strip()
    if not text:
        raise EgressError("tcp relay selector is required")
    relays = state.get("tcp_relays") or {}
    if text in relays:
        return text, relays[text]
    matches = []
    needle = text.lower()
    for rid, relay in relays.items():
        if str(relay.get("name") or "").lower() == needle:
            matches.append((rid, relay))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise EgressError("ambiguous tcp relay name: %s" % selector)
    raise EgressError("tcp relay not found: %s" % selector)


def _tcp_relay_used_ports(state: dict) -> set[int]:
    used = set()
    for _rid, relay in (state.get("tcp_relays") or {}).items():
        if not isinstance(relay, dict):
            continue
        try:
            used.add(int(relay.get("listen_port")))
        except (TypeError, ValueError):
            continue
    return used


def _load_infra_ports():
    try:
        from frp_infrastructure_ports import (  # noqa: WPS433
            coerce_port,
            infrastructure_ports,
            is_tcp_relay_port,
            port_in_service_range,
            protected_listen_ports,
            service_owns_port,
            tcp_relay_port_range,
        )
        return (
            coerce_port,
            infrastructure_ports,
            is_tcp_relay_port,
            port_in_service_range,
            protected_listen_ports,
            service_owns_port,
            tcp_relay_port_range,
        )
    except Exception:
        import importlib.util

        here = Path(__file__).resolve().parent
        path = here / "frp_infrastructure_ports.py"
        spec = importlib.util.spec_from_file_location("frp_infrastructure_ports", str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return (
            mod.coerce_port,
            mod.infrastructure_ports,
            mod.is_tcp_relay_port,
            mod.port_in_service_range,
            mod.protected_listen_ports,
            mod.service_owns_port,
            mod.tcp_relay_port_range,
        )


def assert_tcp_relay_listen_port_allowed(
    port: int,
    state: dict,
    *,
    cfg: Optional[dict] = None,
    registry: Optional[dict] = None,
    exclude_relay_id: Optional[str] = None,
) -> int:
    """Fail closed if listen port is protected, out of pool, or already used."""
    (
        coerce_port,
        _infra,
        is_tcp_relay_port,
        port_in_service_range,
        protected_listen_ports,
        service_owns_port,
        _range,
    ) = _load_infra_ports()
    port_i = validate_port(port)
    if coerce_port(port_i) is None:
        raise EgressError("invalid tcp relay listen port")
    if not is_tcp_relay_port(port_i, cfg):
        raise EgressError(
            "tcp relay listen port %s is outside Fixed TCP pool 6200-6299" % port_i
        )
    if port_in_service_range(port_i, cfg):
        raise EgressError(
            "tcp relay listen port %s collides with published service range" % port_i
        )
    protected = protected_listen_ports(cfg)
    if port_i in protected:
        raise EgressError(
            "tcp relay listen port %s is reserved for infrastructure" % port_i
        )
    owner = service_owns_port(registry, port_i)
    if owner is not None:
        mid, sid = owner
        raise EgressError(
            "tcp relay listen port %s is owned by published service %s/%s"
            % (port_i, mid, sid)
        )
    for rid, relay in (state.get("tcp_relays") or {}).items():
        if exclude_relay_id and rid == exclude_relay_id:
            continue
        if not isinstance(relay, dict):
            continue
        try:
            if int(relay.get("listen_port")) == port_i:
                raise EgressError(
                    "tcp relay listen port %s already used by %s"
                    % (port_i, relay.get("name") or rid)
                )
        except (TypeError, ValueError):
            continue
    # Also refuse HTTP egress listen port even if somehow outside protected set.
    try:
        _host, http_port = listen_bind(cfg)
        if int(http_port) == port_i:
            raise EgressError(
                "tcp relay listen port %s collides with HTTP egress listen" % port_i
            )
    except EgressError:
        raise
    except Exception:
        pass
    return port_i


def allocate_tcp_relay_listen_port(
    state: dict,
    *,
    cfg: Optional[dict] = None,
    registry: Optional[dict] = None,
) -> int:
    _coerce, _infra, _is_pool, _svc_range, _prot, _owns, tcp_relay_port_range = _load_infra_ports()
    start, end = tcp_relay_port_range(cfg)
    used = _tcp_relay_used_ports(state)
    for candidate in range(start, end + 1):
        if candidate in used:
            continue
        try:
            return assert_tcp_relay_listen_port_allowed(
                candidate, state, cfg=cfg, registry=registry
            )
        except EgressError:
            continue
    raise EgressError(
        "no free Fixed TCP Egress listen port in %s-%s" % (start, end)
    )


def tcp_relay_enable_blockers(state: dict, relay: dict) -> list[str]:
    blockers = []
    profile_id = str(relay.get("profile_id") or "")
    destination_id = str(relay.get("destination_id") or "")
    profiles = state.get("egress_profiles") or {}
    profile = profiles.get(profile_id)
    if not isinstance(profile, dict):
        blockers.append("missing profile")
        return blockers
    if not profile.get("enabled"):
        blockers.append("profile disabled")
    dest = None
    for entry in profile.get("destinations") or []:
        if isinstance(entry, dict) and entry.get("id") == destination_id:
            dest = entry
            break
    if dest is None:
        blockers.append("missing destination")
    else:
        try:
            if validate_protocol(dest.get("protocol")) != PROTOCOL_TCP:
                blockers.append("destination not tcp")
            if str(dest.get("match") or "exact") != "exact":
                blockers.append("destination not exact")
        except EgressError:
            blockers.append("invalid destination")
    sources = profile.get("sources") or []
    if not isinstance(sources, list) or not sources:
        blockers.append("no source")
    try:
        validate_port(relay.get("listen_port"))
        _validate_listen_addr(relay.get("listen_addr") or DEFAULT_LISTEN_ADDR)
    except EgressError:
        blockers.append("invalid listen")
    return blockers


def create_tcp_relay(
    state: dict,
    name: str,
    *,
    profile_selector: str,
    destination_selector: str,
    listen_port: Optional[Any] = None,
    listen_addr: str = DEFAULT_LISTEN_ADDR,
    cfg: Optional[dict] = None,
    registry: Optional[dict] = None,
    enabled: bool = False,
) -> tuple[str, dict]:
    if enabled:
        raise EgressError(
            "cannot create an enabled tcp relay; create disabled, then enable"
        )
    name = validate_profile_name(name)
    for _rid, existing in (state.get("tcp_relays") or {}).items():
        if str(existing.get("name") or "").lower() == name.lower():
            raise EgressError("tcp relay already exists: %s" % name)
    pid, profile = resolve_profile(state, profile_selector)
    dest = resolve_destination(profile, destination_selector)
    if validate_protocol(dest.get("protocol")) != PROTOCOL_TCP:
        raise EgressError("tcp relay destination must use protocol=tcp")
    if str(dest.get("match") or "exact") != "exact":
        raise EgressError("tcp relay destination must use match=exact")
    addr = _validate_listen_addr(listen_addr or DEFAULT_LISTEN_ADDR)
    if listen_port is None or str(listen_port).strip() == "":
        port_i = allocate_tcp_relay_listen_port(state, cfg=cfg, registry=registry)
    else:
        port_i = assert_tcp_relay_listen_port_allowed(
            listen_port, state, cfg=cfg, registry=registry
        )
    rid = _new_id(RELAY_ID_PREFIX)
    now = utc_now_iso()
    record = {
        "id": rid,
        "name": name,
        "profile_id": pid,
        "destination_id": dest.get("id"),
        "listen_addr": addr,
        "listen_port": port_i,
        "enabled": False,
        "created_at": now,
        "updated_at": now,
    }
    state.setdefault("tcp_relays", {})[rid] = record
    return rid, record


def set_tcp_relay_enabled(state: dict, selector: str, enabled: bool) -> tuple[str, dict]:
    rid, relay = resolve_tcp_relay(state, selector)
    if enabled:
        blockers = tcp_relay_enable_blockers(state, relay)
        if blockers:
            raise EgressError(
                "cannot enable incomplete tcp relay (%s)" % ", ".join(blockers)
            )
    relay["enabled"] = bool(enabled)
    relay["updated_at"] = utc_now_iso()
    return rid, relay


def delete_tcp_relay(state: dict, selector: str) -> tuple[str, dict]:
    rid, relay = resolve_tcp_relay(state, selector)
    del state["tcp_relays"][rid]
    return rid, relay


def authorize_tcp_relay(
    state: Optional[dict],
    *,
    relay_selector: str,
    source_ip: str,
    load_error: Optional[str] = None,
    preview: bool = False,
) -> dict:
    """Authorize a Fixed TCP Egress connection for one relay listener."""
    base = {
        "decision": DECISION_DENY,
        "reason": REASON_AUTHORIZATION_ERROR,
        "profile_id": None,
        "profile_name": None,
        "relay_id": None,
        "relay_name": None,
        "matched_source": None,
        "matched_destination": None,
        "source_ip": source_ip,
        "hostname": None,
        "port": None,
        "protocol": PROTOCOL_TCP,
    }
    if load_error is not None:
        base["reason"] = REASON_POLICY_INVALID
        return base
    if state is None:
        base["reason"] = REASON_POLICY_MISSING
        return base
    try:
        rid, relay = resolve_tcp_relay(state, relay_selector)
    except EgressError:
        base["reason"] = REASON_RELAY_NOT_FOUND
        return base
    base["relay_id"] = rid
    base["relay_name"] = relay.get("name")
    if not relay.get("enabled", False) and not preview:
        base["reason"] = REASON_RELAY_DISABLED
        return base
    profiles = state.get("egress_profiles") or {}
    profile = profiles.get(relay.get("profile_id"))
    if not isinstance(profile, dict):
        base["reason"] = REASON_RELAY_INCOMPLETE
        return base
    dest = None
    for entry in profile.get("destinations") or []:
        if isinstance(entry, dict) and entry.get("id") == relay.get("destination_id"):
            dest = entry
            break
    if dest is None:
        base["reason"] = REASON_RELAY_INCOMPLETE
        return base
    try:
        host = str(dest.get("host") or "")
        port = int(dest.get("port"))
    except (TypeError, ValueError):
        base["reason"] = REASON_RELAY_INCOMPLETE
        return base
    decision = authorize_request(
        state,
        source_ip=source_ip,
        hostname=host,
        port=port,
        protocol=PROTOCOL_TCP,
        preview=preview,
    )
    decision["relay_id"] = rid
    decision["relay_name"] = relay.get("name")
    if not relay.get("enabled", False) and preview and decision.get("decision") == DECISION_ALLOW:
        decision["preview"] = True
    return decision


def recipes_dir() -> Path:
    env = os.environ.get("FRP_EGRESS_RECIPES_DIR", "").strip()
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    candidates = [
        here / "data" / "egress-recipes",
        Path("/usr/local/lib/drlink/data/egress-recipes"),
    ]
    root = deploy_root()
    if root:
        candidates.insert(1, Path(root) / "usr/local/lib/drlink/data/egress-recipes")
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[0]


def list_recipes() -> list[dict]:
    directory = recipes_dir()
    if not directory.is_dir():
        return []
    rows = []
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        rid = str(raw.get("id") or path.stem)
        rows.append(
            {
                "id": rid,
                "name": str(raw.get("name") or rid),
                "description": str(raw.get("description") or ""),
                "path": str(path),
            }
        )
    return rows[:3]


def load_recipe(selector: str) -> dict:
    needle = str(selector or "").strip().lower()
    if not needle:
        raise EgressError("recipe selector is required")
    for recipe_meta in list_recipes():
        if recipe_meta["id"].lower() == needle or recipe_meta["name"].lower() == needle:
            raw = json.loads(Path(recipe_meta["path"]).read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise EgressError("invalid recipe document")
            return raw
    raise EgressError("recipe not found: %s" % selector)


def apply_recipe(
    state: dict,
    selector: str,
    *,
    profile_name: Optional[str] = None,
    source_cidr: Optional[str] = None,
    cfg: Optional[dict] = None,
    registry: Optional[dict] = None,
) -> dict:
    """Apply a recipe. NEVER auto-enables profiles or relays."""
    recipe = load_recipe(selector)
    kind = str(recipe.get("kind") or "profile").strip().lower()
    name = validate_profile_name(profile_name or recipe.get("profile_name") or recipe.get("name") or "")
    description = str(recipe.get("description") or "")
    pid, profile = create_profile(state, name, description=description, enabled=False)
    for src in recipe.get("sources") or []:
        if isinstance(src, dict):
            cidr = src.get("cidr") or source_cidr
            if cidr:
                add_source(state, pid, cidr, name=str(src.get("name") or ""))
        elif isinstance(src, str):
            add_source(state, pid, src)
    if source_cidr and not (recipe.get("sources") or []):
        add_source(state, pid, source_cidr)
    for dest in recipe.get("destinations") or []:
        if not isinstance(dest, dict):
            continue
        add_destination(
            state,
            pid,
            dest.get("host"),
            dest.get("port"),
            protocol=dest.get("protocol"),
        )
    result = {
        "profile_id": pid,
        "profile_name": profile.get("name"),
        "relay_id": None,
        "relay_name": None,
        "enabled": False,
    }
    if kind == "tcp_relay" or recipe.get("tcp_relay"):
        relay_spec = recipe.get("tcp_relay") or {}
        dests = profile.get("destinations") or []
        tcp_dest = None
        for entry in dests:
            if isinstance(entry, dict) and entry.get("protocol") == PROTOCOL_TCP:
                tcp_dest = entry
                break
        if tcp_dest is None:
            raise EgressError("tcp_relay recipe requires a tcp destination")
        rid, relay = create_tcp_relay(
            state,
            str(relay_spec.get("name") or ("%s-relay" % name)),
            profile_selector=pid,
            destination_selector=tcp_dest["id"],
            listen_port=relay_spec.get("listen_port"),
            listen_addr=str(relay_spec.get("listen_addr") or DEFAULT_LISTEN_ADDR),
            cfg=cfg,
            registry=registry,
            enabled=False,
        )
        result["relay_id"] = rid
        result["relay_name"] = relay.get("name")
    # Explicit: apply never enables.
    profile["enabled"] = False
    return result


def doctor_issues(state: dict) -> list[dict]:
    issues = []
    try:
        validate_egress_state(state)
    except EgressError as exc:
        issues.append(
            {
                "class": "EGRESS_CONFIG_ERROR",
                "severity": "error",
                "message": str(exc),
            }
        )
        return issues

    profiles = list_profiles(state)
    relays = list_tcp_relays(state)
    if not profiles and not relays:
        issues.append(
            {
                "class": "EGRESS_CONFIG_INFO",
                "severity": "info",
                "message": "no egress profiles configured (default DENY)",
            }
        )
        return issues

    enabled_open = 0
    for pid, profile in profiles:
        sources = profile.get("sources") or []
        destinations = profile.get("destinations") or []
        if profile.get("enabled") and sources and destinations:
            enabled_open += 1
        if profile.get("enabled") and sources and not destinations:
            issues.append(
                {
                    "class": "EGRESS_CONFIG_WARN",
                    "severity": "warn",
                    "message": "enabled profile %s has sources but no destinations"
                    % (profile.get("name") or pid),
                }
            )
        if profile.get("enabled") and destinations and not sources:
            issues.append(
                {
                    "class": "EGRESS_CONFIG_WARN",
                    "severity": "warn",
                    "message": "enabled profile %s has destinations but no sources"
                    % (profile.get("name") or pid),
                }
            )
        # Extremely broad source with any destination is dangerous.
        for src in sources:
            try:
                net = ipaddress.ip_network(src.get("cidr") or "", strict=False)
            except ValueError:
                continue
            if profile.get("enabled") and destinations and net.prefixlen == 0:
                issues.append(
                    {
                        "class": "EGRESS_CONFIG_WARN",
                        "severity": "warn",
                        "message": "enabled profile %s allows all sources (0.0.0.0/0 or ::/0)"
                        % (profile.get("name") or pid),
                    }
                )
    if enabled_open == 0 and profiles:
        issues.append(
            {
                "class": "EGRESS_CONFIG_INFO",
                "severity": "info",
                "message": "no enabled egress profile has both sources and destinations",
            }
        )
    enabled_relays = 0
    for rid, relay in relays:
        if relay.get("enabled"):
            enabled_relays += 1
            blockers = tcp_relay_enable_blockers(state, relay)
            if blockers:
                issues.append(
                    {
                        "class": "EGRESS_CONFIG_ERROR",
                        "severity": "error",
                        "message": "enabled tcp relay %s is incomplete (%s)"
                        % (relay.get("name") or rid, ", ".join(blockers)),
                    }
                )
        try:
            assert_tcp_relay_listen_port_allowed(
                int(relay.get("listen_port")),
                state,
                exclude_relay_id=rid,
            )
        except EgressError as exc:
            issues.append(
                {
                    "class": "EGRESS_CONFIG_ERROR",
                    "severity": "error",
                    "message": "tcp relay %s listen conflict: %s"
                    % (relay.get("name") or rid, exc),
                }
            )
        except Exception:
            pass
    if relays and enabled_relays == 0:
        issues.append(
            {
                "class": "EGRESS_CONFIG_INFO",
                "severity": "info",
                "message": "tcp relays configured but none enabled",
            }
        )
    return issues
