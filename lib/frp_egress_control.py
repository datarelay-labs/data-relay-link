#!/usr/bin/env python3
"""Controlled Egress policy plane for Data Relay.

Authoritative state: /var/lib/drlink/egress-control.json

Separate from inbound Access Control. Default DENY / fail-closed.
Agentless authorization is source IP/CIDR + FQDN:port allowlists.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

EGRESS_SCHEMA_VERSION = 1
DEFAULT_EGRESS_PATH = "/var/lib/drlink/egress-control.json"
DEFAULT_CONN_LOG_PATH = "/var/log/drlink/egress-conn.jsonl"

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
    if not configured:
        configured = os.environ.get("FRP_EGRESS_CONN_LOG", "") or DEFAULT_CONN_LOG_PATH
    return _rooted(configured)


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


def empty_egress_state() -> dict:
    return {"schema_version": EGRESS_SCHEMA_VERSION, "egress_profiles": {}}


def atomic_write_json(path: Path, data: dict, mode: int = 0o600) -> None:
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
        try:
            os.chmod(path.parent, 0o700)
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


def canonicalize_hostname(host: str, *, allow_wildcard: bool = True) -> tuple[str, str]:
    """Return (canonical_ascii_hostname, match_mode).

    match_mode is 'exact' or 'wildcard'.
    Wildcard form is strictly '*.label.label' (single leading '*.' only).
    Rejects trailing-dot ambiguity after strip, empty labels, IP literals,
    userinfo, ports, whitespace, and control characters.
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
        return "*." + ascii_host, match_mode

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
    # Reject IP literals for destination policy path by default.
    try:
        ipaddress.ip_address(host)
        raise EgressError("IP literal destinations are denied by default")
    except ValueError:
        pass
    except EgressError:
        raise
    canon, _ = canonicalize_hostname(host, allow_wildcard=False)
    return canon, port


def _parse_egress_state(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise EgressError("egress-control.json must be a JSON object")
    version = raw.get("schema_version")
    if version != EGRESS_SCHEMA_VERSION:
        raise EgressError("unsupported egress-control schema_version: %s" % version)
    profiles = raw.get("egress_profiles")
    if not isinstance(profiles, dict):
        raise EgressError("egress_profiles must be an object")
    return {
        "schema_version": EGRESS_SCHEMA_VERSION,
        "egress_profiles": profiles,
    }


def validate_egress_state(state: dict) -> None:
    if not isinstance(state, dict):
        raise EgressError("invalid egress state")
    if state.get("schema_version") != EGRESS_SCHEMA_VERSION:
        raise EgressError("unsupported egress-control schema_version")
    profiles = state.get("egress_profiles")
    if not isinstance(profiles, dict):
        raise EgressError("egress_profiles must be an object")
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
        for src in sources:
            if not isinstance(src, dict):
                raise EgressError("invalid source entry in %s" % pid)
            cidr = canonicalize_cidr(src.get("cidr") or "")
            if cidr in seen_cidrs:
                raise EgressError("duplicate source CIDR in %s: %s" % (pid, cidr))
            seen_cidrs.add(cidr)
        seen_dests: set[tuple[str, int, str]] = set()
        for dest in destinations:
            if not isinstance(dest, dict):
                raise EgressError("invalid destination entry in %s" % pid)
            host, mode = canonicalize_hostname(dest.get("host") or "", allow_wildcard=True)
            port = validate_port(dest.get("port"))
            stored_mode = str(dest.get("match") or mode).lower()
            if stored_mode not in ("exact", "wildcard"):
                raise EgressError("invalid destination match mode in %s" % pid)
            if stored_mode != mode:
                # Policy host form must agree with match mode.
                if mode == "wildcard" and stored_mode != "wildcard":
                    raise EgressError("wildcard host requires match=wildcard")
                if mode == "exact" and stored_mode == "wildcard":
                    raise EgressError("exact host cannot use match=wildcard")
            key = (host, port, stored_mode)
            if key in seen_dests:
                raise EgressError("duplicate destination in %s: %s:%s" % (pid, host, port))
            seen_dests.add(key)


def load_egress_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    path = path or egress_control_path(cfg)
    if not path.is_file():
        raise EgressError("egress-control.json is missing: %s" % path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EgressError("egress-control.json is unreadable or corrupt") from exc
    state = _parse_egress_state(raw)
    validate_egress_state(state)
    return state


def require_egress_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    return load_egress_state(path=path, cfg=cfg)


def initialize_egress_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    path = path or egress_control_path(cfg)
    state = empty_egress_state()
    if path.is_file():
        return load_egress_state(path=path, cfg=cfg)
    with FileLock(egress_lock_path(path)):
        if path.is_file():
            return load_egress_state(path=path, cfg=cfg)
        atomic_write_json(path, state)
    return state


def save_egress_state(state: dict, path: Optional[Path] = None, cfg: Optional[dict] = None) -> None:
    path = path or egress_control_path(cfg)
    validate_egress_state(state)
    with FileLock(egress_lock_path(path)):
        atomic_write_json(path, state)


def mutate_egress_state(mutator, path: Optional[Path] = None, cfg: Optional[dict] = None):
    path = path or egress_control_path(cfg)
    with FileLock(egress_lock_path(path)):
        state = require_egress_state(path=path, cfg=cfg)
        result = mutator(state)
        validate_egress_state(state)
        atomic_write_json(path, state)
        return result if result is not None else state


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
    enabled: bool = True,
) -> tuple[str, dict]:
    name = validate_profile_name(name)
    desc = str(description or "")
    if len(desc) > DESCRIPTION_MAX_LEN:
        raise EgressError("description too long")
    for _pid, existing in (state.get("egress_profiles") or {}).items():
        if str(existing.get("name") or "").lower() == name.lower():
            raise EgressError("egress profile already exists: %s" % name)
    pid = _new_id(PROFILE_ID_PREFIX)
    now = utc_now_iso()
    record = {
        "id": pid,
        "name": name,
        "description": desc,
        "enabled": bool(enabled),
        "sources": [],
        "destinations": [],
        "created_at": now,
        "updated_at": now,
    }
    state.setdefault("egress_profiles", {})[pid] = record
    return pid, record


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
    profile["enabled"] = bool(enabled)
    profile["updated_at"] = utc_now_iso()
    return pid, profile


def delete_profile(state: dict, selector: str) -> tuple[str, dict]:
    pid, profile = resolve_profile(state, selector)
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
) -> tuple[str, dict, dict]:
    pid, profile = resolve_profile(state, selector)
    canon_host, match_mode = canonicalize_hostname(host, allow_wildcard=True)
    port_i = validate_port(port)
    for existing in profile.get("destinations") or []:
        if (
            str(existing.get("host") or "").lower() == canon_host
            and int(existing.get("port")) == port_i
            and str(existing.get("match") or "exact") == match_mode
        ):
            raise EgressError("destination already present: %s:%s" % (canon_host, port_i))
    entry = {
        "id": _new_id(DEST_ID_PREFIX),
        "host": canon_host,
        "port": port_i,
        "match": match_mode,
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
                canon, mode = canonicalize_hostname(host_part, allow_wildcard=True)
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


def destination_matches(host: str, port: int, destinations: list) -> Optional[dict]:
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
        if hostname_matches(host, entry.get("host") or "", entry.get("match") or "exact"):
            return entry
    return None


def authorize_request(
    state: Optional[dict],
    *,
    source_ip: str,
    hostname: str,
    port: int,
    load_error: Optional[str] = None,
) -> dict:
    """Authorize an egress request. Always fail closed.

    Returns dict with decision, reason, profile_id, profile_name, matched_source,
    matched_destination.
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
    }
    if load_error is not None:
        base["reason"] = REASON_POLICY_INVALID
        return base
    if state is None:
        base["reason"] = REASON_POLICY_MISSING
        return base
    try:
        validate_egress_state(state)
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

        # Evaluate enabled profiles. First full match wins (deterministic by name).
        saw_source_match = False
        saw_disabled_with_match = False
        for pid, profile in profiles:
            sources = profile.get("sources") or []
            destinations = profile.get("destinations") or []
            src = source_matches_cidr_list(source_ip, sources)
            if src is None:
                continue
            saw_source_match = True
            dest = destination_matches(host, port_i, destinations)
            if dest is None:
                continue
            if not profile.get("enabled", False):
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
            }

        if saw_disabled_with_match:
            base["reason"] = REASON_PROFILE_DISABLED
        elif not saw_source_match:
            base["reason"] = REASON_SOURCE_NOT_ALLOWED
        else:
            base["reason"] = REASON_DESTINATION_NOT_ALLOWED
        base["hostname"] = host
        base["port"] = port_i
        return base
    except EgressError as exc:
        msg = str(exc)
        if "IP literal" in msg:
            base["reason"] = REASON_IP_LITERAL_DENIED
        elif "invalid" in msg.lower() or "malformed" in msg.lower():
            base["reason"] = REASON_MALFORMED_REQUEST
        else:
            base["reason"] = REASON_POLICY_INVALID
        return base
    except Exception:
        base["reason"] = REASON_AUTHORIZATION_ERROR
        return base


def emit_conn_log(event: dict, path: Optional[Path] = None, cfg: Optional[dict] = None) -> None:
    """Best-effort connection log. Never raises. Never logs secrets/payloads."""
    try:
        path = path or conn_log_path(cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        lock = path.parent / (path.name + ".lock")
        with FileLock(lock):
            _rotate_conn_log(path)
            record = {
                "timestamp": event.get("timestamp") or utc_now_iso(),
                "source_ip": event.get("source_ip"),
                "hostname": event.get("hostname"),
                "port": event.get("port"),
                "method": event.get("method"),
                "profile_id": event.get("profile_id"),
                "profile_name": event.get("profile_name"),
                "decision": event.get("decision"),
                "reason": event.get("reason"),
            }
            # Optional safe SNI audit field (hostname only — never raw ClientHello).
            observed_sni = event.get("observed_sni")
            if observed_sni is not None:
                record["observed_sni"] = str(observed_sni)[:253]
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            if not path.exists():
                path.write_text(line, encoding="utf-8")
                os.chmod(path, 0o600)
            else:
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(line)
                    handle.flush()
    except Exception:
        return


def _rotate_conn_log(path: Path) -> None:
    try:
        if not path.is_file() or path.stat().st_size < CONN_LOG_MAX_BYTES:
            return
        for idx in range(CONN_LOG_KEEP, 0, -1):
            src = Path("%s.%d" % (path, idx - 1)) if idx > 1 else path
            dst = Path("%s.%d" % (path, idx))
            if src.is_file():
                if idx == CONN_LOG_KEEP and dst.is_file():
                    dst.unlink()
                if src != path or not dst.exists():
                    os.replace(src, dst)
        path.write_text("", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        return


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
    if not profiles:
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
    if enabled_open == 0:
        issues.append(
            {
                "class": "EGRESS_CONFIG_INFO",
                "severity": "info",
                "message": "no enabled egress profile has both sources and destinations",
            }
        )
    return issues
