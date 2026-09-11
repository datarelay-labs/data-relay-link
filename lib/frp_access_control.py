#!/usr/bin/env python3
"""Named Access Lists, TTL entries, and connection authorization for Data Relay Link.

Authoritative state lives in /var/lib/drlink/access-control.json.
Runtime authorization is evaluated by the NewUserConn plugin using an
in-memory cache derived from that file plus registry.json proxy mapping.

Backward compatible: missing access metadata means PUBLIC.
ALLOWLIST failures fail closed (DENY).
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
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

ACCESS_SCHEMA_VERSION = 1
DEFAULT_ACCESS_PATH = "/var/lib/drlink/access-control.json"
DEFAULT_CONN_LOG_PATH = "/var/log/drlink/access-conn.jsonl"
DEFAULT_PLUGIN_ADDR = "127.0.0.1:6101"
DEFAULT_PLUGIN_PATH = "/access-auth"
ACCESS_LIST_ID_PREFIX = "acl_"
ACCESS_LIST_ID_HEX_LEN = 12
ENTRY_ID_PREFIX = "ace_"
ENTRY_ID_HEX_LEN = 12

MODE_PUBLIC = "PUBLIC"
MODE_ALLOWLIST = "ALLOWLIST"
VALID_MODES = frozenset({MODE_PUBLIC, MODE_ALLOWLIST})

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"

REASON_PUBLIC = "PUBLIC"
REASON_CIDR_MATCH = "CIDR_MATCH"
REASON_SOURCE_NOT_ALLOWED = "SOURCE_NOT_ALLOWED"
REASON_ENTRY_EXPIRED = "ENTRY_EXPIRED"
REASON_ACCESS_LIST_MISSING = "ACCESS_LIST_MISSING"
REASON_POLICY_INVALID = "POLICY_INVALID"
REASON_AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
REASON_EMPTY_ALLOWLIST = "EMPTY_ALLOWLIST"
REASON_UNMAPPED_PROXY = "UNMAPPED_PROXY"
REASON_SERVICE_DISABLED = "SERVICE_DISABLED"

EMPTY_ALLOWLIST_MESSAGE = (
    "No allowed sources are configured.\n"
    "An empty ALLOWLIST would block every user connection.\n"
    "Use Disable if you intend to stop publishing the service."
)

PUBLIC_EXPOSURE_LINES = (
    "Exposure      : PUBLIC",
    "Source policy : Any source that can reach this public port may attempt a connection",
    "Target auth   : SSH/application authentication is still required",
    "",
    "Recommended:",
    "  Restrict this service with an Access List if public access is not intended.",
)


def print_public_exposure_notice(*, service_id=None, heading=False):
    """Operator-facing PUBLIC exposure summary (no secrets)."""
    if heading:
        print()
        print("Public exposure")
        print("===============")
        print()
    if service_id:
        print("Service %s is publicly reachable." % service_id)
        print()
    for line in PUBLIC_EXPOSURE_LINES:
        print(line)

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,63}$")
ENTRY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,63}$")
TTL_RE = re.compile(r"^(\d+)([smhd])$", re.IGNORECASE)

CONN_LOG_MAX_BYTES = 5 * 1024 * 1024
CONN_LOG_KEEP = 5
CONN_LOG_MAX_AGE_DAYS = 7


class AccessError(Exception):
    """User-facing access-control error."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_iso_ts(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AccessError("invalid expires_at timestamp: %s" % value) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0)


def format_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def access_control_path(cfg: Optional[dict] = None) -> Path:
    configured = ""
    if isinstance(cfg, dict):
        configured = str(cfg.get("access_control_file") or "").strip()
    if not configured:
        configured = os.environ.get("FRP_ACCESS_CONTROL_FILE", "") or DEFAULT_ACCESS_PATH
    return _rooted(configured)


def conn_log_path(cfg: Optional[dict] = None) -> Path:
    configured = ""
    if isinstance(cfg, dict):
        configured = str(cfg.get("access_conn_log_file") or "").strip()
    if not configured:
        configured = os.environ.get("FRP_ACCESS_CONN_LOG", "") or DEFAULT_CONN_LOG_PATH
    return _rooted(configured)


def registry_path_from_cfg(cfg: dict) -> Path:
    path = Path(cfg["registry_file"])
    root = deploy_root()
    if root and not str(path).startswith(root):
        path = Path(root + str(path))
    return path


def access_lock_path(path: Path) -> Path:
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


def empty_access_state() -> dict:
    return {
        "schema_version": ACCESS_SCHEMA_VERSION,
        "access_lists": {},
        "service_access": {},
    }


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


def _parse_access_state(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise AccessError("access-control.json must be a JSON object")
    version = raw.get("schema_version")
    if version != ACCESS_SCHEMA_VERSION:
        raise AccessError("unsupported access-control schema version %s" % version)
    if not isinstance(raw.get("access_lists"), dict):
        raise AccessError("access_lists must be an object")
    if not isinstance(raw.get("service_access"), dict):
        raise AccessError("service_access must be an object")
    return raw


def require_access_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    """Load authoritative Access Control state. Missing file is corruption."""
    path = path or access_control_path(cfg)
    if not path.exists():
        raise AccessError(
            "access-control.json is missing (authoritative Access Control state required)"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AccessError("access-control.json is unreadable: %s" % exc) from exc
    return _parse_access_state(raw)


def load_access_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    """Load Access Control state for installed runtime (missing → error).

    Installer/init must call initialize_access_state() explicitly. Soft-empty
    fallback is intentionally not used here so missing policy cannot become
    PUBLIC via mutation or display paths.
    """
    return require_access_state(path=path, cfg=cfg)


def initialize_access_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    """Explicit install/init: create empty Access Control state when absent."""
    path = path or access_control_path(cfg)
    if path.exists():
        return require_access_state(path=path, cfg=cfg)
    state = empty_access_state()
    save_access_state(state, path=path, cfg=cfg)
    return state


def save_access_state(state: dict, path: Optional[Path] = None, cfg: Optional[dict] = None) -> None:
    path = path or access_control_path(cfg)
    state = dict(state)
    state["schema_version"] = ACCESS_SCHEMA_VERSION
    validate_access_state(state)
    locks = _locks()
    try:
        with _control_state_mutation_lock(path):
            with FileLock(access_lock_path(path)):
                atomic_write_json(path, state)
    except locks.LockTimeout as exc:
        raise AccessError("timed out waiting for control-state lock") from exc


def mutate_access_state(mutator, path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    path = path or access_control_path(cfg)
    locks = _locks()
    try:
        with _control_state_mutation_lock(path):
            with FileLock(access_lock_path(path)):
                state = require_access_state(path=path, cfg=cfg)
                result = mutator(state)
                validate_access_state(state)
                atomic_write_json(path, state)
                return result if result is not None else state
    except locks.LockTimeout as exc:
        raise AccessError("timed out waiting for control-state lock") from exc


def validate_list_name(name: str) -> str:
    text = str(name or "").strip()
    if not text or not NAME_RE.match(text):
        raise AccessError(
            "invalid access list name (1-64 chars; letters, digits, space, ._-/) "
            "starting with alphanumeric"
        )
    return text


def validate_entry_name(name: str) -> str:
    text = str(name or "").strip()
    if not text or not ENTRY_NAME_RE.match(text):
        raise AccessError(
            "invalid source name (1-64 chars; letters, digits, space, ._-/) "
            "starting with alphanumeric"
        )
    return text


def canonicalize_cidr(source: str) -> str:
    text = str(source or "").strip()
    if not text:
        raise AccessError("source CIDR/address is required")
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
        raise AccessError("invalid IP/CIDR: %s" % source) from exc
    return net.with_prefixlen


def parse_ttl(text: str, now: Optional[datetime] = None) -> datetime:
    raw = str(text or "").strip().lower()
    match = TTL_RE.match(raw)
    if not match:
        raise AccessError("invalid TTL (use Ns/Nm/Nh/Nd, e.g. 30m, 4h, 1d)")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if amount <= 0:
        raise AccessError("TTL must be positive")
    delta = {
        "s": timedelta(seconds=amount),
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
    }[unit]
    base = now or utc_now()
    return (base + delta).replace(microsecond=0)


def generate_id(prefix: str, hex_len: int, existing: set[str]) -> str:
    for _ in range(64):
        value = prefix + secrets.token_hex(hex_len // 2)
        if value not in existing:
            return value
    raise AccessError("unable to allocate unique id")


def sanitize_host_id_part(hostname: str) -> str:
    """Match install-client HOST_SAFE: tr -cs 'A-Za-z0-9._-' '-'."""
    text = str(hostname or "")
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text)


def expected_host_id(hostname: str, machine_id: str) -> str:
    mid = str(machine_id or "")
    return "%s-%s" % (sanitize_host_id_part(hostname), mid[:8])


def expected_proxy_name(hostname: str, machine_id: str, service_id: str) -> str:
    return "%s-%s" % (expected_host_id(hostname, machine_id), str(service_id).strip().lower())


def validate_access_state(state: dict) -> None:
    if not isinstance(state, dict):
        raise AccessError("access state must be an object")
    if state.get("schema_version") != ACCESS_SCHEMA_VERSION:
        raise AccessError("unsupported access-control schema version")
    lists = state.get("access_lists")
    bindings = state.get("service_access")
    if not isinstance(lists, dict) or not isinstance(bindings, dict):
        raise AccessError("access_lists and service_access must be objects")
    names = {}
    for lid, lst in lists.items():
        if not isinstance(lst, dict):
            raise AccessError("access list %s must be an object" % lid)
        if str(lst.get("id") or "") != str(lid):
            raise AccessError("access list id mismatch for %s" % lid)
        name = validate_list_name(lst.get("name") or "")
        key = name.lower()
        if key in names:
            raise AccessError("duplicate access list name: %s" % name)
        names[key] = lid
        entries = lst.get("entries")
        if not isinstance(entries, list):
            raise AccessError("access list entries must be an array")
        seen_cidr = set()
        entry_ids = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise AccessError("access list entry must be an object")
            eid = str(entry.get("id") or "")
            if not eid or eid in entry_ids:
                raise AccessError("access list entry id missing or duplicate")
            entry_ids.add(eid)
            validate_entry_name(entry.get("name") or "")
            cidr = canonicalize_cidr(entry.get("cidr") or "")
            if cidr in seen_cidr:
                raise AccessError("duplicate equivalent CIDR in list: %s" % cidr)
            seen_cidr.add(cidr)
            entry["cidr"] = cidr
            if entry.get("expires_at") is not None:
                parse_iso_ts(entry.get("expires_at"))
    for mid, services in bindings.items():
        if not isinstance(services, dict):
            raise AccessError("service_access[%s] must be an object" % mid)
        for sid, binding in services.items():
            if not isinstance(binding, dict):
                raise AccessError("service binding must be an object")
            mode = str(binding.get("access_mode") or MODE_PUBLIC).upper()
            if mode not in VALID_MODES:
                raise AccessError("invalid access_mode: %s" % mode)
            binding["access_mode"] = mode
            list_id = binding.get("access_list_id")
            if mode == MODE_PUBLIC:
                binding["access_list_id"] = None
            else:
                if not list_id or str(list_id) not in lists:
                    raise AccessError(
                        "ALLOWLIST binding for %s/%s references missing list" % (mid, sid)
                    )


def find_list_by_name(state: dict, name: str, exclude_id: Optional[str] = None) -> Optional[str]:
    want = str(name or "").strip().lower()
    for lid, lst in (state.get("access_lists") or {}).items():
        if exclude_id and lid == exclude_id:
            continue
        if str((lst or {}).get("name") or "").strip().lower() == want:
            return lid
    return None


def resolve_access_list(state: dict, selector: str) -> tuple[str, dict]:
    query = str(selector or "").strip()
    if not query:
        raise AccessError("missing access list selector")
    lists = state.get("access_lists") or {}
    if query in lists and isinstance(lists[query], dict):
        return query, lists[query]
    # unique id prefix
    prefix_hits = [
        (lid, lst) for lid, lst in lists.items()
        if isinstance(lst, dict) and lid.startswith(query)
    ]
    if len(prefix_hits) == 1:
        return prefix_hits[0]
    if len(prefix_hits) > 1:
        raise AccessError("ambiguous access list id prefix: %s" % query)
    by_name = find_list_by_name(state, query)
    if by_name:
        return by_name, lists[by_name]
    raise AccessError("access list not found: %s" % query)


def list_services_using(state: dict, list_id: str) -> list[tuple[str, str]]:
    used = []
    for mid, services in (state.get("service_access") or {}).items():
        if not isinstance(services, dict):
            continue
        for sid, binding in services.items():
            if not isinstance(binding, dict):
                continue
            if binding.get("access_mode") == MODE_ALLOWLIST and binding.get("access_list_id") == list_id:
                used.append((mid, sid))
    used.sort()
    return used


def get_service_binding(state: dict, machine_id: str, service_id: str) -> dict:
    services = (state.get("service_access") or {}).get(machine_id) or {}
    binding = services.get(service_id) if isinstance(services, dict) else None
    if not isinstance(binding, dict):
        return {"access_mode": MODE_PUBLIC, "access_list_id": None}
    mode = str(binding.get("access_mode") or MODE_PUBLIC).upper()
    if mode not in VALID_MODES:
        return {"access_mode": MODE_PUBLIC, "access_list_id": None}
    list_id = binding.get("access_list_id")
    if mode == MODE_PUBLIC:
        list_id = None
    return {"access_mode": mode, "access_list_id": list_id}


def set_service_binding(state: dict, machine_id: str, service_id: str, mode: str, list_id=None) -> None:
    mode = str(mode or MODE_PUBLIC).upper()
    if mode not in VALID_MODES:
        raise AccessError("invalid access_mode")
    sid = str(service_id).strip().lower()
    mid = str(machine_id)
    service_access = state.setdefault("service_access", {})
    client_map = service_access.setdefault(mid, {})
    if mode == MODE_PUBLIC:
        # Persist explicit PUBLIC only if previously present; otherwise omit for compact state.
        if sid in client_map:
            client_map[sid] = {"access_mode": MODE_PUBLIC, "access_list_id": None}
        else:
            # Explicit set to PUBLIC — store for clarity when operator chose it.
            client_map[sid] = {"access_mode": MODE_PUBLIC, "access_list_id": None}
        return
    if not list_id or list_id not in (state.get("access_lists") or {}):
        raise AccessError("ALLOWLIST requires an existing access list")
    entries = (state["access_lists"][list_id].get("entries") or [])
    if not entries or not list_has_usable_entries({"entries": entries}):
        raise AccessError(EMPTY_ALLOWLIST_MESSAGE)
    client_map[sid] = {"access_mode": MODE_ALLOWLIST, "access_list_id": list_id}


def clear_service_binding(state: dict, machine_id: str, service_id: str) -> bool:
    mid = str(machine_id)
    sid = str(service_id).strip().lower()
    service_access = state.get("service_access") or {}
    client_map = service_access.get(mid)
    if not isinstance(client_map, dict) or sid not in client_map:
        return False
    client_map.pop(sid, None)
    if not client_map:
        service_access.pop(mid, None)
    return True


def clear_client_bindings(state: dict, machine_id: str) -> int:
    service_access = state.get("service_access") or {}
    client_map = service_access.pop(str(machine_id), None)
    if not isinstance(client_map, dict):
        return 0
    return len(client_map)


def create_access_list(state: dict, name: str, description: str = "") -> tuple[str, dict]:
    name = validate_list_name(name)
    if find_list_by_name(state, name):
        raise AccessError("access list name already exists: %s" % name)
    lists = state.setdefault("access_lists", {})
    lid = generate_id(ACCESS_LIST_ID_PREFIX, ACCESS_LIST_ID_HEX_LEN, set(lists))
    record = {
        "id": lid,
        "name": name,
        "description": str(description or "").strip(),
        "entries": [],
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
    }
    lists[lid] = record
    return lid, record


def update_access_list_info(state: dict, list_id: str, name=None, description=None) -> dict:
    lst = (state.get("access_lists") or {}).get(list_id)
    if not isinstance(lst, dict):
        raise AccessError("access list not found")
    if name is not None:
        name = validate_list_name(name)
        other = find_list_by_name(state, name, exclude_id=list_id)
        if other:
            raise AccessError("access list name already exists: %s" % name)
        lst["name"] = name
    if description is not None:
        lst["description"] = str(description).strip()
    lst["updated_at"] = utc_now_iso()
    return lst


def delete_access_list(state: dict, list_id: str) -> None:
    used = list_services_using(state, list_id)
    if used:
        lines = ["Cannot delete Access List that is still referenced.", "", "Used by:"]
        for mid, sid in used:
            lines.append("  %s:%s" % (mid[:12], sid))
        lines.append("")
        lines.append("Change those services to PUBLIC or another Access List first.")
        raise AccessError("\n".join(lines))
    lists = state.get("access_lists") or {}
    if list_id not in lists:
        raise AccessError("access list not found")
    lists.pop(list_id, None)


def list_has_usable_entries(access_list: dict, now: Optional[datetime] = None) -> bool:
    now = now or utc_now()
    entries = access_list.get("entries") if isinstance(access_list, dict) else None
    if not isinstance(entries, list):
        return False
    return any(entry_is_active(entry, now) for entry in entries if isinstance(entry, dict))


def ensure_referenced_list_keeps_usable(
    state: dict, list_id: str, now: Optional[datetime] = None
) -> None:
    """Referenced ALLOWLIST must keep at least one usable source after mutation."""
    if not list_services_using(state, list_id):
        return
    lst = (state.get("access_lists") or {}).get(list_id)
    if not isinstance(lst, dict) or not list_has_usable_entries(lst, now=now):
        raise AccessError(EMPTY_ALLOWLIST_MESSAGE)


def find_source_entry(state: dict, list_id: str, selector: str) -> dict:
    lst = (state.get("access_lists") or {}).get(list_id)
    if not isinstance(lst, dict):
        raise AccessError("access list not found")
    entries = lst.get("entries") or []
    query = str(selector or "").strip()
    if not query:
        raise AccessError("missing source selector")
    for entry in entries:
        if entry.get("id") == query:
            return entry
    try:
        want = canonicalize_cidr(query)
    except AccessError:
        want = None
    if want:
        for entry in entries:
            if canonicalize_cidr(entry.get("cidr") or "") == want:
                return entry
    hits = [e for e in entries if str(e.get("name") or "").lower() == query.lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise AccessError("ambiguous source name: %s" % query)
    raise AccessError("source entry not found: %s" % query)


def add_source_entry(
    state: dict,
    list_id: str,
    name: str,
    source: str,
    ttl: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> dict:
    lst = (state.get("access_lists") or {}).get(list_id)
    if not isinstance(lst, dict):
        raise AccessError("access list not found")
    name = validate_entry_name(name)
    cidr = canonicalize_cidr(source)
    entries = lst.setdefault("entries", [])
    for entry in entries:
        if canonicalize_cidr(entry.get("cidr") or "") == cidr:
            raise AccessError("equivalent CIDR already present: %s" % cidr)
    exp = None
    if expires_at is not None and str(expires_at).strip() != "":
        exp = parse_iso_ts(expires_at)
    elif ttl:
        exp = parse_ttl(ttl)
    eid = generate_id(ENTRY_ID_PREFIX, ENTRY_ID_HEX_LEN, {e.get("id") for e in entries})
    record = {
        "id": eid,
        "name": name,
        "cidr": cidr,
        "expires_at": format_iso(exp),
        "created_at": utc_now_iso(),
    }
    entries.append(record)
    lst["updated_at"] = utc_now_iso()
    return record


def remove_source_entry(state: dict, list_id: str, selector: str) -> dict:
    lst = (state.get("access_lists") or {}).get(list_id)
    if not isinstance(lst, dict):
        raise AccessError("access list not found")
    entries = lst.get("entries") or []
    target = find_source_entry(state, list_id, selector)
    remaining = [entry for entry in entries if entry is not target]
    if list_services_using(state, list_id) and not list_has_usable_entries({"entries": remaining}):
        raise AccessError(EMPTY_ALLOWLIST_MESSAGE)
    entries.remove(target)
    lst["updated_at"] = utc_now_iso()
    return target


def replace_source_entry(
    state: dict,
    list_id: str,
    selector: str,
    name: str,
    source: str,
    ttl: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> dict:
    """Validate new values, then replace an existing entry in one state mutation."""
    lst = (state.get("access_lists") or {}).get(list_id)
    if not isinstance(lst, dict):
        raise AccessError("access list not found")
    target = find_source_entry(state, list_id, selector)
    name = validate_entry_name(name)
    cidr = canonicalize_cidr(source)
    exp = None
    if expires_at is not None and str(expires_at).strip() != "":
        exp = parse_iso_ts(expires_at)
    elif ttl:
        exp = parse_ttl(ttl)
    for entry in lst.get("entries") or []:
        if entry is target:
            continue
        if canonicalize_cidr(entry.get("cidr") or "") == cidr:
            raise AccessError("equivalent CIDR already present: %s" % cidr)
    # Preview usability with the replacement applied before mutating.
    preview_entry = dict(target)
    preview_entry["name"] = name
    preview_entry["cidr"] = cidr
    preview_entry["expires_at"] = format_iso(exp)
    preview_entries = [
        preview_entry if entry is target else entry for entry in (lst.get("entries") or [])
    ]
    if list_services_using(state, list_id) and not list_has_usable_entries(
        {"entries": preview_entries}
    ):
        raise AccessError(EMPTY_ALLOWLIST_MESSAGE)
    target["name"] = name
    target["cidr"] = cidr
    target["expires_at"] = format_iso(exp)
    lst["updated_at"] = utc_now_iso()
    return target


def remove_expired_entries(state: dict, list_id: str, now: Optional[datetime] = None) -> list:
    lst = (state.get("access_lists") or {}).get(list_id)
    if not isinstance(lst, dict):
        raise AccessError("access list not found")
    now = now or utc_now()
    kept = []
    removed = []
    for entry in lst.get("entries") or []:
        exp = parse_iso_ts(entry.get("expires_at")) if entry.get("expires_at") else None
        if exp is not None and exp <= now:
            removed.append(entry)
        else:
            kept.append(entry)
    # Expired entries are already non-matching for authorization. Cleanup may
    # leave a referenced ALLOWLIST with zero usable sources; stay ALLOWLIST
    # (no PUBLIC fallback). Manual last-usable removal remains rejected elsewhere.
    lst["entries"] = kept
    if removed:
        lst["updated_at"] = utc_now_iso()
    return removed


def format_remaining(exp: Optional[datetime], now: Optional[datetime] = None) -> str:
    if exp is None:
        return "permanent"
    now = now or utc_now()
    if exp <= now:
        return "expired"
    delta = exp - now
    seconds = int(delta.total_seconds())
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append("%dd" % days)
    if hours:
        parts.append("%dh" % hours)
    if minutes or not parts:
        parts.append("%dm" % minutes)
    return "expires in %s" % " ".join(parts)


def entry_is_active(entry: dict, now: Optional[datetime] = None) -> bool:
    now = now or utc_now()
    if entry.get("expires_at") in (None, ""):
        return True
    exp = parse_iso_ts(entry.get("expires_at"))
    return exp is not None and exp > now


def parse_remote_addr(remote_addr: str) -> str:
    """Strip host:port / [ipv6]:port down to a bare IP string."""
    text = str(remote_addr or "").strip()
    if not text:
        raise AccessError("missing remote address")
    if text.startswith("["):
        end = text.find("]")
        if end <= 1:
            raise AccessError("invalid remote address: %s" % remote_addr)
        host = text[1:end]
    elif text.count(":") == 1:
        host = text.rsplit(":", 1)[0]
    else:
        # bare IPv6 without brackets, or host without port
        host = text
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError as exc:
        raise AccessError("invalid remote address: %s" % remote_addr) from exc


def build_proxy_map(registry: dict) -> dict[str, dict]:
    """Map FRP proxy_name -> {client_id, service_id, public_port, client_label, enabled}.

    Duplicate derived proxy names are a security identity collision — fail closed
    rather than last-write-wins.
    """
    mapping = {}
    collisions = {}
    clients = registry.get("clients") or {}
    if not isinstance(clients, dict):
        return mapping
    for mid, client in clients.items():
        if not isinstance(client, dict):
            continue
        hostname = client.get("hostname") or ""
        label = client.get("label") or ""
        services = client.get("services") or {}
        if not isinstance(services, dict):
            continue
        for sid, svc in services.items():
            if not isinstance(svc, dict):
                continue
            sid_s = str(sid).strip().lower()
            name = expected_proxy_name(hostname, mid, sid_s)
            entry = {
                "client_id": mid,
                "service_id": sid_s,
                "public_port": svc.get("remote_port"),
                "client_label": label,
                "enabled": bool(svc.get("enabled", True)),
                "hostname": hostname,
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
        raise AccessError(
            "derived proxy name collision (fail closed): %s" % "; ".join(owners)
        )
    return mapping


def validate_proxy_name_uniqueness(registry: dict) -> None:
    """Registry invariant: derived FRP proxy names must be unique."""
    build_proxy_map(registry)

def evaluate_source_against_list(
    access_list: dict,
    source_ip: str,
    now: Optional[datetime] = None,
) -> dict:
    now = now or utc_now()
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise AccessError("invalid source IP: %s" % source_ip) from exc
    entries = access_list.get("entries") if isinstance(access_list, dict) else None
    if not isinstance(entries, list) or not entries:
        return {
            "decision": DECISION_DENY,
            "reason": REASON_EMPTY_ALLOWLIST,
            "matched_entry": None,
        }
    expired_hit = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            net = ipaddress.ip_network(entry.get("cidr") or "", strict=False)
        except ValueError:
            return {
                "decision": DECISION_DENY,
                "reason": REASON_POLICY_INVALID,
                "matched_entry": None,
            }
        if addr not in net:
            continue
        exp = parse_iso_ts(entry.get("expires_at")) if entry.get("expires_at") else None
        if exp is not None and exp <= now:
            expired_hit = entry
            continue
        return {
            "decision": DECISION_ALLOW,
            "reason": REASON_CIDR_MATCH,
            "matched_entry": entry,
        }
    if expired_hit is not None:
        return {
            "decision": DECISION_DENY,
            "reason": REASON_ENTRY_EXPIRED,
            "matched_entry": expired_hit,
        }
    return {
        "decision": DECISION_DENY,
        "reason": REASON_SOURCE_NOT_ALLOWED,
        "matched_entry": None,
    }


def authorize(
    access_state: dict,
    registry: dict,
    *,
    proxy_name: Optional[str] = None,
    client_id: Optional[str] = None,
    service_id: Optional[str] = None,
    source_ip: str,
    now: Optional[datetime] = None,
) -> dict:
    """Authorize a user connection. Fail closed for ALLOWLIST problems."""
    now = now or utc_now()
    result = {
        "timestamp": format_iso(now),
        "client_id": None,
        "client_label": None,
        "service_id": None,
        "public_port": None,
        "source_ip": None,
        "access_mode": MODE_PUBLIC,
        "access_list_id": None,
        "access_list_name": None,
        "matched_entry_id": None,
        "matched_entry_name": None,
        "decision": DECISION_DENY,
        "reason": REASON_AUTHORIZATION_ERROR,
        "proxy_name": proxy_name,
    }
    try:
        try:
            result["source_ip"] = str(ipaddress.ip_address(str(source_ip).strip()))
        except ValueError:
            result["source_ip"] = parse_remote_addr(source_ip)

        mapped = None
        if proxy_name:
            mapped = build_proxy_map(registry).get(proxy_name)
            if mapped is None:
                # Mapping failure must fail closed. Never treat unmapped
                # managed-proxy names as PUBLIC / ALLOWLIST bypass.
                result.update(
                    {
                        "decision": DECISION_DENY,
                        "reason": REASON_UNMAPPED_PROXY,
                        "access_mode": MODE_ALLOWLIST,
                    }
                )
                return result
            client_id = mapped["client_id"]
            service_id = mapped["service_id"]
            result["public_port"] = mapped.get("public_port")
            result["client_label"] = mapped.get("client_label") or None
            # Authoritative registry enabled=false must deny even if a stale
            # frpc still presents the proxy (do not rely on client cleanup).
            if not mapped.get("enabled", True):
                result["client_id"] = client_id
                result["service_id"] = str(service_id).strip().lower()
                result["decision"] = DECISION_DENY
                result["reason"] = REASON_SERVICE_DISABLED
                return result
        if not client_id or not service_id:
            result["reason"] = REASON_POLICY_INVALID
            return result

        result["client_id"] = client_id
        result["service_id"] = str(service_id).strip().lower()
        client = (registry.get("clients") or {}).get(client_id) or {}
        if isinstance(client, dict):
            result["client_label"] = result["client_label"] or client.get("label") or None
            svc = (client.get("services") or {}).get(result["service_id"]) or {}
            if isinstance(svc, dict):
                if result["public_port"] is None:
                    result["public_port"] = svc.get("remote_port")
                # Fail closed when authorizing by client_id/service_id directly.
                if not bool(svc.get("enabled", True)):
                    result["decision"] = DECISION_DENY
                    result["reason"] = REASON_SERVICE_DISABLED
                    return result

        binding = get_service_binding(access_state, client_id, result["service_id"])
        result["access_mode"] = binding["access_mode"]
        result["access_list_id"] = binding.get("access_list_id")

        if binding["access_mode"] == MODE_PUBLIC:
            result["decision"] = DECISION_ALLOW
            result["reason"] = REASON_PUBLIC
            return result

        list_id = binding.get("access_list_id")
        access_list = (access_state.get("access_lists") or {}).get(list_id)
        if not isinstance(access_list, dict):
            result["decision"] = DECISION_DENY
            result["reason"] = REASON_ACCESS_LIST_MISSING
            return result
        result["access_list_name"] = access_list.get("name")
        verdict = evaluate_source_against_list(access_list, result["source_ip"], now=now)
        result["decision"] = verdict["decision"]
        result["reason"] = verdict["reason"]
        matched = verdict.get("matched_entry")
        if isinstance(matched, dict):
            result["matched_entry_id"] = matched.get("id")
            result["matched_entry_name"] = matched.get("name")
        return result
    except AccessError:
        result["decision"] = DECISION_DENY
        result["reason"] = REASON_POLICY_INVALID
        return result
    except Exception:
        result["decision"] = DECISION_DENY
        result["reason"] = REASON_AUTHORIZATION_ERROR
        return result


def _rotate_conn_log(path: Path) -> None:
    try:
        if not path.exists():
            return
        if path.stat().st_size < CONN_LOG_MAX_BYTES:
            # age-based prune of rotated files
            cutoff = time.time() - CONN_LOG_MAX_AGE_DAYS * 86400
            for sibling in path.parent.glob(path.name + ".*"):
                try:
                    if sibling.is_file() and sibling.stat().st_mtime < cutoff:
                        sibling.unlink()
                except OSError:
                    pass
            return
        # size rotate
        for idx in range(CONN_LOG_KEEP, 0, -1):
            src = path.with_name("%s.%d" % (path.name, idx))
            dst = path.with_name("%s.%d" % (path.name, idx + 1))
            if idx == CONN_LOG_KEEP and src.exists():
                try:
                    src.unlink()
                except OSError:
                    pass
            elif src.exists():
                os.replace(src, dst)
        os.replace(path, path.with_name(path.name + ".1"))
    except OSError:
        pass


def emit_conn_log(event: dict, path: Optional[Path] = None, cfg: Optional[dict] = None) -> None:
    """Best-effort bounded connection authorization log. Never raises to callers.

    Flock the log inode (not a sidecar ``*.lock``) so traverse-only log
    directories remain compatible if the access plugin ever drops privileges.
    """
    try:
        path = path or conn_log_path(cfg)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        try:
            _rotate_conn_log(path)
        except OSError:
            pass
        record = {
            "timestamp": event.get("timestamp") or utc_now_iso(),
            "client_id": event.get("client_id"),
            "client_label": event.get("client_label"),
            "service_id": event.get("service_id"),
            "public_port": event.get("public_port"),
            "source_ip": event.get("source_ip"),
            "access_mode": event.get("access_mode"),
            "access_list_id": event.get("access_list_id"),
            "access_list_name": event.get("access_list_name"),
            "matched_entry_id": event.get("matched_entry_id"),
            "matched_entry_name": event.get("matched_entry_name"),
            "decision": event.get("decision"),
            "reason": event.get("reason"),
            "proxy_name": event.get("proxy_name"),
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        flags = os.O_WRONLY | os.O_APPEND
        if not path.exists():
            flags |= os.O_CREAT
        fd = os.open(str(path), flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if flags & os.O_CREAT:
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass
                try:
                    os.chmod(path.parent, 0o700)
                except OSError:
                    pass
            os.write(fd, line.encode("utf-8"))
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
    except Exception:
        return


def read_conn_log(
    path: Optional[Path] = None,
    cfg: Optional[dict] = None,
    *,
    client_id: Optional[str] = None,
    service_id: Optional[str] = None,
    decision: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    path = path or conn_log_path(cfg)
    files = []
    if path.exists():
        files.append(path)
    for idx in range(1, CONN_LOG_KEEP + 1):
        rotated = path.with_name("%s.%d" % (path.name, idx))
        if rotated.exists():
            files.append(rotated)
    events = []
    for file_path in files:
        try:
            for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict):
                    continue
                if client_id and item.get("client_id") != client_id:
                    continue
                if service_id and item.get("service_id") != service_id:
                    continue
                if decision and str(item.get("decision") or "").upper() != decision.upper():
                    continue
                events.append(item)
        except OSError:
            continue
    events.sort(key=lambda e: str(e.get("timestamp") or ""), reverse=True)
    return events[: max(0, int(limit))]


def doctor_issues(access_state: dict, registry: dict) -> list[dict]:
    """Return non-mutating diagnostic issue dicts."""
    issues = []
    try:
        validate_access_state(access_state)
    except AccessError as exc:
        issues.append({
            "class": "ACCESS_CONFIG_ERROR",
            "severity": "error",
            "message": str(exc),
        })
        return issues
    names = {}
    now = utc_now()
    for lid, lst in (access_state.get("access_lists") or {}).items():
        name = str((lst or {}).get("name") or "").lower()
        if name in names:
            issues.append({
                "class": "ACCESS_CONFIG_ERROR",
                "severity": "error",
                "message": "duplicate access list name %s" % name,
            })
        names[name] = lid
        for entry in (lst or {}).get("entries") or []:
            try:
                canonicalize_cidr(entry.get("cidr") or "")
            except AccessError as exc:
                issues.append({
                    "class": "ACCESS_CONFIG_ERROR",
                    "severity": "error",
                    "message": "invalid CIDR in %s: %s" % (lid, exc),
                })
            exp = entry.get("expires_at")
            if exp:
                try:
                    when = parse_iso_ts(exp)
                    if when and when <= now:
                        issues.append({
                            "class": "ACCESS_CONFIG_ERROR",
                            "severity": "info",
                            "message": "expired entry %s in list %s" % (entry.get("name"), lst.get("name")),
                        })
                except AccessError as exc:
                    issues.append({
                        "class": "ACCESS_CONFIG_ERROR",
                        "severity": "error",
                        "message": str(exc),
                    })
    clients = (registry.get("clients") or {}) if isinstance(registry, dict) else {}
    for mid, services in (access_state.get("service_access") or {}).items():
        if mid not in clients:
            issues.append({
                "class": "ACCESS_MAPPING_ERROR",
                "severity": "error",
                "message": "dangling bindings for unknown client %s" % mid,
            })
            continue
        client_services = (clients.get(mid) or {}).get("services") or {}
        for sid, binding in (services or {}).items():
            if sid not in client_services:
                issues.append({
                    "class": "ACCESS_MAPPING_ERROR",
                    "severity": "error",
                    "message": "dangling binding %s:%s" % (mid[:12], sid),
                })
            if not isinstance(binding, dict):
                continue
            if binding.get("access_mode") == MODE_ALLOWLIST:
                lid = binding.get("access_list_id")
                lst = (access_state.get("access_lists") or {}).get(lid)
                if not isinstance(lst, dict):
                    issues.append({
                        "class": "ACCESS_CONFIG_ERROR",
                        "severity": "error",
                        "message": "ALLOWLIST %s:%s missing list" % (mid[:12], sid),
                    })
                else:
                    usable = any(entry_is_active(e, now) for e in (lst.get("entries") or []))
                    if not usable:
                        issues.append({
                            "class": "ACCESS_CONFIG_ERROR",
                            "severity": "error",
                            "message": "ALLOWLIST %s:%s has no usable non-expired entries" % (mid[:12], sid),
                        })
    return issues
