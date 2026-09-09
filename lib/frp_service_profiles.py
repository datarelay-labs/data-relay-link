#!/usr/bin/env python3
"""Server-owned Service Profiles (creation templates only).

Authoritative state lives in /var/lib/frp-auto-deploy/service-profiles.json.

Profiles seed client service drafts. They never store remote_port, CLIENT ID,
Service ID, or ACL assignments. Editing or deleting a profile must not mutate
existing services.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

PROFILES_SCHEMA_VERSION = 1
DEFAULT_PROFILES_PATH = "/var/lib/frp-auto-deploy/service-profiles.json"
PROFILE_ID_PREFIX = "prof_"
PROFILE_ID_HEX_LEN = 12
PROFILE_ID_RE = re.compile(r"^prof_[0-9a-f]{12}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
NAME_MAX_LEN = 64
DESCRIPTION_MAX_LEN = 1024
SSH_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,32}$")
PRESETS = frozenset({"ssh", "http", "https", "custom"})
DEFAULT_PORTS = {"ssh": 22, "http": 80, "https": 443}
FORBIDDEN_PROFILE_KEYS = frozenset(
    {
        "remote_port",
        "client_id",
        "machine_id",
        "service_id",
        "access_mode",
        "access_list_id",
        "access_list",
        "acl_id",
    }
)


class ProfileError(Exception):
    """User-facing service-profile error."""


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


def service_profiles_path(cfg: Optional[dict] = None) -> Path:
    configured = ""
    if isinstance(cfg, dict):
        configured = str(cfg.get("service_profiles_file") or "").strip()
    if not configured:
        configured = os.environ.get("FRP_SERVICE_PROFILES_FILE", "") or DEFAULT_PROFILES_PATH
    return _rooted(configured)


def profiles_lock_path(path: Path) -> Path:
    return path.parent / (path.name + ".lock")


def empty_profiles_state() -> dict:
    return {"schema_version": PROFILES_SCHEMA_VERSION, "profiles": {}}


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


def _load_health_module():
    candidates = []
    root = deploy_root()
    if root:
        candidates.append(Path(root) / "usr/local/lib/frp-auto-deploy/frp_health_check.py")
    here = Path(__file__).resolve().parent
    candidates.extend(
        [
            here / "frp_health_check.py",
            Path("/usr/local/lib/frp-auto-deploy/frp_health_check.py"),
        ]
    )
    for path in candidates:
        if not path.is_file():
            continue
        try:
            spec = importlib.util.spec_from_file_location("frp_health_check", str(path))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        except Exception:
            continue
    return None


def normalize_health_check_optional(raw: Any) -> Optional[dict]:
    """Normalize optional health_check; uses frp_health_check when available."""
    if raw is None or raw is False:
        return None
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in ("", "disabled", "none", "off"):
            return None
        raise ProfileError("invalid health_check; expected an object")
    if not isinstance(raw, dict):
        raise ProfileError("invalid health_check; expected an object")
    if not raw:
        return None

    health = _load_health_module()
    if health is not None:
        try:
            return health.normalize_health_check(raw)
        except Exception as exc:
            raise ProfileError(str(exc)) from exc

    # Fallback when frp_health_check.py is unavailable (incomplete install).
    type_raw = str(raw.get("type", "") or "").strip().lower()
    if type_raw in ("", "disabled", "none", "off"):
        return None
    if type_raw not in ("tcp", "http"):
        raise ProfileError("invalid health type; use tcp, http, or disabled")

    def _pos(field: str, default: int) -> int:
        try:
            number = int(str(raw.get(field, default)).strip())
        except (TypeError, ValueError) as exc:
            raise ProfileError("invalid %s; must be a positive integer" % field) from exc
        if number < 1:
            raise ProfileError("invalid %s; must be a positive integer" % field)
        return number

    out = {
        "type": type_raw,
        "timeout_seconds": _pos("timeout_seconds", 3),
        "interval_seconds": _pos("interval_seconds", 10),
        "max_failed": _pos("max_failed", 1),
    }
    if type_raw == "http":
        path = str(raw.get("path") or "/health").strip() or "/health"
        if not path.startswith("/") or len(path) > 256:
            raise ProfileError("invalid health path; must start with /")
        out["path"] = path
    return out


def validate_profile_name(name: str) -> str:
    text = str(name or "").strip()
    if not text or not NAME_RE.match(text):
        raise ProfileError(
            "invalid profile name (1-64 chars; letters, digits, ._-; "
            "must start alphanumeric)"
        )
    return text


def validate_description(value: str, *, required: bool = False) -> str:
    text = str(value or "")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in text):
        raise ProfileError("invalid profile description")
    text = text.strip()
    if required and not text:
        raise ProfileError("profile description is required")
    if len(text) > DESCRIPTION_MAX_LEN:
        raise ProfileError("profile description too long (max %d)" % DESCRIPTION_MAX_LEN)
    return text


def validate_preset(value: str) -> str:
    text = str(value or "").strip().lower()
    if text not in PRESETS:
        raise ProfileError("preset must be ssh, http, https, or custom")
    return text


def validate_target_host(value: str) -> str:
    text = str(value or "").strip()
    if (
        not text
        or len(text) > 253
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in text)
        or any(c in text for c in " /\\;|&$`'\"<>")
    ):
        raise ProfileError("invalid target host")
    return text


def validate_target_port(value: Any) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ProfileError("invalid target port; must be an integer 1-65535") from exc
    if port < 1 or port > 65535:
        raise ProfileError("invalid target port; must be an integer 1-65535")
    return port


def validate_ssh_user(value: str, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        if required:
            raise ProfileError("ssh_user is required for ssh profiles")
        return ""
    if not SSH_USER_RE.fullmatch(text):
        raise ProfileError("invalid ssh_user")
    return text


def validate_profile_id(value: str) -> str:
    text = str(value or "").strip().lower()
    if not PROFILE_ID_RE.fullmatch(text):
        raise ProfileError("profile id must match prof_<12 lowercase hex>")
    return text


def generate_profile_id(existing: set[str]) -> str:
    for _ in range(64):
        value = PROFILE_ID_PREFIX + secrets.token_hex(PROFILE_ID_HEX_LEN // 2)
        if value not in existing:
            return value
    raise ProfileError("unable to allocate unique profile id")


def reject_forbidden_fields(raw: dict) -> None:
    for key in FORBIDDEN_PROFILE_KEYS:
        if key in raw and raw.get(key) not in (None, "", False):
            raise ProfileError("profiles must not store %s" % key)


def _parse_profiles_state(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise ProfileError("service-profiles.json must be a JSON object")
    version = raw.get("schema_version")
    if version != PROFILES_SCHEMA_VERSION:
        raise ProfileError("unsupported service-profiles schema version %s" % version)
    if not isinstance(raw.get("profiles"), dict):
        raise ProfileError("profiles must be an object")
    return raw


def require_profiles_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    """Load authoritative profile store. Missing file is corruption."""
    path = path or service_profiles_path(cfg)
    if not path.exists():
        raise ProfileError(
            "service-profiles.json is missing (authoritative profile store required)"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError("service-profiles.json is unreadable: %s" % exc) from exc
    return _parse_profiles_state(raw)


def load_profiles_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    """Load profile store for installed runtime (missing → error)."""
    return require_profiles_state(path=path, cfg=cfg)


def initialize_profiles_state(path: Optional[Path] = None, cfg: Optional[dict] = None) -> dict:
    """Explicit install/init: create empty profile store when absent."""
    path = path or service_profiles_path(cfg)
    if path.exists():
        return require_profiles_state(path=path, cfg=cfg)
    state = empty_profiles_state()
    save_profiles_state(state, path=path, cfg=cfg)
    return state


def save_profiles_state(state: dict, path: Optional[Path] = None, cfg: Optional[dict] = None) -> None:
    path = path or service_profiles_path(cfg)
    state = dict(state)
    state["schema_version"] = PROFILES_SCHEMA_VERSION
    validate_profiles_state(state)
    with FileLock(profiles_lock_path(path)):
        atomic_write_json(path, state)


def mutate_profiles_state(mutator, path: Optional[Path] = None, cfg: Optional[dict] = None):
    path = path or service_profiles_path(cfg)
    with FileLock(profiles_lock_path(path)):
        state = require_profiles_state(path=path, cfg=cfg)
        result = mutator(state)
        validate_profiles_state(state)
        atomic_write_json(path, state)
        return result if result is not None else state


def validate_profiles_state(state: dict) -> None:
    if not isinstance(state, dict):
        raise ProfileError("profiles state must be an object")
    if state.get("schema_version") != PROFILES_SCHEMA_VERSION:
        raise ProfileError("unsupported service-profiles schema version")
    profiles = state.get("profiles")
    if not isinstance(profiles, dict):
        raise ProfileError("profiles must be an object")
    names = {}
    for pid, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ProfileError("profile %s must be an object" % pid)
        validate_profile_id(pid)
        if str(profile.get("id") or "") != str(pid):
            raise ProfileError("profile id mismatch for %s" % pid)
        reject_forbidden_fields(profile)
        name = validate_profile_name(profile.get("name") or "")
        key = name.lower()
        if key in names:
            raise ProfileError("duplicate profile name: %s" % name)
        names[key] = pid
        validate_preset(profile.get("preset") or "")
        validate_target_host(profile.get("local_ip") or "")
        validate_target_port(profile.get("local_port"))
        preset = str(profile.get("preset") or "").lower()
        if preset == "ssh":
            validate_ssh_user(profile.get("ssh_user") or "", required=True)
        elif profile.get("ssh_user"):
            validate_ssh_user(profile.get("ssh_user") or "")
        if "description" in profile and profile.get("description") is not None:
            validate_description(str(profile.get("description") or ""))
        if "health_check" in profile:
            normalize_health_check_optional(profile.get("health_check"))


def find_profile_id_by_name(state: dict, name: str, exclude_id: str = "") -> Optional[str]:
    want = str(name or "").strip().lower()
    if not want:
        return None
    for pid, profile in (state.get("profiles") or {}).items():
        if exclude_id and pid == exclude_id:
            continue
        if str((profile or {}).get("name") or "").strip().lower() == want:
            return pid
    return None


def resolve_profile(state: dict, selector: str) -> tuple[str, dict]:
    text = str(selector or "").strip()
    if not text:
        raise ProfileError("profile selector is required")
    profiles = state.get("profiles") or {}
    if text in profiles and isinstance(profiles[text], dict):
        return text, profiles[text]
    lowered = text.lower()
    if PROFILE_ID_RE.fullmatch(lowered) and lowered in profiles:
        return lowered, profiles[lowered]
    matches = []
    for pid, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        if str(profile.get("name") or "").strip().lower() == lowered:
            matches.append(pid)
    if len(matches) == 1:
        return matches[0], profiles[matches[0]]
    if len(matches) > 1:
        raise ProfileError("ambiguous profile name: %s" % text)
    raise ProfileError("unknown profile: %s" % text)


def list_profiles(state: dict) -> list[tuple[str, dict]]:
    items = []
    for pid, profile in (state.get("profiles") or {}).items():
        if isinstance(profile, dict):
            items.append((pid, profile))
    items.sort(key=lambda item: str(item[1].get("name") or item[0]).lower())
    return items


def public_profile_view(profile: dict) -> dict:
    """Return a client-safe profile dict (no forbidden identity fields)."""
    out = {
        "id": profile.get("id"),
        "name": profile.get("name"),
        "preset": profile.get("preset"),
        "local_ip": profile.get("local_ip"),
        "local_port": profile.get("local_port"),
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
    }
    if profile.get("description"):
        out["description"] = profile.get("description")
    if profile.get("ssh_user"):
        out["ssh_user"] = profile.get("ssh_user")
    health = normalize_health_check_optional(profile.get("health_check"))
    if health:
        out["health_check"] = health
    return out


def create_profile(
    state: dict,
    name: str,
    *,
    preset: str,
    local_ip: str,
    local_port: Any,
    description: str = "",
    ssh_user: str = "",
    health_check: Any = None,
) -> tuple[str, dict]:
    reject_forbidden_fields(
        {
            "name": name,
            "preset": preset,
            "local_ip": local_ip,
            "local_port": local_port,
            "description": description,
            "ssh_user": ssh_user,
            **(health_check if isinstance(health_check, dict) else {}),
        }
    )
    name = validate_profile_name(name)
    if find_profile_id_by_name(state, name):
        raise ProfileError("profile name already exists: %s" % name)
    preset = validate_preset(preset)
    local_ip = validate_target_host(local_ip)
    local_port = validate_target_port(local_port)
    description = validate_description(description)
    ssh_user = validate_ssh_user(ssh_user, required=(preset == "ssh"))
    health = normalize_health_check_optional(health_check)

    profiles = state.setdefault("profiles", {})
    if not isinstance(profiles, dict):
        raise ProfileError("profiles must be an object")
    pid = generate_profile_id(set(profiles))
    now = utc_now_iso()
    record = {
        "id": pid,
        "name": name,
        "preset": preset,
        "local_ip": local_ip,
        "local_port": local_port,
        "created_at": now,
        "updated_at": now,
    }
    if description:
        record["description"] = description
    if ssh_user:
        record["ssh_user"] = ssh_user
    if health:
        record["health_check"] = health
    profiles[pid] = record
    return pid, record


def update_profile(state: dict, selector: str, prop: str, value: str) -> tuple[str, dict, str]:
    pid, profile = resolve_profile(state, selector)
    prop = str(prop or "").strip().lower().replace("_", "-")
    old = ""
    if prop == "name":
        old = str(profile.get("name") or "")
        name = validate_profile_name(value)
        clash = find_profile_id_by_name(state, name, exclude_id=pid)
        if clash:
            raise ProfileError("profile name already exists: %s" % name)
        profile["name"] = name
    elif prop == "description":
        old = str(profile.get("description") or "")
        description = validate_description(value)
        if description:
            profile["description"] = description
        else:
            profile.pop("description", None)
    elif prop == "preset":
        old = str(profile.get("preset") or "")
        # Atomic non-SSH → SSH transition: "ssh:<user>" or "ssh --ssh-user <user>"
        # style values are accepted so preset and ssh_user change together.
        text = str(value or "").strip()
        ssh_user_inline = ""
        preset_token = text
        if text.lower().startswith("ssh:") or text.lower().startswith("ssh="):
            preset_token = "ssh"
            ssh_user_inline = text[4:].strip()
        elif " " in text and text.split(None, 1)[0].lower() == "ssh":
            preset_token = "ssh"
            ssh_user_inline = text.split(None, 1)[1].strip()
        preset = validate_preset(preset_token)
        profile["preset"] = preset
        if preset == "ssh":
            if ssh_user_inline:
                profile["ssh_user"] = validate_ssh_user(ssh_user_inline, required=True)
            validate_ssh_user(profile.get("ssh_user") or "", required=True)
        elif "local_port" not in profile and preset in DEFAULT_PORTS:
            profile["local_port"] = DEFAULT_PORTS[preset]
        if preset != "ssh":
            # Keep ssh_user only for ssh presets.
            profile.pop("ssh_user", None)
    elif prop in ("target-host", "local-ip", "local_ip"):
        old = str(profile.get("local_ip") or "")
        profile["local_ip"] = validate_target_host(value)
    elif prop in ("target-port", "local-port", "local_port"):
        old = str(profile.get("local_port") or "")
        profile["local_port"] = validate_target_port(value)
    elif prop in ("ssh-user", "ssh_user"):
        old = str(profile.get("ssh_user") or "")
        if str(profile.get("preset") or "") != "ssh":
            raise ProfileError("ssh-user is only valid for ssh profiles")
        user = validate_ssh_user(value, required=True)
        profile["ssh_user"] = user
    elif prop in ("health-type", "health_type"):
        old = str(((profile.get("health_check") or {}) if isinstance(profile.get("health_check"), dict) else {}).get("type") or "")
        text = str(value or "").strip().lower()
        if text in ("", "disabled", "none", "off"):
            profile.pop("health_check", None)
        else:
            current = dict(profile.get("health_check") or {}) if isinstance(profile.get("health_check"), dict) else {}
            current["type"] = text
            normalized = normalize_health_check_optional(current)
            if normalized:
                profile["health_check"] = normalized
            else:
                profile.pop("health_check", None)
    elif prop in ("health-timeout", "health_timeout", "health-timeout-seconds"):
        prior = dict(profile.get("health_check") or {}) if isinstance(profile.get("health_check"), dict) else {}
        old = str(prior.get("timeout_seconds") or "")
        current = dict(prior) if prior else {"type": "tcp"}
        current["timeout_seconds"] = value
        profile["health_check"] = normalize_health_check_optional(current)
    elif prop in ("health-interval", "health_interval", "health-interval-seconds"):
        prior = dict(profile.get("health_check") or {}) if isinstance(profile.get("health_check"), dict) else {}
        old = str(prior.get("interval_seconds") or "")
        current = dict(prior) if prior else {"type": "tcp"}
        current["interval_seconds"] = value
        profile["health_check"] = normalize_health_check_optional(current)
    elif prop in ("health-max-failed", "health_max_failed"):
        prior = dict(profile.get("health_check") or {}) if isinstance(profile.get("health_check"), dict) else {}
        old = str(prior.get("max_failed") or "")
        current = dict(prior) if prior else {"type": "tcp"}
        current["max_failed"] = value
        profile["health_check"] = normalize_health_check_optional(current)
    elif prop in ("health-path", "health_path"):
        prior = dict(profile.get("health_check") or {}) if isinstance(profile.get("health_check"), dict) else {}
        old = str(prior.get("path") or "")
        current = dict(prior) if prior else {"type": "http"}
        current["type"] = "http"
        current["path"] = value
        profile["health_check"] = normalize_health_check_optional(current)
    else:
        raise ProfileError(
            "unknown profile property; use name|description|preset|"
            "target-host|target-port|ssh-user"
        )
    if prop.startswith("health") and profile.get("health_check") is None:
        profile.pop("health_check", None)
    profile["updated_at"] = utc_now_iso()
    # Re-validate ssh requirement after preset/ssh mutations.
    if str(profile.get("preset") or "") == "ssh":
        validate_ssh_user(profile.get("ssh_user") or "", required=True)
    reject_forbidden_fields(profile)
    return pid, profile, old


def delete_profile(state: dict, selector: str) -> tuple[str, str]:
    pid, profile = resolve_profile(state, selector)
    name = str(profile.get("name") or "")
    state["profiles"].pop(pid, None)
    return pid, name


def default_service_id_for_profile(profile: dict, override: str = "") -> str:
    text = str(override or "").strip().lower()
    if text:
        return text
    preset = str(profile.get("preset") or "custom").strip().lower()
    if preset in ("ssh", "http", "https"):
        return preset
    name = str(profile.get("name") or "svc").strip().lower()
    name = re.sub(r"[^a-z0-9._-]+", "-", name).strip("-._")
    if not name or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", name):
        return "svc"
    return name[:32]


def profile_to_service_payload(
    profile: dict,
    *,
    service_id: str = "",
    name: str = "",
) -> dict:
    """Map a profile template to a client draft service payload."""
    reject_forbidden_fields(profile)
    preset = validate_preset(profile.get("preset") or "")
    sid = default_service_id_for_profile(profile, service_id)
    display = str(name or "").strip() or str(profile.get("name") or sid).strip() or sid
    payload = {
        "id": sid,
        "name": display,
        "preset": preset,
        "protocol": "tcp",
        "local_ip": validate_target_host(profile.get("local_ip") or ""),
        "local_port": validate_target_port(profile.get("local_port")),
    }
    if preset == "ssh":
        payload["ssh_user"] = validate_ssh_user(profile.get("ssh_user") or "", required=True)
    health = normalize_health_check_optional(profile.get("health_check"))
    if health:
        payload["health_check"] = health
    # Explicitly never carry identities or public ports.
    for key in FORBIDDEN_PROFILE_KEYS:
        payload.pop(key, None)
    return payload


def doctor_issues(state: dict) -> list[dict]:
    issues = []
    try:
        validate_profiles_state(state)
    except ProfileError as exc:
        issues.append(
            {
                "class": "SERVICE_PROFILES_ERROR",
                "severity": "error",
                "message": str(exc),
            }
        )
    return issues
