#!/usr/bin/env python3
"""Authoritative product-owned state and log path contract (F06/S03).

Single source for backup, restore, support-bundle, and permission reapply
surfaces. Prefer importing helpers here over duplicating path literals.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


@dataclass(frozen=True)
class StatePathSpec:
    path: str
    legacy_paths: tuple[str, ...] = ()
    type: str = "state"
    owner: str = "root"
    group: str = "root"
    mode: int = 0o600
    backup_policy: str = "optional"
    restore_policy: str = "optional"
    support_bundle_policy: str = "include"
    sensitivity: str = "standard"
    rotation_pattern: str | None = None


# Canonical relative paths (from filesystem root / test root).
# Enrollment inventory is a non-authoritative derived/runtime projection of
# SQLite client + published-service state used by the allocator transport.
# Disaster-recovery restores must not re-apply it as authority; rebuild from DB.
CLIENT_INVENTORY = StatePathSpec(
    path="var/lib/drlink/runtime/client-inventory.json",
    legacy_paths=("var/lib/drlink/registry.json",),
    type="state",
    backup_policy="optional",
    restore_policy="ignore",
    sensitivity="critical",
)
# Back-compat alias name used by older callers.
REGISTRY = CLIENT_INVENTORY
# Obsolete JSON policy stores — migration inputs only; not current authority.
ACCESS_CONTROL = StatePathSpec(
    path="var/lib/drlink/access-control.json",
    type="state",
    backup_policy="optional",
    restore_policy="ignore",
    support_bundle_policy="exclude",
    sensitivity="standard",
)
EGRESS_CONTROL = StatePathSpec(
    path="var/lib/drlink/egress-control.json",
    type="state",
    backup_policy="optional",
    restore_policy="ignore",
    support_bundle_policy="exclude",
    sensitivity="standard",
)
SERVICE_PROFILES = StatePathSpec(
    path="var/lib/drlink/service-profiles.json",
    type="state",
    backup_policy="optional",
    restore_policy="ignore",
    support_bundle_policy="exclude",
    sensitivity="standard",
)
CONTROL_DB = StatePathSpec(
    path="var/lib/drlink/drlink.db",
    type="state",
    backup_policy="required",
    restore_policy="required",
    sensitivity="critical",
)
# Runtime projections are regenerated from restored drlink.db after cutover.
RUNTIME_TREE = StatePathSpec(
    path="var/lib/drlink/runtime",
    type="tree",
    backup_policy="tree",
    restore_policy="ignore",
    sensitivity="standard",
)
ENROLLMENTS_TREE = StatePathSpec(
    path="var/lib/drlink/enrollments",
    type="tree",
    backup_policy="tree",
    restore_policy="tree",
    sensitivity="secret",
)
# Zero-Touch / enrollment bootstrap tickets. Historical backup/restore SSOT.
BOOTSTRAP_TREE = StatePathSpec(
    path="var/lib/drlink/bootstrap",
    type="tree",
    backup_policy="tree",
    restore_policy="tree",
    sensitivity="secret",
)
MCP_TLS_TREE = StatePathSpec(
    path="var/lib/drlink/tls/mcp",
    type="tree",
    backup_policy="tree",
    restore_policy="tree",
    support_bundle_policy="exclude",
    sensitivity="secret",
)
CONFIG_JSON = StatePathSpec(
    path="etc/drlink/config.json",
    type="config",
    backup_policy="required",
    restore_policy="required",
    sensitivity="critical",
)
AUDIT_LOG = StatePathSpec(
    path="var/log/drlink/audit.jsonl",
    type="log",
    backup_policy="optional",
    restore_policy="optional",
    support_bundle_policy="include",
    sensitivity="operational",
    rotation_pattern="audit.jsonl.*",
)
ACCESS_CONN_LOG = StatePathSpec(
    path="var/log/drlink/access/connections.jsonl",
    legacy_paths=("var/log/drlink/access-conn.jsonl",),
    type="log",
    backup_policy="optional",
    restore_policy="optional",
    support_bundle_policy="prefer_new",
    sensitivity="operational",
    rotation_pattern="connections.jsonl.*",
)
ACCESS_CONN_LOG_LEGACY = StatePathSpec(
    path="var/log/drlink/access-conn.jsonl",
    type="log",
    backup_policy="optional",
    restore_policy="optional",
    support_bundle_policy="legacy_fallback",
    sensitivity="operational",
    rotation_pattern="access-conn.jsonl.*",
)
EGRESS_CONN_LOG = StatePathSpec(
    path="var/log/drlink/egress/connections.jsonl",
    legacy_paths=("var/log/drlink/egress-conn.jsonl",),
    type="log",
    backup_policy="optional",
    restore_policy="optional",
    support_bundle_policy="prefer_new",
    sensitivity="operational",
    rotation_pattern="connections.jsonl.*",
)
EGRESS_CONN_LOG_LEGACY = StatePathSpec(
    path="var/log/drlink/egress-conn.jsonl",
    type="log",
    backup_policy="optional",
    restore_policy="optional",
    support_bundle_policy="legacy_fallback",
    sensitivity="operational",
    rotation_pattern="egress-conn.jsonl.*",
)

STATE_PATHS: tuple[StatePathSpec, ...] = (
    REGISTRY,
    ACCESS_CONTROL,
    EGRESS_CONTROL,
    SERVICE_PROFILES,
    CONTROL_DB,
    RUNTIME_TREE,
    ENROLLMENTS_TREE,
    BOOTSTRAP_TREE,
    MCP_TLS_TREE,
    CONFIG_JSON,
    AUDIT_LOG,
    ACCESS_CONN_LOG,
    ACCESS_CONN_LOG_LEGACY,
    EGRESS_CONN_LOG,
    EGRESS_CONN_LOG_LEGACY,
)

DEFAULT_EGRESS_CONN_LOG = EGRESS_CONN_LOG.path
LEGACY_EGRESS_CONN_LOG = EGRESS_CONN_LOG_LEGACY.path


def iter_log_specs() -> Iterator[StatePathSpec]:
    for spec in STATE_PATHS:
        if spec.type == "log":
            yield spec


def backup_optional_files() -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for spec in STATE_PATHS:
        if spec.backup_policy != "optional" or spec.type != "log":
            continue
        for rel in (spec.path, *spec.legacy_paths):
            if rel not in seen:
                seen.add(rel)
                out.append(rel)
    return tuple(out)


def backup_required_files() -> tuple[str, ...]:
    return tuple(
        spec.path for spec in STATE_PATHS if spec.backup_policy == "required"
    )


def restore_required_files() -> frozenset[str]:
    return frozenset(
        spec.path for spec in STATE_PATHS if spec.restore_policy == "required"
    )


def restore_ignore_files() -> frozenset[str]:
    ignored: set[str] = set()
    for spec in STATE_PATHS:
        if spec.restore_policy != "ignore":
            continue
        ignored.add(spec.path)
        ignored.update(spec.legacy_paths)
    return frozenset(ignored)


def backup_forensic_optional_files() -> tuple[str, ...]:
    """Non-authoritative state retained in archives when present (forensics/migration)."""
    seen: set[str] = set()
    out: list[str] = []
    for spec in STATE_PATHS:
        if spec.restore_policy != "ignore" or spec.type not in {"state", "tree"}:
            continue
        if spec.type == "tree":
            continue
        for rel in (spec.path, *spec.legacy_paths):
            if rel not in seen:
                seen.add(rel)
                out.append(rel)
    return tuple(out)


def backup_tree_roots() -> tuple[str, ...]:
    return tuple(
        spec.path
        for spec in STATE_PATHS
        if spec.backup_policy == "tree" and spec.type == "tree"
    )


def restore_tree_roots() -> tuple[str, ...]:
    return tuple(
        spec.path
        for spec in STATE_PATHS
        if spec.restore_policy == "tree" and spec.type == "tree"
    )


def rotated_glob_for_spec(spec: StatePathSpec) -> str | None:
    if not spec.rotation_pattern:
        return None
    parent = str(Path(spec.path).parent)
    if parent == ".":
        return spec.rotation_pattern
    return f"{parent}/{spec.rotation_pattern}"


def backup_rotated_globs() -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for spec in iter_log_specs():
        for candidate in (spec,) + tuple(
            StatePathSpec(
                path=legacy,
                rotation_pattern=Path(legacy).name + ".*",
                type="log",
                backup_policy=spec.backup_policy,
                restore_policy=spec.restore_policy,
            )
            for legacy in spec.legacy_paths
        ):
            glob = rotated_glob_for_spec(candidate)
            if glob and glob not in seen:
                seen.add(glob)
                out.append(glob)
        glob = rotated_glob_for_spec(spec)
        if glob and glob not in seen:
            seen.add(glob)
            out.append(glob)
    return tuple(out)


def restore_optional_exact() -> frozenset[str]:
    return frozenset(
        rel
        for spec in STATE_PATHS
        if spec.restore_policy == "optional" and spec.type == "log"
        for rel in (spec.path, *spec.legacy_paths)
    )


def restore_rotated_prefixes() -> tuple[str, ...]:
    prefixes: list[str] = []
    for spec in iter_log_specs():
        for rel in (spec.path, *spec.legacy_paths):
            name = Path(rel).name
            parent = str(Path(rel).parent)
            prefix = f"{parent}/{name}."
            if prefix not in prefixes:
                prefixes.append(prefix)
    return tuple(prefixes)


def restore_rotated_glob_patterns() -> tuple[str, ...]:
    patterns: list[str] = []
    for spec in iter_log_specs():
        for rel in (spec.path, *spec.legacy_paths):
            pattern = f"{Path(rel).name}.*"
            if pattern not in patterns:
                patterns.append(pattern)
    return tuple(patterns)


def allowed_rotated_rel(rel: str) -> bool:
    for prefix in restore_rotated_prefixes():
        if not rel.startswith(prefix):
            continue
        suffix = rel[len(prefix) :]
        return suffix.isdigit() and not rel.endswith(".lock")
    return False


def collect_present_rotated_files(root: Path) -> list[tuple[str, Path]]:
    """Return (relative_path, absolute_path) for rotated log files on disk."""
    found: dict[str, Path] = {}
    log_root = root / "var/log/drlink"
    if not log_root.is_dir() or log_root.is_symlink():
        return []
    for pattern in backup_rotated_globs():
        # pattern is relative to root, e.g. var/log/drlink/audit.jsonl.*
        glob_parent = root / str(Path(pattern).parent)
        glob_name = Path(pattern).name
        if not glob_parent.is_dir():
            continue
        for source in sorted(glob_parent.glob(glob_name)):
            if source.is_symlink() or not source.is_file():
                continue
            if source.name.endswith(".lock"):
                continue
            rel = source.relative_to(root).as_posix()
            found[rel] = source
    return sorted(found.items())


def default_egress_conn_log_rel() -> str:
    return DEFAULT_EGRESS_CONN_LOG


def egress_conn_log_candidates() -> tuple[str, ...]:
    return (DEFAULT_EGRESS_CONN_LOG, LEGACY_EGRESS_CONN_LOG)
