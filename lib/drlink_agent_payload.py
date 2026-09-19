#!/usr/bin/env python3
"""Canonical Agent Host runtime payload.

Single source of truth for the library files that every Linux/macOS Agent
install, upgrade, and bootstrap bundle must ship. Installers compare
installed SHA-256 hashes against this set so SOURCE_HEAD metadata cannot
hide a stale runtime module.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

RUNTIME_MANIFEST_NAME = "runtime-sha256.json"

# Required files installed under the Agent lib directory (basename = source
# name under lib/). Keep this list complete for the public v2.4 Agent CLI.
AGENT_LIB_FILES: tuple[str, ...] = (
    "frp-client-common.sh",
    "frp-common.sh",
    "frp-macos.sh",
    "frp-doctor-common.sh",
    "frp-role-ownership.sh",
    "frp_mgmt_auth.py",
    "frp_health_check.py",
    "frp_doctor.py",
    "frp_support_bundle.py",
    "frp_ctl_grammar.py",
    "frp_cli_catalog.py",
    "frp_version_identity.py",
    "frp_cli_final_commands.json",
    "frp_service_profiles.py",
    "frp_ctl_repl.py",
    "frp_control_locks.py",
    "frp_infrastructure_ports.py",
    "drlink_qualified_artifacts.py",
    "drlink_ai_agent.py",
    "drlink_control_db.py",
    "drlink_control_plane.py",
    "drlink_control_cli.py",
    "drlink_mgmt_sync.py",
    "drlink_v24.py",
    "drlink_v24_cli.py",
    "drlink_v24_bundle.py",
    "drlink_v24_wizard.py",
    "drlink_v24_runtime.py",
    "drlink_v24_ai_identity.py",
    "drlink_configuration_bundle.py",
    "drlink_mcp_tls.py",
    "drlink_runtime_policy.py",
    "drlink_upgrade_reconcile.py",
    "drlink_agent_payload.py",
)

# Subset used for live lineage proof. A mismatch here is a release blocker
# even if SOURCE_HEAD metadata claims the current commit.
AGENT_CRITICAL_LINEAGE_FILES: tuple[str, ...] = (
    "drlink_control_cli.py",
    "drlink_v24.py",
    "drlink_v24_cli.py",
    "drlink_v24_bundle.py",
    "drlink_v24_wizard.py",
    "drlink_v24_runtime.py",
    "drlink_configuration_bundle.py",
    "drlink_mgmt_sync.py",
    "frp_ctl_grammar.py",
    "frp_cli_catalog.py",
)


def agent_lib_files() -> tuple[str, ...]:
    return AGENT_LIB_FILES


def agent_source_rels() -> list[str]:
    return ["lib/%s" % name for name in AGENT_LIB_FILES]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_files(libdir: Path, names: Iterable[str]) -> list[str]:
    missing = []
    for name in names:
        if not (libdir / name).is_file():
            missing.append(name)
    return missing


def hash_lib_files(libdir: Path, names: Iterable[str] | None = None) -> dict[str, str]:
    selected = tuple(names) if names is not None else AGENT_LIB_FILES
    missing = _require_files(libdir, selected)
    if missing:
        raise FileNotFoundError(
            "Agent payload missing required module(s): %s" % ", ".join(missing)
        )
    return {name: sha256_file(libdir / name) for name in selected}


def write_installed_manifest(libdir: Path) -> dict:
    payload = {
        "schema": 1,
        "files": hash_lib_files(libdir, AGENT_LIB_FILES),
        "critical": list(AGENT_CRITICAL_LINEAGE_FILES),
    }
    dest = libdir / RUNTIME_MANIFEST_NAME
    dest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def verify_payload_match(source_lib: Path, dest_lib: Path) -> list[str]:
    """Return human-readable mismatch lines. Empty list means PASS."""
    problems: list[str] = []
    missing = _require_files(dest_lib, AGENT_LIB_FILES)
    if missing:
        problems.append("missing: %s" % ", ".join(missing))
        return problems
    source_hashes = hash_lib_files(source_lib, AGENT_LIB_FILES)
    dest_hashes = hash_lib_files(dest_lib, AGENT_LIB_FILES)
    for name in AGENT_LIB_FILES:
        if source_hashes[name] != dest_hashes[name]:
            problems.append(
                "%s source=%s installed=%s" % (name, source_hashes[name], dest_hashes[name])
            )
    return problems


def verify_installed_lineage(libdir: Path, source_lib: Path | None = None) -> list[str]:
    problems: list[str] = []
    missing = _require_files(libdir, AGENT_LIB_FILES)
    if missing:
        return ["missing: %s" % ", ".join(missing)]
    live = hash_lib_files(libdir, AGENT_LIB_FILES)
    manifest_path = libdir / RUNTIME_MANIFEST_NAME
    if manifest_path.is_file():
        try:
            recorded = json.loads(manifest_path.read_text(encoding="utf-8")).get("files") or {}
        except json.JSONDecodeError:
            recorded = {}
        for name in AGENT_CRITICAL_LINEAGE_FILES:
            expected = recorded.get(name)
            if not expected:
                problems.append("%s missing from runtime manifest" % name)
            elif expected != live.get(name):
                problems.append(
                    "%s live=%s manifest=%s" % (name, live.get(name), expected)
                )
    if source_lib is not None:
        problems.extend(verify_payload_match(source_lib, libdir))
    return problems
