#!/usr/bin/env python3
"""Data Relay Link product-version identity and provenance helpers.

VERSION is the product-version SSOT (PROJECT_VERSION + FRP_VERSION +
RELEASE_CHANNEL). Display identity and channel claims are derived; a bare
PROJECT_VERSION=2.4.0 never implies a stable release by itself.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Optional

SEMVER_CORE = re.compile(r"^(?P<core>\d+\.\d+\.\d+)$")
SEMVER_RC = re.compile(r"^(?P<core>\d+\.\d+\.\d+)-rc\.(?P<n>\d+)$")
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
SHORT_SHA = re.compile(r"^[0-9a-fA-F]{7,12}$")
STABLE_TAG = re.compile(r"^v(\d+\.\d+\.\d+)$")
RC_TAG = re.compile(r"^v(\d+\.\d+\.\d+)-rc\.(\d+)$")

CANONICAL_CHANNELS = ("development", "preview", "stable")


def read_version_file(path: Path | str) -> dict[str, str]:
    values: dict[str, str] = {}
    text = Path(path).read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def normalize_channel(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    ch = str(raw).strip().lower()
    if not ch:
        return None
    if ch in ("development", "dev", "main"):
        return "development"
    if ch in ("preview", "rc", "candidate", "prerelease"):
        return "preview"
    if ch == "stable":
        return "stable"
    return None


def persist_channel(canonical: str) -> str:
    """Wire form written to /etc/drlink/version and release-manifest."""
    ch = normalize_channel(canonical)
    if ch is None:
        raise ValueError("unknown release channel: %r" % (canonical,))
    return ch


def is_full_sha(value: Optional[str]) -> bool:
    return bool(value and FULL_SHA.fullmatch(value))


def is_stable_tag(value: Optional[str]) -> bool:
    return bool(value and STABLE_TAG.fullmatch(value or ""))


def is_rc_tag(value: Optional[str]) -> bool:
    return bool(value and RC_TAG.fullmatch(value or ""))


def is_immutable_source_ref(value: Optional[str]) -> bool:
    return is_full_sha(value) or is_stable_tag(value) or is_rc_tag(value)


def short_sha(full: str) -> str:
    return full[:7].lower()


def derive_display_identity(
    *,
    project_version: str,
    channel: Optional[str],
    source_ref: Optional[str] = None,
    source_head: Optional[str] = None,
    tag_exists: Optional[bool] = None,
    rc_number: Optional[int] = None,
) -> dict[str, str]:
    """Return display fields for show version / machine-readable identity.

    Stable channel is only claimed when provenance is a matching immutable
    stable tag (and, when known, that tag exists). PROJECT_VERSION alone is
    never enough.
    """
    core = (project_version or "").strip()
    if not SEMVER_CORE.fullmatch(core):
        raise ValueError("invalid project version: %r" % (project_version,))

    canonical = normalize_channel(channel) or "development"
    head = (source_head or "").strip()
    ref = (source_ref or "").strip()
    if not head and is_full_sha(ref):
        head = ref

    # Tag-shaped SOURCE_REF drives channel claim more strongly than a stale
    # RELEASE_CHANNEL=stable written before the tag existed.
    tag_match = STABLE_TAG.fullmatch(ref)
    rc_tag_match = RC_TAG.fullmatch(ref)
    rc_ver_match = SEMVER_RC.fullmatch(ref)

    claimed = canonical
    if tag_match and tag_match.group(1) == core:
        if tag_exists is False:
            claimed = "development"
        else:
            claimed = "stable"
    elif rc_tag_match or rc_ver_match:
        claimed = "preview"
    elif is_full_sha(ref) or is_full_sha(head):
        if claimed == "stable":
            # Exact SHA provenance cannot be a stable release claim.
            claimed = "development"
    elif claimed == "stable" and tag_exists is False:
        claimed = "development"

    if claimed == "stable":
        display = core
    elif claimed == "preview":
        n = rc_number
        if n is None and rc_tag_match:
            n = int(rc_tag_match.group(2))
        if n is None and rc_ver_match:
            n = int(rc_ver_match.group("n"))
        if n is None:
            n = 1
        display = "%s-rc.%d" % (core, n)
    else:
        sha = head if is_full_sha(head) else (ref if is_full_sha(ref) else "")
        if sha:
            display = "%s-dev+g%s" % (core, short_sha(sha))
        else:
            display = "%s-dev" % core

    return {
        "product_version": core,
        "display_identity": display,
        "channel": claimed,
        "source_head": head if is_full_sha(head) else "",
        "source_ref": ref or "",
    }


def format_show_version(
    *,
    display_identity: str,
    channel: str,
    source_head: str,
    frp_version: str,
    role: str = "",
    source_ref: str = "",
    bundle_sha256: str = "",
) -> str:
    lines = [
        "Data Relay Link: %s" % display_identity,
        "Channel: %s" % channel,
        "Source HEAD: %s" % (source_head or "unknown"),
        "Relay Engine (FRP): %s" % (frp_version or "unknown"),
    ]
    if role:
        lines.append("Role: %s" % role)
    if source_ref and source_ref != source_head:
        lines.append("Source ref: %s" % source_ref)
    if bundle_sha256:
        lines.append("Bundle SHA256: %s" % bundle_sha256)
    return "\n".join(lines)


def validate_manifest_dict(
    data: Mapping[str, Any],
    *,
    require_artifacts: bool = True,
    allow_stable_without_tag_proof: bool = False,
) -> list[str]:
    """Return a list of validation errors (empty means OK). Offline only."""
    errs: list[str] = []
    schema_version = data.get("schema_version")
    if schema_version not in (1, "1"):
        errs.append("schema_version must be 1")

    project = str(data.get("project_version") or "")
    if not SEMVER_CORE.fullmatch(project):
        errs.append("project_version must be SemVer MAJOR.MINOR.PATCH")

    frp = str(data.get("frp_version") or "")
    if not SEMVER_CORE.fullmatch(frp):
        errs.append("frp_version must be SemVer MAJOR.MINOR.PATCH")

    channel = normalize_channel(str(data.get("channel") or ""))
    if channel is None:
        errs.append("channel must be development|preview|stable")
    else:
        # Accept legacy "dev" only as input; canonical form preferred.
        raw_channel = str(data.get("channel") or "").strip().lower()
        if raw_channel == "dev":
            errs.append("channel must use canonical name 'development' (not 'dev')")

    git_ref = str(data.get("git_ref") or "").strip()
    source_head = str(data.get("source_head") or "").strip()
    if source_head and not is_full_sha(source_head):
        errs.append("source_head must be a 40-character Git SHA")
    if git_ref and not (
        is_full_sha(git_ref) or is_stable_tag(git_ref) or is_rc_tag(git_ref) or git_ref == "main"
    ):
        errs.append("git_ref must be a 40-char SHA, immutable tag, or explicit main")

    if channel == "stable":
        want_tag = "v%s" % project
        if git_ref != want_tag:
            errs.append("stable git_ref must equal %s" % want_tag)
        if SEMVER_RC.fullmatch(project) or "-" in project:
            errs.append("stable project_version must not be a prerelease")
        if not source_head and not allow_stable_without_tag_proof:
            errs.append("stable manifest requires source_head")
        if git_ref == "main":
            errs.append("stable release must not use mutable main")
        qual = data.get("qualification")
        if not isinstance(qual, Mapping) or not qual:
            errs.append("stable manifest requires qualification metadata")
        else:
            status = str(qual.get("status") or "")
            if status != "PASS":
                errs.append("stable qualification status must be PASS")
            heads = [
                str(qual.get("pass1_head") or ""),
                str(qual.get("pass2_head") or ""),
                str(qual.get("final_qualified_head") or ""),
            ]
            if not all(is_full_sha(item) for item in heads):
                errs.append(
                    "stable qualification requires pass1_head, pass2_head, "
                    "and final_qualified_head 40-character SHAs"
                )
            elif len(set(item.lower() for item in heads)) != 1:
                errs.append(
                    "PASS1_HEAD, PASS2_HEAD, and FINAL_QUALIFIED_HEAD must be equal"
                )
            if str(qual.get("real_e2e") or "").lower() == "pending":
                errs.append("stable qualification must not use real_e2e=pending")
    elif channel == "development":
        if not is_full_sha(git_ref) and git_ref != "main":
            errs.append("development git_ref must be a 40-char SHA (or explicit main tip)")
        if is_full_sha(git_ref) and source_head and git_ref.lower() != source_head.lower():
            errs.append("development git_ref must equal source_head")
        if is_full_sha(git_ref) and not source_head:
            # Allow git_ref alone to carry the SHA.
            pass
    elif channel == "preview":
        if not (is_full_sha(git_ref) or is_rc_tag(git_ref)):
            errs.append("preview git_ref must be a 40-char SHA or vX.Y.Z-rc.N tag")

    features = data.get("features")
    if not isinstance(features, Mapping):
        errs.append("features object required")
    else:
        if "mcp_included" not in features:
            errs.append("features.mcp_included required")
        elif features.get("mcp_included") not in (True, False):
            errs.append("features.mcp_included must be boolean")

    if require_artifacts:
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, Mapping) or not artifacts:
            errs.append("artifacts must be a non-empty object")
        else:
            sha_re = re.compile(r"^[0-9a-fA-F]{64}$")
            for name, meta in artifacts.items():
                if not isinstance(meta, Mapping):
                    errs.append("artifact %s must be an object" % name)
                    continue
                digest = str(meta.get("sha256") or "")
                if digest and not sha_re.fullmatch(digest):
                    errs.append("artifact %s has malformed sha256" % name)
                path = str(meta.get("path") or "")
                if not path:
                    errs.append("artifact %s missing path" % name)

    return errs


def load_and_validate_manifest(path: Path | str, **kwargs: Any) -> list[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_manifest_dict(data, **kwargs)


def sync_manifest_provenance(
    manifest: MutableMapping[str, Any],
    *,
    project_version: str,
    frp_version: str,
    channel: str,
    source_head: str,
    mcp_included: bool = False,
) -> MutableMapping[str, Any]:
    canonical = persist_channel(channel)
    manifest["schema_version"] = int(manifest.get("schema_version") or 1)
    manifest["project_version"] = project_version
    manifest["frp_version"] = frp_version
    manifest["channel"] = canonical
    manifest["source_head"] = source_head
    if canonical == "stable":
        manifest["git_ref"] = "v%s" % project_version
    elif canonical == "preview" and is_rc_tag(str(manifest.get("git_ref") or "")):
        pass
    else:
        manifest["git_ref"] = source_head
    features = dict(manifest.get("features") or {})
    features["mcp_included"] = bool(mcp_included)
    manifest["features"] = features
    return manifest


def identity_from_kv(
    kv: Mapping[str, str],
    *,
    tag_exists: Optional[bool] = None,
    rc_number: Optional[int] = None,
) -> dict[str, str]:
    return derive_display_identity(
        project_version=kv.get("PROJECT_VERSION") or kv.get("project_version") or "",
        channel=kv.get("RELEASE_CHANNEL") or kv.get("channel"),
        source_ref=kv.get("SOURCE_REF") or kv.get("source_ref"),
        source_head=kv.get("SOURCE_HEAD") or kv.get("source_head"),
        tag_exists=tag_exists,
        rc_number=rc_number,
    )
