#!/usr/bin/env python3
"""Pinned v2.4.0 Server-local Agent and qualified FRP artifacts.

FRP remains upstream fatedier/frp. This module does not modify FRP and does
not treat upstream source as DataRelay Labs proprietary code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

DRLINK_VERSION = "2.4.0"
FRP_VERSION = "0.71.0"
FRP_UPSTREAM_TAG = "v0.71.0"
FRP_UPSTREAM_COMMIT = "4a23aa181c1d7e28eecaa8216024ed753b9d27c8"
FRP_UPSTREAM_SOURCE_URL = (
    "https://github.com/fatedier/frp/archive/"
    "4a23aa181c1d7e28eecaa8216024ed753b9d27c8.tar.gz"
)
QUALIFICATION_STATUS = "PASS"

INSTALLED_ARTIFACT_ROOT = "/usr/local/share/drlink/artifacts"
HTTP_PREFIX = "/artifacts/"
REPO_FRP_REL = "third_party/frp/v0.71.0"

SUPPORTED = (
    ("linux", "amd64", "frp_0.71.0_linux_amd64.tar.gz",
     "84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"),
    ("linux", "arm64", "frp_0.71.0_linux_arm64.tar.gz",
     "f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266"),
    ("darwin", "arm64", "frp_0.71.0_darwin_arm64.tar.gz",
     "45be02b186860d375ed49a8941ae9569628a54bf14e67fc36b29c98c99dabcc6"),
    ("windows", "amd64", "frp_0.71.0_windows_amd64.zip",
     "9e5062e3e5cf07e67144a3a4acf175ef6a2486f3605dd6cf288bae34ab39819f"),
)

_SAFE_REL = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_HTTP_ALLOWED_PREFIXES = (
    "manifest.json",
    "SHA256SUMS",
    "QUALIFICATION.json",
    "agent/",
    "frp/",
)


def is_full_sha(value):
    return bool(value and _FULL_SHA.fullmatch(str(value).strip()))


class ArtifactError(Exception):
    """Fail-closed artifact error with a public message and no traceback leak."""

    def __init__(self, message, code="ARTIFACT_UNAVAILABLE"):
        super().__init__(message)
        self.code = code
        self.public_message = str(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def missing_artifact_error(
    platform="",
    architecture="",
    agent_version=DRLINK_VERSION,
    frp_version=FRP_VERSION,
):
    plat = platform or "<platform>"
    arch = architecture or "<architecture>"
    return (
        "ERROR:\n"
        "Required qualified artifact is not available on this DRLink Server.\n"
        "\n"
        "Required:\n"
        "  Data Relay Link Agent %s\n"
        "  FRP %s\n"
        "  %s/%s\n"
        "\n"
        "Reinstall or update the DRLink Server package containing\n"
        "the required qualified artifacts.\n"
        "\n"
        "No changes were applied.\n"
        % (agent_version, frp_version, plat, arch)
    )


def integrity_error(kind, platform="", architecture=""):
    plat = platform or "<platform>"
    arch = architecture or "<architecture>"
    return (
        "ERROR:\n"
        "Qualified %s artifact failed verification.\n"
        "\n"
        "Required:\n"
        "  Data Relay Link Agent %s\n"
        "  FRP %s\n"
        "  %s/%s\n"
        "\n"
        "Reinstall or update the DRLink Server package containing\n"
        "the required qualified artifacts.\n"
        "\n"
        "No changes were applied.\n"
        % (kind, DRLINK_VERSION, FRP_VERSION, plat, arch)
    )


def is_forbidden_public_installer_url(url):
    """True when a Managed Host installer URL is a forbidden public fallback."""
    text = str(url or "").strip().lower()
    if not text:
        return False
    return (
        "raw.githubusercontent.com" in text
        or "github.com/datarelay-labs" in text
        or "github.com/fatedier" in text
    )


def allocator_origin(allocator_url):
    parsed = urlparse(str(allocator_url or "").strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ArtifactError(
            "ERROR: allocator URL must be HTTPS.\nNo changes were applied.\n",
            "ARTIFACT_URL_INVALID",
        )
    return "https://%s" % parsed.netloc


def agent_installer_url(allocator_url, platform="linux"):
    name = "bootstrap-client.ps1" if platform == "windows" else "bootstrap-client.sh"
    return "%s/artifacts/agent/%s" % (allocator_origin(allocator_url), name)


def artifact_sha256sums_url(allocator_url):
    return "%s/artifacts/SHA256SUMS" % allocator_origin(allocator_url)


def frp_archive_url(allocator_url, platform, architecture):
    meta = lookup_frp(platform, architecture)
    return "%s/artifacts/frp/%s/%s" % (
        allocator_origin(allocator_url),
        FRP_VERSION,
        meta["filename"],
    )


def lookup_frp(platform, architecture, version=FRP_VERSION):
    plat = str(platform or "").strip().lower()
    arch = str(architecture or "").strip().lower()
    if plat == "darwin" and arch in ("aarch64",):
        arch = "arm64"
    if plat == "linux" and arch in ("x86_64",):
        arch = "amd64"
    if plat == "linux" and arch in ("aarch64",):
        arch = "arm64"
    if version != FRP_VERSION:
        raise ArtifactError(
            missing_artifact_error(plat, arch),
            "ARTIFACT_WRONG_VERSION",
        )
    for item_plat, item_arch, filename, sha256 in SUPPORTED:
        if item_plat == plat and item_arch == arch:
            return {
                "drlink_version": DRLINK_VERSION,
                "artifact_type": "frp-archive",
                "frp_version": FRP_VERSION,
                "frp_upstream_commit": FRP_UPSTREAM_COMMIT,
                "platform": plat,
                "architecture": arch,
                "filename": filename,
                "sha256": sha256,
                "relative_path": "frp/%s/%s" % (FRP_VERSION, filename),
            }
    raise ArtifactError(missing_artifact_error(plat, arch), "ARTIFACT_UNSUPPORTED")


def installed_root(explicit=None, test_root=None):
    if explicit:
        return Path(explicit)
    env = os.environ.get("DRLINK_ARTIFACT_ROOT", "").strip()
    if env:
        return Path(env)
    root = test_root or os.environ.get("FRP_SERVER_TEST_ROOT") or os.environ.get(
        "FRP_DEPLOY_TEST_ROOT", ""
    )
    if root:
        return Path(root) / INSTALLED_ARTIFACT_ROOT.lstrip("/")
    return Path(INSTALLED_ARTIFACT_ROOT)


def repo_frp_root(source_root):
    return Path(source_root) / REPO_FRP_REL


def load_manifest(root):
    path = Path(root) / "manifest.json"
    if not path.is_file():
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_MANIFEST_MISSING")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_MANIFEST_INVALID") from exc
    if not isinstance(data, dict):
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_MANIFEST_INVALID")
    return data


def _require_versions(manifest, agent_version=DRLINK_VERSION, frp_version=FRP_VERSION):
    if str(manifest.get("drlink_version") or "") != agent_version:
        raise ArtifactError(
            missing_artifact_error(agent_version=agent_version, frp_version=frp_version),
            "ARTIFACT_WRONG_VERSION",
        )
    if str(manifest.get("frp_version") or "") != frp_version:
        raise ArtifactError(
            missing_artifact_error(agent_version=agent_version, frp_version=frp_version),
            "ARTIFACT_WRONG_VERSION",
        )


def find_manifest_entry(manifest, artifact_type, platform=None, architecture=None):
    for item in manifest.get("artifacts") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("artifact_type") or "") != artifact_type:
            continue
        if platform is not None and str(item.get("platform") or "") != platform:
            continue
        if architecture is not None and str(item.get("architecture") or "") != architecture:
            continue
        return item
    return None


def verify_file(path, expected_sha256, kind="artifact", platform="", architecture=""):
    file_path = Path(path)
    if not file_path.is_file():
        raise ArtifactError(missing_artifact_error(platform, architecture), "ARTIFACT_MISSING")
    actual = sha256_file(file_path)
    if actual.lower() != str(expected_sha256 or "").strip().lower():
        raise ArtifactError(integrity_error(kind, platform, architecture), "ARTIFACT_CHECKSUM")
    return actual


def lookup_installed(root, artifact_type, platform=None, architecture=None):
    manifest = load_manifest(root)
    _require_versions(manifest)
    item = find_manifest_entry(manifest, artifact_type, platform, architecture)
    if item is None:
        raise ArtifactError(
            missing_artifact_error(platform or "", architecture or ""),
            "ARTIFACT_MISSING",
        )
    rel = str(item.get("relative_path") or item.get("filename") or "")
    if not rel or not _SAFE_REL.fullmatch(rel):
        raise ArtifactError(missing_artifact_error(platform or "", architecture or ""), "ARTIFACT_MISSING")
    path = Path(root) / rel
    verify_file(
        path,
        item.get("sha256"),
        kind=artifact_type,
        platform=platform or "",
        architecture=architecture or "",
    )
    out = dict(item)
    out["path"] = str(path)
    out["size"] = path.stat().st_size
    return out


def resolve_http_path(root, request_path):
    raw = str(request_path or "")
    parsed = urlparse(raw)
    path = parsed.path or raw
    if not path.startswith(HTTP_PREFIX.rstrip("/")):
        return None
    rel = path[len("/artifacts"):].lstrip("/")
    if rel == "":
        rel = "manifest.json"
    if not _SAFE_REL.fullmatch(rel):
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_PATH_INVALID")
    allowed = False
    for prefix in _HTTP_ALLOWED_PREFIXES:
        if rel == prefix.rstrip("/") or rel.startswith(prefix):
            allowed = True
            break
    if not allowed:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_PATH_INVALID")
    candidate = (Path(root) / rel).resolve()
    base = Path(root).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_PATH_INVALID") from exc
    if not candidate.is_file():
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_MISSING")
    return candidate


def _copy_file(src, dest, mode=0o644):
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(".%s.tmp.%s" % (dest.name, os.getpid()))
    shutil.copyfile(src, tmp)
    os.chmod(tmp, mode)
    tmp.replace(dest)


def load_build_provenance(source_root):
    """Immutable build source for Server-local artifact metadata.

    Precedence: expected env SHA, local git HEAD, then release-manifest.json.
    A committed manifest may lag HEAD; git/env must win when available.
    """
    channel = ""
    git_ref = ""
    source_head = ""
    project_version = DRLINK_VERSION
    source = Path(source_root)
    manifest_path = source / "release-manifest.json"
    if manifest_path.is_file():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            data = {}
        if isinstance(data, dict):
            channel = str(data.get("channel") or "").strip()
            git_ref = str(data.get("git_ref") or "").strip()
            source_head = str(data.get("source_head") or "").strip()
            project_version = str(data.get("project_version") or project_version)
    version_path = source / "VERSION"
    if version_path.is_file():
        try:
            for line in version_path.read_text(encoding="utf-8").splitlines():
                if "=" not in line or line.lstrip().startswith("#"):
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key == "RELEASE_CHANNEL" and not channel:
                    channel = value
                if key == "PROJECT_VERSION" and value:
                    project_version = value
        except OSError:
            pass
    for candidate in (
        os.environ.get("FRP_EXPECTED_SOURCE_HEAD", ""),
        os.environ.get("FRP_EXPECTED_SOURCE_REF", ""),
        os.environ.get("FRP_TXN_SOURCE_REF", ""),
    ):
        if is_full_sha(candidate):
            source_head = candidate.strip().lower()
            break
    else:
        try:
            head = subprocess.check_output(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            head = ""
        if is_full_sha(head):
            source_head = head.lower()
        elif is_full_sha(source_head):
            source_head = source_head.lower()
        elif is_full_sha(git_ref):
            source_head = git_ref.lower()
        else:
            source_head = ""
    if is_full_sha(git_ref):
        git_ref = git_ref.lower()
        if source_head and git_ref != source_head:
            git_ref = source_head
    elif not git_ref and source_head:
        git_ref = source_head
    return {
        "project_version": project_version or DRLINK_VERSION,
        "channel": channel or "",
        "git_ref": git_ref,
        "source_head": source_head,
    }


def _atomic_replace_dir(staging, dest):
    dest = Path(dest)
    staging = Path(staging)
    dest.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if dest.exists():
        backup = dest.with_name(".%s.prev.%s" % (dest.name, os.getpid()))
        if backup.exists():
            shutil.rmtree(backup)
        dest.rename(backup)
    try:
        staging.rename(dest)
    except Exception:
        if backup is not None and backup.exists() and not dest.exists():
            backup.rename(dest)
        raise
    if backup is not None and backup.exists():
        shutil.rmtree(backup, ignore_errors=True)


def parse_sha256sums(root):
    path = Path(root) / "SHA256SUMS"
    if not path.is_file():
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_SUMS_MISSING")
    out = {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_SUMS_INVALID") from exc
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            raise ArtifactError(missing_artifact_error(), "ARTIFACT_SUMS_INVALID")
        digest, rel = parts[0], parts[-1].lstrip("*")
        if not _SAFE_REL.fullmatch(rel):
            raise ArtifactError(missing_artifact_error(), "ARTIFACT_SUMS_INVALID")
        out[rel] = digest.lower()
    return out


def verify_tree(root):
    """Require actual file SHA == SHA256SUMS == manifest.json for every artifact."""
    dest = Path(root)
    manifest = load_manifest(dest)
    _require_versions(manifest)
    sums = parse_sha256sums(dest)
    artifacts = manifest.get("artifacts") or []
    if not artifacts:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_MANIFEST_INVALID")
    for item in artifacts:
        if not isinstance(item, dict):
            raise ArtifactError(missing_artifact_error(), "ARTIFACT_MANIFEST_INVALID")
        rel = str(item.get("relative_path") or item.get("filename") or "")
        expected = str(item.get("sha256") or "").strip().lower()
        if not rel or not _SAFE_REL.fullmatch(rel) or not expected:
            raise ArtifactError(missing_artifact_error(), "ARTIFACT_MANIFEST_INVALID")
        if rel not in sums:
            raise ArtifactError(
                integrity_error(str(item.get("artifact_type") or "artifact")),
                "ARTIFACT_SUMS_MISSING",
            )
        if sums[rel] != expected:
            raise ArtifactError(
                integrity_error(str(item.get("artifact_type") or "artifact")),
                "ARTIFACT_CHECKSUM",
            )
        verify_file(
            dest / rel,
            expected,
            kind=str(item.get("artifact_type") or "artifact"),
            platform=str(item.get("platform") or ""),
            architecture=str(item.get("architecture") or ""),
        )
        size = item.get("size")
        actual_size = (dest / rel).stat().st_size
        if size not in (None, "", actual_size) and int(size) != actual_size:
            raise ArtifactError(
                integrity_error(str(item.get("artifact_type") or "artifact")),
                "ARTIFACT_SIZE",
            )
    extra = set(sums) - {
        str(item.get("relative_path") or item.get("filename") or "")
        for item in artifacts
        if isinstance(item, dict)
    }
    if extra:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_SUMS_INVALID")
    return manifest


def _qualify_source(source_root):
    frp_root = repo_frp_root(source_root)
    qual_path = frp_root / "QUALIFICATION.json"
    if not qual_path.is_file():
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_SOURCE_MISSING")
    try:
        qual = json.loads(qual_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_SOURCE_INVALID") from exc
    if str(qual.get("frp_upstream_commit") or "") != FRP_UPSTREAM_COMMIT:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_WRONG_VERSION")
    if str(qual.get("frp_version") or "") != FRP_VERSION:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_WRONG_VERSION")
    if str(qual.get("qualification_status") or "") != QUALIFICATION_STATUS:
        raise ArtifactError(missing_artifact_error(), "ARTIFACT_UNQUALIFIED")
    return frp_root, qual


def _populate_artifact_staging(
    source_root, staging, agent_linux=None, agent_windows=None
):
    frp_root, qual = _qualify_source(source_root)
    dest = Path(staging)
    dest.mkdir(parents=True, exist_ok=True)
    provenance = load_build_provenance(source_root)

    artifacts = []
    for plat, arch, filename, sha256 in SUPPORTED:
        src = frp_root / "binaries" / filename
        if not src.is_file():
            raise ArtifactError(missing_artifact_error(plat, arch), "ARTIFACT_SOURCE_MISSING")
        verify_file(src, sha256, kind="FRP", platform=plat, architecture=arch)
        rel = "frp/%s/%s" % (FRP_VERSION, filename)
        _copy_file(src, dest / rel, 0o644)
        size = (dest / rel).stat().st_size
        artifacts.append({
            "drlink_version": DRLINK_VERSION,
            "artifact_type": "frp-archive",
            "frp_version": FRP_VERSION,
            "frp_upstream_commit": FRP_UPSTREAM_COMMIT,
            "platform": plat,
            "architecture": arch,
            "filename": filename,
            "relative_path": rel,
            "size": size,
            "sha256": sha256,
        })

    for name, src in (
        ("LICENSE", frp_root / "LICENSE"),
        ("go.mod", frp_root / "go.mod"),
        ("go.sum", frp_root / "go.sum"),
        ("QUALIFICATION.json", frp_root / "QUALIFICATION.json"),
    ):
        if not src.is_file():
            raise ArtifactError(missing_artifact_error(), "ARTIFACT_SOURCE_MISSING")
        _copy_file(src, dest / name, 0o644)

    source_archive = (
        frp_root / "source" / ("frp-%s.tar.gz" % FRP_UPSTREAM_COMMIT)
    )
    if source_archive.is_file():
        _copy_file(
            source_archive,
            dest / "source" / source_archive.name,
            0o644,
        )

    agent_specs = (
        ("linux", "any", "bootstrap-client.sh", agent_linux),
        ("windows", "amd64", "bootstrap-client.ps1", agent_windows),
    )
    for plat, arch, filename, src in agent_specs:
        if not src:
            raise ArtifactError(missing_artifact_error(plat, arch), "ARTIFACT_SOURCE_MISSING")
        src_path = Path(src)
        if not src_path.is_file():
            raise ArtifactError(missing_artifact_error(plat, arch), "ARTIFACT_SOURCE_MISSING")
        rel = "agent/%s" % filename
        _copy_file(src_path, dest / rel, 0o755 if filename.endswith(".sh") else 0o644)
        digest = sha256_file(dest / rel)
        artifacts.append({
            "drlink_version": DRLINK_VERSION,
            "artifact_type": "agent-installer",
            "frp_version": FRP_VERSION,
            "frp_upstream_commit": FRP_UPSTREAM_COMMIT,
            "platform": plat,
            "architecture": arch,
            "filename": filename,
            "relative_path": rel,
            "size": (dest / rel).stat().st_size,
            "sha256": digest,
            "source_head": provenance.get("source_head") or "",
        })

    manifest = {
        "schema_version": 1,
        "drlink_version": DRLINK_VERSION,
        "artifact_type": "qualified-distribution",
        "frp_version": FRP_VERSION,
        "frp_upstream_tag": FRP_UPSTREAM_TAG,
        "frp_upstream_commit": FRP_UPSTREAM_COMMIT,
        "frp_upstream_source_url": FRP_UPSTREAM_SOURCE_URL,
        "qualification_status": QUALIFICATION_STATUS,
        "project_version": provenance.get("project_version") or DRLINK_VERSION,
        "channel": provenance.get("channel") or "",
        "source_head": provenance.get("source_head") or "",
        "git_ref": provenance.get("git_ref") or provenance.get("source_head") or "",
        "immutable_source_ref": (
            provenance.get("git_ref") or provenance.get("source_head") or ""
        ),
        "attribution": qual.get("attribution")
        or "FRP is copyright the fatedier/frp authors and is not DataRelay Labs proprietary code.",
        "artifacts": artifacts,
    }
    manifest_path = dest / "manifest.json"
    tmp = manifest_path.with_name(".manifest.json.tmp.%s" % os.getpid())
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    tmp.replace(manifest_path)

    sums_lines = []
    for item in artifacts:
        sums_lines.append("%s  %s" % (item["sha256"], item["relative_path"]))
    sums_lines.sort(key=lambda line: line.split(None, 1)[1])
    sums_path = dest / "SHA256SUMS"
    tmp = sums_path.with_name(".SHA256SUMS.tmp.%s" % os.getpid())
    tmp.write_text("\n".join(sums_lines) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    tmp.replace(sums_path)
    verify_tree(dest)
    return manifest


def install_artifacts(source_root, dest_root, agent_linux=None, agent_windows=None):
    dest = Path(dest_root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.parent / (".%s.staging.%s" % (dest.name, os.getpid()))
    if staging.exists():
        shutil.rmtree(staging)
    swapped = False
    try:
        staging.mkdir(parents=True, exist_ok=True)
        manifest = _populate_artifact_staging(
            source_root, staging, agent_linux, agent_windows
        )
        if os.environ.get("DRLINK_ARTIFACT_INSTALL_FAIL", "").strip() == "before-swap":
            raise ArtifactError(
                "ERROR: simulated artifact install failure before swap.\n"
                "No changes were applied.\n",
                "ARTIFACT_INSTALL_FAILED",
            )
        _atomic_replace_dir(staging, dest)
        swapped = True
        return verify_tree(dest)
    finally:
        if not swapped and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def content_type_for(path):
    name = Path(path).name.lower()
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".sh"):
        return "text/x-shellscript; charset=utf-8"
    if name.endswith(".ps1"):
        return "text/plain; charset=utf-8"
    if name == "sha256sums":
        return "text/plain; charset=utf-8"
    if name.endswith(".tar.gz"):
        return "application/gzip"
    if name.endswith(".zip"):
        return "application/zip"
    return "application/octet-stream"


def _print_error(exc):
    sys.stderr.write(str(exc.public_message if isinstance(exc, ArtifactError) else exc))
    if not str(exc).endswith("\n"):
        sys.stderr.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Qualified DRLink/FRP artifacts")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_install = sub.add_parser("install")
    p_install.add_argument("--source", required=True)
    p_install.add_argument("--dest", required=True)
    p_install.add_argument("--agent-linux", required=True)
    p_install.add_argument("--agent-windows", required=True)

    p_lookup = sub.add_parser("lookup")
    p_lookup.add_argument("--root", required=True)
    p_lookup.add_argument("--type", required=True, choices=("frp-archive", "agent-installer"))
    p_lookup.add_argument("--platform", required=True)
    p_lookup.add_argument("--architecture", default="any")

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--file", required=True)
    p_verify.add_argument("--sha256", required=True)
    p_verify.add_argument("--kind", default="artifact")
    p_verify.add_argument("--platform", default="")
    p_verify.add_argument("--architecture", default="")

    p_origin = sub.add_parser("origin-url")
    p_origin.add_argument("--allocator-url", required=True)

    p_agent = sub.add_parser("agent-url")
    p_agent.add_argument("--allocator-url", required=True)
    p_agent.add_argument("--platform", default="linux")

    p_frp = sub.add_parser("frp-url")
    p_frp.add_argument("--allocator-url", required=True)
    p_frp.add_argument("--platform", required=True)
    p_frp.add_argument("--architecture", required=True)

    p_sums = sub.add_parser("sha256sums-url")
    p_sums.add_argument("--allocator-url", required=True)

    p_missing = sub.add_parser("missing-error")
    p_missing.add_argument("--platform", default="")
    p_missing.add_argument("--architecture", default="")

    p_http = sub.add_parser("resolve-http")
    p_http.add_argument("--root", required=True)
    p_http.add_argument("--path", required=True)

    p_tree = sub.add_parser("verify-tree")
    p_tree.add_argument("--root", required=True)

    p_pin = sub.add_parser("pin")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "install":
            manifest = install_artifacts(
                args.source, args.dest, args.agent_linux, args.agent_windows
            )
            sys.stdout.write(json.dumps({"status": "ok", "count": len(manifest["artifacts"])}) + "\n")
            return 0
        if args.cmd == "lookup":
            item = lookup_installed(
                args.root, args.type, args.platform, args.architecture
            )
            sys.stdout.write(json.dumps(item) + "\n")
            return 0
        if args.cmd == "verify":
            digest = verify_file(
                args.file, args.sha256, args.kind, args.platform, args.architecture
            )
            sys.stdout.write(digest + "\n")
            return 0
        if args.cmd == "origin-url":
            sys.stdout.write(allocator_origin(args.allocator_url) + "\n")
            return 0
        if args.cmd == "agent-url":
            sys.stdout.write(agent_installer_url(args.allocator_url, args.platform) + "\n")
            return 0
        if args.cmd == "frp-url":
            sys.stdout.write(
                frp_archive_url(args.allocator_url, args.platform, args.architecture) + "\n"
            )
            return 0
        if args.cmd == "sha256sums-url":
            sys.stdout.write(artifact_sha256sums_url(args.allocator_url) + "\n")
            return 0
        if args.cmd == "missing-error":
            sys.stderr.write(missing_artifact_error(args.platform, args.architecture))
            return 1
        if args.cmd == "resolve-http":
            path = resolve_http_path(args.root, args.path)
            sys.stdout.write(str(path) + "\n")
            return 0
        if args.cmd == "verify-tree":
            manifest = verify_tree(args.root)
            sys.stdout.write(
                json.dumps({
                    "status": "ok",
                    "count": len(manifest.get("artifacts") or []),
                    "source_head": manifest.get("source_head") or "",
                })
                + "\n"
            )
            return 0
        if args.cmd == "pin":
            sys.stdout.write(
                json.dumps({
                    "drlink_version": DRLINK_VERSION,
                    "frp_version": FRP_VERSION,
                    "frp_upstream_tag": FRP_UPSTREAM_TAG,
                    "frp_upstream_commit": FRP_UPSTREAM_COMMIT,
                    "frp_upstream_source_url": FRP_UPSTREAM_SOURCE_URL,
                    "qualification_status": QUALIFICATION_STATUS,
                })
                + "\n"
            )
            return 0
    except ArtifactError as exc:
        _print_error(exc)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
