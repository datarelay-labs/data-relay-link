#!/usr/bin/env python3
"""Generate a factual SPDX JSON SBOM for Data Relay Link release artifacts.

Includes only repository-owned facts: project version, git commit, pinned FRP
version and known upstream binary hashes, release artifacts, and owned scripts/
modules listed in SHA256SUMS / manifests. Does not invent third-party Python
dependencies for stdlib imports. Writes no host secrets or local absolute paths
beyond relative repository paths.

Ordering contract (see docs/RELEASE_CHECKLIST.md "Release artifact ordering"):
build bundles -> update SHA256SUMS -> generate SBOM -> verify. The SBOM is a
consumer of SHA256SUMS, never an input to it, so METADATA_PATHS below stay out
of both the inventory and SHA256SUMS. That keeps the relation acyclic and lets
a rebuild converge in a single pass.

The document is deterministic for a given source commit: the creation
timestamp comes from SOURCE_DATE_EPOCH or the HEAD commit time, never from
wall-clock now().
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Derived release metadata that must never appear in the SBOM inventory or in
# SHA256SUMS. Keep in sync with scripts/update-sha256sums.sh and
# scripts/verify-sha256sums.sh.
METADATA_PATHS = frozenset(
    {"SHA256SUMS", "release-manifest.json", "dist/sbom.spdx.json"}
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_version(root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (root / "VERSION").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()
    return values


def _git(root: Path, *args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return None


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD") or "UNKNOWN"


def _created_timestamp(root: Path, head: str) -> str:
    """Deterministic creation time: SOURCE_DATE_EPOCH, else HEAD commit time."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not epoch and head != "UNKNOWN":
        epoch = _git(root, "log", "-1", "--format=%ct", head) or ""
    if epoch:
        try:
            when = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            when = None
        if when is not None:
            return when.strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_sha256sums(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Paths may contain spaces; split once after the digest only.
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, rel = parts[0], parts[1].strip()
        if rel.startswith("*"):
            rel = rel[1:]
        if rel in METADATA_PATHS:
            continue
        rows.append((digest, rel))
    return rows


def build_sbom(root: Path, source_commit: str | None = None) -> dict:
    values = _read_version(root)
    project_version = values.get("PROJECT_VERSION", "")
    frp_version = values.get("FRP_VERSION", "")
    head = source_commit or _git_head(root)
    manifest = json.loads((root / "release-manifest.json").read_text(encoding="utf-8"))
    release_ref = str(manifest.get("git_ref") or "")
    created = _created_timestamp(root, head)
    doc_name = "data-relay-link-%s" % project_version
    packages = []
    relationships = []
    root_spid = "SPDXRef-Package-DataRelayLink"
    packages.append(
        {
            "SPDXID": root_spid,
            "name": "Data Relay Link",
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "Organization: datarelay-labs",
            "sourceInfo": "git commit %s; release ref %s" % (head, release_ref),
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "gitCommit",
                    "referenceLocator": head,
                },
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "gitRef",
                    "referenceLocator": release_ref,
                },
            ],
            "comment": "Primary product package. FRP is a pinned upstream dependency.",
        }
    )

    # Pinned FRP platform binaries from release-manifest (factual hashes only).
    frp_meta = (manifest.get("supported_frp_versions") or {}).get(frp_version) or {}
    frp_spid = "SPDXRef-Package-FRP-%s" % frp_version.replace(".", "-")
    packages.append(
        {
            "SPDXID": frp_spid,
            "name": "frp",
            "versionInfo": frp_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "Organization: fatedier",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": v}
                for k, v in sorted(frp_meta.items())
                if k.endswith("_sha256") and isinstance(v, str) and len(v) == 64
            ],
            "comment": "Pinned upstream FRP runtime; hashes from release-manifest.json.",
        }
    )
    relationships.append(
        {
            "spdxElementId": root_spid,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": frp_spid,
        }
    )

    # Release artifacts + SHA256SUMS inventory as files/packages.
    file_ids = []
    for digest, rel in _parse_sha256sums(root / "SHA256SUMS"):
        safe = rel.replace("/", "-").replace(".", "_").replace(" ", "_")
        fid = "SPDXRef-File-%s" % safe[:120]
        # Prefer package-like entries for top-level release artifacts.
        packages.append(
            {
                "SPDXID": fid,
                "name": rel,
                "versionInfo": project_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "comment": "Repository-owned path from SHA256SUMS.",
            }
        )
        relationships.append(
            {
                "spdxElementId": root_spid,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": fid,
            }
        )
        file_ids.append(fid)

    # Top-level release-manifest artifact hashes when present.
    for name, meta in (manifest.get("artifacts") or {}).items():
        if not isinstance(meta, dict):
            continue
        rel = meta.get("path") or ("dist/%s" % name)
        if rel in METADATA_PATHS:
            continue
        digest = meta.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            # Compute from path when hash stripped/missing.
            path = root / rel
            if path.is_file():
                digest = _sha256_file(path)
            else:
                continue
        spid = "SPDXRef-Artifact-%s" % name.replace(".", "_")
        if any(p.get("SPDXID") == spid for p in packages):
            continue
        packages.append(
            {
                "SPDXID": spid,
                "name": name,
                "versionInfo": project_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "comment": "Release artifact from release-manifest.json.",
            }
        )
        relationships.append(
            {
                "spdxElementId": root_spid,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spid,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": (
            "https://github.com/datarelay-labs/datarelay-link/sbom/%s/%s"
            % (project_version, head[:12])
        ),
        "creationInfo": {
            "created": created,
            "creators": [
                "Tool: data-relay-link-generate-sbom",
                "Organization: datarelay-labs",
            ],
            "licenseListVersion": "3.23",
        },
        "packages": packages,
        "relationships": relationships
        + [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root_spid,
            }
        ],
        "comment": (
            "Factual SBOM for Data Relay Link. Stdlib-only Python imports are not "
            "listed as packages. Checksums are integrity hashes, not signatures. "
            "Derived release metadata (%s) is excluded from this inventory and "
            "from SHA256SUMS so the integrity relation stays acyclic."
            % ", ".join(sorted(METADATA_PATHS))
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        default="dist/sbom.spdx.json",
        help="Output path relative to repo root (default: dist/sbom.spdx.json)",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root (default: .)",
    )
    parser.add_argument(
        "--source-commit",
        default="",
        help=(
            "Bind the SBOM to this release source commit instead of HEAD. "
            "Must match the checked-out HEAD unless --allow-unknown-commit."
        ),
    )
    parser.add_argument(
        "--allow-unknown-commit",
        action="store_true",
        help="Permit an unresolvable source commit (non-release, offline use).",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    head = _git_head(root)
    wanted = args.source_commit.strip() or head
    if not args.allow_unknown_commit:
        if wanted == "UNKNOWN":
            print(
                "ERROR: cannot resolve the release source commit; "
                "pass --source-commit or --allow-unknown-commit",
                file=sys.stderr,
            )
            return 1
        if head != "UNKNOWN" and wanted != head:
            print(
                "ERROR: --source-commit %s does not match checked-out HEAD %s"
                % (wanted, head),
                file=sys.stderr,
            )
            return 1
    doc = build_sbom(root, source_commit=wanted)
    out = root / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    tmp.replace(out)
    print("SBOM_WRITTEN", out)
    print("SBOM_PACKAGES", len(doc.get("packages") or []))
    print("SBOM_SOURCE_COMMIT", wanted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
