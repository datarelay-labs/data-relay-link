#!/usr/bin/env python3
"""Generate a factual SPDX JSON SBOM for Data Relay Link release artifacts.

Includes only repository-owned facts: project version, git commit, pinned FRP
version and known upstream binary hashes, release artifacts, and owned scripts/
modules listed in SHA256SUMS / manifests. Does not invent third-party Python
dependencies for stdlib imports. Writes no host secrets or local absolute paths
beyond relative repository paths.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


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


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except Exception:
        return "UNKNOWN"


def _parse_sha256sums(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            digest, rel = parts[0], parts[-1]
            if rel.startswith("*"):
                rel = rel[1:]
            rows.append((digest, rel))
    return rows


def build_sbom(root: Path) -> dict:
    values = _read_version(root)
    project_version = values.get("PROJECT_VERSION", "")
    frp_version = values.get("FRP_VERSION", "")
    head = _git_head(root)
    manifest = json.loads((root / "release-manifest.json").read_text(encoding="utf-8"))
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "gitCommit",
                    "referenceLocator": head,
                }
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
        safe = rel.replace("/", "-").replace(".", "_")
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
        digest = meta.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            # Compute from path when hash stripped/missing.
            rel = meta.get("path") or ("dist/%s" % name)
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
            "https://github.com/datarelay-labs/data-relay-link/sbom/%s/%s"
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
            "listed as packages. Checksums are integrity hashes, not signatures."
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
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    doc = build_sbom(root)
    out = root / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    tmp.replace(out)
    print("SBOM_WRITTEN", out)
    print("SBOM_PACKAGES", len(doc.get("packages") or []))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
