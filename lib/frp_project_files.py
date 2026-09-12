#!/usr/bin/env python3
"""Canonical server project-file manifest loader.

This is the source of truth for:
  full installation managed files
  project-update staging/install/validation
  snapshot/rollback managed project files
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

MANIFEST_NAME = "server-project-files.manifest"
MANAGED_CLASSES = ("project", "optional", "unit", "unit-single443")
SNAPSHOT_EXTRA_CLASSES = ("generated", "binary", "version")


class FileEntry:
    __slots__ = ("cls", "dest", "mode", "source", "validate")

    def __init__(self, cls, dest, mode, source, validate):
        self.cls = cls
        self.dest = dest
        self.mode = mode
        self.source = source
        self.validate = validate


def manifest_path(explicit=None):
    if explicit:
        return Path(explicit)
    here = Path(__file__).resolve().parent
    candidate = here / MANIFEST_NAME
    if candidate.is_file():
        return candidate
    installed = Path("/usr/local/lib/drlink") / MANIFEST_NAME
    if installed.is_file():
        return installed
    env = os.environ.get("FRP_PROJECT_FILE_MANIFEST", "")
    if env:
        return Path(env)
    raise FileNotFoundError("server-project-files.manifest is missing")


def load_entries(path=None):
    text = manifest_path(path).read_text(encoding="utf-8")
    entries = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 5:
            raise ValueError("invalid manifest line: %s" % raw)
        entries.append(FileEntry(*parts))
    return entries


def _source_exists(source_root, source):
    if not source_root or source in ("-", ""):
        return True
    return (Path(source_root) / source).is_file()


def managed_entries(single443=False, source_root=None, include_optional=True, path=None):
    out = []
    for entry in load_entries(path):
        if entry.cls not in MANAGED_CLASSES:
            continue
        if entry.cls == "unit-single443" and not single443:
            continue
        if entry.cls == "optional":
            if not include_optional:
                continue
            if source_root is not None and not _source_exists(source_root, entry.source):
                continue
        out.append(entry)
    return out


def snapshot_rels(path=None):
    rels = []
    for entry in load_entries(path):
        if entry.cls in MANAGED_CLASSES or entry.cls in SNAPSHOT_EXTRA_CLASSES:
            rels.append(entry.dest)
    return rels


def managed_dests(single443=False, source_root=None, path=None):
    return [entry.dest for entry in managed_entries(single443, source_root, True, path)]


def protected_exact(path=None):
    return tuple(e.dest for e in load_entries(path) if e.cls == "protected")


def protected_prefixes(path=None):
    return tuple(e.dest for e in load_entries(path) if e.cls == "protected-prefix")


def destination_lines(single443=False, source_root=None, path=None):
    lines = []
    for entry in managed_entries(single443, source_root, True, path):
        lines.append("%s:%s:%s" % (entry.dest, entry.mode, entry.source))
    return lines


def validate_paths(kind, staged_root=None, single443=False, source_root=None, path=None):
    paths = []
    for entry in managed_entries(single443, source_root, True, path):
        if entry.validate != kind:
            continue
        rel = entry.dest
        paths.append(str(Path(staged_root, rel)) if staged_root else rel)
    return paths


def main(argv=None):
    parser = argparse.ArgumentParser(description="Server project-file manifest")
    parser.add_argument(
        "action",
        choices=("destinations", "snapshot-rels", "managed-rels", "validate-list"),
    )
    parser.add_argument("--single443", action="store_true")
    parser.add_argument("--source")
    parser.add_argument("--staged")
    parser.add_argument("--kind", choices=("bash", "python"))
    parser.add_argument("--manifest")
    args = parser.parse_args(argv)
    if args.action == "destinations":
        for line in destination_lines(args.single443, args.source, args.manifest):
            print(line)
        return 0
    if args.action == "snapshot-rels":
        for rel in snapshot_rels(args.manifest):
            print(rel)
        return 0
    if args.action == "managed-rels":
        for rel in managed_dests(args.single443, args.source, args.manifest):
            print(rel)
        return 0
    if args.action == "validate-list":
        if not args.kind:
            raise SystemExit("ERROR: --kind is required")
        for rel in validate_paths(args.kind, args.staged, args.single443, args.source, args.manifest):
            print(rel)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
