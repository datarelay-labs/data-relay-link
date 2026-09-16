#!/usr/bin/env python3
"""Offline release-manifest schema + semantic validation.

Uses the in-tree semantic rules in lib/frp_version_identity.py. When the
`jsonschema` package is installed it also validates against
RELEASE_MANIFEST.schema.json; offline CI must not require that package.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from frp_version_identity import validate_manifest_dict  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        nargs="?",
        default=str(ROOT / "release-manifest.json"),
        help="Path to release-manifest.json",
    )
    parser.add_argument(
        "--schema",
        default=str(ROOT / "RELEASE_MANIFEST.schema.json"),
        help="Path to RELEASE_MANIFEST.schema.json",
    )
    parser.add_argument(
        "--require-jsonschema",
        action="store_true",
        help="Fail if the optional jsonschema package is unavailable",
    )
    args = parser.parse_args()

    data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    errs = validate_manifest_dict(data, require_artifacts=True)
    schema_path = Path(args.schema)
    if not schema_path.is_file():
        errs.append("schema file missing: %s" % schema_path)
    else:
        # Ensure the schema itself is parseable JSON (offline).
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        if schema.get("$schema") is None and schema.get("type") != "object":
            errs.append("schema root looks invalid")
        try:
            import jsonschema  # type: ignore
        except ImportError:
            if args.require_jsonschema:
                errs.append("jsonschema package required but not installed")
        else:
            try:
                jsonschema.validate(instance=data, schema=schema)
            except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
                errs.append("jsonschema: %s" % exc.message)

    if errs:
        for e in errs:
            print("ERROR: %s" % e, file=sys.stderr)
        print("RELEASE_MANIFEST_VALID=FAIL", file=sys.stderr)
        return 1
    print("RELEASE_MANIFEST_VALID=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
