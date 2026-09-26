#!/usr/bin/env python3
"""Positive/negative offline tests for RELEASE_MANIFEST.schema.json semantics."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from frp_version_identity import (  # noqa: E402
    derive_display_identity,
    validate_manifest_dict,
)


def base_manifest(**overrides):
    data = {
        "schema_version": 1,
        "project_version": "2.4.0",
        "frp_version": "0.71.0",
        "channel": "development",
        "git_ref": "0123456789abcdef0123456789abcdef01234567",
        "source_head": "0123456789abcdef0123456789abcdef01234567",
        "features": {"mcp_included": False},
        "artifacts": {
            "bootstrap-server.sh": {
                "path": "dist/bootstrap-server.sh",
                "sha256": "a" * 64,
            }
        },
    }
    data.update(overrides)
    return data


class ReleaseManifestSchemaTests(unittest.TestCase):
    def test_positive_development(self):
        errs = validate_manifest_dict(base_manifest())
        self.assertEqual(errs, [])

    def test_positive_stable(self):
        qualified = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        data = base_manifest(
            channel="stable",
            git_ref="v2.4.0",
            source_head="0123456789abcdef0123456789abcdef01234567",
            qualification={
                "status": "PASS",
                "pass1_head": qualified,
                "pass2_head": qualified,
                "final_qualified_head": qualified,
            },
        )
        errs = validate_manifest_dict(data)
        self.assertEqual(errs, [], errs)

    def test_negative_stable_pending_placeholder(self):
        data = base_manifest(
            channel="stable",
            git_ref="v2.4.0",
            qualification={"real_e2e": "pending"},
        )
        errs = validate_manifest_dict(data)
        self.assertTrue(any("PASS" in e or "qualification" in e for e in errs), errs)
        try:
            import jsonschema  # type: ignore
        except ImportError:
            return
        schema = json.loads((ROOT / "RELEASE_MANIFEST.schema.json").read_text(encoding="utf-8"))
        qualified = "a" * 40
        pending = base_manifest(
            channel="stable",
            git_ref="v2.4.0",
            source_head="0123456789abcdef0123456789abcdef01234567",
            qualification={
                "status": "PASS",
                "real_e2e": "pending",
                "pass1_head": qualified,
                "pass2_head": qualified,
                "final_qualified_head": qualified,
            },
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=pending, schema=schema)

    def test_negative_stable_pass_heads_differ(self):
        errs = validate_manifest_dict(
            base_manifest(
                channel="stable",
                git_ref="v2.4.0",
                qualification={
                    "status": "PASS",
                    "pass1_head": "a" * 40,
                    "pass2_head": "b" * 40,
                    "final_qualified_head": "a" * 40,
                },
            )
        )
        self.assertTrue(any("must be equal" in e for e in errs), errs)

    def test_negative_invalid_semver(self):
        errs = validate_manifest_dict(base_manifest(project_version="2.4"))
        self.assertTrue(any("SemVer" in e for e in errs))

    def test_negative_short_sha(self):
        errs = validate_manifest_dict(
            base_manifest(source_head="abc1234", git_ref="abc1234")
        )
        self.assertTrue(any("source_head" in e for e in errs))

    def test_negative_stable_without_tag_ref(self):
        errs = validate_manifest_dict(
            base_manifest(
                channel="stable",
                git_ref="0123456789abcdef0123456789abcdef01234567",
                qualification={},
            )
        )
        self.assertTrue(any("stable git_ref" in e for e in errs))

    def test_negative_stable_prerelease_version(self):
        # project_version pattern rejects prerelease; also semantic guard.
        errs = validate_manifest_dict(
            base_manifest(
                project_version="2.4.0-rc.1",
                channel="stable",
                git_ref="v2.4.0-rc.1",
                qualification={},
            )
        )
        self.assertTrue(errs)

    def test_negative_missing_artifacts(self):
        data = base_manifest()
        data["artifacts"] = {}
        errs = validate_manifest_dict(data)
        self.assertTrue(any("artifacts" in e for e in errs))

    def test_negative_malformed_sha256(self):
        data = base_manifest()
        data["artifacts"]["bootstrap-server.sh"]["sha256"] = "deadbeef"
        errs = validate_manifest_dict(data)
        self.assertTrue(any("malformed sha256" in e for e in errs))

    def test_v240_accepts_mcp_included_true(self):
        data = base_manifest(
            channel="development",
            features={"mcp_included": True},
        )
        errs = validate_manifest_dict(data)
        self.assertEqual(errs, [], errs)

    def test_negative_mcp_included_not_boolean(self):
        data = base_manifest(features={"mcp_included": "yes"})
        errs = validate_manifest_dict(data)
        self.assertTrue(any("mcp_included" in e for e in errs))

    def test_repo_manifest_validates(self):
        data = json.loads((ROOT / "release-manifest.json").read_text(encoding="utf-8"))
        errs = validate_manifest_dict(data)
        self.assertEqual(errs, [], errs)

    def test_schema_file_is_json(self):
        schema = json.loads((ROOT / "RELEASE_MANIFEST.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema.get("type"), "object")
        self.assertIn("mcp_included", json.dumps(schema))


class IdentityDerivationTests(unittest.TestCase):
    def test_development_identity(self):
        ident = derive_display_identity(
            project_version="2.4.0",
            channel="development",
            source_head="e30a1342b4d2e6780f1b23163a1c575d8944a535",
        )
        self.assertEqual(ident["display_identity"], "2.4.0-dev+ge30a134")
        self.assertEqual(ident["channel"], "development")

    def test_rc_identity(self):
        ident = derive_display_identity(
            project_version="2.4.0",
            channel="preview",
            source_ref="v2.4.0-rc.2",
            source_head="e30a1342b4d2e6780f1b23163a1c575d8944a535",
        )
        self.assertEqual(ident["display_identity"], "2.4.0-rc.2")
        self.assertEqual(ident["channel"], "preview")

    def test_stable_requires_tag_provenance(self):
        ident = derive_display_identity(
            project_version="2.4.0",
            channel="stable",
            source_ref="e30a1342b4d2e6780f1b23163a1c575d8944a535",
            source_head="e30a1342b4d2e6780f1b23163a1c575d8944a535",
        )
        self.assertEqual(ident["channel"], "development")
        self.assertTrue(ident["display_identity"].startswith("2.4.0-dev+g"))

    def test_stable_with_tag(self):
        ident = derive_display_identity(
            project_version="2.4.0",
            channel="stable",
            source_ref="v2.4.0",
            source_head="e30a1342b4d2e6780f1b23163a1c575d8944a535",
            tag_exists=True,
        )
        self.assertEqual(ident["display_identity"], "2.4.0")
        self.assertEqual(ident["channel"], "stable")

    def test_stable_claimed_but_tag_missing(self):
        ident = derive_display_identity(
            project_version="2.4.0",
            channel="stable",
            source_ref="v2.4.0",
            tag_exists=False,
        )
        self.assertEqual(ident["channel"], "development")


if __name__ == "__main__":
    unittest.main()
