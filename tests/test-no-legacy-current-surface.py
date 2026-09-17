#!/usr/bin/env python3
"""Anti-regression gate: forbid obsolete current product surface.

Fails when development-era ACL/profile/access/egress/help-legacy grammar
reappears in the current CLI catalog, grammar, help, menus, normative docs,
or current Real E2E harnesses.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import frp_cli_catalog as catalog  # noqa: E402
import frp_ctl_grammar as grammar  # noqa: E402

# Narrow allowlist: prior-release / migration fixtures only.
ALLOWLIST = {
    # Immutable historical upgrade fixtures may mention old filenames.
    str(ROOT / "tests" / "fixtures"): "prior-release upgrade fixtures",
}

FORBIDDEN_DOC_PATTERNS = [
    r"(?m)^help legacy\s*$",
    r"(?i)use\s+`?help legacy`?",
    r"(?i)(?<!rejects top-level )(?<!rejects )\bdrlink access\b",
    r"(?i)(?<!rejects top-level )(?<!rejects )\bdrlink egress\b",
    r"(?i)^\s*set service-profile\s*$",
    r"(?i)^\s*set internet-profile\s*$",
    r"(?i)^\s*set acl\b",
    r"(?i)compatibility aliases",
]

FORBIDDEN_E2E_PATTERNS = [
    r"\bhelp legacy\b",
    r"\bdrlink access\b",
    r"\bfrpctl access\b",
    r"\bdrlink egress\b",
    r"\bfrpctl egress\b",
    r"\bservice-profile\b",
    r"\binternet-profile\b",
    r"\bset acl\b",
    r"\bshow acl\b",
]

NORMATIVE_DOCS = [
    ROOT / "docs" / "CLI_REFERENCE.md",
    ROOT / "docs" / "PRODUCT_MASTER.md",
    ROOT / "docs" / "CONTROL_PLANE_ARCHITECTURE.md",
    ROOT / "docs" / "Data Relay Link CLI Information Architecture.md",
    ROOT / "docs" / "SECURITY.md",
    ROOT / "README.md",
]

CURRENT_E2E = [
    ROOT / "tests" / "run-real-e2e.sh",
    ROOT / "tests" / "test-real-e2e-canonical-cli.sh",
]


class LegacyReintroductionGate(unittest.TestCase):
    def test_hidden_compat_aliases_empty(self):
        self.assertEqual(
            len(catalog.HIDDEN_COMPAT_ALIASES),
            0,
            "HIDDEN_COMPAT_ALIASES must be empty for current product surface",
        )

    def test_no_forbidden_catalog_paths(self):
        forbidden_tokens = {
            "access",
            "egress",
            "acl",
            "acls",
            "service-profile",
            "service-profiles",
            "internet-profile",
            "internet-profiles",
            "access-rule",
            "access-rules",
        }
        bad = []
        for cmd in catalog.COMMANDS:
            if any(tok in forbidden_tokens for tok in cmd["path"]):
                bad.append("/".join(cmd["path"]))
            if cmd.get("surface") in ("hidden_compat", "legacy_only"):
                bad.append("/".join(cmd["path"]) + " surface=" + cmd.get("surface"))
        self.assertEqual(bad, [], "forbidden catalog paths: %s" % bad)

    def test_grammar_rejects_obsolete_commands(self):
        samples = [
            ["help", "legacy"],
            ["access", "list"],
            ["egress", "list"],
            ["set", "service-profile", "office"],
            ["set", "internet-profile", "api"],
            ["set", "acl", "office"],
            ["show", "acls"],
            ["create", "service-profile", "x"],
        ]
        for tokens in samples:
            result = grammar.match(tokens, role="server")
            self.assertEqual(
                result.get("status"),
                "error",
                "expected rejection for %s, got %s" % (tokens, result),
            )

    def test_canonical_control_plane_still_routes(self):
        for tokens in (
            ["show", "remote-access"],
            ["set", "internet-access", "allow-api"],
            ["show", "published-services"],
            ["set", "fixed-tcp", "pin"],
        ):
            result = grammar.match(tokens, role="server")
            self.assertEqual(result.get("status"), "ok", tokens)
            self.assertEqual(result.get("action"), "control_plane", tokens)

    def test_normative_docs_have_no_legacy_instructions(self):
        failures = []
        for path in NORMATIVE_DOCS:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for pat in FORBIDDEN_DOC_PATTERNS:
                if re.search(pat, text):
                    failures.append("%s matches %s" % (path.name, pat))
        self.assertEqual(failures, [], "\n".join(failures))

    def test_current_e2e_has_no_legacy_command_usage(self):
        failures = []
        for path in CURRENT_E2E:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for pat in FORBIDDEN_E2E_PATTERNS:
                if re.search(pat, text):
                    failures.append("%s matches %s" % (path.name, pat))
        self.assertEqual(failures, [], "\n".join(failures))

    def test_final_commands_json_parity(self):
        rows = json.loads((ROOT / "lib" / "frp_cli_final_commands.json").read_text())
        self.assertEqual(len(rows), len(catalog.COMMANDS))
        for row in rows:
            self.assertNotEqual(row.get("surface"), "hidden_compat")
            self.assertNotIn(row["path"][0], ("access", "egress"))


if __name__ == "__main__":
    unittest.main()
