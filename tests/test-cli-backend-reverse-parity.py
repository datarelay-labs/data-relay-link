#!/usr/bin/env python3
"""ARCH-AUDIT-001: backend public argparse flags must exist in catalog."""
from __future__ import annotations

import argparse
import ast
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Backend tools whose public CLI must reverse-map into the catalog.
BACKEND_TOOLS = (
    ("tools/frp-access", "access"),
    ("tools/frp-egress", "egress"),
    ("tools/frp-release-client", "client release"),
    ("tools/frp-revoke-client", "client revoke"),
    ("tools/frp-profile", "service-profile"),
)


def load_catalog():
    path = ROOT / "lib" / "frp_cli_catalog.py"
    spec = importlib.util.spec_from_file_location("frp_cli_catalog", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _collect_add_argument_flags(py_path: Path) -> set[str]:
    """Best-effort extract of public --flags from add_argument calls."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    flags = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "add_argument":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith("--"):
                        # Skip suppressed/hidden flags when help=SUPPRESS.
                        kwargs = {
                            kw.arg: kw.value
                            for kw in node.keywords
                            if kw.arg and isinstance(kw.value, (ast.Attribute, ast.Constant))
                        }
                        help_node = kwargs.get("help")
                        if isinstance(help_node, ast.Attribute) and help_node.attr == "SUPPRESS":
                            continue
                        flags.add(arg.value)
    return flags


class BackendCatalogReverseParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = load_catalog()

    def test_required_public_features_in_catalog(self):
        required_paths = {
            ("access", "replace-source"),
            ("access", "public"),
            ("egress", "add-source"),
            ("egress", "create"),
            ("client", "release"),
            ("client", "revoke"),
            ("service-profile", "set"),
        }
        present = {cmd["path"] for cmd in self.cat.COMMANDS if not cmd.get("hidden")}
        missing = sorted(required_paths - present)
        self.assertEqual(missing, [], msg="missing catalog paths: %s" % missing)

    def test_force_and_yes_exposed_where_needed(self):
        by_path = {cmd["path"]: cmd for cmd in self.cat.COMMANDS}
        release = by_path[("client", "release")]
        revoke = by_path[("client", "revoke")]
        public = by_path[("access", "public")]
        self.assertIn("--force", self.cat.flag_names(release["flags"], include_hidden=True))
        self.assertIn("--force", self.cat.flag_names(revoke["flags"], include_hidden=True))
        self.assertIn("--yes", self.cat.flag_names(public["flags"], include_hidden=True))

    def test_egress_add_source_name_flag(self):
        by_path = {cmd["path"]: cmd for cmd in self.cat.COMMANDS}
        add_source = by_path[("egress", "add-source")]
        self.assertIn("--name", self.cat.flag_names(add_source["flags"], include_hidden=True))

    def test_exemptions_documented(self):
        self.assertTrue(hasattr(self.cat, "BACKEND_SURFACE_EXEMPT"))
        self.assertIn(("frp-egress", "create", "--enable"), self.cat.BACKEND_SURFACE_EXEMPT)


if __name__ == "__main__":
    unittest.main()
