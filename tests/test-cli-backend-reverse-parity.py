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
    ("tools/frp-create-client", "enrollment create"),
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
        def covered(path):
            for cmd in self.cat.COMMANDS:
                if cmd.get("hidden"):
                    continue
                if cmd["path"] == path:
                    return True
                if path in (cmd.get("aliases") or ()):
                    return True
            return self.cat.find(list(path), include_aliases=True) is not None

        missing = sorted(p for p in required_paths if not covered(p))
        self.assertEqual(missing, [], msg="missing catalog paths: %s" % missing)

    def test_force_and_yes_exposed_where_needed(self):
        release = self.cat.find(["release", "client"], include_aliases=True)
        revoke = self.cat.find(["revoke", "client"], include_aliases=True)
        public = self.cat.find(["set", "access-public"], include_aliases=True)
        self.assertIsNotNone(release)
        self.assertIsNotNone(revoke)
        self.assertIsNotNone(public)
        self.assertIn("--force", self.cat.flag_names(release["flags"], include_hidden=True))
        self.assertIn("--force", self.cat.flag_names(revoke["flags"], include_hidden=True))
        self.assertIn("--yes", self.cat.flag_names(public["flags"], include_hidden=True))

    def test_egress_add_source_name_flag(self):
        add_source = self.cat.find(["add", "egress-source"], include_aliases=True)
        self.assertIsNotNone(add_source)
        self.assertIn("--name", self.cat.flag_names(add_source["flags"], include_hidden=True))

    def test_exemptions_documented(self):
        self.assertTrue(hasattr(self.cat, "BACKEND_SURFACE_EXEMPT"))
        self.assertIn(("frp-egress", "create", "--enable"), self.cat.BACKEND_SURFACE_EXEMPT)

    def test_create_client_flags_in_enrollment_catalog(self):
        tool_flags = _collect_add_argument_flags(ROOT / "tools" / "frp-create-client")
        cmd = self.cat.find(["create", "enrollment"], include_aliases=True)
        self.assertIsNotNone(cmd)
        cat_flags = set(self.cat.flag_names(cmd["flags"], include_hidden=True))
        expected = {
            "--ttl",
            "--one-line",
            "--ssh",
            "--ssh-user",
            "--ssh-port",
            "--services-file",
            "--platform",
            "--rdp",
            "--rdp-port",
            "--client-name",
            "--label",
            "--note",
        }
        missing = sorted(flag for flag in expected if flag in tool_flags and flag not in cat_flags)
        self.assertEqual(missing, [], msg="catalog missing enrollment flags: %s" % missing)

    def test_enrollment_public_flags_documented(self):
        cmd = self.cat.find(["create", "enrollment"], include_aliases=True)
        by_name = {f["name"]: f for f in cmd["flags"]}
        for name in ("--services-file", "--platform", "--rdp", "--rdp-port"):
            self.assertIn(name, by_name)
            self.assertTrue(by_name[name].get("description"))

    def test_enable_service_alias_includes_enabled(self):
        # Regression: enable service <id> must not collapse to bare set service <id>.
        import frp_ctl_grammar as g

        for toks in (
            ["enable", "service", "web"],
            ["service", "enable", "web"],
            ["disable", "service", "web"],
            ["service", "disable", "web"],
        ):
            resolved = self.cat.resolve_tokens(toks, role="client")
            if toks[0] in ("enable",) or toks[:2] == ["service", "enable"]:
                self.assertEqual(resolved, ["set", "service", "web", "enabled"])
                matched = g.match(resolved, "client")
                self.assertEqual(matched.get("action"), "enable_service")
            else:
                self.assertEqual(resolved, ["unset", "service", "web", "enabled"])
                matched = g.match(resolved, "client")
                self.assertEqual(matched.get("action"), "disable_service")


if __name__ == "__main__":
    unittest.main()
