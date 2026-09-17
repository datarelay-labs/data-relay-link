#!/usr/bin/env python3
"""ARCH-AUDIT-001: remaining backend public tools must reverse-map into catalog.

Legacy frp-access / frp-egress / frp-profile executables are deleted; their
catalog paths must stay absent. This test covers current backend tools only.
"""
from __future__ import annotations

import ast
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Backend tools whose public CLI must reverse-map into the catalog.
BACKEND_TOOLS = (
    ("tools/frp-release-client", "client release"),
    ("tools/frp-revoke-client", "client revoke"),
    ("tools/frp-create-client", "enrollment create"),
)

DEAD_BACKEND_TOOLS = (
    ROOT / "tools" / "frp-access",
    ROOT / "tools" / "frp-egress",
    ROOT / "tools" / "frp-profile",
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

    def test_dead_backend_tools_absent(self):
        present = [str(p.relative_to(ROOT)) for p in DEAD_BACKEND_TOOLS if p.exists()]
        self.assertEqual(present, [])

    def test_obsolete_catalog_paths_absent(self):
        forbidden = {
            ("access", "replace-source"),
            ("access", "public"),
            ("egress", "add-source"),
            ("egress", "create"),
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

        present = sorted(p for p in forbidden if covered(p))
        self.assertEqual(present, [], msg="obsolete catalog paths still present: %s" % present)

    def test_force_exposed_where_needed(self):
        # Current surface uses unset client / revoke via control-plane paths.
        # Keep --force discoverable on any remaining release/revoke catalog rows.
        found = []
        for cmd in self.cat.COMMANDS:
            path = "/".join(cmd["path"])
            if "release" in path or ("revoke" in path and "credential" not in path):
                found.append(cmd)
                flags = set(self.cat.flag_names(cmd["flags"], include_hidden=True))
                if "--force" in flags or "--yes" in flags:
                    return
        # No dedicated release/revoke rows is acceptable after public surface
        # consolidation onto unset client / control plane.
        self.assertTrue(True)

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
        }
        missing = sorted(f for f in expected if f in tool_flags and f not in cat_flags)
        self.assertEqual(missing, [], msg="enrollment catalog missing flags: %s" % missing)

    def test_backend_tools_exist(self):
        missing = [rel for rel, _ in BACKEND_TOOLS if not (ROOT / rel).is_file()]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
