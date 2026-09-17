#!/usr/bin/env python3
"""Focused regressions for v2.4.0 operational UX / CLI / recovery closure."""
from __future__ import annotations

import importlib.util
import json
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "lib"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CATALOG = _load("frp_cli_catalog", LIB / "frp_cli_catalog.py")
GRAMMAR = _load("frp_ctl_grammar", LIB / "frp_ctl_grammar.py")


def _match(tokens, role):
    return GRAMMAR.match(list(tokens), role)


class OperationalUxClosureTests(unittest.TestCase):
    def test_acl_unassign_surface_rejected(self):
        tokens = ["unset", "acl", "office", "service", "dp1", "ssh"]
        result = _match(tokens, "server")
        self.assertEqual(result.get("status"), "error")
        self.assertNotEqual(result.get("action"), "access_cmd")

    def test_wrong_acl_cannot_silently_become_public_rewrite(self):
        # Obsolete ACL grammar must not translate into any mutating action.
        tokens = ["unset", "acl", "definitely-does-not-exist", "service", "dp1", "ssh"]
        result = _match(tokens, "server")
        self.assertEqual(result.get("status"), "error")
        self.assertNotIn(result.get("action"), ("access_cmd", "set_access_public", "access_public"))

    def test_client_service_edit_public_cli(self):
        cases = [
            (["set", "service", "ssh", "target-port", "2222"], "set_service"),
            (["set", "service", "ssh", "target-host", "127.0.0.1"], "set_service"),
            (["set", "service", "ssh", "enabled"], "enable_service"),
            (["unset", "service", "ssh", "enabled"], "disable_service"),
        ]
        for tokens, action in cases:
            with self.subTest(tokens=tokens):
                self.assertIsNone(CATALOG.strict_error(tokens))
                result = _match(tokens, "client")
                self.assertEqual(result.get("status"), "ok", result)
                self.assertEqual(result.get("action"), action, result)

    def test_service_profile_edit_public_cli_rejected(self):
        tokens = ["set", "service-profile", "office-ssh", "target-port", "22"]
        result = _match(tokens, "server")
        self.assertEqual(result.get("status"), "error", result)
        self.assertNotEqual(result.get("action"), "set_profile")

    def test_public_catalog_examples_parse(self):
        data = json.loads((LIB / "frp_cli_final_commands.json").read_text(encoding="utf-8"))
        failures = []
        for row in data:
            if row.get("hidden"):
                continue
            if row.get("illustrative") or row.get("non_executable"):
                continue
            roles = str(row.get("roles") or "any")
            role_candidates = []
            if roles in ("any", "both", "dual"):
                role_candidates = ["server", "client"]
            elif roles == "server":
                role_candidates = ["server"]
            elif roles == "client":
                role_candidates = ["client"]
            else:
                role_candidates = ["server", "client"]
            for example in row.get("examples") or []:
                tokens = shlex.split(str(example))
                if not tokens:
                    continue
                # Skip examples that intentionally require live selectors only.
                ok = False
                detail = None
                for role in role_candidates:
                    if not CATALOG.role_allows(row.get("roles"), role):
                        continue
                    err = CATALOG.strict_error(tokens)
                    if err:
                        detail = err
                        continue
                    result = _match(tokens, role)
                    status = result.get("status")
                    if status in ("ok", "incomplete", "role"):
                        ok = True
                        break
                    detail = result
                if not ok:
                    failures.append((example, detail))
        self.assertEqual(failures, [], failures[:12])

    def test_parent_command_discovery_not_unknown(self):
        cases = [
            (["system", "update"], "server"),
            (["system", "services"], "client"),
        ]
        for tokens, role in cases:
            with self.subTest(tokens=tokens):
                result = _match(tokens, role)
                self.assertEqual(result.get("status"), "incomplete", result)
                msg = result.get("message") or ""
                self.assertNotIn("Unknown system operation", msg)
                self.assertIn("Available:", msg)

    def test_obsolete_system_export_import_rejected(self):
        # Legacy internet-profile export/import parents must not remain as
        # successful mutating surfaces.
        for tokens in (["system", "export"], ["system", "import"]):
            with self.subTest(tokens=tokens):
                result = _match(tokens, "server")
                self.assertIn(result.get("status"), ("error", "incomplete"), result)
                msg = (result.get("message") or "").lower()
                self.assertTrue(
                    "unknown" in msg or "obsolete" in msg or "not part" in msg,
                    result,
                )
                self.assertNotEqual(result.get("action"), "control_plane")

    def test_system_server_status_parity(self):
        result = _match(["system", "server-status"], "server")
        self.assertEqual(result.get("status"), "ok")
        self.assertEqual(result.get("action"), "show_server_status")

    def test_installer_url_set_unset_symmetry(self):
        set_linux = _match(
            ["set", "server", "installer-url", "https://example.test/install.sh"],
            "server",
        )
        set_win = _match(
            ["set", "server", "windows-installer-url", "https://example.test/install.ps1"],
            "server",
        )
        unset_linux = _match(["unset", "server", "installer-url"], "server")
        unset_win = _match(["unset", "server", "windows-installer-url"], "server")
        self.assertEqual(set_linux.get("action"), "set_installer_url")
        self.assertEqual(set_win.get("action"), "set_windows_installer_url")
        self.assertEqual(unset_linux.get("action"), "unset_installer_url")
        self.assertEqual(unset_win.get("action"), "unset_windows_installer_url")

    def test_windows_installer_url_guided_discovery(self):
        entries = CATALOG.NAVIGATION_TREE.get("server.system.settings") or ()
        labels = [row[1] for row in entries]
        targets = [row[4] for row in entries if len(row) > 4]
        self.assertTrue(any("Windows" in str(label) for label in labels), labels)
        self.assertIn("set_windows_installer_url", targets)

    def test_menu_service_workflows_use_canonical_grammar(self):
        # Guided edit/enable/disable must resolve through final public grammar.
        for tokens in (
            ["set", "service", "ssh", "target-port", "2222"],
            ["set", "service", "ssh", "enabled"],
            ["unset", "service", "ssh", "enabled"],
        ):
            result = _match(tokens, "client")
            self.assertEqual(result.get("status"), "ok", result)

    def test_context_management_labels_not_view_only(self):
        text = (ROOT / "tools" / "frpctl").read_text(encoding="utf-8")
        for name in (
            "frpctl_manage_one_acl",
            "frpctl_manage_one_service_profile",
            "frpctl_manage_one_egress_profile",
            "frpctl_manage_one_fixed_tcp",
        ):
            self.assertIn("%s()" % name, text)
        # Misleading ACL public flow must not ask for ACL name first.
        self.assertIn('public_access)', text)
        # Workflow body should select client/service, not prompt ACL first.
        start = text.index("public_access)")
        chunk = text[start : start + 900]
        self.assertIn("frpctl_select_inventory clients", chunk)
        self.assertNotIn('nav_prompt_id "ACL name', chunk)

    def test_pretag_upgrade_url_uses_source_ref(self):
        text = (ROOT / "install-client.sh").read_text(encoding="utf-8")
        self.assertIn("frp_client_installed_source_ref", text)
        self.assertNotIn(
            'v${PROJECT_VERSION}/dist/bootstrap-client.sh | sudo bash -s -- --upgrade',
            text,
        )

    def test_partial_install_installs_management_before_runtime(self):
        text = (ROOT / "install-client.sh").read_text(encoding="utf-8")
        mgmt = text.index("frp_client_install_management_files")
        start = text.index("Starting Data Relay Link client")
        self.assertLess(mgmt, start)

    def test_state_diff_helper_semantics_clear(self):
        text = (LIB / "frp-client-common.sh").read_text(encoding="utf-8")
        self.assertIn("frp_state_has_no_diff()", text)
        # Compatibility alias may remain, but primary callers should use clear name.
        client = (ROOT / "tools" / "frp-client").read_text(encoding="utf-8")
        self.assertIn("frp_state_has_no_diff", client)

    def test_pending_service_changes_discoverable_in_status_code(self):
        text = (ROOT / "tools" / "frp-client").read_text(encoding="utf-8")
        self.assertIn("Pending service changes : YES", text)
        self.assertIn("system services apply", text)
        self.assertIn("system services discard", text)

    def test_menu_command_targets_resolve(self):
        # Every guided command target must exist in final public grammar.
        missing = []
        for _key, entries in (CATALOG.NAVIGATION_TREE or {}).items():
            for row in entries:
                if len(row) < 5:
                    continue
                kind, target = row[3], row[4]
                if kind != "command" or not target:
                    continue
                tokens = shlex.split(str(target))
                found = CATALOG.find(tokens)
                if found is None:
                    # Parent discovery nodes are acceptable.
                    children, _rows = GRAMMAR._catalog_child_tokens(tokens, "server")
                    children2, _ = GRAMMAR._catalog_child_tokens(tokens, "client")
                    if not children and not children2:
                        missing.append(target)
        self.assertEqual(missing, [])


class AclUnassignFailClosedTests(unittest.TestCase):
    def test_legacy_access_tool_absent(self):
        self.assertFalse((ROOT / "tools" / "frp-access").exists())

    def test_grammar_rejects_acl_unassign_surface(self):
        result = GRAMMAR.match(["unset", "acl", "office", "service", "c1", "ssh"], "server")
        self.assertEqual(result.get("status"), "error")

if __name__ == "__main__":
    unittest.main()
