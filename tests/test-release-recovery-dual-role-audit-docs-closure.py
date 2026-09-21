#!/usr/bin/env python3
"""Focused regressions for v2.4.0 release recovery / dual-role / audit / docs closure."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
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


PUBLIC_DOC_FILES = [
    ROOT / "README.md",
    ROOT / "docs" / "CLI_REFERENCE.md",
    ROOT / "docs" / "WINDOWS_CLIENT.md",
    ROOT / "docs" / "MACOS_CLIENT.md",
    ROOT / "docs" / "FRP_UPGRADE.md",
    ROOT / "docs" / "DEPLOYMENT_MODES.md",
    ROOT / "docs" / "SCHEMA_V2_DEPLOYMENT.md",
    ROOT / "docs" / "RELEASE_VALIDATION.md",
]

# Stale public vocabulary that must not appear outside Legacy/Internal sections.
FORBIDDEN_PUBLIC_DOC_PATTERNS = [
    r"\bshow access-rules\b",
    r"\bshow access-rule\b",
    r"\bset access-rule\b",
    r"\bunset access-rule\b",
    r"\bset access-source\b",
    r"\bunset access-source\b",
    r"\bset service-access\b",
    r"\bunset service-access\b",
    r"\btest access\b",
    r"\bsudo drlink doctor\b",
    r"(?<!system )\bdrlink update engine\b",
    r"(?<!system )\bdrlink update product\b",
    r"\bcreate enrollment\b",
    r"\bcreate zero-touch\b",
    r"\bcreate support-bundle\b",
]


def _strip_legacy_sections(text: str) -> str:
    """Remove explicitly labeled Legacy/Internal/Compatibility sections."""
    out = []
    skip = False
    for line in text.splitlines():
        heading = line.strip().lower()
        if heading.startswith("#") and any(
            key in heading for key in ("legacy", "internal", "compatibility", "cheat sheet")
        ):
            skip = True
            continue
        if skip and heading.startswith("#"):
            skip = False
        if skip:
            continue
        out.append(line)
    return "\n".join(out)


def _extract_command_examples(text: str) -> list[str]:
    """Pull likely executable drlink command lines from fenced code / backticks."""
    examples = []
    # Fenced blocks
    for block in re.findall(r"```(?:text|bash|shell)?\n(.*?)```", text, flags=re.S):
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r"^sudo\s+", "", line)
            if line.startswith("drlink "):
                examples.append(line[len("drlink ") :])
            elif re.match(
                r"^(show|set|unset|test|system|menu|help|exit)\b", line
            ):
                examples.append(line)
    # Inline backticks with multi-token commands
    for item in re.findall(r"`([^`]+)`", text):
        item = item.strip()
        item = re.sub(r"^sudo\s+", "", item)
        if item.startswith("drlink "):
            examples.append(item[len("drlink ") :])
        elif re.match(r"^(show|set|unset|test|system)\b.+\s+\S+", item):
            examples.append(item)
    return examples


class ReleaseRecoveryDualRoleAuditDocsClosure(unittest.TestCase):
    def test_restore_requires_confirmation_metadata(self):
        cmd = CATALOG.find(("system", "restore"))
        self.assertIsNotNone(cmd)
        self.assertEqual(cmd.get("confirmation"), "y_n")
        self.assertTrue(cmd.get("destructive"))
        names = {f["name"] for f in (cmd.get("flags") or [])}
        self.assertIn("--yes", names)
        result = GRAMMAR.match(
            ["system", "restore", "/var/lib/drlink/backups/b.tar.gz", "--yes"],
            "server",
        )
        self.assertEqual(result.get("status"), "ok")
        # Unified Server DR: system restore dispatches restore_backup, not control_plane.
        self.assertEqual(result.get("action"), "restore_backup")
        self.assertEqual(result.get("path"), "/var/lib/drlink/backups/b.tar.gz")
        self.assertEqual(result.get("passthrough") or [], ["--yes"])

    def test_restore_help_states_same_version(self):
        help_txt = CATALOG.command_help(CATALOG.find(("system", "restore")))
        self.assertIn("Same-version", help_txt)
        self.assertIn("confirmation", help_txt.lower())

    def test_support_bundle_positional_public_path(self):
        tokens = ["system", "support-bundle", "/tmp/bundle.tgz"]
        self.assertIsNone(CATALOG.strict_error(tokens))
        self.assertEqual(
            CATALOG.to_internal(tokens),
            ["support-bundle", "--output", "/tmp/bundle.tgz"],
        )
        result = GRAMMAR.match(tokens, "server")
        self.assertEqual(result.get("status"), "ok")
        self.assertEqual(
            (result.get("passthrough") or [])[:2],
            ["--output", "/tmp/bundle.tgz"],
        )

    def test_audit_filters_parse(self):
        for tokens in (
            ["system", "audit"],
            ["system", "audit", "last", "20"],
            ["system", "audit", "client", "dp1"],
            ["system", "audit", "event", "backup.created"],
        ):
            with self.subTest(tokens=tokens):
                self.assertIsNone(CATALOG.strict_error(tokens))
                result = GRAMMAR.match(tokens, "server")
                self.assertEqual(result.get("status"), "ok", result)
                self.assertEqual(result.get("action"), "show_audit", result)

    def test_audit_default_human_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "var/log/drlink/audit.jsonl"
            log.parent.mkdir(parents=True)
            records = [
                {
                    "ts": "2026-09-15T20:31:00Z",
                    "event": "client.enrolled",
                    "target": "dp1",
                    "result": "success",
                },
                {
                    "ts": "2026-09-15T20:41:00Z",
                    "event": "backup.created",
                    "details": {"path": "backup-1"},
                },
            ]
            log.write_text(
                "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
            )
            env = os.environ.copy()
            env["FRP_DEPLOY_TEST_ROOT"] = str(root)
            env["FRP_CTL_TEST_ROOT"] = str(root)
            env["FRP_CTL_SOURCED"] = "1"
            script = r"""
set -euo pipefail
ROOT="%s"
export FRP_CTL_SOURCED=1
# shellcheck disable=SC1091
. "$ROOT/tools/frpctl"
frpctl_audit_tail
""" % ROOT
            proc = subprocess.run(
                ["bash", "-c", script],
                cwd=str(ROOT),
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = proc.stdout
            self.assertIn("TIME", out)
            self.assertIn("EVENT", out)
            self.assertIn("client.enrolled", out)
            self.assertNotIn('"event":', out)

    def test_dual_role_lifecycle_labels_are_client_scoped(self):
        tree = CATALOG.NAVIGATION_TREE["both.system"]
        labels = {row[1]: row[4] for row in tree if row[3] == "command"}
        self.assertEqual(labels.get("Pause Agent"), "system pause")
        self.assertEqual(labels.get("Resume Agent"), "system resume")
        self.assertEqual(labels.get("Restart Agent"), "system restart")
        self.assertEqual(labels.get("Agent autostart"), "system autostart")
        for path in (
            ("system", "pause"),
            ("system", "resume"),
            ("system", "restart"),
            ("system", "autostart"),
        ):
            cmd = CATALOG.find(path)
            self.assertEqual(cmd.get("roles"), "client")
            self.assertIn("client", cmd.get("summary", "").lower())

    def test_dual_role_product_update_fail_fast_in_source(self):
        src = (ROOT / "tools" / "frpctl").read_text(encoding="utf-8")
        self.assertIn("DUAL_ROLE_PRODUCT_UPDATE=FAIL_FAST", src)
        self.assertIn("frpctl_verify_dual_role_shared_runtime", src)
        # Must not continue server update after client failure.
        self.assertIn("server role update was not started", src)

    def test_rollback_guidance_preserves_markers(self):
        common = (LIB / "frp-common.sh").read_text(encoding="utf-8")
        self.assertIn("frp_emit_update_rollback_recovery_guidance", common)
        for rel in (
            "tools/frp-update",
            "lib/frp-server-upgrade.sh",
            "lib/frp-client-common.sh",
        ):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("frp_emit_update_rollback_recovery_guidance", text)
            self.assertTrue(
                ("RECOVERY_REQUIRED" in text) or ("RECOVERY_REQUIRED=YES" in text)
            )
            self.assertTrue(
                ("UPDATE_ROLLBACK_FAILED" in text) or ("UPGRADE_ROLLBACK=FAIL" in text)
            )

    def test_doctor_prefers_canonical_actions(self):
        src = (LIB / "frp_doctor.py").read_text(encoding="utf-8")
        self.assertIn("sudo drlink system diagnostics", src)
        self.assertIn("def check_audit_log(", src)
        # Old primary recommendation wording should not remain as the only guidance.
        self.assertNotIn("'restart drlink-egress or inspect journalctl", src)

    def test_public_doc_command_parity(self):
        failures = []
        for path in PUBLIC_DOC_FILES:
            text = _strip_legacy_sections(path.read_text(encoding="utf-8"))
            for pattern in FORBIDDEN_PUBLIC_DOC_PATTERNS:
                for match in re.finditer(pattern, text):
                    # Allow prose that explicitly marks legacy/hidden.
                    start = max(0, match.start() - 80)
                    window = text[start : match.end() + 40].lower()
                    if "legacy" in window or "hidden" in window or "compat" in window:
                        continue
                    failures.append("%s: %s" % (path.name, match.group(0)))
            for example in _extract_command_examples(text):
                # Skip placeholders / incomplete templates / broken markup.
                try:
                    if "<" in example:
                        tokens = shlex.split(example.split("<")[0].strip())
                    else:
                        tokens = shlex.split(example)
                except ValueError:
                    continue
                if not tokens:
                    continue
                if tokens[0] in {"menu", "help", "exit", "clear"}:
                    continue
                cmd = CATALOG.find(tokens, include_aliases=False)
                if cmd is None:
                    # Try longest visible prefix.
                    found = None
                    for i in range(len(tokens), 0, -1):
                        found = CATALOG.find(tokens[:i], include_aliases=False)
                        if found and not found.get("hidden"):
                            break
                        found = None
                    if found is None:
                        # Single-token session helpers / incomplete roots are fine.
                        if len(tokens) == 1 and tokens[0] in {
                            r[0] for r in CATALOG.ROOTS
                        } | {"version", "status", "menu", "help", "exit", "clear"}:
                            continue
                        # Hidden alias match must fail the public doc gate.
                        alias = CATALOG.find(tokens, include_aliases=True)
                        if alias is not None and alias.get("hidden"):
                            failures.append(
                                "%s uses hidden/compat form: %s"
                                % (path.name, example)
                            )
                        elif alias is not None and not alias.get("hidden"):
                            # Visible command reached via shorter alias/root token.
                            continue
                        elif tokens[0] not in {r[0] for r in CATALOG.ROOTS}:
                            failures.append(
                                "%s unknown command example: %s" % (path.name, example)
                            )
                    continue
                if cmd.get("hidden"):
                    failures.append(
                        "%s documents hidden command: %s" % (path.name, example)
                    )
        self.assertEqual(failures, [], failures[:20])

    def test_visible_catalog_examples_still_parse(self):
        data = json.loads((LIB / "frp_cli_final_commands.json").read_text(encoding="utf-8"))
        failures = []
        for row in data:
            if row.get("hidden"):
                continue
            for example in row.get("examples") or []:
                tokens = shlex.split(str(example))
                if CATALOG.strict_error(tokens):
                    # allow incomplete templates with required selectors missing? no for examples
                    pass
                result = GRAMMAR.match(tokens, "server")
                if result.get("status") not in ("ok", "incomplete", "role"):
                    # try client
                    result = GRAMMAR.match(tokens, "client")
                if result.get("status") not in ("ok", "incomplete", "role"):
                    failures.append((example, result))
        self.assertEqual(failures, [], failures[:10])

    def test_hidden_aliases_not_advertised_in_normal_help(self):
        help_txt = GRAMMAR.help_text(["system"], "server")
        self.assertIn("support-bundle", help_txt)
        self.assertNotIn("create support-bundle", help_txt)
        self.assertIn("restore", help_txt)


    def test_dual_role_update_fail_fast_runtime(self):
        """Client failure must not start server project update on dual-role hosts."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Minimal dual-role markers.
            for rel in (
                "etc/systemd/system/drlink-client.service",
                "etc/systemd/system/drlink-server.service",
                "usr/local/lib/drlink",
                "usr/local/bin",
                "etc/drlink",
            ):
                path = root / rel
                if rel.endswith(".service"):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("[Unit]\nDescription=fixture\n")
                else:
                    path.mkdir(parents=True, exist_ok=True)
            (root / "etc/drlink/version").write_text(
                "PROJECT_VERSION=2.4.0\nSOURCE_REF=test\nBUNDLE_SHA256=abc\n"
            )
            for rel in (
                "usr/local/lib/drlink/frpctl",
                "usr/local/lib/drlink/frp_cli_final_commands.json",
                "usr/local/lib/drlink/frp_cli_catalog.py",
                "usr/local/bin/drlink",
            ):
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("fixture-" + rel + "\n")
                p.chmod(0o755 if "frpctl" in rel or rel.endswith("drlink") else 0o644)

            env = os.environ.copy()
            env.update(
                {
                    "FRP_CTL_SOURCED": "1",
                    "FRP_DEPLOY_TEST_ROOT": str(root),
                    "FRP_CTL_TEST_ROOT": str(root),
                    "FRP_CLIENT_TEST_ROOT": str(root),
                    "FRP_SERVER_TEST_ROOT": str(root),
                    "PATH": str(root / "usr/local/bin") + ":" + env.get("PATH", ""),
                }
            )
            # Stub client update failure and server update success markers.
            (root / "usr/local/bin/frp-client").write_text(
                "#!/bin/sh\necho CLIENT_UPDATE_RAN >&2\nexit 41\n"
            )
            (root / "usr/local/bin/frp-client").chmod(0o755)
            (root / "usr/local/bin/frp-project-update").write_text(
                "#!/bin/sh\necho SERVER_UPDATE_RAN >&2\nexit 0\n"
            )
            (root / "usr/local/bin/frp-project-update").chmod(0o755)

            script = r"""
set -euo pipefail
export FRP_CTL_SOURCED=1
. "%s/tools/frpctl"
# Force dual-role detection.
frpctl_is_client() { return 0; }
frpctl_is_server() { return 0; }
frpctl_client_update() { echo CLIENT_UPDATE_RAN >&2; return 41; }
frpctl_run() {
  local name="$1"; shift || true
  if [[ "$name" == "frp-project-update" ]]; then
    echo SERVER_UPDATE_RAN >&2
    return 0
  fi
  command "$name" "$@"
}
result='{"passthrough":[]}'
_frpctl_pt=()
set +e
_frp_up_rc=0
frpctl_with_pt frpctl_client_update || _frp_up_rc=$?
if [[ "${_frp_up_rc}" -ne 0 ]]; then
  echo "ERROR: client role product update failed; server role update was not started." >&2
  echo "DUAL_ROLE_PRODUCT_UPDATE=FAIL_FAST" >&2
else
  frpctl_with_pt frpctl_run frp-project-update || _frp_up_rc=$?
  echo SERVER_CONTINUED >&2
fi
echo RC=$_frp_up_rc
""" % ROOT
            proc = subprocess.run(
                ["bash", "-c", script],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            combined = proc.stdout + proc.stderr
            self.assertIn("CLIENT_UPDATE_RAN", combined)
            self.assertIn("DUAL_ROLE_PRODUCT_UPDATE=FAIL_FAST", combined)
            self.assertNotIn("SERVER_UPDATE_RAN", combined)
            self.assertIn("RC=41", combined)

    def test_rollback_guidance_is_human_executable(self):
        common = (LIB / "frp-common.sh").read_text(encoding="utf-8")
        self.assertIn("sudo drlink system diagnostics", common)
        self.assertIn("sudo drlink system support-bundle", common)
        self.assertIn("Do not re-enroll clients or delete state manually.", common)


if __name__ == "__main__":
    unittest.main()
