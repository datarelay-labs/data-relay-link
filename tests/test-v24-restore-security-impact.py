#!/usr/bin/env python3
"""P0: Server restore DENY→ALLOW security-impact confirmation.

Restore must compare live vs candidate Access policy and require confirmation
when restoring broadens Remote / Internet / AI Access (or causes DENY ALL).
Cancel/missing confirmation must leave authoritative state unchanged.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from drlink_control_plane import ControlPlane
import drlink_v24 as v24

BACKUP = ROOT / "tools" / "frp-backup"
RESTORE = ROOT / "tools" / "frp-restore"


def load_restore():
    loader = SourceFileLoader("frp_restore_impact", str(RESTORE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def seed_server(tree: Path, marker: str = "orig") -> ControlPlane:
    for rel in (
        "etc/drlink/pki",
        "etc/frp",
        "var/lib/drlink/enrollments",
        "var/lib/drlink/bootstrap",
        "var/lib/drlink/backups",
        "var/log/drlink",
    ):
        (tree / rel).mkdir(parents=True, exist_ok=True)
    (tree / "etc/drlink/config.json").write_text(
        json.dumps(
            {
                "role": "server",
                "marker": marker,
                "public_hostname": "dr.example.test",
                "public_host": "dr.example.test",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tree / "etc/drlink/version").write_text(
        "PROJECT_VERSION=2.4.0\nRELEASE_CHANNEL=dev\nSOURCE_REF=test\n",
        encoding="utf-8",
    )
    for name in ("ca.key", "ca.crt", "server.key", "server.crt"):
        (tree / "etc/drlink/pki" / name).write_text("%s-%s\n" % (name, marker), encoding="utf-8")
    (tree / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (tree / "etc/frp/server_token").write_text("token-%s\n" % marker, encoding="utf-8")
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(tree)
    os.environ["FRP_BACKUP_ALREADY_LOCKED"] = "1"
    os.environ["DRLINK_SKIP_ACTIVATION"] = "1"
    plane = ControlPlane(str(tree))
    v24.ensure_v2_schema(plane.conn)
    plane.conn.execute(
        "INSERT OR REPLACE INTO clients(id, label, hostname, created_at, updated_at) "
        "VALUES ('cccccccccccccccccccccccccccccccc', ?, 'host-a', datetime('now'), datetime('now'))",
        (marker,),
    )
    plane.conn.commit()
    plane.compile_runtime()
    return plane


def run_tool(tool: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(tool), *args],
        capture_output=True,
        text=True,
        env=merged,
    )


def _verify(plane: ControlPlane, name: str) -> None:
    plane.conn.execute(
        "UPDATE ai_principals SET credential_status = 'verified', enabled = 1 WHERE name = ?",
        (name,),
    )
    plane.conn.commit()


class RestoreSecurityImpactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-restore-impact-")
        self.tree = Path(self.tmp.name) / "root"
        self.tree.mkdir()
        self.outdir = Path(self.tmp.name) / "out"
        self.outdir.mkdir()
        self.plane = seed_server(self.tree, "orig")
        os.environ.pop("DRLINK_CONFIRM", None)
        os.environ.pop("FRP_RESTORE_YES", None)

    def tearDown(self):
        try:
            self.plane.close()
        except Exception:
            pass
        for key in (
            "FRP_DEPLOY_TEST_ROOT",
            "FRP_BACKUP_ALREADY_LOCKED",
            "DRLINK_SKIP_ACTIVATION",
            "DRLINK_CONFIRM",
            "FRP_RESTORE_YES",
            "FRP_RESTORE_HOOK_FAIL_AFTER",
            "FRP_RESTORE_HOOK_HEALTH_FAIL",
            "FRP_RESTORE_HOOK_ROLLBACK_HEALTH_FAIL",
        ):
            os.environ.pop(key, None)
        self.tmp.cleanup()

    def _backup(self, name: str = "server") -> Path:
        archive = self.outdir / ("%s.tar.gz" % name)
        proc = run_tool(BACKUP, str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return archive

    def _seed_remote_whitelist(self):
        v24.set_network_object(
            self.plane, "src1", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "svc", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "allow-ssh",
            mode="whitelist",
            source="src1",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )

    def _seed_remote_blacklist(self):
        v24.set_network_object(
            self.plane, "bad", type="ip", value="198.51.100.66", oneshot=True
        )
        v24.set_network_object(
            self.plane, "dst", type="ip", value="198.51.100.20", oneshot=True
        )
        v24.set_service_object(self.plane, "svc", type="tcp", port=22, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "remote",
            "block-bad",
            mode="blacklist",
            source="bad",
            destination="dst",
            service="svc",
            enabled=True,
            oneshot=True,
        )

    def _seed_internet_whitelist(self):
        v24.set_network_object(
            self.plane, "lan", type="ip", value="10.10.10.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "web", type="fqdn", value="example.com", oneshot=True
        )
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-web",
            mode="whitelist",
            source="lan",
            destination="web",
            service="https",
            enabled=True,
            oneshot=True,
        )

    def _seed_ai_whitelist(self):
        self.plane.set_ai_principal("bot", enabled=True)
        _verify(self.plane, "bot")
        v24.set_network_object(
            self.plane, "ubuntu-prod", type="ip", value="198.51.100.10", oneshot=True
        )
        v24.set_permission_object(
            self.plane, "exec-only", permissions=["command-exec"], oneshot=True
        )
        v24.set_ai_access_rule(
            self.plane,
            "allow-exec",
            mode="whitelist",
            source="bot",
            destination="ubuntu-prod",
            permission="exec-only",
            enabled=True,
            oneshot=True,
        )

    def _remote_unmatched(self) -> str:
        result = v24.evaluate_selector_policy(
            self.plane,
            "remote",
            source_name="src1" if self.plane.get_object("src1") else "bad",
            destination_name="dst",
            service_name="svc",
        )
        # Prefer an unmatched source when src1 is the allowlist member.
        pol = v24.get_access_policy(self.plane, "remote")
        if pol.get("mode") == "whitelist":
            result = self.plane.evaluate_remote_access(
                "203.0.113.9", "198.51.100.20", "tcp", 22
            )
            return str(result.get("action") or result.get("effective") or "")
        if pol.get("mode") == "blacklist":
            result = self.plane.evaluate_remote_access(
                "203.0.113.9", "198.51.100.20", "tcp", 22
            )
            return str(result.get("action") or result.get("effective") or "")
        return str(result.get("result") or "")

    def test_remote_whitelist_to_no_policy_requires_confirm_and_cancel_is_noop(self):
        # Permissive No Policy backup.
        permissive = self._backup("permissive")
        token_before = (self.tree / "etc/frp/server_token").read_text(encoding="utf-8")

        self._seed_remote_whitelist()
        rev_before = self.plane.current_revision()
        self.assertEqual(
            self.plane.evaluate_remote_access("203.0.113.9", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "DENY",
        )

        # Unconfirmed restore must not mutate.
        proc = run_tool(RESTORE, str(permissive))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Cancelled", proc.stdout + proc.stderr)
        self.assertEqual(
            (self.tree / "etc/frp/server_token").read_text(encoding="utf-8"), token_before
        )
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertEqual(v24.get_access_policy(self.plane, "remote")["mode"], "whitelist")
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertEqual(
            self.plane.evaluate_remote_access("203.0.113.9", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "DENY",
        )

        # Explicit confirmation restores successfully.
        proc = run_tool(RESTORE, "--yes", str(permissive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertIsNone(v24.get_access_policy(self.plane, "remote")["mode"])
        self.assertEqual(
            self.plane.evaluate_remote_access("203.0.113.9", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "ALLOW",
        )

    def test_remote_blacklist_to_less_restrictive_requires_confirm(self):
        permissive = self._backup()
        self._seed_remote_blacklist()
        blocked = self.plane.evaluate_remote_access(
            "198.51.100.66", "198.51.100.20", "tcp", 22
        )
        self.assertEqual(blocked["action"], "DENY")

        proc = run_tool(RESTORE, str(permissive))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("broaden", (proc.stdout + proc.stderr).lower())
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertEqual(v24.get_access_policy(self.plane, "remote")["mode"], "blacklist")

        proc = run_tool(RESTORE, "--yes", str(permissive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertIsNone(v24.get_access_policy(self.plane, "remote")["mode"])

    def test_internet_broadening_requires_confirm(self):
        permissive = self._backup()
        self._seed_internet_whitelist()
        proc = run_tool(RESTORE, str(permissive))
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout + proc.stderr).lower()
        self.assertIn("internet", combined)
        self.assertIn("broaden", combined)

        proc = run_tool(RESTORE, "--yes", str(permissive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertIsNone(v24.get_access_policy(self.plane, "internet")["mode"])

    def test_ai_broadening_requires_confirm_auth_untouched_on_cancel(self):
        permissive = self._backup()
        self._seed_ai_whitelist()
        principal = self.plane.conn.execute(
            "SELECT credential_status, enabled FROM ai_principals WHERE name='bot'"
        ).fetchone()
        self.assertEqual(principal["credential_status"], "verified")
        self.assertEqual(int(principal["enabled"]), 1)

        proc = run_tool(RESTORE, str(permissive))
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout + proc.stderr).lower()
        self.assertIn("ai access", combined)
        self.assertIn("broaden", combined)

        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        principal = self.plane.conn.execute(
            "SELECT credential_status, enabled FROM ai_principals WHERE name='bot'"
        ).fetchone()
        self.assertIsNotNone(principal)
        self.assertEqual(principal["credential_status"], "verified")
        self.assertEqual(v24.get_access_policy(self.plane, "ai")["mode"], "whitelist")

        proc = run_tool(RESTORE, "--yes", str(permissive))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_no_broadening_restore_does_not_prompt(self):
        archive = self._backup()
        # Mutate non-policy state only.
        self.plane.conn.execute("UPDATE clients SET label='mutated'")
        self.plane.conn.commit()
        proc = run_tool(RESTORE, str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("Continue? [y/N]", proc.stdout)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        label = self.plane.conn.execute(
            "SELECT label FROM clients WHERE id='cccccccccccccccccccccccccccccccc'"
        ).fetchone()[0]
        self.assertEqual(label, "orig")

    def test_validate_remains_read_only_even_when_broadening(self):
        permissive = self._backup()
        self._seed_remote_whitelist()
        token_before = (self.tree / "etc/frp/server_token").read_text(encoding="utf-8")
        mode_before = v24.get_access_policy(self.plane, "remote")["mode"]
        proc = run_tool(RESTORE, "--validate", str(permissive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Backup valid", proc.stdout)
        self.assertIn("confirmation would be required", proc.stdout.lower())
        self.assertEqual(
            (self.tree / "etc/frp/server_token").read_text(encoding="utf-8"), token_before
        )
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertEqual(v24.get_access_policy(self.plane, "remote")["mode"], mode_before)

    def test_calculator_direct_remote_whitelist_to_no_policy(self):
        restore = load_restore()
        permissive = self._backup()
        self._seed_remote_whitelist()
        tmp, extracted = restore.validate_to_temp(permissive, require_semantic=True)
        try:
            impact = restore.calculate_restore_access_security_impact(self.tree, extracted)
            self.assertIsNotNone(impact)
            self.assertTrue(impact["access_broadened"])
            self.assertTrue(impact["requires_confirmation"])
            self.assertIn("Remote Access", impact["families_broadened"])
        finally:
            tmp.cleanup()

    def test_remote_blacklist_same_network_object_value_change_requires_confirm(self):
        """Independent FAIL repro: same public name, changed IP — restore must confirm."""
        self._seed_remote_blacklist()
        archive = self._backup("selector-semantic")
        # Candidate blocks .66; live mutates same-name Object to .77.
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.66", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "DENY",
        )
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.77", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "ALLOW",
        )
        v24.set_network_object(
            self.plane,
            "bad",
            type="ip",
            value="198.51.100.77",
            oneshot=True,
            confirm=True,
        )
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.66", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "ALLOW",
        )
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.77", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "DENY",
        )
        rev_before = self.plane.current_revision()
        proc = run_tool(RESTORE, str(archive))
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout + proc.stderr).lower()
        self.assertIn("broaden", combined)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertEqual(self.plane.current_revision(), rev_before)
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.77", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "DENY",
        )

        proc = run_tool(RESTORE, "--yes", str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.plane.close()
        self.plane = ControlPlane(str(self.tree))
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.66", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "DENY",
        )
        self.assertEqual(
            self.plane.evaluate_remote_access("198.51.100.77", "198.51.100.20", "tcp", 22)[
                "action"
            ],
            "ALLOW",
        )

    def test_internet_whitelist_same_network_group_membership_change_requires_confirm(self):
        v24.set_network_object(
            self.plane, "lan-a", type="ip", value="10.10.10.20", oneshot=True
        )
        v24.set_network_object(
            self.plane, "lan-b", type="ip", value="10.10.10.21", oneshot=True
        )
        v24.set_network_object(
            self.plane, "web", type="fqdn", value="example.com", oneshot=True
        )
        v24.set_service_object(self.plane, "https", type="tcp", port=443, oneshot=True)
        v24.set_network_group(
            self.plane, "lans", members=["lan-a", "lan-b"], oneshot=True
        )
        v24.set_access_rule(
            self.plane,
            "internet",
            "allow-web",
            mode="whitelist",
            source="lans",
            destination="web",
            service="https",
            enabled=True,
            oneshot=True,
        )
        archive = self._backup("inet-group")
        # Shrink live group → restore candidate expands allow set.
        v24.set_network_group(
            self.plane, "lans", members=["lan-a"], oneshot=True, confirm=True
        )
        proc = run_tool(RESTORE, str(archive))
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout + proc.stderr).lower()
        self.assertIn("internet", combined)
        self.assertIn("broaden", combined)

    def test_remote_service_object_port_change_requires_confirm(self):
        self._seed_remote_blacklist()
        archive = self._backup("svc-port")
        v24.set_service_object(
            self.plane, "svc", type="tcp", port=2222, oneshot=True, confirm=True
        )
        proc = run_tool(RESTORE, str(archive))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("broaden", (proc.stdout + proc.stderr).lower())

    def test_ai_same_permission_object_semantics_change_requires_confirm(self):
        self._seed_ai_whitelist()
        archive = self._backup("ai-perm")
        v24.set_permission_object(
            self.plane,
            "exec-only",
            permissions=["command-exec", "host-info"],
            oneshot=True,
            confirm=True,
        )
        proc = run_tool(RESTORE, str(archive))
        # Restoring narrower permission set from backup narrows AI Access (DENY ALL risk).
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout + proc.stderr).lower()
        self.assertIn("ai access", combined)
        self.assertTrue("broaden" in combined or "narrow" in combined)

    def test_identical_effective_selector_semantics_does_not_prompt(self):
        self._seed_remote_blacklist()
        archive = self._backup("same-sem")
        # Touch unrelated client label only — policy semantics unchanged.
        self.plane.conn.execute("UPDATE clients SET label='mutated-again'")
        self.plane.conn.commit()
        proc = run_tool(RESTORE, str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("Continue? [y/N]", proc.stdout)


if __name__ == "__main__":
    unittest.main()
