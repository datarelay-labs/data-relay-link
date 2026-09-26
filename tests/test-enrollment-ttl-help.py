#!/usr/bin/env python3
"""F07: enrollment TTL help examples must match parser semantics.

F34 extends this to the TTL upper bound: an enrollment credential is a
short-lived hand-off, so every surface that accepts a TTL (parser, ticket
issuance, manual enrollment, bulk enrollment, help text, catalog) must enforce
and document the same 30-day ceiling.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import re
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    path = ROOT / rel
    spec = importlib.util.spec_from_loader(
        name, loader=importlib.machinery.SourceFileLoader(name, str(path))
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


CREATE = load("frp_create_client", "tools/frp-create-client")
CATALOG = load("frp_cli_catalog", "lib/frp_cli_catalog.py")

MAX_TTL = 30 * 86400


def seed_server_tree(root: Path) -> dict:
    """Minimal server tree that frp-create-client can issue enrollments in."""
    for rel in (
        "etc/drlink/pki",
        "etc/frp",
        "var/lib/drlink/enrollments",
        "var/lib/drlink/bootstrap",
        "var/log/drlink",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "lib" / "frp_pki.py"),
            "ensure",
            "--pki-dir",
            str(root / "etc/drlink/pki"),
            "--public-host",
            "example.test",
        ],
        check=True,
        capture_output=True,
    )
    cfg = {
        "deployment_mode": "direct",
        "public_ip": "203.0.113.10",
        "frp_control_public_port": 8443,
        "control_port": 443,
        "port_start": 19000,
        "port_end": 19020,
        "registry_file": "/var/lib/drlink/registry.json",
        "enrollments_dir": "/var/lib/drlink/enrollments",
        "bootstrap_dir": "/var/lib/drlink/bootstrap",
        "token_file": "/etc/frp/server_token",
        "tls_ca_cert": "/etc/drlink/pki/ca.crt",
        "allocator_public_url": "https://example.test/enroll",
        "client_installer_url": "https://example.test/dist/bootstrap-client.sh",
        "enrollment_retention_days": 30,
    }
    (root / "etc/drlink/config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    (root / "etc/frp/server_token").write_text("token-secret\n", encoding="utf-8")
    (root / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n",
        encoding="utf-8",
    )
    return cfg


def run_tool(root: Path, tool: str, args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / tool), *args],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
    )


class EnrollmentTtlHelpTests(unittest.TestCase):
    def test_duration_and_seconds_parse(self):
        self.assertEqual(CREATE.parse_enrollment_ttl("600"), 600)
        self.assertEqual(CREATE.parse_enrollment_ttl("30m"), 30 * 60)
        self.assertEqual(CREATE.parse_enrollment_ttl("1h"), 3600)
        self.assertEqual(CREATE.parse_enrollment_ttl("4h"), 4 * 3600)
        self.assertEqual(CREATE.parse_enrollment_ttl("1d"), 86400)

    def test_invalid_ttl_rejected(self):
        with self.assertRaises(ValueError):
            CREATE.parse_enrollment_ttl("0")
        with self.assertRaises(ValueError):
            CREATE.parse_enrollment_ttl("bad")

    def test_catalog_enrollment_ttl_examples_parse(self):
        cmd = CATALOG.find(["create", "enrollment"]) or CATALOG.find(
            ["enrollment", "create"], include_aliases=True
        )
        self.assertIsNotNone(cmd)
        ttl_flag = next(f for f in cmd["flags"] if f["name"] == "--ttl")
        self.assertEqual(ttl_flag.get("role"), "enrollment")
        for example in ttl_flag.get("examples") or ():
            CREATE.parse_enrollment_ttl(example)

    def test_access_ttl_metavar_differs_by_role(self):
        # Legacy add access-source was removed; enrollment TTL remains.
        access_cmd = CATALOG.find(["add", "access-source"]) or CATALOG.find(
            ["access", "add-source"], include_aliases=True
        )
        self.assertIsNone(access_cmd)
        enroll_cmd = CATALOG.find(["create", "enrollment"]) or CATALOG.find(
            ["enrollment", "create"], include_aliases=True
        )
        self.assertIsNotNone(enroll_cmd)
        enroll = next(f for f in enroll_cmd["flags"] if f["name"] == "--ttl")
        self.assertEqual(enroll.get("role"), "enrollment")
        self.assertIn("|SECONDS", enroll.get("metavar", ""))

    def test_create_client_epilog_has_no_unparseable_ttl_examples(self):
        text = (ROOT / "tools/frp-create-client").read_text(encoding="utf-8")
        epilog = text.split("epilog=(", 1)[1].split("),", 1)[0]
        ttl_examples = [m.group(1) for m in re.finditer(r"--ttl\s+(\S+)", epilog)]
        self.assertEqual(ttl_examples, [])


class EnrollmentTtlUpperBoundTests(unittest.TestCase):
    """F34: extreme TTLs are rejected everywhere, with the bound documented."""

    def test_maximum_is_thirty_days(self):
        self.assertEqual(CREATE.MAX_ENROLLMENT_TTL_SEC, MAX_TTL)
        self.assertEqual(CREATE.MAX_ENROLLMENT_TTL_SEC, 2592000)

    def test_parser_accepts_the_boundary(self):
        self.assertEqual(CREATE.parse_enrollment_ttl("30d"), MAX_TTL)
        self.assertEqual(CREATE.parse_enrollment_ttl(str(MAX_TTL)), MAX_TTL)
        self.assertEqual(CREATE.parse_enrollment_ttl("720h"), MAX_TTL)

    def test_parser_rejects_beyond_the_boundary(self):
        for raw in (
            "31d",
            "3650d",
            "721h",
            str(MAX_TTL + 1),
            "99999999999",
            "365000d",
        ):
            with self.assertRaises(ValueError, msg=raw) as ctx:
                CREATE.parse_enrollment_ttl(raw)
            self.assertIn("30d", str(ctx.exception), raw)
            self.assertIn("2592000", str(ctx.exception), raw)

    def test_parser_bound_is_far_below_retention_maximum(self):
        """A TTL must never outlive the record that tracks it."""
        lifecycle = load("frp_enrollment_lifecycle", "lib/frp_enrollment_lifecycle.py")
        self.assertLess(
            CREATE.MAX_ENROLLMENT_TTL_SEC,
            lifecycle.MAX_RETENTION_DAYS * 86400,
        )

    def test_help_documents_the_maximum(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            seed_server_tree(root)
            result = run_tool(root, "frp-create-client", ["--help"])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("30d", result.stdout)
            self.assertIn("24h", result.stdout)

    def test_catalog_documents_the_maximum(self):
        cmd = CATALOG.find(["create", "enrollment"]) or CATALOG.find(
            ["enrollment", "create"], include_aliases=True
        )
        self.assertIsNotNone(cmd)
        ttl_flag = next(f for f in cmd["flags"] if f["name"] == "--ttl")
        self.assertEqual(ttl_flag.get("maximum"), MAX_TTL)
        self.assertIn("30d", ttl_flag.get("description", ""))
        self.assertIn("2592000", ttl_flag.get("description", ""))
        # Public help is action-first and does not advertise --ttl; the bound
        # remains on hidden machine flag metadata and guided lifetime prompts.
        self.assertTrue(ttl_flag.get("hidden"))
        self.assertNotIn("--ttl", CATALOG.command_help(cmd))
        self.assertIn("30d", cmd.get("detail", ""))

    def test_manual_and_zero_touch_reject_extreme_ttl(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            seed_server_tree(root)
            manual = run_tool(
                root, "frp-create-client", ["--ttl", "3650d", "--client-name", "manual-extreme"]
            )
            self.assertNotEqual(manual.returncode, 0)
            self.assertIn("30d", manual.stderr)
            zt = run_tool(
                root,
                "frp-create-client",
                ["--one-line", "--ttl", "3650d", "--client-name", "zt-extreme"],
            )
            self.assertNotEqual(zt.returncode, 0)
            self.assertIn("24h", zt.stderr)
            enrollments = list((root / "var/lib/drlink/enrollments").glob("*.json"))
            tickets = list((root / "var/lib/drlink/bootstrap").glob("*.json"))
            self.assertEqual(enrollments, [], "rejected TTL still wrote an enrollment")
            self.assertEqual(tickets, [], "rejected TTL still issued a ticket")

    def test_bulk_enrollment_shares_the_bound(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            seed_server_tree(root)
            rejected = run_tool(
                root, "frp-enroll-bulk", ["--count", "2", "--ttl", "3650d"]
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("24h", rejected.stderr)
            self.assertEqual(
                list((root / "var/lib/drlink/bootstrap").glob("*.json")),
                [],
                "rejected bulk TTL still issued tickets",
            )
            accepted = run_tool(
                root, "frp-enroll-bulk", ["--count", "2", "--ttl", "1h", "--label-prefix", "ok"]
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(
                len(list((root / "var/lib/drlink/bootstrap").glob("*.json"))), 2
            )

    def test_issued_ticket_expiry_respects_the_bound(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            seed_server_tree(root)
            result = run_tool(
                root,
                "frp-create-client",
                ["--one-line", "--ttl", "24h", "--client-name", "zt-max"],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            tickets = list((root / "var/lib/drlink/bootstrap").glob("*.json"))
            self.assertEqual(len(tickets), 1)
            record = json.loads(tickets[0].read_text(encoding="utf-8"))
            remaining = int(record["expires_at"]) - int(time.time())
            self.assertLessEqual(remaining, CREATE.ZERO_TOUCH_MAX_TTL_SEC)
            self.assertGreater(remaining, CREATE.ZERO_TOUCH_MAX_TTL_SEC - 30)
            enrollment = json.loads(
                (root / "var/lib/drlink/enrollments" / (record["enrollment_id"] + ".json"))
                .read_text(encoding="utf-8")
            )
            self.assertEqual(int(enrollment["expires_at"]), int(record["expires_at"]))


class ZeroTouchTtlParityTests(unittest.TestCase):
    """Priority 8D: CLI Zero-Touch TTL ceiling matches Server (24h)."""

    @classmethod
    def setUpClass(cls):
        cls.alloc = load("frp_port_allocator", "server/frp-port-allocator.py")

    def test_cli_and_server_share_24h_ceiling(self):
        self.assertEqual(CREATE.ZERO_TOUCH_MAX_TTL_SEC, 86400)
        self.assertEqual(CREATE.ZERO_TOUCH_MAX_TTL_TEXT, "24h")
        self.assertEqual(self.alloc.ZERO_TOUCH_MAX_TTL_SEC, 86400)
        self.assertEqual(CREATE.ZERO_TOUCH_MAX_TTL_SEC, self.alloc.ZERO_TOUCH_MAX_TTL_SEC)

    def test_recommended_default_and_exact_24h_accepted(self):
        self.assertEqual(CREATE.parse_enrollment_ttl("1h", zero_touch=True), 3600)
        self.assertEqual(CREATE.parse_enrollment_ttl("24h", zero_touch=True), 86400)
        self.assertEqual(CREATE.parse_enrollment_ttl("86400", zero_touch=True), 86400)
        self.assertEqual(CREATE.parse_enrollment_ttl("1d", zero_touch=True), 86400)
        self.assertEqual(self.alloc.normalize_zero_touch_ttl(3600), 3600)
        self.assertEqual(self.alloc.normalize_zero_touch_ttl(86400), 86400)
        self.assertEqual(self.alloc.normalize_zero_touch_ttl(None), 3600)

    def test_over_24h_rejected_locally_including_day_forms(self):
        for raw in ("2d", "24d", "25h", "86401", "48h"):
            with self.assertRaises(ValueError, msg=raw) as ctx:
                CREATE.parse_enrollment_ttl(raw, zero_touch=True)
            err = str(ctx.exception)
            self.assertIn("24h", err, raw)
            self.assertIn("86400", err, raw)
        with self.assertRaises(ValueError):
            self.alloc.normalize_zero_touch_ttl(86401)
        with self.assertRaises(ValueError):
            self.alloc.normalize_zero_touch_ttl(0)
        with self.assertRaises(ValueError):
            self.alloc.normalize_zero_touch_ttl(-1)

    def test_rejected_ttl_leaves_no_enrollment_or_ticket(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            seed_server_tree(root)
            for raw in ("2d", "24d", "25h"):
                result = run_tool(
                    root,
                    "frp-create-client",
                    ["--one-line", "--ttl", raw, "--client-name", "zt-over-%s" % raw],
                )
                self.assertNotEqual(result.returncode, 0, raw)
                self.assertIn("24h", result.stderr, raw)
                self.assertIn("86400", result.stderr, raw)
            self.assertEqual(
                list((root / "var/lib/drlink/enrollments").glob("*.json")), []
            )
            self.assertEqual(
                list((root / "var/lib/drlink/bootstrap").glob("*.json")), []
            )


if __name__ == "__main__":
    unittest.main()
