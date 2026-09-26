#!/usr/bin/env python3
"""F29: enrollment issuance must honor the configured retention policy.

frp-create-client and frp-enroll-bulk used to call issue_bootstrap_ticket()
without cfg=, so the module synthesized a cleanup cfg that carried only paths.
enrollment_retention_days was dropped and cleanup silently fell back to 30 days,
deleting terminal records an administrator had asked to keep for longer.

Each case seeds terminal records of a known age, issues a new enrollment through
a real CLI, and checks which records survived. A record far past the configured
window is always seeded as a control so a "retained" result cannot be a cleanup
that never ran.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENROLL_REL = "var/lib/drlink/enrollments"
BOOTSTRAP_REL = "var/lib/drlink/bootstrap"
DAY = 86400

MANUAL_45D = "a" * 16
MANUAL_400D = "b" * 16
ZT_TICKET_45D = "c" * 16
ZT_ENROLL_45D = "d" * 16
ZT_TICKET_400D = "e" * 16
ZT_ENROLL_400D = "f" * 16


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ELC = load("frp_enrollment_lifecycle", "lib/frp_enrollment_lifecycle.py")


def seed_tree(root: Path, retention_days: int | None) -> None:
    for rel in ("etc/drlink/pki", "etc/frp", ENROLL_REL, BOOTSTRAP_REL, "var/log/drlink"):
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
    }
    if retention_days is not None:
        cfg["enrollment_retention_days"] = retention_days
    (root / "etc/drlink/config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    (root / "etc/drlink/version").write_text(
        "PROJECT_VERSION=2.4.0\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=dev\nSOURCE_REF=test\n",
        encoding="utf-8",
    )
    (root / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (root / "etc/frp/server_token").write_text("token-secret\n", encoding="utf-8")
    (root / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n",
        encoding="utf-8",
    )


def seed_manual_expired(root: Path, enrollment_id: str, age_days: int) -> None:
    expires_at = int(time.time()) - age_days * DAY
    (root / ENROLL_REL / (enrollment_id + ".json")).write_text(
        json.dumps(
            {
                "id": enrollment_id,
                "secret": "s" * 64,
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": expires_at,
                "bound_machine_id": None,
                "used_at": None,
                "label": "manual-%sd" % age_days,
            }
        )
        + "\n",
        encoding="utf-8",
    )


def seed_zero_touch_expired(
    root: Path, ticket_id: str, enrollment_id: str, age_days: int
) -> None:
    expires_at = int(time.time()) - age_days * DAY
    (root / BOOTSTRAP_REL / (ticket_id + ".json")).write_text(
        json.dumps(
            {
                "schema": 1,
                "id": ticket_id,
                "secret_hash": "h" * 64,
                "enrollment_id": enrollment_id,
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": expires_at,
                "bound_machine_id": None,
                "completed_at": None,
                "services": [],
                "label": "zt-%sd" % age_days,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / ENROLL_REL / (enrollment_id + ".json")).write_text(
        json.dumps(
            {
                "id": enrollment_id,
                "secret": "t" * 64,
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": expires_at,
                "bound_machine_id": None,
                "used_at": None,
                "authorized_services": [],
                "label": "zt-%sd" % age_days,
            }
        )
        + "\n",
        encoding="utf-8",
    )


def seed_terminal_records(root: Path) -> None:
    seed_manual_expired(root, MANUAL_45D, 45)
    seed_manual_expired(root, MANUAL_400D, 400)
    seed_zero_touch_expired(root, ZT_TICKET_45D, ZT_ENROLL_45D, 45)
    seed_zero_touch_expired(root, ZT_TICKET_400D, ZT_ENROLL_400D, 400)


def run_cli(root: Path, tool: str, args: list[str]) -> subprocess.CompletedProcess:
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


def present(root: Path, rel: str, record_id: str) -> bool:
    return (root / rel / (record_id + ".json")).is_file()


def assert_survivors(root: Path, case: str, *, retained_45d: bool) -> None:
    for label, rel, record_id in (
        ("manual 45d", ENROLL_REL, MANUAL_45D),
        ("zero-touch ticket 45d", BOOTSTRAP_REL, ZT_TICKET_45D),
        ("zero-touch enrollment 45d", ENROLL_REL, ZT_ENROLL_45D),
    ):
        if present(root, rel, record_id) != retained_45d:
            raise AssertionError(
                "%s: %s should have been %s"
                % (case, label, "retained" if retained_45d else "cleaned")
            )
    # Control: records past every configured window are always cleaned, so a
    # "retained" verdict above cannot come from cleanup silently not running.
    for label, rel, record_id in (
        ("manual 400d", ENROLL_REL, MANUAL_400D),
        ("zero-touch ticket 400d", BOOTSTRAP_REL, ZT_TICKET_400D),
        ("zero-touch enrollment 400d", ENROLL_REL, ZT_ENROLL_400D),
    ):
        if present(root, rel, record_id):
            raise AssertionError("%s: %s survived past every retention window" % (case, label))


def case_zero_touch(tmp: Path, retention_days: int, *, retained_45d: bool) -> None:
    root = tmp / ("zt-%s" % retention_days)
    seed_tree(root, retention_days)
    seed_terminal_records(root)
    result = run_cli(root, "frp-create-client", ["--one-line", "--client-name", "zt-issue"])
    if result.returncode != 0:
        raise AssertionError(
            "zero-touch issue failed (retention=%s): %s %s"
            % (retention_days, result.stdout, result.stderr)
        )
    assert_survivors(root, "zero-touch issue retention=%s" % retention_days, retained_45d=retained_45d)


def case_manual(tmp: Path, retention_days: int, *, retained_45d: bool) -> None:
    root = tmp / ("manual-%s" % retention_days)
    seed_tree(root, retention_days)
    seed_terminal_records(root)
    result = run_cli(root, "frp-create-client", ["--client-name", "manual-issue"])
    if result.returncode != 0:
        raise AssertionError(
            "manual issue failed (retention=%s): %s %s"
            % (retention_days, result.stdout, result.stderr)
        )
    assert_survivors(root, "manual issue retention=%s" % retention_days, retained_45d=retained_45d)


def case_bulk(tmp: Path, retention_days: int, *, retained_45d: bool) -> None:
    root = tmp / ("bulk-%s" % retention_days)
    seed_tree(root, retention_days)
    seed_terminal_records(root)
    result = run_cli(root, "frp-enroll-bulk", ["--count", "2", "--label-prefix", "bulk"])
    if result.returncode != 0:
        raise AssertionError(
            "bulk issue failed (retention=%s): %s %s"
            % (retention_days, result.stdout, result.stderr)
        )
    assert_survivors(root, "bulk issue retention=%s" % retention_days, retained_45d=retained_45d)


def test_retention_is_honored(tmp: Path) -> None:
    case_zero_touch(tmp, 90, retained_45d=True)
    case_bulk(tmp, 90, retained_45d=True)
    print("F29_ZERO_TOUCH_ISSUE_HONORS_RETENTION_90=PASS")
    case_manual(tmp, 90, retained_45d=True)
    print("F29_MANUAL_ISSUE_HONORS_RETENTION_90=PASS")

    case_zero_touch(tmp, 30, retained_45d=False)
    case_bulk(tmp, 30, retained_45d=False)
    print("F29_ZERO_TOUCH_ISSUE_CLEANS_AT_RETENTION_30=PASS")
    case_manual(tmp, 30, retained_45d=False)
    print("F29_MANUAL_ISSUE_CLEANS_AT_RETENTION_30=PASS")
    print("F29_MANUAL_AND_ZERO_TOUCH_SHARE_POLICY=PASS")


def test_unset_retention_uses_documented_default(tmp: Path) -> None:
    root = tmp / "default"
    seed_tree(root, None)
    seed_terminal_records(root)
    result = run_cli(root, "frp-create-client", ["--one-line", "--client-name", "default-issue"])
    if result.returncode != 0:
        raise AssertionError("issue failed: %s %s" % (result.stdout, result.stderr))
    if present(root, ENROLL_REL, MANUAL_45D):
        raise AssertionError("unset retention did not apply the 30-day default")
    if ELC.DEFAULT_RETENTION_DAYS != 30:
        raise AssertionError("documented default retention changed")
    print("F29_UNSET_RETENTION_USES_DEFAULT=PASS")


def test_module_never_substitutes_a_retention_default(tmp: Path) -> None:
    """Without cfg there is no policy to enforce, so nothing may be deleted."""
    root = tmp / "no-cfg"
    seed_tree(root, 90)
    seed_terminal_records(root)
    script = (
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location("
        "'frp_port_allocator', sys.argv[1] + '/server/frp-port-allocator.py')\n"
        "alloc = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(alloc)\n"
        "alloc.issue_bootstrap_ticket(sys.argv[2], sys.argv[3], [], 600, 'no-cfg')\n"
    )
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(ROOT),
            str(root / ENROLL_REL),
            str(root / BOOTSTRAP_REL),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise AssertionError("issue without cfg failed: %s %s" % (result.stdout, result.stderr))
    if not present(root, ENROLL_REL, MANUAL_400D):
        raise AssertionError("issue without cfg applied a substituted retention default")
    print("F29_NO_CFG_NEVER_SUBSTITUTES_RETENTION=PASS")


def main() -> int:
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        try:
            test_retention_is_honored(tmp)
            test_unset_retention_uses_documented_default(tmp)
            test_module_never_substitutes_a_retention_default(tmp)
        finally:
            os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
    print("F29_ENROLLMENT_RETENTION_POLICY=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print("FAIL %s" % exc, file=sys.stderr)
        raise SystemExit(1)
