#!/usr/bin/env python3
"""CORE-003 enrollment atomicity failure-injection regressions."""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_mod():
    spec = importlib.util.spec_from_file_location(
        "frp_port_allocator", ROOT / "server" / "frp-port-allocator.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load_mod()


def hmac_hex(secret, message):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


class Env:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = self.root / "registry.json"
        self.token = self.root / "server_token"
        self.enrollments = self.root / "enrollments"
        self.enrollments.mkdir()
        self.token.write_text("test-frp-token-do-not-use\n")
        self.cfg = self.root / "config.json"
        cfg = {
            "public_ip": "203.0.113.10",
            "control_port": 443,
            "port_start": 18000,
            "port_end": 18020,
            "listen_host": "127.0.0.1",
            "listen_port": 6099,
            "egress_listen_port": 6102,
            "registry_file": str(self.registry),
            "enrollments_dir": str(self.enrollments),
            "token_file": str(self.token),
        }
        self.cfg.write_text(json.dumps(cfg, indent=2) + "\n")
        MOD.atomic_write_json(self.registry, MOD.empty_registry())
        self.allocator = MOD.Allocator(str(self.cfg))
        MOD.port_is_available = lambda port: True

    def cleanup(self):
        self.tmp.cleanup()

    def add_enrollment(self, enrollment_id, secret):
        now = int(time.time())
        record = {
            "id": enrollment_id,
            "secret": secret,
            "created_at": MOD.utc_now_iso(),
            "expires_at": now + 600,
            "bound_machine_id": None,
            "used_at": None,
        }
        path = self.enrollments / f"{enrollment_id}.json"
        MOD.atomic_write_json(path, record)
        return enrollment_id, secret

    def enroll(self, machine_id, enrollment_id, secret):
        body = json.dumps(
            {
                "machine_id": machine_id,
                "hostname": "host-a",
                "services": [],
            },
            separators=(",", ":"),
        ).encode()
        ts = str(int(time.time()))
        sig = hmac_hex(secret, ts + "\n" + body.decode())
        return self.allocator.enroll(enrollment_id, ts, sig, body, headers={}, peer_host=None)

    def load_registry(self):
        return json.loads(self.registry.read_text(encoding="utf-8"))

    def load_enrollment(self, eid):
        return json.loads((self.enrollments / f"{eid}.json").read_text(encoding="utf-8"))


def inject(point_name):
    def boom(point):
        if point == point_name:
            raise OSError("injected %s" % point_name)

    return boom


def main():
    # AFTER_REGISTRY_COMMIT → full rollback (unused enrollment, no client)
    env = Env()
    try:
        eid, secret = env.add_enrollment("a" * 16, "secret-" + "a" * 16)
        orig = MOD._test_enrollment_failure_point
        MOD._test_enrollment_failure_point = inject("AFTER_REGISTRY_COMMIT")
        try:
            code, result = env.enroll("machine-split", eid, secret)
        finally:
            MOD._test_enrollment_failure_point = orig
        reg = env.load_registry()
        enr = env.load_enrollment(eid)
        assert code != 200, result
        assert "machine-split" not in (reg.get("clients") or {}), reg
        assert not enr.get("used_at") and not enr.get("bound_machine_id"), enr
        print("ENROLLMENT_FAIL_AFTER_REGISTRY_COMMIT=PASS")
    finally:
        env.cleanup()

    # AFTER_ENROLLMENT_RECORD_COMMIT → recoverable committed (both bound) or full rollback.
    # Never: registry enrolled + enrollment unused.
    env = Env()
    try:
        eid, secret = env.add_enrollment("b" * 16, "secret-" + "b" * 16)
        orig = MOD._test_enrollment_failure_point
        MOD._test_enrollment_failure_point = inject("AFTER_ENROLLMENT_RECORD_COMMIT")
        try:
            code, result = env.enroll("machine-rec", eid, secret)
        finally:
            MOD._test_enrollment_failure_point = orig
        reg = env.load_registry()
        enr = env.load_enrollment(eid)
        enrolled = "machine-rec" in (reg.get("clients") or {})
        unused = not enr.get("used_at") and not enr.get("bound_machine_id")
        assert not (enrolled and unused), (reg, enr)
        print("ENROLLMENT_FAIL_AFTER_RECORD_COMMIT=PASS")
    finally:
        env.cleanup()

    # AFTER_BOOTSTRAP_CONSUME → must not resurrect unused enrollment.
    env = Env()
    try:
        eid, secret = env.add_enrollment("c" * 16, "secret-" + "c" * 16)
        orig = MOD._test_enrollment_failure_point
        MOD._test_enrollment_failure_point = inject("AFTER_BOOTSTRAP_CONSUME")
        try:
            code, result = env.enroll("machine-boot", eid, secret)
        finally:
            MOD._test_enrollment_failure_point = orig
        reg = env.load_registry()
        enr = env.load_enrollment(eid)
        enrolled = "machine-boot" in (reg.get("clients") or {})
        unused = not enr.get("used_at") and not enr.get("bound_machine_id")
        assert not (enrolled and unused), (reg, enr)
        print("ENROLLMENT_FAIL_AFTER_BOOTSTRAP_CONSUME=PASS")
    finally:
        env.cleanup()

    print("CORE_003_ENROLLMENT_ATOMICITY=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print("FAIL", exc, file=sys.stderr)
        raise SystemExit(1)
