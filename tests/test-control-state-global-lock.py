#!/usr/bin/env python3
"""NEW-001: production Access/Egress/Profile writers vs backup under control-state.lock.

The previous concurrency test wrapped helper operations in control-state.lock
itself, so it could not prove production writers participate. These cases invoke
the real CLI/write paths.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    path = ROOT / rel
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LOCKS = load("frp_control_locks", "lib/frp_control_locks.py")
ACL = load("frp_access_control", "lib/frp_access_control.py")


def seed_tree(root: Path) -> None:
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
    for rel in (
        "etc/drlink/pki",
        "etc/frp",
        "var/lib/drlink/enrollments",
        "var/lib/drlink/bootstrap",
        "var/log/drlink",
        "usr/local/lib/drlink",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)
    cfg = {
        "deployment_mode": "direct",
        "registry_file": "/var/lib/drlink/registry.json",
        "access_control_file": "/var/lib/drlink/access-control.json",
        "egress_control_file": "/var/lib/drlink/egress-control.json",
        "service_profiles_file": "/var/lib/drlink/service-profiles.json",
        "public_hostname": "frp-backup.example.com",
        "bootstrap_hostname": "bootstrap-backup.example.com",
        "public_ip": "203.0.113.10",
    }
    (root / "etc/drlink/config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    (root / "etc/drlink/version").write_text(
        "PROJECT_VERSION=2.3.1\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=dev\nSOURCE_REF=test\n",
        encoding="utf-8",
    )
    (root / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (root / "etc/frp/server_token").write_text("token-secret\n", encoding="utf-8")
    (root / "etc/drlink/pki/ca.key").write_text("ca-key\n", encoding="utf-8")
    (root / "etc/drlink/pki/ca.crt").write_text("ca-crt\n", encoding="utf-8")
    (root / "etc/drlink/pki/server.key").write_text("srv-key\n", encoding="utf-8")
    (root / "etc/drlink/pki/server.crt").write_text("srv-crt\n", encoding="utf-8")
    registry = {
        "schema_version": 2,
        "clients": {
            "machine-aaa": {
                "label": "alpha",
                "hostname": "alpha-host",
                "services": {
                    "ssh": {"remote_port": 6001, "enabled": True},
                    "web": {"remote_port": 6002, "enabled": True},
                },
            }
        },
        "reserved": [6001, 6002],
    }
    (root / "var/lib/drlink/registry.json").write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    access = ACL.empty_access_state()
    ACL.save_access_state(access, path=root / "var/lib/drlink/access-control.json", cfg=cfg)
    (root / "var/lib/drlink/egress-control.json").write_text(
        json.dumps({"schema_version": 2, "egress_profiles": {}}) + "\n", encoding="utf-8"
    )
    (root / "var/lib/drlink/service-profiles.json").write_text(
        json.dumps({"schema_version": 1, "profiles": {}}) + "\n", encoding="utf-8"
    )


def lock_nb(path: Path):
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BlockingIOError:
        os.close(fd)
        return None


def unlock(fd) -> None:
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    os.close(fd)


def run_cli(root: Path, tool: str, args: list[str], extra_env=None, timeout=20):
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / tool), *args],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


def archive_payload_json(archive: Path, rel: str) -> dict:
    import tarfile

    with tarfile.open(archive, "r:gz") as tar:
        member = tar.extractfile("payload/" + rel)
        assert member is not None, rel
        return json.loads(member.read().decode("utf-8"))


def test_cli_blocks_on_control_state_lock(tmp: Path) -> None:
    """Old defect: CLI mutate ignored control-state.lock and would succeed here."""
    root = tmp / "cli-block"
    seed_tree(root)
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
    cases = [
        ("frp-egress", ["create", "office-egress"], root / "var/lib/drlink/egress-control.json"),
        (
            "frp-profile",
            ["create", "ssh-tmpl", "--preset", "custom", "--target-host", "127.0.0.1", "--target-port", "22"],
            root / "var/lib/drlink/service-profiles.json",
        ),
        ("frp-access", ["create", "Office"], root / "var/lib/drlink/access-control.json"),
    ]
    for tool, args, state_path in cases:
        before = state_path.read_text(encoding="utf-8")
        with LOCKS.acquire_control_state_lock(root, timeout=5):
            result = run_cli(
                root,
                tool,
                args,
                extra_env={"FRP_CONTROL_STATE_LOCK_TIMEOUT": "1"},
                timeout=8,
            )
            after = state_path.read_text(encoding="utf-8")
            if result.returncode == 0:
                raise AssertionError(
                    "%s mutation succeeded while control-state.lock was held:\n%s\n%s"
                    % (tool, result.stdout, result.stderr)
                )
            if after != before:
                raise AssertionError("%s mutated state while control-state.lock was held" % tool)
            if "timed out waiting for control-state lock" not in (result.stderr + result.stdout):
                raise AssertionError(
                    "%s did not fail closed on control-state timeout: rc=%s out=%r err=%r"
                    % (tool, result.returncode, result.stdout, result.stderr)
                )
        # After release, the same command must succeed (production path works).
        result = run_cli(root, tool, args, extra_env={"FRP_CONTROL_STATE_LOCK_TIMEOUT": "5"})
        if result.returncode != 0:
            raise AssertionError(
                "%s failed after lock release: %s\n%s" % (tool, result.stdout, result.stderr)
            )
    print("NEW_001_CLI_BLOCKS_ON_CONTROL_STATE=PASS")


def test_backup_vs_real_mutations(tmp: Path) -> None:
    root = tmp / "backup-vs"
    seed_tree(root)
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
    ready = tmp / "backup.ready"
    go = tmp / "backup.go"
    archive = tmp / "backup.tar.gz"
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["FRP_BACKUP_HOOK_READY"] = str(ready)
    env["FRP_BACKUP_HOOK_GO"] = str(go)
    env["FRP_BACKUP_HOOK_WAIT"] = "20"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    backup = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "frp-backup"), str(archive)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not ready.is_file():
        if backup.poll() is not None:
            out, err = backup.communicate()
            raise AssertionError("backup exited before hook: %s %s" % (out, err))
        time.sleep(0.05)
    if not ready.is_file():
        backup.kill()
        raise AssertionError("backup lock hook never became ready")

    # Resource locks must remain free: writers wait on control-state, not reverse order.
    egress_lock = lock_nb(root / "var/lib/drlink/egress-control.json.lock")
    if egress_lock is None:
        backup.kill()
        raise AssertionError("backup held egress resource lock before/without writers")
    unlock(egress_lock)

    procs = []
    for tool, args in (
        ("frp-egress", ["create", "locked-egress"]),
        (
            "frp-profile",
            ["create", "locked-profile", "--preset", "http", "--target-host", "127.0.0.1", "--target-port", "80"],
        ),
        ("frp-access", ["create", "LockedList"]),
    ):
        starter = subprocess.Popen(
            [sys.executable, str(ROOT / "tools" / tool), *args],
            cwd=str(ROOT),
            env={**env, "FRP_CONTROL_STATE_LOCK_TIMEOUT": "30"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        procs.append((tool, starter))

    time.sleep(0.2)
    egress_live = json.loads((root / "var/lib/drlink/egress-control.json").read_text(encoding="utf-8"))
    profiles_live = json.loads((root / "var/lib/drlink/service-profiles.json").read_text(encoding="utf-8"))
    access_live = json.loads((root / "var/lib/drlink/access-control.json").read_text(encoding="utf-8"))
    if egress_live.get("egress_profiles"):
        backup.kill()
        raise AssertionError("egress mutation applied while backup held control-state.lock")
    if profiles_live.get("profiles"):
        backup.kill()
        raise AssertionError("profile mutation applied while backup held control-state.lock")
    if access_live.get("access_lists"):
        backup.kill()
        raise AssertionError("access mutation applied while backup held control-state.lock")
    for tool, proc in procs:
        if proc.poll() is not None:
            out, err = proc.communicate()
            backup.kill()
            raise AssertionError("%s finished while backup held locks: %s %s" % (tool, out, err))

    go.write_text("go\n", encoding="utf-8")
    backup_out, backup_err = backup.communicate(timeout=20)
    if backup.returncode != 0:
        raise AssertionError("backup failed: %s %s" % (backup_out, backup_err))

    for tool, proc in procs:
        rc = proc.wait(timeout=30)
        out, err = proc.communicate()
        if rc != 0:
            raise AssertionError("%s failed after backup release: %s %s" % (tool, out, err))

    ctrl = root / "var/lib/drlink/control-state.lock"
    access_lock = root / "var/lib/drlink/access-control.json.lock"
    fd = lock_nb(ctrl)
    if fd is None:
        raise AssertionError("control-state.lock still held after backup and CLI writers exited")
    unlock(fd)
    fd = lock_nb(access_lock)
    if fd is None:
        raise AssertionError("access resource lock still held after CLI writers exited")
    unlock(fd)

    # Binding requires the list from create; retry assign once state exists.
    src = run_cli(
        root,
        "frp-access",
        ["add-source", "LockedList", "--name", "office", "--source", "198.51.100.0/24", "--yes"],
    )
    if src.returncode != 0:
        raise AssertionError("add-source failed: %s %s" % (src.stdout, src.stderr))
    assign = run_cli(root, "frp-access", ["assign", "alpha", "web", "LockedList"])
    if assign.returncode != 0:
        raise AssertionError("cross-plane assign failed: %s %s" % (assign.stdout, assign.stderr))

    archived_egress = archive_payload_json(archive, "var/lib/drlink/egress-control.json")
    archived_profiles = archive_payload_json(archive, "var/lib/drlink/service-profiles.json")
    archived_access = archive_payload_json(archive, "var/lib/drlink/access-control.json")
    if archived_egress.get("egress_profiles"):
        raise AssertionError("backup archive captured in-flight egress mutation")
    if archived_profiles.get("profiles"):
        raise AssertionError("backup archive captured in-flight profile mutation")
    if archived_access.get("access_lists"):
        raise AssertionError("backup archive captured in-flight access mutation")

    live_egress = json.loads((root / "var/lib/drlink/egress-control.json").read_text(encoding="utf-8"))
    live_profiles = json.loads((root / "var/lib/drlink/service-profiles.json").read_text(encoding="utf-8"))
    live_access = json.loads((root / "var/lib/drlink/access-control.json").read_text(encoding="utf-8"))
    if not live_egress.get("egress_profiles"):
        raise AssertionError("egress mutation did not apply after backup release")
    if not live_profiles.get("profiles"):
        raise AssertionError("profile mutation did not apply after backup release")
    if not live_access.get("access_lists"):
        raise AssertionError("access mutation did not apply after backup release")
    bindings = (live_access.get("service_access") or {}).get("machine-aaa") or {}
    if "web" not in bindings:
        raise AssertionError("cross-plane access binding missing after backup release")
    print("NEW_001_BACKUP_VS_MUTATION=PASS")


def test_access_interactive_toctou(tmp: Path) -> None:
    root = tmp / "toctou"
    seed_tree(root)
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
    cfg = json.loads((root / "etc/drlink/config.json").read_text(encoding="utf-8"))
    lid, _record = ACL.mutate_access_state(
        lambda state: ACL.create_access_list(state, "Office"),
        cfg=cfg,
    )
    ACL.mutate_access_state(
        lambda state: ACL.add_source_entry(state, lid, "office", "198.51.100.0/24"),
        cfg=cfg,
    )

    def bind_ssh(state):
        ACL.set_service_binding(state, "machine-aaa", "ssh", ACL.MODE_ALLOWLIST, lid)
        return True

    ACL.mutate_access_state(bind_ssh, cfg=cfg)
    access_mod = SourceFileLoader("frp_access_cli", str(ROOT / "tools" / "frp-access")).load_module()
    used_before = ACL.list_services_using(ACL.load_access_state(cfg=cfg), lid)

    def bind_web(state):
        ACL.set_service_binding(state, "machine-aaa", "web", ACL.MODE_ALLOWLIST, lid)
        return True

    ACL.mutate_access_state(bind_web, cfg=cfg)

    try:
        access_mod.revalidate_shared_list_mutation(cfg, "Office", used_before)
    except SystemExit as exc:
        msg = str(exc)
        if "impact changed" not in msg:
            raise AssertionError("unexpected SystemExit: %s" % msg)
    else:
        raise AssertionError("stale confirmation was accepted after impact changed")

    before_sources = (ACL.load_access_state(cfg=cfg).get("access_lists") or {}).get(lid, {}).get("entries") or []

    def add_src(state):
        return ACL.add_source_entry(state, lid, "office", "198.51.100.0/24")

    try:
        access_mod.mutate_access_after_confirm(cfg, "Office", used_before, add_src, expected_lid=lid)
    except SystemExit:
        pass
    else:
        raise AssertionError("stale confirmed mutation was applied")
    after_sources = (ACL.load_access_state(cfg=cfg).get("access_lists") or {}).get(lid, {}).get("entries") or []
    if after_sources != before_sources:
        raise AssertionError("TOCTOU confirmation mutated Access List")
    print("ACCESS_INTERACTIVE_TOCTOU=PASS")


def test_lock_order_control_before_resource(tmp: Path) -> None:
    root = tmp / "order"
    seed_tree(root)
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
    with LOCKS.acquire_control_state_lock(root, timeout=5):
        fd = lock_nb(root / "var/lib/drlink/egress-control.json.lock")
        if fd is None:
            raise AssertionError("holding control-state.lock inverted onto the resource lock")
        unlock(fd)
    print("LOCK_ORDER_PROOF=PASS")


def main() -> int:
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        try:
            test_cli_blocks_on_control_state_lock(tmp)
            test_backup_vs_real_mutations(tmp)
            test_access_interactive_toctou(tmp)
            test_lock_order_control_before_resource(tmp)
        finally:
            os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
            os.environ.pop("FRP_CONTROL_STATE_LOCK_TIMEOUT", None)
    print("NEW_001_CONTROL_STATE_GLOBAL_LOCK=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
