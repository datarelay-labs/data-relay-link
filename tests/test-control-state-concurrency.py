#!/usr/bin/env python3
"""Concurrency regression: assign vs release under control-state.lock."""
from __future__ import annotations

import importlib.util
import json
import os
import random
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LOCKS = load("frp_control_locks", "lib/frp_control_locks.py")
ACL = load("frp_access_control", "lib/frp_access_control.py")
CREG = load("frp_client_registry", "lib/frp_client_registry.py")


def seed_tree(root: Path) -> dict:
    for rel in ("etc/drlink", "var/lib/drlink"):
        (root / rel).mkdir(parents=True, exist_ok=True)
    cfg = {
        "registry_file": "/var/lib/drlink/registry.json",
        "access_control_file": "/var/lib/drlink/access-control.json",
    }
    (root / "etc/drlink/config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
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
    reg_path = root / "var/lib/drlink/registry.json"
    reg_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    access = ACL.empty_access_state()
    lid, _ = ACL.create_access_list(access, "Office")
    ACL.add_source_entry(access, lid, "office", "198.51.100.0/24")
    ACL.save_access_state(access, path=root / "var/lib/drlink/access-control.json", cfg=cfg)
    return {"cfg": cfg, "registry_path": reg_path, "list_id": lid}


def registry_lock(path: Path):
    import fcntl

    lock_path = path.parent / "registry.lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def unlock(fd) -> None:
    import fcntl

    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def assign_binding(root: Path, cfg: dict, list_id: str, service: str) -> None:
    with LOCKS.acquire_control_state_lock(root):
        def mut(state):
            ACL.set_service_binding(state, "machine-aaa", service, ACL.MODE_ALLOWLIST, list_id)

        ACL.mutate_access_state(mut, cfg=cfg)


def release_service(root: Path, cfg: dict, reg_path: Path, service: str) -> None:
    with LOCKS.acquire_control_state_lock(root):
        fd = registry_lock(reg_path)
        try:
            state = json.loads(reg_path.read_text(encoding="utf-8"))
            client = state["clients"]["machine-aaa"]
            client["services"].pop(service, None)
            state["clients"]["machine-aaa"] = client
            reg_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        finally:
            unlock(fd)

        def mut(state):
            ACL.clear_service_binding(state, "machine-aaa", service)

        ACL.mutate_access_state(mut, cfg=cfg)


def assert_no_dangling(root: Path, cfg: dict, reg_path: Path) -> None:
    registry = json.loads(reg_path.read_text(encoding="utf-8"))
    access = ACL.load_access_state(cfg=cfg)
    live = set()
    for mid, client in (registry.get("clients") or {}).items():
        for sid in (client.get("services") or {}):
            live.add((mid, sid))
    for mid, services in (access.get("service_access") or {}).items():
        if not isinstance(services, dict):
            continue
        for sid in services:
            if (str(mid), str(sid)) not in live:
                raise AssertionError(
                    "dangling access binding for released service: %s:%s" % (mid, sid)
                )


def main() -> int:
    errors = []
    for iteration in range(40):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
            ctx = seed_tree(root)
            cfg = ctx["cfg"]
            reg_path = ctx["registry_path"]
            list_id = ctx["list_id"]
            barrier = threading.Barrier(2)

            def worker_a():
                random.seed(iteration * 2)
                time.sleep(random.random() * 0.02)
                barrier.wait(timeout=5)
                try:
                    assign_binding(root, cfg, list_id, "ssh")
                except Exception as exc:
                    errors.append("assign ssh: %s" % exc)

            def worker_b():
                random.seed(iteration * 2 + 1)
                time.sleep(random.random() * 0.02)
                barrier.wait(timeout=5)
                try:
                    release_service(root, cfg, reg_path, "web")
                except Exception as exc:
                    errors.append("release web: %s" % exc)

            t1 = threading.Thread(target=worker_a)
            t2 = threading.Thread(target=worker_b)
            t1.start()
            t2.start()
            t1.join(timeout=10)
            t2.join(timeout=10)
            try:
                assert_no_dangling(root, cfg, reg_path)
            except AssertionError as exc:
                errors.append(str(exc))
            os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    if errors:
        print("CONTROL_STATE_CONCURRENCY=FAIL")
        for item in errors[:5]:
            print(item, file=sys.stderr)
        return 1
    print("CONTROL_STATE_CONCURRENCY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
