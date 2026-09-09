#!/usr/bin/env python3
import importlib.util
import json
import os
import tempfile
import types
from importlib.machinery import SourceFileLoader
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESTORE = ROOT / "tools" / "frp-restore"


def load_module():
    loader = SourceFileLoader("frp_restore", str(RESTORE))
    spec = importlib.util.spec_from_loader("frp_restore", loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def seed_tree(root: Path) -> None:
    for rel in (
        "etc/frp-auto-deploy/pki",
        "etc/frp",
        "var/lib/frp-auto-deploy",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)
    (root / "etc/frp-auto-deploy/config.json").write_text(
        json.dumps(
            {
                "public_host": "203.0.113.10",
                "frp_control_public_port": 443,
                "allocator_listen_port": 6099,
                "listen_port": 6099,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "var/lib/frp-auto-deploy/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n",
        encoding="utf-8",
    )
    (root / "var/lib/frp-auto-deploy/access-control.json").write_text(
        json.dumps({"schema_version": 1, "access_lists": {}, "service_access": {}}) + "\n",
        encoding="utf-8",
    )
    (root / "etc/frp/frps.toml").write_text('bindPort = 443\n', encoding="utf-8")
    (root / "etc/frp/server_token").write_text("token\n", encoding="utf-8")
    (root / "etc/frp-auto-deploy/pki/ca.crt").write_text("ca\n", encoding="utf-8")


def main() -> int:
    mod = load_module()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        seed_tree(root)

        old_env = {k: os.environ.get(k) for k in ("FRP_SKIP_SYSTEMD", "FRP_DEPLOY_TEST_ROOT", "FRP_RESTORE_READY_TIMEOUT", "FRP_RESTORE_READY_INTERVAL")}
        os.environ.pop("FRP_SKIP_SYSTEMD", None)
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
        os.environ["FRP_RESTORE_READY_TIMEOUT"] = "1"
        os.environ["FRP_RESTORE_READY_INTERVAL"] = "0"

        counters = {"is_active": 0, "ss": 0, "healthz": 0, "access_healthz": 0}
        seen = {"urls": [], "cafile": None}
        real_subprocess = mod.subprocess
        real_urllib = __import__("urllib.request", fromlist=["request"])
        real_ssl = mod.ssl.create_default_context

        def fake_run(args, capture_output=False, text=False, check=False):
            if args[:2] == ["systemctl", "is-active"]:
                counters["is_active"] += 1
                return types.SimpleNamespace(stdout="active\n", returncode=0)
            if args[:2] == ["ss", "-lnt"]:
                counters["ss"] += 1
                stdout = "" if counters["ss"] < 3 else "LISTEN 0 4096 *:443 *:*\n"
                return types.SimpleNamespace(stdout=stdout, returncode=0)
            raise AssertionError(f"unexpected subprocess call: {args}")

        def fake_context(cafile=None):
            seen["cafile"] = cafile
            return object()

        def fake_urlopen(url, context=None, timeout=5):
            seen["urls"].append(url)
            if str(url).startswith("http://") and "/healthz" in str(url):
                counters["access_healthz"] += 1
                if counters["access_healthz"] < 2:
                    raise OSError("access plugin not ready yet")
                return types.SimpleNamespace(read=lambda: b'{"ok":true}')
            counters["healthz"] += 1
            if counters["healthz"] < 3:
                raise OSError("not ready yet")
            return types.SimpleNamespace(read=lambda: b"ok")

        mod.subprocess.run = fake_run
        real_urlopen = real_urllib.urlopen
        mod.ssl.create_default_context = fake_context
        real_urllib.urlopen = fake_urlopen
        try:
            mod.verify_restored_control_state(root)
        finally:
            mod.subprocess = real_subprocess
            mod.ssl.create_default_context = real_ssl
            real_urllib.urlopen = real_urlopen
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        assert counters["ss"] >= 3, counters
        assert counters["healthz"] >= 3, counters
        assert counters["access_healthz"] >= 2, counters
        assert "https://127.0.0.1:6099/healthz" in seen["urls"], seen
        assert "http://127.0.0.1:6101/healthz" in seen["urls"], seen
        assert seen["cafile"] == str(root / "etc/frp-auto-deploy/pki/ca.crt"), seen
        print("RESTORE_READINESS_RETRY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
