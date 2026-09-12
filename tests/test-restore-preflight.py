#!/usr/bin/env python3
"""Restore semantic preflight validation tests."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tarfile
import tempfile
from importlib.machinery import SourceFileLoader
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_restore():
    loader = SourceFileLoader("frp_restore", str(ROOT / "tools" / "frp-restore"))
    spec = importlib.util.spec_from_loader("frp_restore", loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def write_min_payload(payload: Path) -> None:
    for rel in (
        "etc/drlink/pki",
        "etc/frp",
        "var/lib/drlink",
    ):
        (payload / rel).mkdir(parents=True, exist_ok=True)
    (payload / "etc/drlink/config.json").write_text(
        json.dumps(
            {
                "port_start": 6000,
                "port_end": 6098,
                "egress_listen_port": 6102,
                "allocator_listen_port": 6099,
                "registry_file": "/var/lib/drlink/registry.json",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (payload / "etc/drlink/version").write_text("PROJECT_VERSION=1.0.0\n", encoding="utf-8")
    (payload / "etc/drlink/pki/ca.key").write_text("key\n", encoding="utf-8")
    (payload / "etc/drlink/pki/ca.crt").write_text("crt\n", encoding="utf-8")
    (payload / "etc/drlink/pki/server.key").write_text("key\n", encoding="utf-8")
    (payload / "etc/drlink/pki/server.crt").write_text("crt\n", encoding="utf-8")
    (payload / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (payload / "etc/frp/server_token").write_text("token\n", encoding="utf-8")
    (payload / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n",
        encoding="utf-8",
    )
    (payload / "var/lib/drlink/access-control.json").write_text(
        json.dumps({"schema_version": 1, "access_lists": {}, "service_access": {}}) + "\n",
        encoding="utf-8",
    )
    (payload / "var/lib/drlink/egress-control.json").write_text(
        json.dumps({"schema_version": 2, "egress_profiles": {}}) + "\n",
        encoding="utf-8",
    )
    (payload / "var/lib/drlink/service-profiles.json").write_text(
        json.dumps({"schema_version": 1, "profiles": {}}) + "\n",
        encoding="utf-8",
    )


def build_archive(staging: Path, payload: Path) -> Path:
    archive = staging / "backup.tar.gz"
    manifest = {
        "format": "frp-auto-deploy-server-backup",
        "schema_version": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "project_version": "1.0.0",
        "files": [],
    }
    checksum_lines = []
    for path in sorted(payload.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(payload).as_posix()
        digest = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
        manifest["files"].append({"path": rel, "sha256": digest})
        checksum_lines.append("%s  payload/%s" % (digest, rel))
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (staging / "checksums.sha256").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(staging / "manifest.json", arcname="manifest.json")
        tar.add(staging / "checksums.sha256", arcname="checksums.sha256")
        tar.add(payload, arcname="payload")
    return archive


def main() -> int:
    mod = load_restore()
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        payload = staging / "payload"
        payload.mkdir()
        write_min_payload(payload)
        archive = build_archive(staging, payload)
        mod.validate_to_temp(archive)
        print("RESTORE_PREFLIGHT_VALID=PASS")

        bad = staging / "bad-payload"
        shutil.copytree(payload, bad)
        bad_reg = bad / "var/lib/drlink/registry.json"
        registry = json.loads(bad_reg.read_text(encoding="utf-8"))
        registry["clients"] = {
            "mid": {
                "services": {
                    "ssh": {"remote_port": 6102},
                    "web": {"remote_port": 6102},
                }
            }
        }
        bad_reg.write_text(json.dumps(registry) + "\n", encoding="utf-8")
        bad_stage = staging / "bad-stage"
        bad_stage.mkdir(exist_ok=True)
        bad_archive = build_archive(bad_stage, bad)
        try:
            mod.validate_to_temp(bad_archive)
        except mod.RestoreError as exc:
            if "invariant" not in str(exc).lower() and "collision" not in str(exc).lower():
                print("unexpected error: %s" % exc, file=sys.stderr)
                return 1
            print("RESTORE_PREFLIGHT_INVALID=PASS")
        else:
            print("RESTORE_PREFLIGHT_INVALID=FAIL", file=sys.stderr)
            return 1

        # Dangling Access↔registry bindings must fail closed before mutation.
        dangling = staging / "dangling-payload"
        shutil.copytree(payload, dangling)
        access_path = dangling / "var/lib/drlink/access-control.json"
        access_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "access_lists": {},
                    "service_access": {
                        "missing-machine": {
                            "ssh": {"access_mode": "PUBLIC"},
                        }
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        dangling_stage = staging / "dangling-stage"
        dangling_stage.mkdir(exist_ok=True)
        dangling_archive = build_archive(dangling_stage, dangling)
        try:
            mod.validate_to_temp(dangling_archive)
        except mod.RestoreError as exc:
            msg = str(exc).lower()
            if "cross-reference" not in msg and "dangling" not in msg and "unknown client" not in msg:
                print("unexpected dangling error: %s" % exc, file=sys.stderr)
                return 1
            print("RESTORE_PREFLIGHT_ACCESS_XREF=PASS")
        else:
            print("RESTORE_PREFLIGHT_ACCESS_XREF=FAIL", file=sys.stderr)
            return 1

        bad_ids = staging / "egress-id-payload"
        shutil.copytree(payload, bad_ids)
        (bad_ids / "var/lib/drlink/egress-control.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "egress_profiles": {
                        "egp_aaaaaaaaaaaa": {
                            "id": "egp_aaaaaaaaaaaa",
                            "name": "office",
                            "enabled": False,
                            "description": "",
                            "sources": [{"cidr": "203.0.113.10/32"}],
                            "destinations": [
                                {
                                    "host": "example.com",
                                    "port": 443,
                                    "match": "exact",
                                    "protocol": "https",
                                }
                            ],
                            "created_at": "t",
                            "updated_at": "t",
                        }
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        bad_id_stage = staging / "egress-id-stage"
        bad_id_stage.mkdir(exist_ok=True)
        bad_id_archive = build_archive(bad_id_stage, bad_ids)
        try:
            mod.validate_to_temp(bad_id_archive)
        except mod.RestoreError as exc:
            if "egress" not in str(exc).lower() and "id" not in str(exc).lower():
                print("unexpected egress-id error: %s" % exc, file=sys.stderr)
                return 1
            print("RESTORE_PREFLIGHT_EGRESS_ENTRY_ID=PASS")
        else:
            print("RESTORE_PREFLIGHT_EGRESS_ENTRY_ID=FAIL", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
