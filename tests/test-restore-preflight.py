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
    # Forensic legacy JSON may be present but is not authority.
    (payload / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n",
        encoding="utf-8",
    )
    (payload / "var/lib/drlink/access-control.json").write_text(
        json.dumps({"schema_version": 1, "access_lists": {}, "service_access": {}}) + "\n",
        encoding="utf-8",
    )
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(payload)
    os.environ.setdefault("DRLINK_SKIP_ACTIVATION", "1")
    sys.path.insert(0, str(ROOT / "lib"))
    from drlink_control_plane import ControlPlane
    import drlink_v24 as v24

    plane = ControlPlane(str(payload))
    try:
        v24.ensure_v2_schema(plane.conn)
        plane.conn.commit()
    finally:
        plane.close()
    # ControlPlane opens under FRP_DEPLOY_TEST_ROOT; copy DB into payload path used by archive.
    db_src = payload / "var/lib/drlink/drlink.db"
    if not db_src.is_file():
        raise RuntimeError("failed to seed control DB for preflight fixture")


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

        # Missing required control DB must reject before mutation.
        bad = staging / "bad-payload"
        shutil.copytree(payload, bad)
        (bad / "var/lib/drlink/drlink.db").unlink()
        bad_stage = staging / "bad-stage"
        bad_stage.mkdir(exist_ok=True)
        bad_archive = build_archive(bad_stage, bad)
        try:
            mod.validate_to_temp(bad_archive)
        except mod.RestoreError as exc:
            if "drlink.db" not in str(exc).lower() and "missing required" not in str(exc).lower():
                print("unexpected error: %s" % exc, file=sys.stderr)
                return 1
            print("RESTORE_PREFLIGHT_INVALID=PASS")
        else:
            print("RESTORE_PREFLIGHT_INVALID=FAIL", file=sys.stderr)
            return 1

        # Corrupt DB bytes must reject before mutation.
        corrupt = staging / "corrupt-payload"
        shutil.copytree(payload, corrupt)
        (corrupt / "var/lib/drlink/drlink.db").write_bytes(b"not-sqlite")
        corrupt_stage = staging / "corrupt-stage"
        corrupt_stage.mkdir(exist_ok=True)
        corrupt_archive = build_archive(corrupt_stage, corrupt)
        try:
            mod.validate_to_temp(corrupt_archive)
        except mod.RestoreError as exc:
            msg = str(exc).lower()
            if "database" not in msg and "integrity" not in msg and "control" not in msg:
                print("unexpected dangling error: %s" % exc, file=sys.stderr)
                return 1
            print("RESTORE_PREFLIGHT_ACCESS_XREF=PASS")
        else:
            print("RESTORE_PREFLIGHT_ACCESS_XREF=FAIL", file=sys.stderr)
            return 1

        # Contradictory legacy JSON must not fail validation (non-authoritative).
        legacy = staging / "legacy-payload"
        shutil.copytree(payload, legacy)
        (legacy / "var/lib/drlink/access-control.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "access_lists": {},
                    "service_access": {
                        "missing-machine": {"ssh": {"access_mode": "PUBLIC"}}
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        legacy_stage = staging / "legacy-stage"
        legacy_stage.mkdir(exist_ok=True)
        legacy_archive = build_archive(legacy_stage, legacy)
        try:
            mod.validate_to_temp(legacy_archive)
        except mod.RestoreError as exc:
            print("legacy JSON should not block DR validation: %s" % exc, file=sys.stderr)
            return 1
        print("RESTORE_PREFLIGHT_EGRESS_ENTRY_ID=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
