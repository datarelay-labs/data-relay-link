#!/usr/bin/env python3
"""Failure-injection: release must not report success with split registry/ACL state."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def pass_(name):
    print("PASS %s" % name)


def fail(name, detail=""):
    print("FAIL %s %s" % (name, detail), file=sys.stderr)
    raise SystemExit(1)


def write_tree(tmp: Path):
    etc = tmp / "etc" / "drlink"
    var = tmp / "var" / "lib" / "drlink"
    lib = tmp / "usr" / "local" / "lib" / "drlink"
    etc.mkdir(parents=True)
    var.mkdir(parents=True)
    lib.mkdir(parents=True)
    for name in (
        "frp_client_registry.py",
        "frp_control_locks.py",
        "frp_access_control.py",
        "frp_audit.py",
        "frp_policy_fingerprint.py",
    ):
        src = ROOT / "lib" / name
        if src.is_file():
            (lib / name).write_bytes(src.read_bytes())

    mid = "aabbccddeeff00112233445566778899"
    registry = {
        "schema_version": 2,
        "clients": {
            mid: {
                "hostname": "edge-01",
                "label": "edge",
                "services": {
                    "ssh": {
                        "id": "ssh",
                        "remote_port": 6001,
                        "enabled": True,
                        "preset": "ssh",
                    }
                },
            }
        },
        "reserved": [6001],
        "groups": {},
    }
    access = {
        "schema_version": 1,
        "access_lists": {
            "lst_aaaaaaaa": {
                "id": "lst_aaaaaaaa",
                "name": "Office",
                "entries": [
                    {
                        "id": "ent_bbbbbbbb",
                        "name": "net",
                        "cidr": "198.51.100.0/24",
                    }
                ],
            }
        },
        "service_access": {
            mid: {
                "ssh": {
                    "access_mode": "ALLOWLIST",
                    "access_list_id": "lst_aaaaaaaa",
                }
            }
        },
    }
    reg_path = var / "registry.json"
    access_path = var / "access-control.json"
    reg_path.write_text(json.dumps(registry, indent=2) + "\n")
    access_path.write_text(json.dumps(access, indent=2) + "\n")
    # Production-style absolute paths; FRP_DEPLOY_TEST_ROOT prefixes them.
    cfg = {
        "registry_file": "/var/lib/drlink/registry.json",
        "access_control_file": "/var/lib/drlink/access-control.json",
    }
    (etc / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    return mid, reg_path, access_path


def run_release(tool, args, tmp, inject=False):
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(tmp)
    if inject:
        env["FRP_TEST_FAIL_ACL_CLEANUP"] = "1"
    else:
        env.pop("FRP_TEST_FAIL_ACL_CLEANUP", None)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / tool), *args],
        input="RELEASE\n",
        text=True,
        capture_output=True,
        env=env,
        cwd=str(ROOT),
    )
    return proc


def main():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        mid, reg_path, access_path = write_tree(tmp)

        # Service release with injected ACL failure → PARTIAL, exit 1, no "Released."
        proc = run_release(
            "frp-release-service", [mid, "ssh", "--force"], tmp, inject=True
        )
        if proc.returncode != 1:
            fail("service partial exit", "code=%s out=%r err=%r" % (proc.returncode, proc.stdout, proc.stderr))
        if "PARTIAL" not in proc.stdout + proc.stderr and "PARTIAL" not in proc.stderr:
            # Message is printed to stdout/stderr; require the marker.
            if "PARTIAL:" not in proc.stderr and "PARTIAL:" not in proc.stdout:
                fail("service partial marker", "stderr=%r stdout=%r" % (proc.stderr, proc.stdout))
        if "Released." in proc.stdout:
            fail("service silent success", "must not print Released. on ACL failure")
        reg = json.loads(reg_path.read_text())
        if "ssh" in (reg["clients"][mid].get("services") or {}):
            fail("service registry not mutated")
        access = json.loads(access_path.read_text())
        if mid not in (access.get("service_access") or {}):
            fail("service ACL unexpectedly cleared despite inject")
        if "ssh" not in access["service_access"][mid]:
            fail("service ACL binding missing after inject (unexpected clear)")
        pass_("release service reports PARTIAL on ACL failure")

        # Clean ACL leftover then client release with inject.
        access["service_access"][mid] = {
            "ssh": {"access_mode": "ALLOWLIST", "access_list_id": "lst_aaaaaaaa"}
        }
        # Re-add a stub service so client release has something; client already has no ssh.
        reg["clients"][mid]["services"] = {
            "web": {"id": "web", "remote_port": 6002, "enabled": True}
        }
        reg_path.write_text(json.dumps(reg, indent=2) + "\n")
        access_path.write_text(json.dumps(access, indent=2) + "\n")

        proc = run_release("frp-release-client", [mid, "--force"], tmp, inject=True)
        if proc.returncode != 1:
            fail("client partial exit", "code=%s err=%r" % (proc.returncode, proc.stderr))
        if "PARTIAL:" not in proc.stderr and "PARTIAL:" not in proc.stdout:
            fail("client partial marker", proc.stderr)
        if "Released." in proc.stdout:
            fail("client silent success")
        reg = json.loads(reg_path.read_text())
        if mid in (reg.get("clients") or {}):
            fail("client registry not removed")
        access = json.loads(access_path.read_text())
        if mid not in (access.get("service_access") or {}):
            fail("client ACL unexpectedly cleared despite inject")
        pass_("release client reports PARTIAL on ACL failure")

        # Happy path without inject still succeeds.
        mid2 = "bbccddeeff00112233445566778899aa"
        reg = {
            "schema_version": 2,
            "clients": {
                mid2: {
                    "hostname": "edge-02",
                    "services": {
                        "ssh": {"id": "ssh", "remote_port": 6003, "enabled": True}
                    },
                }
            },
            "reserved": [6003],
            "groups": {},
        }
        access = {
            "schema_version": 1,
            "access_lists": {},
            "service_access": {
                mid2: {"ssh": {"access_mode": "PUBLIC", "access_list_id": None}}
            },
        }
        reg_path.write_text(json.dumps(reg, indent=2) + "\n")
        access_path.write_text(json.dumps(access, indent=2) + "\n")
        proc = run_release("frp-release-client", [mid2, "--force"], tmp, inject=False)
        if proc.returncode != 0 or "Released." not in proc.stdout:
            fail("client happy path", "code=%s out=%r err=%r" % (proc.returncode, proc.stdout, proc.stderr))
        access = json.loads(access_path.read_text())
        if mid2 in (access.get("service_access") or {}):
            fail("client ACL not cleaned on success")
        pass_("release client cleans ACL on success")


if __name__ == "__main__":
    main()
