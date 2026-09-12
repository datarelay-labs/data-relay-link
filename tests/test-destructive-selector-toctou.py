#!/usr/bin/env python3
"""BUG-AUDIT-002: destructive commands must not re-resolve mutable selectors."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _seed_registry(root: Path, clients: dict) -> Path:
    etc = root / "etc/drlink"
    etc.mkdir(parents=True, exist_ok=True)
    var = root / "var/lib/drlink"
    var.mkdir(parents=True, exist_ok=True)
    reg = var / "registry.json"
    state = {"schema_version": 2, "clients": clients}
    reg.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    (etc / "config.json").write_text(
        json.dumps({"registry_file": "/var/lib/drlink/registry.json"}) + "\n",
        encoding="utf-8",
    )
    # Omit access-control.json so release ACL cleanup is skipped; this suite
    # asserts registry selector pinning, not Access Control transactions.
    lib = root / "usr/local/lib/drlink"
    lib.mkdir(parents=True, exist_ok=True)
    for name in (
        "frp_client_registry.py",
        "frp_control_locks.py",
        "frp_access_control.py",
        "frp_audit.py",
    ):
        shutil.copy2(ROOT / "lib" / name, lib / name)
    return reg


def _client(label: str, hostname: str, services: dict | None = None) -> dict:
    return {
        "label": label,
        "hostname": hostname,
        "mgmt_status": "enrolled",
        "mgmt_pubkey": "pub",
        "mgmt_fingerprint": "abcd" * 8,
        "mgmt_mac_key": "mac",
        "services": services
        or {
            "ssh": {
                "remote_port": 60001,
                "enabled": True,
                "local_ip": "127.0.0.1",
                "local_port": 22,
            }
        },
    }


class DestructiveSelectorToctouTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.reg = _seed_registry(
            self.root,
            {
                "aaaaaaaaaaaaaaaa": _client("branch-a", "host-a"),
                "bbbbbbbbbbbbbbbb": _client("branch-b", "host-b"),
            },
        )
        self.env = os.environ.copy()
        self.env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        self.env["PYTHONUNBUFFERED"] = "1"

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)

    def _run_with_mutation(self, tool: Path, args: list[str], answer: str, mutate):
        """Confirm target CLIENT-A, mutate selector mapping, then answer prompt."""
        proc = subprocess.Popen(
            [sys.executable, "-u", str(tool), *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env,
        )
        assert proc.stdin is not None and proc.stdout is not None
        seen = {"ok": False}
        err_box = {"text": ""}

        def reader():
            chunks = []
            while True:
                line = proc.stdout.readline()
                if line == "" and proc.poll() is not None:
                    break
                if not line:
                    time.sleep(0.05)
                    continue
                chunks.append(line)
                # Once the confirmed immutable CLIENT ID is shown, mutate.
                if (not seen["ok"]) and "aaaaaaaaaaaaaaaa" in line:
                    mutate()
                    seen["ok"] = True
                    # Give the mutation a moment, then answer confirmation.
                    time.sleep(0.05)
                    try:
                        proc.stdin.write(answer + "\n")
                        proc.stdin.flush()
                    except BrokenPipeError:
                        pass
            err_box["text"] = "".join(chunks)

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            self.fail("command timed out waiting for confirmation/mutation")
        t.join(timeout=2)
        err = proc.stderr.read() if proc.stderr else ""
        out = err_box["text"]
        self.assertTrue(seen["ok"], msg=f"confirmed CLIENT ID never shown; out={out!r} err={err!r}")
        return proc.returncode, out, err

    def test_release_client_label_swap_does_not_hit_other_client(self):
        def mutate():
            state = json.loads(self.reg.read_text(encoding="utf-8"))
            state["clients"]["aaaaaaaaaaaaaaaa"]["label"] = "old-a"
            state["clients"]["bbbbbbbbbbbbbbbb"]["label"] = "branch-a"
            self.reg.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        code, out, err = self._run_with_mutation(
            ROOT / "tools/frp-release-client",
            ["branch-a", "--force"],
            "RELEASE",
            mutate,
        )
        self.assertEqual(code, 0, msg=f"out={out!r} err={err!r}")
        state = json.loads(self.reg.read_text(encoding="utf-8"))
        self.assertNotIn("aaaaaaaaaaaaaaaa", state["clients"])
        self.assertIn("bbbbbbbbbbbbbbbb", state["clients"])
        self.assertEqual(state["clients"]["bbbbbbbbbbbbbbbb"]["label"], "branch-a")

    def test_revoke_client_label_swap_does_not_hit_other_client(self):
        def mutate():
            state = json.loads(self.reg.read_text(encoding="utf-8"))
            state["clients"]["aaaaaaaaaaaaaaaa"]["label"] = "old-a"
            state["clients"]["bbbbbbbbbbbbbbbb"]["label"] = "branch-a"
            self.reg.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        code, out, err = self._run_with_mutation(
            ROOT / "tools/frp-revoke-client",
            ["branch-a"],
            "REVOKE",
            mutate,
        )
        self.assertEqual(code, 0, msg=f"out={out!r} err={err!r}")
        state = json.loads(self.reg.read_text(encoding="utf-8"))
        self.assertEqual(state["clients"]["aaaaaaaaaaaaaaaa"]["mgmt_status"], "revoked")
        self.assertEqual(state["clients"]["bbbbbbbbbbbbbbbb"]["mgmt_status"], "enrolled")

    def test_release_service_label_swap_keeps_other_client(self):
        def mutate():
            state = json.loads(self.reg.read_text(encoding="utf-8"))
            state["clients"]["aaaaaaaaaaaaaaaa"]["label"] = "old-a"
            state["clients"]["bbbbbbbbbbbbbbbb"]["label"] = "branch-a"
            self.reg.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        code, out, err = self._run_with_mutation(
            ROOT / "tools/frp-release-service",
            ["branch-a", "ssh", "--force"],
            "RELEASE",
            mutate,
        )
        self.assertEqual(code, 0, msg=f"out={out!r} err={err!r}")
        state = json.loads(self.reg.read_text(encoding="utf-8"))
        self.assertEqual(state["clients"]["aaaaaaaaaaaaaaaa"]["services"], {})
        self.assertIn("ssh", state["clients"]["bbbbbbbbbbbbbbbb"]["services"])

    def test_release_client_target_removed_after_confirm(self):
        def mutate():
            state = json.loads(self.reg.read_text(encoding="utf-8"))
            state["clients"].pop("aaaaaaaaaaaaaaaa", None)
            self.reg.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        code, out, err = self._run_with_mutation(
            ROOT / "tools/frp-release-client",
            ["branch-a", "--force"],
            "RELEASE",
            mutate,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("Target changed while waiting for confirmation", out + err)
        state = json.loads(self.reg.read_text(encoding="utf-8"))
        self.assertIn("bbbbbbbbbbbbbbbb", state["clients"])

    def test_release_service_removed_after_confirm(self):
        def mutate():
            state = json.loads(self.reg.read_text(encoding="utf-8"))
            state["clients"]["aaaaaaaaaaaaaaaa"]["services"] = {}
            self.reg.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

        code, out, err = self._run_with_mutation(
            ROOT / "tools/frp-release-service",
            ["branch-a", "ssh", "--force"],
            "RELEASE",
            mutate,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("Target changed while waiting for confirmation", out + err)
        state = json.loads(self.reg.read_text(encoding="utf-8"))
        self.assertIn("ssh", state["clients"]["bbbbbbbbbbbbbbbb"]["services"])


if __name__ == "__main__":
    unittest.main()
