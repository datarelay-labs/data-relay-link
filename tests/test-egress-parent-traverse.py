#!/usr/bin/env python3
"""Service-user traverse for /run/drlink and /var/log/drlink parents.

0700 on the parent blocks drlink-egress even when the child is writable.
Repair is group-execute 0710 (not world 0755) and must not open unrelated
directories. Connection-audit failures must be visible.
"""
from __future__ import annotations

import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "frp_egress_control_traverse", ROOT / "lib" / "frp_egress_control.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EG = _load()


def _sudo(*args, **kwargs):
    return subprocess.run(["sudo", "-n", *args], **kwargs)


def _sudo_works() -> bool:
    if shutil.which("sudo") is None:
        return False
    proc = _sudo("true", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if proc.returncode != 0:
        return False
    return _sudo(
        "id", "drlink-egress", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0


class ConnLogFailureVisible(unittest.TestCase):
    def test_untraversable_parent_is_diagnosed(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        log_dir = Path(tmp.name) / "var/log/drlink"
        egress = log_dir / "egress"
        egress.mkdir(parents=True)
        log_path = egress / "connections.jsonl"
        log_path.write_text("", encoding="utf-8")
        os.chmod(log_dir, 0)
        buf = io.StringIO()
        with redirect_stderr(buf):
            EG.emit_conn_log(
                {
                    "decision": "ALLOW",
                    "hostname": "allowed.test",
                    "port": 443,
                    "source_ip": "127.0.0.1",
                    "reason": "rule",
                },
                path=log_path,
            )
        os.chmod(log_dir, 0o755)
        text = buf.getvalue()
        self.assertIn("connection audit unavailable", text)
        self.assertIn(str(log_path), text)
        self.assertEqual(log_path.stat().st_size, 0)


@unittest.skipUnless(_sudo_works(), "sudo to drlink-egress is not available")
class ServiceUserParentTraverse(unittest.TestCase):
    def test_egress_user_traverses_only_required_parents(self):
        root = Path(tempfile.mkdtemp(prefix="drlink-traverse-"))
        self.addCleanup(lambda: _sudo("rm", "-rf", str(root)))
        os.chmod(root, 0o755)
        lib_dir = root / "lib"
        lib_dir.mkdir()
        shutil.copy(ROOT / "lib" / "frp_egress_control.py", lib_dir / "frp_egress_control.py")
        os.chmod(lib_dir, 0o755)
        os.chmod(lib_dir / "frp_egress_control.py", 0o644)
        run_parent = root / "run/drlink"
        log_parent = root / "var/log/drlink"
        secret = root / "etc/frp"
        run_leaf = run_parent / "egress"
        log_leaf = log_parent / "egress"
        for path in (run_leaf, log_leaf, secret):
            path.mkdir(parents=True)
        os.chmod(root, 0o755)
        _sudo("chown", "root:drlink-egress", str(run_parent), str(log_parent), check=True)
        _sudo("chmod", "0700", str(run_parent), str(log_parent), check=True)
        _sudo("chown", "root:root", str(secret), check=True)
        _sudo("chmod", "0700", str(secret), check=True)
        _sudo("chown", "drlink-egress:drlink-egress", str(run_leaf), check=True)
        _sudo("chmod", "0700", str(run_leaf), check=True)
        _sudo("chown", "root:drlink-egress", str(log_leaf), check=True)
        _sudo("chmod", "0770", str(log_leaf), check=True)

        def as_user(user: str, *args):
            return _sudo("-u", user, *args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        lib = str(lib_dir)

        for parent in (run_parent, log_parent):
            self.assertNotEqual(as_user("drlink-egress", "test", "-x", str(parent)).returncode, 0)
            self.assertNotEqual(as_user("drlink-egress", "test", "-x", str(parent / "egress")).returncode, 0)
        blocked = _sudo(
            "-u",
            "drlink-egress",
            "env",
            "PYTHONPATH=" + lib,
            "LOG=" + str(log_leaf / "connections.jsonl"),
            "python3",
            "-c",
            "import os, frp_egress_control as e; "
            "e.emit_conn_log({'decision':'ALLOW','hostname':'allowed.test','port':443,"
            "'source_ip':'127.0.0.1','reason':'rule'}, path=os.environ['LOG'])",
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertIn("connection audit unavailable", blocked.stderr)

        repair = _sudo(
            "env",
            "PYTHONPATH=" + lib,
            "DRLINK_TRAVERSE_RUN=" + str(run_parent),
            "DRLINK_TRAVERSE_LOG=" + str(log_parent),
            "python3",
            "-c",
            "import os, frp_egress_control as e; "
            "e.ensure_service_parent_traverse(["
            "os.environ['DRLINK_TRAVERSE_RUN'], os.environ['DRLINK_TRAVERSE_LOG']]) ",
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(repair.returncode, 0, repair.stderr)

        for parent in (run_parent, log_parent):
            mode = _sudo("stat", "-c", "%a %G", str(parent), check=True, text=True, stdout=subprocess.PIPE)
            self.assertEqual(mode.stdout.strip(), "710 drlink-egress")
            self.assertEqual(as_user("drlink-egress", "test", "-x", str(parent)).returncode, 0)
            self.assertNotEqual(as_user("drlink-egress", "test", "-r", str(parent)).returncode, 0)
            bits = stat.S_IMODE(os.stat(parent).st_mode)
            self.assertEqual(bits & 0o007, 0, "parent must not be world-accessible")

        self.assertNotEqual(as_user("drlink-egress", "test", "-x", str(secret)).returncode, 0)
        if _sudo("id", "nobody", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            self.assertNotEqual(as_user("nobody", "test", "-x", str(run_parent)).returncode, 0)
            self.assertNotEqual(as_user("nobody", "test", "-x", str(log_parent)).returncode, 0)

        snap = run_leaf / "effective.json"
        log_path = log_leaf / "connections.jsonl"
        script = lib_dir / "write_audit.py"
        script.write_text(
            "import os\n"
            "import frp_egress_control as e\n"
            "open(os.environ['SNAP'], 'w', encoding='utf-8').write('{}\\n')\n"
            "e.emit_conn_log({'decision':'ALLOW','hostname':'allowed.test','port':443,"
            "'source_ip':'127.0.0.1','reason':'rule'}, path=os.environ['LOG'])\n"
            "e.emit_conn_log({'decision':'DENY','hostname':'denied.test','port':443,"
            "'source_ip':'127.0.0.1','reason':'rule'}, path=os.environ['LOG'])\n",
            encoding="utf-8",
        )
        os.chmod(script, 0o755)
        write = _sudo(
            "-u",
            "drlink-egress",
            "env",
            "PYTHONPATH=" + lib,
            "SNAP=" + str(snap),
            "LOG=" + str(log_path),
            "python3",
            str(script),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(write.returncode, 0, write.stderr)
        body = _sudo("cat", str(log_path), check=True, text=True, stdout=subprocess.PIPE).stdout
        self.assertIn('"decision":"ALLOW"', body)
        self.assertIn('"decision":"DENY"', body)
        snap_body = _sudo("cat", str(snap), check=True, text=True, stdout=subprocess.PIPE).stdout
        self.assertIn("{", snap_body)


if __name__ == "__main__":
    unittest.main()
