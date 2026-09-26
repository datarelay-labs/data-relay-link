#!/usr/bin/env python3
"""F28: a bootstrap enrollment pair is atomic with respect to backup.

issue_bootstrap_ticket() writes two durable files (enrollment record, bootstrap
ticket) that are only meaningful together. A backup running between them used to
archive a half pair: an orphan enrollment or an unredeemable orphan ticket.

These cases pause the writer between the two writes with a failure-injection
hook, run a real backup concurrently, and assert the archive holds either the
pre-create state or the complete pair. Restore preflight is then checked to
reject an orphan Zero-Touch pair while still accepting manual enrollments that
legitimately have no bootstrap ticket.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


LOCKS = load("frp_control_locks", "lib/frp_control_locks.py")
ELC = load("frp_enrollment_lifecycle", "lib/frp_enrollment_lifecycle.py")

STATE_DIR_REL = "var/lib/drlink"
ENROLL_REL = STATE_DIR_REL + "/enrollments"
BOOTSTRAP_REL = STATE_DIR_REL + "/bootstrap"


def seed_tree(root: Path) -> dict:
    for rel in (
        "etc/drlink/pki",
        "etc/frp",
        ENROLL_REL,
        BOOTSTRAP_REL,
        "var/log/drlink",
    ):
        (root / rel).mkdir(parents=True, exist_ok=True)
    cfg = {
        "deployment_mode": "direct",
        "public_ip": "203.0.113.10",
        "frp_control_public_port": 8443,
        "control_port": 443,
        "port_start": 19000,
        "port_end": 19020,
        "listen_host": "127.0.0.1",
        "listen_port": 6099,
        "registry_file": "/var/lib/drlink/registry.json",
        "enrollments_dir": "/var/lib/drlink/enrollments",
        "bootstrap_dir": "/var/lib/drlink/bootstrap",
        "token_file": "/etc/frp/server_token",
        "tls_ca_cert": "/etc/drlink/pki/ca.crt",
        "enrollment_retention_days": 30,
    }
    (root / "etc/drlink/config.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    (root / "etc/drlink/version").write_text(
        "PROJECT_VERSION=2.4.0\nFRP_VERSION=0.71.0\nRELEASE_CHANNEL=dev\nSOURCE_REF=test\n",
        encoding="utf-8",
    )
    (root / "etc/frp/frps.toml").write_text("bindPort = 443\n", encoding="utf-8")
    (root / "etc/frp/server_token").write_text("token-secret\n", encoding="utf-8")
    for name in ("ca.key", "ca.crt", "server.key", "server.crt"):
        (root / "etc/drlink/pki" / name).write_text(name + "\n", encoding="utf-8")
    (root / "var/lib/drlink/registry.json").write_text(
        json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n",
        encoding="utf-8",
    )
    (root / "var/lib/drlink/access-control.json").write_text(
        json.dumps({"schema_version": 1, "access_lists": {}, "service_access": {}}) + "\n",
        encoding="utf-8",
    )
    (root / "var/lib/drlink/egress-control.json").write_text(
        json.dumps({"schema_version": 2, "egress_profiles": {}}) + "\n", encoding="utf-8"
    )
    (root / "var/lib/drlink/service-profiles.json").write_text(
        json.dumps({"schema_version": 1, "profiles": {}}) + "\n", encoding="utf-8"
    )
    os.environ["FRP_DEPLOY_TEST_ROOT"] = str(root)
    os.environ.setdefault("DRLINK_SKIP_ACTIVATION", "1")
    sys.path.insert(0, str(ROOT / "lib"))
    from drlink_control_plane import ControlPlane
    import drlink_v24 as v24

    plane = ControlPlane(str(root))
    try:
        v24.ensure_v2_schema(plane.conn)
        plane.conn.commit()
    finally:
        plane.close()
    return cfg


WRITER_SOURCE = """
import importlib.util, json, os, sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    'frp_port_allocator', sys.argv[2] + '/server/frp-port-allocator.py'
)
alloc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(alloc)
cfg = json.loads((root / 'etc/drlink/config.json').read_text(encoding='utf-8'))
cfg['enrollments_dir'] = str(root / 'var/lib/drlink/enrollments')
cfg['bootstrap_dir'] = str(root / 'var/lib/drlink/bootstrap')
cfg['registry_file'] = str(root / 'var/lib/drlink/registry.json')
cfg['token_file'] = str(root / 'etc/frp/server_token')
ticket, enroll, record = alloc.issue_bootstrap_ticket(
    cfg['enrollments_dir'],
    cfg['bootstrap_dir'],
    [],
    600,
    'pair-atomicity',
    label='pair-atomicity',
    cfg=cfg,
)
print(json.dumps({'enrollment_id': enroll['id'], 'ticket_id': record['id']}))
"""


def start_writer(root: Path, ready: Path, go: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["FRP_ENROLLMENT_PAIR_HOOK_READY"] = str(ready)
    env["FRP_ENROLLMENT_PAIR_HOOK_GO"] = str(go)
    env["FRP_ENROLLMENT_PAIR_HOOK_WAIT"] = "30"
    return subprocess.Popen(
        [sys.executable, "-c", WRITER_SOURCE, str(root), str(ROOT)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )


def start_backup(root: Path, archive: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["FRP_BACKUP_LOCK_TIMEOUT"] = "60"
    return subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "frp-backup"), str(archive)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )


def wait_for_file(path: Path, proc: subprocess.Popen, what: str, timeout=20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise AssertionError("%s exited before its hook: %s %s" % (what, out, err))
        time.sleep(0.05)
    proc.kill()
    raise AssertionError("%s hook never became ready" % what)


def archive_members(archive: Path, rel: str) -> dict[str, dict]:
    """Ticket and enrollment JSON only. Dedicated secret files are not records."""
    prefix = "payload/" + rel + "/"
    out: dict[str, dict] = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.startswith(prefix):
                continue
            if not member.name.endswith(".json"):
                continue
            handle = tar.extractfile(member)
            assert handle is not None, member.name
            raw = handle.read().decode("utf-8")
            out[member.name[len(prefix):]] = json.loads(raw)
    return out


def test_backup_never_sees_half_pair(tmp: Path) -> None:
    root = tmp / "half-pair"
    seed_tree(root)
    ready = tmp / "pair.ready"
    go = tmp / "pair.go"
    archive = tmp / "concurrent.tar.gz"

    writer = start_writer(root, ready, go)
    try:
        wait_for_file(ready, writer, "pair writer")
        # The enrollment half is already on disk here; the ticket is not.
        staged = list((root / ENROLL_REL).glob("*.json"))
        if len(staged) != 1:
            raise AssertionError("expected one staged enrollment, got %s" % staged)
        if list((root / BOOTSTRAP_REL).glob("*.json")):
            raise AssertionError("ticket was written before the pause hook")

        backup = start_backup(root, archive)
        try:
            time.sleep(1.0)
            if backup.poll() is not None:
                out, err = backup.communicate()
                raise AssertionError(
                    "backup completed while the pair was half-written: %s %s" % (out, err)
                )
        finally:
            go.write_text("go\n", encoding="utf-8")
        writer_out, writer_err = writer.communicate(timeout=60)
        if writer.returncode != 0:
            raise AssertionError("pair writer failed: %s %s" % (writer_out, writer_err))
        ids = json.loads(writer_out.strip().splitlines()[-1])
        backup_out, backup_err = backup.communicate(timeout=60)
        if backup.returncode != 0:
            raise AssertionError("backup failed: %s %s" % (backup_out, backup_err))
    finally:
        if writer.poll() is None:
            writer.kill()

    enrollments = archive_members(archive, ENROLL_REL)
    tickets = archive_members(archive, BOOTSTRAP_REL)
    enroll_name = ids["enrollment_id"] + ".json"
    ticket_name = ids["ticket_id"] + ".json"
    archived_enroll = enroll_name in enrollments
    archived_ticket = ticket_name in tickets
    if archived_enroll != archived_ticket:
        raise AssertionError(
            "archive captured half a pair: enrollment=%s ticket=%s"
            % (archived_enroll, archived_ticket)
        )
    print("F28_BACKUP_COHERENT_PAIR_GENERATION=PASS")
    if archived_ticket:
        alloc = load("frp_port_allocator_pair", "server/frp-port-allocator.py")
        token = (root / "etc/frp/server_token").read_text(encoding="utf-8").strip()
        recovered = alloc.unwrap_bootstrap_ticket(tickets[ticket_name].get("bt1_wrapped"), token)
        if not alloc.bootstrap_wrap_matches_record(recovered, tickets[ticket_name]):
            raise AssertionError("archived ticket did not recover with the archived server token")
        print("F28_ARCHIVED_WRAP_RECOVERS=PASS")

    # Whatever the archive captured must be coherent to the lifecycle layer too.
    with tempfile.TemporaryDirectory() as extract_name:
        extracted = Path(extract_name)
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(extracted)
        payload = extracted / "payload"
        rows = ELC.collect_logical_enrollments(payload / ENROLL_REL, payload / BOOTSTRAP_REL)
        broken = [row for row in rows if row.get("pair_error")]
        if broken:
            raise AssertionError(
                "archived enrollment state has pair errors: %s"
                % [(row["id"], row["pair_error"]) for row in broken]
            )
    print("F28_ARCHIVED_PAIR_LIFECYCLE_COHERENT=PASS")

    # Live tree ends with the complete pair and the writer's locks released.
    if not (root / ENROLL_REL / enroll_name).is_file():
        raise AssertionError("enrollment record missing after writer released")
    if not (root / BOOTSTRAP_REL / ticket_name).is_file():
        raise AssertionError("bootstrap ticket missing after writer released")
    for lock_path in LOCKS.state_dir_lock_paths(root / STATE_DIR_REL):
        with LOCKS.ExclusiveFileLock(lock_path, timeout=5):
            pass
    print("F28_PAIR_LOCKS_RELEASED=PASS")


def test_writer_waits_for_backup(tmp: Path) -> None:
    """Reverse order: a backup holding the locks blocks pair issuance."""
    root = tmp / "writer-waits"
    seed_tree(root)
    ready = tmp / "backup.ready"
    go = tmp / "backup.go"
    archive = tmp / "backup-first.tar.gz"

    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["FRP_BACKUP_HOOK_READY"] = str(ready)
    env["FRP_BACKUP_HOOK_GO"] = str(go)
    env["FRP_BACKUP_HOOK_WAIT"] = "30"
    backup = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "frp-backup"), str(archive)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    writer = None
    try:
        wait_for_file(ready, backup, "backup")
        writer = start_writer(root, tmp / "unused.ready", tmp / "unused.go")
        time.sleep(1.0)
        if writer.poll() is not None:
            out, err = writer.communicate()
            raise AssertionError(
                "pair issuance completed while backup held the locks: %s %s" % (out, err)
            )
        if list((root / ENROLL_REL).glob("*.json")):
            raise AssertionError("enrollment written while backup held the locks")
        go.write_text("go\n", encoding="utf-8")
        out, err = backup.communicate(timeout=60)
        if backup.returncode != 0:
            raise AssertionError("backup failed: %s %s" % (out, err))
        out, err = writer.communicate(timeout=60)
        if writer.returncode != 0:
            raise AssertionError("pair writer failed after backup released: %s %s" % (out, err))
    finally:
        for proc in (backup, writer):
            if proc is not None and proc.poll() is None:
                proc.kill()

    if not archive_members(archive, ENROLL_REL) == {}:
        raise AssertionError("backup archived an enrollment it should not have seen")
    if list((root / BOOTSTRAP_REL).glob("*.json")) == []:
        raise AssertionError("pair issuance did not complete after backup released")
    print("F28_WRITER_WAITS_FOR_BACKUP=PASS")


def _restore(root: Path, archive: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / "frp-restore"), str(archive)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
    )


def _backup(root: Path, archive: Path) -> None:
    env = os.environ.copy()
    env["FRP_DEPLOY_TEST_ROOT"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "frp-backup"), str(archive)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise AssertionError("backup failed: %s %s" % (result.stdout, result.stderr))


def test_restore_preflight_pair_rules(tmp: Path) -> None:
    root = tmp / "preflight"
    seed_tree(root)
    now = int(time.time())

    # Manual enrollment: no bootstrap ticket, and that is legitimate.
    (root / ENROLL_REL / ("a" * 16 + ".json")).write_text(
        json.dumps(
            {
                "id": "a" * 16,
                "secret": "s" * 64,
                "created_at": "2026-07-01T00:00:00Z",
                "expires_at": now + 600,
                "bound_machine_id": None,
                "used_at": None,
                "label": "manual",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manual_archive = tmp / "manual.tar.gz"
    _backup(root, manual_archive)
    result = _restore(root, manual_archive)
    if result.returncode != 0:
        raise AssertionError(
            "restore rejected a legitimate manual enrollment: %s %s"
            % (result.stdout, result.stderr)
        )
    if not (root / ENROLL_REL / ("a" * 16 + ".json")).is_file():
        raise AssertionError("manual enrollment missing after restore")
    print("F28_RESTORE_ACCEPTS_MANUAL_WITHOUT_TICKET=PASS")

    # Orphan Zero-Touch ticket: the paired enrollment record does not exist.
    # Restore prunes state trees that the archive did not contain any files for.
    (root / BOOTSTRAP_REL).mkdir(parents=True, exist_ok=True)
    (root / BOOTSTRAP_REL / ("b" * 16 + ".json")).write_text(
        json.dumps(
            {
                "schema": 1,
                "id": "b" * 16,
                "secret_hash": "h" * 64,
                "enrollment_id": "c" * 16,
                "created_at": "2026-07-01T00:00:00Z",
                "expires_at": now + 600,
                "bound_machine_id": None,
                "completed_at": None,
                "services": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    orphan_archive = tmp / "orphan.tar.gz"
    _backup(root, orphan_archive)
    result = _restore(root, orphan_archive)
    if result.returncode == 0:
        raise AssertionError("restore accepted an orphan Zero-Touch ticket")
    combined = result.stdout + result.stderr
    if "orphan Zero-Touch pairs" not in combined:
        raise AssertionError("restore rejected without a pair-specific reason: %s" % combined)
    print("F28_RESTORE_REJECTS_ORPHAN_ZERO_TOUCH_PAIR=PASS")

    # A complete pair restores cleanly.
    (root / ENROLL_REL / ("c" * 16 + ".json")).write_text(
        json.dumps(
            {
                "id": "c" * 16,
                "secret": "t" * 64,
                "created_at": "2026-07-01T00:00:00Z",
                "expires_at": now + 600,
                "bound_machine_id": None,
                "used_at": None,
                "authorized_services": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paired_archive = tmp / "paired.tar.gz"
    _backup(root, paired_archive)
    result = _restore(root, paired_archive)
    if result.returncode != 0:
        raise AssertionError(
            "restore rejected a complete pair: %s %s" % (result.stdout, result.stderr)
        )
    print("F28_RESTORE_ACCEPTS_COMPLETE_PAIR=PASS")


def archive_member_names(archive: Path, rel: str) -> set[str]:
    prefix = "payload/" + rel + "/"
    names: set[str] = set()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.startswith(prefix):
                names.add(member.name[len(prefix):])
    return names


def test_dedicated_wrap_key_backup_restore(tmp: Path) -> None:
    """A no-token wrap key is backed up, restored at 0600, and is not a ticket."""
    root = tmp / "wrap-key"
    seed_tree(root)
    cfg = json.loads((root / "etc/drlink/config.json").read_text(encoding="utf-8"))
    cfg["enrollments_dir"] = str(root / ENROLL_REL)
    cfg["bootstrap_dir"] = str(root / BOOTSTRAP_REL)
    cfg["registry_file"] = str(root / "var/lib/drlink/registry.json")
    cfg["token_file"] = str(root / "etc/frp/no-such-token")
    alloc = load("frp_port_allocator_wrapkey", "server/frp-port-allocator.py")
    ticket, _enroll, record = alloc.issue_bootstrap_ticket(
        cfg["enrollments_dir"],
        cfg["bootstrap_dir"],
        [],
        600,
        "wrap-key",
        label="wrap-key",
        cfg=cfg,
    )
    key_path = root / BOOTSTRAP_REL / alloc.BOOTSTRAP_WRAP_KEY_NAME
    if not key_path.is_file() or (key_path.stat().st_mode & 0o777) != 0o600:
        raise AssertionError("dedicated wrap key missing or not mode 0600")
    archive = tmp / "wrap-key.tar.gz"
    _backup(root, archive)
    names = archive_member_names(archive, BOOTSTRAP_REL)
    if alloc.BOOTSTRAP_WRAP_KEY_NAME not in names:
        raise AssertionError("backup omitted the dedicated wrap key")
    tickets = archive_members(archive, BOOTSTRAP_REL)
    if alloc.BOOTSTRAP_WRAP_KEY_NAME in tickets:
        raise AssertionError("pair validation parsed the wrap key as ticket JSON")
    ticket_name = record["id"] + ".json"
    if ticket_name not in tickets:
        raise AssertionError("backup omitted the ticket JSON")
    with tarfile.open(archive, "r:gz") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read().decode("utf-8"))
    key_rel = BOOTSTRAP_REL + "/" + alloc.BOOTSTRAP_WRAP_KEY_NAME
    modes = [entry.get("mode") for entry in manifest.get("files", []) if entry.get("path") == key_rel]
    if modes != [0o600]:
        raise AssertionError("backup manifest mode for wrap key is %s" % modes)

    dest = tmp / "wrap-key-restored"
    seed_tree(dest)
    for child in (dest / BOOTSTRAP_REL).iterdir():
        if child.is_file():
            child.unlink()
    result = _restore(dest, archive)
    if result.returncode != 0:
        raise AssertionError(
            "restore rejected a tree with a wrap key: %s %s" % (result.stdout, result.stderr)
        )
    restored_key = dest / BOOTSTRAP_REL / alloc.BOOTSTRAP_WRAP_KEY_NAME
    if not restored_key.is_file() or (restored_key.stat().st_mode & 0o777) != 0o600:
        raise AssertionError("restored wrap key missing or not mode 0600")
    restored = json.loads((dest / BOOTSTRAP_REL / ticket_name).read_text(encoding="utf-8"))
    recovered = alloc.unwrap_bootstrap_ticket(
        restored.get("bt1_wrapped"), restored_key.read_text(encoding="utf-8").strip()
    )
    if recovered != ticket or not alloc.bootstrap_wrap_matches_record(recovered, restored):
        raise AssertionError("restored wrap key did not recover bt1")
    rows = ELC.collect_logical_enrollments(dest / ENROLL_REL, dest / BOOTSTRAP_REL)
    broken = [row for row in rows if row.get("pair_error")]
    if broken:
        raise AssertionError(
            "restored pair has errors: %s" % [(row.get("id"), row.get("pair_error")) for row in broken]
        )
    if any(alloc.BOOTSTRAP_WRAP_KEY_NAME in str(row.get("id") or "") for row in rows):
        raise AssertionError("pair validation treated the wrap key as a ticket")
    bundle = load("frp_support_bundle_wrapkey", "lib/frp_support_bundle.py")
    if not bundle.is_forbidden_source(restored_key):
        raise AssertionError("support bundle would copy the wrap key")
    print("F28_WRAP_KEY_BACKUP_RESTORE=PASS")


def main() -> int:
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        try:
            test_backup_never_sees_half_pair(tmp)
            test_writer_waits_for_backup(tmp)
            test_restore_preflight_pair_rules(tmp)
            test_dedicated_wrap_key_backup_restore(tmp)
        finally:
            os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
    print("F28_ENROLLMENT_PAIR_ATOMICITY=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print("FAIL %s" % exc, file=sys.stderr)
        raise SystemExit(1)
