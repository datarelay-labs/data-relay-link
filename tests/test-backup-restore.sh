#!/usr/bin/env bash
# Disaster-recovery backup validation, exact restore, and rollback coverage.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
TREE="$WORKDIR/root"
OUTDIR="$WORKDIR/output"
BACKUP="$OUTDIR/server.tar.gz"

seed_state() {
  local tree="$1" marker="$2"
  mkdir -p \
    "$tree/etc/frp-auto-deploy/pki" \
    "$tree/etc/frp" \
    "$tree/var/lib/frp-auto-deploy/enrollments" \
    "$tree/var/lib/frp-auto-deploy/bootstrap"
  printf '{"deployment_mode":"direct","marker":"%s","public_hostname":"frp-backup.example.com","bootstrap_hostname":"bootstrap-backup.example.com","public_ip":"203.0.113.10"}\n' "$marker" \
    >"$tree/etc/frp-auto-deploy/config.json"
  cat >"$tree/etc/frp-auto-deploy/version" <<EOF
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
RELEASE_CHANNEL=dev
SOURCE_REF=main
BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  printf 'bindPort = 443\n# %s\n' "$marker" >"$tree/etc/frp/frps.toml"
  printf 'token-%s-super-secret\n' "$marker" >"$tree/etc/frp/server_token"
  printf '{"schema_version":2,"clients":{"client-a":{"label":"%s","notes":"private note","services":{"ssh":{"remote_port":6001}}}},"reserved":[6002]}\n' \
    "$marker" >"$tree/var/lib/frp-auto-deploy/registry.json"
  printf 'nonce-%s\n' "$marker" >"$tree/var/lib/frp-auto-deploy/mgmt-nonces.json"
  printf 'ca-key-%s\n' "$marker" >"$tree/etc/frp-auto-deploy/pki/ca.key"
  printf 'ca-cert-%s\n' "$marker" >"$tree/etc/frp-auto-deploy/pki/ca.crt"
  printf 'server-key-%s\n' "$marker" >"$tree/etc/frp-auto-deploy/pki/server.key"
  printf 'server-cert-%s\n' "$marker" >"$tree/etc/frp-auto-deploy/pki/server.crt"
  printf 'serial-%s\n' "$marker" >"$tree/etc/frp-auto-deploy/pki/ca.srl"
  printf '{"ticket":"%s-enrollment"}\n' "$marker" \
    >"$tree/var/lib/frp-auto-deploy/enrollments/ticket.json"
  printf '{"ticket":"%s-bootstrap"}\n' "$marker" \
    >"$tree/var/lib/frp-auto-deploy/bootstrap/ticket.json"
  mkdir -p "$tree/var/log/frp-auto-deploy"
  printf '{"event":"backup.created","marker":"%s"}\n' "$marker" \
    >"$tree/var/log/frp-auto-deploy/audit.jsonl"
  printf '{"event":"rotated","marker":"%s"}\n' "$marker" \
    >"$tree/var/log/frp-auto-deploy/audit.jsonl.1"
  chmod 700 \
    "$tree/etc/frp-auto-deploy" "$tree/etc/frp-auto-deploy/pki" \
    "$tree/etc/frp" "$tree/var/lib/frp-auto-deploy" \
    "$tree/var/lib/frp-auto-deploy/enrollments" \
    "$tree/var/lib/frp-auto-deploy/bootstrap" \
    "$tree/var/log/frp-auto-deploy"
  find "$tree/etc/frp-auto-deploy" "$tree/etc/frp" "$tree/var/lib/frp-auto-deploy" \
    "$tree/var/log/frp-auto-deploy" \
    -type f -exec chmod 600 {} +
}

mode_of() {
  python3 - "$1" <<'PY'
import os, stat, sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
}

archive_variant() {
  local source="$1" output="$2" operation="$3"
  python3 - "$source" "$output" "$operation" <<'PY'
import hashlib, json, sys, tarfile, tempfile
from pathlib import Path

source, output, operation = map(Path, sys.argv[1:])
with tempfile.TemporaryDirectory() as name:
    root = Path(name)
    with tarfile.open(source, "r:gz") as archive:
        archive.extractall(root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if operation.name == "checksum":
        target = root / "payload/etc/frp/server_token"
        target.write_text("tampered-secret\n")
    elif operation.name == "missing":
        rel = "etc/frp/server_token"
        (root / "payload" / rel).unlink()
        manifest["files"] = [item for item in manifest["files"] if item["path"] != rel]
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        lines = [
            line for line in (root / "checksums.sha256").read_text().splitlines()
            if not line.endswith("payload/" + rel)
        ]
        (root / "checksums.sha256").write_text("\n".join(lines) + "\n")
    with tarfile.open(output, "w:gz") as archive:
        archive.add(root / "manifest.json", arcname="manifest.json")
        archive.add(root / "checksums.sha256", arcname="checksums.sha256")
        archive.add(root / "payload", arcname="payload")
PY
}

seed_state "$TREE" original
mkdir -p "$OUTDIR"
chmod 755 "$OUTDIR"
export FRP_DEPLOY_TEST_ROOT="$TREE"

BACKUP_STDOUT="$WORKDIR/backup.stdout"
python3 "$ROOT/tools/frp-backup" "$BACKUP" >"$BACKUP_STDOUT" \
  || fail "backup creation"
[[ -f "$BACKUP" ]] || fail "backup archive missing"
CUSTOM_PARENT_UID="$(stat -c %u "$OUTDIR")"
CUSTOM_PARENT_MODE="$(mode_of "$OUTDIR")"
[[ "$CUSTOM_PARENT_MODE" == "0o755" ]] || fail "custom parent fixture mode"
[[ "$(mode_of "$BACKUP")" == "0o600" ]] || fail "backup archive mode"
[[ "$(stat -c %u "$OUTDIR")" == "$CUSTOM_PARENT_UID" ]] || fail "custom parent owner changed"
[[ "$(mode_of "$OUTDIR")" == "$CUSTOM_PARENT_MODE" ]] || fail "custom parent mode changed"
grep -q 'contains private keys' "$BACKUP_STDOUT" || fail "secret warning missing"
if grep -qE 'token-original-super-secret|private note|original-enrollment' "$BACKUP_STDOUT"; then
  fail "backup leaked a secret"
fi
pass "BACKUP_CREATE_PERMISSIONS_NO_SECRET_LEAK"

BAD_CHECKSUM="$WORKDIR/checksum.tar.gz"
archive_variant "$BACKUP" "$BAD_CHECKSUM" checksum
BEFORE="$(sha256sum "$TREE/etc/frp/server_token" | awk '{print $1}')"
if python3 "$ROOT/tools/frp-restore" "$BAD_CHECKSUM" >"$WORKDIR/bad.stdout" 2>"$WORKDIR/bad.stderr"; then
  fail "checksum corruption accepted"
fi
[[ "$(sha256sum "$TREE/etc/frp/server_token" | awk '{print $1}')" == "$BEFORE" ]] \
  || fail "checksum failure modified current state"
grep -q 'checksum verification failed' "$WORKDIR/bad.stderr" || {
  sed 's/^/DIAGNOSTIC: /' "$WORKDIR/bad.stderr" >&2
  fail "checksum diagnostic"
}
pass "RESTORE_CHECKSUM_REJECTED_WITHOUT_MUTATION"

MISSING="$WORKDIR/missing.tar.gz"
archive_variant "$BACKUP" "$MISSING" missing
if python3 "$ROOT/tools/frp-restore" "$MISSING" >/dev/null 2>"$WORKDIR/missing.stderr"; then
  fail "missing required file accepted"
fi
grep -q 'missing required file' "$WORKDIR/missing.stderr" || fail "missing-file diagnostic"
pass "RESTORE_MISSING_FILE_REJECTED"

seed_state "$TREE" mutated
printf 'stale\n' >"$TREE/etc/frp-auto-deploy/frontend.conf"
RESTORE_STDOUT="$WORKDIR/restore.stdout"
python3 "$ROOT/tools/frp-restore" "$BACKUP" >"$RESTORE_STDOUT" \
  || fail "exact restore"
grep -q '"marker":"original"' "$TREE/etc/frp-auto-deploy/config.json" || fail "config restore"
grep -q '"public_hostname":"frp-backup.example.com"' "$TREE/etc/frp-auto-deploy/config.json" \
  || fail "public_hostname restore"
grep -q '"bootstrap_hostname":"bootstrap-backup.example.com"' "$TREE/etc/frp-auto-deploy/config.json" \
  || fail "bootstrap_hostname restore"
grep -q '"public_ip":"203.0.113.10"' "$TREE/etc/frp-auto-deploy/config.json" || fail "public_ip restore"
grep -q '"label":"original"' "$TREE/var/lib/frp-auto-deploy/registry.json" || fail "registry restore"
grep -q '6002' "$TREE/var/lib/frp-auto-deploy/registry.json" || fail "reservation restore"
grep -q 'token-original-super-secret' "$TREE/etc/frp/server_token" || fail "token restore"
grep -q 'ca-key-original' "$TREE/etc/frp-auto-deploy/pki/ca.key" || fail "CA restore"
grep -q 'serial-original' "$TREE/etc/frp-auto-deploy/pki/ca.srl" || fail "PKI serial restore"
grep -q 'original-enrollment' "$TREE/var/lib/frp-auto-deploy/enrollments/ticket.json" \
  || fail "enrollment restore"
grep -q 'original-bootstrap' "$TREE/var/lib/frp-auto-deploy/bootstrap/ticket.json" \
  || fail "bootstrap restore"
grep -q '"marker":"original"' "$TREE/var/log/frp-auto-deploy/audit.jsonl" \
  || fail "audit.jsonl restore"
grep -q '"marker":"original"' "$TREE/var/log/frp-auto-deploy/audit.jsonl.1" \
  || fail "rotated audit restore"
[[ ! -f "$TREE/etc/frp-auto-deploy/frontend.conf" ]] || fail "absent optional file not removed"
[[ "$(mode_of "$TREE/etc/frp/server_token")" == "0o600" ]] || fail "token mode"
[[ "$(mode_of "$TREE/etc/frp-auto-deploy/pki")" == "0o700" ]] || fail "PKI directory mode"
if grep -qE 'token-original-super-secret|private note|original-enrollment' "$RESTORE_STDOUT"; then
  fail "restore leaked a secret"
fi
find "$TREE/var/lib/frp-auto-deploy/backups" -name 'pre-restore-*.tar.gz' -type f \
  | grep -q . || fail "pre-restore snapshot missing"
pass "RESTORE_EXACT_STATE_PERMISSIONS_NO_SECRET_LEAK"
pass "AUDIT_INCLUDED_IN_BACKUP_RESTORE"

# Cross-version restore must fail closed.
CROSS="$WORKDIR/cross-tree"
seed_state "$CROSS" cross
export FRP_DEPLOY_TEST_ROOT="$CROSS"
python3 "$ROOT/tools/frp-backup" "$WORKDIR/cross.tar.gz" >/dev/null
# Simulate newer installed product while backup remains older.
cat >"$CROSS/etc/frp-auto-deploy/version" <<EOF
PROJECT_VERSION=2.1.2
FRP_VERSION=0.71.0
RELEASE_CHANNEL=dev
SOURCE_REF=main
BUNDLE_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
if python3 "$ROOT/tools/frp-restore" "$WORKDIR/cross.tar.gz" \
  >"$WORKDIR/cross.stdout" 2>"$WORKDIR/cross.stderr"; then
  fail "cross-version restore should fail closed"
fi
grep -qi 'cross-version restore is not supported' "$WORKDIR/cross.stderr" \
  || fail "cross-version diagnostic"
grep -q 'PROJECT_VERSION=2.1.2' "$CROSS/etc/frp-auto-deploy/version" \
  || fail "cross-version restore mutated installed version"
pass "CROSS_VERSION_RESTORE_FAIL_CLOSED"

seed_state "$TREE" rollback-source
export FRP_DEPLOY_TEST_ROOT="$TREE"
ROLLBACK_BEFORE="$WORKDIR/rollback.before"
cp "$TREE/var/lib/frp-auto-deploy/registry.json" "$ROLLBACK_BEFORE"
if FRP_RESTORE_HOOK_FAIL_AFTER=4 \
  python3 "$ROOT/tools/frp-restore" "$BACKUP" >/dev/null 2>"$WORKDIR/rollback.stderr"; then
  fail "injected restore failure unexpectedly succeeded"
fi
cmp -s "$TREE/var/lib/frp-auto-deploy/registry.json" "$ROLLBACK_BEFORE" \
  || fail "registry was not rolled back"
grep -q 'token-rollback-source-super-secret' "$TREE/etc/frp/server_token" \
  || fail "token was not rolled back"
grep -q 'ca-key-rollback-source' "$TREE/etc/frp-auto-deploy/pki/ca.key" \
  || fail "CA was not rolled back"
grep -q 'previous state was restored' "$WORKDIR/rollback.stderr" || fail "rollback diagnostic"
pass "RESTORE_FAILURE_ROLLBACK"

# Concurrent registry mutation cannot interleave with a locked backup copy.
CONC="$WORKDIR/conc"
seed_state "$CONC" concurrent
export FRP_DEPLOY_TEST_ROOT="$CONC"
READY="$WORKDIR/backup.ready"
GO="$WORKDIR/backup.go"
rm -f "$READY" "$GO"
CONC_BACKUP="$WORKDIR/conc.tar.gz"
FRP_BACKUP_HOOK_READY="$READY" FRP_BACKUP_HOOK_GO="$GO" FRP_BACKUP_HOOK_WAIT=15 \
  python3 "$ROOT/tools/frp-backup" "$CONC_BACKUP" >"$WORKDIR/conc.stdout" 2>"$WORKDIR/conc.stderr" &
BACK_PID=$!
for _ in $(seq 1 80); do
  [[ -f "$READY" ]] && break
  sleep 0.05
done
[[ -f "$READY" ]] || { kill "$BACK_PID" 2>/dev/null || true; fail "backup lock hook"; }
python3 - "$CONC" "$WORKDIR/writer.started" "$WORKDIR/writer.done" <<'PY' &
import json, os, sys, time
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(Path(os.environ.get("FRP_TEST_LOCKS_LIB", ""))))
# Non-blocking attempt: writer must not observe a half-copied registry.
lock = root / "var/lib/frp-auto-deploy/registry.lock"
import fcntl
fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o600)
Path(sys.argv[2]).write_text("started\n")
deadline = time.time() + 8
got = False
while time.time() < deadline:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        got = True
        break
    except BlockingIOError:
        time.sleep(0.05)
if got:
    path = root / "var/lib/frp-auto-deploy/registry.json"
    json.loads(path.read_text())
    path.write_text(json.dumps({"schema_version":2,"clients":{"mutated":{}},"reserved":[]}) + "\n")
    fcntl.flock(fd, fcntl.LOCK_UN)
Path(sys.argv[3]).write_text("got=%s\n" % got)
os.close(fd)
PY
sleep 0.2
touch "$GO"
wait "$BACK_PID" || fail "concurrent backup"
python3 - "$CONC_BACKUP" <<'PY'
import json, tarfile, sys, tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as name:
    dest = Path(name)
    with tarfile.open(sys.argv[1], "r:gz") as archive:
        archive.extractall(dest)
    data = json.loads((dest / "payload/var/lib/frp-auto-deploy/registry.json").read_text())
    assert data.get("schema_version") == 2
    assert "client-a" in data.get("clients", {})
    assert data["clients"]["client-a"]["label"] == "concurrent"
print("BACKUP_JSON_OK")
PY
pass "BACKUP_CONCURRENT_REGISTRY_MUTATION"
pass "BACKUP_CONSISTENCY"

# Health-gated restore rollback.
HEALTH="$WORKDIR/health-tree"
seed_state "$HEALTH" health
export FRP_DEPLOY_TEST_ROOT="$HEALTH"
python3 "$ROOT/tools/frp-backup" "$WORKDIR/health.tar.gz" >/dev/null
seed_state "$HEALTH" mutated
if FRP_RESTORE_HOOK_HEALTH_FAIL=1 \
  python3 "$ROOT/tools/frp-restore" "$WORKDIR/health.tar.gz" \
  >"$WORKDIR/health.stdout" 2>"$WORKDIR/health.stderr"; then
  fail "health-fail restore should fail"
fi
grep -q 'token-mutated-super-secret' "$HEALTH/etc/frp/server_token" || fail "health rollback token"
grep -q 'previous state was restored' "$WORKDIR/health.stderr" || fail "health rollback message"
pass "RESTORE_HEALTH_GATE"
pass "RESTORE_HEALTH_FAILURE_ROLLBACK"

if FRP_RESTORE_HOOK_HEALTH_FAIL=1 FRP_RESTORE_HOOK_ROLLBACK_HEALTH_FAIL=1 \
  python3 "$ROOT/tools/frp-restore" "$WORKDIR/health.tar.gz" \
  >"$WORKDIR/rbhealth.stdout" 2>"$WORKDIR/rbhealth.stderr"; then
  fail "rollback health failure should fail"
fi
grep -q 'RESTORE_ROLLBACK_FAILED' "$WORKDIR/rbhealth.stderr" || fail "RESTORE_ROLLBACK_FAILED"
grep -q 'RECOVERY_REQUIRED' "$WORKDIR/rbhealth.stderr" || fail "restore recovery required"
[[ -f "$HEALTH/var/lib/frp-auto-deploy/server-update-pending.json" ]] || fail "restore pending missing"
pass "RESTORE_ROLLBACK_FAILURE"

# Default product-owned backup directory is secured; custom parents are not taken over.
DEFAULT_TREE="$WORKDIR/default-root"
seed_state "$DEFAULT_TREE" default-dir
export FRP_DEPLOY_TEST_ROOT="$DEFAULT_TREE"
python3 "$ROOT/tools/frp-backup" >"$WORKDIR/default.stdout" \
  || fail "default backup creation"
DEFAULT_DIR="$DEFAULT_TREE/var/lib/frp-auto-deploy/backups"
[[ -d "$DEFAULT_DIR" ]] || fail "default backup directory missing"
[[ "$(mode_of "$DEFAULT_DIR")" == "0o700" ]] || fail "default backup directory mode"
DEFAULT_ARCHIVE="$(find "$DEFAULT_DIR" -maxdepth 1 -type f -name 'server-backup-*.tar.gz' | head -n 1)"
[[ -n "$DEFAULT_ARCHIVE" ]] || fail "default backup archive missing"
[[ "$(mode_of "$DEFAULT_ARCHIVE")" == "0o600" ]] || fail "default backup archive mode"
pass "BACKUP_DEFAULT_DIRECTORY_SECURE"

LINK_TARGET="$WORKDIR/link-target.tar.gz"
cp "$BACKUP" "$LINK_TARGET"
LINK_OUT="$WORKDIR/backup-symlink.tar.gz"
ln -s "$LINK_TARGET" "$LINK_OUT"
PARENT_BEFORE_UID="$(stat -c %u "$WORKDIR")"
PARENT_BEFORE_MODE="$(mode_of "$WORKDIR")"
if python3 "$ROOT/tools/frp-backup" "$LINK_OUT" >"$WORKDIR/sym.out" 2>"$WORKDIR/sym.err"; then
  fail "backup target symlink accepted"
fi
grep -qi 'symlink' "$WORKDIR/sym.err" || fail "backup symlink diagnostic"
[[ "$(stat -c %u "$WORKDIR")" == "$PARENT_BEFORE_UID" ]] || fail "symlink backup changed parent owner"
[[ "$(mode_of "$WORKDIR")" == "$PARENT_BEFORE_MODE" ]] || fail "symlink backup changed parent mode"
pass "BACKUP_TARGET_SYMLINK_REJECTED"

RESTORE_LINK="$WORKDIR/restore-symlink.tar.gz"
ln -s "$BACKUP" "$RESTORE_LINK"
if python3 "$ROOT/tools/frp-restore" "$RESTORE_LINK" >"$WORKDIR/rsym.out" 2>"$WORKDIR/rsym.err"; then
  fail "restore archive symlink accepted"
fi
grep -qi 'symlink' "$WORKDIR/rsym.err" || fail "restore symlink diagnostic"
pass "RESTORE_ARCHIVE_SYMLINK_REJECTED"

printf 'this is not a tar archive\n' >"$WORKDIR/corrupt.tar.gz"
if python3 "$ROOT/tools/frp-restore" "$WORKDIR/corrupt.tar.gz" >"$WORKDIR/corr.out" 2>"$WORKDIR/corr.err"; then
  fail "corrupted archive accepted"
fi
grep -qi 'not a valid tar archive\|backup is not a valid' "$WORKDIR/corr.err" || fail "corrupt archive diagnostic"
pass "RESTORE_CORRUPT_ARCHIVE_REJECTED"

echo "BACKUP_RESTORE_TEST=PASS"
