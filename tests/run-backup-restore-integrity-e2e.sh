#!/usr/bin/env bash
# Targeted Real E2E: backup/restore fail-closed on missing authoritative state.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
SERVER="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
OUT_DIR="${FRP_BACKUP_E2E_OUT:-$ROOT/e2e-reports/backup-integrity-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"
exec > >(tee -a "$OUT_DIR/run.log") 2>&1

pass(){ echo "PASS $1"; }
fail(){ echo "FAIL $1" >&2; echo "TARGETED_REAL_E2E=FAIL" >"$OUT_DIR/result.env"; exit 1; }
blocker(){ echo "ENVIRONMENT_BLOCKER $1" >&2; echo "TARGETED_REAL_E2E=ENVIRONMENT_BLOCKER" >"$OUT_DIR/result.env"; exit 2; }
sshx(){ local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$h" "$@"; }

echo "=== Backup/Restore integrity targeted Real E2E ==="
sshx "$SERVER" 'echo ok' >/dev/null || blocker "server unreachable"

echo "=== sync backup/restore + ACL helpers onto server ==="
TMP=/tmp/frp-backup-sync-$$
sshx "$SERVER" "sudo rm -rf $TMP && sudo mkdir -p $TMP && sudo chmod 777 $TMP"
for f in \
  lib/frp_access_control.py \
  lib/frp_service_profiles.py \
  lib/frp_client_registry.py \
  tools/frp-backup \
  tools/frp-restore \
  tools/frpctl
do
  scp -o BatchMode=yes -o ConnectTimeout=15 "$ROOT/$f" "$SERVER:$TMP/$(basename "$f")"
done
sshx "$SERVER" "sudo install -m 0644 $TMP/frp_access_control.py /usr/local/lib/frp-auto-deploy/frp_access_control.py
sudo install -m 0644 $TMP/frp_service_profiles.py /usr/local/lib/frp-auto-deploy/frp_service_profiles.py
sudo install -m 0644 $TMP/frp_client_registry.py /usr/local/lib/frp-auto-deploy/frp_client_registry.py
sudo install -m 0755 $TMP/frp-backup /usr/local/sbin/frp-backup
sudo install -m 0755 $TMP/frp-restore /usr/local/sbin/frp-restore
sudo install -m 0755 $TMP/frpctl /usr/local/sbin/frpctl
sudo rm -rf $TMP"

sshx "$SERVER" 'sudo test -f /var/lib/frp-auto-deploy/access-control.json' || blocker "ACL file missing before test"
sshx "$SERVER" 'sudo test -f /var/lib/frp-auto-deploy/registry.json' || blocker "registry missing before test"
sshx "$SERVER" 'sudo test -f /var/lib/frp-auto-deploy/service-profiles.json' || blocker "profiles missing before test"

BAK_OK="/var/lib/frp-auto-deploy/backups/e2e-integrity-ok.tar.gz"
BAK_DIR="/var/lib/frp-auto-deploy/backups"
sshx "$SERVER" "sudo mkdir -p $BAK_DIR && sudo rm -f $BAK_OK"

echo "=== normal backup PASS ==="
sshx "$SERVER" "sudo frpctl create backup $BAK_OK" | tee "$OUT_DIR/backup-ok.txt"
sshx "$SERVER" "sudo test -s $BAK_OK" || fail "normal backup archive missing"
pass NORMAL_BACKUP

echo "=== backup fails when ACL missing ==="
sshx "$SERVER" "sudo mv /var/lib/frp-auto-deploy/access-control.json /var/lib/frp-auto-deploy/access-control.json.bak-integrity"
set +e
sshx "$SERVER" "sudo frpctl create backup $BAK_DIR/e2e-integrity-missing-acl.tar.gz" >"$OUT_DIR/backup-missing-acl.txt" 2>&1
rc=$?
set -e
sshx "$SERVER" "sudo mv /var/lib/frp-auto-deploy/access-control.json.bak-integrity /var/lib/frp-auto-deploy/access-control.json"
[[ "$rc" -ne 0 ]] || fail "backup should FAIL when ACL missing"
grep -qiE 'access-control|ACL|authoritative|missing|required' "$OUT_DIR/backup-missing-acl.txt" \
  || echo "WARN: backup failed without clear ACL diagnostic (rc=$rc)"
sshx "$SERVER" 'sudo test -s /var/lib/frp-auto-deploy/access-control.json' || fail "ACL missing after restore of original"
pass BACKUP_MISSING_ACL_FAIL

echo "=== backup fails when registry missing ==="
sshx "$SERVER" "sudo mv /var/lib/frp-auto-deploy/registry.json /var/lib/frp-auto-deploy/registry.json.bak-integrity"
set +e
sshx "$SERVER" "sudo frpctl create backup $BAK_DIR/e2e-integrity-missing-reg.tar.gz" >"$OUT_DIR/backup-missing-reg.txt" 2>&1
rc=$?
set -e
sshx "$SERVER" "sudo mv /var/lib/frp-auto-deploy/registry.json.bak-integrity /var/lib/frp-auto-deploy/registry.json"
[[ "$rc" -ne 0 ]] || fail "backup should FAIL when registry missing"
sshx "$SERVER" 'sudo python3 -c "import json; r=json.load(open(\"/var/lib/frp-auto-deploy/registry.json\")); assert r.get(\"clients\"), \"empty registry\""' \
  || fail "registry empty/corrupt after recovery"
pass BACKUP_MISSING_REGISTRY_FAIL

echo "=== restore rejects archive missing ACL (crafted) ==="
CRAFT="/tmp/frp-e2e-missing-acl-$$.tar.gz"
sshx "$SERVER" "sudo python3 - <<PY
import json, shutil, tarfile, tempfile
from pathlib import Path
src = Path('$BAK_OK')
out = Path('$CRAFT')
work = Path(tempfile.mkdtemp(prefix='frp-e2e-craft-'))
try:
    with tarfile.open(src, 'r:gz') as tin:
        tin.extractall(work)
    acl = work / 'payload' / 'var' / 'lib' / 'frp-auto-deploy' / 'access-control.json'
    if acl.exists():
        acl.unlink()
    man_path = work / 'manifest.json'
    man = json.loads(man_path.read_text())
    man['files'] = [
        e for e in (man.get('files') or [])
        if e.get('path') != 'var/lib/frp-auto-deploy/access-control.json'
    ]
    man_path.write_text(json.dumps(man, indent=2, sort_keys=True) + '\n')
    sums = work / 'checksums.sha256'
    sums.write_text(''.join('%s  payload/%s\n' % (e['sha256'], e['path']) for e in man['files']))
    with tarfile.open(out, 'w:gz') as tout:
        tout.add(man_path, arcname='manifest.json')
        tout.add(sums, arcname='checksums.sha256')
        tout.add(work / 'payload', arcname='payload')
    print('crafted', out, 'size', out.stat().st_size)
finally:
    shutil.rmtree(work, ignore_errors=True)
PY"
set +e
sshx "$SERVER" "sudo python3 /usr/local/sbin/frp-restore $CRAFT" >"$OUT_DIR/restore-missing-acl.txt" 2>&1
rc=$?
set -e
sshx "$SERVER" "sudo rm -f $CRAFT"
[[ "$rc" -ne 0 ]] || fail "restore should FAIL when ACL missing from archive"
pass RESTORE_MISSING_ACL_FAIL

echo "=== normal restore + access plugin readiness ==="
CODE_BEFORE="$(sshx "$SERVER" 'curl -s -o /dev/null -w %{http_code} http://127.0.0.1:6101/healthz || true')"
sshx "$SERVER" "sudo python3 /usr/local/sbin/frp-restore $BAK_OK" | tee "$OUT_DIR/restore-ok.txt"
CODE=""
for i in $(seq 1 30); do
  CODE="$(sshx "$SERVER" 'curl -s -o /dev/null -w %{http_code} http://127.0.0.1:6101/healthz || true')"
  [[ "$CODE" == "200" ]] && break
  sleep 2
done
[[ "$CODE" == "200" ]] || fail "access plugin healthz not 200 after restore (got $CODE, before=$CODE_BEFORE)"
sshx "$SERVER" 'systemctl is-active frp-access-plugin' | grep -qx active || fail "access plugin inactive after restore"
pass RESTORE_ACCESS_PLUGIN_READY

cat >"$OUT_DIR/result.env" <<EOF
TARGETED_REAL_E2E=PASS
BACKUP_NORMAL=PASS
BACKUP_MISSING_ACL=PASS
BACKUP_MISSING_REGISTRY=PASS
RESTORE_MISSING_ACL=PASS
RESTORE_ACCESS_PLUGIN=PASS
EOF
echo "TARGETED_REAL_E2E=PASS report=$OUT_DIR"
