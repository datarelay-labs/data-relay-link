#!/usr/bin/env bash
# Lightweight targeted Real E2E for Support Bundle (Linux server + client).
# Optional: set FRP_E2E_SERVER_ALIAS / FRP_E2E_CLIENT_ALIAS. When hosts are
# unreachable, exits 2 as ENVIRONMENT_BLOCKER (does not fail the product).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new)
SERVER="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
CLIENT="${FRP_E2E_CLIENT_ALIAS:-frp-e2e-aws}"
OUT_DIR="${FRP_SUPPORT_E2E_OUT:-$ROOT/e2e-reports/support-bundle-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"
exec > >(tee -a "$OUT_DIR/run.log") 2>&1

pass(){ echo "PASS $1"; }
fail(){ echo "FAIL $1" >&2; echo "TARGETED_REAL_E2E=FAIL" >"$OUT_DIR/result.env"; exit 1; }
blocker(){ echo "ENVIRONMENT_BLOCKER $1" >&2; echo "TARGETED_REAL_E2E=ENVIRONMENT_BLOCKER" >"$OUT_DIR/result.env"; exit 2; }
sshx(){ local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$h" "$@"; }

echo "=== Support Bundle targeted Real E2E ==="

# Local fixture path always runs (no remote required).
bash "$ROOT/tests/test-support-bundle.sh" | tee "$OUT_DIR/unit.log"
pass "LOCAL_FIXTURE_SUITE"

# Portability: command surface exists for Windows/macOS packaging.
grep -q 'support-bundle' "$ROOT/windows/tools/FrpClient.ps1" || fail "windows command missing"
grep -q 'frp_support_bundle.py' "$ROOT/lib/frp-client-common.sh" || fail "client install missing lib"
grep -q 'frp-support-bundle' "$ROOT/lib/server-project-files.manifest" || fail "server manifest missing tool"
pass "PORTABILITY_COMMAND_SURFACE"

if ! sshx "$SERVER" 'echo ok' >/dev/null 2>&1; then
  blocker "server unreachable ($SERVER); local suite already passed"
fi
if ! sshx "$CLIENT" 'echo ok' >/dev/null 2>&1; then
  blocker "client unreachable ($CLIENT); local suite already passed"
fi

# Live hosts may predate this feature; sync the Support Bundle surface before
# invoking `frpctl support-bundle` (same pattern as target-health / access-control).
echo "=== sync support-bundle feature onto server ==="
TMP_SRV=/tmp/frp-support-srv-$$
sshx "$SERVER" "sudo rm -rf $TMP_SRV && sudo mkdir -p $TMP_SRV && sudo chmod 777 $TMP_SRV"
for f in \
  lib/frp_support_bundle.py \
  lib/frp_ctl_grammar.py \
  lib/frp_doctor.py \
  tools/frp-support-bundle \
  tools/frpctl
do
  scp -o BatchMode=yes -o ConnectTimeout=12 "$ROOT/$f" "$SERVER:$TMP_SRV/$(basename "$f")"
done
sshx "$SERVER" "sudo install -m 0644 $TMP_SRV/frp_support_bundle.py /usr/local/lib/frp-auto-deploy/frp_support_bundle.py
sudo install -m 0644 $TMP_SRV/frp_ctl_grammar.py /usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py
sudo install -m 0644 $TMP_SRV/frp_doctor.py /usr/local/lib/frp-auto-deploy/frp_doctor.py
sudo install -m 0755 $TMP_SRV/frp-support-bundle /usr/local/sbin/frp-support-bundle
sudo install -m 0755 $TMP_SRV/frpctl /usr/local/sbin/frpctl
sudo rm -rf $TMP_SRV
sudo frpctl help 2>/dev/null | grep -q support-bundle
sudo test -x /usr/local/sbin/frp-support-bundle"

echo "=== sync support-bundle feature onto client ==="
TMP_CLI=/tmp/frp-support-cli-$$
sshx "$CLIENT" "sudo rm -rf $TMP_CLI && sudo mkdir -p $TMP_CLI && sudo chmod 777 $TMP_CLI"
for f in \
  lib/frp_support_bundle.py \
  lib/frp_ctl_grammar.py \
  lib/frp_doctor.py \
  tools/frp-support-bundle \
  tools/frpctl
do
  scp -o BatchMode=yes -o ConnectTimeout=12 "$ROOT/$f" "$CLIENT:$TMP_CLI/$(basename "$f")"
done
sshx "$CLIENT" "sudo install -m 0644 $TMP_CLI/frp_support_bundle.py /usr/local/lib/frp-auto-deploy/frp_support_bundle.py
sudo install -m 0644 $TMP_CLI/frp_ctl_grammar.py /usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py
sudo install -m 0644 $TMP_CLI/frp_doctor.py /usr/local/lib/frp-auto-deploy/frp_doctor.py
sudo install -m 0755 $TMP_CLI/frp-support-bundle /usr/local/bin/frp-support-bundle
sudo install -m 0755 $TMP_CLI/frpctl /usr/local/bin/frpctl
sudo rm -rf $TMP_CLI
sudo frpctl help 2>/dev/null | grep -q support-bundle
sudo test -x /usr/local/bin/frp-support-bundle"
pass "REMOTE_FEATURE_SYNC"

run_remote_bundle() {
  local host="$1" label="$2"
  local remote_path="/tmp/frp-support-e2e-${label}.tar.gz"
  sshx "$host" "sudo frpctl support-bundle --output ${remote_path} && sudo chmod a+r ${remote_path}" \
    | tee "$OUT_DIR/${label}.create.log"
  sshx "$host" "test -f ${remote_path} && tar -tzf ${remote_path} | head"
  # shellcheck disable=SC2029
  sshx "$host" "python3 - <<PY
import tarfile
path='${remote_path}'
forbidden=(
  'BEGIN '+'RSA PRIVATE KEY',
  'BEGIN '+'PRIVATE KEY',
  'BEGIN '+'OPENSSH PRIVATE KEY',
  'Enrollment Code:',
)
with tarfile.open(path,'r:gz') as tf:
  names=tf.getnames()
  assert 'meta.json' in names, names
  assert 'manifest.json' in names, names
  for m in tf.getmembers():
    if not m.isfile():
      continue
    data=tf.extractfile(m).read()
    text=data.decode('utf-8','replace')
    for bad in forbidden:
      if bad in text:
        raise SystemExit('secret pattern %r in %s' % (bad, m.name))
    base=m.name.rsplit('/',1)[-1]
    if base.endswith('.key') or base == 'server_token':
      raise SystemExit('forbidden member %s' % m.name)
print('ok', len(names), 'members')
PY"
  pass "REMOTE_${label}_BUNDLE"
}

run_remote_bundle "$SERVER" "server"
run_remote_bundle "$CLIENT" "client"

echo "TARGETED_REAL_E2E=PASS" >"$OUT_DIR/result.env"
echo "ALL SUPPORT BUNDLE E2E CHECKS PASSED"
echo "Report: $OUT_DIR"
