#!/usr/bin/env bash
# Finding A - Zero-Touch lost-response recovery.
#
# If the HTTPS response from /bootstrap/redeem or /enroll is lost, or the
# client crashes after the allocator commits but before local state
# (client-state.json + frpc.toml + management identity) is written, the
# client must be able to resume from a local crash-safe pending-enrollment
# transaction (lib/frp-client-common.sh: frp_pending_enroll_write/_load/
# _clear) instead of losing the Enrollment Secret and requiring a fresh
# Enrollment Code. A used Bootstrap Ticket must never be redeemed again;
# resume relies on the allocator's existing idempotent replay of a used
# Enrollment Code (server/frp-port-allocator.py
# _used_enrollment_idempotent_replay).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
ALLOC_PID=""
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
frp_test_arm_cleanup

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

extract_bootstrap_ticket() {
  python3 - "$1" <<'PY'
import base64, json, re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", text)
if not m:
    raise SystemExit('missing ticket')
parts = m.group(1).split('.', 1)
padded = parts[1] + ('=' * (-len(parts[1]) % 4))
payload = json.loads(base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8'))
print(payload['t'])
PY
}

make_frpc() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  cat >"$dest" <<'EOF'
#!/bin/sh
if [ "$1" = verify ]; then
  exit 0
fi
exit 0
EOF
  chmod +x "$dest"
}

start_allocator() {
  local cfg="$1"
  python3 "$ROOT/server/frp-port-allocator.py" --config "$cfg" >"$WORKDIR/alloc.log" 2>&1 &
  ALLOC_PID=$!
  local i
  for i in $(seq 1 50); do
    if curl -fsS --cacert "$ALLOC_ROOT/pki/ca.crt" "https://127.0.0.1:${ALLOC_PORT}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  cat "$WORKDIR/alloc.log" >&2 || true
  fail "allocator did not start"
}

ALLOC_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
ALLOC_ROOT="$WORKDIR/allocator"
mkdir -p "$ALLOC_ROOT/enrollments" "$ALLOC_ROOT/bootstrap"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$ALLOC_ROOT/pki" --public-host 127.0.0.1 >/dev/null
CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$ALLOC_ROOT/pki/ca.crt")"
python3 - "$ALLOC_ROOT" "$ALLOC_PORT" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
port = int(sys.argv[2])
pki = root / 'pki'
(root / 'server_token').write_text('test-enroll-token-do-not-use\n')
(root / 'server_token').chmod(0o600)
(root / 'registry.json').write_text(json.dumps({
    'schema_version': 2, 'reserved': [], 'clients': {},
}, indent=2) + '\n')
(root / 'config.json').write_text(json.dumps({
    'public_host': '203.0.113.10',
    'public_ip': '203.0.113.10',
    'frp_control_public_port': 8443,
    'frp_control_listen_port': 443,
    'port_start': 18400,
    'port_end': 18430,
    'listen_host': '127.0.0.1',
    'listen_port': port,
    'allocator_listen_port': port,
    'allocator_public_port': port,
    'tls_ca_cert': str(pki / 'ca.crt'),
    'tls_server_cert': str(pki / 'server.crt'),
    'tls_server_key': str(pki / 'server.key'),
    'registry_file': str(root / 'registry.json'),
    'enrollments_dir': str(root / 'enrollments'),
    'bootstrap_dir': str(root / 'bootstrap'),
    'token_file': str(root / 'server_token'),
    'client_installer_url': 'https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/main/dist/bootstrap-client.sh',
    'allocator_public_url': 'https://127.0.0.1:%s/enroll' % port,
}, indent=2) + '\n')
PY
start_allocator "$ALLOC_ROOT/config.json"
SSH_USER="$(id -un)"

# Server-side tree used only by frp-create-client to mint tickets.
LIVE_TREE="$WORKDIR/live-server"
mkdir -p "$LIVE_TREE/etc/frp-auto-deploy" "$LIVE_TREE/var/lib/frp-auto-deploy" "$LIVE_TREE/etc/frp"
cp -a "$ALLOC_ROOT/pki" "$LIVE_TREE/etc/frp-auto-deploy/pki"
python3 - "$LIVE_TREE" "$ALLOC_PORT" <<'PY'
import json, sys
from pathlib import Path
tree = Path(sys.argv[1])
port = int(sys.argv[2])
(tree / 'etc/frp-auto-deploy/config.json').write_text(json.dumps({
    'public_host': '203.0.113.10',
    'public_ip': '203.0.113.10',
    'frp_control_public_port': 8443,
    'frp_control_listen_port': 443,
    'allocator_public_url': 'https://127.0.0.1:%s/enroll' % port,
    'tls_ca_cert': '/etc/frp-auto-deploy/pki/ca.crt',
    'tls_server_cert': '/etc/frp-auto-deploy/pki/server.crt',
    'tls_server_key': '/etc/frp-auto-deploy/pki/server.key',
    'client_installer_url': 'https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/main/dist/bootstrap-client.sh',
    'enrollments_dir': '/var/lib/frp-auto-deploy/enrollments',
    'bootstrap_dir': '/var/lib/frp-auto-deploy/bootstrap',
    'registry_file': '/var/lib/frp-auto-deploy/registry.json',
    'token_file': '/etc/frp/server_token',
}, indent=2) + '\n')
PY
ln -sfn "$ALLOC_ROOT/enrollments" "$LIVE_TREE/var/lib/frp-auto-deploy/enrollments"
ln -sfn "$ALLOC_ROOT/bootstrap" "$LIVE_TREE/var/lib/frp-auto-deploy/bootstrap"
ln -sfn "$ALLOC_ROOT/registry.json" "$LIVE_TREE/var/lib/frp-auto-deploy/registry.json"
ln -sfn "$ALLOC_ROOT/server_token" "$LIVE_TREE/etc/frp/server_token"

issue_ticket() {
  local note="$1"
  FRP_DEPLOY_TEST_ROOT="$LIVE_TREE" python3 "$ROOT/tools/frp-create-client" \
    --one-line --ssh --ssh-user "$SSH_USER" --note "$note"
}

run_client() {
  # run_client TREE TICKET MACHINE_ID OUT [EXTRA_ENV...]
  local tree="$1" ticket="$2" machine="$3" out="$4"
  shift 4
  mkdir -p "$tree/etc/frp" "$tree/usr/local/bin" "$tree/usr/local/lib/frp-auto-deploy"
  make_frpc "$tree/usr/local/bin/frpc"
  (
    export FRP_CLIENT_TEST_ROOT="$tree"
    export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
    export FRP_SKIP_DOWNLOAD=1
    export FRP_SKIP_SYSTEMD=1
    export FRP_TEST_HOSTNAME="pending-recovery"
    export FRP_TEST_MACHINE_ID="$machine"
    export FRP_ALLOCATOR_URL="https://127.0.0.1:${ALLOC_PORT}/enroll"
    export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
    export FRP_CLIENT_SOURCED=1
    export FRP_CLIENT_HOOK_LOG="${out}.hook"
    : >"$FRP_CLIENT_HOOK_LOG"
    if [[ -n "$ticket" ]]; then
      export FRP_BOOTSTRAP_TICKET="$ticket"
      export FRP_ZERO_TOUCH=1
      export FRP_SSH_USER="$SSH_USER"
      export FRP_SSH_PORT=22
    else
      unset FRP_BOOTSTRAP_TICKET FRP_ZERO_TOUCH FRP_SSH_USER FRP_SSH_PORT 2>/dev/null || true
    fi
    for kv in "$@"; do
      export "$kv"
    done
    # shellcheck source=../install-client.sh
    . "$ROOT/install-client.sh"
    set +e
    frp_client_main >"$out" 2>"${out%.out}.err" </dev/null
    rc=$?
    set -e
    exit "$rc"
  )
}

pending_path() { printf '%s' "$1/etc/frp/enroll-pending.json"; }

# ---------------------------------------------------------------------------
# 1. "redeemed" phase resume: /bootstrap/redeem succeeds and is persisted,
#    but the /enroll response is lost (simulated: FRP_CLIENT_HOOK_ENROLL_FAIL
#    short-circuits before any network call reaches the allocator). Resuming
#    with no ticket must exact-replay /enroll using the persisted secret and
#    complete the install without ever redeeming the ticket twice.
# ---------------------------------------------------------------------------
issue_ticket customer-redeemed >"$WORKDIR/t1-create.out"
T1_TICKET="$(extract_bootstrap_ticket "$WORKDIR/t1-create.out")"
T1_ID="${T1_TICKET#bt1.}"; T1_ID="${T1_ID%%.*}"
T1_TREE="$WORKDIR/client-redeemed"
T1_MACHINE='11112222333344445555666677778888'

if run_client "$T1_TREE" "$T1_TICKET" "$T1_MACHINE" "$WORKDIR/t1-a.out" \
    "FRP_CLIENT_HOOK_ENROLL_FAIL=1"; then
  fail "attempt 1 (enroll hook failure) unexpectedly succeeded"
fi
[[ -f "$(pending_path "$T1_TREE")" ]] || fail "pending file missing after redeemed-phase crash"
PENDING1_PHASE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["phase"])' "$(pending_path "$T1_TREE")")"
[[ "$PENDING1_PHASE" == "redeemed" ]] || fail "expected phase=redeemed, got $PENDING1_PHASE"
[[ ! -f "$T1_TREE/etc/frp/client-state.json" ]] || fail "client-state.json must not exist yet"
grep -q bootstrap_redeem "$WORKDIR/t1-a.out.hook" || fail "attempt 1 did not redeem"
grep -q '^enroll$' "$WORKDIR/t1-a.out.hook" || fail "attempt 1 did not attempt enroll"

# Resume: no ticket, no zero-touch env at all.
if ! run_client "$T1_TREE" "" "$T1_MACHINE" "$WORKDIR/t1-b.out"; then
  cat "$WORKDIR/t1-b.out" "$WORKDIR/t1-b.err" >&2
  fail "resume from redeemed phase did not succeed"
fi
grep -qi 'resuming from local crash-safe recovery state' "$WORKDIR/t1-b.out" "$WORKDIR/t1-b.err" \
  || fail "resume did not announce recovery"
if grep -q bootstrap_redeem "$WORKDIR/t1-b.out.hook"; then
  fail "resume re-redeemed an already-bound bootstrap ticket"
fi
grep -q '^enroll$' "$WORKDIR/t1-b.out.hook" || fail "resume did not exact-replay /enroll"
[[ -f "$T1_TREE/etc/frp/client-state.json" ]] || fail "resume did not commit client-state.json"
[[ ! -f "$(pending_path "$T1_TREE")" ]] || fail "pending file must be cleared after successful resume"
python3 - "$T1_TREE/etc/frp/client-state.json" <<'PY' || fail "resumed state missing ssh service"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['services']['ssh']['remote_port'], state
PY
pass "REDEEMED_PHASE_EXACT_REPLAY_RESUME"
pass "REDEEMED_PHASE_NO_TICKET_REUSE"
pass "REDEEMED_PHASE_PENDING_CLEARED_AFTER_SUCCESS"

# Ticket is now fully consumed: a third attempt with the *original* ticket
# (e.g. an admin re-pasting the one-liner after resume already finished)
# must be rejected, proving the recovery path never weakened single-use
# ticket semantics.
T1_AGAIN="$WORKDIR/client-redeemed-again"
if run_client "$T1_AGAIN" "$T1_TICKET" 'ffff1111222233334444555566667777' "$WORKDIR/t1-c.out"; then
  fail "reusing a fully-consumed ticket on another machine should fail"
fi
grep -qE 'BOOTSTRAP_TICKET_(USED|BOUND)' "$WORKDIR/t1-c.out" "$WORKDIR/t1-c.err" \
  || fail "expected ticket-used/bound rejection after full completion"
pass "TICKET_SINGLE_USE_PRESERVED_AFTER_RECOVERY"

# ---------------------------------------------------------------------------
# 2. "enrolled" phase resume: /enroll succeeds and the allocator commits the
#    reservation, but the client crashes before client-state.json is
#    written (simulated: FRP_CLIENT_HOOK_CRASH_AFTER_ENROLL). Resuming must
#    reuse the cached response and finish the local commit WITHOUT another
#    /enroll (or /bootstrap/redeem) round trip.
# ---------------------------------------------------------------------------
issue_ticket customer-enrolled >"$WORKDIR/t2-create.out"
T2_TICKET="$(extract_bootstrap_ticket "$WORKDIR/t2-create.out")"
T2_TREE="$WORKDIR/client-enrolled"
T2_MACHINE='22223333444455556666777788889999'

if run_client "$T2_TREE" "$T2_TICKET" "$T2_MACHINE" "$WORKDIR/t2-a.out" \
    "FRP_CLIENT_HOOK_CRASH_AFTER_ENROLL=1"; then
  fail "attempt 1 (crash-after-enroll hook) unexpectedly succeeded"
fi
[[ -f "$(pending_path "$T2_TREE")" ]] || fail "pending file missing after enrolled-phase crash"
PENDING2_PHASE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["phase"])' "$(pending_path "$T2_TREE")")"
[[ "$PENDING2_PHASE" == "enrolled" ]] || fail "expected phase=enrolled, got $PENDING2_PHASE"
[[ ! -f "$T2_TREE/etc/frp/client-state.json" ]] || fail "client-state.json must not exist yet"
python3 - "$(pending_path "$T2_TREE")" <<'PY' || fail "cached enroll response missing from pending file"
import json, sys
from pathlib import Path
rec = json.loads(Path(sys.argv[1]).read_text())
assert rec['enroll_meta']['token_ciphertext']
assert rec['allocated_services'][0]['remote_port']
assert rec.get('mgmt_fingerprint')
PY

if ! run_client "$T2_TREE" "" "$T2_MACHINE" "$WORKDIR/t2-b.out"; then
  cat "$WORKDIR/t2-b.out" "$WORKDIR/t2-b.err" >&2
  fail "resume from enrolled phase did not succeed"
fi
grep -qi 'reusing the previously completed enrollment response' "$WORKDIR/t2-b.out" \
  || fail "resume did not reuse cached response"
if grep -q bootstrap_redeem "$WORKDIR/t2-b.out.hook"; then
  fail "resume re-redeemed an already-bound bootstrap ticket"
fi
if grep -q '^enroll$' "$WORKDIR/t2-b.out.hook"; then
  fail "resume made an unnecessary /enroll round trip despite a cached response"
fi
[[ -f "$T2_TREE/etc/frp/client-state.json" ]] || fail "resume did not commit client-state.json"
[[ ! -f "$(pending_path "$T2_TREE")" ]] || fail "pending file must be cleared after successful resume"
pass "ENROLLED_PHASE_CACHED_RESUME_NO_NETWORK_CALL"
pass "ENROLLED_PHASE_PENDING_CLEARED_AFTER_SUCCESS"

# ---------------------------------------------------------------------------
# 3. Pending file storage properties: root-only 0600 while it exists, and
#    the enrollment secret it legitimately holds must never leak into the
#    committed client-state.json.
# ---------------------------------------------------------------------------
issue_ticket customer-mode-check >"$WORKDIR/t3-create.out"
T3_TICKET="$(extract_bootstrap_ticket "$WORKDIR/t3-create.out")"
T3_TREE="$WORKDIR/client-mode-check"
T3_MACHINE='33334444555566667777888899990000'
if run_client "$T3_TREE" "$T3_TICKET" "$T3_MACHINE" "$WORKDIR/t3-a.out" \
    "FRP_CLIENT_HOOK_CRASH_AFTER_ENROLL=1"; then
  fail "mode-check attempt unexpectedly succeeded"
fi
MODE="$(stat -c '%a' "$(pending_path "$T3_TREE")")"
[[ "$MODE" == "600" ]] || fail "pending file mode expected 600, got $MODE"

if ! run_client "$T3_TREE" "" "$T3_MACHINE" "$WORKDIR/t3-b.out"; then
  cat "$WORKDIR/t3-b.out" "$WORKDIR/t3-b.err" >&2
  fail "mode-check resume failed"
fi
if grep -qi 'secret' "$T3_TREE/etc/frp/client-state.json"; then
  fail "client-state.json must never contain the word secret"
fi
pass "PENDING_FILE_MODE_0600"
pass "PENDING_FILE_SECRET_NEVER_IN_CLIENT_STATE"

# ---------------------------------------------------------------------------
# 4. Manual (non zero-touch) enrollment also gets crash-safe recovery: the
#    pending write/load/clear helpers work independent of the Bootstrap
#    Ticket path itself. Exercise the bash helpers directly.
# ---------------------------------------------------------------------------
(
  set -euo pipefail
  # shellcheck source=../lib/frp-common.sh
  . "$ROOT/lib/frp-common.sh"
  # shellcheck source=../lib/frp-client-common.sh
  . "$ROOT/lib/frp-client-common.sh"
  export FRP_CLIENT_TEST_ROOT="$WORKDIR/helper-unit"
  mkdir -p "$FRP_CLIENT_TEST_ROOT/etc/frp"
  SVC_FILE="$WORKDIR/helper-services.json"
  printf '%s' '[{"id":"web","name":"web","preset":"custom","local_ip":"127.0.0.1","local_port":8080}]' >"$SVC_FILE"
  frp_pending_enroll_write redeemed "unit-machine-id" "unit-host" "https://example.test/enroll" \
    "abc123" "s3cr3t-value" "$SVC_FILE"
  [[ -f "$(frp_pending_enroll_path)" ]] || { echo "FAIL helper write did not create file" >&2; exit 1; }
  MODE="$(stat -c '%a' "$(frp_pending_enroll_path)")"
  [[ "$MODE" == "600" ]] || { echo "FAIL helper file mode $MODE" >&2; exit 1; }
  frp_pending_enroll_exists_for "unit-machine-id" || { echo "FAIL exists_for should match" >&2; exit 1; }
  if frp_pending_enroll_exists_for "other-machine-id"; then
    echo "FAIL exists_for should not match a different machine id" >&2
    exit 1
  fi
  OUT_SVC="$WORKDIR/helper-out-services.json"
  OUT_ALLOC="$WORKDIR/helper-out-allocated.json"
  OUT_META="$WORKDIR/helper-out-meta.json"
  : >"$OUT_ALLOC"
  : >"$OUT_META"
  frp_pending_enroll_load "unit-machine-id" "$OUT_SVC" "$OUT_ALLOC" "$OUT_META" \
    LOADED_PHASE LOADED_ID LOADED_SECRET
  [[ "$LOADED_PHASE" == "redeemed" ]] || { echo "FAIL loaded phase $LOADED_PHASE" >&2; exit 1; }
  [[ "$LOADED_ID" == "abc123" ]] || { echo "FAIL loaded id $LOADED_ID" >&2; exit 1; }
  [[ "$LOADED_SECRET" == "s3cr3t-value" ]] || { echo "FAIL loaded secret mismatch" >&2; exit 1; }
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d[0]["id"]=="web"' "$OUT_SVC"
  frp_pending_enroll_clear
  [[ ! -f "$(frp_pending_enroll_path)" ]] || { echo "FAIL clear did not remove file" >&2; exit 1; }
  echo "HELPER_UNIT_OK"
)
pass "PENDING_ENROLL_HELPERS_WRITE_LOAD_CLEAR"

echo
echo "PENDING_ENROLL_RECOVERY_TEST=PASS"
