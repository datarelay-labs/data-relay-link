#!/usr/bin/env bash
# Test-owned allocator processes must not survive success, failure, or SIGTERM.
# Must never stop the product allocator.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

parent_cleanup() {
  local rc="${FRP_SAVED_EXIT_RC:-$?}"
  local mode="${1:-}"
  if [[ "$mode" == signal ]]; then
    trap - EXIT INT TERM HUP
  fi
  set +e
  frp_test_stop_tmp_allocators
  rm -rf "$WORKDIR"
  if [[ "$mode" == signal ]]; then
    exit "$rc"
  fi
}
trap parent_cleanup EXIT
trap 'FRP_SAVED_EXIT_RC=130; parent_cleanup signal' INT
trap 'FRP_SAVED_EXIT_RC=143; parent_cleanup signal' TERM
trap 'FRP_SAVED_EXIT_RC=129; parent_cleanup signal' HUP

PRODUCT_BEFORE="$(frp_test_product_allocator_pids || true)"

write_fixture() {
  local dest="$1" mode="$2"
  cat >"$dest" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ROOT=$(printf '%q' "$ROOT")
HELPER=$(printf '%q' "$ROOT/tests/lib/frp-test-procs.sh")
MODE=$(printf '%q' "$mode")
READY=$(printf '%q' "$WORKDIR/ready")
# shellcheck disable=SC1090
. "\$HELPER"
WORKDIR="\$(mktemp -d)"
ALLOC_PID=""
frp_test_arm_cleanup
ALLOC_ROOT="\$WORKDIR/allocator"
mkdir -p "\$ALLOC_ROOT/enrollments"
python3 "\$ROOT/lib/frp_pki.py" ensure --pki-dir "\$ALLOC_ROOT/pki" --public-host 127.0.0.1 >/dev/null
PORT="\$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 - "\$ALLOC_ROOT" "\$PORT" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
port = int(sys.argv[2])
pki = root / 'pki'
(root / 'server_token').write_text('test-frp-token-do-not-use\\n')
(root / 'server_token').chmod(0o600)
(root / 'registry.json').write_text(json.dumps({
    'schema_version': 2, 'reserved': [], 'clients': {},
}, indent=2) + '\\n')
(root / 'config.json').write_text(json.dumps({
    'public_host': '127.0.0.1',
    'frp_control_public_port': 443,
    'frp_control_listen_port': 443,
    'port_start': 19400,
    'port_end': 19410,
    'listen_host': '127.0.0.1',
    'listen_port': port,
    'allocator_listen_port': port,
    'tls_ca_cert': str(pki / 'ca.crt'),
    'tls_server_cert': str(pki / 'server.crt'),
    'tls_server_key': str(pki / 'server.key'),
    'registry_file': str(root / 'registry.json'),
    'enrollments_dir': str(root / 'enrollments'),
    'token_file': str(root / 'server_token'),
}, indent=2) + '\\n')
PY
python3 "\$ROOT/server/frp-port-allocator.py" --config "\$ALLOC_ROOT/config.json" >"\$WORKDIR/alloc.log" 2>&1 &
ALLOC_PID=\$!
for i in \$(seq 1 50); do
  if curl -fsS --cacert "\$ALLOC_ROOT/pki/ca.crt" "https://127.0.0.1:\${PORT}/healthz" >/dev/null 2>&1; then
    printf '%s\\n' "\$ALLOC_PID" >"\$READY"
    break
  fi
  sleep 0.1
done
[[ -f "\$READY" ]] || { cat "\$WORKDIR/alloc.log" >&2; exit 1; }
case "\$MODE" in
  success) exit 0 ;;
  fail) echo "induced failure" >&2; exit 1 ;;
  hang) sleep 60 & wait \$! || true; exit 0 ;;
  chain)
    prev="\$(trap -p EXIT 2>/dev/null || true)"
    trap ':' EXIT
    eval "\$prev"
    exit 0
    ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$dest"
}

wait_ready() {
  local i
  rm -f "$WORKDIR/ready"
  for i in $(seq 1 80); do
    if [[ -f "$WORKDIR/ready" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

assert_product_preserved() {
  local after pid
  after="$(frp_test_product_allocator_pids || true)"
  if [[ -z "${PRODUCT_BEFORE//[$'\n']/}" ]]; then
    [[ -z "${after//[$'\n']/}" ]] || fail "test started a product allocator"
    return 0
  fi
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    frp_test_pid_alive "$pid" || fail "product allocator pid $pid stopped"
    grep -qx "$pid" <<<"$after" || fail "product allocator pid $pid missing after test"
  done <<<"$PRODUCT_BEFORE"
}

write_fixture "$WORKDIR/fixture.sh" success
"$WORKDIR/fixture.sh"
wait_ready || true
frp_test_assert_no_tmp_allocators || fail "success path left a /tmp allocator"
assert_product_preserved
pass "success path reaps test allocator"

write_fixture "$WORKDIR/fixture-fail.sh" fail
if "$WORKDIR/fixture-fail.sh"; then
  fail "failure fixture should exit 1"
fi
frp_test_assert_no_tmp_allocators || fail "failure path left a /tmp allocator"
assert_product_preserved
pass "failure path reaps test allocator"

write_fixture "$WORKDIR/fixture-term.sh" hang
rm -f "$WORKDIR/ready"
"$WORKDIR/fixture-term.sh" &
child=$!
wait_ready || { kill -KILL "$child" 2>/dev/null || true; fail "hang fixture allocator did not start"; }
[[ -n "$(frp_test_tmp_allocator_pids || true)" ]] || fail "hang fixture did not start a /tmp allocator"
kill -TERM "$child"
for i in $(seq 1 50); do
  if ! kill -0 "$child" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$child" 2>/dev/null; then
  kill -KILL "$child" 2>/dev/null || true
  wait "$child" 2>/dev/null || true
  fail "SIGTERM fixture did not exit"
fi
wait "$child" || true
frp_test_assert_no_tmp_allocators || fail "SIGTERM path left a /tmp allocator"
assert_product_preserved
pass "SIGTERM path reaps test allocator"

write_fixture "$WORKDIR/fixture-chain.sh" chain
"$WORKDIR/fixture-chain.sh"
frp_test_assert_no_tmp_allocators || fail "chained EXIT trap left a /tmp allocator"
assert_product_preserved
pass "chained EXIT trap still reaps test allocator"

if [[ -n "${PRODUCT_BEFORE//[$'\n']/}" ]]; then
  product_pid="$(printf '%s\n' "$PRODUCT_BEFORE" | head -n1)"
  if frp_test_stop_pid "$product_pid"; then
    fail "stop_pid should refuse the product allocator"
  fi
  frp_test_pid_alive "$product_pid" || fail "refused stop still killed product allocator"
  pass "stop_pid refuses product allocator"
else
  pass "stop_pid product refuse skipped (no product allocator)"
fi

assert_product_preserved
frp_test_assert_no_tmp_allocators || fail "final leftover /tmp allocator"
pass "product allocator still running when present"

echo
echo "ALLOCATOR_PROCESS_CLEANUP=PASS"
