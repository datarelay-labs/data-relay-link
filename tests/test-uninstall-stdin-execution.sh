#!/usr/bin/env bash
# Uninstall scripts must support curl|bash -s stdin execution under set -u.
# File execution must keep working. Never touch the real host.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

MOCK="$WORKDIR/mock-systemctl"
cat >"$MOCK" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
shift || true
unit=""
for arg in "$@"; do
  case "$arg" in
    -p|--value|LoadState) continue ;;
    *) unit="$arg" ;;
  esac
done
state_dir="${FRP_MOCK_UNIT_DIR:-}"
unit_state() {
  if [[ -f "${state_dir}/${1}.active" ]]; then
    echo active
  elif [[ -f "${state_dir}/${1}.loaded" ]]; then
    echo inactive
  else
    echo not-found
  fi
}
case "$cmd" in
  show)
    st="$(unit_state "$unit")"
    if [[ "$st" == "not-found" ]]; then echo not-found; else echo loaded; fi
    exit 0
    ;;
  is-active)
    st="$(unit_state "$unit")"
    if [[ "$st" == "active" ]]; then echo active; exit 0; fi
    echo inactive
    exit 3
    ;;
  stop|disable|reset-failed|daemon-reload)
    if [[ -n "$state_dir" ]]; then
      rm -f "${state_dir}/${unit}.active"
      : >"${state_dir}/${unit}.loaded"
      rm -f "${state_dir}/${unit}.enabled"
    fi
    exit 0
    ;;
  is-enabled)
    if [[ -f "${state_dir}/${unit}.enabled" ]]; then
      echo enabled
      exit 0
    fi
    echo disabled
    exit 1
    ;;
  *) exit 0 ;;
esac
EOF
chmod 0755 "$MOCK"

seed_server() {
  local tree="$1"
  mkdir -p \
    "$tree/etc/drlink/pki" \
    "$tree/etc/frp" \
    "$tree/var/lib/drlink" \
    "$tree/usr/local/bin" \
    "$tree/usr/local/lib/drlink" \
    "$tree/etc/systemd/system"
  : >"$tree/etc/frp/server_token"
  : >"$tree/etc/drlink/pki/ca.key"
  : >"$tree/etc/drlink/pki/ca.crt"
  printf '{}\n' >"$tree/var/lib/drlink/registry.json"
  : >"$tree/usr/local/bin/frpctl"
  : >"$tree/usr/local/bin/drlink"
  cp "$ROOT/lib/frp-role-ownership.sh" "$tree/usr/local/lib/drlink/frp-role-ownership.sh"
  cp "$ROOT/lib/frp_project_files.py" "$tree/usr/local/lib/drlink/frp_project_files.py"
  mkdir -p "$tree/usr/local/lib/drlink/data/egress-recipes"
  : >"$tree/etc/systemd/system/drlink-server.service"
}

seed_client() {
  local tree="$1"
  mkdir -p \
    "$tree/etc/frp" \
    "$tree/etc/drlink" \
    "$tree/var/lib/drlink" \
    "$tree/usr/local/bin" \
    "$tree/usr/local/lib/drlink" \
    "$tree/etc/systemd/system"
  printf '{}\n' >"$tree/etc/frp/client-state.json"
  : >"$tree/usr/local/bin/frp-client"
  : >"$tree/usr/local/bin/drlink"
  cp "$ROOT/lib/frp-role-ownership.sh" "$tree/usr/local/lib/drlink/frp-role-ownership.sh"
  : >"$tree/etc/systemd/system/drlink-client.service"
}

assert_no_bash_source_error() {
  local err="$1"
  if grep -q 'BASH_SOURCE\[0\]: unbound variable' "$err"; then
    fail "BASH_SOURCE unbound variable: $(cat "$err")"
  fi
}

# Prove the regression shape: unset BASH_SOURCE under set -u must be exercised.
PROOF="$WORKDIR/proof.sh"
cat >"$PROOF" <<'EOF'
set -euo pipefail
if [[ -n "${BASH_SOURCE[0]+x}" && -n "${BASH_SOURCE[0]}" ]]; then
  echo "HAS_BASH_SOURCE=${BASH_SOURCE[0]}"
else
  echo "BASH_SOURCE_UNSET_OR_EMPTY=YES"
fi
echo "SET_U_ENABLED=YES"
EOF
proof_out="$(cat "$PROOF" | bash -s --)"
grep -q 'BASH_SOURCE_UNSET_OR_EMPTY=YES' <<<"$proof_out" || fail "stdin did not unset BASH_SOURCE"
grep -q 'SET_U_ENABLED=YES' <<<"$proof_out" || fail "set -u not enabled"
pass "BASH_SOURCE_STDIN_PROOF"

# --- server: file execution ---
TREE="$WORKDIR/server-file"
UNIT="$WORKDIR/units-server-file"
seed_server "$TREE"
mkdir -p "$UNIT"
: >"$UNIT/drlink-server.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_UNINSTALL_HOOK_SYSTEMCTL="$MOCK"
export FRP_MOCK_UNIT_DIR="$UNIT"
export FRP_SKIP_SYSTEMD=0
if ! "$ROOT/dist/uninstall-server.sh" --purge --yes \
  >"$WORKDIR/server-file.out" 2>"$WORKDIR/server-file.err"; then
  fail "server file uninstall: $(cat "$WORKDIR/server-file.err")"
fi
assert_no_bash_source_error "$WORKDIR/server-file.err"
[[ ! -f "$TREE/usr/local/bin/drlink" ]] || fail "server file uninstall left drlink"
[[ ! -e "$TREE/usr/local/lib/drlink" ]] || fail "server file uninstall left library tree"
pass "SERVER_FILE_EXECUTION"

# --- server: stdin execution ---
TREE="$WORKDIR/server-stdin"
UNIT="$WORKDIR/units-server-stdin"
seed_server "$TREE"
mkdir -p "$UNIT"
: >"$UNIT/drlink-server.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
# Run from a directory that must NOT be treated as the script dir.
cd "$WORKDIR"
if ! cat "$ROOT/dist/uninstall-server.sh" | bash -s -- --purge --yes \
  >"$WORKDIR/server-stdin.out" 2>"$WORKDIR/server-stdin.err"; then
  fail "server stdin uninstall: $(cat "$WORKDIR/server-stdin.err")"
fi
assert_no_bash_source_error "$WORKDIR/server-stdin.err"
grep -q 'BASH_SOURCE\[0\]: unbound variable' "$WORKDIR/server-stdin.err" && \
  fail "server stdin still hits BASH_SOURCE unbound"
[[ ! -f "$TREE/etc/frp/server_token" ]] || fail "server stdin purge left token"
[[ ! -e "$TREE/usr/local/lib/drlink" ]] || fail "server stdin purge left library tree"
pass "SERVER_STDIN_EXECUTION"

# --- client: file execution ---
TREE="$WORKDIR/client-file"
UNIT="$WORKDIR/units-client-file"
seed_client "$TREE"
mkdir -p "$UNIT"
: >"$UNIT/drlink-client.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
if ! "$ROOT/dist/uninstall-client.sh" \
  >"$WORKDIR/client-file.out" 2>"$WORKDIR/client-file.err"; then
  fail "client file uninstall: $(cat "$WORKDIR/client-file.err")"
fi
assert_no_bash_source_error "$WORKDIR/client-file.err"
[[ ! -f "$TREE/etc/frp/client-state.json" ]] || fail "client file left state"
[[ ! -e "$TREE/usr/local/lib/drlink" ]] || fail "client file left library tree"
[[ ! -e "$TREE/etc/frp" ]] || fail "client file left /etc/frp"
pass "CLIENT_FILE_EXECUTION"

# --- client: stdin execution ---
TREE="$WORKDIR/client-stdin"
UNIT="$WORKDIR/units-client-stdin"
seed_client "$TREE"
mkdir -p "$UNIT"
: >"$UNIT/drlink-client.loaded"
export FRP_UNINSTALL_TEST_ROOT="$TREE"
export FRP_MOCK_UNIT_DIR="$UNIT"
cd "$WORKDIR"
if ! cat "$ROOT/dist/uninstall-client.sh" | bash -s -- \
  >"$WORKDIR/client-stdin.out" 2>"$WORKDIR/client-stdin.err"; then
  fail "client stdin uninstall: $(cat "$WORKDIR/client-stdin.err")"
fi
assert_no_bash_source_error "$WORKDIR/client-stdin.err"
[[ ! -f "$TREE/usr/local/bin/frp-client" ]] || fail "client stdin left frp-client"
pass "CLIENT_STDIN_EXECUTION"

echo "STDIN_EXECUTION_REACHES_REAL_UNINSTALL_LOGIC=YES"
echo "NO_REAL_HOST_DELETION=YES"
echo "UNINSTALL_STDIN_EXECUTION_TEST=PASS"
