#!/usr/bin/env bash
# Installer wiring: wait_for_proxies success is the only path that passes
# runtime_verified=True into activate_enrolled_services_as_remote_services.
# The flag is a command-scoped environment value, not a leaked shell export.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

mkdir -p "$WORK/bin"
cat >"$WORK/bin/python3" <<'EOF'
#!/usr/bin/env bash
# Record only the enrolled-activation program. Other installer python stays real.
if [[ "${1:-}" == "-c" ]]; then
  printf '%s\n' "${FRP_ENROLLED_PROXIES_VERIFIED-UNSET}" >"${DRLINK_VERIFY_CAPTURE:?}/env"
  printf '%s\n' "$*" >"${DRLINK_VERIFY_CAPTURE:?}/args"
  exit 0
fi
exec /usr/bin/python3 "$@"
EOF
chmod 0755 "$WORK/bin/python3"

export DRLINK_VERIFY_CAPTURE="$WORK"
export PATH="$WORK/bin:${PATH}"
unset FRP_ENROLLED_PROXIES_VERIFIED FRP_CLIENT_TEST_ROOT FRP_SKIP_SYSTEMD || true

# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"

if grep -nE '^[[:space:]]*export[[:space:]]+FRP_ENROLLED_PROXIES_VERIFIED([[:space:]]|$)' \
  "$ROOT/install-client.sh"; then
  fail "installer still exports FRP_ENROLLED_PROXIES_VERIFIED into the shell"
fi
grep -q 'FRP_ENROLLED_PROXIES_VERIFIED="$verified" python3' "$ROOT/install-client.sh" \
  || fail "activation does not pass the flag as a scoped python3 environment"

# Order comes from the sourced function, not a brace parse of the file.
# test-zero-touch-bootstrap.sh and test-frp-client.sh set FRP_CLIENT_TEST_ROOT
# and/or FRP_SKIP_SYSTEMD, so they never enter this verified branch.
main_def="$(declare -f frp_client_main)"
[[ -n "$main_def" ]] || fail "frp_client_main was not defined after sourcing"
if declare -f frp_client_apply_enrolled_runtime_evidence >/dev/null 2>&1; then
  fail "test-only frp_client_apply_enrolled_runtime_evidence is still defined"
fi

first_line_with() {
  local needle="$1"
  local n=0
  local line
  while IFS= read -r line; do
    n=$((n + 1))
    if [[ "$line" == *"$needle"* ]]; then
      printf '%s\n' "$n"
      return 0
    fi
  done <<<"$main_def"
  return 1
}

reset_line="$(first_line_with 'FRP_ENROLLED_PROXIES_VERIFIED=0')" \
  || fail "frp_client_main does not reset FRP_ENROLLED_PROXIES_VERIFIED=0"
note_line="$(first_line_with 'frp_client_note_enrolled_proxies_verified')" \
  || fail "frp_client_main does not call frp_client_note_enrolled_proxies_verified"
activate_line="$(first_line_with 'frp_client_activate_enrolled_services')" \
  || fail "frp_client_main does not call frp_client_activate_enrolled_services"
unset_line="$(first_line_with 'unset FRP_ENROLLED_PROXIES_VERIFIED')" \
  || fail "frp_client_main does not unset FRP_ENROLLED_PROXIES_VERIFIED"
first_flag_line="$(first_line_with 'FRP_ENROLLED_PROXIES_VERIFIED')" \
  || fail "frp_client_main does not mention FRP_ENROLLED_PROXIES_VERIFIED"
[[ "$first_flag_line" == "$reset_line" ]] \
  || fail "frp_client_main uses the flag before resetting it (line $first_flag_line)"
[[ "$reset_line" -lt "$note_line" && "$note_line" -lt "$activate_line" && "$activate_line" -lt "$unset_line" ]] \
  || fail "frp_client_main order reset=$reset_line note=$note_line activate=$activate_line unset=$unset_line"
activate_text="$(sed -n "${activate_line}p" <<<"$main_def")"
[[ "$activate_text" == *'${FRP_ENROLLED_PROXIES_VERIFIED:-0}'* ]] \
  || fail "frp_client_main activate call does not pass the reset flag: $activate_text"
pass "MAIN_RESETS_NOTES_ACTIVATES_UNSETS_IN_ORDER"

assert_python_flag() {
  local expected="$1"
  local label="$2"
  [[ "$(cat "$WORK/env")" == "$expected" ]] || fail "$label: python saw $(cat "$WORK/env"), want $expected"
  grep -q 'runtime_verified=verified' "$WORK/args" || fail "$label: runtime_verified was not passed"
  grep -q 'activate_enrolled_services_as_remote_services' "$WORK/args" \
    || fail "$label: activator was not invoked"
}

assert_flag_not_exported() {
  local label="$1"
  local parent
  parent="$(/usr/bin/python3 -c 'import os; print(os.environ.get("FRP_ENROLLED_PROXIES_VERIFIED", "UNSET"))')"
  [[ "$parent" == "UNSET" ]] || fail "$label: flag leaked into the parent environment"
}

unset FRP_CLIENT_TEST_ROOT FRP_SKIP_SYSTEMD FRP_ENROLLED_PROXIES_VERIFIED || true
wait_for_proxies() { return 0; }
frp_client_note_enrolled_proxies_verified host-ssh
[[ "${FRP_ENROLLED_PROXIES_VERIFIED:-}" == "1" ]] \
  || fail "wait_for_proxies success did not record verification"
frp_client_activate_enrolled_services "${FRP_ENROLLED_PROXIES_VERIFIED:-0}"
assert_python_flag 1 "verified helpers"
unset FRP_ENROLLED_PROXIES_VERIFIED
assert_flag_not_exported "verified helpers"
pass "WAIT_SUCCESS_PASSES_RUNTIME_VERIFIED_TRUE"

export FRP_CLIENT_TEST_ROOT="$WORK/client-root"
frp_client_activate_enrolled_services 1
assert_python_flag 0 "FRP_CLIENT_TEST_ROOT"
unset FRP_CLIENT_TEST_ROOT
assert_flag_not_exported "FRP_CLIENT_TEST_ROOT"
pass "TEST_ROOT_PASSES_RUNTIME_VERIFIED_FALSE"

export FRP_SKIP_SYSTEMD=1
frp_client_activate_enrolled_services 1
assert_python_flag 0 "FRP_SKIP_SYSTEMD"
unset FRP_SKIP_SYSTEMD
assert_flag_not_exported "FRP_SKIP_SYSTEMD"
pass "SKIP_SYSTEMD_PASSES_RUNTIME_VERIFIED_FALSE"

export FRP_ENROLLED_PROXIES_VERIFIED=1
frp_client_activate_enrolled_services 0
assert_python_flag 0 "backfill"
unset FRP_ENROLLED_PROXIES_VERIFIED
assert_flag_not_exported "backfill"
pass "BACKFILL_PASSES_RUNTIME_VERIFIED_FALSE"

export FRP_ENROLLED_PROXIES_VERIFIED=1
wait_for_proxies() { return 1; }
if frp_client_note_enrolled_proxies_verified host-ssh; then
  fail "failed wait_for_proxies was treated as verified"
fi
[[ "${FRP_ENROLLED_PROXIES_VERIFIED:-}" == "0" ]] \
  || fail "failed wait_for_proxies left the verification flag set"
unset FRP_ENROLLED_PROXIES_VERIFIED
pass "WAIT_FAILURE_DOES_NOT_VERIFY"
