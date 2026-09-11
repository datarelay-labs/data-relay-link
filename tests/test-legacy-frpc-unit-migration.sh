#!/usr/bin/env bash
# E2E-001 regression: product-owned frpc.service must retire to a single
# canonical drlink-client.service supervisor; unrelated admin units survive.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

write_product_legacy_unit() {
  local dest="$1"
  local desc="${2:-FRP Client}"
  cat >"$dest" <<EOF
[Unit]
Description=${desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

write_canonical_unit() {
  local dest="$1"
  cat >"$dest" <<'EOF'
[Unit]
Description=Data Relay Link Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

write_admin_unit() {
  local dest="$1"
  cat >"$dest" <<'EOF'
[Unit]
Description=Admin Managed FRP
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/frpc -c /etc/admin/frpc.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
}

# Ownership fingerprints
PROD="$WORK/prod.service"
write_product_legacy_unit "$PROD" "FRP Client"
frp_legacy_client_unit_is_product_owned "$PROD" || fail "historical FRP Client not owned"
write_product_legacy_unit "$PROD" "Data Relay Link Client (legacy unit name; use drlink-client)"
frp_legacy_client_unit_is_product_owned "$PROD" || fail "renamed legacy text not owned"
write_admin_unit "$PROD"
frp_legacy_client_unit_is_product_owned "$PROD" && fail "admin unit incorrectly owned"
pass "OWNERSHIP_FINGERPRINTS"

# State A — old-only: frpc.service exists, drlink-client absent
A="$WORK/state-a"
mkdir -p "$A/etc/systemd/system" "$A/etc/frp" "$A/usr/local/bin"
write_product_legacy_unit "$A/etc/systemd/system/frpc.service"
printf '{}\n' >"$A/etc/frp/client-state.json"
printf '#!/bin/bash\necho ok\n' >"$A/usr/local/bin/drlink"
chmod 0755 "$A/usr/local/bin/drlink"
FRP_SERVER_SOURCE="$ROOT" FRP_CLIENT_TEST_ROOT="$A" frp_migrate_legacy_systemd_units || fail "state A migrate"
[[ -f "$A/etc/systemd/system/drlink-client.service" ]] || fail "state A canonical missing"
[[ ! -f "$A/etc/systemd/system/frpc.service" ]] || fail "state A legacy remains"
pass "STATE_A_OLD_ONLY"

# State B — both units installed; retire leaves canonical
B="$WORK/state-b"
mkdir -p "$B/etc/systemd/system"
write_product_legacy_unit "$B/etc/systemd/system/frpc.service"
write_canonical_unit "$B/etc/systemd/system/drlink-client.service"
FRP_CLIENT_TEST_ROOT="$B" frp_retire_legacy_client_unit || fail "state B retire"
[[ -f "$B/etc/systemd/system/drlink-client.service" ]] || fail "state B canonical missing"
[[ ! -f "$B/etc/systemd/system/frpc.service" ]] || fail "state B legacy remains"
pass "STATE_B_BOTH_UNITS"

# State C — both enabled/active coexistence (file-level equivalent of E2E-001)
C="$WORK/state-c"
mkdir -p "$C/etc/systemd/system"
write_product_legacy_unit "$C/etc/systemd/system/frpc.service"
write_canonical_unit "$C/etc/systemd/system/drlink-client.service"
FRP_CLIENT_TEST_ROOT="$C" frp_retire_legacy_client_unit || fail "state C retire"
[[ -f "$C/etc/systemd/system/drlink-client.service" ]] || fail "state C canonical missing"
[[ ! -f "$C/etc/systemd/system/frpc.service" ]] || fail "state C legacy remains"
# Idempotent second pass
FRP_CLIENT_TEST_ROOT="$C" frp_retire_legacy_client_unit || fail "state C retire2"
[[ -f "$C/etc/systemd/system/drlink-client.service" ]] || fail "state C canonical after idempotent"
pass "STATE_C_COEXISTENCE_REPAIR"

# State D — canonical-only unaffected
D="$WORK/state-d"
mkdir -p "$D/etc/systemd/system"
write_canonical_unit "$D/etc/systemd/system/drlink-client.service"
FRP_CLIENT_TEST_ROOT="$D" frp_retire_legacy_client_unit || fail "state D retire"
[[ -f "$D/etc/systemd/system/drlink-client.service" ]] || fail "state D canonical removed"
[[ ! -e "$D/etc/systemd/system/frpc.service" ]] || fail "state D invented legacy"
pass "STATE_D_CANONICAL_ONLY"

# State E — unrelated administrator frpc.service preserved
E="$WORK/state-e"
mkdir -p "$E/etc/systemd/system"
write_admin_unit "$E/etc/systemd/system/frpc.service"
write_canonical_unit "$E/etc/systemd/system/drlink-client.service"
FRP_CLIENT_TEST_ROOT="$E" frp_retire_legacy_client_unit || fail "state E retire"
[[ -f "$E/etc/systemd/system/frpc.service" ]] || fail "state E admin unit removed"
[[ -f "$E/etc/systemd/system/drlink-client.service" ]] || fail "state E canonical missing"
pass "STATE_E_ADMIN_PRESERVED"

# Uninstall removes product-owned legacy unit, preserves admin unit
U="$WORK/uninstall"
mkdir -p "$U/etc/systemd/system" "$U/usr/local/bin" "$U/etc/frp"
write_product_legacy_unit "$U/etc/systemd/system/frpc.service"
write_canonical_unit "$U/etc/systemd/system/drlink-client.service"
printf 'bin\n' >"$U/usr/local/bin/frpc"
printf '{"schema_version":1}\n' >"$U/etc/frp/client-state.json"
export FRP_UNINSTALL_TEST_ROOT="$U"
export FRP_UNINSTALL_HOOK_SKIP_SYSTEMD=1
"$ROOT/uninstall-client.sh" >"$WORK/un.out" 2>"$WORK/un.err" || {
  cat "$WORK/un.out" "$WORK/un.err" >&2
  fail "uninstall product legacy"
}
[[ ! -e "$U/etc/systemd/system/frpc.service" ]] || fail "uninstall left product frpc.service"
[[ ! -e "$U/etc/systemd/system/drlink-client.service" ]] || fail "uninstall left drlink-client.service"
[[ ! -e "$U/usr/local/bin/frpc" ]] || fail "uninstall left frpc binary"
pass "UNINSTALL_PRODUCT_LEGACY"

UA="$WORK/uninstall-admin"
mkdir -p "$UA/etc/systemd/system" "$UA/usr/local/bin" "$UA/etc/frp"
write_admin_unit "$UA/etc/systemd/system/frpc.service"
write_canonical_unit "$UA/etc/systemd/system/drlink-client.service"
printf 'bin\n' >"$UA/usr/local/bin/frpc"
printf '{"schema_version":1}\n' >"$UA/etc/frp/client-state.json"
export FRP_UNINSTALL_TEST_ROOT="$UA"
"$ROOT/uninstall-client.sh" >"$WORK/una.out" 2>"$WORK/una.err" || fail "uninstall with admin"
[[ -f "$UA/etc/systemd/system/frpc.service" ]] || fail "uninstall removed admin frpc.service"
[[ ! -e "$UA/etc/systemd/system/drlink-client.service" ]] || fail "uninstall left canonical"
grep -q 'non-product frpc.service' "$WORK/una.err" || fail "missing admin warn"
pass "UNINSTALL_ADMIN_PRESERVED"

# Install-time retire before binary restore (file-level contract)
I="$WORK/install-retire"
mkdir -p "$I/etc/systemd/system"
write_product_legacy_unit "$I/etc/systemd/system/frpc.service"
write_canonical_unit "$I/etc/systemd/system/drlink-client.service"
FRP_CLIENT_TEST_ROOT="$I" frp_retire_legacy_client_unit || fail "install retire"
[[ ! -f "$I/etc/systemd/system/frpc.service" ]] || fail "install-time legacy remains"
[[ -f "$I/etc/systemd/system/drlink-client.service" ]] || fail "install-time canonical missing"
pass "INSTALL_TIME_RETIRE"

# Source contract: install retires legacy before starting the canonical unit.
grep -q 'frp_retire_legacy_client_unit' "$ROOT/install-client.sh" || fail "install missing retire"
grep -n 'frp_retire_legacy_client_unit' "$ROOT/install-client.sh" | head -1 | grep -q . || fail "install retire site"
# Fail-closed: retire failures must not be swallowed with || true before canonical start.
if grep -nE 'frp_retire_legacy_client_unit[[:space:]]*\|\|[[:space:]]*true' \
  "$ROOT/install-client.sh" "$ROOT/lib/frp-client-common.sh" >/dev/null; then
  fail "retire failures must not be swallowed with || true"
fi
# Ensure binary restore follows the first retire call site in the main path.
python3 - "$ROOT/install-client.sh" <<'PY' || fail "install order"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
retire = text.find("frp_retire_legacy_client_unit")
binary = text.find('frp_atomic_install "$extracted" "$(frp_client_path /usr/local/bin/frpc)"')
if retire < 0 or binary < 0 or retire > binary:
    raise SystemExit("retire must precede frpc binary restore")
# Canonical start must follow a hard fail path (|| return 1 / || exit 1), not || true.
for needle in (
    "frp_retire_legacy_client_unit || return 1",
    "frp_retire_legacy_client_unit || exit 1",
):
    if needle not in text:
        raise SystemExit(f"missing fail-closed retire site: {needle}")
print("ORDER_OK")
PY
pass "INSTALL_RETIRE_BEFORE_BINARY"

# ---------------------------------------------------------------------------
# Fail-closed retirement with mocked systemctl (P1 lifecycle hardening)
# ---------------------------------------------------------------------------
MOCK="$WORK/mock-systemctl"
cat >"$MOCK" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
log="${FRP_MOCK_SYSTEMCTL_LOG:-}"
if [[ -n "$log" ]]; then
  printf '%s\n' "$*" >>"$log"
fi
cmd="${1:-}"
shift || true
unit=""
for arg in "$@"; do
  case "$arg" in
    -p|--value|MainPID|LoadState) continue ;;
    *.service|frpc|drlink-client) unit="$arg" ;;
  esac
done
[[ "$unit" == *.service ]] || unit="${unit}.service"
state_dir="${FRP_MOCK_UNIT_DIR:-}"
fail_stop="${FRP_MOCK_STOP_FAIL:-0}"
still_active="${FRP_MOCK_STILL_ACTIVE:-0}"
keep_mainpid="${FRP_MOCK_KEEP_MAINPID:-0}"
case "$cmd" in
  is-active)
    if [[ -f "${state_dir}/${unit}.active" ]]; then
      echo active
      exit 0
    fi
    echo inactive
    exit 3
    ;;
  show)
    if [[ "$*" == *MainPID* ]]; then
      if [[ -f "${state_dir}/${unit}.mainpid" ]]; then
        cat "${state_dir}/${unit}.mainpid"
      else
        echo 0
      fi
      exit 0
    fi
    echo loaded
    exit 0
    ;;
  stop)
    if [[ "$fail_stop" == "1" ]]; then
      exit 1
    fi
    if [[ "$still_active" != "1" && -n "$state_dir" ]]; then
      rm -f "${state_dir}/${unit}.active"
      : >"${state_dir}/${unit}.loaded"
    fi
    if [[ "$keep_mainpid" != "1" && -n "$state_dir" ]]; then
      rm -f "${state_dir}/${unit}.mainpid"
    fi
    exit 0
    ;;
  disable)
    rm -f "${state_dir}/${unit}.enabled" 2>/dev/null || true
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
  enable|restart)
    # Canonical supervisor start — must not run when legacy retire fails.
    printf 'canonical-start:%s\n' "$*" >>"${FRP_MOCK_CANONICAL_START_LOG:-/dev/null}"
    : >"${state_dir:-/tmp}/${unit}.active"
    exit 0
    ;;
  daemon-reload|reset-failed)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
chmod +x "$MOCK"

owns_hook_yes() { return 0; }
owns_hook_no() { return 1; }

# Simulate the install gate: retire must succeed before canonical start is attempted.
simulate_install_start_gate() {
  local tree="$1" start_log="$2"
  : >"$start_log"
  export FRP_CLIENT_TEST_ROOT="$tree"
  export FRP_LEGACY_RETIRE_HOOK_SYSTEMCTL="$MOCK"
  export FRP_MOCK_CANONICAL_START_LOG="$start_log"
  if ! frp_retire_legacy_client_unit; then
    return 1
  fi
  # Only reached when retirement succeeded — mirrors frp_client_service_start.
  frp_legacy_retire_systemctl enable drlink-client >/dev/null
  frp_legacy_retire_systemctl restart drlink-client >/dev/null
  return 0
}

# 1. active product-owned legacy unit → stop succeeds → migration PASS
FC1="$WORK/fc-stop-ok"
mkdir -p "$FC1/etc/systemd/system"
write_product_legacy_unit "$FC1/etc/systemd/system/frpc.service"
write_canonical_unit "$FC1/etc/systemd/system/drlink-client.service"
UNIT1="$WORK/units-fc1"
mkdir -p "$UNIT1"
: >"$UNIT1/frpc.service.active"
: >"$UNIT1/frpc.service.loaded"
: >"$UNIT1/frpc.service.enabled"
printf '4242\n' >"$UNIT1/frpc.service.mainpid"
export FRP_MOCK_UNIT_DIR="$UNIT1"
export FRP_MOCK_SYSTEMCTL_LOG="$WORK/fc1.log"
export FRP_MOCK_STOP_FAIL=0
export FRP_MOCK_STILL_ACTIVE=0
export FRP_MOCK_KEEP_MAINPID=0
unset FRP_LEGACY_RETIRE_HOOK_OWNS_FRPC || true
START1="$WORK/fc1.start"
if ! simulate_install_start_gate "$FC1" "$START1"; then
  fail "active stop-success retire failed"
fi
[[ ! -f "$FC1/etc/systemd/system/frpc.service" ]] || fail "fc1 legacy unit remains"
[[ -f "$FC1/etc/systemd/system/drlink-client.service" ]] || fail "fc1 canonical missing"
grep -q 'canonical-start:' "$START1" || fail "fc1 canonical start not reached"
pass "ACTIVE_STOP_SUCCESS"

# 2. active product-owned legacy unit → stop fails → install FAILS before canonical start
FC2="$WORK/fc-stop-fail"
mkdir -p "$FC2/etc/systemd/system"
write_product_legacy_unit "$FC2/etc/systemd/system/frpc.service"
write_canonical_unit "$FC2/etc/systemd/system/drlink-client.service"
UNIT2="$WORK/units-fc2"
mkdir -p "$UNIT2"
: >"$UNIT2/frpc.service.active"
: >"$UNIT2/frpc.service.loaded"
: >"$UNIT2/frpc.service.enabled"
printf '4243\n' >"$UNIT2/frpc.service.mainpid"
export FRP_MOCK_UNIT_DIR="$UNIT2"
export FRP_MOCK_SYSTEMCTL_LOG="$WORK/fc2.log"
export FRP_MOCK_STOP_FAIL=1
START2="$WORK/fc2.start"
if simulate_install_start_gate "$FC2" "$START2" 2>"$WORK/fc2.err"; then
  fail "stop-failure retire unexpectedly succeeded"
fi
grep -q 'LEGACY_UNIT_STOP_FAILED' "$WORK/fc2.err" || fail "fc2 missing stop failure class"
[[ -f "$FC2/etc/systemd/system/frpc.service" ]] || fail "fc2 legacy unit removed on stop failure"
if grep -q 'canonical-start:' "$START2" 2>/dev/null; then
  fail "fc2 canonical start must be blocked"
fi
pass "ACTIVE_STOP_FAILURE_BLOCKS_CANONICAL"
pass "CANONICAL_START_BLOCKED_ON_LEGACY_STOP_FAILURE"

# 3. stop returns success but legacy MainPID remains → install FAILS
FC3="$WORK/fc-mainpid"
mkdir -p "$FC3/etc/systemd/system"
write_product_legacy_unit "$FC3/etc/systemd/system/frpc.service"
write_canonical_unit "$FC3/etc/systemd/system/drlink-client.service"
UNIT3="$WORK/units-fc3"
mkdir -p "$UNIT3"
: >"$UNIT3/frpc.service.active"
: >"$UNIT3/frpc.service.loaded"
: >"$UNIT3/frpc.service.enabled"
printf '4244\n' >"$UNIT3/frpc.service.mainpid"
export FRP_MOCK_UNIT_DIR="$UNIT3"
export FRP_MOCK_SYSTEMCTL_LOG="$WORK/fc3.log"
export FRP_MOCK_STOP_FAIL=0
export FRP_MOCK_STILL_ACTIVE=0
export FRP_MOCK_KEEP_MAINPID=1
export FRP_LEGACY_RETIRE_HOOK_OWNS_FRPC=owns_hook_yes
START3="$WORK/fc3.start"
if simulate_install_start_gate "$FC3" "$START3" 2>"$WORK/fc3.err"; then
  fail "mainpid-remains retire unexpectedly succeeded"
fi
grep -q 'LEGACY_UNIT_PROCESS_REMAINS' "$WORK/fc3.err" || fail "fc3 missing process remains class"
[[ -f "$FC3/etc/systemd/system/frpc.service" ]] || fail "fc3 legacy unit removed while MainPID remains"
if grep -q 'canonical-start:' "$START3" 2>/dev/null; then
  fail "fc3 canonical start must be blocked"
fi
unset FRP_LEGACY_RETIRE_HOOK_OWNS_FRPC || true
pass "STOP_OK_MAINPID_REMAINS_BLOCKS_CANONICAL"

# 4. inactive product-owned unit → safe removal PASS
FC4="$WORK/fc-inactive"
mkdir -p "$FC4/etc/systemd/system"
write_product_legacy_unit "$FC4/etc/systemd/system/frpc.service"
write_canonical_unit "$FC4/etc/systemd/system/drlink-client.service"
UNIT4="$WORK/units-fc4"
mkdir -p "$UNIT4"
: >"$UNIT4/frpc.service.loaded"
: >"$UNIT4/frpc.service.enabled"
export FRP_MOCK_UNIT_DIR="$UNIT4"
export FRP_MOCK_SYSTEMCTL_LOG="$WORK/fc4.log"
export FRP_MOCK_STOP_FAIL=0
export FRP_MOCK_KEEP_MAINPID=0
export FRP_LEGACY_RETIRE_HOOK_OWNS_FRPC=owns_hook_no
START4="$WORK/fc4.start"
if ! simulate_install_start_gate "$FC4" "$START4"; then
  fail "inactive retire failed"
fi
[[ ! -f "$FC4/etc/systemd/system/frpc.service" ]] || fail "fc4 legacy remains"
grep -q 'canonical-start:' "$START4" || fail "fc4 canonical start missing"
# Idempotent second pass
export FRP_CLIENT_TEST_ROOT="$FC4"
export FRP_LEGACY_RETIRE_HOOK_SYSTEMCTL="$MOCK"
frp_retire_legacy_client_unit || fail "fc4 idempotent retire"
unset FRP_LEGACY_RETIRE_HOOK_OWNS_FRPC || true
pass "INACTIVE_SAFE_REMOVAL"

# 5. unrelated admin frpc.service → untouched PASS
FC5="$WORK/fc-admin"
mkdir -p "$FC5/etc/systemd/system"
write_admin_unit "$FC5/etc/systemd/system/frpc.service"
write_canonical_unit "$FC5/etc/systemd/system/drlink-client.service"
UNIT5="$WORK/units-fc5"
mkdir -p "$UNIT5"
: >"$UNIT5/frpc.service.active"
: >"$UNIT5/frpc.service.loaded"
: >"$UNIT5/frpc.service.enabled"
export FRP_MOCK_UNIT_DIR="$UNIT5"
export FRP_MOCK_SYSTEMCTL_LOG="$WORK/fc5.log"
: >"$WORK/fc5.log"
START5="$WORK/fc5.start"
if ! simulate_install_start_gate "$FC5" "$START5" 2>"$WORK/fc5.err"; then
  fail "admin preserve retire failed"
fi
[[ -f "$FC5/etc/systemd/system/frpc.service" ]] || fail "fc5 admin unit removed"
grep -q 'non-product frpc.service' "$WORK/fc5.err" || fail "fc5 missing admin warn"
# Must not stop/disable an unrelated admin unit.
if grep -E '^(stop|disable)( |$)' "$WORK/fc5.log" >/dev/null 2>&1; then
  fail "fc5 touched admin unit via systemctl"
fi
grep -q 'canonical-start:' "$START5" || fail "fc5 canonical start missing"
pass "UNRELATED_ADMIN_FRPC_SERVICE_PRESERVED"

pass "LEGACY_RETIRE_FAIL_CLOSED"
echo "LEGACY_FRPC_UNIT_MIGRATION_TEST=PASS"
