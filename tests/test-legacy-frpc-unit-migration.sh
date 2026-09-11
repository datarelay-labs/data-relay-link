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
# Ensure binary restore follows the first retire call site in the main path.
python3 - "$ROOT/install-client.sh" <<'PY' || fail "install order"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
retire = text.find("frp_retire_legacy_client_unit")
binary = text.find('frp_atomic_install "$extracted" "$(frp_client_path /usr/local/bin/frpc)"')
if retire < 0 or binary < 0 or retire > binary:
    raise SystemExit("retire must precede frpc binary restore")
print("ORDER_OK")
PY
pass "INSTALL_RETIRE_BEFORE_BINARY"

echo "LEGACY_FRPC_UNIT_MIGRATION_TEST=PASS"
