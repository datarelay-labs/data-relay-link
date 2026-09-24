#!/usr/bin/env bash
# Linux Agent install and product update must install, enable, and restart
# drlink-ai-agent.service without restarting frpc.
set -euo pipefail

unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT \
  FRP_CLIENT_SOURCED FRP_CLIENT_UPGRADE FRP_CLIENT_UPDATE_SOURCE \
  FRP_CLIENT_UPDATE_CHECK FRP_SKIP_SYSTEMD FRP_SYSTEMCTL_BIN || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

grep -q 'frp_client_converge_ai_agent_unit' "$ROOT/install-client.sh" || fail "install path missing AI agent converge"
grep -q 'systemctl enable drlink-client' "$ROOT/install-client.sh" || fail "client unit enable missing"
pass "INSTALL_CALLS_AI_AGENT_CONVERGE"

MOCK="$WORKDIR/systemctl"
LOG="$WORKDIR/systemctl.log"
cat >"$MOCK" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$LOG"
exit 0
EOF
chmod 0755 "$MOCK"

install_tree() {
  local tree="$1"
  mkdir -p "$tree/etc/frp" "$tree/etc/drlink" "$tree/usr/local/bin" "$tree/usr/local/lib/drlink"
  cat >"$tree/usr/local/bin/frpc" <<'EOF'
#!/bin/sh
if [ "$1" = verify ]; then exit 0; fi
if [ "$1" = --version ]; then echo "frpc version 0.71.0"; exit 0; fi
exit 0
EOF
  chmod 0755 "$tree/usr/local/bin/frpc"
  printf '#!/bin/sh\necho old-client\n' >"$tree/usr/local/bin/frp-client"
  chmod 0755 "$tree/usr/local/bin/frp-client"
  echo old >"$tree/usr/local/lib/drlink/frp-client-common.sh"
  echo old >"$tree/usr/local/lib/drlink/frp_mgmt_auth.py"
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://203.0.113.10:6099/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "ai-agent-lifecycle",
    "machine_id": "aabbccddeeff00112233445566778899",
    "host_id": "ai-agent-aabbccdd",
    "services": {"ssh": {"id": "ssh", "remote_port": 6003, "enabled": True, "local_ip": "127.0.0.1", "local_port": 22}},
}, indent=2) + "\n")
PY
  chmod 600 "$tree/etc/frp/client-state.json"
  cat >"$tree/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"
EOF
  chmod 600 "$tree/etc/frp/frpc.toml"
  echo access >"$tree/etc/frp/access-info.txt"
  echo ca >"$tree/etc/drlink/allocator-ca.crt"
  python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
    "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
  chmod 600 "$tree/etc/frp/client-identity.key"
  printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"$tree/etc/frp/client-identity.mac"
  chmod 600 "$tree/etc/frp/client-identity.mac"
  cat >"$tree/etc/drlink/version" <<'EOF'
PROJECT_VERSION=1.7.0
FRP_VERSION=0.71.0
EOF
}

INSTALL="$WORKDIR/install-root"
: >"$LOG"
(
  export FRP_CLIENT_TEST_ROOT="$INSTALL"
  export FRP_SYSTEMCTL_BIN="$MOCK"
  # shellcheck disable=SC1091
  . "$ROOT/lib/frp-client-common.sh"
  frp_client_converge_ai_agent_unit "$ROOT"
)
[[ -f "$INSTALL/etc/systemd/system/drlink-ai-agent.service" ]] || fail "install did not write unit"
grep -q 'drlink_ai_agent.py' "$INSTALL/etc/systemd/system/drlink-ai-agent.service" || fail "install unit exec"
grep -qx 'enable drlink-ai-agent' "$LOG" || fail "install enable"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "install restart"
if grep -q 'drlink-client' "$LOG"; then fail "install restarted frpc via AI converge"; fi
pass "INSTALL_ENABLES_AND_RESTARTS_AI_AGENT"

TREE="$WORKDIR/update-root"
install_tree "$TREE"
STATE_BEFORE="$(python3 - "$TREE/etc/frp/client-state.json" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
: >"$LOG"
export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_SYSTEMCTL_BIN="$MOCK"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
if ! "$ROOT/tools/frp-client" update --source "$ROOT" >"$WORKDIR/update.out" 2>"$WORKDIR/update.err"; then
  cat "$WORKDIR/update.out" "$WORKDIR/update.err" >&2
  fail "product update"
fi
grep -q 'frpc restarted  : NO' "$WORKDIR/update.out" || fail "frpc restart contract"
grep -q 'AI agent service : converged' "$WORKDIR/update.out" || fail "update converge line"
[[ -f "$TREE/etc/systemd/system/drlink-ai-agent.service" ]] || fail "update did not install unit"
grep -q 'drlink_ai_agent.py' "$TREE/etc/systemd/system/drlink-ai-agent.service" || fail "update unit exec"
grep -qx 'enable drlink-ai-agent' "$LOG" || fail "update enable"
grep -qx 'restart drlink-ai-agent' "$LOG" || fail "update restart"
if grep -q 'drlink-client' "$LOG"; then fail "update restarted frpc"; fi
STATE_AFTER="$(python3 - "$TREE/etc/frp/client-state.json" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
[[ "$STATE_BEFORE" == "$STATE_AFTER" ]] || fail "update changed client state"
pass "PRODUCT_UPDATE_CONVERGES_AI_AGENT_WITHOUT_FRPC_RESTART"
