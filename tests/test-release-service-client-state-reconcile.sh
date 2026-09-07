#!/usr/bin/env bash
# Verify that released services are removed from client local state while
# disabled-but-still-reserved services are kept.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

TREE="$WORKDIR/client-root"
mkdir -p "$TREE/etc/frp" "$TREE/etc/frp-auto-deploy" "$TREE/usr/local/lib/frp-auto-deploy"
cp "$ROOT/lib/frp-client-common.sh" "$TREE/usr/local/lib/frp-auto-deploy/frp-client-common.sh"
cp "$ROOT/lib/frp-common.sh" "$TREE/usr/local/lib/frp-auto-deploy/frp-common.sh"
if [[ -f "$ROOT/lib/frp-macos.sh" ]]; then
  cp "$ROOT/lib/frp-macos.sh" "$TREE/usr/local/lib/frp-auto-deploy/frp-macos.sh"
fi

write_state() {
  local web_enabled="$1"
  python3 - "$TREE/etc/frp/client-state.json" "$web_enabled" <<'PY'
import json, sys
from pathlib import Path

dest = Path(sys.argv[1])
web_enabled = (sys.argv[2].lower() == "true")

state = {
  "schema_version": 1,
  "allocator_url": "https://127.0.0.1:9999/enroll",
  "frp_server": "203.0.113.10",
  "frp_server_port": 443,
  "hostname": "dp-example",
  "machine_id": "aabbccddeeff00112233445566778899",
  "host_id": "host-example",
  "services": {
    "ssh": {
      "id": "ssh",
      "name": "SSH",
      "protocol": "tcp",
      "local_ip": "127.0.0.1",
      "local_port": 22,
      "preset": "ssh",
      "ssh_user": "aella",
      "remote_port": 6000,
      "enabled": True,
    },
    "web": {
      "id": "web",
      "name": "Web",
      "protocol": "tcp",
      "local_ip": "127.0.0.1",
      "local_port": 18080,
      "preset": "http",
      "remote_port": 6001,
      "enabled": web_enabled,
    },
  },
}

dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

read_has_web() {
  python3 - "$TREE/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print("web" in (state.get("services") or {}))
PY
}

run_reconcile() {
  FRP_CLIENT_TEST_ROOT="$TREE" \
    FRP_CLIENT_LIB="$TREE/usr/local/lib/frp-auto-deploy/frp-client-common.sh" \
    FRP_CLIENT_RECONCILE_REGISTRY_IDS="$1" \
    bash -c 'source "$FRP_CLIENT_LIB"; frp_client_reconcile_released_services'
}

read_has_ssh() {
  python3 - "$TREE/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
print("ssh" in (state.get("services") or {}))
PY
}

echo "=== case: released on server => disabled web record removed ==="
write_state "false"
run_reconcile '["ssh"]'
[[ "$(read_has_web)" == "False" ]] || { echo "web record still present after release"; exit 1; }

echo "=== case: disabled but reserved on server => web record kept ==="
write_state "false"
run_reconcile '["ssh","web"]'
[[ "$(read_has_web)" == "True" ]] || { echo "web record removed unexpectedly after disable"; exit 1; }

echo "=== case: last enabled service force-released => enabled ssh record removed ==="
write_state "true"
run_reconcile '[]'
[[ "$(read_has_ssh)" == "False" ]] || { echo "enabled ssh still present after last-service release"; exit 1; }
[[ "$(read_has_web)" == "False" ]] || { echo "enabled web still present after last-service release"; exit 1; }

echo "=== case: enabled ssh still reserved => ssh record kept ==="
write_state "true"
run_reconcile '["ssh"]'
[[ "$(read_has_ssh)" == "True" ]] || { echo "enabled ssh removed while still reserved"; exit 1; }
[[ "$(read_has_web)" == "False" ]] || { echo "enabled web not dropped after server release"; exit 1; }

echo "PASS test-release-service-client-state-reconcile"
