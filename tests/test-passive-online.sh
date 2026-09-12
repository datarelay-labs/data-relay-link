#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR/bin"
cat >"$WORKDIR/bin/ss" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'LISTEN 0 4096 0.0.0.0:6002 0.0.0.0:*'
SH
chmod +x "$WORKDIR/bin/ss"

PATH="$WORKDIR/bin:$PATH" python3 - "$ROOT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'lib'))
import frp_client_registry as creg

snapshot = creg.passive_listening_ports()
assert snapshot == ({6002}, True), snapshot
assert creg.passive_port_state(6002, snapshot) == 'online'
assert creg.passive_port_state(6003, snapshot) == 'offline'
assert creg.passive_port_state(6002, (set(), False)) == 'unknown'
PY

if ! command -v grep >/dev/null 2>&1; then
  echo "FAIL: grep is required for this test" >&2
  exit 1
fi
if grep -nE 'connect_ex' \
  "$ROOT/tools/frp-clients" "$ROOT/tools/frp-release-client" \
  "$ROOT/tools/frp-release-service" "$ROOT/lib/frp-common.sh" \
  "$ROOT/lib/frp-doctor-common.sh" >/dev/null; then
  echo "FAIL active application socket probe remains" >&2
  exit 1
fi

echo "PASSIVE_ONLINE_TEST=PASS"
