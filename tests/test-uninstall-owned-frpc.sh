#!/usr/bin/env bash
# Uninstall must not pkill -x frpc; unrelated frpc binaries must survive.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'kill "$UNRELATED_PID" 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

if grep -E 'pkill[[:space:]]+-x[[:space:]]+frpc' "$ROOT/uninstall-client.sh"; then
  echo "FAIL: uninstall-client.sh still uses blanket pkill -x frpc" >&2
  exit 1
fi

mkdir -p "$WORKDIR/unrelated" "$WORKDIR/tree/usr/local/bin"
cp /bin/sleep "$WORKDIR/unrelated/frpc"
chmod +x "$WORKDIR/unrelated/frpc"
"$WORKDIR/unrelated/frpc" 60 &
UNRELATED_PID=$!
sleep 0.2
kill -0 "$UNRELATED_PID"

export FRP_UNINSTALL_TEST_ROOT="$WORKDIR/tree"
export FRP_UNINSTALL_HOOK_SKIP_SYSTEMD=1
bash "$ROOT/uninstall-client.sh" >/dev/null

if ! kill -0 "$UNRELATED_PID" 2>/dev/null; then
  echo "FAIL: unrelated frpc process was killed" >&2
  exit 1
fi

echo "UNINSTALL_OWNED_FRPC_TEST=PASS"
