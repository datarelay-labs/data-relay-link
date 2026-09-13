#!/usr/bin/env bash
# frpctl on macOS must find grammar/repl modules in the Application Support lib,
# not only next to /usr/local/bin (where ../lib does not exist).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Isolate from leaked harness env left by sibling tests / interactive shells.
unset FRP_CTL_TEST_ROOT FRP_CLIENT_TEST_ROOT FRP_DEPLOY_TEST_ROOT \
  FRP_UPDATE_ROOT FRP_CTL_TEST_INPUT FRP_CTL_DRY_RUN || true

export FRP_TEST_UNAME_S=Darwin
export FRP_TEST_UNAME_M=arm64
export FRP_MACOS_STATE_ROOT="$TMP/state"
export FRP_MACOS_PREFIX="$TMP/prefix"

mkdir -p "$TMP/prefix/bin" "$TMP/prefix/lib" "$TMP/state/lib"
install -m 0755 "$ROOT/tools/frpctl" "$TMP/prefix/bin/frpctl"
install -m 0644 "$ROOT/lib/frp-doctor-common.sh" "$TMP/prefix/lib/frp-doctor-common.sh"
install -m 0644 "$ROOT/lib/frp-common.sh" "$TMP/prefix/lib/frp-common.sh"
install -m 0644 "$ROOT/lib/frp-macos.sh" "$TMP/prefix/lib/frp-macos.sh"
# Grammar lives only in the macOS state lib, matching a real install.
install -m 0644 "$ROOT/lib/frp_ctl_grammar.py" "$TMP/state/lib/frp_ctl_grammar.py"
install -m 0644 "$ROOT/lib/frp_cli_catalog.py" "$TMP/state/lib/frp_cli_catalog.py"
install -m 0644 "$ROOT/lib/frp_ctl_repl.py" "$TMP/state/lib/frp_ctl_repl.py"

# Client marker so role detection is client, not unknown.
python3 - "$TMP/state/client-state.json" <<'PY'
from pathlib import Path
import json, sys
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "machine_id": "aabbccddeeff00112233445566778899",
    "services": {},
}) + "\n", encoding="utf-8")
PY

out="$("$TMP/prefix/bin/frpctl" help 2>&1)" || {
  printf '%s\n' "$out" >&2
  echo "FAIL: frpctl help exited nonzero on Darwin layout" >&2
  exit 1
}
printf '%s\n' "$out" | grep -Eq 'Grammar: <resource> <action>|status[[:space:]]+Host status' || {
  printf '%s\n' "$out" >&2
  echo "FAIL: frpctl help missing grammar text" >&2
  exit 1
}
if printf '%s\n' "$out" | grep -q 'missing frp_ctl_grammar.py'; then
  echo "FAIL: grammar still unresolved" >&2
  exit 1
fi
echo "MACOS_FRPCTL_MODULES_TEST=PASS"
