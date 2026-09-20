#!/usr/bin/env bash
# Create/refresh the pinned official MCP SDK venv used by Full Suite interop.
# Prints the interpreter path on stdout; progress on stderr.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQ="$ROOT/tests/requirements-mcp-sdk.txt"
VENV="${DRLINK_MCP_SDK_VENV:-$ROOT/.venv/mcp-sdk}"
PY="${DRLINK_MCP_SDK_BOOTSTRAP_PYTHON:-python3}"

if [[ ! -f "$REQ" ]]; then
  echo "ERROR: missing $REQ" >&2
  exit 2
fi

need_install=0
if [[ ! -x "$VENV/bin/python" ]]; then
  need_install=1
else
  if ! "$VENV/bin/python" -c 'import mcp, httpx2' >/dev/null 2>&1; then
    need_install=1
  else
    # Refresh when the pin file is newer than the venv marker / pyvenv.cfg.
    if [[ "$REQ" -nt "$VENV/pyvenv.cfg" ]]; then
      need_install=1
    fi
  fi
fi

if [[ "$need_install" -eq 1 ]]; then
  echo "Ensuring pinned MCP SDK venv at $VENV" >&2
  mkdir -p "$(dirname "$VENV")"
  rm -rf "$VENV"
  "$PY" -m venv "$VENV"
  # All pip progress must stay off stdout: callers capture the interpreter path
  # (and GitHub Actions GITHUB_ENV rejects multiline / progress noise).
  "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1
  "$VENV/bin/python" -m pip install -r "$REQ" >&2
  "$VENV/bin/python" -c 'import mcp, httpx2; print("MCP_SDK_IMPORT=PASS", mcp.__name__, httpx2.__name__)' >&2
fi

# Sole stdout line: absolute interpreter path.
printf '%s\n' "$VENV/bin/python"
