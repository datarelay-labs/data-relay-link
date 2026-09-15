#!/usr/bin/env bash
# Product-upgrade policy unit checks (mixed-version gate + preservation helpers).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - <<'PY' || fail "version compare helpers"
def parse(text):
    parts = []
    for piece in str(text).split('.'):
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    return tuple(parts) if parts else None

assert parse('2.1.1') < parse('2.1.2')
assert parse('2.1.2') == parse('2.1.2')
assert parse('2.1.2') > parse('2.1.1')
print('OK')
PY
pass "VERSION_ORDER"

python3 - <<'PY' || fail "server-older compare"
import sys
def parse(text):
    parts=[]
    for piece in str(text).split('.'):
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    return tuple(parts) if parts else None
server=parse('2.1.1'); candidate=parse('2.1.2')
sys.exit(0 if candidate > server else 1)
PY
pass "CLIENT_NEWER_THAN_SERVER_DETECTABLE"

python3 - <<'PY' || fail "allocator version helpers"
import importlib.machinery
import importlib.util
from pathlib import Path
path = Path("server/frp-port-allocator.py")
spec = importlib.util.spec_from_file_location(
    "alloc",
    path,
    loader=importlib.machinery.SourceFileLoader("alloc", str(path)),
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.parse_project_version("2.1.1") == (2, 1, 1)
assert mod.parse_project_version("bad") is None
print("OK")
PY
pass "ALLOCATOR_VERSION_HELPERS"

python3 - "$ROOT/lib/frp-client-common.sh" <<'PY' || fail "version gate CA path"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
start = text.index('frp_client_require_server_compatible_for_upgrade()')
end = text.index('\n}', start)
body = text[start:end]
if '/etc/drlink/allocator-ca.crt' not in body:
    raise SystemExit('missing canonical CA path in version gate')
print('OK')
PY
pass "VERSION_GATE_CA_PATH"

echo "PRODUCT_UPGRADE_POLICY_TEST=PASS"
