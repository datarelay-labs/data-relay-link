#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORK/enrollment"
mkdir -p "$TREE/etc/frp-auto-deploy" "$TREE/var/lib/frp-auto-deploy/enrollments" "$TREE/var/lib/frp-auto-deploy/bootstrap"
python3 - "$TREE" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
(root / 'etc/frp-auto-deploy/config.json').write_text(json.dumps({
    'enrollments_dir': '/var/lib/frp-auto-deploy/enrollments',
    'bootstrap_dir': '/var/lib/frp-auto-deploy/bootstrap',
}) + '\n', encoding='utf-8')
(root / 'var/lib/frp-auto-deploy/enrollments/0011223344556677.json').write_text(json.dumps({
    'id': '0011223344556677',
    'secret': 'TEST_SECRET_SHOULD_NOT_APPEAR',
    'created_at': '2026-08-30T00:00:00Z\x1b[31m\r',
    'expires_at': 'not-an-epoch',
    'label': 'bad\x1b[31m\r\tlabel',
}) + '\n', encoding='utf-8')
PY
export FRP_DEPLOY_TEST_ROOT="$TREE"
python3 "$ROOT/tools/frp-enrollments" >"$WORK/enroll.out" 2>"$WORK/enroll.err" || fail "malformed enrollment crashed"
! grep -q 'Traceback' "$WORK/enroll.err" || fail "malformed enrollment traceback"
grep -E '^0011223344556677[[:space:]]+manual' "$WORK/enroll.out" | grep -q 'invalid' || fail "invalid expiry not reported"
! grep -Fq 'TEST_SECRET_SHOULD_NOT_APPEAR' "$WORK/enroll.out" || fail "enrollment secret leaked"
python3 - "$WORK/enroll.out" <<'PY'
import sys
from pathlib import Path
data = Path(sys.argv[1]).read_bytes()
bad = [b for b in data if (b < 32 and b != 10) or b == 127]
if bad:
    raise SystemExit('terminal control byte leaked: %r' % bad)
PY
pass MALFORMED_ENROLLMENT_SAFE
pass TERMINAL_CONTROL_CHAR_SAFE

CTLROOT="$WORK/client"
mkdir -p "$CTLROOT/etc/frp" "$CTLROOT/etc/frp-auto-deploy" "$CTLROOT/usr/local/bin"
printf '{"services":{}}\n' >"$CTLROOT/etc/frp/client-state.json"
printf 'PROJECT_VERSION=2.1.0\n' >"$CTLROOT/etc/frp-auto-deploy/version"
unset FRP_DEPLOY_TEST_ROOT
export FRP_CTL_TEST_ROOT="$CTLROOT"
"$ROOT/tools/frpctl" version >"$WORK/version-unknown.out"
grep -q '^FRP version     : legacy / unknown$' "$WORK/version-unknown.out" || fail "unknown version not truthful"
cat >"$CTLROOT/usr/local/bin/frpc" <<'EOF'
#!/usr/bin/env bash
printf 'v0.69.9\n'
EOF
chmod +x "$CTLROOT/usr/local/bin/frpc"
"$ROOT/tools/frpctl" version >"$WORK/version-binary.out"
grep -q '^FRP version     : 0.69.9$' "$WORK/version-binary.out" || fail "binary version fallback"
printf 'PROJECT_VERSION=2.1.0\nFRP_VERSION=0.71.0\n' >"$CTLROOT/etc/frp-auto-deploy/version"
printf '#!/usr/bin/env bash\nprintf "9.9.9\\n"\n' >"$CTLROOT/usr/local/bin/frpc"
chmod +x "$CTLROOT/usr/local/bin/frpc"
"$ROOT/tools/frpctl" version >"$WORK/version-meta.out"
grep -q '^FRP version     : 0.71.0$' "$WORK/version-meta.out" || fail "metadata precedence"
printf 'PROJECT_VERSION=2.1.0\n' >"$CTLROOT/etc/frp-auto-deploy/version"
printf '#!/usr/bin/env bash\nprintf "0.69.9\\033[31m\\n"\n' >"$CTLROOT/usr/local/bin/frpc"
chmod +x "$CTLROOT/usr/local/bin/frpc"
"$ROOT/tools/frpctl" version >"$WORK/version-unsafe.out"
grep -q '^FRP version     : legacy / unknown$' "$WORK/version-unsafe.out" || fail "unsafe version output trusted"
pass FRP_VERSION_METADATA_PRESERVED
pass FRP_VERSION_BINARY_FALLBACK
pass FRP_VERSION_UNKNOWN_TRUTHFUL

export FRP_CTL_GRAMMAR_PAYLOAD='{"role":"server","names":[],"clients":[],"services":{},"local_services":[],"inventory_warning":true}'
printf 'exit\n' | python3 "$ROOT/lib/frp_ctl_repl.py" --frpctl /bin/true \
  >"$WORK/inventory.out" 2>"$WORK/inventory.err" || fail "inventory-warning REPL failure"
unset FRP_CTL_GRAMMAR_PAYLOAD
[[ "$(grep -c 'completion inventory could not be loaded' "$WORK/inventory.err" || true)" -eq 1 ]] || fail "inventory warning count"
grep -q 'Run: doctor' "$WORK/inventory.err" || fail "inventory doctor hint"
! grep -Eq 'Traceback|JSONDecodeError|registry.json' "$WORK/inventory.err" || fail "inventory details leaked"
pass COMPLETION_INVENTORY_WARNING_SAFE

python3 - "$ROOT" <<'PY'
import contextlib, io, sys
from pathlib import Path
root = Path(sys.argv[1]); sys.path.insert(0, str(root / 'lib'))
import frp_ctl_repl as repl
class FakeReadline:
    def __init__(self): self.line='set '
    def get_line_buffer(self): return self.line
fake=FakeReadline(); real=repl.readline; repl.readline=fake
try:
    editor=repl.LineEditor({'role':'server','names':[],'clients':[],'services':{},'local_services':[]})
    out=io.StringIO()
    with contextlib.redirect_stdout(out): editor.display_matches('', ['client','installer-url'], 13)
    first=out.getvalue()
    assert 'client' in first and 'installer-url' in first
    assert first.count('frpctl> set ') == 1, first
    assert fake.line == 'set '
    out=io.StringIO()
    with contextlib.redirect_stdout(out): editor.display_matches('', ['client','installer-url'], 13)
    assert out.getvalue() == '', out.getvalue()
finally:
    repl.readline=real
PY
pass TAB_PROMPT_RESTORE_SAFE
pass TAB_NO_REPEAT_SPAM

before_client="$(sha256sum "$ROOT/dist/bootstrap-client.sh" | awk '{print $1}')"
before_server="$(sha256sum "$ROOT/dist/bootstrap-server.sh" | awk '{print $1}')"
"$ROOT/scripts/build-bundles.sh" >/dev/null
after_client="$(sha256sum "$ROOT/dist/bootstrap-client.sh" | awk '{print $1}')"
after_server="$(sha256sum "$ROOT/dist/bootstrap-server.sh" | awk '{print $1}')"
[[ "$before_client" == "$after_client" && "$before_server" == "$after_server" ]] || fail "bundle rebuild changed committed artifacts"
pass BUNDLE_MANIFEST_SELF_REFERENCE_SAFE

echo 'CLI_HARDENING_TESTS=PASS'
