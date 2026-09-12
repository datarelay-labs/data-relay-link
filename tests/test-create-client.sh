#!/usr/bin/env bash
# frp-create-client prints a complete, safely quoted client command.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/drlink/pki" "$TREE/var/lib/drlink/enrollments"
python3 "$ROOT/lib/frp_pki.py" ensure \
  --pki-dir "$TREE/etc/drlink/pki" \
  --public-host 203.0.113.10 >/dev/null
CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$TREE/etc/drlink/pki/ca.crt")"

python3 - "$TREE/etc/drlink/config.json" "$TREE/var/lib/drlink/enrollments" "$TREE/etc/drlink/pki/ca.crt" <<'PY'
import json, sys
from pathlib import Path
cfg = Path(sys.argv[1])
enroll = Path(sys.argv[2])
cfg.write_text(json.dumps({
  "public_host": "203.0.113.10",
  "public_ip": "203.0.113.10",
  "frp_control_public_port": 8443,
  "frp_control_listen_port": 443,
  "allocator_public_url": "https://203.0.113.10:9443/enroll",
  "tls_ca_cert": sys.argv[3],
  "client_installer_url": "https://raw.githubusercontent.com/datarelay-labs/data-relay-link/main/dist/bootstrap-client.sh",
  "enrollments_dir": str(enroll),
}, indent=2) + "\n")
PY

OUT="$WORKDIR/create.out"
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$ROOT/tools/frp-create-client" >"$OUT"
grep -q 'Enrollment Code:' "$OUT" || fail "enrollment header"
grep -qE '^[0-9a-f]{16}\.[0-9a-f]{64}$' "$OUT" || fail "enrollment code format"
grep -q 'Data Relay Link Server: 203.0.113.10:8443' "$OUT" || fail "public FRP endpoint"
if grep -q '203.0.113.10:443' "$OUT"; then
  fail "internal listen port leaked as client-facing FRP endpoint"
fi
grep -q 'Allocator: https://203.0.113.10:9443/enroll' "$OUT" || fail "allocator public URL"
grep -q "CA SHA256: ${CA_FP}" "$OUT" || fail "CA fingerprint"
grep -q 'sudo env FRP_ALLOCATOR_URL=' "$OUT" || fail "sudo env allocator URL"
grep -q 'FRP_ALLOCATOR_CA_SHA256=' "$OUT" || fail "CA fingerprint in install command"
grep -q 'https://203.0.113.10:9443/enroll' "$OUT" || fail "allocator URL value"
grep -q 'curl -fsSL' "$OUT" || fail "curl installer"
if grep -q 'FRP_ENROLLMENT' "$OUT"; then
  fail "enrollment secret must not appear in the env command name"
fi
code="$(awk '/^Enrollment Code:/{getline; print; exit}' "$OUT")"
sudo_line="$(grep 'sudo env FRP_ALLOCATOR_URL=' "$OUT")"
if grep -F "$code" <<<"$sudo_line" >/dev/null; then
  fail "enrollment code leaked into sudo command"
fi
grep -q 'datarelay-labs/data-relay-link' "$OUT" || fail "canonical repository URL"
if grep -F 'RickLee-kr' "$OUT" >/dev/null; then
  fail "stale repository owner in frp-create-client output"
fi
if grep -F 'xdr-labs' "$OUT" >/dev/null; then
  fail "stale repository owner xdr-labs in frp-create-client output"
fi
if grep -F 'frp-auto-deploy' "$OUT" >/dev/null; then
  fail "stale repository name frp-auto-deploy in frp-create-client output"
fi
if grep -F 'frp.xdr.ooo' "$OUT" >/dev/null; then
  fail "stale docs domain in frp-create-client output"
fi
pass "CASE D generated client command"

# Shell-sensitive allocator URL is quoted so bash does not execute extra commands.
python3 - "$TREE/etc/drlink/config.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text())
cfg['allocator_public_url'] = "https://203.0.113.10/enroll;id"
cfg['client_installer_url'] = "https://example.test/bootstrap-client.sh"
path.write_text(json.dumps(cfg, indent=2) + "\n")
PY
FRP_DEPLOY_TEST_ROOT="$TREE" python3 "$ROOT/tools/frp-create-client" >"$WORKDIR/quoted.out"
python3 - "$WORKDIR/quoted.out" <<'PY'
import re, subprocess, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"sudo env FRP_ALLOCATOR_URL=(.*)(?: FRP_ALLOCATOR_CA_SHA256=.*)? bash", text)
if not m:
    # Fall back: capture the first assignment.
    m = re.search(r"sudo env FRP_ALLOCATOR_URL=(\S+)", text)
if not m:
    raise SystemExit('missing sudo env line')
assign = m.group(1)
wanted = "https://203.0.113.10/enroll;id"
script = f"FRP_ALLOCATOR_URL={assign}; printf '%s' \"${{FRP_ALLOCATOR_URL}}\""
out = subprocess.check_output(['bash', '-c', script], text=True)
if out != wanted:
    raise SystemExit(f'quoted assignment decoded to {out!r}')
if '\n' in out or out != wanted:
    raise SystemExit('command injection from allocator URL')
PY
pass "CASE E URL quoting"

echo
echo "CREATE_CLIENT_COMMAND_TEST=PASS"
