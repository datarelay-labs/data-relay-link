#!/usr/bin/env bash
# Client CA fingerprint bootstrap and verified HTTPS helper.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
ALLOC_PID=""
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
frp_test_arm_cleanup

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_CLIENT_SOURCED=1
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"

ALLOC_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
ALLOC_ROOT="$WORKDIR/allocator"
mkdir -p "$ALLOC_ROOT/enrollments"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$ALLOC_ROOT/pki" --public-host 127.0.0.1 >/dev/null
CA_FP="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$ALLOC_ROOT/pki/ca.crt")"
python3 - "$ALLOC_ROOT" "$ALLOC_PORT" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
port = int(sys.argv[2])
pki = root / 'pki'
(root / 'server_token').write_text('test-frp-token-do-not-use\n')
(root / 'server_token').chmod(0o600)
(root / 'registry.json').write_text(json.dumps({
    'schema_version': 2, 'reserved': [], 'clients': {},
}, indent=2) + '\n')
(root / 'config.json').write_text(json.dumps({
    'public_host': '203.0.113.10',
    'frp_control_public_port': 443,
    'frp_control_listen_port': 443,
    'port_start': 19300,
    'port_end': 19310,
    'listen_host': '127.0.0.1',
    'listen_port': port,
    'allocator_listen_port': port,
    'tls_ca_cert': str(pki / 'ca.crt'),
    'tls_server_cert': str(pki / 'server.crt'),
    'tls_server_key': str(pki / 'server.key'),
    'registry_file': str(root / 'registry.json'),
    'enrollments_dir': str(root / 'enrollments'),
    'token_file': str(root / 'server_token'),
}, indent=2) + '\n')
PY
python3 "$ROOT/server/frp-port-allocator.py" --config "$ALLOC_ROOT/config.json" >"$WORKDIR/alloc.log" 2>&1 &
ALLOC_PID=$!
for i in $(seq 1 50); do
  if curl -fsS --cacert "$ALLOC_ROOT/pki/ca.crt" "https://127.0.0.1:${ALLOC_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

URL="https://127.0.0.1:${ALLOC_PORT}/enroll"
TREE="$WORKDIR/client"
mkdir -p "$TREE"
export FRP_CLIENT_TEST_ROOT="$TREE"

# Correct fingerprint bootstrap.
export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
frp_bootstrap_allocator_ca "$URL" || fail "correct fingerprint bootstrap"
[[ -f "$TREE/etc/drlink/allocator-ca.crt" ]] || fail "trusted CA not installed"
mode="$(python3 - "$TREE/etc/drlink/allocator-ca.crt" <<'PY'
import os,stat,sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)"
[[ "$mode" == "0o644" ]] || fail "trusted CA mode"
got="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$TREE/etc/drlink/allocator-ca.crt")"
[[ "$got" == "$CA_FP" ]] || fail "installed fingerprint"
pass "correct CA fingerprint bootstrap succeeds"
pass "trusted CA file installed atomically"
pass "trusted CA ownership/mode safe"

# Wrong fingerprint fails closed and does not replace the good file.
BAD_TREE="$WORKDIR/bad"
mkdir -p "$BAD_TREE"
export FRP_CLIENT_TEST_ROOT="$BAD_TREE"
export FRP_ALLOCATOR_CA_SHA256="$(printf '%064d' 1 | tr '0' 'a')"
if frp_bootstrap_allocator_ca "$URL" 2>"$WORKDIR/mismatch.err"; then
  fail "wrong fingerprint should fail"
fi
grep -qi 'mismatch' "$WORKDIR/mismatch.err" || fail "mismatch error"
if [[ -e "$BAD_TREE/etc/drlink/allocator-ca.crt" ]]; then
  fail "mismatch wrote trusted CA"
fi
pass "wrong fingerprint fails closed"

# Canonical fingerprint is SHA256 of openssl DER, matching frp_pki.py.
bash_fp="$(frp_ca_fingerprint_file "$ALLOC_ROOT/pki/ca.crt")"
der_fp="$(openssl x509 -in "$ALLOC_ROOT/pki/ca.crt" -outform DER | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
[[ "$bash_fp" == "$CA_FP" && "$bash_fp" == "$der_fp" ]] || fail "canonical DER SHA256 mismatch"
pass "canonical fingerprint is SHA256 of parsed DER"

# Malformed (not PEM) fails.
MALFORMED="$WORKDIR/malformed.crt"
printf 'not-a-certificate\n' >"$MALFORMED"
export FRP_CLIENT_TEST_ROOT="$WORKDIR/malformed-client"
unset FRP_ALLOCATOR_CA_SHA256
export FRP_ALLOCATOR_CA_FILE="$MALFORMED"
if frp_bootstrap_allocator_ca "$URL" 2>"$WORKDIR/malformed.err"; then
  fail "malformed CA should fail"
fi
grep -qi 'not a valid X.509' "$WORKDIR/malformed.err" || fail "malformed X.509 error"
if [[ -e "$WORKDIR/malformed-client/etc/drlink/allocator-ca.crt" ]]; then
  fail "malformed CA installed"
fi
pass "malformed certificate fails"

# Base64 garbage wrapped as a certificate must not become trusted.
GARBAGE="$WORKDIR/garbage.crt"
python3 - "$GARBAGE" <<'PY'
import base64, sys
from pathlib import Path
body = base64.b64encode(b'not-an-x509-certificate-' * 16).decode('ascii')
Path(sys.argv[1]).write_text(
    '-----BEGIN CERTIFICATE-----\n' + body + '\n-----END CERTIFICATE-----\n',
    encoding='utf-8',
)
PY
export FRP_CLIENT_TEST_ROOT="$WORKDIR/garbage-client"
unset FRP_ALLOCATOR_CA_SHA256
export FRP_ALLOCATOR_CA_FILE="$GARBAGE"
if frp_bootstrap_allocator_ca "$URL" 2>"$WORKDIR/garbage.err"; then
  fail "garbage PEM should fail"
fi
grep -qi 'not a valid X.509' "$WORKDIR/garbage.err" || fail "garbage X.509 error"
if [[ -e "$WORKDIR/garbage-client/etc/drlink/allocator-ca.crt" ]]; then
  fail "garbage CA installed"
fi
pass "base64 garbage wrapped as certificate is rejected"

# Tampered valid PEM is rejected before trust.
TAMPER="$WORKDIR/tamper.crt"
python3 - "$ALLOC_ROOT/pki/ca.crt" "$TAMPER" <<'PY'
from pathlib import Path
src, dest = Path(__import__('sys').argv[1]), Path(__import__('sys').argv[2])
text = src.read_text(encoding='utf-8')
lines = text.splitlines()
body = [ln for ln in lines if ln and not ln.startswith('-----')]
if not body:
    raise SystemExit('no pem body')
# Flip one character inside the first body line so PEM markers remain.
first = list(body[0])
for i, ch in enumerate(first):
    if ch.isalnum():
        first[i] = 'A' if ch != 'A' else 'B'
        break
body[0] = ''.join(first)
out = []
in_body = False
bi = 0
for ln in lines:
    if ln.startswith('-----BEGIN'):
        out.append(ln)
        in_body = True
        continue
    if ln.startswith('-----END'):
        out.append(ln)
        in_body = False
        continue
    if in_body and ln.strip():
        out.append(body[bi])
        bi += 1
    else:
        out.append(ln)
dest.write_text('\n'.join(out) + '\n', encoding='utf-8')
PY
export FRP_CLIENT_TEST_ROOT="$WORKDIR/tamper-client"
unset FRP_ALLOCATOR_CA_SHA256
export FRP_ALLOCATOR_CA_FILE="$TAMPER"
if frp_bootstrap_allocator_ca "$URL" 2>"$WORKDIR/tamper.err"; then
  fail "tampered CA should fail"
fi
grep -qi 'not a valid X.509\|fingerprint mismatch' "$WORKDIR/tamper.err" || fail "tamper error"
if [[ -e "$WORKDIR/tamper-client/etc/drlink/allocator-ca.crt" ]]; then
  fail "tampered CA installed"
fi
pass "modified/tampered CA fails"

# Downloaded garbage PEM must not contact /enroll.
FAKEBIN="$WORKDIR/fakebin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FRP_FAKE_CURL_LOG}"
outfile=""
url=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "-o" ]]; then
    outfile="$arg"
  fi
  if [[ "$arg" == https://* ]]; then
    url="$arg"
  fi
  prev="$arg"
done
if [[ "$url" == */ca.crt ]]; then
  cat "${FRP_FAKE_CA_BODY}" >"$outfile"
  exit 0
fi
if [[ "$url" == */enroll* ]]; then
  echo ENROLL_CONTACTED >>"${FRP_FAKE_CURL_LOG}"
  exit 0
fi
echo "unexpected curl: $*" >&2
exit 1
EOF
chmod +x "$FAKEBIN/curl"
export FRP_FAKE_CURL_LOG="$WORKDIR/curl-args.log"
export FRP_FAKE_CA_BODY="$GARBAGE"
: >"$FRP_FAKE_CURL_LOG"
export FRP_CLIENT_TEST_ROOT="$WORKDIR/download-garbage"
unset FRP_ALLOCATOR_CA_FILE
export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
ORIG_PATH="$PATH"
PATH="$FAKEBIN:$PATH"
if frp_bootstrap_allocator_ca "https://203.0.113.10:9443/enroll" 2>"$WORKDIR/download-garbage.err"; then
  PATH="$ORIG_PATH"
  fail "downloaded garbage CA should fail"
fi
PATH="$ORIG_PATH"
grep -qi 'not a valid X.509' "$WORKDIR/download-garbage.err" || fail "downloaded garbage X.509 error"
if grep -q ENROLL_CONTACTED "$FRP_FAKE_CURL_LOG"; then
  fail "garbage CA contacted /enroll"
fi
if [[ -e "$WORKDIR/download-garbage/etc/drlink/allocator-ca.crt" ]]; then
  fail "downloaded garbage CA installed"
fi
pass "downloaded garbage CA is rejected before /enroll"

# Pre-provisioned valid CA with matching fingerprint.
export FRP_CLIENT_TEST_ROOT="$WORKDIR/preprov"
unset FRP_ALLOCATOR_CA_SHA256
export FRP_ALLOCATOR_CA_FILE="$ALLOC_ROOT/pki/ca.crt"
export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
frp_bootstrap_allocator_ca "$URL" || fail "pre-provisioned valid CA"
got="$(python3 "$ROOT/lib/frp_pki.py" fingerprint --cert "$WORKDIR/preprov/etc/drlink/allocator-ca.crt")"
[[ "$got" == "$CA_FP" ]] || fail "pre-provisioned fingerprint"
pass "pre-provisioned valid CA is installed"

# Pre-provisioned valid CA with wrong fingerprint fails closed.
export FRP_CLIENT_TEST_ROOT="$WORKDIR/preprov-bad-fp"
export FRP_ALLOCATOR_CA_FILE="$ALLOC_ROOT/pki/ca.crt"
export FRP_ALLOCATOR_CA_SHA256="$(printf '%064d' 1 | tr '0' 'a')"
if frp_bootstrap_allocator_ca "$URL" 2>"$WORKDIR/preprov-bad-fp.err"; then
  fail "pre-provisioned wrong fingerprint should fail"
fi
grep -qi 'mismatch' "$WORKDIR/preprov-bad-fp.err" || fail "pre-provisioned mismatch error"
if [[ -e "$WORKDIR/preprov-bad-fp/etc/drlink/allocator-ca.crt" ]]; then
  fail "pre-provisioned mismatch wrote trusted CA"
fi
pass "pre-provisioned CA requires fingerprint match"

# Existing trusted CA is reused; download is not used to replace it.
export FRP_CLIENT_TEST_ROOT="$TREE"
unset FRP_ALLOCATOR_CA_FILE
export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
before="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TREE/etc/drlink/allocator-ca.crt")"
: >"$FRP_FAKE_CURL_LOG"
PATH="$FAKEBIN:$PATH"
frp_bootstrap_allocator_ca "$URL" || { PATH="$ORIG_PATH"; fail "existing trusted CA reuse"; }
PATH="$ORIG_PATH"
after="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TREE/etc/drlink/allocator-ca.crt")"
[[ "$before" == "$after" ]] || fail "existing trusted CA replaced"
if grep -q '/ca.crt' "$FRP_FAKE_CURL_LOG"; then
  fail "existing trusted CA triggered download"
fi
pass "existing trusted CA is reused without replacement"

# Existing trusted CA with wrong expected fingerprint fails closed and is kept.
export FRP_ALLOCATOR_CA_SHA256="$(printf '%064d' 1 | tr '0' 'a')"
if frp_bootstrap_allocator_ca "$URL" 2>"$WORKDIR/existing-mismatch.err"; then
  fail "existing CA wrong fingerprint should fail"
fi
grep -qi 'mismatch' "$WORKDIR/existing-mismatch.err" || fail "existing mismatch error"
after2="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TREE/etc/drlink/allocator-ca.crt")"
[[ "$before" == "$after2" ]] || fail "mismatch replaced existing trusted CA"
pass "existing trusted CA fingerprint is verified"

# Helper uses --cacert and never -k for normal calls.
python3 - "$ROOT/lib/frp-client-common.sh" <<'PY' || fail "insecure curl policy"
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text(encoding='utf-8')
insecure = [i+1 for i, line in enumerate(text.splitlines()) if '--insecure' in line or re.search(r'(^|[\s])-k([\s]|$)', line)]
if len(insecure) != 1:
    raise SystemExit('expected exactly one --insecure (CA fetch), found %s' % insecure)
# The insecure line must be inside frp_bootstrap_allocator_ca, fetching /ca.crt.
idx = text.find('frp_bootstrap_allocator_ca()')
end = text.find('\nfrp_', idx + 10)
boot = text[idx:end]
if '--insecure' not in boot or '/ca.crt' not in boot:
    raise SystemExit('bootstrap missing narrowly scoped insecure CA fetch')
if 'X-Enrollment' in boot or 'X-Mgmt' in boot or 'X-Signature' in boot:
    raise SystemExit('insecure CA fetch carries secret payload')
curlfn_idx = text.find('frp_allocator_curl()')
curlfn_end = text.find('\nfrp_', curlfn_idx + 10)
curlfn = text[curlfn_idx:curlfn_end]
if '--insecure' in curlfn or re.search(r'(^|[\s])-k([\s]|$)', curlfn):
    raise SystemExit('trusted helper uses insecure curl')
if '--cacert' not in curlfn:
    raise SystemExit('trusted helper missing --cacert')
enroll_idx = text.find('frp_enroll_services()')
if enroll_idx < 0:
    raise SystemExit('missing enroll helper')
# Look until the next top-level function after enroll (wait_for_proxies is before enroll).
if text.count('frp_allocator_curl', enroll_idx) < 2:
    raise SystemExit('enroll does not use verified helper')
print('ok')
PY
pass "first /enroll occurs only over verified HTTPS"
pass "normal allocator calls contain no -k/--insecure"
pass "insecure CA fetch carries no secret payload"

# Verified helper succeeds against the live allocator.
unset FRP_ALLOCATOR_CA_FILE
export FRP_ALLOCATOR_CA_SHA256="$CA_FP"
export FRP_CLIENT_TEST_ROOT="$TREE"
code="$(frp_allocator_curl -fsS "https://127.0.0.1:${ALLOC_PORT}/healthz")"
[[ "$code" == *status* ]] || fail "verified helper healthz"
pass "verified allocator helper uses installed CA"

echo
echo "CA_BOOTSTRAP_TEST=PASS"
