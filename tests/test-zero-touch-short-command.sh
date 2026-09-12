#!/usr/bin/env bash
# Short Zero-Touch opaque package encode/decode and command shape.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - "$ROOT/tools/frp-create-client" <<'PY' || fail "package round-trip"
import importlib.machinery
import importlib.util
import sys
from pathlib import Path

path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "frp_create_client",
    path,
    loader=importlib.machinery.SourceFileLoader("frp_create_client", str(path)),
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

url = "https://203.0.113.10/enroll"
ca = "a" * 64
ticket = "bt1." + ("b" * 16) + "." + ("c" * 64)
package = mod.encode_zero_touch_package(url, ca, ticket)
assert package.startswith("zt1."), package
got_url, got_ca, got_ticket = mod.decode_zero_touch_package(package)
assert got_url == url
assert got_ca == ca
assert got_ticket == ticket

try:
    mod.encode_zero_touch_package("http://example", ca, ticket)
    raise SystemExit("accepted http allocator")
except ValueError:
    pass
try:
    mod.decode_zero_touch_package("zt1.!!!!")
    raise SystemExit("accepted garbage")
except ValueError:
    pass
print("OK")
PY
pass "ZERO_TOUCH_PACKAGE_ROUNDTRIP"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
TREE="$WORKDIR/tree"
mkdir -p "$TREE/etc/drlink/pki" "$TREE/var/lib/drlink/enrollments" \
  "$TREE/var/lib/drlink/bootstrap"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$TREE/etc/drlink/pki/ca.key" \
  -out "$TREE/etc/drlink/pki/ca.crt" \
  -days 1 -subj "/CN=frp-test-ca" >/dev/null 2>&1 \
  || fail "openssl ca"

python3 - "$TREE/etc/drlink/config.json" "$TREE" <<'PY'
import json, sys
from pathlib import Path
tree = Path(sys.argv[2])
cfg = {
  "public_ip": "203.0.113.10",
  "control_port": 443,
  "frp_control_public_port": 443,
  "port_start": 6000,
  "port_end": 6098,
  "listen_port": 6099,
  "allocator_public_url": "https://203.0.113.10/enroll",
  "client_installer_url": "https://raw.githubusercontent.com/datarelay-labs/data-relay-link/v2.1.1/dist/bootstrap-client.sh",
  "tls_ca_cert": str(tree / "etc/drlink/pki/ca.crt"),
  "enrollments_dir": str(tree / "var/lib/drlink/enrollments"),
  "bootstrap_dir": str(tree / "var/lib/drlink/bootstrap"),
  "registry_file": str(tree / "var/lib/drlink/registry.json"),
}
Path(sys.argv[1]).write_text(json.dumps(cfg, indent=2) + "\n")
(tree / "var/lib/drlink/registry.json").write_text(
  json.dumps({"schema_version": 2, "clients": {}, "reserved": []}) + "\n"
)
PY

export FRP_DEPLOY_TEST_ROOT="$TREE"
OUT="$WORKDIR/one-line.out"
python3 "$ROOT/tools/frp-create-client" --one-line --client-name short-zt --note 'pkg' \
  >"$OUT" || { cat "$OUT"; fail "create one-line"; }
grep -q 'Zero-touch client command' "$OUT" || fail "header"
grep -E -q "curl -fsSL '.+' \| sudo bash -s -- 'zt1\." "$OUT" \
  || { cat "$OUT"; fail "short command shape"; }
if grep -q 'FRP_BOOTSTRAP_TICKET=' "$OUT"; then
  fail "legacy env block still preferred"
fi
if grep -qiE 'curl -k|curl --insecure|wget --no-check-certificate' "$OUT"; then
  fail "insecure TLS in command"
fi
pass "ZERO_TOUCH_SHORT_COMMAND_SHAPE"

# shellcheck source=/dev/null
source "$ROOT/lib/frp-common.sh"
# shellcheck source=/dev/null
source "$ROOT/lib/frp-client-common.sh"
PACKAGE="$(python3 - "$OUT" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
m = re.search(r"sudo bash -s -- '(zt1\.[^']+)'", text)
assert m, text
print(m.group(1))
PY
)"
frp_zero_touch_apply_package "$PACKAGE" || fail "apply package"
[[ "${FRP_ZERO_TOUCH}" == "1" ]] || fail "ZERO_TOUCH not set"
[[ -n "${FRP_BOOTSTRAP_TICKET}" ]] || fail "ticket missing"
[[ "${FRP_ALLOCATOR_URL}" == https://* ]] || fail "allocator url"
[[ "${#FRP_ALLOCATOR_CA_SHA256}" -eq 64 ]] || fail "ca pin length"
pass "ZERO_TOUCH_PACKAGE_APPLY"

echo "ZERO_TOUCH_SHORT_COMMAND_TEST=PASS"
