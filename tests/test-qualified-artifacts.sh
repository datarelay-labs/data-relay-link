#!/usr/bin/env bash
# Targeted Server-local Agent/FRP artifact tests (no public fallback).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 "$ROOT/tests/test-qualified-artifacts.py" || fail "python unit tests"

WORKDIR="$(mktemp -d /tmp/drlink-artifact-test.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

python3 "$ROOT/lib/drlink_qualified_artifacts.py" install \
  --source "$ROOT" --dest "$WORKDIR/artifacts" \
  --agent-linux "$ROOT/dist/bootstrap-client.sh" \
  --agent-windows "$ROOT/dist/bootstrap-client.ps1" \
  >/dev/null || fail "install artifacts"

python3 "$ROOT/lib/drlink_qualified_artifacts.py" verify-tree \
  --root "$WORKDIR/artifacts" >/dev/null || fail "verify-tree after install"
python3 - "$WORKDIR/artifacts" <<'PY' || fail "artifact hash parity"
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
sums = {}
for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, rel = line.split()
    sums[rel] = digest
assert len(str(manifest.get("source_head") or "")) == 40, manifest.get("source_head")
for item in manifest["artifacts"]:
    rel = item["relative_path"]
    actual = hashlib.sha256((root / rel).read_bytes()).hexdigest()
    assert actual == item["sha256"] == sums[rel], (rel, actual, item["sha256"], sums[rel])
print("ARTIFACT_HASH_PARITY=PASS")
PY
pass "ARTIFACT_HASH_PARITY"

STALE="$WORKDIR/stale-root"
python3 "$ROOT/lib/drlink_qualified_artifacts.py" install \
  --source "$ROOT" --dest "$STALE" \
  --agent-linux "$ROOT/dist/bootstrap-client.sh" \
  --agent-windows "$ROOT/dist/bootstrap-client.ps1" >/dev/null
OLD_SHA="$(sha256sum "$STALE/agent/bootstrap-client.sh" | awk '{print $1}')"
printf '\n# stale\n' >>"$STALE/agent/bootstrap-client.sh"
python3 - "$STALE" "$OLD_SHA" <<'PY'
from pathlib import Path
import json, sys
root = Path(sys.argv[1])
old = sys.argv[2]
text = (root / "SHA256SUMS").read_text(encoding="utf-8")
(root / "SHA256SUMS").write_text(text.replace(old, "a" * 64), encoding="utf-8")
man = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
for item in man["artifacts"]:
    if item.get("relative_path") == "agent/bootstrap-client.sh":
        item["sha256"] = "b" * 64
(root / "manifest.json").write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
PY
if DRLINK_ARTIFACT_INSTALL_FAIL=before-swap python3 "$ROOT/lib/drlink_qualified_artifacts.py" install \
  --source "$ROOT" --dest "$STALE" \
  --agent-linux "$ROOT/dist/bootstrap-client.sh" \
  --agent-windows "$ROOT/dist/bootstrap-client.ps1" >/dev/null 2>"$WORKDIR/fail-swap.err"; then
  fail "failed artifact update should not commit"
fi
grep -q 'No changes were applied' "$WORKDIR/fail-swap.err" || fail "failed update public error"
python3 "$ROOT/lib/drlink_qualified_artifacts.py" install \
  --source "$ROOT" --dest "$STALE" \
  --agent-linux "$ROOT/dist/bootstrap-client.sh" \
  --agent-windows "$ROOT/dist/bootstrap-client.ps1" >/dev/null || fail "repair install"
python3 "$ROOT/lib/drlink_qualified_artifacts.py" verify-tree --root "$STALE" >/dev/null \
  || fail "repaired tree verify"
REPAIRED="$(sha256sum "$STALE/agent/bootstrap-client.sh" | awk '{print $1}')"
[[ "$REPAIRED" == "$OLD_SHA" ]] || fail "repaired linux installer sha"
pass "SERVER_LOCAL_ARTIFACT_ATOMIC_UPDATE"
pass "STALE_ARTIFACT_METADATA_REPAIRED"

EXTRACT="$WORKDIR/extract"
mkdir -p "$EXTRACT"
cp "$ROOT/release-manifest.json" "$EXTRACT/release-manifest.json"
cp "$ROOT/VERSION" "$EXTRACT/VERSION"
unset FRP_EXPECTED_SOURCE_REF FRP_EXPECTED_SOURCE_HEAD FRP_TXN_SOURCE_REF \
  FRP_RELEASE_CHANNEL FRP_BOOTSTRAP_URL FRP_CLIENT_INSTALLER_URL || true
frp_infer_expected_source_from_release_manifest "$EXTRACT"
[[ "${FRP_EXPECTED_SOURCE_HEAD:-}" =~ ^[0-9a-fA-F]{40}$ ]] \
  || fail "extract SOURCE_HEAD missing"
mkdir -p "$WORKDIR/version-dest"
frp_write_version_file "$WORKDIR/version-dest/version"
grep -q "SOURCE_HEAD=${FRP_EXPECTED_SOURCE_HEAD}" "$WORKDIR/version-dest/version" \
  || fail "version file missing SOURCE_HEAD"
pass "ZERO_TOUCH_MANIFEST_SOURCE_HEAD"

python3 "$ROOT/lib/drlink_qualified_artifacts.py" lookup \
  --root "$WORKDIR/artifacts" --type frp-archive \
  --platform linux --architecture amd64 >/dev/null || fail "lookup amd64"

if python3 "$ROOT/lib/drlink_qualified_artifacts.py" lookup \
    --root "$WORKDIR/artifacts" --type frp-archive \
    --platform linux --architecture riscv64 >/dev/null 2>"$WORKDIR/bad-arch.err"; then
  fail "wrong arch should fail"
fi
grep -q 'No changes were applied' "$WORKDIR/bad-arch.err" || fail "wrong-arch public error"

# Use a tiny static server from the installed artifact tree.
PORT_FILE="$WORKDIR/port"
python3 - "$WORKDIR/artifacts" "$PORT_FILE" <<'PY' &
import http.server, os, sys, json
from pathlib import Path
root = Path(sys.argv[1])
port_file = Path(sys.argv[2])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        rel = self.path.split('?', 1)[0]
        if rel == '/artifacts' or rel == '/artifacts/':
            rel = '/artifacts/manifest.json'
        if not rel.startswith('/artifacts/'):
            self.send_error(404)
            return
        path = (root / rel[len('/artifacts/'):]).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            self.send_error(404)
            return
        if not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, format, *args):
        return

httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
port_file.write_text(str(httpd.server_address[1]))
httpd.serve_forever()
PY
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ -s "$PORT_FILE" ]] && break
  sleep 0.1
done
PORT="$(cat "$PORT_FILE")"
[[ -n "$PORT" ]] || fail "artifact http server port"

# HTTPS is required for production URLs; this loopback check uses the tree
# plus curl against the local static map to prove serving + SHA256.
curl -fsS "http://127.0.0.1:${PORT}/artifacts/manifest.json" >"$WORKDIR/manifest.json"
python3 - "$WORKDIR/manifest.json" <<'PY' || fail "served manifest"
import json,sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
assert data["drlink_version"]=="2.4.0"
assert data["frp_version"]=="0.71.0"
assert data["frp_upstream_commit"]=="4a23aa181c1d7e28eecaa8216024ed753b9d27c8"
PY
GOT="$(curl -fsS "http://127.0.0.1:${PORT}/artifacts/frp/0.71.0/frp_0.71.0_linux_amd64.tar.gz" | sha256sum | awk '{print $1}')"
[[ "$GOT" == "$FRP_SHA256_AMD64" ]] || fail "served FRP sha256"
pass "SERVER_LOCAL_SERVING"

# Corrupt copy fails closed.
cp "$WORKDIR/artifacts/frp/0.71.0/frp_0.71.0_linux_amd64.tar.gz" "$WORKDIR/frp-good.tar.gz"
cp "$WORKDIR/frp-good.tar.gz" "$WORKDIR/frp-bad.tar.gz"
printf x >>"$WORKDIR/frp-bad.tar.gz"
if python3 "$ROOT/lib/drlink_qualified_artifacts.py" verify \
    --file "$WORKDIR/frp-bad.tar.gz" --sha256 "$FRP_SHA256_AMD64" --kind FRP \
    --platform linux --architecture amd64 >/dev/null 2>"$WORKDIR/corrupt.err"; then
  fail "corrupt artifact should fail"
fi
grep -q 'No changes were applied' "$WORKDIR/corrupt.err" || fail "corrupt public error"
python3 "$ROOT/lib/drlink_qualified_artifacts.py" verify \
  --file "$WORKDIR/frp-good.tar.gz" --sha256 "$FRP_SHA256_AMD64" --kind FRP \
  --platform linux --architecture amd64 >/dev/null || fail "restored artifact verify"
pass "CORRUPT_ARTIFACT_FAIL_CLOSED"

# install-client download path must require allocator and reject fatedier.
if grep -n 'frp_release_url' "$ROOT/install-client.sh"; then
  fail "install-client still uses frp_release_url"
fi
if grep -n 'github.com/fatedier' "$ROOT/install-client.sh"; then
  fail "install-client still references fatedier"
fi
if ! grep -q 'frp_allocator_curl' "$ROOT/install-client.sh"; then
  fail "install-client FRP download must use pinned allocator CA"
fi
if grep -n 'github.com/fatedier/frp/releases' "$ROOT/install-server.sh"; then
  fail "install-server still downloads fatedier releases"
fi
pass "INSTALLER_NO_FATEDIER"

# Zero-Touch installer URL helper consumes the same SHA256SUMS mapping.
python3 - <<PY || fail "zero-touch sums mapping"
import sys
sys.path.insert(0, "$ROOT/lib")
import frp_zero_touch as zt
url = "https://203.0.113.10/artifacts/agent/bootstrap-client.sh"
assert zt.sha256sums_url_for_installer(url) == "https://203.0.113.10/artifacts/SHA256SUMS"
assert zt.linux_installer_sum_names(url) == ("agent/bootstrap-client.sh",)
PY
pass "ZERO_TOUCH_ARTIFACT_MAPPING"

python3 - <<PY || fail "create-client server-local installer resolution"
import importlib.machinery
import importlib.util
path = "$ROOT/tools/frp-create-client"
spec = importlib.util.spec_from_loader(
    "frp_create_client_qa_sh",
    loader=importlib.machinery.SourceFileLoader("frp_create_client_qa_sh", path),
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cfg = {"allocator_public_url": "https://203.0.113.10:6099/enroll"}
linux = mod.resolve_configured_installer_url(cfg, windows=False)
windows = mod.resolve_configured_installer_url(cfg, windows=True)
assert linux == "https://203.0.113.10:6099/artifacts/agent/bootstrap-client.sh", linux
assert windows == "https://203.0.113.10:6099/artifacts/agent/bootstrap-client.ps1", windows
for url in (linux, windows):
    assert "raw.githubusercontent.com" not in url
    assert "github.com/datarelay-labs" not in url
    assert "github.com/fatedier" not in url
PY
pass "CREATE_CLIENT_NO_PUBLIC_INSTALLER_FALLBACK"

echo "QUALIFIED_ARTIFACT_TESTS=PASS"
