#!/usr/bin/env bash
# Legacy client secure bridge, candidate metadata, and same-version build identity.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# shellcheck disable=SC1091
. "$ROOT/VERSION"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

write_runtime_fixture() {
  local tree="$1"
  mkdir -p "$tree/etc/frp" "$tree/etc/frp-auto-deploy" "$tree/usr/local/bin" \
    "$tree/usr/local/lib/frp-auto-deploy"
  cat >"$tree/usr/local/bin/frpc" <<'EOF'
#!/bin/sh
if [ "${1:-}" = verify ]; then exit 0; fi
if [ "${1:-}" = --version ]; then echo "frpc version 0.71.0"; exit 0; fi
exit 0
EOF
  chmod 0755 "$tree/usr/local/bin/frpc"
  cat >"$tree/etc/frp/client-state.json" <<'EOF'
{
  "allocator_url": "https://allocator.example.test/enroll",
  "frp_server": "203.0.113.10",
  "frp_server_port": 443,
  "host_id": "bridge-client-aabbccdd",
  "hostname": "aella",
  "machine_id": "aabbccddeeff00112233445566778899",
  "schema_version": 1,
  "services": {
    "ssh": {
      "enabled": true,
      "id": "ssh",
      "local_ip": "127.0.0.1",
      "local_port": 22,
      "name": "SSH",
      "preset": "ssh",
      "protocol": "tcp",
      "remote_port": 6000,
      "ssh_user": "aella"
    }
  },
  "transport": "wss"
}
EOF
  chmod 0600 "$tree/etc/frp/client-state.json"
  cat >"$tree/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.method = "token"
auth.token = "bridge-update-token-secret"
transport.protocol = "websocket"
transport.tls.enable = true

[[proxies]]
name = "bridge-client-aabbccdd-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000
EOF
  chmod 0600 "$tree/etc/frp/frpc.toml"
  printf 'Public SSH: 203.0.113.10:6000\n' >"$tree/etc/frp/access-info.txt"
  printf '%s\n' 'test allocator CA certificate bytes' >"$tree/etc/frp-auto-deploy/allocator-ca.crt"
  python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
    "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
  printf '%064d\n' 0 >"$tree/etc/frp/client-identity.mac"
  chmod 0600 "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.mac"
  chmod 0644 "$tree/etc/frp/client-identity.pub" "$tree/etc/frp-auto-deploy/allocator-ca.crt"
}

write_version() {
  local tree="$1"
  cat >"$tree/etc/frp-auto-deploy/version"
  chmod 0644 "$tree/etc/frp-auto-deploy/version"
}

snapshot_preserved_state() {
  local tree="$1" output="$2"
  python3 - "$tree" "$output" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, output = Path(sys.argv[1]), Path(sys.argv[2])
files = [
    "etc/frp/client-state.json",
    "etc/frp/frpc.toml",
    "etc/frp/access-info.txt",
    "etc/frp/client-identity.key",
    "etc/frp/client-identity.pub",
    "etc/frp/client-identity.mac",
    "etc/frp-auto-deploy/allocator-ca.crt",
    "usr/local/bin/frpc",
]
state = json.loads((root / "etc/frp/client-state.json").read_text())
result = {
    "digests": {
        rel: hashlib.sha256((root / rel).read_bytes()).hexdigest()
        for rel in files
    },
    "version": (root / "etc/frp-auto-deploy/version").read_text()
    if (root / "etc/frp-auto-deploy/version").is_file() else "",
    "machine_id": state["machine_id"],
    "hostname": state["hostname"],
    "allocator_url": state["allocator_url"],
    "ssh_port": state["services"]["ssh"]["remote_port"],
    "ssh_enabled": state["services"]["ssh"]["enabled"],
}
output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY
}

assert_preserved_state() {
  local tree="$1" snapshot="$2"
  python3 - "$tree" "$snapshot" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, snapshot = Path(sys.argv[1]), Path(sys.argv[2])
before = json.loads(snapshot.read_text())
for rel, expected in before["digests"].items():
    actual = hashlib.sha256((root / rel).read_bytes()).hexdigest()
    assert actual == expected, f"changed {rel}"
state = json.loads((root / "etc/frp/client-state.json").read_text())
assert state["machine_id"] == before["machine_id"]
assert state["hostname"] == before["hostname"]
assert state["allocator_url"] == before["allocator_url"]
assert state["services"]["ssh"]["remote_port"] == before["ssh_port"]
assert state["services"]["ssh"]["enabled"] == before["ssh_enabled"]
assert state["services"]["ssh"]["id"] == "ssh"
PY
}

assert_version_unchanged() {
  local tree="$1" snapshot="$2"
  python3 - "$tree" "$snapshot" <<'PY'
import json, sys
from pathlib import Path
root, snapshot = Path(sys.argv[1]), Path(sys.argv[2])
before = json.loads(snapshot.read_text())
current = (root / "etc/frp-auto-deploy/version").read_text() \
    if (root / "etc/frp-auto-deploy/version").is_file() else ""
assert current == before["version"], "version file mutated"
PY
}

install_old_tools() {
  local tree="$1"
  mkdir -p "$tree/usr/local/bin" "$tree/usr/local/lib/frp-auto-deploy"
  cat >"$tree/usr/local/bin/frpctl" <<'EOF'
#!/bin/sh
echo old-frpctl
exit 0
EOF
  cat >"$tree/usr/local/bin/frp-client" <<'EOF'
#!/bin/sh
echo old-frp-client
exit 0
EOF
  chmod 0755 "$tree/usr/local/bin/frpctl" "$tree/usr/local/bin/frp-client"
  echo old >"$tree/usr/local/lib/frp-auto-deploy/frp-client-common.sh"
}

extract_bundle_file() {
  local bundle="$1" rel="$2" dest="$3"
  python3 - "$bundle" "$rel" "$dest" <<'PY'
import base64, re, sys
from pathlib import Path
bundle, rel, dest = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
text = bundle.read_text()
pat = re.compile(
    r"(?:base64 -d|_frp_b64d) >\"\$TMP/" + re.escape(rel) + r"\" <<'B64'\n(.*?)\nB64",
    re.S,
)
match = pat.search(text)
if not match:
    raise SystemExit(f"missing {rel} in generated bundle")
dest.write_bytes(base64.b64decode("".join(match.group(1).split())))
PY
}

# ---------------------------------------------------------------------------
# Real generated client bundle
# ---------------------------------------------------------------------------
python3 "$ROOT/scripts/build-bundles.py" >/dev/null
BUNDLE="$ROOT/dist/bootstrap-client.sh"
[[ -x "$BUNDLE" ]] || fail "generated bootstrap-client.sh missing"
grep -q 'release-manifest.json' "$BUNDLE" || fail "generated bundle missing release-manifest.json"
extract_bundle_file "$BUNDLE" "release-manifest.json" "$WORKDIR/bundle-release-manifest.json"
python3 - "$WORKDIR/bundle-release-manifest.json" "$PROJECT_VERSION" <<'PY' || fail "bundle manifest identity"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
assert data.get("project_version") == sys.argv[2]
assert data.get("channel") == "dev"
assert data.get("git_ref") == "main"
PY
pass "CLIENT_BUNDLE_CONTAINS_RELEASE_MANIFEST"
pass "REAL_GENERATED_CLIENT_BUNDLE"

# ---------------------------------------------------------------------------
# Candidate metadata validation
# ---------------------------------------------------------------------------
# shellcheck disable=SC1091
. "$ROOT/lib/frp-common.sh"
# shellcheck disable=SC1091
. "$ROOT/lib/frp-client-common.sh"

VALID_META="$(frp_validate_release_source_metadata "$ROOT")" || fail "valid source metadata"
[[ "$VALID_META" == "${PROJECT_VERSION}"$'\tdev\tmain' ]] ||
  fail "valid metadata triple: $VALID_META"
pass "CLIENT_CANDIDATE_METADATA_VALID"

BADCH="$WORKDIR/bad-channel"
mkdir -p "$BADCH"
cp "$ROOT/VERSION" "$BADCH/VERSION"
cp "$ROOT/release-manifest.json" "$BADCH/release-manifest.json"
python3 - "$BADCH/release-manifest.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["channel"] = "stable"
p.write_text(json.dumps(d) + "\n")
PY
if frp_validate_release_source_metadata "$BADCH" >/dev/null 2>"$WORKDIR/bad-channel.err"; then
  fail "channel/ref disagreement accepted"
fi
grep -qi 'channel/ref disagreement\|channel mismatch' "$WORKDIR/bad-channel.err" ||
  fail "channel disagreement message"
if FRP_EXPECTED_RELEASE_CHANNEL=stable \
  frp_validate_release_source_metadata "$ROOT" >/dev/null 2>"$WORKDIR/expected-stable.err"; then
  fail "expected stable accepted a dev candidate"
fi
grep -qi 'channel mismatch' "$WORKDIR/expected-stable.err" || fail "expected channel mismatch"
pass "CLIENT_CANDIDATE_METADATA_CHANNEL_MISMATCH"

BADREF="$WORKDIR/bad-ref"
mkdir -p "$BADREF"
cp "$ROOT/VERSION" "$BADREF/VERSION"
cp "$ROOT/release-manifest.json" "$BADREF/release-manifest.json"
if FRP_EXPECTED_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF="v${PROJECT_VERSION}" \
  frp_validate_release_source_metadata "$ROOT" >/dev/null 2>"$WORKDIR/bad-ref.err"; then
  fail "expected ref mismatch accepted"
fi
grep -qi 'source ref mismatch' "$WORKDIR/bad-ref.err" || fail "expected ref mismatch message"
pass "CLIENT_CANDIDATE_METADATA_REF_MISMATCH"

# ---------------------------------------------------------------------------
# Installed identity reporting
# ---------------------------------------------------------------------------
NOCH="$WORKDIR/no-channel"
write_runtime_fixture "$NOCH"
write_version "$NOCH" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
EOF
export FRP_CLIENT_TEST_ROOT="$NOCH"
[[ "$(frp_client_installed_release_channel)" == "unknown" ]] || fail "missing channel not unknown"
pass "LEGACY_CLIENT_NO_CHANNEL"

NOREF="$WORKDIR/no-ref"
write_runtime_fixture "$NOREF"
write_version "$NOREF" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
RELEASE_CHANNEL=dev
EOF
export FRP_CLIENT_TEST_ROOT="$NOREF"
[[ "$(frp_client_installed_source_ref)" == "unknown" ]] || fail "missing source ref not unknown"
pass "LEGACY_CLIENT_NO_SOURCE_REF"

NOSHA="$WORKDIR/no-sha"
write_runtime_fixture "$NOSHA"
write_version "$NOSHA" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
RELEASE_CHANNEL=dev
SOURCE_REF=main
EOF
export FRP_CLIENT_TEST_ROOT="$NOSHA"
[[ "$(frp_client_installed_bundle_sha256)" == "unknown" ]] || fail "missing bundle sha not unknown"
pass "LEGACY_CLIENT_NO_BUNDLE_SHA"

# ---------------------------------------------------------------------------
# Remote / generated-bundle fail-closed
# ---------------------------------------------------------------------------
LEGACY="$WORKDIR/legacy-remote"
write_runtime_fixture "$LEGACY"
install_old_tools "$LEGACY"
write_version "$LEGACY" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
EOF
snapshot_preserved_state "$LEGACY" "$WORKDIR/legacy.before"
export FRP_CLIENT_TEST_ROOT="$LEGACY"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/legacy.hooks"
: >"$FRP_CLIENT_HOOK_LOG"
unset FRP_RELEASE_CHANNEL FRP_EXPECTED_RELEASE_CHANNEL FRP_EXPECTED_SOURCE_REF \
  FRP_BUNDLE_SHA256 FRP_CLIENT_UPDATE_SHA256 || true

if FRP_CLIENT_TEST_ROOT="$LEGACY" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  bash "$BUNDLE" --upgrade --check >"$WORKDIR/legacy-check.out" 2>"$WORKDIR/legacy-check.err"; then
  fail "legacy bundle --check should fail closed"
fi
grep -q 'LEGACY_CLIENT_SECURE_BRIDGE_REQUIRED' "$WORKDIR/legacy-check.out" "$WORKDIR/legacy-check.err" ||
  fail "legacy check failure class"
grep -q 'Legacy secure bridge required' "$WORKDIR/legacy-check.out" "$WORKDIR/legacy-check.err" ||
  fail "legacy check bridge message"
grep -q 'State mutation           : NO' "$WORKDIR/legacy-check.out" ||
  fail "legacy check mutation line"
assert_preserved_state "$LEGACY" "$WORKDIR/legacy.before"
assert_version_unchanged "$LEGACY" "$WORKDIR/legacy.before"
grep -q 'old-frpctl' "$LEGACY/usr/local/bin/frpctl" || fail "legacy check replaced tools"
if grep -Eq '^(enroll|bootstrap_redeem|restart)$' "$FRP_CLIENT_HOOK_LOG"; then
  fail "legacy check contacted allocator or restarted"
fi
pass "LEGACY_BRIDGE_CHECK_ONLY_READONLY"

if FRP_CLIENT_TEST_ROOT="$LEGACY" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  bash "$BUNDLE" --upgrade >"$WORKDIR/legacy-up.out" 2>"$WORKDIR/legacy-up.err"; then
  fail "legacy bundle upgrade should fail closed"
fi
grep -q 'LEGACY_CLIENT_SECURE_BRIDGE_REQUIRED' "$WORKDIR/legacy-up.out" "$WORKDIR/legacy-up.err" ||
  fail "legacy upgrade failure class"
assert_preserved_state "$LEGACY" "$WORKDIR/legacy.before"
assert_version_unchanged "$LEGACY" "$WORKDIR/legacy.before"
grep -q 'old-frpctl' "$LEGACY/usr/local/bin/frpctl" || fail "legacy upgrade replaced tools"
pass "LEGACY_REMOTE_UPDATE_FAIL_CLOSED"
pass "LEGACY_SECURE_BRIDGE_REQUIRED"

# Remote fetch path on a legacy tree (HTTPS mock never used because fail-closed first).
export FRP_CLIENT_UPDATE_URL="https://updates.example.test/main/dist/bootstrap-client.sh"
export FRP_CLIENT_UPDATE_METADATA_URL="https://updates.example.test/main/SHA256SUMS"
if FRP_CLIENT_TEST_ROOT="$LEGACY" FRP_SKIP_SYSTEMD=1 \
  "$ROOT/tools/frp-client" update --check >"$WORKDIR/legacy-fetch-check.out" 2>"$WORKDIR/legacy-fetch-check.err"; then
  fail "legacy remote --check should fail closed"
fi
grep -q 'LEGACY_CLIENT_SECURE_BRIDGE_REQUIRED' \
  "$WORKDIR/legacy-fetch-check.out" "$WORKDIR/legacy-fetch-check.err" ||
  fail "legacy remote check class"
assert_preserved_state "$LEGACY" "$WORKDIR/legacy.before"
assert_version_unchanged "$LEGACY" "$WORKDIR/legacy.before"

# ---------------------------------------------------------------------------
# Verified bridges against the real generated bundle
# ---------------------------------------------------------------------------
# Dev-channel candidate (repository tree may already be a stable RC).
DEV_SRC="$WORKDIR/dev-src"
cp -a "$ROOT/." "$DEV_SRC/"
rm -rf "$DEV_SRC/.git" "$DEV_SRC/dist"
python3 - "$DEV_SRC/release-manifest.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["channel"] = "dev"
d["git_ref"] = "main"
p.write_text(json.dumps(d, indent=2) + "\n")
PY
python3 "$DEV_SRC/scripts/build-bundles.py" >/dev/null
DEV_BUNDLE="$DEV_SRC/dist/bootstrap-client.sh"
DEV_BUNDLE_SHA="$(sha "$DEV_BUNDLE")"

BUNDLE_SHA="$(sha "$BUNDLE")"
DEV_TREE="$WORKDIR/legacy-dev-bridge"
write_runtime_fixture "$DEV_TREE"
install_old_tools "$DEV_TREE"
write_version "$DEV_TREE" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
EOF
snapshot_preserved_state "$DEV_TREE" "$WORKDIR/dev-bridge.before"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/dev-bridge.hooks"
: >"$FRP_CLIENT_HOOK_LOG"
if ! FRP_CLIENT_TEST_ROOT="$DEV_TREE" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF=main \
  FRP_BUNDLE_SHA256="$DEV_BUNDLE_SHA" FRP_BUNDLE_FILE="$DEV_BUNDLE" \
  bash "$DEV_BUNDLE" --upgrade >"$WORKDIR/dev-bridge.out" 2>"$WORKDIR/dev-bridge.err"; then
  cat "$WORKDIR/dev-bridge.out" "$WORKDIR/dev-bridge.err" >&2
  fail "verified dev/main bridge"
fi
assert_preserved_state "$DEV_TREE" "$WORKDIR/dev-bridge.before"
grep -q 'RELEASE_CHANNEL=dev' "$DEV_TREE/etc/frp-auto-deploy/version" || fail "dev bridge channel"
grep -q 'SOURCE_REF=main' "$DEV_TREE/etc/frp-auto-deploy/version" || fail "dev bridge ref"
grep -q "BUNDLE_SHA256=$DEV_BUNDLE_SHA" "$DEV_TREE/etc/frp-auto-deploy/version" || fail "dev bridge sha"
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$DEV_TREE/etc/frp-auto-deploy/version" || fail "dev bridge version"
grep -q "FRP_VERSION=${FRP_VERSION}" "$DEV_TREE/etc/frp-auto-deploy/version" || fail "dev bridge frp"
if grep -Eq '^(enroll|bootstrap_redeem|restart)$' "$FRP_CLIENT_HOOK_LOG"; then
  fail "dev bridge contacted allocator or restarted"
fi
pass "LEGACY_DEV_MAIN_BRIDGE"
pass "BUILD_IDENTITY_PERSISTENCE"
pass "DEV_STAYS_DEV"
pass "NO_REENROLLMENT"
pass "NO_ALLOCATOR_MUTATION"
pass "NO_UNNECESSARY_FRPC_RESTART"
pass "CLIENT_STATE_PRESERVED"
pass "FRPC_CONFIG_PRESERVED"
pass "PORT_PRESERVED"
pass "IDENTITY_PRESERVED"
pass "CA_PRESERVED"
pass "FRPC_BINARY_PRESERVED"

# Stable verified bridge uses a temporary stable-looking candidate.
STABLE_SRC="$WORKDIR/stable-src"
cp -a "$ROOT/." "$STABLE_SRC/"
rm -rf "$STABLE_SRC/.git" "$STABLE_SRC/dist"
python3 - "$STABLE_SRC/release-manifest.json" "$PROJECT_VERSION" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["channel"] = "stable"
d["git_ref"] = "v%s" % sys.argv[2]
p.write_text(json.dumps(d, indent=2) + "\n")
PY
python3 "$STABLE_SRC/scripts/build-bundles.py" >/dev/null
STABLE_BUNDLE="$STABLE_SRC/dist/bootstrap-client.sh"
STABLE_SHA="$(sha "$STABLE_BUNDLE")"
STABLE_TREE="$WORKDIR/legacy-stable-bridge"
write_runtime_fixture "$STABLE_TREE"
install_old_tools "$STABLE_TREE"
write_version "$STABLE_TREE" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
EOF
snapshot_preserved_state "$STABLE_TREE" "$WORKDIR/stable-bridge.before"
if ! FRP_CLIENT_TEST_ROOT="$STABLE_TREE" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=stable FRP_EXPECTED_SOURCE_REF="v${PROJECT_VERSION}" \
  FRP_BUNDLE_SHA256="$STABLE_SHA" FRP_BUNDLE_FILE="$STABLE_BUNDLE" \
  bash "$STABLE_BUNDLE" --upgrade >"$WORKDIR/stable-bridge.out" 2>"$WORKDIR/stable-bridge.err"; then
  cat "$WORKDIR/stable-bridge.out" "$WORKDIR/stable-bridge.err" >&2
  fail "verified stable bridge"
fi
assert_preserved_state "$STABLE_TREE" "$WORKDIR/stable-bridge.before"
grep -q 'RELEASE_CHANNEL=stable' "$STABLE_TREE/etc/frp-auto-deploy/version" || fail "stable bridge channel"
grep -q "SOURCE_REF=v${PROJECT_VERSION}" "$STABLE_TREE/etc/frp-auto-deploy/version" || fail "stable bridge ref"
grep -q "BUNDLE_SHA256=$STABLE_SHA" "$STABLE_TREE/etc/frp-auto-deploy/version" || fail "stable bridge sha"
pass "LEGACY_STABLE_BRIDGE"
pass "STABLE_STAYS_STABLE"

# Expected constraints reject a contradictory candidate.
if FRP_CLIENT_TEST_ROOT="$LEGACY" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=stable FRP_EXPECTED_SOURCE_REF="v${PROJECT_VERSION}" \
  FRP_BUNDLE_SHA256="$DEV_BUNDLE_SHA" FRP_BUNDLE_FILE="$DEV_BUNDLE" \
  bash "$DEV_BUNDLE" --upgrade >"$WORKDIR/wrong-line.out" 2>"$WORKDIR/wrong-line.err"; then
  fail "expected stable accepted a dev bundle"
fi
grep -Eqi 'channel mismatch|source ref mismatch' "$WORKDIR/wrong-line.err" || fail "wrong-line message"
assert_preserved_state "$LEGACY" "$WORKDIR/legacy.before"

# ---------------------------------------------------------------------------
# Exact bug state: stable / v2.1.0 / unknown SHA
# ---------------------------------------------------------------------------
BUG="$WORKDIR/bug-state"
write_runtime_fixture "$BUG"
install_old_tools "$BUG"
write_version "$BUG" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
RELEASE_CHANNEL=stable
SOURCE_REF=v2.1.0
EOF
snapshot_preserved_state "$BUG" "$WORKDIR/bug.before"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/bug.hooks"
: >"$FRP_CLIENT_HOOK_LOG"
# Do not auto-reinterpret as dev.
if FRP_CLIENT_TEST_ROOT="$BUG" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  bash "$BUNDLE" --upgrade >"$WORKDIR/bug-auto.out" 2>"$WORKDIR/bug-auto.err"; then
  fail "bug state without verified SHA should fail closed"
fi
grep -q 'LEGACY_CLIENT_SECURE_BRIDGE_REQUIRED' "$WORKDIR/bug-auto.out" "$WORKDIR/bug-auto.err" ||
  fail "bug state fail-closed class"
assert_preserved_state "$BUG" "$WORKDIR/bug.before"
assert_version_unchanged "$BUG" "$WORKDIR/bug.before"
grep -q 'RELEASE_CHANNEL=stable' "$BUG/etc/frp-auto-deploy/version" || fail "bug state auto-changed channel"
pass "BUG_STATE_STABLE_V210_UNKNOWN_SHA"

if ! FRP_CLIENT_TEST_ROOT="$BUG" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF=main \
  FRP_BUNDLE_SHA256="$DEV_BUNDLE_SHA" FRP_BUNDLE_FILE="$DEV_BUNDLE" \
  bash "$DEV_BUNDLE" --upgrade >"$WORKDIR/bug-recover.out" 2>"$WORKDIR/bug-recover.err"; then
  cat "$WORKDIR/bug-recover.out" "$WORKDIR/bug-recover.err" >&2
  fail "explicit verified dev recovery"
fi
assert_preserved_state "$BUG" "$WORKDIR/bug.before"
grep -q 'RELEASE_CHANNEL=dev' "$BUG/etc/frp-auto-deploy/version" || fail "recovery channel"
grep -q 'SOURCE_REF=main' "$BUG/etc/frp-auto-deploy/version" || fail "recovery ref"
grep -q "BUNDLE_SHA256=$DEV_BUNDLE_SHA" "$BUG/etc/frp-auto-deploy/version" || fail "recovery sha"
if grep -Eq '^(enroll|bootstrap_redeem|restart)$' "$FRP_CLIENT_HOOK_LOG"; then
  fail "recovery contacted allocator or restarted"
fi
pass "BUG_STATE_EXPLICIT_DEV_RECOVERY"

# Environment disappearance must not erase persisted identity.
unset FRP_RELEASE_CHANNEL FRP_EXPECTED_SOURCE_REF FRP_BUNDLE_SHA256 FRP_BUNDLE_FILE || true
grep -q 'RELEASE_CHANNEL=dev' "$BUG/etc/frp-auto-deploy/version" || fail "identity lost after env unset"
grep -q "BUNDLE_SHA256=$DEV_BUNDLE_SHA" "$BUG/etc/frp-auto-deploy/version" || fail "sha lost after env unset"

# ---------------------------------------------------------------------------
# Same-version build identity + --check contract
# ---------------------------------------------------------------------------
MODERN="$WORKDIR/modern"
write_runtime_fixture "$MODERN"
write_version "$MODERN" <<'EOF'
PROJECT_VERSION=2.1.0
FRP_VERSION=0.71.0
RELEASE_CHANNEL=dev
SOURCE_REF=main
BUNDLE_SHA256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
# Distinct installed SHA so the first verified apply refreshes management tools.
if ! FRP_CLIENT_TEST_ROOT="$MODERN" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF=main \
  FRP_BUNDLE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  bash "$DEV_BUNDLE" --upgrade >"$WORKDIR/modern-install.out" 2>"$WORKDIR/modern-install.err"; then
  cat "$WORKDIR/modern-install.out" "$WORKDIR/modern-install.err" >&2
  fail "modern fixture tool install"
fi
snapshot_preserved_state "$MODERN" "$WORKDIR/modern.before"
CHECK_TOOL_SHA="$(sha "$MODERN/usr/local/bin/frpctl")"
export FRP_CLIENT_TEST_ROOT="$MODERN"
export FRP_CTL_TEST_ROOT="$MODERN"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/modern.hooks"
: >"$FRP_CLIENT_HOOK_LOG"

if ! "$ROOT/tools/frp-client" update --source "$DEV_SRC" --check \
  >"$WORKDIR/modern-check.out" 2>"$WORKDIR/modern-check.err"; then
  cat "$WORKDIR/modern-check.out" "$WORKDIR/modern-check.err" >&2
  fail "modern --check"
fi
grep -q "Installed project version : ${PROJECT_VERSION}" "$WORKDIR/modern-check.out" || fail "check installed version"
grep -q "Target project version    : ${PROJECT_VERSION}" "$WORKDIR/modern-check.out" || fail "check target version"
grep -q 'Installed release channel : dev' "$WORKDIR/modern-check.out" || fail "check installed channel"
grep -q 'Target release channel    : dev' "$WORKDIR/modern-check.out" || fail "check target channel"
grep -q 'Installed source ref      : main' "$WORKDIR/modern-check.out" || fail "check installed ref"
grep -q 'Target source ref         : main' "$WORKDIR/modern-check.out" || fail "check target ref"
grep -q 'Installed bundle SHA256   : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$WORKDIR/modern-check.out" || fail "check installed sha"
grep -q 'Target bundle SHA256      : unknown' "$WORKDIR/modern-check.out" || fail "check target sha unknown for --source"
grep -q 'Update                    : available' "$WORKDIR/modern-check.out" || fail "unknown/different target available"
grep -q 'State mutation           : NO' "$WORKDIR/modern-check.out" || fail "check mutation line"
assert_preserved_state "$MODERN" "$WORKDIR/modern.before"
[[ "$(sha "$MODERN/usr/local/bin/frpctl")" == "$CHECK_TOOL_SHA" ]] || fail "check replaced tools"
if grep -Eq '^(enroll|bootstrap_redeem|restart)$' "$FRP_CLIENT_HOOK_LOG"; then
  fail "modern check contacted allocator or restarted"
fi
pass "CHECK_REPORTS_INSTALLED_AND_TARGET_IDENTITY"
pass "CHECK_ONLY_READONLY"
pass "SAME_VERSION_UNKNOWN_BUILD"

# Same version + different verified SHA => persist the new verified identity.
if ! FRP_CLIENT_TEST_ROOT="$MODERN" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF=main \
  FRP_BUNDLE_SHA256="$DEV_BUNDLE_SHA" FRP_BUNDLE_FILE="$DEV_BUNDLE" \
  bash "$DEV_BUNDLE" --upgrade >"$WORKDIR/diff-up.out" 2>"$WORKDIR/diff-up.err"; then
  cat "$WORKDIR/diff-up.out" "$WORKDIR/diff-up.err" >&2
  fail "same-version different build"
fi
assert_preserved_state "$MODERN" "$WORKDIR/modern.before"
grep -q "BUNDLE_SHA256=$DEV_BUNDLE_SHA" "$MODERN/etc/frp-auto-deploy/version" || fail "different build sha not persisted"
grep -q 'RELEASE_CHANNEL=dev' "$MODERN/etc/frp-auto-deploy/version" || fail "dev changed on different build"
pass "SAME_VERSION_DIFFERENT_BUILD"

snapshot_preserved_state "$MODERN" "$WORKDIR/same.before"
SAME_TOOL="$(sha "$MODERN/usr/local/bin/frpctl")"
if ! FRP_CLIENT_TEST_ROOT="$MODERN" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF=main \
  FRP_BUNDLE_SHA256="$DEV_BUNDLE_SHA" FRP_BUNDLE_FILE="$DEV_BUNDLE" \
  bash "$DEV_BUNDLE" --upgrade --check >"$WORKDIR/same-check.out" 2>"$WORKDIR/same-check.err"; then
  fail "same-build --check"
fi
grep -q "Installed bundle SHA256   : ${DEV_BUNDLE_SHA}" "$WORKDIR/same-check.out" || fail "same-build installed sha"
grep -q "Target bundle SHA256      : ${DEV_BUNDLE_SHA}" "$WORKDIR/same-check.out" || fail "same-build target sha"
grep -q 'Update                    : not needed' "$WORKDIR/same-check.out" || fail "same-build should be not needed"
assert_preserved_state "$MODERN" "$WORKDIR/same.before"
[[ "$(sha "$MODERN/usr/local/bin/frpctl")" == "$SAME_TOOL" ]] || fail "same-build check mutated tools"

if ! FRP_CLIENT_TEST_ROOT="$MODERN" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF=main \
  FRP_BUNDLE_SHA256="$DEV_BUNDLE_SHA" FRP_BUNDLE_FILE="$DEV_BUNDLE" \
  bash "$DEV_BUNDLE" --upgrade >"$WORKDIR/same-up.out" 2>"$WORKDIR/same-up.err"; then
  fail "same-build upgrade"
fi
grep -q 'Update                    : not needed' "$WORKDIR/same-up.out" || fail "same-build apply not needed"
assert_preserved_state "$MODERN" "$WORKDIR/same.before"
[[ "$(sha "$MODERN/usr/local/bin/frpctl")" == "$SAME_TOOL" ]] || fail "same-build apply mutated tools"
pass "SAME_VERSION_SAME_BUILD"

if grep -E 'bridge-update-token-secret|BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY' \
  "$WORKDIR"/*.out "$WORKDIR"/*.err >/dev/null 2>&1; then
  fail "secret leaked into bridge logs"
fi

echo "LEGACY_CLIENT_SECURE_BRIDGE_TEST=PASS"
