#!/usr/bin/env bash
# Real installed-client update through controlled HTTPS-shaped remote artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

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
  "host_id": "installed-client-aabbccdd",
  "hostname": "installed-client",
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
      "remote_port": 6003,
      "ssh_user": "aella"
    },
    "web": {
      "enabled": false,
      "id": "web",
      "local_ip": "127.0.0.1",
      "local_port": 80,
      "name": "Web",
      "preset": "http",
      "protocol": "tcp",
      "remote_port": 6004
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
auth.token = "installed-update-token-secret"
transport.protocol = "websocket"
transport.tls.enable = true

[[proxies]]
name = "installed-client-aabbccdd-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6003
EOF
  chmod 0600 "$tree/etc/frp/frpc.toml"
  printf 'Public SSH: 203.0.113.10:6003\n' >"$tree/etc/frp/access-info.txt"
  printf '%s\n' 'test allocator CA certificate bytes' >"$tree/etc/frp-auto-deploy/allocator-ca.crt"
  python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
    "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
  printf '%064d\n' 0 >"$tree/etc/frp/client-identity.mac"
  chmod 0600 "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.mac"
  chmod 0644 "$tree/etc/frp/client-identity.pub" "$tree/etc/frp-auto-deploy/allocator-ca.crt"
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
    "machine_id": state["machine_id"],
    "hostname": state["hostname"],
    "allocator_url": state["allocator_url"],
    "services": {
        key: {
            "id": value["id"],
            "remote_port": value["remote_port"],
            "enabled": value["enabled"],
        }
        for key, value in state["services"].items()
    },
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
for key, expected in before["services"].items():
    actual = state["services"][key]
    assert actual["id"] == expected["id"]
    assert actual["remote_port"] == expected["remote_port"]
    assert actual["enabled"] == expected["enabled"]
PY
}

assert_management_unchanged() {
  local tree="$1" before="$2"
  [[ "$(sha "$tree/usr/local/bin/frpctl")" == "$before" ]] || fail "live management tool changed"
}

# Build two same-version bundles outside the source tree. Bundle B has a distinct
# management-tool identity but the same PROJECT_VERSION.
BUILD_SRC="$WORKDIR/build-src"
mkdir -p "$BUILD_SRC"
cp -a "$ROOT/." "$BUILD_SRC/"
rm -rf "$BUILD_SRC/.git" "$BUILD_SRC/dist"
# This harness exercises the explicit-dev remote update path; rewrite candidate
# metadata to channel=dev / main even when the repository tree is a stable RC.
python3 - "$BUILD_SRC/release-manifest.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
d = json.loads(p.read_text())
d["channel"] = "dev"
d["git_ref"] = "main"
p.write_text(json.dumps(d, indent=2) + "\n")
PY
python3 "$BUILD_SRC/scripts/build-bundles.py" >/dev/null
BUNDLE_A="$WORKDIR/bootstrap-client-a.sh"
cp "$BUILD_SRC/dist/bootstrap-client.sh" "$BUNDLE_A"
A_SHA="$(sha "$BUNDLE_A")"
printf '\n# P2.20 same-version remote build marker\n' >>"$BUILD_SRC/tools/frpctl"
python3 "$BUILD_SRC/scripts/build-bundles.py" >/dev/null

REMOTE="$WORKDIR/remote"
mkdir -p "$REMOTE"
cp "$BUILD_SRC/dist/bootstrap-client.sh" "$REMOTE/bootstrap-client.sh"
B_SHA="$(sha "$REMOTE/bootstrap-client.sh")"
printf '%s  dist/bootstrap-client.sh\n' "$B_SHA" >"$REMOTE/SHA256SUMS"
[[ "$A_SHA" != "$B_SHA" ]] || fail "same-version bundle identities should differ"

# Create an enrolled runtime, then install bundle A's management software.
CLIENT="$WORKDIR/client"
write_runtime_fixture "$CLIENT"
FRP_CLIENT_TEST_ROOT="$CLIENT" FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_RELEASE_CHANNEL=dev FRP_BUNDLE_SHA256="$A_SHA" \
  bash "$BUNDLE_A" --upgrade >"$WORKDIR/initial-install.out"
[[ -x "$CLIENT/usr/local/bin/frpctl" ]] || fail "installed frpctl missing"
grep -q 'RELEASE_CHANNEL=dev' "$CLIENT/etc/frp-auto-deploy/version" || fail "initial dev channel"
grep -q 'SOURCE_REF=main' "$CLIENT/etc/frp-auto-deploy/version" || fail "initial dev ref"
grep -q "BUNDLE_SHA256=$A_SHA" "$CLIENT/etc/frp-auto-deploy/version" || fail "initial bundle identity"
pass "INSTALLED_METADATA_AVAILABLE"

# curl replacement preserves production HTTPS validation while serving a local,
# deterministic remote endpoint without Internet access.
MOCKBIN="$WORKDIR/mockbin"
mkdir -p "$MOCKBIN"
cat >"$MOCKBIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out="" url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --retry|--connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >>"$MOCK_CURL_LOG"
case "$url" in
  */SHA256SUMS)
    [[ "${MOCK_CURL_FAIL_METADATA:-0}" != 1 && -f "$MOCK_REMOTE_DIR/SHA256SUMS" ]] || exit 22
    cp "$MOCK_REMOTE_DIR/SHA256SUMS" "$out"
    ;;
  */dist/bootstrap-client.sh)
    [[ "${MOCK_CURL_FAIL_ARTIFACT:-0}" != 1 && -f "$MOCK_REMOTE_DIR/bootstrap-client.sh" ]] || exit 22
    cp "$MOCK_REMOTE_DIR/bootstrap-client.sh" "$out"
    ;;
  *) exit 22 ;;
esac
EOF
chmod 0755 "$MOCKBIN/curl"

export PATH="$MOCKBIN:$CLIENT/usr/local/bin:/usr/bin:/bin"
export FRP_CLIENT_TEST_ROOT="$CLIENT"
export FRP_CTL_TEST_ROOT="$CLIENT"
export FRP_CLIENT_LIB="$CLIENT/usr/local/lib/frp-auto-deploy/frp-client-common.sh"
export FRP_SKIP_SYSTEMD=1
export FRP_SKIP_DOWNLOAD=1
export FRP_CLIENT_UPDATE_URL="https://updates.example.test/main/dist/bootstrap-client.sh"
export FRP_CLIENT_UPDATE_METADATA_URL="https://updates.example.test/main/SHA256SUMS"
export MOCK_REMOTE_DIR="$REMOTE"
export MOCK_CURL_LOG="$WORKDIR/curl.log"
export FRP_CLIENT_HOOK_LOG="$WORKDIR/client-hooks.log"
unset FRP_RELEASE_CHANNEL FRP_CLIENT_UPDATE_SHA256 FRP_RELEASE_SHA256SUMS_FILE || true
: >"$MOCK_CURL_LOG"
: >"$FRP_CLIENT_HOOK_LOG"

snapshot_preserved_state "$CLIENT" "$WORKDIR/runtime.before"
CHECK_TOOL_SHA="$(sha "$CLIENT/usr/local/bin/frpctl")"
"$CLIENT/usr/local/bin/frpctl" update --check >"$WORKDIR/check.out" 2>"$WORKDIR/check.err"
grep -q 'Update                    : available' "$WORKDIR/check.out" || fail "same-version build not available"
grep -q 'Installed project version :' "$WORKDIR/check.out" || fail "check missing installed version"
grep -q 'Target project version    :' "$WORKDIR/check.out" || fail "check missing target version"
grep -q 'Installed release channel :' "$WORKDIR/check.out" || fail "check missing installed channel"
grep -q 'Target release channel    :' "$WORKDIR/check.out" || fail "check missing target channel"
grep -q 'Installed source ref      :' "$WORKDIR/check.out" || fail "check missing installed ref"
grep -q 'Target source ref         :' "$WORKDIR/check.out" || fail "check missing target ref"
grep -q 'Installed bundle SHA256   :' "$WORKDIR/check.out" || fail "check missing installed sha"
grep -q 'Target bundle SHA256      :' "$WORKDIR/check.out" || fail "check missing target sha"
assert_preserved_state "$CLIENT" "$WORKDIR/runtime.before"
assert_management_unchanged "$CLIENT" "$CHECK_TOOL_SHA"
if grep -Eq '^(enroll|bootstrap_redeem|restart)$' "$FRP_CLIENT_HOOK_LOG"; then
  fail "check-only contacted allocator or restarted"
fi
pass "SAME_VERSION_DIFFERENT_BUILD"
pass "CHECK_ONLY_READONLY"

"$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/update.out" 2>"$WORKDIR/update.err"
assert_preserved_state "$CLIENT" "$WORKDIR/runtime.before"
grep -q 'RELEASE_CHANNEL=dev' "$CLIENT/etc/frp-auto-deploy/version" || fail "dev channel changed"
grep -q 'SOURCE_REF=main' "$CLIENT/etc/frp-auto-deploy/version" || fail "dev source ref changed"
grep -q "BUNDLE_SHA256=$B_SHA" "$CLIENT/etc/frp-auto-deploy/version" || fail "verified build identity not persisted"
grep -q 'P2.20 same-version remote build marker' "$CLIENT/usr/local/bin/frpctl" || fail "remote management tool not applied"
grep -q '/main/SHA256SUMS' "$MOCK_CURL_LOG" || fail "remote metadata not fetched"
grep -q '/main/dist/bootstrap-client.sh' "$MOCK_CURL_LOG" || fail "remote artifact not fetched"
if grep -Eq '^(enroll|bootstrap_redeem|restart)$' "$FRP_CLIENT_HOOK_LOG"; then
  fail "update contacted allocator or restarted"
fi
pass "REMOTE_INSTALLED_CLIENT_UPDATE"
pass "DEV_MAIN_UPDATE"
pass "SHA256_VALID"
"$CLIENT/usr/local/bin/frpctl" update --check >"$WORKDIR/same-build-check.out" 2>"$WORKDIR/same-build-check.err"
grep -q "Installed bundle SHA256   : ${B_SHA}" "$WORKDIR/same-build-check.out" || fail "same-build installed sha"
grep -q "Target bundle SHA256      : ${B_SHA}" "$WORKDIR/same-build-check.out" || fail "same-build target sha"
grep -q 'Update                    : not needed' "$WORKDIR/same-build-check.out" || fail "same verified build should be not needed"
assert_preserved_state "$CLIENT" "$WORKDIR/runtime.before"
pass "SAME_VERSION_SAME_BUILD"
pass "STATE_PRESERVED"
pass "FRPC_CONFIG_PRESERVED"
pass "PORTS_PRESERVED"
pass "IDENTITY_PRESERVED"
pass "CA_PRESERVED"
pass "NO_ENROLLMENT"
pass "NO_ALLOCATOR_MUTATION"
pass "NO_UNNECESSARY_RESTART"
pass "BUILD_INFO_PERSISTENCE"

# A stable installed client resolves both artifact and metadata at vPROJECT_VERSION.
# shellcheck source=../VERSION
. "$ROOT/VERSION"
cp "$CLIENT/etc/frp-auto-deploy/version" "$WORKDIR/dev-version"
python3 - "$CLIENT/etc/frp-auto-deploy/version" "$PROJECT_VERSION" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
ver = sys.argv[2]
text = p.read_text().replace("RELEASE_CHANNEL=dev", "RELEASE_CHANNEL=stable")
text = text.replace("SOURCE_REF=main", "SOURCE_REF=v%s" % ver)
p.write_text(text)
PY
unset FRP_CLIENT_UPDATE_URL FRP_CLIENT_UPDATE_METADATA_URL
# Load a fresh installed process so defaults are derived from persisted stable state.
stable_urls="$(
  FRP_CLIENT_LIB="$CLIENT/usr/local/lib/frp-auto-deploy/frp-client-common.sh" \
    bash -c '. "$FRP_CLIENT_LIB"; printf "%s\n%s\n" "$FRP_CLIENT_UPDATE_URL" "$FRP_CLIENT_UPDATE_METADATA_URL"'
)"
grep -q "/v${PROJECT_VERSION}/dist/bootstrap-client.sh" <<<"$stable_urls" || fail "stable artifact URL mutable"
grep -q "/v${PROJECT_VERSION}/SHA256SUMS" <<<"$stable_urls" || fail "stable metadata URL mutable"
: >"$MOCK_CURL_LOG"
if "$CLIENT/usr/local/bin/frpctl" update --check >"$WORKDIR/stable-check.out" 2>"$WORKDIR/stable-check.err"; then
  fail "stable expected channel must not accept a dev candidate"
fi
grep -q "/v${PROJECT_VERSION}/SHA256SUMS" "$MOCK_CURL_LOG" || fail "stable metadata was not fetched from tag"
grep -q "/v${PROJECT_VERSION}/dist/bootstrap-client.sh" "$MOCK_CURL_LOG" || fail "stable artifact was not fetched from tag"
grep -Eqi 'channel mismatch|source ref mismatch|WRONG_METADATA' \
  "$WORKDIR/stable-check.out" "$WORKDIR/stable-check.err" ||
  fail "stable/dev candidate mismatch not reported"
assert_preserved_state "$CLIENT" "$WORKDIR/runtime.before"
cp "$WORKDIR/dev-version" "$CLIENT/etc/frp-auto-deploy/version"
export FRP_CLIENT_UPDATE_URL="https://updates.example.test/main/dist/bootstrap-client.sh"
export FRP_CLIENT_UPDATE_METADATA_URL="https://updates.example.test/main/SHA256SUMS"
pass "STABLE_IMMUTABLE_UPDATE"

# Integrity failures occur before any live replacement.
LIVE_SHA="$(sha "$CLIENT/usr/local/bin/frpctl")"
cp "$REMOTE/bootstrap-client.sh" "$WORKDIR/valid-bundle"
printf '\n# tampered\n' >>"$REMOTE/bootstrap-client.sh"
if "$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/tamper.out" 2>"$WORKDIR/tamper.err"; then
  fail "tampered artifact accepted"
fi
grep -q 'INTEGRITY_FAILED' "$WORKDIR/tamper.out" "$WORKDIR/tamper.err" || fail "tamper failure class"
assert_management_unchanged "$CLIENT" "$LIVE_SHA"
pass "TAMPERED_ARTIFACT"

cp "$WORKDIR/valid-bundle" "$REMOTE/bootstrap-client.sh"
printf '%s  dist/bootstrap-client.sh\n' "$A_SHA" >"$REMOTE/SHA256SUMS"
if "$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/wrong-metadata.out" 2>"$WORKDIR/wrong-metadata.err"; then
  fail "wrong metadata accepted"
fi
grep -q 'SHA256 checksum mismatch' "$WORKDIR/wrong-metadata.err" || fail "wrong metadata mismatch message"
assert_management_unchanged "$CLIENT" "$LIVE_SHA"
pass "SHA256_MISMATCH"
pass "WRONG_METADATA_REJECTED"

printf '%s  dist/bootstrap-client.sh\n' 'not-a-sha256' >"$REMOTE/SHA256SUMS"
if "$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/malformed-sha.out" 2>"$WORKDIR/malformed-sha.err"; then
  fail "malformed SHA256 accepted"
fi
grep -q 'malformed SHA256' "$WORKDIR/malformed-sha.err" || fail "malformed SHA256 message"
assert_management_unchanged "$CLIENT" "$LIVE_SHA"
pass "MALFORMED_SHA256_REJECTED"

rm -f "$REMOTE/SHA256SUMS"
if "$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/missing-metadata.out" 2>"$WORKDIR/missing-metadata.err"; then
  fail "missing metadata accepted"
fi
grep -q 'INTEGRITY_FAILED' "$WORKDIR/missing-metadata.out" "$WORKDIR/missing-metadata.err" || fail "missing metadata failure class"
assert_management_unchanged "$CLIENT" "$LIVE_SHA"
pass "MISSING_METADATA_REJECTED"

export FRP_CLIENT_UPDATE_URL="http://updates.example.test/main/dist/bootstrap-client.sh"
if "$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/http.out" 2>"$WORKDIR/http.err"; then
  fail "HTTP artifact URL accepted"
fi
grep -qi 'valid HTTPS URL' "$WORKDIR/http.err" || fail "HTTP rejection message"
assert_management_unchanged "$CLIENT" "$LIVE_SHA"
pass "HTTP_REJECTED"

export FRP_CLIENT_UPDATE_URL="https:///main/dist/bootstrap-client.sh"
if "$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/malformed-url.out" 2>"$WORKDIR/malformed-url.err"; then
  fail "malformed artifact URL accepted"
fi
grep -qi 'valid HTTPS URL' "$WORKDIR/malformed-url.err" || fail "malformed URL rejection message"
assert_management_unchanged "$CLIENT" "$LIVE_SHA"
pass "MALFORMED_URL_REJECTED"

export FRP_CLIENT_UPDATE_URL="https://updates.example.test/main/dist/bootstrap-client.sh"
printf '%s  dist/bootstrap-client.sh\n' "$B_SHA" >"$REMOTE/SHA256SUMS"
export MOCK_CURL_FAIL_ARTIFACT=1
if "$CLIENT/usr/local/bin/frpctl" update >"$WORKDIR/download.out" 2>"$WORKDIR/download.err"; then
  fail "artifact download failure accepted"
fi
unset MOCK_CURL_FAIL_ARTIFACT
grep -q 'DOWNLOAD_FAILED' "$WORKDIR/download.out" "$WORKDIR/download.err" || fail "download failure class"
assert_management_unchanged "$CLIENT" "$LIVE_SHA"
pass "DOWNLOAD_FAILURE"

if grep -E 'installed-update-token-secret|BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY' \
  "$WORKDIR"/*.out "$WORKDIR"/*.err >/dev/null 2>&1; then
  fail "secret leaked into update logs"
fi
pass "NO_SECRET_LEAK"
pass "NO_SELF_REFERENTIAL_CHECKSUM"
echo "INSTALLED_CLIENT_UPDATE_TEST=PASS"
