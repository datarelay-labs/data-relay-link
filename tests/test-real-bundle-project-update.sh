#!/usr/bin/env bash
# Exercise the generated bootstrap-server.sh bundle for --upgrade --check.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
python3 "$ROOT/scripts/build-bundles.py"
[[ -x "$ROOT/dist/bootstrap-server.sh" ]] || fail "bootstrap-server missing"
pass "REAL_BUNDLE_BUILT"

setup_tree() {
  local tree="$1"
  mkdir -p \
    "$tree/etc/frp-auto-deploy/pki" "$tree/etc/frp" \
    "$tree/var/lib/frp-auto-deploy" \
    "$tree/usr/local/bin" "$tree/usr/local/lib/frp-auto-deploy" \
    "$tree/usr/local/sbin" "$tree/etc/systemd/system"
  cat >"$tree/usr/local/bin/frps" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "--version" ]] && echo "0.71.0"
exit 0
EOF
  chmod 0755 "$tree/usr/local/bin/frps"
  printf 'token\n' >"$tree/etc/frp/server_token"
  printf 'ca\n' >"$tree/etc/frp-auto-deploy/pki/ca.crt"
  printf 'bindPort = 7000\n' >"$tree/etc/frp/frps.toml"
  cat >"$tree/etc/frp-auto-deploy/config.json" <<'EOF'
{
  "public_host": "server.example",
  "deployment_mode": "single443",
  "frp_control_public_port": 443,
  "frp_control_listen_port": 7000,
  "allocator_listen_port": 6099,
  "allocator_public_url": "https://server.example/enroll"
}
EOF
  printf '{"schema_version":2,"reserved":[6000],"clients":{}}\n' \
    >"$tree/var/lib/frp-auto-deploy/registry.json"
  cat >"$tree/etc/frp-auto-deploy/version" <<EOF
PROJECT_VERSION=2.0.0
FRP_VERSION=0.71.0
RELEASE_CHANNEL=stable
SOURCE_REF=v${PROJECT_VERSION}
EOF
}

TREE="$WORKDIR/tree"
setup_tree "$TREE"
BEFORE="$(find "$TREE" -type f -exec sha256sum {} + | sort)"
TREE_CHANNEL="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/release-manifest.json"))["channel"])')"
env FRP_SERVER_TEST_ROOT="$TREE" FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
  bash "$ROOT/dist/bootstrap-server.sh" --upgrade --check \
  >"$WORKDIR/bundle-check.out" 2>"$WORKDIR/bundle-check.err" || fail "bundle --check"
grep -q 'State mutation             : NO' "$WORKDIR/bundle-check.out" || fail "bundle check report"
AFTER="$(find "$TREE" -type f -exec sha256sum {} + | sort)"
[[ "$BEFORE" == "$AFTER" ]] || fail "bundle --check mutated the tree"
pass "REAL_BUNDLE_CHECK_ONLY"

# Installed updater --check against the real generated bundle via curl mock.
FIX="$WORKDIR/fix"
MOCK="$WORKDIR/mockbin"
mkdir -p "$FIX" "$MOCK"
cp "$ROOT/dist/bootstrap-server.sh" "$FIX/bootstrap-server.sh"
printf '%s  dist/bootstrap-server.sh\n' "$(sha256sum "$FIX/bootstrap-server.sh" | awk '{print $1}')" \
  >"$FIX/SHA256SUMS"
cat >"$MOCK/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
out=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://fixture.invalid/SHA256SUMS) cp "$FRP_TEST_FIXTURE/SHA256SUMS" "$out" ;;
  https://fixture.invalid/bootstrap-server.sh) cp "$FRP_TEST_FIXTURE/bootstrap-server.sh" "$out" ;;
  *) echo "unexpected $url" >&2; exit 22 ;;
esac
EOF
chmod 0755 "$MOCK/curl"
REMOTE="$WORKDIR/remote"
setup_tree "$REMOTE"
mkdir -p "$REMOTE/usr/local/sbin" "$REMOTE/usr/local/lib/frp-auto-deploy"
cp "$ROOT/tools/frp-project-update" "$REMOTE/usr/local/sbin/frp-project-update"
cp "$ROOT/lib/frp-common.sh" "$REMOTE/usr/local/lib/frp-auto-deploy/frp-common.sh"
BEFORE2="$(find "$REMOTE" -type f -exec sha256sum {} + | sort)"
env PATH="$MOCK:$PATH" FRP_TEST_FIXTURE="$FIX" FRP_SERVER_TEST_ROOT="$REMOTE" \
  FRP_RELEASE_CHANNEL="$TREE_CHANNEL" \
  FRP_SERVER_PROJECT_SHA256SUMS_URL=https://fixture.invalid/SHA256SUMS \
  FRP_SERVER_PROJECT_UPDATE_URL=https://fixture.invalid/bootstrap-server.sh \
  "$ROOT/tools/frp-project-update" --check \
  >"$WORKDIR/installed-check.out" 2>"$WORKDIR/installed-check.err" || fail "installed --check"
grep -q 'State mutation             : NO' "$WORKDIR/installed-check.out" || fail "installed check report"
AFTER2="$(find "$REMOTE" -type f -exec sha256sum {} + | sort)"
[[ "$BEFORE2" == "$AFTER2" ]] || fail "installed --check mutated"
pass "REAL_BUNDLE_PROJECT_UPDATE"

echo "REAL_BUNDLE_PROJECT_UPDATE_TEST=PASS"
