#!/usr/bin/env bash
# Client product update must persist the validated SOURCE_REF/SOURCE_HEAD and
# self-heal that identity on a same-bundle refresh, including rollback.
set -euo pipefail

unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT \
  FRP_CLIENT_SOURCED FRP_CLIENT_UPGRADE FRP_CLIENT_UPDATE_SOURCE \
  FRP_CLIENT_UPDATE_CHECK FRP_EXPECTED_SOURCE_REF FRP_EXPECTED_SOURCE_HEAD \
  FRP_EXPECTED_RELEASE_CHANNEL FRP_RELEASE_CHANNEL FRP_TXN_SOURCE_REF \
  FRP_BUNDLE_SHA256 FRP_CLIENT_UPGRADE_HOOK_FAIL || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
# shellcheck source=lib/frp-test-procs.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-procs.sh"
# shellcheck source=lib/frp-test-safe-copy.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/frp-test-safe-copy.sh"
frp_test_arm_cleanup

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# shellcheck disable=SC1091
. "$ROOT/VERSION"

BUNDLE="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OLD_REF="0123456789abcdef0123456789abcdef01234567"
OLD_HEAD="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
STABLE_HEAD="cccccccccccccccccccccccccccccccccccccccc"
PREVIEW_HEAD="dddddddddddddddddddddddddddddddddddddddd"
MAIN_HEAD="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
STALE_MANIFEST_HEAD="1111111111111111111111111111111111111111"
EXACT_CANDIDATE_SHA="2222222222222222222222222222222222222222"

kv() {
  awk -F= -v k="$1" '$1==k {print substr($0, index($0,"=")+1); exit}' "$2"
}

manifest_field() {
  python3 - "$1" "$2" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])
PY
}

write_client_fixture() {
  local tree="$1" channel="$2" source_ref="$3" source_head="$4" units_from="$5"
  mkdir -p "$tree/etc/frp" "$tree/etc/drlink" "$tree/usr/local/bin" \
    "$tree/usr/local/lib/drlink" "$tree/etc/systemd/system"
  cat >"$tree/usr/local/bin/frpc" <<'EOF'
#!/bin/sh
if [ "${1:-}" = verify ]; then exit 0; fi
if [ "${1:-}" = --version ]; then echo "frpc version 0.71.0"; exit 0; fi
exit 0
EOF
  chmod 0755 "$tree/usr/local/bin/frpc"
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://allocator.example.test/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "provenance-client",
    "machine_id": "aabbccddeeff00112233445566778899",
    "host_id": "provenance-client-aabbccdd",
    "services": {
        "ssh": {
            "id": "ssh", "name": "SSH", "preset": "ssh", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 6003,
            "enabled": True, "ssh_user": "aella",
        },
    },
}, indent=2, sort_keys=True) + "\n")
PY
  chmod 0600 "$tree/etc/frp/client-state.json"
  cat >"$tree/etc/frp/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"

[[proxies]]
name = "provenance-client-aabbccdd-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6003
EOF
  chmod 0600 "$tree/etc/frp/frpc.toml"
  python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
    "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.pub"
  python3 - "$tree/etc/frp/client-identity.mac" <<'PY'
from pathlib import Path
Path(__import__("sys").argv[1]).write_text("a" * 64 + "\n")
PY
  chmod 0600 "$tree/etc/frp/client-identity.key" "$tree/etc/frp/client-identity.mac"
  chmod 0644 "$tree/etc/frp/client-identity.pub"
  printf 'allocator-ca\n' >"$tree/etc/drlink/allocator-ca.crt"
  cat >"$tree/etc/drlink/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=0.71.0
RELEASE_CHANNEL=${channel}
SOURCE_REF=${source_ref}
SOURCE_HEAD=${source_head}
BUNDLE_SHA256=${BUNDLE}
EOF
  chmod 0644 "$tree/etc/drlink/version"
  # Matching unit bytes keep this refresh on the provenance path alone.
  cp "$units_from/client/drlink-client.service" "$tree/etc/systemd/system/drlink-client.service"
  cp "$units_from/client/drlink-ai-agent.service" "$tree/etc/systemd/system/drlink-ai-agent.service"
}

rewrite_manifest() {
  local source="$1" channel="$2" git_ref="$3" source_head="$4"
  python3 - "$source/release-manifest.json" "$channel" "$git_ref" "$source_head" <<'PY'
import json, sys
from pathlib import Path
path, channel, git_ref, source_head = sys.argv[1:]
data = json.loads(Path(path).read_text(encoding="utf-8"))
data["channel"] = channel
data["git_ref"] = git_ref
data["source_head"] = source_head
data["immutable_source_ref"] = git_ref
Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
}

run_upgrade() {
  local tree="$1" source="$2" mode="$3"
  shift 3
  env -u FRP_CLIENT_UPDATE_SOURCE -u FRP_CLIENT_UPGRADE_HOOK_FAIL \
    -u FRP_EXPECTED_SOURCE_REF -u FRP_EXPECTED_SOURCE_HEAD \
    -u FRP_EXPECTED_RELEASE_CHANNEL -u FRP_RELEASE_CHANNEL \
    -u FRP_TXN_SOURCE_REF \
    FRP_CLIENT_TEST_ROOT="$tree" \
    FRP_SKIP_SYSTEMD=1 \
    FRP_SKIP_DOWNLOAD=1 \
    FRP_BUNDLE_SHA256="$BUNDLE" \
    "$@" \
    bash "$source/install-client.sh" --upgrade $mode
}

assert_state_preserved() {
  local tree="$1"
  python3 - "$tree/etc/frp/client-state.json" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["machine_id"] == "aabbccddeeff00112233445566778899"
assert state["services"]["ssh"]["remote_port"] == 6003
PY
}

assert_healed() {
  local tree="$1" channel="$2" source_ref="$3" source_head="$4"
  local version="$tree/etc/drlink/version"
  [[ "$(kv RELEASE_CHANNEL "$version")" == "$channel" ]] || fail "channel $tree"
  [[ "$(kv SOURCE_REF "$version")" == "$source_ref" ]] || fail "source ref $tree got $(kv SOURCE_REF "$version")"
  [[ "$(kv SOURCE_HEAD "$version")" == "$source_head" ]] || fail "source head $tree got $(kv SOURCE_HEAD "$version")"
  [[ "$(kv BUNDLE_SHA256 "$version")" == "$BUNDLE" ]] || fail "bundle sha $tree"
  assert_state_preserved "$tree"
}

assert_idempotent() {
  local tree="$1" source="$2" label="$3"
  shift 3
  local before after
  before="$(sha256sum "$tree/etc/drlink/version" | awk '{print $1}')"
  run_upgrade "$tree" "$source" --check "$@" >"$WORKDIR/${label}-check2.out"
  grep -q 'Update                    : not needed' "$WORKDIR/${label}-check2.out" || fail "$label second check"
  run_upgrade "$tree" "$source" "" "$@" >"$WORKDIR/${label}-apply2.out"
  grep -q 'Update                    : not needed' "$WORKDIR/${label}-apply2.out" || fail "$label second apply"
  after="$(sha256sum "$tree/etc/drlink/version" | awk '{print $1}')"
  [[ "$before" == "$after" ]] || fail "$label second apply rewrote version"
}

# Exact candidate SHA: same bundle, stale older SOURCE_REF/SOURCE_HEAD.
EXACT_REF="$(manifest_field "$ROOT/release-manifest.json" git_ref)"
EXACT_HEAD="$(manifest_field "$ROOT/release-manifest.json" source_head)"
[[ "$EXACT_REF" =~ ^[0-9a-fA-F]{40}$ ]] || fail "repo git_ref is not an exact SHA"
[[ "$EXACT_HEAD" =~ ^[0-9a-fA-F]{40}$ ]] || fail "repo source_head is not an exact SHA"
[[ "$OLD_REF" != "$EXACT_REF" && "$OLD_HEAD" != "$EXACT_HEAD" ]] || fail "fixture collides with candidate"

EXACT="$WORKDIR/exact"
write_client_fixture "$EXACT" development "$OLD_REF" "$OLD_HEAD" "$ROOT"
VER_BEFORE="$(sha256sum "$EXACT/etc/drlink/version" | awk '{print $1}')"
run_upgrade "$EXACT" "$ROOT" --check >"$WORKDIR/exact-check.out"
grep -q 'Update                    : available' "$WORKDIR/exact-check.out" || fail "stale provenance check"
[[ "$(sha256sum "$EXACT/etc/drlink/version" | awk '{print $1}')" == "$VER_BEFORE" ]] || fail "check mutated version"
[[ "$(kv SOURCE_REF "$EXACT/etc/drlink/version")" == "$OLD_REF" ]] || fail "check changed source ref"
run_upgrade "$EXACT" "$ROOT" "" >"$WORKDIR/exact-apply.out"
grep -q 'Upgrade complete.' "$WORKDIR/exact-apply.out" || fail "exact apply"
assert_healed "$EXACT" development "$EXACT_REF" "$EXACT_HEAD"
assert_idempotent "$EXACT" "$ROOT" exact
pass "EXACT_SHA_SAME_BUNDLE_PROVENANCE_SELF_HEAL"
pass "EXACT_SHA_SECOND_RUN_IDEMPOTENT"

ROLL="$WORKDIR/rollback"
write_client_fixture "$ROLL" development "$OLD_REF" "$OLD_HEAD" "$ROOT"
if env -u FRP_CLIENT_UPDATE_SOURCE \
  -u FRP_EXPECTED_SOURCE_REF -u FRP_EXPECTED_SOURCE_HEAD \
  -u FRP_EXPECTED_RELEASE_CHANNEL -u FRP_RELEASE_CHANNEL \
  FRP_CLIENT_TEST_ROOT="$ROLL" \
  FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_BUNDLE_SHA256="$BUNDLE" \
  FRP_CLIENT_UPGRADE_HOOK_FAIL=after-mgmt-origin \
  bash "$ROOT/install-client.sh" --upgrade >"$WORKDIR/rollback.out" 2>"$WORKDIR/rollback.err"; then
  fail "post-version failure should roll back"
fi
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/rollback.out" "$WORKDIR/rollback.err" || fail "rollback marker"
[[ "$(kv SOURCE_REF "$ROLL/etc/drlink/version")" == "$OLD_REF" ]] || fail "rollback lost source ref"
[[ "$(kv SOURCE_HEAD "$ROLL/etc/drlink/version")" == "$OLD_HEAD" ]] || fail "rollback lost source head"
[[ "$(kv BUNDLE_SHA256 "$ROLL/etc/drlink/version")" == "$BUNDLE" ]] || fail "rollback lost bundle"
[[ ! -f "$ROLL/var/lib/drlink/client-update-pending.json" ]] || fail "rollback left pending marker"
assert_state_preserved "$ROLL"
pass "PROVENANCE_ROLLBACK_RESTORES_PRIOR_IDENTITY"

SRC="$WORKDIR/src"
frp_test_copy_repo_tree "$ROOT" "$SRC"

# Exact expected SHA must win over a stale development manifest. git_ref=main
# and source_head are both different from the candidate that was validated.
[[ "$EXACT_CANDIDATE_SHA" != "$STALE_MANIFEST_HEAD" ]] || fail "mismatch fixture collapsed"
rewrite_manifest "$SRC" development main "$STALE_MANIFEST_HEAD"
MISMATCH="$WORKDIR/mismatch"
write_client_fixture "$MISMATCH" development "$OLD_REF" "$OLD_HEAD" "$SRC"
run_upgrade "$MISMATCH" "$SRC" --check \
  FRP_EXPECTED_RELEASE_CHANNEL=development \
  FRP_EXPECTED_SOURCE_REF="$EXACT_CANDIDATE_SHA" \
  >"$WORKDIR/mismatch-check.out"
grep -q 'Update                    : available' "$WORKDIR/mismatch-check.out" || fail "mismatch check"
[[ "$(kv SOURCE_REF "$MISMATCH/etc/drlink/version")" == "$OLD_REF" ]] || fail "mismatch check changed ref"
run_upgrade "$MISMATCH" "$SRC" "" \
  FRP_EXPECTED_RELEASE_CHANNEL=development \
  FRP_EXPECTED_SOURCE_REF="$EXACT_CANDIDATE_SHA" \
  >"$WORKDIR/mismatch-apply.out"
grep -q 'Upgrade complete.' "$WORKDIR/mismatch-apply.out" || fail "mismatch apply"
assert_healed "$MISMATCH" development "$EXACT_CANDIDATE_SHA" "$EXACT_CANDIDATE_SHA"
[[ "$(kv SOURCE_HEAD "$MISMATCH/etc/drlink/version")" != "$STALE_MANIFEST_HEAD" ]] || fail "stale manifest head persisted"
assert_idempotent "$MISMATCH" "$SRC" mismatch \
  FRP_EXPECTED_RELEASE_CHANNEL=development \
  FRP_EXPECTED_SOURCE_REF="$EXACT_CANDIDATE_SHA"
pass "EXACT_SHA_PRECEDES_STALE_MANIFEST_SOURCE_HEAD"
pass "EXACT_SHA_MISMATCH_SECOND_RUN_IDEMPOTENT"

MISMATCH_ROLL="$WORKDIR/mismatch-rollback"
write_client_fixture "$MISMATCH_ROLL" development "$OLD_REF" "$OLD_HEAD" "$SRC"
if env -u FRP_CLIENT_UPDATE_SOURCE \
  -u FRP_EXPECTED_SOURCE_HEAD -u FRP_RELEASE_CHANNEL \
  FRP_CLIENT_TEST_ROOT="$MISMATCH_ROLL" \
  FRP_SKIP_SYSTEMD=1 FRP_SKIP_DOWNLOAD=1 \
  FRP_BUNDLE_SHA256="$BUNDLE" \
  FRP_EXPECTED_RELEASE_CHANNEL=development \
  FRP_EXPECTED_SOURCE_REF="$EXACT_CANDIDATE_SHA" \
  FRP_CLIENT_UPGRADE_HOOK_FAIL=after-mgmt-origin \
  bash "$SRC/install-client.sh" --upgrade \
  >"$WORKDIR/mismatch-rollback.out" 2>"$WORKDIR/mismatch-rollback.err"; then
  fail "mismatch post-version failure should roll back"
fi
grep -q 'UPGRADE_ROLLBACK=PASS' "$WORKDIR/mismatch-rollback.out" "$WORKDIR/mismatch-rollback.err" || fail "mismatch rollback marker"
[[ "$(kv SOURCE_REF "$MISMATCH_ROLL/etc/drlink/version")" == "$OLD_REF" ]] || fail "mismatch rollback lost source ref"
[[ "$(kv SOURCE_HEAD "$MISMATCH_ROLL/etc/drlink/version")" == "$OLD_HEAD" ]] || fail "mismatch rollback lost source head"
assert_state_preserved "$MISMATCH_ROLL"
pass "EXACT_SHA_MISMATCH_ROLLBACK_RESTORES_PRIOR_IDENTITY"

rewrite_manifest "$SRC" stable "v${PROJECT_VERSION}" "$STABLE_HEAD"
STABLE="$WORKDIR/stable"
write_client_fixture "$STABLE" stable "$OLD_REF" "$OLD_HEAD" "$SRC"
run_upgrade "$STABLE" "$SRC" "" \
  FRP_EXPECTED_RELEASE_CHANNEL=stable \
  FRP_EXPECTED_SOURCE_REF="v${PROJECT_VERSION}" \
  >"$WORKDIR/stable-apply.out"
assert_healed "$STABLE" stable "v${PROJECT_VERSION}" "$STABLE_HEAD"
assert_idempotent "$STABLE" "$SRC" stable \
  FRP_EXPECTED_RELEASE_CHANNEL=stable \
  FRP_EXPECTED_SOURCE_REF="v${PROJECT_VERSION}"
pass "STABLE_TAG_REF_AND_SOURCE_HEAD"

rewrite_manifest "$SRC" preview "v${PROJECT_VERSION}-rc.1" "$PREVIEW_HEAD"
PREVIEW="$WORKDIR/preview"
write_client_fixture "$PREVIEW" preview "$OLD_REF" "$OLD_HEAD" "$SRC"
run_upgrade "$PREVIEW" "$SRC" "" \
  FRP_EXPECTED_RELEASE_CHANNEL=preview \
  FRP_EXPECTED_SOURCE_REF="v${PROJECT_VERSION}-rc.1" \
  >"$WORKDIR/preview-apply.out"
assert_healed "$PREVIEW" preview "v${PROJECT_VERSION}-rc.1" "$PREVIEW_HEAD"
assert_idempotent "$PREVIEW" "$SRC" preview \
  FRP_EXPECTED_RELEASE_CHANNEL=preview \
  FRP_EXPECTED_SOURCE_REF="v${PROJECT_VERSION}-rc.1"
pass "PREVIEW_RC_REF_AND_SOURCE_HEAD"

rewrite_manifest "$SRC" development main "$MAIN_HEAD"
MAIN="$WORKDIR/main"
write_client_fixture "$MAIN" development "$OLD_REF" "$OLD_HEAD" "$SRC"
run_upgrade "$MAIN" "$SRC" "" \
  FRP_EXPECTED_RELEASE_CHANNEL=development \
  FRP_EXPECTED_SOURCE_REF=main \
  >"$WORKDIR/main-apply.out"
assert_healed "$MAIN" development main "$MAIN_HEAD"
assert_idempotent "$MAIN" "$SRC" main \
  FRP_EXPECTED_RELEASE_CHANNEL=development \
  FRP_EXPECTED_SOURCE_REF=main
pass "DEVELOPMENT_MAIN_REF_AND_SOURCE_HEAD"

echo "CLIENT_UPGRADE_PROVENANCE_TEST=PASS"
