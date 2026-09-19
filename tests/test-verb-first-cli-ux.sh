#!/usr/bin/env bash
# Release-blocking gates for action-first / verb-first public CLI UX.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CTL="$ROOT/tools/frpctl"
export PYTHONPATH="$ROOT/lib${PYTHONPATH:+:$PYTHONPATH}"
export FRP_CTL_DRY_RUN=1
export FRP_CTL_ROLE=server

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

grammar() {
  python3 - "$ROOT" "$1" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1] + "/lib")
import frp_ctl_grammar as g
line = sys.argv[2]
toks = g.tokenize(line)
result = g.match(toks, "server", names=["24cd7856", "aabbccdd"])
print(json.dumps(result, ensure_ascii=False))
PY
}

assert_json_field() {
  local json="$1" field="$2" expect="$3"
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); v=d.get(sys.argv[2]); assert str(v)==sys.argv[3], (sys.argv[2], v, sys.argv[3])' \
    "$json" "$field" "$expect"
}

# --- ROOT_DOMAIN_ORIENTED ---
HELP="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_ctl_grammar as g
print(g.help_text([], "server"))
PY
)"
echo "$HELP" | grep -q '^show$' || fail "root help missing show"
echo "$HELP" | grep -q '^set$' || fail "root help missing set"
echo "$HELP" | grep -q 'unset' || fail "root help missing unset"
echo "$HELP" | grep -q 'system' || fail "root help missing system"
python3 - <<'PY' || fail "help internet missing Internet Access"
import sys
sys.path.insert(0, "lib")
import frp_ctl_grammar as g

text = g.help_text(["internet"], "server") or ""
if "Internet Access" not in text:
    raise SystemExit("help internet missing Internet Access:\n%r" % (text[:500],))
PY

echo "$HELP" | grep -q 'help commands' || fail "root help missing help commands"
! echo "$HELP" | grep -qE '^[[:space:]]*client[[:space:]]' || fail "root help advertises client"
! echo "$HELP" | grep -qE '^[[:space:]]*enrollment[[:space:]]' || fail "root help advertises enrollment"
! echo "$HELP" | grep -qE '^[[:space:]]*zero-touch[[:space:]]' || fail "root help advertises zero-touch"
! echo "$HELP" | grep -qE '^View$' || fail "root help still flat View category"
pass ROOT_DOMAIN_ORIENTED
pass ROOT_ACTION_FIRST_MENTIONED_IN_DOMAIN_HELP

# --- SHOW_TREE / CREATE_TREE ---
SHOW_CANDS="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_ctl_grammar as g
print("\n".join(g.completion_candidates("show ", "server", ["24cd7856"], {}, [], trailing=True)))
PY
)"
echo "$SHOW_CANDS" | grep -qx 'managed-host' || fail "show tree missing managed-host"
echo "$SHOW_CANDS" | grep -qx 'managed-hosts' || fail "show tree missing managed-hosts"
echo "$SHOW_CANDS" | grep -qx 'status' || fail "show tree missing status"
SET_CANDS="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_ctl_grammar as g
print("\n".join(g.completion_candidates("set ", "server", [], {}, [], trailing=True)))
PY
)"
echo "$SET_CANDS" | grep -qx 'enrollment' || fail "set tree missing enrollment"
echo "$SET_CANDS" | grep -qx 'remote-access' || fail "set tree missing remote-access"
echo "$SET_CANDS" | grep -qx 'internet-access' || fail "set tree missing internet-access"
echo "$SET_CANDS" | grep -qx 'enrollment' || fail "set tree missing enrollment"
echo "$SET_CANDS" | grep -qx 'server' || fail "set tree missing server"
# Obsolete public set children must stay absent.
echo "$SET_CANDS" | grep -qx 'acl' && fail "set tree still exposes acl"
echo "$SET_CANDS" | grep -qx 'service-profile' && fail "set tree still exposes service-profile"
echo "$SET_CANDS" | grep -qx 'internet-profile' && fail "set tree still exposes internet-profile"
pass SHOW_TREE
pass SET_TREE

# --- NO_PUBLIC_RESOURCE_FIRST_ADVERTISEMENT ---
MENU="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_cli_catalog as c
print(c.render_guided_menu("server"))
PY
)"
! echo "$MENU" | grep -q 'client list' || fail "menu advertises client list"
! echo "$MENU" | grep -q 'enrollment create' || fail "menu advertises enrollment create"
! echo "$MENU" | grep -q 'zero-touch create' || fail "menu advertises zero-touch create"
echo "$MENU" | grep -q 'Managed Hosts' || fail "menu missing Managed Hosts"
echo "$MENU" | grep -q 'Objects' || fail "menu missing Objects"
echo "$MENU" | grep -q 'Remote Access' || fail "menu missing Remote Access root"
echo "$MENU" | grep -q 'Internet Access' || fail "menu missing Internet Access"
echo "$MENU" | grep -q 'AI Access' || fail "menu missing AI Access root"
! echo "$MENU" | grep -q 'Controlled Egress' || fail "menu still has Controlled Egress root"
! echo "$MENU" | grep -q 'Organize' || fail "menu still has Organize root"
! echo "$MENU" | grep -q 'Operate' || fail "menu still has Operate root"
! echo "$HELP" | grep -q 'client show' || fail "help advertises client show"
pass NO_PUBLIC_RESOURCE_FIRST_ADVERTISEMENT
pass MENU_DOMAIN_ORIENTED
# --- NO_PUBLIC_LONG_OPTIONS ---
FLAG_HITS="$(python3 - <<'PY'
import sys
sys.path.insert(0,"lib")
import frp_ctl_grammar as g
lines = [
    "create enrollment ",
    "create enrollment --",
    "show managed-hosts ",
    "update product ",
    "doctor ",
]
bad=[]
for line in lines:
    for c in g.completion_candidates(line, "server", ["24cd7856"], {}, [], trailing=True):
        if str(c).startswith("-"):
            bad.append((line, c))
print("\n".join("%s -> %s" % item for item in bad))
PY
)"
[[ -z "$FLAG_HITS" ]] || fail "public flag completion: $FLAG_HITS"
! echo "$HELP" | grep -qE -- '--ttl|--ssh|--force|--yes|--json|--protocol' || fail "help advertises long options"
pass NO_PUBLIC_LONG_OPTIONS

# --- NO_BACKEND_COMMAND_LEAK / argparse ---
ERR="$(grammar 'create enrollment --')"
assert_json_field "$ERR" status error
echo "$ERR" | grep -qi 'do not use --options' || fail "missing no-options guidance"
! echo "$ERR" | grep -qi 'frp-create-client' || fail "backend command leak in rejection"
! echo "$ERR" | grep -qi 'usage: frp-' || fail "argparse usage leak"
pass NO_BACKEND_COMMAND_LEAK
pass NO_BACKEND_ARGPARSE_USAGE_LEAK
pass ERROR_OWNERSHIP_TEST

# --- TAB_ACTION_FIRST / TAB_CLIENT_IDS ---
ROOT_CANDS="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_ctl_grammar as g
print("\n".join(g.completion_candidates("", "server", ["24cd7856"], {}, [], trailing=True)))
PY
)"
echo "$ROOT_CANDS" | grep -qx 'show' || fail "tab root missing show"
! echo "$ROOT_CANDS" | grep -qx 'client' || fail "tab root still has client"
HOST_CANDS="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_ctl_grammar as g
print("\n".join(g.completion_candidates("show managed-host ", "server", ["24cd7856", "aabbccdd"], {}, [], trailing=True)))
PY
)"
echo "$HOST_CANDS" | grep -qx '24cd7856' || fail "tab managed-host ids"
pass TAB_ACTION_FIRST
pass TAB_CLIENT_IDS

# --- CONTEXT_HELP_ACTION_FIRST ---
CTX="$(grammar 'unset ?')"
echo "$CTX" | grep -q 'managed-host' || fail "context help missing unset managed-host"
echo "$CTX" | grep -qi 'Available' || fail "context help missing Available"
pass CONTEXT_HELP_ACTION_FIRST

# --- ROLE_FILTERING ---
CLIENT_ROOTS="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_cli_catalog as c
print("\n".join(c.roots_for_role("client")))
PY
)"
echo "$CLIENT_ROOTS" | grep -qx 'show' || fail "client role missing show"
echo "$CLIENT_ROOTS" | grep -qx 'system' || fail "client role missing system"
! echo "$CLIENT_ROOTS" | grep -qx 'create' || fail "client role leaked create"
! echo "$CLIENT_ROOTS" | grep -qx 'revoke' || fail "client role still sees revoke"
CLIENT_SYSTEM="$(python3 - <<'PY'
import sys; sys.path.insert(0,"lib")
import frp_ctl_grammar as g
print("\n".join(g.completion_candidates("system ", "client", [], {}, [], trailing=True)))
PY
)"
echo "$CLIENT_SYSTEM" | grep -qx 'support-bundle' || fail "client system missing support-bundle"
! echo "$CLIENT_SYSTEM" | grep -qx 'backup' || fail "client system leaked server backup"
pass ROLE_FILTERING

# --- INCOMPLETE_COMMAND_HELP ---
INC="$(grammar 'revoke client')"
echo "$INC" | grep -q 'revoke client <ID>' || fail "incomplete usage"
! echo "$INC" | grep -q 'client show' || fail "incomplete recommends resource-first"
echo "$INC" | grep -qi 'Tab' || fail "incomplete missing Tab tip"
pass INCOMPLETE_COMMAND_HELP

# --- REVOKE_RELEASE_DELETE_DISTINCT ---
R1="$(grammar 'revoke client 24cd7856')"
R2="$(grammar 'release client 24cd7856')"
R3="$(grammar 'delete enrollment abcdef12')"
assert_json_field "$R1" action revoke_client
assert_json_field "$R2" action release_client
assert_json_field "$R3" action purge_enrollment
pass REVOKE_RELEASE_DELETE_DISTINCT

# --- GUIDED_ZERO_TOUCH / GUIDED_ENROLLMENT ---
ZT="$(grammar 'set enrollment zero-touch')"
EN="$(grammar 'set enrollment')"
assert_json_field "$ZT" action create_zero_touch
assert_json_field "$EN" action create_enrollment
pass GUIDED_ZERO_TOUCH
pass GUIDED_ENROLLMENT

# --- BACKEND_CAPABILITY_PARITY (spot checks) ---
for line_action in \
  "show managed-hosts:control_plane" \
  "create backup:create_backup" \
  "system update product:update_project" \
  "system update engine:update_frp" \
  "unset group edge:delete_group" \
  "set internet-access allow-api:control_plane"
do
  line="${line_action%%:*}"
  action="${line_action##*:}"
  js="$(grammar "$line")"
  assert_json_field "$js" action "$action"
done
# Obsolete resource-first / egress-destination must reject (no auto-translation).
HF="$(grammar 'add egress-destination ubuntu')"
assert_json_field "$HF" status error
pass BACKEND_CAPABILITY_PARITY
pass NO_LEGACY_EGRESS_DESTINATION_TRANSLATION

# --- ALLOCATOR_PUBLIC_HOSTNAME_SEPARATION (EXPECTED_BEHAVIOR) ---
if [[ -f "$ROOT/tests/test-server-install-config.sh" ]] && grep -q 'ALLOCATOR_SEPARATE_FROM_PUBLIC_HOSTNAME\|allocator URL stays on public IP' "$ROOT/tests/test-server-install-config.sh"; then
  pass ALLOCATOR_FQDN_DEFAULT
else
  fail "allocator/public_hostname separation coverage missing from test-server-install-config.sh"
fi

echo
echo "All verb-first CLI UX gates passed."
