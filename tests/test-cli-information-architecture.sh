#!/usr/bin/env bash
# Canonical CLI information architecture + discovery parity (v2.4.0).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/lib${PYTHONPATH:+:$PYTHONPATH}"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- SERVER / CLIENT ROOT DOMAINS ---
SERVER_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_guided_menu("server"))
PY
)"
for label in Clients Services "Internet Access" System Help Exit; do
  echo "$SERVER_MENU" | grep -q "$label" || fail "server menu missing $label"
done
! echo "$SERVER_MENU" | grep -q 'Remote Access' || fail "NO_REMOTE_ACCESS_ROOT"
! echo "$SERVER_MENU" | grep -q 'Controlled Egress' || fail "NO_CONTROLLED_EGRESS_ROOT"
! echo "$SERVER_MENU" | grep -q 'Organize' || fail "NO_ORGANIZE_ROOT"
! echo "$SERVER_MENU" | grep -q 'Operate' || fail "NO_OPERATE_ROOT"
pass SERVER_ROOT_DOMAINS

CLIENT_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_guided_menu("client"))
PY
)"
for label in Services System Help Exit; do
  echo "$CLIENT_MENU" | grep -q "$label" || fail "client menu missing $label"
done
! echo "$CLIENT_MENU" | grep -q 'Clients' || fail "client menu must not show Clients"
! echo "$CLIENT_MENU" | grep -q 'Internet Access' || fail "client menu must not show Internet Access"
pass CLIENT_ROOT_DOMAINS

BOTH_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_guided_menu("both"))
PY
)"
echo "$BOTH_MENU" | grep -q 'Clients' || fail "dual-role must use server domain root"
! echo "$BOTH_MENU" | grep -q 'Client operations' || fail "dual-role must not split Client/Server ops"
pass DUAL_ROLE_SERVER_DOMAIN_ROOT

# --- ROOT ? / help domain-oriented ---
QMARK="$(python3 - <<'PY'
import frp_ctl_grammar as g
print(g.context_help([], "server"))
PY
)"
echo "$QMARK" | grep -q 'Work areas' || fail "bare ? missing Work areas"
echo "$QMARK" | grep -q 'Clients' || fail "bare ? missing Clients"
! echo "$QMARK" | grep -qE '^Available:$' || fail "bare ? still flat Available dump"
! echo "$QMARK" | grep -qE '^[[:space:]]*show[[:space:]]+View' || fail "bare ? flat action dump"
pass ROOT_QUESTION_MARK_NOT_FLAT_ACTION_DUMP

HELP="$(python3 - <<'PY'
import frp_ctl_grammar as g
print(g.help_text([], "server"))
PY
)"
for topic in clients services internet system commands; do
  echo "$HELP" | grep -q "help $topic" || fail "root help missing help $topic"
  text="$(python3 -c "import frp_ctl_grammar as g; print(g.help_text(['$topic'], 'server'))")"
  [[ -n "$text" ]] || fail "help $topic empty"
  echo "$text" | grep -qiE 'Unknown help topic' && fail "help $topic unknown"
done
pass HELP_DOMAIN_TOPICS

# --- help commands complete ---
python3 - <<'PY' || fail "HELP_COMMANDS_COMPLETE"
import frp_cli_catalog as c
import frp_ctl_grammar as g
text = g.help_text(["commands"], "server")
missing = []
for cmd in c.COMMANDS:
    if cmd.get("hidden"):
        continue
    if not c.role_allows(cmd["roles"], "server"):
        continue
    usage = c.usage_line(cmd)
    # usage_line may include placeholders; match the path prefix.
    path = " ".join(cmd["path"])
    if path not in text and usage not in text:
        missing.append(path)
if missing:
    raise SystemExit("missing from help commands: %s" % ", ".join(missing[:12]))
print("ok")
PY
pass HELP_COMMANDS_COMPLETE

# --- Context candidates grouped ---
SHOW_CTX="$(python3 - <<'PY'
import frp_ctl_grammar as g
print(g.context_help(["show"], "server"))
PY
)"
echo "$SHOW_CTX" | grep -q 'Clients' || fail "show ? missing Clients group"
echo "$SHOW_CTX" | grep -q 'Internet Access' || fail "show ? missing Internet Access group"
echo "$SHOW_CTX" | grep -q 'System' || fail "show ? missing System group"
pass CONTEXT_CANDIDATES_GROUPED

TAB_FMT="$(python3 - <<'PY'
import frp_ctl_grammar as g
cands = g.completion_candidates("show ", "server", [], {}, [], trailing=True)
print(g.format_tab_candidates("show ", cands, "server"))
PY
)"
echo "$TAB_FMT" | grep -q 'Clients' || fail "show Tab missing Clients group"
pass TAB_CANDIDATES_GROUPED

# --- Navigation leaves use canonical drlink commands (no frp-* targets) ---
python3 - <<'PY' || fail "NAVIGATION_LEAVES_USE_CANONICAL_DRLINK"
import frp_cli_catalog as c
bad = []
for key, entries in c.NAVIGATION_TREE.items():
    for action_id, label, desc, kind, target in entries:
        if kind == "command":
            if not target or target.startswith("frp-"):
                bad.append((key, action_id, target))
            toks = str(target).split()
            if not c.find(toks) and not c.find(toks, include_aliases=True):
                # allow bare roots like apply/discard/sync/doctor
                if toks[0] not in {r[0] for r in c.ROOTS}:
                    bad.append((key, action_id, target))
        if kind == "workflow" and target and str(target).startswith("frp-"):
            bad.append((key, action_id, target))
if bad:
    raise SystemExit(repr(bad[:10]))
print("ok")
PY
pass NAVIGATION_LEAVES_USE_CANONICAL_DRLINK

if grep -nE 'frpctl_nav_workflow|frpctl_nav_dispatch' tools/frpctl >/dev/null; then
  ! grep -E 'frpctl_run frp-(clients|enrollments|egress|groups|access|backup)( |$)' tools/frpctl \
    | grep -v '^[[:space:]]*#' \
    | grep -E 'frpctl_nav_|server_menu|client_menu' >/dev/null \
    || true
fi
# Menu walker must not shell out to backend names as leaf targets.
! grep -n "frpctl_run frp-" tools/frpctl | grep -E 'nav_workflow|nav_dispatch' \
  || fail "MENU_BACKEND_BYPASS"
pass MENU_BACKEND_BYPASS_NO

# --- Public command discovery parity ---
python3 - <<'PY' || fail "PUBLIC_COMMAND_DISCOVERY_PARITY"
import frp_cli_catalog as c
import frp_ctl_grammar as g

help_text = g.help_text(["commands"], "server")
missing_parse = []
missing_tab = []
missing_help = []
for cmd in c.COMMANDS:
    if cmd.get("hidden"):
        continue
    if not c.role_allows(cmd["roles"], "server"):
        continue
    path = list(cmd["path"])
    # Parseable: match accepts the path prefix (may be incomplete if args required).
    result = g.match(path, "server", names=["24cd7856"])
    status = result.get("status")
    if status not in ("ok", "incomplete"):
        missing_parse.append((" ".join(path), status, result.get("message")))
    # Tab-discoverable: each path token appears among candidates at that depth.
    for i in range(len(path)):
        prefix_line = " ".join(path[:i]) + (" " if i else "")
        cands = g.completion_candidates(
            prefix_line, "server", ["24cd7856"], {}, [], trailing=True
        )
        if path[i] not in cands:
            missing_tab.append((" ".join(path), "token", path[i], "after", prefix_line))
            break
    if " ".join(path) not in help_text:
        missing_help.append(" ".join(path))

if missing_parse or missing_tab or missing_help:
    parts = []
    if missing_parse:
        parts.append("parse=%s" % missing_parse[:5])
    if missing_tab:
        parts.append("tab=%s" % missing_tab[:5])
    if missing_help:
        parts.append("help=%s" % missing_help[:8])
    raise SystemExit("; ".join(parts))
print("PARSEABLE=YES")
print("TAB_DISCOVERABLE=YES")
print("HELP_COMMANDS_VISIBLE=YES")
PY
pass PUBLIC_COMMAND_DISCOVERY_PARITY

# --- PRODUCT_MASTER IA contract ---
grep -q 'Canonical CLI Information Architecture' docs/PRODUCT_MASTER.md \
  || fail "PRODUCT_MASTER missing IA section"
grep -q 'Internet Access' docs/PRODUCT_MASTER.md || fail "PRODUCT_MASTER missing Internet Access"
grep -q 'help commands' docs/CLI_REFERENCE.md || fail "CLI_REFERENCE missing help commands"
! grep -qE '^access list$' docs/CLI_REFERENCE.md || fail "CLI_REFERENCE still teaches access list"
! grep -q 'Root \`?\` lists resources' docs/CLI_REFERENCE.md \
  || fail "CLI_REFERENCE stale root ? claim"
pass DOCS_IA_CONTRACT

echo "ALL CLI INFORMATION ARCHITECTURE CHECKS PASSED"
