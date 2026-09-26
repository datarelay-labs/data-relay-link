#!/usr/bin/env bash
# Canonical CLI information architecture + discovery parity (v2.4.0).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/lib${PYTHONPATH:+:$PYTHONPATH}"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- SERVER / AGENT ROOT DOMAINS ---
SERVER_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_guided_menu("server"))
PY
)"
for label in "Managed Hosts" "Network Objects" "Service Objects" "Remote Access" "Internet Access" "AI Access" System Help Exit; do
  echo "$SERVER_MENU" | grep -q "$label" || fail "server menu missing $label"
done
! echo "$SERVER_MENU" | grep -q 'Controlled Egress' || fail "NO_CONTROLLED_EGRESS_ROOT"
! echo "$SERVER_MENU" | grep -qE '(^|[[:space:]])Clients([[:space:]]|$)' || fail "NO_CLIENTS_ROOT"
! echo "$SERVER_MENU" | grep -q 'Organize' || fail "NO_ORGANIZE_ROOT"
! echo "$SERVER_MENU" | grep -q 'Operate' || fail "NO_OPERATE_ROOT"
pass SERVER_ROOT_DOMAINS

CLIENT_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_guided_menu("client"))
PY
)"
for label in "Remote Services" Agent Configuration System Help Exit; do
  echo "$CLIENT_MENU" | grep -q "$label" || fail "agent menu missing $label"
done
! echo "$CLIENT_MENU" | grep -q 'Clients' || fail "agent menu must not show Clients"
! echo "$CLIENT_MENU" | grep -q 'Internet Access' || fail "agent menu must not show Internet Access"
# Diagnostics/Status live under System (not competing root entries).
SYSTEM_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_navigation_menu("client.system"))
PY
)"
for label in Status Diagnostics "Support Bundle" "Version Information" Updates; do
  echo "$SYSTEM_MENU" | grep -q "$label" || fail "agent System menu missing $label"
done
pass CLIENT_ROOT_DOMAINS

BOTH_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_guided_menu("both"))
PY
)"
echo "$BOTH_MENU" | grep -q 'Managed Hosts' || fail "dual-role must use server domain root"
! echo "$BOTH_MENU" | grep -q 'Client operations' || fail "dual-role must not split Client/Server ops"
pass DUAL_ROLE_SERVER_DOMAIN_ROOT

# --- ROOT ? / help domain-oriented ---
QMARK="$(python3 - <<'PY'
import frp_ctl_grammar as g
print(g.context_help([], "server"))
PY
)"
echo "$QMARK" | grep -q '^show$' || fail "bare ? missing show"
echo "$QMARK" | grep -q '^set$' || fail "bare ? missing set"
echo "$QMARK" | grep -q '^system$' || fail "bare ? missing system"
! echo "$QMARK" | grep -qE '^Available:$' || fail "bare ? still flat Available dump"
! echo "$QMARK" | grep -qE '^View$' || fail "bare ? View heading"
! echo "$QMARK" | grep -q 'create' || fail "bare ? leaked create"
pass ROOT_QUESTION_MARK_NOT_FLAT_ACTION_DUMP

HELP="$(python3 - <<'PY'
import frp_ctl_grammar as g
print(g.help_text([], "server"))
PY
)"
for topic in "managed-hosts" "network-objects" "remote-access" internet-access ai-access system commands; do
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
echo "$SHOW_CTX" | grep -q 'Managed Hosts' || fail "show ? missing Managed Hosts group"
echo "$SHOW_CTX" | grep -q 'Remote Access' || fail "show ? missing Remote Access group"
echo "$SHOW_CTX" | grep -q 'Internet Access' || fail "show ? missing Internet Access group"
echo "$SHOW_CTX" | grep -q 'AI Access' || fail "show ? missing AI Access group"
echo "$SHOW_CTX" | grep -q 'System' || fail "show ? missing System group"
pass CONTEXT_CANDIDATES_GROUPED

TAB_FMT="$(python3 - <<'PY'
import frp_ctl_grammar as g
cands = g.completion_candidates("show ", "server", [], {}, [], trailing=True)
print(g.format_tab_candidates("show ", cands, "server"))
PY
)"
echo "$TAB_FMT" | grep -q 'Managed Hosts' || fail "show Tab missing Managed Hosts group"
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

# --- Beginner descriptions on Remote Access / Internet Access ---
REMOTE_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_navigation_menu("server.remote", title="Remote Access"))
PY
)"
echo "$REMOTE_MENU" | grep -qE 'Rules|Create Remote Access' || fail "remote missing rules"
echo "$REMOTE_MENU" | grep -q 'Test' || fail "remote missing test"
! echo "$REMOTE_MENU" | grep -q 'Published Services' || fail "remote must not advertise Published Services"
! echo "$REMOTE_MENU" | grep -q 'Service Presets' || fail "remote must not advertise Service Presets"
pass REMOTE_ACCESS_MENU

INTERNET_MENU="$(python3 - <<'PY'
import frp_cli_catalog as c
print(c.render_navigation_menu("server.internet", title="Internet Access"))
PY
)"
echo "$INTERNET_MENU" | grep -qE 'Rules|Create Internet Access' || fail "internet missing rules"
echo "$INTERNET_MENU" | grep -q 'Test' || fail "internet missing test"
! echo "$INTERNET_MENU" | grep -q 'Controlled Egress' || fail "internet menu leaked Controlled Egress"
pass INTERNET_ACCESS_BEGINNER_DESCRIPTIONS

# --- Network Groups workflow is wired ---
python3 - <<'PY' || fail "NETWORK_GROUPS_MENU"
import frp_cli_catalog as c
labels = [e[1] for e in c.navigation_entries("server.network_objects")]
assert any("Network Group" in x for x in labels), labels
print("ok")
PY
pass NETWORK_GROUPS_MENU

# --- Guided identity banner is not repeated every submenu ---
grep -q 'shown_identity' tools/frpctl || fail "nav loop missing one-shot identity banner gate"
pass SUBMENU_VERSION_BANNER_NOT_REPEATED

# --- PRODUCT_MASTER IA contract ---
grep -q 'CLI Information Architecture' docs/PRODUCT_MASTER.md \
  || fail "PRODUCT_MASTER missing IA section"
grep -q 'Internet Access' docs/PRODUCT_MASTER.md || fail "PRODUCT_MASTER missing Internet Access"
grep -q 'DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md' docs/PRODUCT_MASTER.md \
  || fail "PRODUCT_MASTER missing CLI/AI Master SSOT"
grep -q 'Managed Hosts' docs/PRODUCT_MASTER.md || fail "PRODUCT_MASTER missing Managed Hosts"
grep -q 'help commands' docs/CLI_REFERENCE.md || fail "CLI_REFERENCE missing help commands"
! grep -qE '^access list$' docs/CLI_REFERENCE.md || fail "CLI_REFERENCE still teaches access list"
! grep -q 'Root \`?\` lists resources' docs/CLI_REFERENCE.md \
  || fail "CLI_REFERENCE stale root ? claim"
pass DOCS_IA_CONTRACT

echo "ALL CLI INFORMATION ARCHITECTURE CHECKS PASSED"
