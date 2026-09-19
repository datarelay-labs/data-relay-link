#!/usr/bin/env bash
# Focused CLI UX tests: service-add grammar, auto Service IDs, wizard, apply quiet.
# Local fixtures only — no network, containers, daemons, or sleeps.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

chmod +x "$ROOT/tools/frpctl" "$ROOT/tools/frp-client"
export FRP_CTL_BIN_DIR="$ROOT/tools"
export FRP_CLIENT_LIB="$ROOT/lib/frp-client-common.sh"
export FRP_SOURCE_ROOT="$ROOT"
export FRP_SKIP_SYSTEMD=1
export HOME="$WORKDIR/home"
mkdir -p "$HOME"
unset FRP_CLIENT_TEST_INPUT FRP_CTL_TEST_INPUT FRP_CTL_DRY_RUN || true
unset _FRP_CLIENT_INPUT_READY _FRP_CLIENT_INPUT_FILE || true
unset _FRP_CTL_INPUT_READY _FRP_CTL_INPUT_FILE || true

# --- Grammar: service add ? / Tab ---
python3 - <<'PY' || fail "service add help/completion"
import sys
sys.path.insert(0, "lib")
import frp_ctl_grammar as g

help_text = g.context_help(["service", "add"], "client")
for needle in ("ssh", "http", "https", "custom", "profile", "127.0.0.1", "192.168", "service apply"):
    if needle.lower() not in help_text.lower() and needle not in help_text:
        raise SystemExit("missing in service add ?: %s" % needle)
if "generated automatically" not in help_text.lower() and "automatic" not in help_text.lower():
    raise SystemExit("missing auto ID guidance in service add ?")
# Normal help must not advertise --id
if "--id" in help_text:
    raise SystemExit("service add ? must not advertise --id")

cands = g.completion_candidates("service add ", "client", [], {}, [], trailing=True)
if cands != ["ssh", "http", "https", "custom", "profile"]:
    raise SystemExit("service add tab=%r" % cands)

ssh_flags = g.completion_candidates("service add ssh --", "client", [], {}, [], trailing=False)
if "--id" in ssh_flags:
    raise SystemExit("ssh Tab must not offer --id: %r" % ssh_flags)

http_flags = g.completion_candidates("service add http --", "client", [], {}, [], trailing=False)
if "--id" in http_flags or "--ssh-user" in http_flags:
    raise SystemExit("http Tab must not offer --id/--ssh-user: %r" % http_flags)

https_flags = g.completion_candidates("service add https --", "client", [], {}, [], trailing=False)
if "--id" in https_flags:
    raise SystemExit("https Tab must not offer --id: %r" % https_flags)

custom_flags = g.completion_candidates("service add custom --", "client", [], {}, [], trailing=False)
if "--id" in custom_flags:
    raise SystemExit("custom Tab must not offer --id: %r" % custom_flags)

adv = g.help_text(["advanced"], "client")
if "--id" not in adv:
    raise SystemExit("help advanced must document hidden --id")

root = g.canonical_verbs("client")
if "status" in root or "version" in root:
    raise SystemExit("client-only root tab must hide status/version: %r" % root)
for need in ("show", "service", "client", "system", "help", "menu", "exit"):
    if need not in root:
        raise SystemExit("client root missing %s" % need)

inc = g.match(["service", "set", "ssh"], "client")
msg = inc.get("message") or ""
if "service set" not in msg:
    raise SystemExit("service set incomplete must prefer canonical form")
if msg.strip().startswith("set service") or "\n  set service" in msg:
    raise SystemExit("primary usage must not teach set service")
PY
pass "SERVICE_ADD_HELP_AND_COMPLETION"

# --- Service ID helper unit ---
python3 - <<'PY' || fail "service id unit"
import sys
sys.path.insert(0, "lib")
from frp_service_id import suggest_service_id
assert suggest_service_id("ssh", []) == "ssh"
assert suggest_service_id("http", []) == "http"
assert suggest_service_id("https", []) == "https"
assert suggest_service_id("custom", [], target_port=3389) == "tcp-3389"
assert suggest_service_id("custom", [], target_port=555) == "tcp-555"
used = ["ssh", "ssh-2", "http", "https", "tcp-3389", "tcp-555"]
assert suggest_service_id("ssh", used) == "ssh-3"
assert suggest_service_id("http", used) == "http-2"
assert suggest_service_id("https", used) == "https-2"
assert suggest_service_id("custom", used, target_port=3389) == "tcp-3389-2"
assert suggest_service_id("custom", used, target_port=555) == "tcp-555-2"
PY
pass "SERVICE_ID_UNIT"

# --- wait_for_proxies must quiet-match (no journal dump on success) ---
if ! grep -n 'start proxy success' "$ROOT/lib/frp-client-common.sh" | grep -q 'grep -qF'; then
  fail "wait_for_proxies must use quiet grep -qF"
fi
pass "APPLY_PROXY_MATCH_QUIET"

# --- frp-client auto ID + bare add + explicit override ---
CLIENT="$WORKDIR/client"
mkdir -p "$CLIENT/etc/frp" "$CLIENT/var/lib/frp-auto-deploy" \
  "$CLIENT/usr/local/lib/frp-auto-deploy"
cp "$ROOT/lib/frp_service_id.py" "$CLIENT/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_health_check.py" "$CLIENT/usr/local/lib/frp-auto-deploy/"
python3 - "$CLIENT/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://127.0.0.1:9/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "cli-ux",
    "machine_id": "00112233445566778899aabbccddeeff",
    "host_id": "cli-ux-00112233",
    "services": {},
}, indent=2, sort_keys=True) + "\n")
PY

export FRP_CLIENT_TEST_ROOT="$CLIENT"
export FRP_CTL_TEST_ROOT="$CLIENT"

set +e
"$ROOT/tools/frp-client" add-service </dev/null >"$WORKDIR/bare.out" 2>"$WORKDIR/bare.err"
bare_rc=$?
set -e
[[ "$bare_rc" -eq 2 ]] || fail "bare add non-tty rc=$bare_rc"
grep -q 'Missing service type' "$WORKDIR/bare.err" || fail "bare add usage"
grep -q 'service add' "$WORKDIR/bare.err" || fail "bare add example"
if grep -qi 'id is required' "$WORKDIR/bare.err" "$WORKDIR/bare.out"; then
  fail "bare add must not require --id"
fi
pass "BARE_ADD_NON_TTY"

# Non-interactive automation still works with explicit fields
"$ROOT/tools/frp-client" add-service ssh --ssh-user aella >"$WORKDIR/add1.out"
grep -q "Pending service 'ssh' added" "$WORKDIR/add1.out" || fail "first ssh id"
grep -q 'service apply' "$WORKDIR/add1.out" || fail "apply guidance"
"$ROOT/tools/frp-client" add-service ssh --ssh-user root >"$WORKDIR/add2.out"
grep -q "Pending service 'ssh-2' added" "$WORKDIR/add2.out" || fail "second ssh id"
"$ROOT/tools/frp-client" add-service http --target-host 127.0.0.1 --target-port 80 >"$WORKDIR/add-http.out"
grep -q "Pending service 'http' added" "$WORKDIR/add-http.out" || fail "http id"
"$ROOT/tools/frp-client" add-service https --target-host 127.0.0.1 --target-port 443 >"$WORKDIR/add-https.out"
grep -q "Pending service 'https' added" "$WORKDIR/add-https.out" || fail "https id"
"$ROOT/tools/frp-client" add-service custom --target-port 555 >"$WORKDIR/add-custom.out"
grep -q "Pending service 'tcp-555' added" "$WORKDIR/add-custom.out" || fail "custom id"
"$ROOT/tools/frp-client" add-service ssh --id special-ssh --ssh-user aella >"$WORKDIR/add-spec.out"
grep -q "Pending service 'special-ssh' added" "$WORKDIR/add-spec.out" || fail "explicit id"
pass "SERVICE_ID_AUTO_AND_OVERRIDE"

# Fixture with collisions including pending draft
python3 - "$CLIENT/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://127.0.0.1:9/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "cli-ux",
    "machine_id": "00112233445566778899aabbccddeeff",
    "host_id": "cli-ux-00112233",
    "services": {
        "ssh": {"id":"ssh","name":"SSH","preset":"ssh","protocol":"tcp",
                "local_ip":"127.0.0.1","local_port":22,"enabled":True,"ssh_user":"a"},
        "ssh-2": {"id":"ssh-2","name":"SSH","preset":"ssh","protocol":"tcp",
                  "local_ip":"127.0.0.1","local_port":22,"enabled":True,"ssh_user":"b"},
        "http": {"id":"http","name":"HTTP","preset":"http","protocol":"tcp",
                 "local_ip":"127.0.0.1","local_port":80,"enabled":True},
        "https": {"id":"https","name":"HTTPS","preset":"https","protocol":"tcp",
                  "local_ip":"127.0.0.1","local_port":443,"enabled":True},
        "tcp-555": {"id":"tcp-555","name":"TCP 555","preset":"custom","protocol":"tcp",
                    "local_ip":"127.0.0.1","local_port":555,"enabled":True},
        "tcp-3389": {"id":"tcp-3389","name":"RDP","preset":"custom","protocol":"tcp",
                     "local_ip":"127.0.0.1","local_port":3389,"enabled":True},
    },
}, indent=2, sort_keys=True) + "\n")
PY
rm -f "$CLIENT/var/lib/frp-auto-deploy/client-draft.json"
"$ROOT/tools/frp-client" add-service ssh --ssh-user c >"$WORKDIR/add3.out"
grep -q "Pending service 'ssh-3' added" "$WORKDIR/add3.out" || fail "ssh-3 after collisions"
"$ROOT/tools/frp-client" add-service http --target-port 80 >"$WORKDIR/add-http2.out"
grep -q "Pending service 'http-2' added" "$WORKDIR/add-http2.out" || fail "http-2"
"$ROOT/tools/frp-client" add-service https --target-port 443 >"$WORKDIR/add-https2.out"
grep -q "Pending service 'https-2' added" "$WORKDIR/add-https2.out" || fail "https-2"
"$ROOT/tools/frp-client" add-service custom --target-port 555 >"$WORKDIR/add-custom2.out"
grep -q "Pending service 'tcp-555-2' added" "$WORKDIR/add-custom2.out" || fail "tcp-555-2"
pass "SERVICE_ID_COLLISION"

# --- Wizard: bare add numeric selection owns input ---
rm -f "$CLIENT/var/lib/frp-auto-deploy/client-draft.json"
python3 - "$CLIENT/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://127.0.0.1:9/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 443,
    "hostname": "cli-ux",
    "machine_id": "00112233445566778899aabbccddeeff",
    "host_id": "cli-ux-00112233",
    "services": {},
}, indent=2, sort_keys=True) + "\n")
PY
# Invalid 9 then valid 3 (HTTPS): local defaults → confirm
export FRP_CLIENT_TEST_INPUT="$(printf '%s\n' 9 3 1 '' '' Y)"
unset _FRP_CLIENT_INPUT_READY _FRP_CLIENT_INPUT_FILE || true
"$ROOT/tools/frp-client" add-service >"$WORKDIR/wiz-bare.out" 2>"$WORKDIR/wiz-bare.err"
grep -q 'ERROR: select 1-6' "$WORKDIR/wiz-bare.err" || fail "invalid select should re-prompt"
grep -q 'HTTPS service' "$WORKDIR/wiz-bare.out" "$WORKDIR/wiz-bare.err" || fail "bare wizard chose HTTPS"
grep -q "Pending service 'https' added" "$WORKDIR/wiz-bare.out" || fail "bare wizard https pending"
python3 - "$CLIENT/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "bare wizard draft"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
s=d["services"]["https"]
assert s["local_ip"]=="127.0.0.1" and int(s["local_port"])==443
PY
pass "BARE_ADD_WIZARD_NUMERIC"

# --- Wizard: service add http enters wizard (not instant create) ---
rm -f "$CLIENT/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_TEST_INPUT="$(printf '%s\n' 1 '' '' Y)"
unset _FRP_CLIENT_INPUT_READY || true
"$ROOT/tools/frp-client" add-service http >"$WORKDIR/wiz-http.out" 2>"$WORKDIR/wiz-http.err"
grep -q 'HTTP service' "$WORKDIR/wiz-http.out" "$WORKDIR/wiz-http.err" || fail "http wizard title"
grep -q 'Where is the HTTP service' "$WORKDIR/wiz-http.err" || fail "http location prompt"
grep -q "Pending service 'http' added" "$WORKDIR/wiz-http.out" || fail "http wizard pending"
python3 - "$CLIENT/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "http local defaults"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
s=d["services"]["http"]
assert s["local_ip"]=="127.0.0.1" and int(s["local_port"])==80, s
assert s["name"]=="HTTP"
PY
if grep -q 'Service ID' "$WORKDIR/wiz-http.out"; then
  fail "wizard confirmation must not display Service ID"
fi
pass "HTTP_WIZARD_LOCAL"

# LAN HTTP
rm -f "$CLIENT/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_TEST_INPUT="$(printf '%s\n' 2 10.10.10.60 '' '' Y)"
unset _FRP_CLIENT_INPUT_READY || true
"$ROOT/tools/frp-client" add-service http >"$WORKDIR/wiz-http-lan.out" 2>"$WORKDIR/wiz-http-lan.err"
grep -q "Pending service 'http' added" "$WORKDIR/wiz-http-lan.out" || fail "lan http pending"
python3 - "$CLIENT/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "lan http draft"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
s=d["services"]["http"]
assert s["local_ip"]=="10.10.10.60" and int(s["local_port"])==80, s
PY
pass "HTTP_WIZARD_LAN"

# SSH defaults port 22
rm -f "$CLIENT/var/lib/frp-auto-deploy/client-draft.json"
unset SUDO_USER || true
export USER=root LOGNAME=root
export FRP_CLIENT_TEST_INPUT="$(printf '%s\n' 1 '' tester '' Y)"
unset _FRP_CLIENT_INPUT_READY || true
"$ROOT/tools/frp-client" add-service ssh >"$WORKDIR/wiz-ssh.out" 2>"$WORKDIR/wiz-ssh.err"
grep -q "Pending service 'ssh' added" "$WORKDIR/wiz-ssh.out" || fail "ssh wizard pending"
python3 - "$CLIENT/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "ssh defaults"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
s=d["services"]["ssh"]
assert s["local_ip"]=="127.0.0.1" and int(s["local_port"])==22, s
assert s["ssh_user"]=="tester"
PY
pass "SSH_WIZARD"

# HTTPS defaults 443
rm -f "$CLIENT/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_TEST_INPUT="$(printf '%s\n' 1 '' '' Y)"
unset _FRP_CLIENT_INPUT_READY || true
"$ROOT/tools/frp-client" add-service https >"$WORKDIR/wiz-https.out" 2>"$WORKDIR/wiz-https.err"
python3 - "$CLIENT/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "https defaults"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
s=d["services"]["https"]
assert s["local_ip"]=="127.0.0.1" and int(s["local_port"])==443, s
PY
pass "HTTPS_WIZARD"

# Custom requires port; LAN example
rm -f "$CLIENT/var/lib/frp-auto-deploy/client-draft.json"
export FRP_CLIENT_TEST_INPUT="$(printf '%s\n' 2 10.10.10.60 555 '' Y)"
unset _FRP_CLIENT_INPUT_READY || true
"$ROOT/tools/frp-client" add-service custom >"$WORKDIR/wiz-custom.out" 2>"$WORKDIR/wiz-custom.err"
grep -q "Pending service 'tcp-555' added" "$WORKDIR/wiz-custom.out" || fail "custom wizard id"
python3 - "$CLIENT/var/lib/frp-auto-deploy/client-draft.json" <<'PY' || fail "custom draft"
import json,sys
from pathlib import Path
d=json.loads(Path(sys.argv[1]).read_text())
s=d["services"]["tcp-555"]
assert s["local_ip"]=="10.10.10.60" and int(s["local_port"])==555, s
assert s["name"]=="TCP 555"
PY
pass "CUSTOM_WIZARD"

# Type-only without TTY / test input must not silently create for http
# (non-TTY automation without flags still creates — intentional compat)
"$ROOT/tools/frp-client" add-service http </dev/null >"$WORKDIR/http-nontty.out" 2>"$WORKDIR/http-nontty.err" || true
grep -q "Pending service 'http" "$WORKDIR/http-nontty.out" || fail "non-tty http automation compat"
pass "HTTP_NON_TTY_AUTOMATION_COMPAT"

unset FRP_CLIENT_TEST_INPUT
unset _FRP_CLIENT_INPUT_READY || true

# --- Canonical service set error ---
export FRP_CTL_DRY_RUN=1
set +e
"$ROOT/tools/frpctl" service set ssh >"$WORKDIR/set.out" 2>"$WORKDIR/set.err"
set_rc=$?
set -e
cat "$WORKDIR/set.out" "$WORKDIR/set.err" >"$WORKDIR/set.all"
grep -q 'Missing service property' "$WORKDIR/set.all" || fail "set missing property"
grep -q 'service set' "$WORKDIR/set.all" || fail "canonical service set"
if grep -E '^\s*set service' "$WORKDIR/set.all"; then
  fail "must not teach set service as primary"
fi
pass "SERVICE_SET_CANONICAL"

# Legacy still dispatches
"$ROOT/tools/frpctl" set service ssh target-port 2222 >"$WORKDIR/leg-set.out"
grep -qx 'DISPATCH frp-client set-service ssh target-port 2222' "$WORKDIR/leg-set.out" || fail "legacy set"
"$ROOT/tools/frpctl" service add ssh --ssh-user aella >"$WORKDIR/pos-add.out"
grep -q 'DISPATCH frp-client add-service ssh --ssh-user aella' "$WORKDIR/pos-add.out" || fail "positional add dispatch"
"$ROOT/tools/frpctl" service add --preset ssh --id web >"$WORKDIR/leg-add.out"
grep -qx 'DISPATCH frp-client add-service --preset ssh --id web' "$WORKDIR/leg-add.out" || fail "legacy flag add"
"$ROOT/tools/frpctl" service apply --verbose >"$WORKDIR/apply-v.out"
grep -qx 'DISPATCH frp-client apply-pending --verbose' "$WORKDIR/apply-v.out" || fail "apply --verbose dispatch"
pass "LEGACY_AND_POSITIONAL_DISPATCH"

# --- Menu Add uses add-service (not bare frp-client) ---
export FRP_CTL_TEST_INPUT=$'2\n1\n6\n5\n'
export FRP_CTL_DRY_RUN=1
grep -q 'frpctl_invoke frp-client add-service' "$ROOT/tools/frpctl" \
  || fail "menu add must call frp-client add-service"
if grep -nE 'frpctl_client_service_menu|frpctl_client_service_add_menu' -A20 "$ROOT/tools/frpctl" \
  | grep -E 'frpctl_run frp-client\s*$'; then
  fail "menu add must not launch bare frp-client interactive manager"
fi
pass "MENU_ADD_ALIGNED"

# --- Zero-touch auto IDs (fixture; dry-run create zero-touch) ---
SERVER="$WORKDIR/server"
mkdir -p "$SERVER/etc/frp-auto-deploy" "$SERVER/var/lib/frp-auto-deploy" \
  "$SERVER/usr/local/lib/frp-auto-deploy"
cp "$ROOT/lib/frp_service_id.py" "$SERVER/usr/local/lib/frp-auto-deploy/"
python3 - "$SERVER/etc/frp-auto-deploy/config.json" "$SERVER/var/lib/frp-auto-deploy/registry.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "public_ip": "203.0.113.10", "control_port": 443, "port_start": 6000,
    "port_end": 6098, "listen_port": 6099,
    "allocator_public_url": "https://203.0.113.10:6099/enroll",
    "registry_file": "/var/lib/frp-auto-deploy/registry.json",
}, indent=2) + "\n")
Path(sys.argv[2]).write_text(json.dumps({"schema_version": 2, "reserved": [], "clients": {}}, indent=2) + "\n")
PY
cat >"$SERVER/etc/frp-auto-deploy/version" <<'EOF'
PROJECT_VERSION=2.3.0
FRP_VERSION=0.71.0
EOF
unset FRP_CLIENT_TEST_ROOT FRP_CTL_SOURCED
export FRP_CTL_TEST_ROOT="$SERVER"
export FRP_CTL_DRY_RUN=1
# create zero-touch → Linux → Configure services → name/note → SSH,SSH,HTTP → Finish → exit
export FRP_CTL_TEST_INPUT="$(printf '%s\n' \
  'create zero-touch' 1 2 zt-auto '' \
  1 '' '' aella \
  1 '' '' root \
  2 '' '' \
  5 \
  exit)"
set +e
"$ROOT/tools/frpctl" >"$WORKDIR/zt.out" 2>"$WORKDIR/zt.err"
set -e
grep -q 'SERVICES_JSON ' "$WORKDIR/zt.out" || {
  echo "--- zt.out ---"; cat "$WORKDIR/zt.out"; echo "--- zt.err ---"; cat "$WORKDIR/zt.err"; fail "zt missing SERVICES_JSON"
}
python3 - "$WORKDIR/zt.out" <<'PY' || fail "zt auto ids content"
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"^SERVICES_JSON (.+)$", text, re.M)
items = json.loads(m.group(1))
ids = [i["id"] for i in items]
assert ids == ["ssh", "ssh-2", "http"], ids
assert "192.168" in text or "LAN" in text
if "Service ID [" in text:
    raise SystemExit("prompted for Service ID")
PY
unset FRP_CTL_TEST_INPUT
pass "ZERO_TOUCH_AUTO_IDS"

# --- Installer guidance strings ---
grep -q 'frpctl create zero-touch' "$ROOT/install-server.sh" || fail "server install zt"
grep -q 'frpctl show clients' "$ROOT/install-server.sh" || fail "server install clients"
grep -q 'frpctl doctor' "$ROOT/install-server.sh" || fail "server install doctor"
grep -q 'Everyday management' "$ROOT/install-server.sh" || fail "server everyday"
grep -q 'frpctl show services' "$ROOT/install-client.sh" || fail "client install services"
grep -q 'frpctl show info' "$ROOT/install-client.sh" || fail "client install info"
grep -q 'frpctl system update' "$ROOT/install-client.sh" || fail "client system update"
pass "INSTALLER_GUIDANCE"

# --- REPL: exit code 2 suppressed ---
python3 - <<'PY' || fail "repl exit code policy"
from pathlib import Path
text = Path("lib/frp_ctl_repl.py").read_text(encoding="utf-8")
if "proc.returncode != 2" not in text and "returncode == 2" not in text:
    # Accept equivalent policy
    if "exit code" in text and "!= 2" not in text and "not in (0, 2" not in text and "returncode != 2" not in text:
        raise SystemExit("expected rc=2 suppression")
assert "Command failed with exit code" in text
PY
pass "REPL_EXIT_CODE_POLICY"

echo "ALL CLI UX TESTS PASSED"
