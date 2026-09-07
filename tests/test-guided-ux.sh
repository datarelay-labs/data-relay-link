#!/usr/bin/env bash
# First-time guided installer / frp-client prompt coverage.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'frp_reset_test_input; rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_CLIENT_SOURCED=1
export FRP_SKIP_CONNECTIVITY_CHECK=1
export FRP_SSH_USER=aella
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"

need() {
  local file="$1" needle="$2" label="$3"
  grep -q "$needle" "$file" || fail "$label (missing: $needle)"
}

# --- Guidance text ----------------------------------------------------------
frp_ux_print_all_guidance >"$WORKDIR/guide.out"
need "$WORKDIR/guide.out" 'Enrollment Code' 'enrollment heading'
need "$WORKDIR/guide.out" 'sudo frp-create-client' 'enrollment source command'
need "$WORKDIR/guide.out" 'short-lived' 'short-lived enrollment'
need "$WORKDIR/guide.out" 'not stored' 'code not stored'
need "$WORKDIR/guide.out" 'not the FRP token' 'not the FRP token'
need "$WORKDIR/guide.out" 'Press Enter to accept the default' 'bracket defaults'
need "$WORKDIR/guide.out" 'Service ID' 'service id heading'
need "$WORKDIR/guide.out" 'lowercase and case-insensitive' 'service id case'
need "$WORKDIR/guide.out" 'public port' 'service id persistence'
need "$WORKDIR/guide.out" 'Target host' 'target host heading'
need "$WORKDIR/guide.out" '127.0.0.1' 'local target example'
need "$WORKDIR/guide.out" 'another reachable internal IP' 'remote internal target'
need "$WORKDIR/guide.out" 'Target port' 'target port heading'
need "$WORKDIR/guide.out" 'Standard SSH uses port 22' 'ssh port help'
need "$WORKDIR/guide.out" 'Standard HTTP uses port 80' 'http port help'
need "$WORKDIR/guide.out" 'Standard HTTPS uses port 443' 'https port help'
need "$WORKDIR/guide.out" 'Grafana' 'custom port examples'
need "$WORKDIR/guide.out" 'SSH user' 'ssh user heading'
need "$WORKDIR/guide.out" 'does NOT create an operating-system account' 'ssh user metadata'
need "$WORKDIR/guide.out" 'without terminating TLS' 'https passthrough'
need "$WORKDIR/guide.out" 'Custom TCP' 'custom tcp type'
need "$WORKDIR/guide.out" 'SSH is optional' 'ssh optional'
need "$WORKDIR/guide.out" 'assigned automatically by the FRP server' 'auto public port'
need "$WORKDIR/guide.out" 'one or more services' 'multiple services'
pass "guided field explanations"

# --- Defaults: SSH / HTTP / HTTPS ------------------------------------------
run_preset() {
  local input="$1" outfile="$2"
  frp_reset_test_input
  export FRP_CLIENT_TEST_INPUT="$input"
  local payload=""
  frp_ux_prompt_new_service payload >"$WORKDIR/preset.out" 2>"$WORKDIR/preset.err"
  printf '%s\n' "$payload" >"$outfile"
  unset FRP_CLIENT_TEST_INPUT
  frp_reset_test_input
}

run_preset $'1\n\n\n\n\n' "$WORKDIR/ssh.json"
python3 - "$WORKDIR/ssh.json" <<'PY' || fail "ssh defaults"
import json,sys
p=json.loads(open(sys.argv[1]).read())
assert p['id']=='ssh', p
assert p['preset']=='ssh'
assert p['local_ip']=='127.0.0.1'
assert int(p['local_port'])==22
assert p['ssh_user']=='aella'
PY
pass "SSH defaults accepted by Enter"

run_preset $'2\n\n\n\n' "$WORKDIR/http.json"
python3 - "$WORKDIR/http.json" <<'PY' || fail "http defaults"
import json,sys
p=json.loads(open(sys.argv[1]).read())
assert p['id']=='http', p
assert p['preset']=='http'
assert p['local_ip']=='127.0.0.1'
assert int(p['local_port'])==80
PY
pass "HTTP defaults accepted by Enter"

run_preset $'3\n\n\n\n' "$WORKDIR/https.json"
python3 - "$WORKDIR/https.json" <<'PY' || fail "https defaults"
import json,sys
p=json.loads(open(sys.argv[1]).read())
assert p['id']=='https', p
assert p['preset']=='https'
assert p['local_ip']=='127.0.0.1'
assert int(p['local_port'])==443
PY
pass "HTTPS defaults accepted by Enter"

run_preset $'4\ngrafana\nGrafana\n\n3000\n' "$WORKDIR/custom.json"
python3 - "$WORKDIR/custom.json" <<'PY' || fail "custom tcp"
import json,sys
p=json.loads(open(sys.argv[1]).read())
assert p['id']=='grafana', p
assert p['name']=='Grafana'
assert p['preset']=='custom'
assert p['local_ip']=='127.0.0.1'
assert int(p['local_port'])==3000
PY
pass "Custom TCP prompt"

# --- Zero services cannot install ------------------------------------------
SERVICES_FILE="$WORKDIR/services.json"
services_init
frp_reset_test_input
export FRP_CLIENT_TEST_INPUT=$'3\n4\n'
if collect_services_interactive >"$WORKDIR/zero.out" 2>"$WORKDIR/zero.err"; then
  fail "zero-service install should not succeed"
fi
grep -q 'at least one service must be configured' "$WORKDIR/zero.err" "$WORKDIR/zero.out" || fail "zero-service error"
unset FRP_CLIENT_TEST_INPUT
frp_reset_test_input
pass "zero services cannot install"

# --- Install confirmation: No returns to menu ------------------------------
SERVICES_FILE="$WORKDIR/services.json"
services_init
frp_reset_test_input
# empty menu -> default add; SSH with defaults; Install; No; Cancel
export FRP_CLIENT_TEST_INPUT=$'\n1\n\n\n\n\n3\nn\n4\n'
if collect_services_interactive >"$WORKDIR/noconfirm.out" 2>"$WORKDIR/noconfirm.err"; then
  fail "cancel after No should exit non-zero"
fi
grep -q 'Ready to install' "$WORKDIR/noconfirm.out" || fail "install summary missing"
grep -q 'assigned automatically' "$WORKDIR/noconfirm.out" || fail "auto port on summary"
grep -q 'Returning to the service configuration menu' "$WORKDIR/noconfirm.out" || fail "No did not return to menu"
[[ "$(services_count)" == "1" ]] || fail "No should keep configured services"
unset FRP_CLIENT_TEST_INPUT
frp_reset_test_input
pass "install confirmation No returns to menu"

# --- Install confirmation Yes proceeds -------------------------------------
SERVICES_FILE="$WORKDIR/services.json"
services_init
frp_reset_test_input
export FRP_CLIENT_TEST_INPUT=$'\n1\n\n\n\n\n3\nY\n'
if ! collect_services_interactive >"$WORKDIR/yes.out" 2>"$WORKDIR/yes.err"; then
  fail "Yes should complete collect_services_interactive"
fi
grep -q 'Ready to install' "$WORKDIR/yes.out" || fail "summary before yes"
grep -q 'install FRP v0.71.0' "$WORKDIR/yes.out" || fail "frp version in summary"
grep -q 'Public port : assigned automatically' "$WORKDIR/yes.out" || fail "public port automatic"
[[ "$(services_count)" == "1" ]] || fail "yes count"
python3 - "$SERVICES_FILE" <<'PY' || fail "yes ssh payload"
import json,sys
data=json.loads(open(sys.argv[1]).read())
assert data[0]['id']=='ssh'
assert data[0]['local_ip']=='127.0.0.1'
assert int(data[0]['local_port'])==22
PY
unset FRP_CLIENT_TEST_INPUT
frp_reset_test_input
pass "install confirmation Yes proceeds"

# --- Completion screen -----------------------------------------------------
cat >"$WORKDIR/done-services.json" <<'EOF'
[{"id":"ssh","name":"SSH","preset":"ssh","local_ip":"127.0.0.1","local_port":22,"remote_port":6002,"ssh_user":"aella"}]
EOF
print_complete "203.0.113.10" "$WORKDIR/done-services.json" >"$WORKDIR/complete.out"
need "$WORKDIR/complete.out" 'FRP Installation Complete' 'complete header'
need "$WORKDIR/complete.out" 'Your FRP client is running successfully' 'success line'
need "$WORKDIR/complete.out" 'Local target : 127.0.0.1:22' 'complete target'
need "$WORKDIR/complete.out" 'Public port  : 6002' 'complete public'
need "$WORKDIR/complete.out" 'ssh -p 6002 aella@203.0.113.10' 'complete ssh'
need "$WORKDIR/complete.out" 'sudo frpctl' 'complete frpctl'
need "$WORKDIR/complete.out" 'sudo frp-client' 'complete manage'
need "$WORKDIR/complete.out" 'sudo frp-client status' 'complete status'
need "$WORKDIR/complete.out" 'sudo frp-client info' 'complete info'
pass "installation complete screen"

# --- Apply summary ---------------------------------------------------------
python3 - "$WORKDIR" <<'PY'
import json, sys
from pathlib import Path
wd = Path(sys.argv[1])
cur = {
  "schema_version": 1,
  "frp_server": "203.0.113.10",
  "services": {
    "ssh": {"id":"ssh","local_ip":"127.0.0.1","local_port":22,"remote_port":6002,"enabled":True,"preset":"ssh"}
  }
}
cand = json.loads(json.dumps(cur))
cand["services"]["grafana"] = {"id":"grafana","local_ip":"127.0.0.1","local_port":3000,"enabled":True,"preset":"custom"}
(wd/"cur.json").write_text(json.dumps(cur)+"\n")
(wd/"cand.json").write_text(json.dumps(cand)+"\n")
PY
frp_ux_print_apply_summary "$WORKDIR/cur.json" "$WORKDIR/cand.json" >"$WORKDIR/apply.out"
need "$WORKDIR/apply.out" 'Ready to apply' 'apply heading'
need "$WORKDIR/apply.out" '+ grafana' 'pending add'
need "$WORKDIR/apply.out" 'public port: assigned automatically' 'apply auto port'
need "$WORKDIR/apply.out" 'will restart the FRP client' 'restart warning'
pass "apply confirmation summary"

python3 - "$WORKDIR" <<'PY'
import json, sys
from pathlib import Path
wd = Path(sys.argv[1])
cur = {
  "schema_version": 1,
  "frp_server": "203.0.113.10",
  "services": {
    "ssh": {"id":"ssh","name":"SSH","local_ip":"127.0.0.1","local_port":22,"remote_port":6002,"enabled":True,"preset":"ssh","ssh_user":"aella"}
  }
}
cand = json.loads(json.dumps(cur))
cand["services"]["ssh"]["name"] = "ssh"
(wd/"name-cur.json").write_text(json.dumps(cur)+"\n")
(wd/"name-cand.json").write_text(json.dumps(cand)+"\n")
PY
frp_state_diff "$WORKDIR/name-cur.json" "$WORKDIR/name-cand.json" >"$WORKDIR/name-pending.out"
frp_ux_print_apply_summary "$WORKDIR/name-cur.json" "$WORKDIR/name-cand.json" >"$WORKDIR/name-apply.out"
need "$WORKDIR/name-pending.out" 'Display name: SSH -> ssh' 'pending name'
need "$WORKDIR/name-apply.out" 'Display name: SSH -> ssh' 'apply name'
if grep -A2 '^Changes:' "$WORKDIR/name-apply.out" | grep -q '(none)'; then
  fail "apply Changes=(none) for a name-only pending change"
fi
need "$WORKDIR/name-apply.out" 'local connection information only' 'local-only apply copy'
pass "pending and apply diffs agree for name-only"

echo
echo "GUIDED_UX_TEST=PASS"
