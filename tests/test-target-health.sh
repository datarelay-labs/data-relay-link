#!/usr/bin/env bash
# Target Health Check: persist, render, validate, status presentation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export PYTHONPATH="$ROOT/lib${PYTHONPATH:+:$PYTHONPATH}"
export FRP_CLIENT_SOURCED=1
export FRP_HEALTH_CHECK_PY="$ROOT/lib/frp_health_check.py"
# shellcheck source=../install-client.sh
. "$ROOT/install-client.sh"

python3 - <<'PY' || fail "helper validation"
import frp_health_check as HC

assert HC.normalize_health_check(None) is None
assert HC.normalize_health_check({"type": "disabled"}) is None
tcp = HC.normalize_health_check({"type": "tcp"}, required=True)
assert tcp == {
    "type": "tcp",
    "timeout_seconds": 3,
    "interval_seconds": 10,
    "max_failed": 1,
}
http = HC.default_health_check("http")
assert http["path"] == "/health"
lines = HC.health_check_toml_lines(http)
assert 'healthCheck.type = "http"' in lines
assert 'healthCheck.path = "/health"' in lines
assert HC.health_check_toml_lines(None) == []
try:
    HC.normalize_health_check({"type": "udp"})
except HC.HealthCheckError:
    pass
else:
    raise SystemExit("accepted bad type")
try:
    HC.normalize_health_check({"type": "http", "path": "health"})
except HC.HealthCheckError:
    pass
else:
    raise SystemExit("accepted bad path")
try:
    HC.normalize_health_check({"type": "tcp", "timeout_seconds": 0})
except HC.HealthCheckError:
    pass
else:
    raise SystemExit("accepted bad timeout")
item = {"local_ip": "127.0.0.1", "local_port": 1}
assert HC.target_status_label(item) == "N/A"
HC.apply_health_property(item, "health-type", "tcp")
assert item["health_check"]["type"] == "tcp"
HC.apply_health_property(item, "health-type", "disabled")
assert "health_check" not in item
print("ok")
PY
pass "helper normalize/validate/toml"

# --- TOML rendering ---
SERVICES_FILE="$WORKDIR/services.json"
cat >"$SERVICES_FILE" <<'EOF'
[
  {
    "id": "plain",
    "name": "Plain",
    "protocol": "tcp",
    "local_ip": "127.0.0.1",
    "local_port": 9001,
    "remote_port": 6101,
    "preset": "custom"
  },
  {
    "id": "tcp-hc",
    "name": "TCP HC",
    "protocol": "tcp",
    "local_ip": "127.0.0.1",
    "local_port": 9002,
    "remote_port": 6102,
    "preset": "custom",
    "health_check": {
      "type": "tcp",
      "timeout_seconds": 3,
      "interval_seconds": 10,
      "max_failed": 1
    }
  },
  {
    "id": "http-hc",
    "name": "HTTP HC",
    "protocol": "tcp",
    "local_ip": "127.0.0.1",
    "local_port": 9003,
    "remote_port": 6103,
    "preset": "custom",
    "health_check": {
      "type": "http",
      "timeout_seconds": 5,
      "interval_seconds": 15,
      "max_failed": 2,
      "path": "/ready"
    }
  }
]
EOF

TOML="$WORKDIR/frpc.toml"
render_frpc_toml "$TOML" "203.0.113.10" "443" "dummy-token" "host-abcd" "$SERVICES_FILE"
python3 - "$TOML" <<'PY' || fail "toml healthCheck render"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
assert text.count("[[proxies]]") == 3
plain = text[text.index('name = "host-abcd-plain"'):text.index('name = "host-abcd-tcp-hc"')]
assert "healthCheck" not in plain
tcp = text[text.index('name = "host-abcd-tcp-hc"'):text.index('name = "host-abcd-http-hc"')]
assert 'healthCheck.type = "tcp"' in tcp
assert "healthCheck.timeoutSeconds = 3" in tcp
assert "healthCheck.intervalSeconds = 10" in tcp
assert "healthCheck.maxFailed = 1" in tcp
assert "healthCheck.path" not in tcp
http = text[text.index('name = "host-abcd-http-hc"'):]
assert 'healthCheck.type = "http"' in http
assert 'healthCheck.path = "/ready"' in http
assert "healthCheck.timeoutSeconds = 5" in http
PY
pass "toml tcp/http/disabled"

# --- write/read persistence ---
STATE="$WORKDIR/client-state.json"
frp_write_client_state "$STATE" "https://example.test/enroll" "203.0.113.10" \
  "7000" "testhost" "mid-health-001" "host-abcd" "$SERVICES_FILE" "tcp" ""
python3 - "$STATE" <<'PY' || fail "state persistence"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
svcs = state["services"]
assert "health_check" not in svcs["plain"]
assert svcs["tcp-hc"]["health_check"]["type"] == "tcp"
assert svcs["http-hc"]["health_check"]["path"] == "/ready"
assert "health_check" not in json.dumps({"x": svcs["plain"]})
print("ok")
PY
pass "write_client_state preserves health_check"

# --- set service props via frp-client ---
export FRP_CLIENT_TEST_ROOT="$WORKDIR/client-root"
mkdir -p \
  "$FRP_CLIENT_TEST_ROOT/etc/frp" \
  "$FRP_CLIENT_TEST_ROOT/var/lib/drlink" \
  "$FRP_CLIENT_TEST_ROOT/usr/local/lib/drlink"
cp "$ROOT/lib/frp_health_check.py" "$FRP_CLIENT_TEST_ROOT/usr/local/lib/drlink/"
cp "$ROOT/lib/frp-client-common.sh" "$FRP_CLIENT_TEST_ROOT/usr/local/lib/drlink/"
python3 - "$STATE" "$FRP_CLIENT_TEST_ROOT/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
src, dest = Path(sys.argv[1]), Path(sys.argv[2])
state = json.loads(src.read_text())
plain = state["services"]["plain"]
tcp = state["services"]["tcp-hc"]
state["services"] = {"plain": plain, "tcp-hc": tcp}
dest.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
PY

export FRP_SKIP_SYSTEMD=1
export FRP_SKIP_CONNECTIVITY_CHECK=1
DRAFT="$FRP_CLIENT_TEST_ROOT/var/lib/drlink/client-draft.json"
CLIENT="$ROOT/tools/frp-client"
"$CLIENT" set-service plain health-type tcp >/dev/null
"$CLIENT" set-service plain health-timeout 7 >/dev/null
"$CLIENT" set-service plain health-interval 20 >/dev/null
"$CLIENT" set-service plain health-max-failed 3 >/dev/null
python3 - "$DRAFT" <<'PY' || fail "set service health props"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
hc = state["services"]["plain"]["health_check"]
assert hc["type"] == "tcp"
assert hc["timeout_seconds"] == 7
assert hc["interval_seconds"] == 20
assert hc["max_failed"] == 3
print("ok")
PY
pass "set service health props persist in pending"

# Validation rejects
if "$CLIENT" set-service plain health-type udp >/dev/null 2>"$WORKDIR/bad-type.err"; then
  fail "bad health-type accepted"
fi
grep -qi 'health type\|invalid' "$WORKDIR/bad-type.err" || fail "bad type message"
"$CLIENT" set-service plain health-type http >/dev/null
if "$CLIENT" set-service plain health-path "ready" >/dev/null 2>"$WORKDIR/bad-path.err"; then
  fail "bad health-path accepted"
fi
grep -qi 'path' "$WORKDIR/bad-path.err" || fail "bad path message"
if "$CLIENT" set-service plain health-timeout 0 >/dev/null 2>"$WORKDIR/bad-to.err"; then
  fail "bad timeout accepted"
fi
pass "validation rejects bad type/path/timeout"

# disable/enable preserves health_check
"$CLIENT" set-service plain health-type http >/dev/null
"$CLIENT" set-service plain health-path /healthz >/dev/null
python3 - "$DRAFT" <<'PY' || fail "draft http health"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
hc = state["services"]["plain"]["health_check"]
assert hc["type"] == "http" and hc["path"] == "/healthz"
print("ok")
PY
"$CLIENT" disable-service plain >/dev/null
python3 - "$DRAFT" <<'PY' || fail "disable preserved health"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
plain = state["services"]["plain"]
assert plain.get("enabled") is False
assert plain["health_check"]["type"] == "http"
assert plain["health_check"]["path"] == "/healthz"
print("ok")
PY
"$CLIENT" enable-service plain >/dev/null
python3 - "$DRAFT" <<'PY' || fail "enable preserved health"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
plain = state["services"]["plain"]
assert plain.get("enabled", True) is not False
assert plain["health_check"]["path"] == "/healthz"
print("ok")
PY
pass "disable/enable preserves health_check"

# backup/restore preserves health in client-state
export FRP_CLIENT_BACKUP_KEEP=5
python3 - "$FRP_CLIENT_TEST_ROOT/etc/frp/client-state.json" "$DRAFT" <<'PY'
import json, sys
from pathlib import Path
live, draft = Path(sys.argv[1]), Path(sys.argv[2])
state = json.loads(draft.read_text())
live.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
PY
BACKUP="$(frp_backup_client_files)"
python3 - "$FRP_CLIENT_TEST_ROOT/etc/frp/client-state.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
state = json.loads(p.read_text())
state["services"]["plain"].pop("health_check", None)
p.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
PY
frp_restore_client_files "$BACKUP"
python3 - "$FRP_CLIENT_TEST_ROOT/etc/frp/client-state.json" <<'PY' || fail "backup/restore health"
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state["services"]["plain"]["health_check"]["path"] == "/healthz"
print("ok")
PY
pass "backup/restore preserves health_check"


# TARGET probe display
python3 - <<'PY' || fail "probe status labels"
import http.server, socketserver, threading, frp_health_check as HC

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args):
        pass

httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
port = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
item = {
    "local_ip": "127.0.0.1",
    "local_port": port,
    "enabled": True,
    "remote_port": 6000,
    "health_check": HC.default_health_check("http"),
}
assert HC.target_status_label(item) == "HEALTHY"
httpd.shutdown()
item["local_port"] = port  # closed
assert HC.target_status_label(item) == "UNHEALTHY"
item.pop("health_check")
assert HC.target_status_label(item) == "N/A"
assert HC.tunnel_status_label({"enabled": True, "remote_port": 1}) == "UNKNOWN"
assert HC.tunnel_status_label({"enabled": True, "remote_port": 1}, live_state="online") == "ONLINE"
assert HC.tunnel_status_label({"enabled": True, "remote_port": 1}, live_state="offline") == "OFFLINE"
assert HC.tunnel_status_label({"enabled": False, "remote_port": 1}) == "OFFLINE"
assert HC.tunnel_status_label({"enabled": True}) == "UNKNOWN"
assert HC.client_status_label("active") == "ONLINE"
assert HC.client_status_label("inactive") == "OFFLINE"
assert "DOWN" not in (HC.STATUS_UNKNOWN, HC.client_status_label("weird"))
print("ok")
PY
pass "TARGET probe HEALTHY/UNHEALTHY/N/A"

# Grammar props
python3 - "$ROOT/lib" <<'PY' || fail "grammar health props"
import sys
sys.path.insert(0, sys.argv[1])
import frp_ctl_grammar as G
ok = G.match(["set", "service", "web", "health-type", "tcp"], "client")
assert ok["status"] == "ok" and ok["property"] == "health-type"
bad = G.match(["set", "service", "web", "health-bogus", "1"], "client")
assert bad["status"] != "ok"
inc = G.match(["set", "service", "web"], "client")
assert "health-type" in inc.get("message", "")
print("ok")
PY
pass "grammar health props"

echo "ALL TARGET HEALTH CHECK TESTS PASSED"
