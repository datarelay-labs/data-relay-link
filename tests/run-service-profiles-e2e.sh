#!/usr/bin/env bash
# Targeted Real E2E for Service Profiles.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
SERVER="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
CLIENT_HOST="${FRP_PROFILES_E2E_CLIENT:-${FRP_ACCESS_E2E_CLIENT:-frp-e2e-aws}}"
OUT_DIR="${FRP_PROFILES_E2E_OUT:-$ROOT/e2e-reports/service-profiles-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"
exec > >(tee -a "$OUT_DIR/run.log") 2>&1

pass(){ echo "PASS $1"; }
fail(){ echo "FAIL $1" >&2; echo "TARGETED_REAL_E2E=FAIL" >"$OUT_DIR/result.env"; exit 1; }
blocker(){ echo "ENVIRONMENT_BLOCKER $1" >&2; echo "TARGETED_REAL_E2E=ENVIRONMENT_BLOCKER" >"$OUT_DIR/result.env"; exit 2; }
sshx(){ local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$h" "$@"; }

echo "=== Service Profiles targeted Real E2E ==="
sshx "$SERVER" 'echo ok' >/dev/null || blocker "server unreachable"
sshx "$CLIENT_HOST" 'echo ok' >/dev/null || blocker "client unreachable"

# Deploy latest profile tooling to server/client from this worktree (project files only).
deploy_file() {
  local host="$1" src="$2" dest="$3" mode="${4:-755}"
  scp "${SSH_OPTS[@]}" "$src" "$host:/tmp/frp-profiles-upload.$$" >/dev/null
  sshx "$host" "sudo install -m $mode /tmp/frp-profiles-upload.$$ '$dest' && rm -f /tmp/frp-profiles-upload.$$"
}

deploy_file "$SERVER" "$ROOT/lib/frp_service_profiles.py" /usr/local/lib/drlink/frp_service_profiles.py 644
deploy_file "$SERVER" "$ROOT/lib/frp_health_check.py" /usr/local/lib/drlink/frp_health_check.py 644
deploy_file "$SERVER" "$ROOT/tools/frp-profile" /usr/local/sbin/frp-profile 755
deploy_file "$SERVER" "$ROOT/lib/frp_ctl_grammar.py" /usr/local/lib/drlink/frp_ctl_grammar.py 644
deploy_file "$SERVER" "$ROOT/tools/frpctl" /usr/local/lib/drlink/frpctl 755
deploy_file "$SERVER" "$ROOT/tools/drlink" /usr/local/bin/drlink 755
deploy_file "$SERVER" "$ROOT/server/frp-port-allocator.py" /usr/local/lib/drlink/frp-port-allocator.py 644
deploy_file "$CLIENT_HOST" "$ROOT/lib/frp_service_profiles.py" /usr/local/lib/drlink/frp_service_profiles.py 644
deploy_file "$CLIENT_HOST" "$ROOT/lib/frp_health_check.py" /usr/local/lib/drlink/frp_health_check.py 644
deploy_file "$CLIENT_HOST" "$ROOT/tools/frp-client" /usr/local/sbin/frp-client 755
deploy_file "$CLIENT_HOST" "$ROOT/lib/frp_ctl_grammar.py" /usr/local/lib/drlink/frp_ctl_grammar.py 644
deploy_file "$CLIENT_HOST" "$ROOT/tools/frpctl" /usr/local/lib/drlink/frpctl 755
deploy_file "$CLIENT_HOST" "$ROOT/tools/drlink" /usr/local/bin/drlink 755

# Ensure empty profiles file exists on server.
sshx "$SERVER" 'sudo python3 - <<'\''PY'\''
import importlib.util, json
from pathlib import Path
cfg=json.loads(Path("/etc/drlink/config.json").read_text())
cfg.setdefault("service_profiles_file", "/var/lib/drlink/service-profiles.json")
Path("/etc/drlink/config.json").write_text(json.dumps(cfg, indent=2)+"\n")
spec=importlib.util.spec_from_file_location("frp_service_profiles","/usr/local/lib/drlink/frp_service_profiles.py")
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
path=mod.service_profiles_path(cfg)
if not path.is_file():
    mod.save_profiles_state(mod.empty_profiles_state(), path=path, cfg=cfg)
print(path)
PY'
# Restart allocator so GET /v1/profiles is available.
sshx "$SERVER" 'sudo systemctl restart drlink-allocator && sleep 1 && systemctl is-active drlink-allocator' \
  || fail "allocator restart"

# Shared e2e clients may retain Target Health fixtures whose health target is down.
# Apply waits for "start proxy success", which FRP withholds while health checks fail.
sshx "$CLIENT_HOST" 'sudo python3 - <<'\''PY'\''
import json, os, signal, socket, subprocess, time
from pathlib import Path

def port_open(port: int) -> bool:
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()

state_path = Path("/etc/frp/client-state.json")
ports = set()
if state_path.is_file():
    state = json.loads(state_path.read_text())
    for item in (state.get("services") or {}).values():
        hc = item.get("health_check") if isinstance(item, dict) else None
        if not isinstance(hc, dict):
            continue
        if str(hc.get("type") or "").lower() != "http":
            continue
        try:
            ports.add(int(item.get("local_port")))
        except (TypeError, ValueError):
            pass

stub = Path("/tmp/frp-e2e-health-stub.py")
stub.write_text(
    "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
    "import sys\n"
    "port = int(sys.argv[1])\n"
    "class H(BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        self.send_response(200)\n"
    "        self.end_headers()\n"
    "        self.wfile.write(b\"ok\\n\")\n"
    "    def log_message(self, *args):\n"
    "        pass\n"
    "HTTPServer((\"127.0.0.1\", port), H).serve_forever()\n"
)
for port in sorted(ports):
    if port_open(port):
        continue
    log = f"/tmp/frp-e2e-health-stub-{port}.log"
    subprocess.Popen(
        ["python3", str(stub), str(port)],
        stdout=open(log, "ab"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    for _ in range(20):
        if port_open(port):
            break
        time.sleep(0.1)
    else:
        raise SystemExit(f"failed to start health stub on {port}")
print("health_stub_ports=%s" % (",".join(str(p) for p in sorted(ports)) or "none"))
PY' || fail "health stub for existing http health checks"

PROFILE_NAME="e2e-ssh-profile-$$"
SERVICE_ID="e2eprofssh$$"
SERVICE_ID2="e2eprofssh2$$"

# Cleanup leftovers from prior runs.
sshx "$SERVER" "sudo drlink delete profile '$PROFILE_NAME' >/dev/null 2>&1 || true"
sshx "$CLIENT_HOST" "sudo drlink discard >/dev/null 2>&1 || true"

sshx "$SERVER" "sudo drlink create profile '$PROFILE_NAME' --preset ssh --target-host 127.0.0.1 --target-port 22 --ssh-user ubuntu --description e2e" \
  | tee "$OUT_DIR/01-create-profile.log" \
  | grep -q 'Created profile prof_' || fail "create profile"
pass "create SSH profile"

# Resolve client machine id on server.
CLIENT_ID="$(sshx "$SERVER" "sudo python3 - <<'PY'
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/drlink/registry.json').read_text())
want=None
for mid,c in (reg.get('clients') or {}).items():
  label=str((c or {}).get('label') or '')
  host=str((c or {}).get('hostname') or '')
  if 'al2' in label.lower() or 'al2023' in label.lower() or 'aws' in label.lower() or host.startswith('ip-'):
    want=mid; break
if not want and reg.get('clients'):
  want=next(iter(reg['clients']))
print(want or 'NOTFOUND')
PY")"
[[ "$CLIENT_ID" != "NOTFOUND" && -n "$CLIENT_ID" ]] || blocker "no enrolled client found"
echo "CLIENT_ID=$CLIENT_ID"

# Drop prior fixed-id leftovers and this run's ids if present.
for sid in e2eprofssh e2eprofssh2 "$SERVICE_ID" "$SERVICE_ID2"; do
  sshx "$SERVER" "printf 'RELEASE\n' | sudo drlink release service --force '$CLIENT_ID' '$sid' >/dev/null 2>&1 || true"
done
sshx "$CLIENT_HOST" "sudo drlink discard >/dev/null 2>&1 || true"
# Keep client.toml aligned if a prior run left stale proxies after a failed apply.
sshx "$CLIENT_HOST" 'sudo bash -s' <<'EOF' >/dev/null || true
set -euo pipefail
. /usr/local/lib/drlink/frp-client-common.sh
path="$(frp_client_state_path)"
python3 - "$path" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
st = json.loads(path.read_text())
svcs = st.get("services") or {}
changed = False
for sid in list(svcs):
    if sid.startswith("e2eprofssh"):
        svcs.pop(sid, None)
        changed = True
if changed:
    path.write_text(json.dumps(st, indent=2) + "\n")
print("changed=%s" % changed)
PY
token="$(frp_token_from_toml_file "$(frp_client_toml_path)" || true)"
if [[ -n "${token:-}" ]]; then
  frp_regenerate_toml_from_state "$token" || true
  frp_regenerate_access_from_state || true
  frp_client_restart || true
fi
EOF

# Seed draft on client from profile, then apply.
sshx "$CLIENT_HOST" "sudo drlink add service --profile '$PROFILE_NAME' --id '$SERVICE_ID' --name E2EProfileSSH" \
  | tee "$OUT_DIR/02-add-service.log" \
  | grep -qi 'Pending service' || fail "add service --profile"
sshx "$CLIENT_HOST" "sudo drlink apply" | tee "$OUT_DIR/03-apply.log" || fail "apply"
pass "apply profile-seeded SSH service"

# Fetch public port and verify SSH banner.
read -r PUBLIC_PORT < <(sshx "$SERVER" "sudo python3 - <<PY
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/drlink/registry.json').read_text())
c=(reg.get('clients') or {}).get('$CLIENT_ID') or {}
svc=((c.get('services') or {}).get('$SERVICE_ID') or {})
print(svc.get('remote_port') or '')
PY")
[[ -n "$PUBLIC_PORT" ]] || fail "missing remote_port after apply"
SERVER_IP="$(sshx "$SERVER" 'curl -4 -fsS --max-time 8 https://ifconfig.me')"
SERVER_IP="${SERVER_IP//[$'\r\n']/}"
echo "PUBLIC_PORT=$PUBLIC_PORT SERVER_IP=$SERVER_IP"

sshx "$CLIENT_HOST" "python3 - <<PY
import socket,sys
s=socket.socket(); s.settimeout(8)
s.connect(('$SERVER_IP', int('$PUBLIC_PORT')))
data=s.recv(64); s.close()
assert data.startswith(b'SSH-'), data
print('ALLOW_BANNER')
PY" | tee "$OUT_DIR/04-ssh-banner.log" | grep -q ALLOW_BANNER || fail "ssh connectivity"
pass "SSH connectivity via profile-created service"

# Snapshot service config, edit profile, ensure existing service unchanged.
sshx "$SERVER" "sudo python3 - <<'PY'
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/drlink/registry.json').read_text())
Path('/tmp/frp-profile-svc-before.json').write_text(json.dumps(reg, sort_keys=True))
PY"
OLD_TARGET="$(sshx "$CLIENT_HOST" "sudo python3 - <<'PY'
import json
from pathlib import Path
st=json.loads(Path('/etc/frp/client-state.json').read_text())
svc=(st.get('services') or {}).get('$SERVICE_ID') or {}
print('%s:%s' % (svc.get('local_ip'), svc.get('local_port')))
PY")"
sshx "$SERVER" "sudo drlink set profile '$PROFILE_NAME' target-port 2222" | tee "$OUT_DIR/05-edit-profile.log" || fail "edit profile"
NEW_TARGET="$(sshx "$CLIENT_HOST" "sudo python3 - <<'PY'
import json
from pathlib import Path
st=json.loads(Path('/etc/frp/client-state.json').read_text())
svc=(st.get('services') or {}).get('$SERVICE_ID') or {}
print('%s:%s' % (svc.get('local_ip'), svc.get('local_port')))
PY")"
[[ "$OLD_TARGET" == "$NEW_TARGET" ]] || fail "profile edit mutated existing service ($OLD_TARGET -> $NEW_TARGET)"
pass "profile edit leaves existing service unchanged"

# New service from edited profile gets new defaults.
sshx "$CLIENT_HOST" "sudo drlink add service --profile '$PROFILE_NAME' --id '$SERVICE_ID2' --name E2EProfileSSH2" >/dev/null
sshx "$CLIENT_HOST" "sudo python3 - <<'PY'
import json
from pathlib import Path
draft=json.loads(Path('/var/lib/drlink/client-draft.json').read_text())
svc=(draft.get('services') or {}).get('$SERVICE_ID2') or {}
assert int(svc.get('local_port') or 0)==2222, svc
print('NEW_DEFAULTS_OK')
PY" | grep -q NEW_DEFAULTS_OK || fail "new service did not pick updated profile defaults"
sshx "$CLIENT_HOST" "sudo drlink discard" >/dev/null || true
pass "new service gets updated profile defaults"

# Delete profile; existing live service remains.
sshx "$SERVER" "sudo drlink delete profile '$PROFILE_NAME'" | tee "$OUT_DIR/06-delete-profile.log" || fail "delete profile"
STILL="$(sshx "$SERVER" "sudo python3 - <<PY
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/drlink/registry.json').read_text())
c=(reg.get('clients') or {}).get('$CLIENT_ID') or {}
svc=((c.get('services') or {}).get('$SERVICE_ID') or {})
print('YES' if svc.get('remote_port') else 'NO')
PY")"
[[ "$STILL" == "YES" ]] || fail "delete profile removed live service"
pass "delete profile leaves existing service"

# Cleanup live e2e service to avoid port clutter.
sshx "$SERVER" "printf 'RELEASE\n' | sudo drlink release service --force '$CLIENT_ID' '$SERVICE_ID' >/dev/null 2>&1 || true"
sshx "$SERVER" "printf 'RELEASE\n' | sudo drlink release service --force '$CLIENT_ID' '$SERVICE_ID2' >/dev/null 2>&1 || true"
sshx "$CLIENT_HOST" "sudo drlink discard >/dev/null 2>&1 || true"

echo "TARGETED_REAL_E2E=PASS" >"$OUT_DIR/result.env"
echo "SERVICE_PROFILES_REAL_E2E=PASS"
pass "service profiles targeted Real E2E"
