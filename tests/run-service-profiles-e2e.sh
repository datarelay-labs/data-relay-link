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

deploy_file "$SERVER" "$ROOT/lib/frp_service_profiles.py" /usr/local/lib/frp-auto-deploy/frp_service_profiles.py 644
deploy_file "$SERVER" "$ROOT/tools/frp-profile" /usr/local/sbin/frp-profile 755
deploy_file "$SERVER" "$ROOT/lib/frp_ctl_grammar.py" /usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py 644
deploy_file "$SERVER" "$ROOT/tools/frpctl" /usr/local/sbin/frpctl 755
deploy_file "$SERVER" "$ROOT/server/frp-port-allocator.py" /usr/local/lib/frp-auto-deploy/frp-port-allocator.py 644
deploy_file "$CLIENT_HOST" "$ROOT/lib/frp_service_profiles.py" /usr/local/lib/frp-auto-deploy/frp_service_profiles.py 644
deploy_file "$CLIENT_HOST" "$ROOT/tools/frp-client" /usr/local/sbin/frp-client 755
deploy_file "$CLIENT_HOST" "$ROOT/lib/frp_ctl_grammar.py" /usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py 644
deploy_file "$CLIENT_HOST" "$ROOT/tools/frpctl" /usr/local/sbin/frpctl 755

# Ensure empty profiles file exists on server.
sshx "$SERVER" 'sudo python3 - <<'\''PY'\''
import importlib.util, json
from pathlib import Path
cfg=json.loads(Path("/etc/frp-auto-deploy/config.json").read_text())
cfg.setdefault("service_profiles_file", "/var/lib/frp-auto-deploy/service-profiles.json")
Path("/etc/frp-auto-deploy/config.json").write_text(json.dumps(cfg, indent=2)+"\n")
spec=importlib.util.spec_from_file_location("frp_service_profiles","/usr/local/lib/frp-auto-deploy/frp_service_profiles.py")
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
path=mod.service_profiles_path(cfg)
if not path.is_file():
    mod.save_profiles_state(mod.empty_profiles_state(), path=path, cfg=cfg)
print(path)
PY'
# Restart allocator so GET /v1/profiles is available.
sshx "$SERVER" 'sudo systemctl restart frp-port-allocator && sleep 1 && systemctl is-active frp-port-allocator' \
  || fail "allocator restart"

PROFILE_NAME="e2e-ssh-profile-$$"
SERVICE_ID="e2eprofssh"

# Cleanup leftovers from prior runs.
sshx "$SERVER" "sudo frpctl delete profile '$PROFILE_NAME' >/dev/null 2>&1 || true"
sshx "$CLIENT_HOST" "sudo frpctl discard >/dev/null 2>&1 || true"

sshx "$SERVER" "sudo frpctl create profile '$PROFILE_NAME' --preset ssh --target-host 127.0.0.1 --target-port 22 --ssh-user ubuntu --description e2e" \
  | tee "$OUT_DIR/01-create-profile.log" \
  | grep -q 'Created profile prof_' || fail "create profile"
pass "create SSH profile"

# Resolve client machine id on server.
CLIENT_ID="$(sshx "$SERVER" "sudo python3 - <<'PY'
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/frp-auto-deploy/registry.json').read_text())
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

# Seed draft on client from profile, then apply.
sshx "$CLIENT_HOST" "sudo frpctl add service --profile '$PROFILE_NAME' --id '$SERVICE_ID' --name E2EProfileSSH" \
  | tee "$OUT_DIR/02-add-service.log" \
  | grep -qi 'Pending service' || fail "add service --profile"
sshx "$CLIENT_HOST" "sudo frpctl apply" | tee "$OUT_DIR/03-apply.log" || fail "apply"
pass "apply profile-seeded SSH service"

# Fetch public port and verify SSH banner.
read -r PUBLIC_PORT < <(sshx "$SERVER" "sudo python3 - <<PY
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/frp-auto-deploy/registry.json').read_text())
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
reg=json.loads(Path('/var/lib/frp-auto-deploy/registry.json').read_text())
Path('/tmp/frp-profile-svc-before.json').write_text(json.dumps(reg, sort_keys=True))
PY"
OLD_TARGET="$(sshx "$CLIENT_HOST" "sudo python3 - <<'PY'
import json
from pathlib import Path
st=json.loads(Path('/etc/frp/client-state.json').read_text())
svc=(st.get('services') or {}).get('$SERVICE_ID') or {}
print('%s:%s' % (svc.get('local_ip'), svc.get('local_port')))
PY")"
sshx "$SERVER" "sudo frpctl set profile '$PROFILE_NAME' target-port 2222" | tee "$OUT_DIR/05-edit-profile.log" || fail "edit profile"
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
SERVICE_ID2="e2eprofssh2"
sshx "$CLIENT_HOST" "sudo frpctl add service --profile '$PROFILE_NAME' --id '$SERVICE_ID2' --name E2EProfileSSH2" >/dev/null
sshx "$CLIENT_HOST" "sudo python3 - <<'PY'
import json
from pathlib import Path
draft=json.loads(Path('/var/lib/frp-auto-deploy/client-draft.json').read_text())
svc=(draft.get('services') or {}).get('$SERVICE_ID2') or {}
assert int(svc.get('local_port') or 0)==2222, svc
print('NEW_DEFAULTS_OK')
PY" | grep -q NEW_DEFAULTS_OK || fail "new service did not pick updated profile defaults"
sshx "$CLIENT_HOST" "sudo frpctl discard" >/dev/null || true
pass "new service gets updated profile defaults"

# Delete profile; existing live service remains.
sshx "$SERVER" "sudo frpctl delete profile '$PROFILE_NAME'" | tee "$OUT_DIR/06-delete-profile.log" || fail "delete profile"
STILL="$(sshx "$SERVER" "sudo python3 - <<PY
import json
from pathlib import Path
reg=json.loads(Path('/var/lib/frp-auto-deploy/registry.json').read_text())
c=(reg.get('clients') or {}).get('$CLIENT_ID') or {}
svc=((c.get('services') or {}).get('$SERVICE_ID') or {})
print('YES' if svc.get('remote_port') else 'NO')
PY")"
[[ "$STILL" == "YES" ]] || fail "delete profile removed live service"
pass "delete profile leaves existing service"

# Cleanup live e2e service to avoid port clutter.
sshx "$SERVER" "sudo frpctl release service '$CLIENT_ID' '$SERVICE_ID' >/dev/null 2>&1 || true"
sshx "$CLIENT_HOST" "sudo frpctl discard >/dev/null 2>&1 || true"

echo "TARGETED_REAL_E2E=PASS" >"$OUT_DIR/result.env"
echo "SERVICE_PROFILES_REAL_E2E=PASS"
pass "service profiles targeted Real E2E"
