#!/usr/bin/env bash
# Live v2.3.1 → v2.4.0 candidate upgrade qualification.
#
# Requires:
#   - e2e-reports/v2.3.1-golden-upgrade-baseline/ (evidence of prior golden capture)
#   - A release-equivalent v2.3.1 tree (default: FRP_V231_TREE or sibling checkout at 796fe55)
#   - SSH to FRP_E2E_SERVER_ALIAS (default frp-e2e-server)
#
# Flow:
#   1. Install v2.3.1 from the golden-era tree (not merely rename VERSION strings)
#   2. Seed minimal Remote Access + Egress state with stable IDs/ports
#   3. Upgrade to the current (v2.4 candidate) tree via bootstrap --upgrade
#   4. Verify identity/port/egress preservation + schema migration + new runtime
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/prod-qual-common.sh
source "$ROOT/tests/lib/prod-qual-common.sh"

OUT="${FRP_E2E_OUT_DIR:-$ROOT/e2e-reports/v231-to-v240-upgrade-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
PROD_QUAL_SUMMARY="$OUT/summary.txt"
PROD_QUAL_GATES="$OUT/gates.env"
PROD_QUAL_FAILS=0
: >"$PROD_QUAL_SUMMARY"
: >"$PROD_QUAL_GATES"

SERVER="${FRP_E2E_SERVER_ALIAS:-frp-e2e-server}"
GOLDEN="${FRP_E2E_GOLDEN_BASELINE:-$ROOT/e2e-reports/v2.3.1-golden-upgrade-baseline}"
V231_TREE="${FRP_V231_TREE:-}"
if [[ -z "$V231_TREE" ]]; then
  for cand in \
    "/home/aella/frp-auto-deploy-dev" \
    "$(dirname "$ROOT")/frp-auto-deploy-dev" \
    "$ROOT"; do
    if [[ -f "$cand/VERSION" ]] && grep -q '^PROJECT_VERSION=2\.3\.1$' "$cand/VERSION" 2>/dev/null; then
      V231_TREE="$cand"
      break
    fi
  done
fi
HEAD="$(pq_head_sha)"
PROJECT_VERSION="$(awk -F= '/^PROJECT_VERSION=/{print $2}' "$ROOT/VERSION")"
PUBLIC_HOSTNAME="${FRP_E2E_PUBLIC_HOSTNAME:-221.139.249.113.nip.io}"
PUBLIC_IP="${FRP_E2E_SERVER_IP:-221.139.249.113}"

tree_channel() {
  python3 - "$1/release-manifest.json" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
channel = str(data.get("channel") or "").strip().lower()
if channel not in ("dev", "stable"):
    raise SystemExit("unsupported release-manifest channel: %r" % channel)
print(channel)
PY
}
V231_CHANNEL="$(tree_channel "$V231_TREE")"
V240_CHANNEL="$(tree_channel "$ROOT")"

pq_note "LIVE_V231_TO_V240_UPGRADE start HEAD=$HEAD PROJECT_VERSION=$PROJECT_VERSION"
pq_note "OUT=$OUT GOLDEN=$GOLDEN V231_TREE=$V231_TREE"
pq_note "V231_CHANNEL=$V231_CHANNEL V240_CHANNEL=$V240_CHANNEL"

fail_out() {
  pq_gate LIVE_V231_TO_V240_UPGRADE FAIL
  pq_note "$*"
  exit 1
}

[[ -d "$GOLDEN" ]] || fail_out "golden baseline missing: $GOLDEN"
[[ -n "$V231_TREE" && -f "$V231_TREE/dist/bootstrap-server.sh" ]] || fail_out "v2.3.1 tree missing (set FRP_V231_TREE)"
grep -q '^PROJECT_VERSION=2\.3\.1$' "$V231_TREE/VERSION" || fail_out "FRP_V231_TREE is not PROJECT_VERSION=2.3.1"
[[ "$PROJECT_VERSION" == "2.4.0" ]] || fail_out "current tree must be PROJECT_VERSION=2.4.0 (got $PROJECT_VERSION)"

# Record golden evidence into this run
mkdir -p "$OUT/golden"
cp -a "$GOLDEN/." "$OUT/golden/" 2>/dev/null || true
pq_gate GOLDEN_BASELINE_PRESENT PASS

# --- 0) Purge existing server so starting side is a real v2.3.1 install ---
pq_note "Purging existing server install for clean v2.3.1 baseline"
set +e
pq_ssh "$SERVER" "sudo bash -s -- --purge --yes" \
  <"$ROOT/dist/uninstall-server.sh" >"$OUT/server-purge.log" 2>&1
purge_rc=$?
set -uo pipefail
# purge may return non-zero if already absent; require config gone afterward
if pq_ssh "$SERVER" 'test -f /etc/drlink/config.json'; then
  pq_gate V231_PURGE FAIL
  tail -40 "$OUT/server-purge.log" | tee -a "$PROD_QUAL_SUMMARY" || true
  fail_out "server still installed after purge (rc=$purge_rc)"
fi
pq_gate V231_PURGE PASS

# --- 1) Fresh v2.3.1 install on server ---
pq_note "Installing release-equivalent v2.3.1 from $V231_TREE (FRP_RELEASE_CHANNEL=$V231_CHANNEL)"
set +e
pq_ssh "$SERVER" "sudo env \
  FRP_PUBLIC_HOSTNAME='$PUBLIC_HOSTNAME' \
  FRP_PUBLIC_IP='$PUBLIC_IP' \
  FRP_RELEASE_CHANNEL='$V231_CHANNEL' \
  bash -s --" \
  <"$V231_TREE/dist/bootstrap-server.sh" >"$OUT/v231-install.log" 2>&1
inst_rc=$?
set -uo pipefail
if [[ "$inst_rc" -ne 0 ]]; then
  pq_gate V231_INSTALL FAIL
  tail -80 "$OUT/v231-install.log" | tee -a "$PROD_QUAL_SUMMARY" || true
  fail_out "v2.3.1 install failed rc=$inst_rc"
fi
pq_gate V231_INSTALL PASS

# Confirm installed version identity
v231_ver="$(pq_ssh "$SERVER" 'sudo cat /etc/drlink/version 2>/dev/null || true')"
printf '%s\n' "$v231_ver" >"$OUT/v231-version.txt"
if ! grep -q '2\.3\.1' <<<"$v231_ver"; then
  pq_gate V231_VERSION_IDENTITY FAIL
  fail_out "installed version file missing 2.3.1: $v231_ver"
fi
pq_gate V231_VERSION_IDENTITY PASS

# --- 2) Seed stable Remote Access + Egress state ---
pq_ssh "$SERVER" 'sudo python3 -' >"$OUT/seed.log" 2>&1 <<'PY'
import json, os, time, uuid
from pathlib import Path

reg_path = Path("/var/lib/drlink/registry.json")
eg_path = Path("/var/lib/drlink/egress-control.json")
acl_path = Path("/var/lib/drlink/access-control.json")

now = int(time.time())
machine_id = "upgrade-e2e-machine-001"
client_id = "upgclid01deadbeef"
service_id = "ssh"
remote_port = 6010

reg = {
    "schema_version": 1,
    "clients": {
        machine_id: {
            "client_id": client_id,
            "machine_id": machine_id,
            "hostname": "upgrade-e2e-client",
            "label": "v231-upgrade-seed",
            "labels": {"role": "upgrade-seed"},
            "tags": {"qual": "v231-to-v240"},
            "groups": ["upgrade-lab"],
            "notes": "seeded for live upgrade qualification",
            "services": {
                service_id: {
                    "service_id": service_id,
                    "id": service_id,
                    "remote_port": remote_port,
                    "local_port": 22,
                    "local_ip": "127.0.0.1",
                    "type": "tcp",
                    "enabled": True,
                }
            },
            "created_at": now,
            "updated_at": now,
        }
    },
}
reg_path.parent.mkdir(parents=True, exist_ok=True)
reg_path.write_text(json.dumps(reg, indent=2) + "\n", encoding="utf-8")
os.chmod(reg_path, 0o600)

# Minimal v2 egress policy (HTTP/HTTPS only; Fixed TCP arrives after upgrade migration)
eg = {
    "schema_version": 2,
    "egress_profiles": {
        "egp_upgrade_seed": {
            "id": "egp_upgrade_seed",
            "name": "upgrade-seed",
            "description": "seeded profile for upgrade",
            "enabled": False,
            "sources": [
                {
                    "id": "egs_upgrade_seed",
                    "cidr": "10.20.30.0/24",
                    "description": "lab",
                }
            ],
            "destinations": [
                {
                    "id": "egd_upgrade_seed",
                    "host": "example.com",
                    "port": 443,
                    "protocol": "https",
                    "match": "exact",
                }
            ],
            "created_at": now,
            "updated_at": now,
        }
    },
}
eg_path.write_text(json.dumps(eg, indent=2) + "\n", encoding="utf-8")
os.chmod(eg_path, 0o600)

if not acl_path.is_file():
    acl = {"schema_version": 1, "lists": {}, "bindings": {}}
    acl_path.write_text(json.dumps(acl, indent=2) + "\n", encoding="utf-8")
    os.chmod(acl_path, 0o600)

print("SEED_OK")
print(json.dumps({"client_id": client_id, "service_id": service_id, "remote_port": remote_port}))
PY
grep -q SEED_OK "$OUT/seed.log" || fail_out "state seed failed"
pq_gate V231_STATE_SEED PASS

# Pre-upgrade fingerprint
pq_ssh "$SERVER" 'sudo python3 -' >"$OUT/pre-upgrade-fingerprint.json" <<'PY'
import json
from pathlib import Path

def load(path):
    p = Path(path)
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

reg = load("/var/lib/drlink/registry.json") or {}
eg = load("/var/lib/drlink/egress-control.json") or {}
acl = load("/var/lib/drlink/access-control.json") or {}
clients = []
for mid, c in (reg.get("clients") or {}).items():
    if not isinstance(c, dict):
        continue
    services = []
    for sid, svc in (c.get("services") or {}).items():
        if isinstance(svc, dict):
            services.append({
                "service_id": sid,
                "remote_port": svc.get("remote_port"),
                "local_port": svc.get("local_port"),
            })
    clients.append({
        "machine_id": mid,
        "client_id": c.get("client_id") or c.get("id") or mid,
        "labels": c.get("labels") or {},
        "tags": c.get("tags") or {},
        "groups": c.get("groups") or c.get("group"),
        "services": services,
    })
doc = {
    "registry_schema": reg.get("schema_version"),
    "egress_schema": eg.get("schema_version"),
    "access_lists": sorted((acl.get("lists") or {}).keys()),
    "clients": clients,
    "egress_profiles": sorted((eg.get("egress_profiles") or {}).keys()),
    "tcp_relays": sorted((eg.get("tcp_relays") or {}).keys()),
    "version_file": Path("/etc/drlink/version").read_text(encoding="utf-8")
        if Path("/etc/drlink/version").is_file() else "",
}
print(json.dumps(doc, indent=2, sort_keys=True))
PY

# --- 3) Upgrade to current v2.4 tree ---
# Prefer stdin bootstrap from the candidate tree so we do not depend on an unpublished tag.
# Match FRP_RELEASE_CHANNEL to the candidate tree manifest (same rule as short-url E2E).
pq_note "Upgrading server to v2.4 candidate from current tree (FRP_RELEASE_CHANNEL=$V240_CHANNEL)"
set +e
pq_ssh "$SERVER" "sudo env \
  FRP_PUBLIC_HOSTNAME='$PUBLIC_HOSTNAME' \
  FRP_PUBLIC_IP='$PUBLIC_IP' \
  FRP_RELEASE_CHANNEL='$V240_CHANNEL' \
  bash -s -- --upgrade" \
  <"$ROOT/dist/bootstrap-server.sh" >"$OUT/server-upgrade.log" 2>&1
up_rc=$?
set -uo pipefail
if [[ "$up_rc" -ne 0 ]]; then
  pq_gate UPGRADE_SERVER FAIL
  tail -80 "$OUT/server-upgrade.log" | tee -a "$PROD_QUAL_SUMMARY" || true
  fail_out "upgrade failed rc=$up_rc"
fi
pq_gate UPGRADE_SERVER PASS

# Post-upgrade fingerprint
pq_ssh "$SERVER" 'sudo python3 -' >"$OUT/post-upgrade-fingerprint.json" <<'PY'
import json
from pathlib import Path

def load(path):
    p = Path(path)
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

reg = load("/var/lib/drlink/registry.json") or {}
eg = load("/var/lib/drlink/egress-control.json") or {}
acl = load("/var/lib/drlink/access-control.json") or {}
clients = []
for mid, c in (reg.get("clients") or {}).items():
    if not isinstance(c, dict):
        continue
    services = []
    for sid, svc in (c.get("services") or {}).items():
        if isinstance(svc, dict):
            services.append({
                "service_id": sid,
                "remote_port": svc.get("remote_port"),
                "local_port": svc.get("local_port"),
            })
    clients.append({
        "machine_id": mid,
        "client_id": c.get("client_id") or c.get("id") or mid,
        "labels": c.get("labels") or {},
        "tags": c.get("tags") or {},
        "groups": c.get("groups") or c.get("group"),
        "services": services,
    })
relays = []
for rid, r in (eg.get("tcp_relays") or {}).items():
    if isinstance(r, dict):
        relays.append({
            "id": rid,
            "name": r.get("name"),
            "listen_port": r.get("listen_port"),
            "enabled": r.get("enabled"),
        })
doc = {
    "registry_schema": reg.get("schema_version"),
    "egress_schema": eg.get("schema_version"),
    "access_lists": sorted((acl.get("lists") or {}).keys()),
    "clients": clients,
    "egress_profiles": sorted((eg.get("egress_profiles") or {}).keys()),
    "tcp_relays": relays,
    "version_file": Path("/etc/drlink/version").read_text(encoding="utf-8")
        if Path("/etc/drlink/version").is_file() else "",
    "tcp_unit": Path("/etc/systemd/system/drlink-tcp-egress.service").is_file()
        or Path("/lib/systemd/system/drlink-tcp-egress.service").is_file(),
}
print(json.dumps(doc, indent=2, sort_keys=True))
PY

python3 - "$OUT/pre-upgrade-fingerprint.json" "$OUT/post-upgrade-fingerprint.json" "$PROJECT_VERSION" <<'PY' | tee -a "$PROD_QUAL_GATES"
import json, sys
from pathlib import Path
pre = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
post = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
want_ver = sys.argv[3]
ok = True

def gate(name, cond):
    global ok
    print(f"{name}={'PASS' if cond else 'FAIL'}")
    if not cond:
        ok = False

pre_ids = sorted(c.get("client_id") for c in pre.get("clients") or [])
post_ids = sorted(c.get("client_id") for c in post.get("clients") or [])
gate("UPGRADE_CLIENT_ID_PRESERVED", pre_ids == post_ids and len(pre_ids) > 0)

def svc_map(doc):
    out = {}
    for c in doc.get("clients") or []:
        for s in c.get("services") or []:
            out[(c.get("client_id"), s.get("service_id"))] = s.get("remote_port")
    return out

gate("UPGRADE_SERVICE_ID_PRESERVED", set(svc_map(pre)) == set(svc_map(post)) and len(svc_map(pre)) > 0)
gate("UPGRADE_PUBLIC_PORT_PRESERVED", svc_map(pre) == svc_map(post))

def meta(doc):
    rows = []
    for c in doc.get("clients") or []:
        rows.append((
            c.get("client_id"),
            json.dumps(c.get("tags") or {}, sort_keys=True),
            json.dumps(c.get("groups") or c.get("group") or [], sort_keys=True, default=str),
        ))
    return sorted(rows)

gate("UPGRADE_GROUP_TAG_STATE_PRESERVED", meta(pre) == meta(post))
gate("UPGRADE_EGRESS_STATE_PRESERVED", pre.get("egress_profiles") == post.get("egress_profiles"))
gate("UPGRADE_ACCESS_STATE_PRESERVED", pre.get("access_lists") == post.get("access_lists"))
gate("UPGRADE_EGRESS_SCHEMA_V3", post.get("egress_schema") == 3)
gate("UPGRADE_VERSION_FILE", want_ver in str(post.get("version_file") or ""))
gate("UPGRADE_TCP_UNIT_PRESENT", bool(post.get("tcp_unit")))
print("COMPARE_OK=%s" % ("PASS" if ok else "FAIL"))
raise SystemExit(0 if ok else 1)
PY
up_cmp=$?

# Runtime health after upgrade
set +e
pq_ssh "$SERVER" 'sudo drlink doctor >/tmp/drlink-doctor-upgrade.txt 2>&1; sudo drlink status >/tmp/drlink-status-upgrade.txt 2>&1; systemctl is-active drlink-server drlink-allocator drlink-access drlink-egress; systemctl cat drlink-tcp-egress >/dev/null 2>&1; echo TCP_UNIT_RC=$?'
rt_rc=$?
set -uo pipefail
pq_ssh "$SERVER" 'sudo cat /tmp/drlink-doctor-upgrade.txt' >"$OUT/doctor.txt" || true
pq_ssh "$SERVER" 'sudo cat /tmp/drlink-status-upgrade.txt' >"$OUT/status.txt" || true
if [[ "$rt_rc" -eq 0 ]]; then
  pq_gate UPGRADE_RUNTIME_HEALTH PASS
else
  pq_gate UPGRADE_RUNTIME_HEALTH FAIL
  up_cmp=1
fi

# Fixed TCP feature available after upgrade (create disabled)
set +e
pq_ssh "$SERVER" 'sudo drlink egress tcp list >/tmp/tcp-list.txt 2>&1; echo EC=$?'
tcp_list_rc=$?
set -uo pipefail
pq_ssh "$SERVER" 'sudo cat /tmp/tcp-list.txt' >"$OUT/tcp-list.txt" || true
if [[ "$tcp_list_rc" -eq 0 ]]; then
  pq_gate UPGRADE_FIXED_TCP_AVAILABLE PASS
else
  pq_gate UPGRADE_FIXED_TCP_AVAILABLE FAIL
  up_cmp=1
fi

if [[ "$up_cmp" -eq 0 ]] && ! grep -q '=FAIL$' "$PROD_QUAL_GATES"; then
  pq_gate LIVE_V231_TO_V240_UPGRADE PASS
  pq_note "LIVE_V231_TO_V240_UPGRADE=PASS"
  python3 - "$OUT" "$HEAD" <<'PY'
import json, sys
from pathlib import Path
out, head = Path(sys.argv[1]), sys.argv[2]
gates = {}
for line in (out / "gates.env").read_text().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        gates[k] = v
doc = {
    "schema_version": 1,
    "git_head": head,
    "gates": gates,
    "final_status": gates.get("LIVE_V231_TO_V240_UPGRADE"),
    "evidence": {
        "golden": "golden/",
        "pre": "pre-upgrade-fingerprint.json",
        "post": "post-upgrade-fingerprint.json",
        "upgrade_log": "server-upgrade.log",
    },
}
(out / "summary.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
  exit 0
fi
pq_gate LIVE_V231_TO_V240_UPGRADE FAIL
pq_note "LIVE_V231_TO_V240_UPGRADE=FAIL"
exit 1
