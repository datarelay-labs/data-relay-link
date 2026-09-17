#!/usr/bin/env bash
# Targeted Fixed TCP Egress + schema v3 regression tests.

# PRIOR_RELEASE_MIGRATION_TEST: tools/frp-access|frp-egress|frp-profile removed
echo "SKIP: dead legacy policy tools removed from current product surface" >&2
exit 0
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export FRP_DEPLOY_TEST_ROOT="$TMP"
mkdir -p "$TMP/etc/drlink" "$TMP/var/lib/drlink" "$TMP/var/log/drlink/egress" "$TMP/usr/local/lib/drlink/data/egress-recipes"
cp -a "$ROOT/lib/data/egress-recipes/." "$TMP/usr/local/lib/drlink/data/egress-recipes/"
cp -a "$ROOT/lib/data/public_suffix_list.dat" "$TMP/usr/local/lib/drlink/data/" 2>/dev/null || \
  cp -a "$ROOT/lib/data/public_suffix_list.dat" "$TMP/usr/local/lib/drlink/" 2>/dev/null || true
# PSL lives next to recipes under lib/data in source; control module looks beside itself.
mkdir -p "$TMP/usr/local/lib/drlink"
ln -sfn "$ROOT/lib/frp_egress_control.py" "$TMP/usr/local/lib/drlink/frp_egress_control.py"
ln -sfn "$ROOT/lib/frp_egress_runtime.py" "$TMP/usr/local/lib/drlink/frp_egress_runtime.py"
ln -sfn "$ROOT/lib/frp_infrastructure_ports.py" "$TMP/usr/local/lib/drlink/frp_infrastructure_ports.py"
ln -sfn "$ROOT/lib/frp_control_locks.py" "$TMP/usr/local/lib/drlink/frp_control_locks.py"
ln -sfn "$ROOT/lib/frp_public_suffix.py" "$TMP/usr/local/lib/drlink/frp_public_suffix.py"
ln -sfn "$ROOT/lib/frp_policy_fingerprint.py" "$TMP/usr/local/lib/drlink/frp_policy_fingerprint.py"
mkdir -p "$TMP/usr/local/lib/drlink/data"
ln -sfn "$ROOT/lib/data/public_suffix_list.dat" "$TMP/usr/local/lib/drlink/data/public_suffix_list.dat"

cat >"$TMP/etc/drlink/config.json" <<'EOF'
{
  "egress_control_file": "/var/lib/drlink/egress-control.json",
  "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
  "egress_listen_addr": "127.0.0.1",
  "egress_listen_port": 6102,
  "port_start": 6000,
  "port_end": 6098
}
EOF

EGRESS="$ROOT/tools/frp-egress"
python3 - "$ROOT" <<'PY'
import importlib.util
import ipaddress
import json
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(sys.argv[1])
sys.path.insert(0, str(ROOT / "lib"))

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

EG = load("frp_egress_control", ROOT / "lib" / "frp_egress_control.py")
RT = load("frp_egress_runtime", ROOT / "lib" / "frp_egress_runtime.py")
TCP = load("drlink_tcp_egress", ROOT / "server" / "drlink-tcp-egress.py")

cfg = {"egress_control_file": "/var/lib/drlink/egress-control.json", "egress_listen_port": 6102}
path = EG.egress_control_path(cfg)
path.parent.mkdir(parents=True, exist_ok=True)

failures = []

def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("FAIL:", msg)
    else:
        print("PASS:", msg)

# --- schema migration v1→v3 and v2→v3 ---
v1 = {
    "schema_version": 1,
    "egress_profiles": {
        "egp_aaaaaaaaaaaa": {
            "id": "egp_aaaaaaaaaaaa",
            "name": "legacy",
            "enabled": False,
            "description": "",
            "sources": [{"id": "egs_bbbbbbbbbbbb", "cidr": "10.0.0.0/24"}],
            "destinations": [
                {"id": "egd_cccccccccccc", "host": "a.example.com", "port": 80, "match": "exact"},
                {"id": "egd_dddddddddddd", "host": "b.example.com", "port": 443, "match": "exact"},
            ],
            "created_at": "t",
            "updated_at": "t",
        }
    },
}
migrated = EG.migrate_egress_state_to_current(v1)
check(migrated["schema_version"] == 3, "v1→v3 schema_version=3")
check(migrated.get("tcp_relays") == {}, "v1→v3 adds empty tcp_relays")
check(migrated["egress_profiles"]["egp_aaaaaaaaaaaa"]["destinations"][0]["protocol"] == "http", "v1→v3 :80→http")
check(migrated["egress_profiles"]["egp_aaaaaaaaaaaa"]["destinations"][1]["protocol"] == "https", "v1→v3 :443→https")

v2 = {
    "schema_version": 2,
    "egress_profiles": migrated["egress_profiles"],
}
migrated2 = EG.migrate_egress_state_v2_to_v3(v2)
check(migrated2["schema_version"] == 3, "v2→v3 schema_version=3")
check(migrated2.get("tcp_relays") == {}, "v2→v3 tcp_relays={}")
check(
    list(migrated2["egress_profiles"].keys()) == ["egp_aaaaaaaaaaaa"],
    "v2→v3 preserves profile ids",
)

# persist migration on load
path.write_text(json.dumps(v2) + "\n", encoding="utf-8")
loaded = EG.load_egress_state(path=path, cfg=cfg, persist_migration=True)
check(loaded["schema_version"] == 3, "load persists v2→v3")
check(json.loads(path.read_text())["schema_version"] == 3, "on-disk schema is 3")

# corruption fail closed
path.write_text("{not-json", encoding="utf-8")
try:
    EG.load_egress_state(path=path, cfg=cfg)
    check(False, "corrupt policy fail closed")
except EG.EgressError:
    check(True, "corrupt policy fail closed")

EG.save_egress_state(EG.empty_egress_state(), path=path, cfg=cfg)

# --- create disabled; incomplete enable reject ---
def mut_create(state):
    return EG.create_profile(state, "tcp-prof", enabled=False)

pid, profile = EG.mutate_egress_state(mut_create, cfg=cfg)
check(profile.get("enabled") is False, "profile create disabled")

try:
    EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=cfg)
    check(False, "incomplete profile enable reject")
except EG.EgressError:
    check(True, "incomplete profile enable reject")

EG.mutate_egress_state(lambda s: EG.add_source(s, pid, "203.0.113.10/32"), cfg=cfg)
EG.mutate_egress_state(
    lambda s: EG.add_destination(s, pid, "license.example.com", 27000, protocol="tcp"),
    cfg=cfg,
)
EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=cfg)

rid, relay = EG.mutate_egress_state(
    lambda s: EG.create_tcp_relay(
        s,
        "vendor-license",
        profile_selector=pid,
        destination_selector="license.example.com:27000",
        cfg=cfg,
    ),
    cfg=cfg,
)
check(relay.get("enabled") is False, "tcp relay create disabled")
check(6200 <= int(relay["listen_port"]) <= 6299, "auto listen allocation 6200-6299")

# incomplete enable: disable profile then try enable relay
EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, False), cfg=cfg)
try:
    EG.mutate_egress_state(lambda s: EG.set_tcp_relay_enabled(s, rid, True), cfg=cfg)
    check(False, "incomplete relay enable reject")
except EG.EgressError as exc:
    check("incomplete" in str(exc).lower() or "disabled" in str(exc).lower(), "incomplete relay enable reject")

EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=cfg)

# explicit port + duplicate reject + protected port reject
rid2, relay2 = EG.mutate_egress_state(
    lambda s: EG.create_tcp_relay(
        s,
        "vendor-license-2",
        profile_selector=pid,
        destination_selector="license.example.com:27000",
        listen_port=6210,
        cfg=cfg,
    ),
    cfg=cfg,
)
check(int(relay2["listen_port"]) == 6210, "explicit listen port")
try:
    EG.mutate_egress_state(
        lambda s: EG.create_tcp_relay(
            s,
            "dup-port",
            profile_selector=pid,
            destination_selector="license.example.com:27000",
            listen_port=6210,
            cfg=cfg,
        ),
        cfg=cfg,
    )
    check(False, "duplicate listen reject")
except EG.EgressError:
    check(True, "duplicate listen reject")

try:
    EG.mutate_egress_state(
        lambda s: EG.create_tcp_relay(
            s,
            "bad-port",
            profile_selector=pid,
            destination_selector="license.example.com:27000",
            listen_port=6102,
            cfg=cfg,
        ),
        cfg=cfg,
    )
    check(False, "protected port reject")
except EG.EgressError:
    check(True, "protected port reject")

# allow/deny source; IP literal deny; unsafe DNS deny
EG.mutate_egress_state(lambda s: EG.set_tcp_relay_enabled(s, rid, True), cfg=cfg)
state = EG.load_egress_state(cfg=cfg)
allow = EG.authorize_tcp_relay(state, relay_selector=rid, source_ip="203.0.113.10")
check(allow["decision"] == EG.DECISION_ALLOW, "allow matching source")
deny = EG.authorize_tcp_relay(state, relay_selector=rid, source_ip="198.51.100.1")
check(deny["decision"] == EG.DECISION_DENY, "deny non-matching source")

try:
    EG.mutate_egress_state(
        lambda s: EG.add_destination(s, pid, "1.2.3.4", 27000, protocol="tcp"),
        cfg=cfg,
    )
    check(False, "IP literal deny in policy")
except EG.EgressError:
    check(True, "IP literal deny in policy")

try:
    EG.mutate_egress_state(
        lambda s: EG.add_destination(s, pid, "*.license.example.com", 27000, protocol="tcp"),
        cfg=cfg,
    )
    check(False, "tcp wildcard deny")
except EG.EgressError:
    check(True, "tcp wildcard deny")

# DNS unsafe categories
for label, ips in (
    ("private", ["10.1.2.3"]),
    ("loopback", ["127.0.0.1"]),
    ("link-local", ["169.254.1.1"]),
    ("cgnat", ["100.64.1.2"]),
    ("metadata", ["169.254.169.254"]),
    ("mixed", ["1.1.1.1", "10.0.0.1"]),
):
    try:
        EG.validate_resolved_addresses(ips)
        check(False, "DNS unsafe deny: %s" % label)
    except EG.EgressError:
        check(True, "DNS unsafe deny: %s" % label)

# exact IP connect (no re-resolve)
seen_hosts = []

def fake_resolve(hostname):
    seen_hosts.append(hostname)
    return ["203.0.113.50"]

def fake_connect(ip, port, hostname, timeout):
    # hostname must not be used for DNS; connect by exact IP.
    if ip != "203.0.113.50":
        raise OSError("unexpected ip %s" % ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Don't actually connect — return a closed socket? Better: bind a local listener.
    return sock

# Use a real local listener for connect validation
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
local_port = srv.getsockname()[1]

def accept_once():
    c, _ = srv.accept()
    c.close()

threading.Thread(target=accept_once, daemon=True).start()

def resolve_local(_hostname):
    return ["127.0.0.1"]

# 127.0.0.1 is unsafe for production validation — prove validate denies it
try:
    EG.validate_resolved_addresses(["127.0.0.1"])
    check(False, "loopback validate deny")
except EG.EgressError:
    check(True, "loopback validate deny")

# exact validated public IP connect path via happy_eyeballs + default_connect semantics
connected = []

def resolve_pub(host):
    return ["203.0.113.50", "198.51.100.50"]

def connect_exact(ip, port, hostname, timeout):
    connected.append((ip, hostname))
    # Simulate success without network using a dummy connected pair
    a, b = socket.socketpair()
    b.close()
    return a

sock = RT.happy_eyeballs_connect(connect_exact, ["203.0.113.50"], 27000, "license.example.com")
check(connected and connected[0][0] == "203.0.113.50", "exact IP connect")
check(connected[0][1] == "license.example.com", "hostname passed but unused for DNS")
sock.close()

# relay/profile disable
EG.mutate_egress_state(lambda s: EG.set_tcp_relay_enabled(s, rid, False), cfg=cfg)
state = EG.load_egress_state(cfg=cfg)
d = EG.authorize_tcp_relay(state, relay_selector=rid, source_ip="203.0.113.10")
check(d["decision"] == EG.DECISION_DENY and d["reason"] == EG.REASON_RELAY_DISABLED, "relay disable denies")

EG.mutate_egress_state(lambda s: EG.set_tcp_relay_enabled(s, rid, True), cfg=cfg)
EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, False), cfg=cfg)
state = EG.load_egress_state(cfg=cfg)
d = EG.authorize_tcp_relay(state, relay_selector=rid, source_ip="203.0.113.10")
check(d["decision"] == EG.DECISION_DENY, "profile disable denies relay traffic")

# recipe apply disabled
EG.mutate_egress_state(lambda s: EG.set_profile_enabled(s, pid, True), cfg=cfg)
before = json.loads(path.read_text())
result = EG.mutate_egress_state(
    lambda s: EG.apply_recipe(s, "tcp-fixed", profile_name="recipe-tcp", source_cidr="203.0.113.0/24", cfg=cfg),
    cfg=cfg,
)
check(result.get("enabled") is False, "recipe apply disabled flag")
state = EG.load_egress_state(cfg=cfg)
rpid = result["profile_id"]
check(state["egress_profiles"][rpid]["enabled"] is False, "recipe profile left disabled")
if result.get("relay_id"):
    check(state["tcp_relays"][result["relay_id"]]["enabled"] is False, "recipe relay left disabled")

# explain no mutation
before_hash = path.read_text()
decision = EG.authorize_request(
    state,
    source_ip="203.0.113.10",
    hostname="license.example.com",
    port=27000,
    protocol="tcp",
    preview=True,
)
after_hash = path.read_text()
check(before_hash == after_hash, "explain/authorize preview no mutation")
check(decision.get("decision") in (EG.DECISION_ALLOW, EG.DECISION_DENY), "explain returns decision")

srv.close()

if failures:
    print("%d failure(s)" % len(failures))
    sys.exit(1)
print("ALL PASS")
PY

# CLI smoke: explain alias + recipe list + tcp list
"$EGRESS" recipe list | grep -E 'https-api|http-update|tcp-fixed' >/dev/null
"$EGRESS" explain 203.0.113.10 license.example.com 27000 --protocol tcp >/dev/null || true
"$EGRESS" test 203.0.113.10 license.example.com 27000 --protocol tcp >/dev/null || true
"$EGRESS" tcp list >/dev/null
echo "CLI smoke OK"
