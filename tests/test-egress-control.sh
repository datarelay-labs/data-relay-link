#!/usr/bin/env bash
# Shell/CLI grammar coverage for Controlled Egress.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export FRP_DEPLOY_TEST_ROOT="$TMP"
mkdir -p \
  "$TMP/etc/drlink" \
  "$TMP/var/lib/drlink" \
  "$TMP/var/log/drlink" \
  "$TMP/usr/local/lib/drlink" \
  "$TMP/usr/local/sbin"

cp "$ROOT/lib/frp_egress_control.py" "$TMP/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_control_locks.py" "$TMP/usr/local/lib/drlink/"
cp "$ROOT/lib/frp_public_suffix.py" "$TMP/usr/local/lib/drlink/"
mkdir -p "$TMP/usr/local/lib/drlink/data"
cp "$ROOT/lib/data/public_suffix_list.dat" "$TMP/usr/local/lib/drlink/data/"
cp "$ROOT/lib/frp_audit.py" "$TMP/usr/local/lib/drlink/" 2>/dev/null || true
cp "$ROOT/tools/frp-egress" "$TMP/usr/local/sbin/"
chmod +x "$TMP/usr/local/sbin/frp-egress"

cat >"$TMP/etc/drlink/config.json" <<EOF
{
  "egress_control_file": "/var/lib/drlink/egress-control.json",
  "egress_conn_log_file": "/var/log/drlink/egress-conn.jsonl",
  "egress_listen_addr": "0.0.0.0",
  "egress_listen_port": 6102
}
EOF

python3 - <<'PY'
import importlib.util, os, json
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
spec = importlib.util.spec_from_file_location(
    "eg", root / "usr/local/lib/drlink/frp_egress_control.py"
)
eg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eg)
path = root / "var/lib/drlink/egress-control.json"
eg.save_egress_state(eg.empty_egress_state(), path=path)
print(path)
PY

EGRESS="$TMP/usr/local/sbin/frp-egress"

"$EGRESS" create ubuntu-update --description "Ubuntu updates"
"$EGRESS" add-destination ubuntu-update security.ubuntu.com 443 --protocol https
"$EGRESS" add-destination ubuntu-update archive.ubuntu.com 443 --protocol https
"$EGRESS" add-source ubuntu-update 203.0.113.10/32
# Create is DISABLED by default — must enable before ALLOW.
! "$EGRESS" test 203.0.113.10 security.ubuntu.com 443 --protocol https
"$EGRESS" enable ubuntu-update
"$EGRESS" show ubuntu-update | grep -q security.ubuntu.com
"$EGRESS" test 203.0.113.10 security.ubuntu.com 443 --protocol https | grep -q 'Final        : ALLOW'
! "$EGRESS" test 203.0.113.10 evil.example.com 443 --protocol https
! "$EGRESS" test 198.51.100.1 security.ubuntu.com 443 --protocol https
"$EGRESS" disable ubuntu-update
out="$("$EGRESS" test 203.0.113.10 security.ubuntu.com 443 --protocol https 2>&1 || true)"
grep -q 'Policy       : DENY' <<<"$out" || { echo "$out"; exit 1; }
grep -q 'Final        : DENY' <<<"$out" || { echo "$out"; exit 1; }
grep -q 'Protocol     : https' <<<"$out" || { echo "$out"; exit 1; }
"$EGRESS" enable ubuntu-update
# DNS unsafe parity: ALLOW policy + private resolution must Final DENY.
"$EGRESS" add-destination ubuntu-update localhost 443 --protocol https
out="$("$EGRESS" test 203.0.113.10 localhost 443 --protocol https 2>&1 || true)"
grep -q 'Policy       : ALLOW' <<<"$out" || { echo "$out"; exit 1; }
grep -q 'Final        : DENY' <<<"$out" || { echo "$out"; exit 1; }
"$EGRESS" remove-destination ubuntu-update localhost:443
"$EGRESS" test 203.0.113.10 security.ubuntu.com 443 --protocol https
"$EGRESS" remove-destination ubuntu-update archive.ubuntu.com:443
"$EGRESS" remove-source ubuntu-update 203.0.113.10/32
"$EGRESS" delete ubuntu-update
"$EGRESS" list | grep -q '(none)'

# Grammar checks
python3 - "$ROOT" <<'PY'
import importlib.util, sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("g", root / "lib/frp_ctl_grammar.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
cases = [
    ["create", "egress-profile", "x"],
    ["add", "egress-profile", "x", "destination", "a.example.com", "443"],
    ["add", "egress-profile", "x", "source", "10.0.0.0/24"],
    ["show", "egress-profiles"],
    ["show", "egress-profile", "x"],
    ["enable", "egress-profile", "x"],
    ["disable", "egress-profile", "x"],
    ["delete", "egress-profile", "x"],
    ["egress", "status"],
]
for toks in cases:
    r = g.match(toks, "server")
    assert r.get("status") == "ok", (toks, r)
print("grammar ok")
PY

echo "PASS test-egress-control.sh"
