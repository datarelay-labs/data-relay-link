#!/usr/bin/env bash
# Shell/CLI grammar coverage for Controlled Egress.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export FRP_DEPLOY_TEST_ROOT="$TMP"
mkdir -p \
  "$TMP/etc/frp-auto-deploy" \
  "$TMP/var/lib/frp-auto-deploy" \
  "$TMP/var/log/frp-auto-deploy" \
  "$TMP/usr/local/lib/frp-auto-deploy" \
  "$TMP/usr/local/sbin"

cp "$ROOT/lib/frp_egress_control.py" "$TMP/usr/local/lib/frp-auto-deploy/"
cp "$ROOT/lib/frp_audit.py" "$TMP/usr/local/lib/frp-auto-deploy/" 2>/dev/null || true
cp "$ROOT/tools/frp-egress" "$TMP/usr/local/sbin/"
chmod +x "$TMP/usr/local/sbin/frp-egress"

cat >"$TMP/etc/frp-auto-deploy/config.json" <<EOF
{
  "egress_control_file": "/var/lib/frp-auto-deploy/egress-control.json",
  "egress_conn_log_file": "/var/log/frp-auto-deploy/egress-conn.jsonl",
  "egress_listen_addr": "0.0.0.0",
  "egress_listen_port": 6080
}
EOF

python3 - <<'PY'
import importlib.util, os, json
from pathlib import Path
root = Path(os.environ["FRP_DEPLOY_TEST_ROOT"])
spec = importlib.util.spec_from_file_location(
    "eg", root / "usr/local/lib/frp-auto-deploy/frp_egress_control.py"
)
eg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eg)
path = root / "var/lib/frp-auto-deploy/egress-control.json"
eg.save_egress_state(eg.empty_egress_state(), path=path)
print(path)
PY

EGRESS="$TMP/usr/local/sbin/frp-egress"

"$EGRESS" create ubuntu-update --description "Ubuntu updates"
"$EGRESS" add-destination ubuntu-update security.ubuntu.com 443
"$EGRESS" add-destination ubuntu-update archive.ubuntu.com 443
"$EGRESS" add-source ubuntu-update 203.0.113.10/32
"$EGRESS" show ubuntu-update | grep -q security.ubuntu.com
"$EGRESS" test 203.0.113.10 security.ubuntu.com 443
! "$EGRESS" test 203.0.113.10 evil.example.com 443
! "$EGRESS" test 198.51.100.1 security.ubuntu.com 443
"$EGRESS" disable ubuntu-update
! "$EGRESS" test 203.0.113.10 security.ubuntu.com 443
"$EGRESS" enable ubuntu-update
"$EGRESS" test 203.0.113.10 security.ubuntu.com 443
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
