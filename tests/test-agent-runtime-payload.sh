#!/usr/bin/env bash
# Fresh install + upgrade replacement of the canonical Agent v2.4 payload.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=../lib/frp-common.sh
. "$ROOT/lib/frp-common.sh"
# shellcheck source=../lib/frp-client-common.sh
. "$ROOT/lib/frp-client-common.sh"

WORKDIR="$(mktemp -d /tmp/frp-test-agent-runtime-payload.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

export FRP_SKIP_SYSTEMD=1
export FRP_CLIENT_TEST_ROOT="$WORKDIR/fresh"
mkdir -p "$FRP_CLIENT_TEST_ROOT"

frp_client_install_management_files "$ROOT" || fail "fresh install management files"

python3 - "$ROOT" "$FRP_CLIENT_TEST_ROOT" <<'PY' || fail "AGENT_FRESH_INSTALL_MODULE_COMPLETENESS"
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "lib"))
from drlink_agent_payload import (
    AGENT_CRITICAL_LINEAGE_FILES,
    AGENT_LIB_FILES,
    verify_payload_match,
    hash_lib_files,
)

root = Path(sys.argv[1])
dest = Path(sys.argv[2]) / "usr/local/lib/drlink"
problems = verify_payload_match(root / "lib", dest)
if problems:
    raise SystemExit("\n".join(problems))
live = hash_lib_files(dest, AGENT_CRITICAL_LINEAGE_FILES)
src = hash_lib_files(root / "lib", AGENT_CRITICAL_LINEAGE_FILES)
for name in AGENT_LIB_FILES:
    path = dest / name
    if not path.is_file():
        raise SystemExit("missing %s" % name)
for name in AGENT_CRITICAL_LINEAGE_FILES:
    if live[name] != src[name]:
        raise SystemExit("hash mismatch %s" % name)
print("ALL_REQUIRED_V24_AGENT_MODULES_PRESENT=YES")
print("AGENT_RUNTIME_LINEAGE_MATCH=PASS")
PY
pass AGENT_FRESH_INSTALL_MODULE_COMPLETENESS
pass AGENT_RUNTIME_LINEAGE_MATCH

# Plant stale critical modules, then reinstall from current source.
for stale in drlink_control_cli.py drlink_v24_cli.py drlink_v24_bundle.py; do
  printf 'STALE_MODULE_FROM_OLD_HEAD\n' > "$FRP_CLIENT_TEST_ROOT/usr/local/lib/drlink/$stale"
done
frp_client_install_management_files "$ROOT" || fail "upgrade/reinstall after stale modules"

python3 - "$ROOT" "$FRP_CLIENT_TEST_ROOT" <<'PY' || fail "AGENT_STALE_MODULE_REPLACEMENT"
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "lib"))
from drlink_agent_payload import AGENT_CRITICAL_LINEAGE_FILES, hash_lib_files, verify_payload_match

root = Path(sys.argv[1])
dest = Path(sys.argv[2]) / "usr/local/lib/drlink"
text = (dest / "drlink_control_cli.py").read_text(encoding="utf-8")
if "STALE_MODULE_FROM_OLD_HEAD" in text:
    raise SystemExit("stale drlink_control_cli.py survived")
problems = verify_payload_match(root / "lib", dest)
if problems:
    raise SystemExit("\n".join(problems))
live = hash_lib_files(dest, AGENT_CRITICAL_LINEAGE_FILES)
src = hash_lib_files(root / "lib", AGENT_CRITICAL_LINEAGE_FILES)
for name in AGENT_CRITICAL_LINEAGE_FILES:
    if live[name] != src[name]:
        raise SystemExit("%s still stale" % name)
print("ALL_REQUIRED_V24_AGENT_MODULES_REPLACED=YES")
PY
pass AGENT_UPGRADE_MODULE_COMPLETENESS
pass AGENT_STALE_MODULE_REPLACEMENT

echo "AGENT_RUNTIME_PAYLOAD=PASS"
