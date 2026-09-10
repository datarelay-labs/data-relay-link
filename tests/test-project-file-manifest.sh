#!/usr/bin/env bash
# FULL_INSTALL_MANAGED_FILES == PROJECT_UPDATE_MANAGED_FILES == ROLLBACK_SNAPSHOT_MANAGED_PROJECT_FILES
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

python3 - "$ROOT" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "lib"))
import frp_project_files
import frp_install_txn

managed = set(frp_project_files.managed_dests(single443=True, source_root=root))
snapshot = set(frp_install_txn.SNAPSHOT_RELS)
generated = {e.dest for e in frp_project_files.load_entries() if e.cls == "generated"}
binary = {e.dest for e in frp_project_files.load_entries() if e.cls == "binary"}
version = {e.dest for e in frp_project_files.load_entries() if e.cls == "version"}
protected = set(frp_install_txn.PROTECTED_EXACT)
snapshot_managed = snapshot - generated - binary - version - protected
if managed != snapshot_managed:
    missing = sorted(managed - snapshot_managed)
    extra = sorted(snapshot_managed - managed)
    raise SystemExit("manifest drift managed vs snapshot: missing=%s extra=%s" % (missing, extra))

install_server = (root / "install-server.sh").read_text(encoding="utf-8")
upgrade = (root / "lib" / "frp-server-upgrade.sh").read_text(encoding="utf-8")
if "frp_server_install_manifest_files" not in install_server:
    raise SystemExit("install-server.sh does not install from the canonical manifest")
if "frp_server_upgrade_destinations" not in upgrade:
    raise SystemExit("upgrade destinations helper missing")
if "server-project-files.manifest" not in (root / "scripts" / "build-bundles.py").read_text():
    raise SystemExit("bundle builder missing canonical manifest")

required = {
    "usr/local/lib/drlink/frp_audit.py",
    "usr/local/lib/drlink/frp_support_bundle.py",
    "usr/local/lib/drlink/frp-enrollments",
    "usr/local/lib/drlink/frp-enrollment-revoke",
    "usr/local/lib/drlink/frp-enroll-bulk",
    "usr/local/lib/drlink/frp-backup",
    "usr/local/lib/drlink/frp-restore",
    "usr/local/lib/drlink/frp-support-bundle",
    "usr/local/lib/drlink/frp-upstream",
    "usr/local/lib/drlink/frpctl",
    "usr/local/bin/drlink",
}
missing = sorted(required - managed)
if missing:
    raise SystemExit("managed set missing %s" % missing)
print("PARITY_OK")
PY
pass "PROJECT_FILE_MANIFEST_PARITY"
pass "P1_MANIFEST_PARITY_GATE"
echo "PROJECT_FILE_MANIFEST_TEST=PASS"
