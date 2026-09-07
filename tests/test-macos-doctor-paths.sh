#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export FRP_TEST_UNAME_S=Darwin FRP_MACOS_STATE_ROOT=/tmp/frp-macos-state FRP_MACOS_PREFIX=/tmp/frp-macos-prefix
python3 - "$ROOT/lib/frp_doctor.py" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.macos_map_path('/etc/frp/client-state.json') == '/tmp/frp-macos-state/client-state.json'
assert mod.macos_map_path('/usr/local/bin/frpc') == '/tmp/frp-macos-state/bin/frpc'
assert mod.macos_map_path('/usr/local/bin/frpctl') == '/tmp/frp-macos-prefix/bin/frpctl'
assert mod.macos_map_path('/etc/systemd/system/frpc.service') == '/Library/LaunchDaemons/com.datarelay.frp-auto-deploy.frpc.plist'
assert mod.macos_map_path('/usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py') == '/tmp/frp-macos-state/lib/frp_ctl_grammar.py'
assert mod.client_has_enabled_services({'services': {}}) is False
assert mod.client_has_enabled_services({'services': {'ssh': {'enabled': True}}}) is True
assert mod.client_has_enabled_services({'services': {'ssh': {'enabled': False}}}) is False
print('MACOS_DOCTOR_PATHS_TEST=PASS')
PY
