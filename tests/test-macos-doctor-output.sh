#!/usr/bin/env bash
# Doctor presentation on Darwin: no Linux distro-matrix warning, launchd labels.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() { echo "FAIL $1" >&2; exit 1; }
pass() { echo "PASS $1"; }

# ---------------------------------------------------------------------------
# Python: Darwin must not emit the Linux container-matrix warning.
# ---------------------------------------------------------------------------
python3 - "$ROOT/lib/frp_doctor.py" <<'PY' || fail "darwin unknown os_id still warned"
import importlib.util, os, sys
os.environ['FRP_TEST_UNAME_S'] = 'Darwin'
os.environ['FRP_TEST_UNAME_M'] = 'arm64'
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
report = mod.Report()
facts = {
    'platform': {
        'os': 'macOS',
        'os_id': 'unknown',
        'os_family': 'darwin',
        'arch': 'arm64',
        'macos_version': '14.6.1',
        'service_manager': 'launchd',
        'kernel': '23.6.0',
        'bash': '3.2.57',
        'python': '3.12.0',
        'openssl': 'LibreSSL 3.3.6',
        'systemd': '',
    },
    'disk': {},
    'clock': {},
}
mod.check_host_facts(report, facts)
ids = {c['id']: c for c in report.checks}
assert 'distro_support' not in ids, ids.get('distro_support')
assert ids['macos_support']['status'] == mod.PASS
assert 'container matrix' not in (ids['macos_support'].get('message') or '')
assert 'systemd Linux' not in (ids['macos_support'].get('recommendation') or '')
text = ' '.join(c['message'] + ' ' + (c.get('recommendation') or '') for c in report.checks)
assert 'container matrix' not in text
assert 'uncertified rather than broken' not in text
print('darwin_unknown_os_id_ok')
PY
pass "DARWIN_NO_LINUX_DISTRO_WARNING"

python3 - "$ROOT/lib/frp_doctor.py" <<'PY' || fail "supported darwin macos_support"
import importlib.util, os, sys
os.environ['FRP_TEST_UNAME_S'] = 'Darwin'
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
report = mod.Report()
mod.check_host_facts(report, {
    'platform': {
        'os': 'macOS 14.6.1', 'os_id': 'macos', 'os_family': 'darwin',
        'arch': 'arm64', 'macos_version': '14.6.1', 'service_manager': 'launchd',
    },
    'disk': {'avail_mb': 4096, 'path': '/var/lib/frp-auto-deploy'},
    'clock': {},
})
ids = {c['id']: c for c in report.checks}
assert ids['macos_support']['status'] == mod.PASS
assert 'Apple Silicon' in ids['macos_support']['message']
assert 'distro_support' not in ids
assert 'systemd=' not in ids['host_facts']['detail']
assert 'service_manager=launchd' in ids['host_facts']['detail']
print('supported_darwin_ok')
PY
pass "DARWIN_MACOS_SUPPORT_PASS"

python3 - "$ROOT/lib/frp_doctor.py" <<'PY' || fail "intel darwin should FAIL macos_support"
import importlib.util, os, sys
os.environ['FRP_TEST_UNAME_S'] = 'Darwin'
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
report = mod.Report()
mod.check_host_facts(report, {
    'platform': {
        'os': 'macOS 14.0', 'os_id': 'macos', 'os_family': 'darwin',
        'arch': 'x86_64', 'macos_version': '14.0', 'service_manager': 'launchd',
    },
    'disk': {}, 'clock': {},
})
ids = {c['id']: c for c in report.checks}
assert ids['macos_support']['status'] == mod.FAIL
assert 'Apple Silicon' in (ids['macos_support'].get('recommendation') or '')
assert 'distro_support' not in ids
print('intel_darwin_fail_ok')
PY
pass "DARWIN_INTEL_MACOS_SUPPORT_FAIL"

python3 - "$ROOT/lib/frp_doctor.py" <<'PY' || fail "old darwin should FAIL macos_support"
import importlib.util, os, sys
os.environ['FRP_TEST_UNAME_S'] = 'Darwin'
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
report = mod.Report()
mod.check_host_facts(report, {
    'platform': {
        'os': 'macOS 10.15', 'os_id': 'macos', 'os_family': 'darwin',
        'arch': 'arm64', 'macos_version': '10.15.7', 'service_manager': 'launchd',
    },
    'disk': {}, 'clock': {},
})
ids = {c['id']: c for c in report.checks}
assert ids['macos_support']['status'] == mod.FAIL
assert 'older than the supported minimum' in ids['macos_support']['message']
print('old_macos_fail_ok')
PY
pass "DARWIN_OLD_RELEASE_MACOS_SUPPORT_FAIL"

# Linux path must keep the container-matrix check.
python3 - "$ROOT/lib/frp_doctor.py" <<'PY' || fail "linux distro_support regression"
import importlib.util, os, sys
os.environ.pop('FRP_TEST_UNAME_S', None)
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
report = mod.Report()
mod.check_host_facts(report, {
    'platform': {'os': 'Arch Linux', 'os_id': 'arch', 'arch': 'x86_64', 'systemd': '255'},
    'disk': {}, 'clock': {},
})
ids = {c['id']: c for c in report.checks}
assert ids['distro_support']['status'] == mod.WARN
assert 'container matrix' in ids['distro_support']['message']
assert 'macos_support' not in ids

report2 = mod.Report()
mod.check_host_facts(report2, {
    'platform': {'os': 'Ubuntu 24.04', 'os_id': 'ubuntu', 'arch': 'x86_64', 'systemd': '255'},
    'disk': {}, 'clock': {},
})
ids2 = {c['id']: c for c in report2.checks}
assert ids2['distro_support']['status'] == mod.INFO
assert 'container matrix' in ids2['distro_support']['message']
print('linux_distro_support_ok')
PY
pass "LINUX_DISTRO_SUPPORT_UNCHANGED"

# ---------------------------------------------------------------------------
# Runtime labels: launchd on Darwin, frpc.service on Linux.
# ---------------------------------------------------------------------------
python3 - "$ROOT/lib/frp_doctor.py" <<'PY' || fail "darwin launchd runtime label"
import importlib.util, os, sys
os.environ['FRP_TEST_UNAME_S'] = 'Darwin'
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
facts = {
    'systemd_usable': False,
    'units': {'frpc': {'active': 'active', 'enabled': 'enabled'}},
    'platform': {'os_id': 'macos', 'os_family': 'darwin', 'service_manager': 'launchd'},
}
report = mod.Report()
mod.check_unit(report, facts, 'frpc', 'frpc_service', 'frpc.service')
item = report.checks[0]
assert item['status'] == mod.PASS
assert 'launchd job com.datarelay.frp-auto-deploy.frpc is active' == item['message']
assert 'frpc.service' not in item['message']
assert 'systemctl' not in (item.get('recommendation') or '')

report_fail = mod.Report()
facts_fail = dict(facts)
facts_fail['units'] = {'frpc': {'active': 'inactive', 'enabled': 'enabled'}}
mod.check_unit(report_fail, facts_fail, 'frpc', 'frpc_service', 'frpc.service')
item_f = report_fail.checks[0]
assert item_f['status'] == mod.FAIL
assert 'launchd job com.datarelay.frp-auto-deploy.frpc is not active' == item_f['message']
assert 'frpc.service' not in item_f['message']
assert 'launchctl print system/com.datarelay.frp-auto-deploy.frpc' in item_f['recommendation']
assert 'systemctl' not in item_f['recommendation']

human_report = mod.Report()
human_report.role = 'client'
human_report.role_label = 'Client'
mod.check_host_facts(human_report, {
    'platform': {
        'os': 'macOS 14.6.1', 'os_id': 'macos', 'os_family': 'darwin',
        'arch': 'arm64', 'macos_version': '14.6.1', 'service_manager': 'launchd',
    },
    'disk': {'avail_mb': 4096, 'path': '/x'}, 'clock': {},
})
mod.check_unit(human_report, facts, 'frpc', 'frpc_service', 'frpc.service')
text = mod.render_human(human_report)
assert 'frpc.service' not in text
assert 'container matrix' not in text
assert 'uncertified rather than broken' not in text
assert 'launchd job com.datarelay.frp-auto-deploy.frpc' in text
assert 'macos_support' in text
assert 'distro_support' not in text
print('darwin_launchd_label_ok')
PY
pass "DARWIN_LAUNCHD_RUNTIME_LABEL"

python3 - "$ROOT/lib/frp_doctor.py" <<'PY' || fail "linux frpc.service runtime label"
import importlib.util, os, sys
os.environ.pop('FRP_TEST_UNAME_S', None)
spec = importlib.util.spec_from_file_location('frp_doctor', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
facts = {
    'systemd_usable': True,
    'units': {'frpc': {'active': 'active', 'enabled': 'enabled'}},
    'platform': {'os_id': 'ubuntu'},
}
report = mod.Report()
mod.check_unit(report, facts, 'frpc', 'frpc_service', 'frpc.service')
item = report.checks[0]
assert item['status'] == mod.PASS
assert item['message'] == 'frpc.service is active'
assert 'launchd' not in item['message']

report_fail = mod.Report()
facts_fail = dict(facts)
facts_fail['units'] = {'frpc': {'active': 'inactive', 'enabled': 'enabled'}}
mod.check_unit(report_fail, facts_fail, 'frpc', 'frpc_service', 'frpc.service')
item_f = report_fail.checks[0]
assert item_f['status'] == mod.FAIL
assert item_f['message'] == 'frpc.service is not active'
assert 'systemctl status frpc' in item_f['recommendation']
assert 'launchctl' not in item_f['recommendation']
print('linux_frpc_service_label_ok')
PY
pass "LINUX_FRPC_SERVICE_LABEL_UNCHANGED"

# ---------------------------------------------------------------------------
# Bash facts: Darwin must not inherit Linux /etc/os-release.
# ---------------------------------------------------------------------------
MOCKBIN="$WORKDIR/bin"
mkdir -p "$MOCKBIN"
cat >"$MOCKBIN/launchctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == print ]]; then
  echo "	pid = 4242"
  exit 0
fi
exit 0
EOF
chmod 0755 "$MOCKBIN/launchctl"

(
  unset FRP_COMMON_LOADED FRP_MACOS_LOADED FRP_DOCTOR_LOADED
  export FRP_TEST_UNAME_S=Darwin
  export FRP_TEST_UNAME_M=arm64
  export FRP_TEST_MACOS_PRODUCT_VERSION=14.6.1
  export FRP_SKIP_SYSTEMD=1
  export PATH="$MOCKBIN:$PATH"
  # shellcheck disable=SC1091
  . "$ROOT/lib/frp-common.sh"
  # shellcheck disable=SC1091
  . "$ROOT/lib/frp-doctor-common.sh"
  facts="$WORKDIR/darwin-facts.json"
  frp_doctor_collect_facts "$facts"
  python3 - "$facts" <<'PY' || exit 1
import json, sys
from pathlib import Path
facts = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
plat = facts.get('platform') or {}
assert plat.get('os_id') == 'macos', plat
assert plat.get('os_family') == 'darwin', plat
assert plat.get('service_manager') == 'launchd', plat
assert str(plat.get('os') or '').startswith('macOS'), plat
assert plat.get('arch') == 'arm64', plat
assert plat.get('macos_version') == '14.6.1', plat
assert plat.get('os_id') not in ('ubuntu', 'debian', 'fedora', 'rhel', 'centos')
assert (facts.get('units') or {}).get('frpc', {}).get('active') == 'active'
print('facts_ok')
PY
) || fail "darwin facts leaked linux distro or missed launchd"
pass "DARWIN_FACTS_NO_LINUX_OS_RELEASE"

# ---------------------------------------------------------------------------
# Full doctor CLI on a Darwin-mapped client fixture.
# ---------------------------------------------------------------------------
TREE="$WORKDIR/client"
STATE="$TREE/Library/Application Support/frp-auto-deploy"
mkdir -p "$STATE/bin" "$STATE/lib" "$STATE/state" "$STATE/logs" \
  "$TREE/usr/local/bin" \
  "$TREE/Library/LaunchDaemons"
# shellcheck disable=SC1091
. "$ROOT/VERSION"
cat >"$STATE/version" <<EOF
PROJECT_VERSION=${PROJECT_VERSION}
FRP_VERSION=${FRP_VERSION}
EOF
for bin in "$STATE/bin/frpc" "$TREE/usr/local/bin/frp-client"; do
  cat >"$bin" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == --version ]]; then
  echo "frpc version 0.70.1"
  exit 0
fi
exit 0
EOF
  chmod 0755 "$bin"
done
echo 'fixture' >"$TREE/Library/LaunchDaemons/com.datarelay.frp-auto-deploy.frpc.plist"
python3 "$ROOT/lib/frp_mgmt_auth.py" gen-key \
  "$STATE/client-identity.key" "$STATE/client-identity.pub"
chmod 600 "$STATE/client-identity.key"
printf '%s\n' "$(printf 'a%.0s' {1..64})" >"$STATE/client-identity.mac"
chmod 600 "$STATE/client-identity.mac"
python3 "$ROOT/lib/frp_pki.py" ensure --pki-dir "$WORKDIR/pki" --public-host "203.0.113.10" >/dev/null
cp "$WORKDIR/pki/ca.crt" "$STATE/allocator-ca.crt"
chmod 644 "$STATE/allocator-ca.crt"
python3 - "$STATE/client-state.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "allocator_url": "https://203.0.113.10:9443/enroll",
    "frp_server": "203.0.113.10",
    "frp_server_port": 8443,
    "hostname": "macos-doctor",
    "machine_id": "00112233445566778899aabbccddeeff",
    "host_id": "macos-doctor-00112233",
    "services": {
        "ssh": {
            "id": "ssh", "name": "SSH", "preset": "ssh", "protocol": "tcp",
            "local_ip": "127.0.0.1", "local_port": 22, "remote_port": 6001,
            "enabled": True, "ssh_user": "aella",
        },
    },
}, indent=2, sort_keys=True) + "\n")
PY
chmod 600 "$STATE/client-state.json"
cat >"$STATE/frpc.toml" <<'EOF'
serverAddr = "203.0.113.10"
serverPort = 8443
auth.method = "token"
auth.token = "test-frp-token-do-not-use"
transport.tls.enable = true

[[proxies]]
name = "macos-doctor-00112233-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6001
EOF
chmod 600 "$STATE/frpc.toml"
cat >"$STATE/access-info.txt" <<'EOF'
FRP Server: 203.0.113.10:8443
EOF

chmod +x "$ROOT/tools/frpctl"
unset FRP_COMMON_LOADED FRP_MACOS_LOADED FRP_DOCTOR_LOADED
export FRP_TEST_UNAME_S=Darwin
export FRP_TEST_UNAME_M=arm64
export FRP_TEST_MACOS_PRODUCT_VERSION=14.6.1
export FRP_SKIP_SYSTEMD=1
export FRP_DOCTOR_SKIP_NETWORK=1
export FRP_DOCTOR_PY="$ROOT/lib/frp_doctor.py"
export FRP_CTL_TEST_ROOT="$TREE"
export FRP_CLIENT_TEST_ROOT="$TREE"
export FRP_DEPLOY_TEST_ROOT="$TREE"
export FRP_MACOS_STATE_ROOT='/Library/Application Support/frp-auto-deploy'
export PATH="$MOCKBIN:$PATH"
export HOME="$WORKDIR/home"
mkdir -p "$HOME"

set +e
"$ROOT/tools/frpctl" doctor --json >"$WORKDIR/darwin.json" 2>"$WORKDIR/darwin.json.err"
json_rc=$?
"$ROOT/tools/frpctl" doctor >"$WORKDIR/darwin.human" 2>"$WORKDIR/darwin.human.err"
human_rc=$?
set -e

python3 - "$WORKDIR/darwin.json" "$WORKDIR/darwin.json.err" "$json_rc" <<'PY' || fail "darwin doctor json"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
err = Path(sys.argv[2]).read_text(encoding='utf-8')
rc = int(sys.argv[3])
text = json.dumps(data) + '\n' + err
ids = {c.get('id'): c for c in data.get('checks') or []}
assert 'distro_support' not in ids, ids.get('distro_support')
assert 'container matrix' not in text
assert 'uncertified rather than broken' not in text
assert 'supported systemd Linux' not in text
assert ids.get('macos_support', {}).get('status') == 'PASS', ids.get('macos_support')
frpc = ids.get('frpc_service') or {}
assert 'launchd job com.datarelay.frp-auto-deploy.frpc' in (frpc.get('message') or ''), frpc
assert 'frpc.service' not in (frpc.get('message') or '')
assert 'systemctl' not in (frpc.get('recommendation') or '')
warns = [c for c in data.get('checks') or [] if c.get('status') == 'WARN']
fails = [c for c in data.get('checks') or [] if c.get('status') == 'FAIL']
# Only real Darwin conditions may WARN/FAIL. The Linux distro warning must not.
assert all(c.get('id') != 'distro_support' for c in warns + fails)
if frpc.get('status') == 'PASS' and ids.get('macos_support', {}).get('status') == 'PASS':
    assert data.get('overall') in ('PASS', 'PASS_WITH_WARNINGS'), data.get('overall')
    if data.get('overall') == 'PASS':
        assert rc == 0
print('json_ok overall=%s frpc=%s' % (data.get('overall'), frpc.get('status')))
PY

grep -F 'frpc.service' "$WORKDIR/darwin.human" && fail "human doctor mentioned frpc.service"
grep -F 'container matrix' "$WORKDIR/darwin.human" && fail "human doctor mentioned Linux container matrix"
grep -F 'uncertified rather than broken' "$WORKDIR/darwin.human" && fail "human doctor used Linux uncertified wording"
grep -F 'launchd job com.datarelay.frp-auto-deploy.frpc' "$WORKDIR/darwin.human" || fail "human doctor missing launchd job"
grep -F 'macos_support' "$WORKDIR/darwin.human" || fail "human doctor missing macos_support"
grep -F 'distro_support' "$WORKDIR/darwin.human" && fail "human doctor emitted distro_support"
[[ "$human_rc" -eq 0 || "$human_rc" -eq 1 ]] || fail "human doctor exit $human_rc"
pass "DARWIN_DOCTOR_CLI_OUTPUT"

echo
echo "MACOS_DOCTOR_OUTPUT_TEST=PASS"
exit 0
