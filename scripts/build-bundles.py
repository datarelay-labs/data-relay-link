#!/usr/bin/env python3
import base64
import json
import sys
from pathlib import Path

root=Path(__file__).resolve().parents[1]
dist=root/'dist'
dist.mkdir(exist_ok=True)
sys.path.insert(0, str(root / 'lib'))
from drlink_agent_payload import agent_source_rels

def bundle_payload(rel):
    data = (root / rel).read_bytes()
    if rel != 'release-manifest.json':
        return data
    # Artifact hashes describe the outer bundles. Strip them from the
    # embedded manifest so a bundle never contains a hash of itself.
    import_data = json.loads(data.decode('utf-8'))
    for meta in (import_data.get('artifacts') or {}).values():
        if isinstance(meta, dict):
            meta.pop('sha256', None)
    return (json.dumps(import_data, indent=2, sort_keys=False) + '\n').encode('utf-8')

files=[
 'VERSION',
 'release-manifest.json',
 'install-server.sh',
 'uninstall-server.sh',
 'lib/frp-common.sh',
 'lib/frp_mgmt_auth.py',
 'lib/frp_pki.py',
 'lib/frp_frontend.py',
 'lib/frp_install_txn.py',
 'lib/frp-server-upgrade.sh',
 'lib/frp_client_registry.py',
 'lib/frp_enrollment_lifecycle.py',
 'lib/frp_audit.py',
 'lib/frp_project_files.py',
 'lib/frp-role-ownership.sh',
 'lib/frp_control_locks.py',
 'lib/frp_server_config.py',
 'lib/frp_zero_touch.py',
 'lib/drlink_qualified_artifacts.py',
 'lib/server-project-files.manifest',
 'lib/frp-doctor-common.sh',
 'lib/frp_doctor.py',
 'lib/frp_support_bundle.py',
 'lib/frp_ctl_grammar.py',
 'lib/frp_cli_catalog.py',
 'lib/frp_version_identity.py',
 'lib/frp_cli_final_commands.json',
 'lib/drlink_control_db.py',
 'lib/drlink_control_plane.py',
 'lib/drlink_control_cli.py',
 'lib/drlink_mgmt_sync.py',
 'lib/drlink_v24.py',
 'lib/drlink_v24_bundle.py',
 'lib/drlink_v24_cli.py',
 'lib/drlink_v24_wizard.py',
 'lib/drlink_v24_ai_identity.py',
 'lib/drlink_v24_runtime.py',
 'lib/drlink_configuration_bundle.py',
 'lib/drlink_runtime_policy.py',
 'lib/drlink_upgrade_reconcile.py',
 'lib/drlink_ai_agent.py',
 'lib/drlink_mcp_bridge.py',
 'lib/drlink_mcp_tls.py',
 'lib/drlink_mcp_tls_renew.py',
 'lib/frp_ctl_repl.py',
 'lib/frp_access_control.py',
 'lib/frp_egress_control.py',
 'lib/frp_egress_runtime.py',
 'lib/frp_state_paths.py',
 'lib/frp_infrastructure_ports.py',
 'lib/frp_health_check.py',
 'lib/frp_service_profiles.py',
 'lib/frp_machine_id.py',
 'lib/frp_bounded_server.py',
 'lib/frp_public_suffix.py',
 'lib/frp_policy_fingerprint.py',
 'lib/data/public_suffix_list.dat',
 'lib/data/egress-recipes/https-api.json',
 'lib/data/egress-recipes/http-update.json',
 'lib/data/egress-recipes/tcp-fixed.json',
 'server/frp-port-allocator.py',
 'server/frp-access-plugin.py',
 'server/frp-egress-gateway.py',
 'server/drlink-tcp-egress.py',
 'server/migrate_token.py',
 'server/drlink-server.service',
 'server/drlink-allocator.service',
 'server/drlink-access.service',
 'server/drlink-egress.service',
 'server/drlink-tcp-egress.service',
 'server/drlink-frontend.service',
 'server/drlink-mcp-bridge.py',
 'server/drlink-mcp-bridge.service',
 'server/drlink-mcp-tls-renew.service',
 'server/drlink-mcp-tls-renew.timer',
 'tools/frp-create-client',
 'tools/frp-enrollments',
 'tools/frp-enrollment-revoke',
 'tools/frp-enrollment-purge',
 'tools/frp-enroll-bulk',
 'tools/frp-clients',
 'tools/frp-client-info',
 'tools/frp-services',
 'tools/frp-groups',
 'tools/frp-group-set',
 'tools/frp-release-client',
 'tools/frp-release-service',
 'tools/frp-revoke-client',
 'tools/frp-client-set',
 'tools/frp-set-client-installer-url',
 'tools/frp-server-set',
 'tools/frp-server-status',
 'tools/frp-project-update',
 'tools/frp-backup',
 'tools/frp-restore',
 'tools/frp-support-bundle',
 'tools/frp-update',
 'tools/frp-upstream',
 'tools/drlink',
 'tools/frpctl',
]

def write_server_bundle(rels):
    out=[
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        'echo "Downloading qualified Data Relay Link installer..."',
        'TMP="$(mktemp -d)"',
        'trap \'rm -rf "$TMP"\' EXIT',
        'echo "Validating installer..."',
    ]
    for rel in rels:
        data=base64.b64encode(bundle_payload(rel)).decode()
        parent=str(Path(rel).parent)
        if parent!='.': out.append(f'mkdir -p "$TMP/{parent}"')
        out.append(f"base64 -d >\"$TMP/{rel}\" <<'B64'")
        for i in range(0,len(data),76): out.append(data[i:i+76])
        out.append('B64')
    for rel in rels:
        if rel.endswith('.sh') or rel.startswith('tools/') or rel.endswith('.py'):
            out.append(f'chmod +x "$TMP/{rel}"')
    out.append('echo "Preparing installation..."')
    out.append('echo "Installing Data Relay Link Server..."')
    return out

# Client bundles are generated first so the server payload can include them.
SERVER_BOOTSTRAP_REF_SNIPPET = r'''if [[ -z "${FRP_EXPECTED_SOURCE_REF:-}" ]]; then
  _frp_bootstrap_ref=""
  if [[ -n "${FRP_BOOTSTRAP_URL:-}" ]]; then
    _frp_bootstrap_ref="$(python3 -c '
import sys
from urllib.parse import unquote, urlsplit
url = sys.argv[1]
host, owner = sys.argv[2:4]
allowed = set(sys.argv[4:])
try:
    p = urlsplit(url)
except ValueError:
    raise SystemExit(0)
if p.scheme != "https" or p.hostname != host:
    raise SystemExit(0)
parts = [unquote(x) for x in p.path.split("/") if x]
if len(parts) >= 3 and parts[0] == owner and parts[1] in allowed:
    print(parts[2])
' "$FRP_BOOTSTRAP_URL" raw.githubusercontent.com datarelay-labs datarelay-link data-relay-link 2>/dev/null || true)"
  fi
  if [[ -z "$_frp_bootstrap_ref" && -d /proc ]]; then
    _frp_bootstrap_ref="$(python3 - <<'PY' 2>/dev/null || true
import os, re
from urllib.parse import unquote, urlsplit
pat = re.compile(
    r"https://raw\\.githubusercontent\\.com/datarelay-labs/"
    r"(?:datarelay-link|data-relay-link)/"
    r"([^/\\s\"']+)/dist/bootstrap-server\\.sh"
)
pgid = os.getpgid(0)
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    try:
        if os.getpgid(int(name)) != pgid:
            continue
        raw = open(f"/proc/{name}/cmdline", "rb").read()
    except (OSError, ProcessLookupError, PermissionError):
        continue
    text = raw.replace(b"\\0", b" ").decode("utf-8", "replace")
    m = pat.search(text)
    if not m:
        continue
    ref = unquote(m.group(1))
    if ref and ref not in (".", ".."):
        print(ref)
        break
PY
)"
  fi
  if [[ -n "$_frp_bootstrap_ref" ]]; then
    export FRP_EXPECTED_SOURCE_REF="$_frp_bootstrap_ref"
  fi
  unset _frp_bootstrap_ref
fi'''

client_files=[
 'VERSION',
 'release-manifest.json',
 'install-client.sh',
 'uninstall-client.sh',
] + agent_source_rels() + [
 'tools/frp-client',
 'tools/drlink',
 'tools/frpctl',
 'tools/frp-support-bundle',
 'tools/frp-update',
 'client/com.datarelay.drlink.frpc.plist',
 'client/drlink-client.service',
 'client/drlink-ai-agent.service',
]
client_lines=[
 '#!/usr/bin/env bash',
 'set -euo pipefail',
 'echo "Downloading qualified Data Relay Link installer..."',
 '_frp_b64d() { base64 --decode 2>/dev/null || base64 -D; }',
 'TMP="$(mktemp -d)"',
 'trap \'rm -rf "$TMP"\' EXIT',
 'echo "Validating installer..."',
]
for rel in client_files:
    data=base64.b64encode(bundle_payload(rel)).decode()
    parent=str(Path(rel).parent)
    if parent!='.': client_lines.append(f'mkdir -p "$TMP/{parent}"')
    client_lines.append(f"_frp_b64d >\"$TMP/{rel}\" <<'B64'")
    for i in range(0,len(data),76): client_lines.append(data[i:i+76])
    client_lines.append('B64')
for rel in client_files:
    if rel.endswith('.sh') or rel.startswith('tools/'):
        client_lines.append(f'chmod +x "$TMP/{rel}"')
client_lines.append('echo "Preparing installation..."')
client_lines.append('echo "Installing Data Relay Link Agent Host..."')
client_lines.append('exec "$TMP/install-client.sh" "$@"')
(dist/'bootstrap-client.sh').write_text('\n'.join(client_lines)+'\n')
(dist/'bootstrap-client.sh').chmod(0o755)

# Windows PowerShell bootstrap: embed the complete windows/ client tree.
# dist/bootstrap-client.ps1 is generated; do not hand-edit it.
win_files = [
    path.relative_to(root).as_posix()
    for path in sorted((root / 'windows').rglob('*'))
    if path.is_file()
]
ps_lines = [
    '#Requires -Version 5.1',
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "$tmp = Join-Path $env:TEMP ('frp-win-bundle-' + [guid]::NewGuid().ToString('N'))",
    'New-Item -ItemType Directory -Force -Path $tmp | Out-Null',
    'try {',
]
for rel in win_files:
    data = base64.b64encode((root / rel).read_bytes()).decode('ascii')
    parent = str(Path(rel).parent).replace('\\', '/')
    ps_lines.append(f"  $dir = Join-Path $tmp '{parent}'")
    ps_lines.append('  New-Item -ItemType Directory -Force -Path $dir | Out-Null')
    ps_lines.append(f"  $out = Join-Path $tmp '{rel}'")
    ps_lines.append("  $b64 = @'")
    ps_lines.extend(data[i:i+120] for i in range(0, len(data), 120))
    ps_lines.append("'@")
    ps_lines.append(
        "  [IO.File]::WriteAllBytes($out, "
        "[Convert]::FromBase64String(($b64 -replace '\\s','')))"
    )
ps_lines.extend([
    "  $installer = Join-Path $tmp 'windows/install-client.ps1'",
    '  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer @args',
    '  exit $LASTEXITCODE',
    '} finally {',
    '  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue',
    '}',
])
(dist/'bootstrap-client.ps1').write_text(
    '\n'.join(ps_lines)+'\n', encoding='utf-8'
)

server_rels = list(files)
for path in sorted((root / 'third_party' / 'frp').rglob('*')):
    if path.is_file():
        server_rels.append(path.relative_to(root).as_posix())
server_rels.extend(['dist/bootstrap-client.sh', 'dist/bootstrap-client.ps1'])
lines = write_server_bundle(server_rels)
lines.append(SERVER_BOOTSTRAP_REF_SNIPPET)
lines.append('exec "$TMP/install-server.sh" "$@"')
(dist/'bootstrap-server.sh').write_text('\n'.join(lines)+'\n')
(dist/'bootstrap-server.sh').chmod(0o755)

for src,dst in [('uninstall-client.sh','uninstall-client.sh'),('uninstall-server.sh','uninstall-server.sh')]:
    (dist/dst).write_bytes((root/src).read_bytes())
    (dist/dst).chmod(0o755)
print('Built dist/bootstrap-server.sh, bootstrap-client.sh, and bootstrap-client.ps1')
