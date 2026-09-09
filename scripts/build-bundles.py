#!/usr/bin/env python3
import base64
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
dist=root/'dist'
dist.mkdir(exist_ok=True)

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
 'lib/server-project-files.manifest',
 'lib/frp-doctor-common.sh',
 'lib/frp_doctor.py',
 'lib/frp_support_bundle.py',
 'lib/frp_ctl_grammar.py',
 'lib/frp_ctl_repl.py',
 'lib/frp_access_control.py',
 'lib/frp_egress_control.py',
 'lib/frp_health_check.py',
 'lib/frp_service_profiles.py',
 'server/frp-port-allocator.py',
 'server/frp-access-plugin.py',
 'server/frp-egress-gateway.py',
 'server/migrate_token.py',
 'server/frps.service',
 'server/frp-port-allocator.service',
 'server/frp-access-plugin.service',
 'server/frp-egress-gateway.service',
 'server/frp-frontend.service',
 'tools/frp-create-client',
 'tools/frp-enrollments',
 'tools/frp-enrollment-revoke',
 'tools/frp-enrollment-purge',
 'tools/frp-enroll-bulk',
 'tools/frp-clients',
 'tools/frp-client-info',
 'tools/frp-groups',
 'tools/frp-group-set',
 'tools/frp-release-client',
 'tools/frp-release-service',
 'tools/frp-access',
 'tools/frp-egress',
 'tools/frp-profile',
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

lines=['#!/usr/bin/env bash','set -euo pipefail','TMP="$(mktemp -d)"','trap \'rm -rf "$TMP"\' EXIT']
for rel in files:
    data=base64.b64encode(bundle_payload(rel)).decode()
    parent=str(Path(rel).parent)
    if parent!='.': lines.append(f'mkdir -p "$TMP/{parent}"')
    lines.append(f"base64 -d >\"$TMP/{rel}\" <<'B64'")
    for i in range(0,len(data),76): lines.append(data[i:i+76])
    lines.append('B64')
for rel in files:
    if rel.endswith('.sh') or rel.startswith('tools/') or rel.endswith('.py'):
        lines.append(f'chmod +x "$TMP/{rel}"')
lines.append('exec "$TMP/install-server.sh" "$@"')
(dist/'bootstrap-server.sh').write_text('\n'.join(lines)+'\n')
(dist/'bootstrap-server.sh').chmod(0o755)

client_files=[
 'VERSION',
 'release-manifest.json',
 'install-client.sh',
 'uninstall-client.sh',
 'lib/frp-common.sh',
 'lib/frp-macos.sh',
 'lib/frp-client-common.sh',
 'lib/frp_mgmt_auth.py',
 'lib/frp_health_check.py',
 'lib/frp-doctor-common.sh',
 'lib/frp_doctor.py',
 'lib/frp_support_bundle.py',
 'lib/frp_ctl_grammar.py',
 'lib/frp_ctl_repl.py',
 'lib/frp-role-ownership.sh',
 'tools/frp-client',
 'tools/drlink',
 'tools/frpctl',
 'tools/frp-support-bundle',
 'tools/frp-update',
 'client/com.datarelay.frp-auto-deploy.frpc.plist',
]
client_lines=[
 '#!/usr/bin/env bash',
 'set -euo pipefail',
 '_frp_b64d() { base64 --decode 2>/dev/null || base64 -D; }',
 'TMP="$(mktemp -d)"',
 'trap \'rm -rf "$TMP"\' EXIT',
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

for src,dst in [('uninstall-client.sh','uninstall-client.sh'),('uninstall-server.sh','uninstall-server.sh')]:
    (dist/dst).write_bytes((root/src).read_bytes())
    (dist/dst).chmod(0o755)
print('Built dist/bootstrap-server.sh, bootstrap-client.sh, and bootstrap-client.ps1')
