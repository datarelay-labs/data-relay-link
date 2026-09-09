#!/usr/bin/env python3
import base64
import json
import os
import subprocess
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

def read_project_version():
    values = {}
    for line in (root / 'VERSION').read_text(encoding='utf-8').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values.get('PROJECT_VERSION', '0.0.0')

def detect_build_provenance():
    """Return (channel, source_ref) for this working tree build.

    Exact tag vPROJECT_VERSION → stable / that tag.
    Otherwise → development / immutable commit SHA (never claim a stable tag).
    """
    project = read_project_version()
    expected_tag = 'v%s' % project
    override_ref = (os.environ.get('FRP_BUILD_SOURCE_REF') or '').strip()
    override_channel = (os.environ.get('FRP_BUILD_RELEASE_CHANNEL') or '').strip().lower()
    if override_ref:
        channel = override_channel or (
            'stable' if override_ref == expected_tag else 'dev'
        )
        if channel in ('development', 'main'):
            channel = 'dev'
        if channel not in ('dev', 'stable'):
            channel = 'dev'
        return channel, override_ref
    try:
        exact = subprocess.check_output(
            ['git', '-C', str(root), 'describe', '--tags', '--exact-match', 'HEAD'],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        exact = ''
    if exact == expected_tag:
        return 'stable', expected_tag
    try:
        sha = subprocess.check_output(
            ['git', '-C', str(root), 'rev-parse', 'HEAD'],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        # Fallback: release-manifest line identity when git is unavailable.
        try:
            data = json.loads((root / 'release-manifest.json').read_text(encoding='utf-8'))
            channel = str(data.get('channel') or 'stable').strip().lower()
            ref = str(data.get('git_ref') or expected_tag).strip()
            if channel in ('development', 'main'):
                channel = 'dev'
            if channel not in ('dev', 'stable'):
                channel = 'stable'
            return channel, ref
        except Exception:
            return 'stable', expected_tag
    return 'dev', sha

def provenance_preamble(channel, source_ref):
    # Shell-safe single-quoted embeds (refs are hex / vX.Y.Z / main).
    def sh_quote(value):
        return "'" + value.replace("'", "'\"'\"'") + "'"
    return [
        '# Bundle provenance stamped at build time.',
        'if [[ -z "${FRP_SOURCE_REF:-}" ]]; then',
        '  export FRP_SOURCE_REF=%s' % sh_quote(source_ref),
        'fi',
        'if [[ -z "${FRP_RELEASE_CHANNEL:-}" ]]; then',
        '  export FRP_RELEASE_CHANNEL=%s' % sh_quote(channel),
        'fi',
        '# Prefer hashing the on-disk bootstrap when not piped via stdin.',
        'if [[ -z "${FRP_BUNDLE_SHA256:-}" ]]; then',
        '  _frp_self="${BASH_SOURCE[0]:-}"',
        '  if [[ -n "$_frp_self" && -f "$_frp_self" ]]; then',
        '    FRP_BUNDLE_SHA256="$(sha256sum "$_frp_self" 2>/dev/null | awk \'{print $1}\')"',
        '    export FRP_BUNDLE_SHA256',
        '  fi',
        '  unset _frp_self',
        'fi',
    ]

BUILD_CHANNEL, BUILD_SOURCE_REF = detect_build_provenance()

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
 'lib/frp_server_reconfigure.py',
 'lib/frp_zero_touch.py',
 'lib/server-project-files.manifest',
 'lib/frp-doctor-common.sh',
 'lib/frp_doctor.py',
 'lib/frp_support_bundle.py',
 'lib/frp_ctl_grammar.py',
 'lib/frp_ctl_repl.py',
 'lib/frp_service_id.py',
 'lib/frp_access_control.py',
 'lib/frp_health_check.py',
 'lib/frp_service_profiles.py',
 'server/frp-port-allocator.py',
 'server/frp-access-plugin.py',
 'server/migrate_token.py',
 'server/frps.service',
 'server/frp-port-allocator.service',
 'server/frp-access-plugin.service',
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
 'tools/frpctl',
]

lines=['#!/usr/bin/env bash','set -euo pipefail']
lines.extend(provenance_preamble(BUILD_CHANNEL, BUILD_SOURCE_REF))
lines.extend(['TMP="$(mktemp -d)"','trap \'rm -rf "$TMP"\' EXIT'])
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
 'lib/frp_service_id.py',
 'lib/frp-role-ownership.sh',
 'tools/frp-client',
 'tools/frpctl',
 'tools/frp-support-bundle',
 'tools/frp-update',
 'client/com.datarelay.frp-auto-deploy.frpc.plist',
]
client_lines=[
 '#!/usr/bin/env bash',
 'set -euo pipefail',
]
client_lines.extend(provenance_preamble(BUILD_CHANNEL, BUILD_SOURCE_REF))
client_lines.extend([
 '_frp_b64d() { base64 --decode 2>/dev/null || base64 -D; }',
 'TMP="$(mktemp -d)"',
 'trap \'rm -rf "$TMP"\' EXIT',
])
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
    # Provenance for Windows enroll (mirrors bash bootstrap stamps).
    f"if (-not $env:FRP_SOURCE_REF) {{ $env:FRP_SOURCE_REF = '{BUILD_SOURCE_REF}' }}",
    f"if (-not $env:FRP_RELEASE_CHANNEL) {{ $env:FRP_RELEASE_CHANNEL = '{BUILD_CHANNEL}' }}",
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
print(
    'Built dist/bootstrap-server.sh, bootstrap-client.sh, and bootstrap-client.ps1'
    f' (channel={BUILD_CHANNEL} source_ref={BUILD_SOURCE_REF})'
)
