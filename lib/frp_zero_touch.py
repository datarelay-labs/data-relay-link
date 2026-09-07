#!/usr/bin/env python3
"""Shared Zero-Touch short-command helpers (zt1 package + short URL script).

The short URL is a thin entry layer over the existing zt1/bootstrap/redeem
enrollment path. It does not replace Private CA management trust.
"""
from __future__ import annotations

import base64
import json
import re
import shlex

ZERO_TOUCH_PACKAGE_PREFIX = 'zt1'
BOOTSTRAP_TICKET_RE = re.compile(
    r'^bt1\.[0-9a-f]{16}\.[0-9a-f]{64}$',
    re.IGNORECASE,
)
# Redact opaque tickets in /i/<ticket> request paths and URLs.
SHORT_URL_PATH_RE = re.compile(r'(/i/)([^/?\s#]+)', re.IGNORECASE)
ZT1_TOKEN_RE = re.compile(r'zt1\.[A-Za-z0-9_-]{16,}', re.IGNORECASE)
BT1_TOKEN_RE = re.compile(r'bt1\.[0-9a-f]{16}\.[0-9a-f]{32,}', re.IGNORECASE)


def shell_quote(value):
    quoted = shlex.quote(str(value))
    if quoted and quoted[0] not in ("'", '"'):
        quoted = "'" + quoted + "'"
    return quoted


def encode_zero_touch_package(allocator_url, ca_sha256, ticket):
    """Encode opaque short-command package for trusted public installer bootstrap."""
    payload = {
        'v': 1,
        'u': str(allocator_url or '').strip(),
        'c': str(ca_sha256 or '').strip().lower(),
        't': str(ticket or '').strip(),
    }
    if not payload['u'].lower().startswith('https://') or not payload['c'] or not payload['t']:
        raise ValueError('incomplete zero-touch package')
    if len(payload['c']) != 64 or any(ch not in '0123456789abcdef' for ch in payload['c']):
        raise ValueError('invalid CA fingerprint in zero-touch package')
    raw = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    token = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    return '%s.%s' % (ZERO_TOUCH_PACKAGE_PREFIX, token)


def decode_zero_touch_package(package):
    """Decode zt1.* package into allocator URL, CA SHA256, and bootstrap ticket."""
    text = str(package or '').strip()
    parts = text.split('.', 1)
    if len(parts) != 2 or parts[0] != ZERO_TOUCH_PACKAGE_PREFIX or not parts[1]:
        raise ValueError('invalid zero-touch package')
    padded = parts[1] + ('=' * (-len(parts[1]) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode('ascii'))
        payload = json.loads(raw.decode('utf-8'))
    except Exception as exc:
        raise ValueError('invalid zero-touch package') from exc
    if not isinstance(payload, dict) or int(payload.get('v') or 0) != 1:
        raise ValueError('unsupported zero-touch package version')
    url = str(payload.get('u') or '').strip()
    ca = str(payload.get('c') or '').strip().lower()
    ticket = str(payload.get('t') or '').strip()
    if not url.lower().startswith('https://') or len(ca) != 64 or not ticket:
        raise ValueError('incomplete zero-touch package')
    if any(ch not in '0123456789abcdef' for ch in ca):
        raise ValueError('invalid CA fingerprint in zero-touch package')
    return url, ca, ticket


def bootstrap_hostname(cfg):
    """Optional publicly trusted Zero-Touch bootstrap hostname (not public_hostname)."""
    if not isinstance(cfg, dict):
        return ''
    return str(cfg.get('bootstrap_hostname') or '').strip().lower()


def short_url_for_ticket(hostname, ticket):
    host = str(hostname or '').strip().lower().rstrip('.')
    ticket = str(ticket or '').strip()
    if not host or not ticket:
        raise ValueError('bootstrap hostname and ticket are required')
    if not BOOTSTRAP_TICKET_RE.fullmatch(ticket):
        raise ValueError('invalid bootstrap ticket for short URL')
    return 'https://%s/i/%s' % (host, ticket)


def short_url_command(hostname, ticket):
    url = short_url_for_ticket(hostname, ticket)
    return 'curl -fsSL %s | sudo bash' % shell_quote(url)


def powershell_quote(value):
    """Return a PowerShell single-quoted literal."""
    return "'" + str(value).replace("'", "''") + "'"


def short_url_windows_command(hostname, ticket):
    """Download the short bootstrap and execute it with PowerShell -File."""
    url = short_url_for_ticket(hostname, ticket) + '?platform=windows'
    script = (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "$p=Join-Path $env:TEMP ('frp-short-'+[guid]::NewGuid().ToString('N')+'.ps1');"
        "try{"
        "(New-Object Net.WebClient).DownloadFile(%s,$p);"
        "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p;"
        "$rc=$LASTEXITCODE;if($rc -ne 0){exit $rc}"
        "}finally{Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue}"
    ) % powershell_quote(url)
    return (
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
        + powershell_quote(script)
    )


def sha256sums_url_for_installer(installer_url):
    installer = str(installer_url or '').strip()
    suffix = '/dist/bootstrap-client.ps1'
    if not installer.endswith(suffix):
        raise ValueError(
            'Windows installer URL must end with /dist/bootstrap-client.ps1'
        )
    sums_url = installer[:-len(suffix)] + '/SHA256SUMS'
    if not sums_url.lower().startswith('https://'):
        raise ValueError('SHA256SUMS URL must be HTTPS')
    return sums_url


def render_short_url_bootstrap_script(allocator_url, ca_sha256, ticket, installer_url):
    """Return a small generic bootstrap script that reuses the zt1 installer path.

    Contains only locator/trust/ticket data required to continue through the
    existing redeem + enroll flow. Enrollment profile stays server-side.
    """
    package = encode_zero_touch_package(allocator_url, ca_sha256, ticket)
    installer = str(installer_url or '').strip()
    if not installer.lower().startswith('https://'):
        raise ValueError('installer URL must be HTTPS')
    lines = [
        '#!/bin/bash',
        '# FRP Auto Deploy — Zero-Touch short URL bootstrap',
        '# Generic entry script. Enrollment profile remains server-side.',
        'set -euo pipefail',
        'if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then',
        '  echo "ERROR: re-run as: curl -fsSL <bootstrap-url> | sudo bash" >&2',
        '  exit 1',
        'fi',
        'INSTALLER=%s' % shell_quote(installer),
        'PACKAGE=%s' % shell_quote(package),
        '# Stock OS trust for the publicly trusted installer URL only.',
        '# Allocator/Private-CA trust comes from the opaque package pin.',
        'curl -fsSL --proto "=https" --tlsv1.2 "$INSTALLER" | bash -s -- "$PACKAGE"',
        '',
    ]
    return '\n'.join(lines)


def render_short_url_windows_bootstrap_script(
    allocator_url, ca_sha256, ticket, installer_url
):
    """Return a PowerShell bootstrap that verifies the installer before -File."""
    allocator = str(allocator_url or '').strip()
    ca = str(ca_sha256 or '').strip().lower()
    ticket = str(ticket or '').strip()
    installer = str(installer_url or '').strip()
    if not allocator.lower().startswith('https://'):
        raise ValueError('allocator URL must be HTTPS')
    if len(ca) != 64 or any(ch not in '0123456789abcdef' for ch in ca):
        raise ValueError('invalid CA fingerprint')
    if not BOOTSTRAP_TICKET_RE.fullmatch(ticket):
        raise ValueError('invalid bootstrap ticket')
    if not installer.lower().startswith('https://'):
        raise ValueError('installer URL must be HTTPS')
    sums_url = sha256sums_url_for_installer(installer)
    lines = [
        '#Requires -Version 5.1',
        "# FRP Auto Deploy - Windows Zero-Touch short URL bootstrap",
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
        "$dir = Join-Path $env:TEMP ('frp-bs-' + [guid]::NewGuid().ToString('N'))",
        'New-Item -ItemType Directory -Force -Path $dir | Out-Null',
        'try {',
        "  $sums = Join-Path $dir 'SHA256SUMS'",
        "  $installer = Join-Path $dir 'bootstrap-client.ps1'",
        '  (New-Object Net.WebClient).DownloadFile(%s, $sums)' % powershell_quote(sums_url),
        '  (New-Object Net.WebClient).DownloadFile(%s, $installer)' % powershell_quote(installer),
        '  $want = $null',
        '  Get-Content -LiteralPath $sums | ForEach-Object {',
        "    if ($_ -match '^([0-9a-fA-F]{64})\\s+dist/bootstrap-client\\.ps1\\s*$') {",
        '      if ($want) { throw "duplicate bootstrap-client.ps1 hash" }',
        '      $want = $Matches[1].ToLowerInvariant()',
        '    }',
        '  }',
        '  if (-not $want) { throw "bootstrap-client.ps1 hash missing from SHA256SUMS" }',
        '  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()',
        '  if ($got -ne $want) { throw "bootstrap-client.ps1 SHA256 mismatch" }',
        '  $env:FRP_ALLOCATOR_URL = %s' % powershell_quote(allocator),
        '  $env:FRP_ALLOCATOR_CA_SHA256 = %s' % powershell_quote(ca),
        '  $env:FRP_BOOTSTRAP_TICKET = %s' % powershell_quote(ticket),
        "  $env:FRP_ZERO_TOUCH = '1'",
        "  $env:FRP_PLATFORM = 'windows'",
        '  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -ZeroTouch',
        '  $rc = $LASTEXITCODE',
        '  Remove-Item Env:FRP_BOOTSTRAP_TICKET -ErrorAction SilentlyContinue',
        '  if ($rc -ne 0) { exit $rc }',
        '} finally {',
        '  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue',
        '}',
        '',
    ]
    return '\n'.join(lines)


def redact_text(text):
    """Redact bootstrap tickets, zt1 packages, and /i/<ticket> path segments."""
    if not text:
        return ''
    out = str(text)
    out = SHORT_URL_PATH_RE.sub(r'\1<redacted>', out)
    out = BT1_TOKEN_RE.sub('bt1.<redacted>', out)
    out = ZT1_TOKEN_RE.sub('zt1.<redacted>', out)
    return out
