#!/usr/bin/env python3
"""Shared Zero-Touch short-command helpers (zt1 package + short URL script).

The short URL is a thin entry layer over the existing zt1/bootstrap/redeem
enrollment path. It does not replace Private CA management trust.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from urllib.parse import urlparse

ZERO_TOUCH_PACKAGE_PREFIX = 'zt1'
BOOTSTRAP_TICKET_RE = re.compile(
    r'^bt1\.[0-9a-f]{16}\.[0-9a-f]{64}$',
    re.IGNORECASE,
)
# 128-bit CSPRNG capability, unpadded base64url. Must match allocator parsing.
COMPACT_CREDENTIAL_RE = re.compile(r'^[A-Za-z0-9_-]{22}$')
DNS_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$'
)
# Characters that are safe unquoted in POSIX sh for this URL shape.
SHELL_UNSAFE_URL_RE = re.compile(r'[^A-Za-z0-9:/._-]')
# Redact opaque tickets in /i/<ticket> request paths and URLs.
SHORT_URL_PATH_RE = re.compile(r'(/i/)([^/?\s#]+)', re.IGNORECASE)
ZT1_TOKEN_RE = re.compile(r'zt1\.[A-Za-z0-9_-]{16,}', re.IGNORECASE)
BT1_TOKEN_RE = re.compile(r'bt1\.[0-9a-f]{16}\.[0-9a-f]{32,}', re.IGNORECASE)
BOOTSTRAP_ENV_RE = re.compile(r'(FRP_BOOTSTRAP_TICKET\s*=\s*)\S+', re.IGNORECASE)


def accepted_bootstrap_credential(ticket):
    text = str(ticket or '').strip()
    return bool(
        BOOTSTRAP_TICKET_RE.fullmatch(text) or COMPACT_CREDENTIAL_RE.fullmatch(text)
    )


def bootstrap_record_id(ticket):
    """Internal ticket-file id for a public credential.

    Legacy bt1 uses the explicit id. Compact credentials use the first 16 hex
    chars of SHA-256 over the exact ASCII credential (same derivation as the
    allocator). Returns '' when the credential is not an accepted form.
    """
    text = str(ticket or '').strip()
    if BOOTSTRAP_TICKET_RE.fullmatch(text):
        return text.split('.')[1].lower()
    if COMPACT_CREDENTIAL_RE.fullmatch(text):
        return hashlib.sha256(text.encode('ascii')).hexdigest()[:16]
    return ''


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
    if not accepted_bootstrap_credential(ticket):
        raise ValueError('invalid bootstrap ticket for short URL')
    return 'https://%s/i/%s' % (host, ticket)


def short_url_command(hostname, ticket):
    url = short_url_for_ticket(hostname, ticket)
    host = str(hostname or '').strip().lower().rstrip('.')
    cred = str(ticket or '').strip()
    if (
        DNS_HOSTNAME_RE.fullmatch(host)
        and accepted_bootstrap_credential(cred)
        and SHELL_UNSAFE_URL_RE.search(url) is None
    ):
        return 'curl -fsSL %s|sudo bash' % url
    return 'curl -fsSL %s | sudo bash' % shell_quote(url)


def https_origin(url):
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("URL must be HTTPS")
    return "https://%s" % parsed.netloc


def same_https_origin(left, right):
    """True when two HTTPS URLs share a host and port (443 is the default)."""
    try:
        a = urlparse(str(left or "").strip())
        b = urlparse(str(right or "").strip())
    except Exception:
        return False
    if a.scheme != "https" or b.scheme != "https":
        return False

    def key(parsed):
        return ((parsed.hostname or "").lower(), parsed.port or 443)

    return key(a) == key(b)


def private_ca_fresh_client_command(hostname, ticket, ca_pem):
    """One-line Linux/macOS Zero-Touch command for a private-CA enrollment host.

    The operator session already holds the public CA certificate. The command
    embeds that certificate, verifies the short-URL fetch with ``--cacert``,
    and exports ``FRP_ALLOCATOR_CA_FILE`` so later same-origin downloads and
    enrollment pin the same trust anchor. TLS verification stays enabled.
    """
    url = short_url_for_ticket(hostname, ticket)
    pem = str(ca_pem or "")
    if "PRIVATE KEY" in pem or "BEGIN CERTIFICATE" not in pem:
        raise ValueError("allocator CA certificate is required")
    pem = pem.strip() + "\n"
    try:
        encoded = base64.b64encode(pem.encode("ascii")).decode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("allocator CA certificate is not ASCII PEM") from exc
    if not encoded or any(ch.isspace() for ch in encoded):
        raise ValueError("allocator CA certificate encoding failed")
    inner = (
        "set -euo pipefail; "
        "d=$(mktemp -d); "
        "trap 'rm -rf \"$d\"' EXIT; "
        "umask 077; "
        "python3 -c \"import base64,sys; open(sys.argv[1],'wb').write(base64.b64decode(sys.argv[2]))\" "
        "\"$d/ca.crt\" %s; "
        "openssl x509 -in \"$d/ca.crt\" -noout >/dev/null; "
        "export FRP_ALLOCATOR_CA_FILE=\"$d/ca.crt\"; "
        "curl -fsSL --proto =https --tlsv1.2 --cacert \"$d/ca.crt\" %s | bash"
    ) % (shell_quote(encoded), shell_quote(url))
    if "--insecure" in inner or re.search(r"(^|[ \t])curl -k([ \t]|$)", inner):
        raise ValueError("refusing insecure fresh-client command")
    return "sudo bash -c %s" % shell_quote(inner)


def ca_crt_url(allocator_url):
    return https_origin(allocator_url) + "/ca.crt"


def pinned_ca_linux_command(installer_url, allocator_url, ca_sha256, package):
    """Pasteable Linux/macOS Zero-Touch command for a Private CA allocator.

    Stock ``curl -fsSL`` cannot fetch the Server-local installer until the
    allocator CA is trusted. Download ``/ca.crt`` insecurely, pin it by the
    SHA-256 already carried in the zt1 package, then fetch the installer
    with ``--cacert``. Same bootstrap rule as ``frp_bootstrap_allocator_ca``.
    """
    installer = str(installer_url or "").strip()
    fp = str(ca_sha256 or "").strip().lower()
    pkg = str(package or "").strip()
    if not installer.lower().startswith("https://"):
        raise ValueError("installer URL must be HTTPS")
    if len(fp) != 64 or any(ch not in "0123456789abcdef" for ch in fp):
        raise ValueError("invalid CA fingerprint")
    if not pkg.startswith("zt1."):
        raise ValueError("invalid zero-touch package")
    ca_url = ca_crt_url(allocator_url)
    inner = (
        "set -euo pipefail; "
        "d=$(mktemp -d /tmp/drlink-zt.XXXXXX); "
        'trap "rm -rf $d" EXIT; '
        "curl --fail --silent --show-error --max-time 30 --proto =https --insecure "
        "-o $d/ca.crt %s; "
        "openssl x509 -in $d/ca.crt -outform DER -out $d/ca.der >/dev/null; "
        'fp=$(openssl dgst -sha256 $d/ca.der | awk "{print \\$NF}" | tr A-F a-f); '
        "test \"$fp\" = %s; "
        "curl -fsSL --proto =https --cacert $d/ca.crt %s | bash -s -- %s"
    ) % (
        shell_quote(ca_url),
        shell_quote(fp),
        shell_quote(installer),
        shell_quote(pkg),
    )
    return "sudo bash -c %s" % shell_quote(inner)


def pinned_ca_windows_inner(
    installer_url, allocator_url, ca_sha256, ticket, sums_url
):
    """PowerShell -Command body: pin /ca.crt, then verified installer download."""
    installer = str(installer_url or "").strip()
    fp = str(ca_sha256 or "").strip().lower()
    ticket = str(ticket or "").strip()
    allocator = str(allocator_url or "").strip()
    sums = str(sums_url or "").strip()
    if not installer.lower().startswith("https://"):
        raise ValueError("installer URL must be HTTPS")
    if not allocator.lower().startswith("https://"):
        raise ValueError("allocator URL must be HTTPS")
    if not sums.lower().startswith("https://"):
        raise ValueError("SHA256SUMS URL must be HTTPS")
    if len(fp) != 64 or any(ch not in "0123456789abcdef" for ch in fp):
        raise ValueError("invalid CA fingerprint")
    ca_url = ca_crt_url(allocator_url)
    return (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "$d=Join-Path $env:TEMP ('frp-bs-'+[guid]::NewGuid().ToString('N'));"
        "New-Item -ItemType Directory -Force -Path $d|Out-Null;"
        "try{"
        "$ca=Join-Path $d 'ca.crt';$m=Join-Path $d 'SHA256SUMS';$p=Join-Path $d 'bootstrap-client.ps1';"
        "$curl=Get-Command curl.exe -ErrorAction Stop;"
        "& $curl.Source --fail --silent --show-error --max-time 30 --proto =https --insecure -o $ca "
        + powershell_quote(ca_url)
        + ";"
        "$cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ca);"
        "$fp=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)) -replace '-','' ;"
        "if($fp.ToLowerInvariant() -ne "
        + powershell_quote(fp)
        + "){throw 'CA fingerprint mismatch'};"
        "& $curl.Source --fail --silent --show-error --max-time 60 --proto =https --cacert $ca --ssl-no-revoke -o $m "
        + powershell_quote(sums)
        + ";"
        "if($LASTEXITCODE -ne 0){throw 'SHA256SUMS download failed'};"
        "& $curl.Source --fail --silent --show-error --max-time 60 --proto =https --cacert $ca --ssl-no-revoke -o $p "
        + powershell_quote(installer)
        + ";"
        "if($LASTEXITCODE -ne 0){throw 'bootstrap-client.ps1 download failed'};"
        "$w=$null;Get-Content -LiteralPath $m|ForEach-Object{"
        "if($_ -match '^([0-9a-fA-F]{64})\\s+(?:dist/bootstrap-client\\.ps1|agent/bootstrap-client\\.ps1|bootstrap-client\\.ps1)\\s*$'){"
        "if($w){throw 'duplicate bootstrap-client.ps1 hash'};"
        "$w=$Matches[1].ToLowerInvariant()}};"
        "if(-not $w){throw 'bootstrap-client.ps1 hash missing from SHA256SUMS'};"
        "$g=(Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant();"
        "if($g -ne $w){throw 'bootstrap-client.ps1 SHA256 mismatch'};"
        "$env:FRP_ALLOCATOR_URL="
        + powershell_quote(allocator)
        + ";"
        "$env:FRP_ALLOCATOR_CA_SHA256="
        + powershell_quote(fp)
        + ";"
        "$env:FRP_BOOTSTRAP_TICKET="
        + powershell_quote(ticket)
        + ";"
        "$env:FRP_ZERO_TOUCH='1';$env:FRP_PLATFORM='windows';"
        "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p -ZeroTouch;"
        "$rc=$LASTEXITCODE;Remove-Item Env:FRP_BOOTSTRAP_TICKET -ErrorAction SilentlyContinue;"
        "if($rc -ne 0){exit $rc}"
        "}finally{Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue}"
    )


def pinned_ca_windows_command(
    installer_url, allocator_url, ca_sha256, ticket, sums_url
):
    inner = pinned_ca_windows_inner(
        installer_url, allocator_url, ca_sha256, ticket, sums_url
    )
    return (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
        + powershell_quote(inner)
    )


def powershell_quote(value):
    """Return a PowerShell single-quoted literal."""
    return "'" + str(value).replace("'", "''") + "'"


def windows_strict_launcher(hostname, credential, stage1_sha256):
    """Direct elevated PowerShell launcher. Hash-before-execute, no outer -Command.

    Baseline for remote.xdr.ooo + 22-char credential + 64-hex digest is 420 chars.
    """
    digest = str(stage1_sha256 or '').strip().lower()
    if len(digest) != 64 or any(ch not in '0123456789abcdef' for ch in digest):
        raise ValueError('invalid stage-1 SHA256')
    url = short_url_for_ticket(hostname, credential) + '?platform=windows'
    if re.search(r'[^A-Za-z0-9:/._?=-]', url):
        raise ValueError('windows short URL is not command-safe')
    return (
        "$h='%s';$p=\"$env:TEMP\\d-$([guid]::NewGuid()).ps1\";"
        "try{curl.exe -fsSLo $p %s;if($LASTEXITCODE){exit $LASTEXITCODE};"
        "if((Get-FileHash $p).Hash -ne $h){exit 90};"
        "&powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p;exit $LASTEXITCODE}"
        "finally{Remove-Item $p -Force -ErrorAction SilentlyContinue}"
    ) % (digest, url)


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
    if not installer.lower().startswith('https://'):
        raise ValueError('installer URL must be HTTPS')
    marker = '/artifacts/'
    if marker in installer:
        return installer.split(marker, 1)[0] + '/artifacts/SHA256SUMS'
    for suffix in ('/dist/bootstrap-client.ps1', '/dist/bootstrap-client.sh'):
        if installer.endswith(suffix):
            return installer[: -len(suffix)] + '/SHA256SUMS'
    # Non-release layouts (tests / custom mirrors): SHA256SUMS beside the installer.
    if '/' not in installer[8:]:
        raise ValueError('installer URL path is incomplete')
    parent = installer.rsplit('/', 1)[0]
    return parent + '/SHA256SUMS'


def linux_installer_sum_names(installer_url):
    """Return candidate SHA256SUMS pathnames for the Linux installer artifact."""
    installer = str(installer_url or '').strip()
    if installer.endswith('/artifacts/agent/bootstrap-client.sh'):
        return ('agent/bootstrap-client.sh',)
    if installer.endswith('/dist/bootstrap-client.sh'):
        return ('dist/bootstrap-client.sh',)
    name = installer.rsplit('/', 1)[-1]
    if not name:
        raise ValueError('Linux installer URL must include a filename')
    if name == 'bootstrap-client.sh':
        return ('dist/bootstrap-client.sh', 'bootstrap-client.sh', 'agent/bootstrap-client.sh')
    return (name,)


def _pinned_or_stock_curl_line(url_var, dest_var, pin_private_ca):
    """Curl one HTTPS URL, pinning the allocator CA when the origin matches.

    ``FRP_ALLOCATOR_CA_FILE`` is set by the fresh-client command. A distinct
    public installer origin keeps stock OS trust. Neither path uses
    ``--insecure``.
    """
    stock = 'curl -fsSL --proto "=https" --tlsv1.2 "$%s" -o "$%s"' % (url_var, dest_var)
    if not pin_private_ca:
        return stock
    return (
        'if [[ -n "${FRP_ALLOCATOR_CA_FILE:-}" && -f "$FRP_ALLOCATOR_CA_FILE" ]]; then '
        'curl -fsSL --proto "=https" --tlsv1.2 --cacert "$FRP_ALLOCATOR_CA_FILE" '
        '"$%s" -o "$%s"; else %s; fi'
    ) % (url_var, dest_var, stock)


def render_short_url_bootstrap_script(allocator_url, ca_sha256, ticket, installer_url):
    """Return a small generic bootstrap script that reuses the zt1 installer path.

    Downloads installer + SHA256SUMS, verifies the exact expected hash, then
    executes. Same-origin HTTPS checksum integrity — not signed authentication.
    """
    package = encode_zero_touch_package(allocator_url, ca_sha256, ticket)
    installer = str(installer_url or '').strip()
    if not installer.lower().startswith('https://'):
        raise ValueError('installer URL must be HTTPS')
    sums_url = sha256sums_url_for_installer(installer)
    expected_names = linux_installer_sum_names(installer)
    names_csv = ','.join(expected_names)
    lines = [
        '#!/bin/bash',
        '# Data Relay Link — Zero-Touch short URL bootstrap',
        '# Generic entry script. Enrollment profile remains server-side.',
        '# Integrity: download SHA256SUMS + installer, verify, then execute.',
        '# Not a cryptographic signature — same-origin HTTPS checksum only.',
        'set -euo pipefail',
        'if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then',
        '  echo "ERROR: re-run as: curl -fsSL <bootstrap-url>|sudo bash" >&2',
        '  exit 1',
        'fi',
        'INSTALLER_URL=%s' % shell_quote(installer),
        'SUMS_URL=%s' % shell_quote(sums_url),
        'EXPECTED_NAMES=%s' % shell_quote(names_csv),
        'PACKAGE=%s' % shell_quote(package),
        'WORKDIR="$(mktemp -d /tmp/drlink-bootstrap.XXXXXX)"',
        'cleanup() { rm -rf "$WORKDIR"; }',
        'trap cleanup EXIT',
        'umask 077',
        'SUMS_FILE="$WORKDIR/SHA256SUMS"',
        'INSTALLER_FILE="$WORKDIR/bootstrap-client.sh"',
        _pinned_or_stock_curl_line('SUMS_URL', 'SUMS_FILE', same_https_origin(sums_url, allocator_url)),
        _pinned_or_stock_curl_line('INSTALLER_URL', 'INSTALLER_FILE', same_https_origin(installer, allocator_url)),
        'WANT="$(awk -v names="$EXPECTED_NAMES" \'BEGIN{split(names,a,","); for(i in a) ok[a[i]]=1; c=0} ($2 in ok){print tolower($1); c++} END{if(c!=1) exit 1}\' "$SUMS_FILE")"',
        'GOT="$(sha256sum "$INSTALLER_FILE" | awk \'{print tolower($1)}\')"',
        'if [[ "$GOT" != "$WANT" ]]; then',
        '  echo "ERROR: installer SHA256 mismatch (integrity check failed)" >&2',
        '  exit 1',
        'fi',
        'chmod 0700 "$INSTALLER_FILE"',
        '# Same-origin artifacts use FRP_ALLOCATOR_CA_FILE when the fresh-client',
        '# command supplied it. A distinct public installer origin uses stock OS trust.',
        '# The installer then pins this CA by fingerprint before enrollment.',
        'bash "$INSTALLER_FILE" "$PACKAGE"',
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
    if not accepted_bootstrap_credential(ticket):
        raise ValueError('invalid bootstrap ticket')
    if not installer.lower().startswith('https://'):
        raise ValueError('installer URL must be HTTPS')
    sums_url = sha256sums_url_for_installer(installer)
    lines = [
        '#Requires -Version 5.1',
        "# Data Relay Link - Windows Zero-Touch short URL bootstrap",
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
        "    if ($_ -match '^([0-9a-fA-F]{64})\\s+(?:dist/bootstrap-client\\.ps1|agent/bootstrap-client\\.ps1|bootstrap-client\\.ps1)\\s*$') {",
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
    out = BOOTSTRAP_ENV_RE.sub(r'\1<redacted>', out)
    out = BT1_TOKEN_RE.sub('bt1.<redacted>', out)
    out = ZT1_TOKEN_RE.sub('zt1.<redacted>', out)
    return out
