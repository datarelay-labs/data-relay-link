#!/usr/bin/env python3
"""Shared server config helpers for public IP vs optional public hostname.

control_host  — FRP control / infrastructure endpoint (public_ip, legacy public_host)
access_host   — user-facing published-service endpoint (public_hostname or control_host)
public_url_host — install-time canonical host for Enrollment/Management HTTPS,
                  allocator URL, Server-local installer links, Zero-Touch commands,
                  and status/help public links (domain or IP, chosen once at install)

public_hostname is an optional DNS alias for published-service access and may
also be selected as public_url_host. It must never become the default FRP
control destination or PKI identity by itself.

bootstrap_hostname is an optional advanced override for a publicly trusted
Zero-Touch edge. When unset, a DNS public_url_host is still the short-URL
host, but that host presents the project private CA. The advertised command
must carry that CA; stock curl cannot validate it on a fresh client.
"""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse


def durable_replace(tmp, path):
    """Shared durable replace (lib/frp_control_locks.py)."""
    mod = sys.modules.get('frp_control_locks')
    if mod is None:
        spec = importlib.util.spec_from_file_location(
            'frp_control_locks', str(Path(__file__).resolve().parent / 'frp_control_locks.py')
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules['frp_control_locks'] = mod
        spec.loader.exec_module(mod)
    return mod.durable_replace(tmp, path)


# DNS hostname: labels of [A-Za-z0-9-] separated by dots; no scheme/port/path.
_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$'
)
_UNSAFE_HOST_CHARS = set(' \t\r\n/;|&$`<>\'"\\@?#%{}[]()=+~*^!')


class ConfigError(ValueError):
    pass


def _strip(value):
    if value is None:
        return ''
    return str(value).strip()


def is_ip_literal(value):
    text = _strip(value)
    if not text:
        return False
    if text.startswith('[') and text.endswith(']'):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def validate_public_ip(value, *, required=True, allow_hostname=False):
    """Validate a public IP (or legacy hostname when allow_hostname=True)."""
    text = _strip(value)
    if not text:
        if required:
            raise ConfigError('public IP is required')
        return ''
    if any(ch in text for ch in _UNSAFE_HOST_CHARS) or '/' in text:
        raise ConfigError('public IP contains invalid characters')
    if is_ip_literal(text):
        # Normalize bracketed IPv6 input to bare form for storage.
        if text.startswith('[') and text.endswith(']'):
            return text[1:-1]
        return text
    if allow_hostname:
        validate_public_hostname(text, required=True)
        return text
    raise ConfigError('public IP must be an IPv4 or IPv6 address')


def validate_public_hostname(value, *, required=False):
    """Validate an optional DNS hostname (not an IP, URL, or host:port)."""
    text = _strip(value)
    if not text:
        if required:
            raise ConfigError('public hostname is required')
        return ''
    lowered = text.lower()
    if lowered.startswith(('http://', 'https://')):
        raise ConfigError('public hostname must not include a URL scheme')
    if any(ch in text for ch in _UNSAFE_HOST_CHARS):
        raise ConfigError('public hostname contains invalid characters')
    if '@' in text or '/' in text or '?' in text or '#' in text:
        raise ConfigError('public hostname must be a bare DNS name')
    if ':' in text:
        raise ConfigError('public hostname must not include a port')
    if is_ip_literal(text):
        raise ConfigError('public hostname must be a DNS name, not an IP address')
    if not _HOSTNAME_RE.fullmatch(text):
        raise ConfigError('public hostname is not a valid DNS name')
    return text.lower()


def control_host(cfg):
    """Canonical FRP control host: public_ip preferred, then legacy public_host."""
    if not isinstance(cfg, dict):
        raise ConfigError('server config is not an object')
    for key in ('public_ip', 'public_host'):
        value = _strip(cfg.get(key))
        if value:
            return value
    raise ConfigError('public_ip is not configured')


def public_hostname(cfg):
    if not isinstance(cfg, dict):
        return ''
    try:
        return validate_public_hostname(cfg.get('public_hostname') or '', required=False)
    except ConfigError:
        # Persisted invalid values should not crash readers; treat as unset.
        return ''


def bootstrap_hostname(cfg):
    """Optional Zero-Touch public TLS bootstrap hostname (advanced override)."""
    if not isinstance(cfg, dict):
        return ''
    try:
        return validate_public_hostname(cfg.get('bootstrap_hostname') or '', required=False)
    except ConfigError:
        return ''


def public_url_host(cfg):
    """Install-time canonical host for user-facing public HTTPS / ZT / installer URLs.

    Preference: explicit public_url_host (or legacy enrollment_public_host),
    then allocator_public_url authority, then public_hostname, then control IP.
    """
    if not isinstance(cfg, dict):
        return ''
    for key in ('public_url_host', 'enrollment_public_host'):
        value = _strip(cfg.get(key))
        if not value:
            continue
        if is_ip_literal(value):
            return validate_public_ip(value, required=True)
        try:
            return validate_public_hostname(value, required=True)
        except ConfigError:
            return value
    url = _strip(cfg.get('allocator_public_url') or '')
    if url:
        try:
            host = urlparse(url).hostname or ''
        except Exception:
            host = ''
        host = _strip(host)
        if host:
            if is_ip_literal(host):
                return host
            try:
                return validate_public_hostname(host, required=True)
            except ConfigError:
                return host
    alias = public_hostname(cfg)
    if alias:
        return alias
    try:
        return control_host(cfg)
    except ConfigError:
        return ''


def short_url_hostname(cfg):
    """Hostname for Zero-Touch short URL commands.

    Advanced bootstrap_hostname wins when set. Otherwise use public_url_host
    when it is a DNS name. IP-selected public URL identity does not invent a
    short-URL hostname from a separate public_hostname alias.
    """
    boot = bootstrap_hostname(cfg)
    if boot:
        return boot
    host = public_url_host(cfg)
    if not host or is_ip_literal(host):
        return ''
    try:
        return validate_public_hostname(host, required=True)
    except ConfigError:
        return ''


def access_host(cfg):
    """User-facing access host: optional hostname, else control host."""
    alias = public_hostname(cfg)
    if alias:
        return alias
    return control_host(cfg)


def resolve_public_endpoint_host(cfg=None, *, root=None, fallback=""):
    """Resolve the operator-facing public endpoint host for Remote Services.

    Prefer an explicit DRLINK_HOST override, then configured public_hostname,
    then the control/public IP. Never invent ``drlink.local`` as a public
    Internet target unless that name is actually configured.
    """
    env = _strip(os.environ.get("DRLINK_HOST") or "")
    if env:
        return env
    data = cfg if isinstance(cfg, dict) else None
    if data is None and root is not None:
        path = Path(root) / "etc/drlink/config.json"
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                loaded = None
            if isinstance(loaded, dict):
                data = loaded
    if data is None:
        # Agent Host: public_hostname may live in client-state.
        if root is not None:
            for rel in ("etc/frp/client-state.json", "client-state.json"):
                path = Path(root) / rel
                if not path.is_file():
                    continue
                try:
                    state = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(state, dict):
                    alias = _strip(state.get("public_hostname") or "")
                    if alias:
                        return alias
                    server = _strip(state.get("frp_server") or state.get("server") or "")
                    if server:
                        return server
        fb = _strip(fallback)
        return fb
    alias = public_hostname(data)
    if alias:
        return alias
    host = control_host(data)
    if host:
        return host
    return _strip(fallback)


def format_host_for_url(host):
    text = _strip(host)
    if not text:
        return text
    if text.startswith('[') and text.endswith(']'):
        return text
    if is_ip_literal(text) and ':' in text:
        return '[%s]' % text
    return text


def format_host_port(host, port):
    return '%s:%s' % (format_host_for_url(host), port)


def format_http_url(scheme, host, port):
    return '%s://%s' % (scheme, format_host_port(host, port))


def dns_record_guidance(hostname, public_ip):
    """Return multi-line DNS configuration guidance for operators."""
    hostname = validate_public_hostname(hostname, required=True)
    ip = _strip(public_ip)
    record_type = 'A'
    if is_ip_literal(ip):
        try:
            parsed = ipaddress.ip_address(ip[1:-1] if ip.startswith('[') else ip)
            if isinstance(parsed, ipaddress.IPv6Address):
                record_type = 'AAAA'
        except ValueError:
            pass
    lines = [
        'Public hostname configured.',
        '',
        'Create this DNS record:',
        '',
        '  Type  : %s' % record_type,
        '  Name  : %s' % hostname,
        '  Value : %s' % ip,
        '',
        'DNS records are managed outside Data Relay Link.',
        '',
        'The Public IP remains available while DNS propagates.',
    ]
    return '\n'.join(lines)


def https_passthrough_guidance(hostname):
    host = validate_public_hostname(hostname, required=True)
    return (
        'TLS is passed through to the target HTTPS service.\n'
        '\n'
        'To avoid certificate warnings, the target service certificate\n'
        'must be valid for %s.' % host
    )


def render_access_lines(control, alias, remote_port, *, preset='custom', ssh_user=''):
    """Preferred hostname + IP fallback connection lines for one service."""
    control = _strip(control)
    alias = _strip(alias)
    port = int(remote_port)
    preferred = alias if alias and alias != control else ''
    lines = []

    def endpoint(host, kind):
        if kind == 'ssh':
            user = _strip(ssh_user)
            if user:
                return 'ssh -p %s %s@%s' % (port, user, host)
            return 'ssh -p %s <user>@%s' % (port, host)
        if kind == 'http':
            return format_http_url('http', host, port)
        if kind == 'https':
            return format_http_url('https', host, port)
        return format_host_port(host, port)

    kind = 'custom'
    if preset == 'ssh':
        kind = 'ssh'
    elif preset == 'http':
        kind = 'http'
    elif preset == 'https':
        kind = 'https'

    if preferred:
        lines.append('  Preferred:')
        lines.append('    %s' % endpoint(preferred, kind))
        lines.append('  Fallback:')
        lines.append('    %s' % endpoint(control, kind))
    else:
        lines.append('  %s' % endpoint(control, kind))
    return lines


def resolve_dns_addresses(hostname, timeout=2.0):
    """Best-effort DNS lookup. Returns (addresses, error_message)."""
    host = validate_public_hostname(hostname, required=True)
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(float(timeout))
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return [], str(exc)
    except OSError as exc:
        return [], str(exc)
    finally:
        socket.setdefaulttimeout(previous)
    seen = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen, ''


def assess_dns(hostname, public_ip, timeout=2.0):
    """Return status dict: NOT_CONFIGURED|PENDING|READY|MISMATCH (+ details)."""
    alias = _strip(hostname)
    if not alias:
        return {
            'status': 'NOT_CONFIGURED',
            'message': 'public hostname is not configured',
            'addresses': [],
        }
    try:
        alias = validate_public_hostname(alias, required=True)
    except ConfigError as exc:
        return {
            'status': 'MISMATCH',
            'message': str(exc),
            'addresses': [],
        }
    addresses, err = resolve_dns_addresses(alias, timeout=timeout)
    if err or not addresses:
        return {
            'status': 'PENDING',
            'message': err or 'hostname does not resolve yet',
            'addresses': [],
        }
    ip = _strip(public_ip)
    if ip.startswith('[') and ip.endswith(']'):
        ip = ip[1:-1]
    if ip and ip in addresses:
        return {
            'status': 'READY',
            'message': 'hostname resolves and includes the configured public IP',
            'addresses': addresses,
        }
    return {
        'status': 'MISMATCH',
        'message': 'hostname resolves but does not include the configured public IP',
        'addresses': addresses,
    }


def load_config(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ConfigError('server config is not an object')
    return data


def _reapply_config_egress_permissions(path):
    """Preserve drlink-egress readability after config.json inode replacement."""
    try:
        here = Path(__file__).resolve().parent
        candidates = [
            here / 'frp_egress_control.py',
            Path('/usr/local/lib/drlink/frp_egress_control.py'),
        ]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            import importlib.util
            spec = importlib.util.spec_from_file_location('frp_egress_control', str(candidate))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.reapply_egress_runtime_permissions(config_path=Path(path), parents=True)
            return
    except Exception:
        return


def atomic_write_config(path, cfg):
    path = Path(path)
    payload = json.dumps(cfg, indent=2, sort_keys=True) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        # config.json carries the server's identity, ports and trust anchors;
        # a lost rename would silently restore a superseded configuration on
        # the next boot.
        durable_replace(tmp, path)
        if path.name == 'config.json':
            _reapply_config_egress_permissions(path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def set_public_hostname(cfg, hostname):
    """Mutate cfg in place: set or clear public_hostname. Returns previous value."""
    previous = _strip(cfg.get('public_hostname') or '')
    text = _strip(hostname)
    if not text:
        cfg.pop('public_hostname', None)
        return previous
    cfg['public_hostname'] = validate_public_hostname(text, required=True)
    return previous


def set_bootstrap_hostname(cfg, hostname):
    """Mutate cfg in place: set or clear bootstrap_hostname. Returns previous value.

    Does not create DNS records, issue certificates, open firewall ports, or
    configure ACME. Operator owns public TLS termination for this name.
    """
    previous = _strip(cfg.get('bootstrap_hostname') or '')
    text = _strip(hostname)
    if not text:
        cfg.pop('bootstrap_hostname', None)
        return previous
    cfg['bootstrap_hostname'] = validate_public_hostname(text, required=True)
    return previous


def deploy_root():
    return os.environ.get('FRP_DEPLOY_TEST_ROOT', '')


def config_path(root=None):
    if root is None:
        root = deploy_root()
    return Path(root + '/etc/drlink/config.json')
