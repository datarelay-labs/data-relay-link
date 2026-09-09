#!/usr/bin/env python3
"""Read-only FRP Auto Deploy diagnostics.

Python 3.7 + stdlib + OpenSSL CLI. Does not mutate files, services, or
management state. JSON is generated here so Bash does not hand-escape it.
"""
from __future__ import print_function

import sys
if sys.version_info < (3, 7):
    sys.stderr.write('ERROR: python 3.7 or newer is required\n')
    raise SystemExit(2)

import argparse
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

REPORT_SCHEMA = 1
CERT_WARN_DAYS = 30
NETWORK_TIMEOUT = 5
DISK_WARN_MB = 100
BACKUP_KEEP_DEFAULT = 5
MAX_CLOCK_SKEW = 300
PINNED_FRP_DEFAULT = '0.71.0'

PASS = 'PASS'
INFO = 'INFO'
WARN = 'WARN'
FAIL = 'FAIL'
NOT_APPLICABLE = 'NOT_APPLICABLE'
NOT_TESTED = 'NOT_TESTED'

SEVERITY_RANK = {
    PASS: 0,
    INFO: 1,
    NOT_APPLICABLE: 1,
    NOT_TESTED: 2,
    WARN: 3,
    FAIL: 4,
}

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}

SECRET_RE = re.compile(
    r'(BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY|'
    r'auth\.token\s*=\s*\S+|'
    r'mgmt_mac_key|'
    r'FRP_BOOTSTRAP_TICKET=|'
    r'bt1\.[0-9a-f]{16}\.[0-9a-f]{32,}|'
    r'zt1\.[A-Za-z0-9_-]{16,}|'
    r'Enrollment Code:\s*\S+)',
    re.IGNORECASE,
)

HEX64_RE = re.compile(r'^[0-9a-f]{64}$')
SUPPORTED_DISTRO_IDS = {
    'ubuntu', 'rocky', 'almalinux', 'amzn', 'centos', 'rhel', 'debian', 'fedora',
}
MACOS_LAUNCHD_LABEL_DEFAULT = 'com.datarelay.frp-auto-deploy.frpc'
MACOS_MIN_PRODUCT_MAJOR_DEFAULT = 11
MACOS_OS_IDS = {'macos', 'darwin'}


class DoctorError(Exception):
    pass


MARKER_NOTE = 'Do not delete the pending marker by hand unless recovering from a known-good backup. doctor does not delete the marker.'


def _recovery_for_role(role, kind):
    if kind == 'frp':
        if role in ('client', 'partial_client'):
            return 'sudo frpctl update frp'
        return 'sudo frpctl frp-update'
    if role in ('client', 'partial_client'):
        return 'sudo frpctl update'
    if role in ('server', 'partial_server', 'dual'):
        return 'sudo frpctl project-update'
    return ''


def _recovery_for_operation(operation, role):
    op = str(operation or '').strip()
    extra = '\n%s' % MARKER_NOTE
    if op == 'project-update':
        return 'sudo frpctl project-update' + extra
    if op in ('frp-update',):
        return 'sudo frpctl frp-update' + extra
    if op in ('client-update',):
        return 'sudo frpctl update' + extra
    if op == 'install':
        return 're-run the server installer; do not delete the pending marker' + extra
    if op == 'restore':
        return 'inspect the pending restore marker and retry sudo frpctl restore only after the failure is understood' + extra
    if op == 'update':
        if role in ('client', 'partial_client', 'dual'):
            return 'sudo frpctl update' + extra
        return 'sudo frpctl frp-update' + extra
    return (
        'inspect the pending transaction marker (server-update-pending.json / '
        'client-update-pending.json / legacy update-pending.json) operation=%s '
        'and re-run the matching command' % (op or 'unknown')
        + extra
    )


def redact(text):
    if not text:
        return ''
    text = str(text)
    # Preserve /i/<redacted> shape for short-URL path logs.
    text = re.sub(r'(/i/)[^/?\s#]+', r'\1<redacted>', text, flags=re.IGNORECASE)
    text = SECRET_RE.sub('[redacted]', text)
    text = re.sub(r'auth\.token\s*=\s*".*?"', 'auth.token = "[redacted]"', text)
    return text


def now_utc():
    return datetime.now(timezone.utc)


def parse_openssl_date(value):
    text = str(value or '').strip()
    if '=' in text:
        text = text.split('=', 1)[1].strip()
    text = text.replace('GMT', '').strip()
    parts = text.split()
    if len(parts) < 4:
        return None
    try:
        month = MONTHS[parts[0]]
        day = int(parts[1])
        hms = parts[2].split(':')
        year = int(parts[3])
        return datetime(
            year, month, day,
            int(hms[0]), int(hms[1]), int(hms[2] if len(hms) > 2 else 0),
            tzinfo=timezone.utc,
        )
    except (KeyError, ValueError, IndexError):
        return None


def run_cmd(args, timeout=10, input_bytes=None):
    try:
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            input=input_bytes,
            check=False,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def openssl_bin():
    return shutil.which('openssl')


def _doctor_is_darwin():
    forced = str(os.environ.get('FRP_TEST_UNAME_S') or '').strip()
    if forced:
        return forced == 'Darwin'
    return sys.platform == 'darwin'


def _doctor_launchd_label():
    label = str(os.environ.get('FRP_MACOS_LAUNCHD_LABEL') or MACOS_LAUNCHD_LABEL_DEFAULT).strip()
    return label or MACOS_LAUNCHD_LABEL_DEFAULT


def _macos_min_product_major():
    raw = str(os.environ.get('FRP_MACOS_MIN_PRODUCT_VERSION') or MACOS_MIN_PRODUCT_MAJOR_DEFAULT).strip()
    try:
        return int(raw)
    except ValueError:
        return MACOS_MIN_PRODUCT_MAJOR_DEFAULT


def _facts_is_darwin(facts=None):
    if _doctor_is_darwin():
        return True
    platform = (facts or {}).get('platform') or {}
    os_family = str(platform.get('os_family') or '').strip().lower()
    if os_family in MACOS_OS_IDS:
        return True
    os_id = str(platform.get('os_id') or '').strip().lower()
    return os_id in MACOS_OS_IDS


def _frpc_runtime_label(facts=None):
    if _facts_is_darwin(facts):
        return 'launchd job %s' % _doctor_launchd_label()
    return 'frpc.service'


def _frpc_runtime_recovery(facts=None):
    if _facts_is_darwin(facts):
        return (
            'inspect the job with launchctl print system/%s; doctor does not restart services'
            % _doctor_launchd_label()
        )
    return 'inspect the unit with systemctl status frpc; doctor does not restart services'


def _doctor_macos_state_root():
    return str(os.environ.get('FRP_MACOS_STATE_ROOT') or '/Library/Application Support/frp-auto-deploy').rstrip('/')


def _doctor_macos_prefix():
    return str(os.environ.get('FRP_MACOS_PREFIX') or '/usr/local').rstrip('/')


def client_has_enabled_services(state):
    services = (state or {}).get('services') if isinstance(state, dict) else None
    if not isinstance(services, dict):
        return False
    for rec in services.values():
        if isinstance(rec, dict) and rec.get('enabled', True) is not False:
            return True
    return False


def macos_map_path(abs_path):
    """Mirror lib/frp-macos.sh frp_macos_map_path for doctor file probes."""
    p = str(abs_path or '')
    if not p:
        return p
    state = _doctor_macos_state_root()
    prefix = _doctor_macos_prefix()
    if p in ('/etc/frp', '/etc/frp-auto-deploy'):
        return state
    if p.startswith('/etc/frp/'):
        return state + '/' + p[len('/etc/frp/'):]
    if p.startswith('/etc/frp-auto-deploy/'):
        return state + '/' + p[len('/etc/frp-auto-deploy/'):]
    if p == '/var/lib/frp-auto-deploy':
        return state + '/state'
    if p.startswith('/var/lib/frp-auto-deploy/'):
        return state + '/state/' + p[len('/var/lib/frp-auto-deploy/'):]
    if p == '/etc/systemd/system/frpc.service':
        return '/Library/LaunchDaemons/com.datarelay.frp-auto-deploy.frpc.plist'
    if p == '/usr/local/lib/frp-auto-deploy':
        return state + '/lib'
    if p.startswith('/usr/local/lib/frp-auto-deploy/'):
        return state + '/lib/' + p[len('/usr/local/lib/frp-auto-deploy/'):]
    if p == '/usr/local/bin/frpc':
        return state + '/bin/frpc'
    if p.startswith('/usr/local/bin/'):
        return prefix + '/bin/' + p[len('/usr/local/bin/'):]
    if p.startswith('/usr/local/sbin/'):
        return prefix + '/sbin/' + p[len('/usr/local/sbin/'):]
    return p


class Paths(object):
    def __init__(self, root):
        self.root = str(root or '')

    def p(self, abs_path):
        mapped = macos_map_path(abs_path) if _doctor_is_darwin() else abs_path
        if self.root:
            return Path(self.root + mapped)
        return Path(mapped)

    def exists(self, abs_path):
        return self.p(abs_path).exists()

    def is_file(self, abs_path):
        return self.p(abs_path).is_file()

    def is_dir(self, abs_path):
        return self.p(abs_path).is_dir()

    def read_text(self, abs_path):
        path = self.p(abs_path)
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            return None

    def read_bytes(self, abs_path):
        path = self.p(abs_path)
        if not path.is_file():
            return None
        try:
            return path.read_bytes()
        except OSError:
            return None

    def sha256(self, abs_path):
        data = self.read_bytes(abs_path)
        if data is None:
            return None
        return hashlib.sha256(data).hexdigest()

    def mode(self, abs_path):
        path = self.p(abs_path)
        try:
            return stat.S_IMODE(path.stat().st_mode)
        except OSError:
            return None

    def owner_ids(self, abs_path):
        path = self.p(abs_path)
        try:
            st = path.stat()
            return st.st_uid, st.st_gid
        except OSError:
            return None, None

    def mtime(self, abs_path):
        path = self.p(abs_path)
        try:
            return path.stat().st_mtime
        except OSError:
            return None


class Report(object):
    def __init__(self):
        self.checks = []
        self.role = 'uninstalled'
        self.role_label = 'Uninstalled'
        self.confidence = 'none'
        self.project_version = ''
        self.frp_version = ''
        self.embedded_version = ''
        self.pinned_frp = PINNED_FRP_DEFAULT
        self.facts = {}
        self.display = {}
        self.fatal = None

    def add(self, check_id, status, message, detail='', recommendation='', section='general'):
        self.checks.append({
            'id': check_id,
            'status': status,
            'message': message,
            'detail': redact(detail or ''),
            'recommendation': recommendation or '',
            'section': section,
        })

    def counts(self):
        out = {
            PASS: 0, INFO: 0, WARN: 0, FAIL: 0,
            NOT_APPLICABLE: 0, NOT_TESTED: 0,
        }
        for item in self.checks:
            status = item.get('status')
            if status in out:
                out[status] += 1
        return out

    def overall(self):
        if self.fatal:
            return 'ERROR'
        counts = self.counts()
        if counts[FAIL]:
            return 'FAIL'
        if counts[WARN]:
            return 'PASS_WITH_WARNINGS'
        return 'PASS'

    def recommended_actions(self):
        seen = set()
        actions = []
        for status in (FAIL, WARN):
            for item in self.checks:
                if item.get('status') != status:
                    continue
                rec = (item.get('recommendation') or '').strip()
                if not rec or rec in seen:
                    continue
                seen.add(rec)
                actions.append(rec)
        return actions


def load_json_file(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8')), None
    except FileNotFoundError:
        return None, 'missing'
    except json.JSONDecodeError as exc:
        return None, 'invalid JSON (%s)' % exc
    except OSError as exc:
        return None, 'unreadable (%s)' % exc


def load_json_path(paths, abs_path):
    path = paths.p(abs_path)
    if not path.is_file():
        return None, 'missing'
    try:
        return json.loads(path.read_text(encoding='utf-8')), None
    except json.JSONDecodeError as exc:
        return None, 'invalid JSON (%s)' % exc
    except OSError as exc:
        return None, 'unreadable (%s)' % exc


def coerce_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def file_mode_oct(mode):
    if mode is None:
        return 'missing'
    return '0o%04o' % mode


def secret_mode_ok(mode):
    if mode is None:
        return False
    return (mode & 0o077) == 0


def public_mode_ok(mode):
    if mode is None:
        return False
    return (mode & 0o002) == 0


def kv_file(paths, abs_path, key):
    text = paths.read_text(abs_path)
    if not text:
        return ''
    for line in text.splitlines():
        if line.startswith(key + '='):
            return line.split('=', 1)[1].strip()
    return ''


def detect_role(paths):
    server_files = [
        '/etc/frp-auto-deploy/config.json',
        '/etc/frp/server_token',
        '/var/lib/frp-auto-deploy/registry.json',
        '/etc/frp/frps.toml',
        '/usr/local/bin/frps',
        '/usr/local/sbin/frp-create-client',
        '/usr/local/lib/frp-auto-deploy/frp-port-allocator.py',
        '/etc/systemd/system/frps.service',
        '/etc/systemd/system/frp-port-allocator.service',
        '/etc/frp-auto-deploy/pki/ca.crt',
    ]
    client_files = [
        '/etc/frp/client-state.json',
        '/etc/frp/frpc.toml',
        '/etc/frp/client-identity.key',
        '/usr/local/bin/frpc',
        '/usr/local/bin/frp-client',
        '/etc/systemd/system/frpc.service',
        '/etc/frp-auto-deploy/allocator-ca.crt',
    ]
    server_hits = [p for p in server_files if paths.exists(p)]
    client_hits = [p for p in client_files if paths.exists(p)]
    has_server_config = paths.is_file('/etc/frp-auto-deploy/config.json')
    has_client_state = paths.is_file('/etc/frp/client-state.json')
    has_frpc_unit = paths.is_file('/etc/systemd/system/frpc.service')
    has_frps_unit = paths.is_file('/etc/systemd/system/frps.service')
    server_n = len(server_hits)
    client_n = len(client_hits)

    result = {
        'role': 'uninstalled',
        'label': 'Uninstalled',
        'confidence': 'none',
        'status': INFO,
        'reason': 'no FRP Auto Deploy installation markers were found',
        'server_signals': server_n,
        'client_signals': client_n,
        'missing_client_unit': has_client_state and not has_frpc_unit,
        'missing_server_unit': has_server_config and not has_frps_unit,
    }

    if server_n >= 2 and client_n >= 2:
        result.update({
            'role': 'dual',
            'label': 'Server + Client',
            'confidence': 'complete',
            'status': PASS,
            'reason': 'server and client markers are both present',
        })
        if result['missing_client_unit'] or result['missing_server_unit']:
            result['confidence'] = 'partial'
        return result

    if server_n >= 2 or has_server_config:
        if server_n == 1 and not has_server_config:
            result.update({
                'role': 'partial_server',
                'label': 'Partial server installation',
                'confidence': 'partial',
                'status': FAIL,
                'reason': 'only one server marker is present',
            })
            return result
        if result['missing_server_unit'] and server_n < 4:
            result.update({
                'role': 'partial_server',
                'label': 'Partial server installation',
                'confidence': 'partial',
                'status': FAIL,
                'reason': 'server config exists but frps unit is missing',
            })
            return result
        result.update({
            'role': 'server',
            'label': 'Server',
            'confidence': 'complete' if server_n >= 4 else 'partial',
            'status': PASS if server_n >= 3 else WARN,
            'reason': 'server installation markers are present',
        })
        return result

    if client_n >= 2 or has_client_state:
        if has_client_state and not has_frpc_unit:
            result.update({
                'role': 'partial_client',
                'label': 'Partial client installation',
                'confidence': 'partial',
                'status': FAIL,
                'reason': 'client-state exists but frpc unit is missing',
            })
            return result
        if client_n == 1 and not has_client_state:
            result.update({
                'role': 'partial_client',
                'label': 'Partial client installation',
                'confidence': 'partial',
                'status': FAIL,
                'reason': 'only one client marker is present',
            })
            return result
        result.update({
            'role': 'client',
            'label': 'Client',
            'confidence': 'complete' if client_n >= 4 else 'partial',
            'status': PASS if client_n >= 3 else WARN,
            'reason': 'client installation markers are present',
        })
        return result

    if server_n == 1 and client_n == 1:
        result.update({
            'role': 'ambiguous',
            'label': 'Ambiguous',
            'confidence': 'none',
            'status': FAIL,
            'reason': 'server and client markers are inconsistent',
        })
        return result
    if server_n == 1:
        result.update({
            'role': 'partial_server',
            'label': 'Partial server installation',
            'confidence': 'partial',
            'status': FAIL,
            'reason': 'incomplete server markers',
        })
        return result
    if client_n == 1:
        result.update({
            'role': 'partial_client',
            'label': 'Partial client installation',
            'confidence': 'partial',
            'status': FAIL,
            'reason': 'incomplete client markers',
        })
        return result
    return result


def check_permissions(report, paths, abs_path, check_id, secret=True, expect_root=False, section='security'):
    path = paths.p(abs_path)
    if not path.exists():
        return None
    mode = paths.mode(abs_path)
    uid, gid = paths.owner_ids(abs_path)
    detail_parts = ['mode %s' % file_mode_oct(mode)]
    if uid is not None:
        detail_parts.append('uid=%s gid=%s' % (uid, gid))
    detail = ', '.join(detail_parts)
    ok = secret_mode_ok(mode) if secret else public_mode_ok(mode)
    if not ok:
        expected = '0600' if secret else '0644 (not world-writable)'
        report.add(
            check_id, FAIL,
            '%s permissions are too broad' % abs_path,
            '%s, expected %s' % (detail, expected),
            'restore mode %s on %s; doctor does not change permissions' % (expected.split()[0], abs_path),
            section,
        )
        return False
    if expect_root and uid not in (None, 0):
        report.add(
            check_id, WARN,
            '%s is not root-owned' % abs_path,
            detail,
            'restore root:root ownership on %s' % abs_path,
            section,
        )
        return True
    report.add(check_id, PASS, '%s permissions are safe' % Path(abs_path).name, detail, '', section)
    return True


def parse_binary_version(paths, abs_path):
    path = paths.p(abs_path)
    if not path.is_file() or not os.access(str(path), os.X_OK):
        return 'unknown'
    proc = run_cmd([str(path), '--version'], timeout=5)
    if proc is None:
        return 'unknown'
    text = (proc.stdout or b'').decode('utf-8', 'replace')
    match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', text)
    return match.group(1) if match else 'unknown'


def cert_info(cert_path):
    openssl = openssl_bin()
    if not openssl:
        return {'ok': False, 'error': 'openssl is not installed'}
    proc = run_cmd([openssl, 'x509', '-in', str(cert_path), '-noout', '-startdate', '-enddate', '-subject', '-fingerprint', '-sha256'], timeout=10)
    if proc is None or proc.returncode != 0:
        err = ''
        if proc is not None:
            err = (proc.stderr or proc.stdout or b'').decode('utf-8', 'replace').strip()
        return {'ok': False, 'error': redact(err) or 'not a valid X.509 certificate'}
    text = (proc.stdout or b'').decode('utf-8', 'replace')
    start = end = subject = fingerprint = ''
    for line in text.splitlines():
        if line.startswith('notBefore='):
            start = line
        elif line.startswith('notAfter='):
            end = line
        elif line.startswith('subject='):
            subject = line.split('=', 1)[1].strip()
        elif 'Fingerprint' in line or line.lower().startswith('sha256'):
            fingerprint = line.split('=', 1)[-1].replace(':', '').strip().lower()
    start_dt = parse_openssl_date(start)
    end_dt = parse_openssl_date(end)
    now = now_utc()
    days = None
    status = PASS
    message = 'valid'
    if start_dt and now < start_dt:
        status = FAIL
        message = 'not yet valid'
        days = (start_dt - now).days
    elif end_dt:
        delta = end_dt - now
        days = int(delta.total_seconds() // 86400)
        if delta.total_seconds() <= 0:
            status = FAIL
            message = 'expired'
        elif days <= CERT_WARN_DAYS:
            status = WARN
            message = 'expires in %s days' % days
        else:
            status = PASS
            message = 'expires in %s days' % days
    dns, ips = read_cert_sans(cert_path)
    return {
        'ok': True,
        'status': status,
        'message': message,
        'days': days,
        'subject': subject,
        'fingerprint': fingerprint,
        'dns': sorted(dns),
        'ips': sorted(ips),
        'start': start,
        'end': end,
    }


def read_cert_sans(cert_path):
    openssl = openssl_bin()
    dns = set()
    ips = set()
    if not openssl:
        return dns, ips
    proc = run_cmd([openssl, 'x509', '-in', str(cert_path), '-noout', '-text'], timeout=10)
    if proc is None or proc.returncode != 0:
        return dns, ips
    text = (proc.stdout or b'').decode('utf-8', 'replace')
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if 'Subject Alternative Name' not in line:
            continue
        blob = []
        for follow in lines[i + 1:]:
            stripped = follow.strip()
            if not stripped:
                continue
            if stripped.startswith('X509') or stripped.startswith('Signature'):
                break
            if not follow.startswith(' '):
                break
            blob.append(stripped)
            if 'DNS:' in stripped or 'IP' in stripped:
                break
        joined = ' '.join(blob)
        for item in joined.split(','):
            item = item.strip()
            if item.startswith('DNS:'):
                dns.add(item[4:].strip())
            elif item.startswith('IP Address:'):
                ips.add(item[len('IP Address:'):].strip())
            elif item.startswith('IP:'):
                ips.add(item[3:].strip())
        break
    return dns, ips


def verify_signed_by_ca(ca_path, cert_path):
    openssl = openssl_bin()
    if not openssl:
        return False, 'openssl is not installed'
    proc = run_cmd([openssl, 'verify', '-CAfile', str(ca_path), str(cert_path)], timeout=10)
    if proc is None:
        return False, 'openssl verify failed'
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or b'').decode('utf-8', 'replace').strip()
        return False, redact(err) or 'server certificate is not signed by the local CA'
    return True, ''


def pubkey_from_private(key_path):
    openssl = openssl_bin()
    if not openssl:
        return None, 'openssl is not installed'
    proc = run_cmd([openssl, 'ec', '-in', str(key_path), '-pubout'], timeout=10)
    if proc is None or proc.returncode != 0:
        proc = run_cmd([openssl, 'pkey', '-in', str(key_path), '-pubout'], timeout=10)
    if proc is None or proc.returncode != 0:
        err = ''
        if proc is not None:
            err = (proc.stderr or b'').decode('utf-8', 'replace').strip()
        return None, redact(err) or 'could not derive public key'
    return (proc.stdout or b'').decode('utf-8', 'replace'), ''


def canonicalize_pub(pem):
    openssl = openssl_bin()
    if not openssl or not pem:
        return pem or ''
    fd, tmp = tempfile.mkstemp(prefix='frp-doc-pub.')
    try:
        os.close(fd)
        os.chmod(tmp, 0o600)
        Path(tmp).write_text(pem if pem.endswith('\n') else pem + '\n', encoding='utf-8')
        proc = run_cmd([openssl, 'pkey', '-pubin', '-in', tmp, '-pubout'], timeout=10)
        if proc is None or proc.returncode != 0:
            return pem
        text = (proc.stdout or b'').decode('utf-8', 'replace').replace('\r\n', '\n')
        if not text.endswith('\n'):
            text += '\n'
        return text
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def tcp_reachable(host, port, timeout=NETWORK_TIMEOUT):
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.close()
        return True, ''
    except socket.timeout:
        return False, 'timeout'
    except socket.gaierror:
        return False, 'dns'
    except ConnectionRefusedError:
        return False, 'connection_refused'
    except OSError as exc:
        text = str(exc).lower()
        if 'timed out' in text:
            return False, 'timeout'
        if 'name or service' in text or 'not known' in text:
            return False, 'dns'
        if 'refused' in text:
            return False, 'connection_refused'
        return False, 'error'


def classify_ssl_error(exc):
    text = str(exc).lower()
    if 'hostname' in text or 'doesn\'t match' in text or 'does not match' in text:
        return 'HOSTNAME_MISMATCH'
    if 'expired' in text or 'not yet valid' in text or 'certificate has expired' in text:
        return 'EXPIRED_CERT'
    if 'unknown ca' in text or 'unable to get local issuer' in text or 'certificate_verify_failed' in text:
        return 'UNKNOWN_CA'
    if 'reset' in text or 'connection reset' in text:
        return 'TLS_RESET'
    return 'TLS_ERROR'


def https_healthz(url, ca_path, timeout=NETWORK_TIMEOUT):
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        return {'ok': False, 'error_class': 'NOT_HTTPS', 'detail': 'allocator URL is not HTTPS'}
    origin = '%s://%s' % (parsed.scheme, parsed.netloc)
    health = origin + '/healthz'
    try:
        ctx = ssl.create_default_context(cafile=str(ca_path) if ca_path else None)
        if hasattr(ssl, 'TLSVersion'):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        req = Request(health, method='GET')
        with urlopen(req, context=ctx, timeout=timeout) as resp:
            body = resp.read(256).decode('utf-8', 'replace').strip()
            return {
                'ok': resp.status == 200,
                'status_code': resp.status,
                'body': body[:80],
                'error_class': None,
                'detail': 'HTTP %s' % resp.status,
                'url': health,
            }
    except HTTPError as exc:
        return {
            'ok': False,
            'error_class': 'HTTP_%s' % exc.code,
            'detail': 'HTTP %s' % exc.code,
            'url': health,
        }
    except ssl.CertificateError as exc:
        return {'ok': False, 'error_class': classify_ssl_error(exc), 'detail': str(exc), 'url': health}
    except ssl.SSLError as exc:
        return {'ok': False, 'error_class': classify_ssl_error(exc), 'detail': str(exc), 'url': health}
    except socket.timeout:
        return {'ok': False, 'error_class': 'timeout', 'detail': 'timeout', 'url': health}
    except socket.gaierror:
        return {'ok': False, 'error_class': 'dns', 'detail': 'DNS failure', 'url': health}
    except URLError as exc:
        reason = getattr(exc, 'reason', exc)
        if isinstance(reason, ssl.SSLError):
            return {'ok': False, 'error_class': classify_ssl_error(reason), 'detail': str(reason), 'url': health}
        text = str(reason).lower()
        if 'timed out' in text:
            cls = 'timeout'
        elif 'refused' in text:
            cls = 'connection_refused'
        elif 'name or service' in text or 'not known' in text:
            cls = 'dns'
        elif 'reset' in text:
            cls = 'TLS_RESET'
        else:
            cls = 'unreachable'
        return {'ok': False, 'error_class': cls, 'detail': str(reason), 'url': health}
    except ConnectionResetError as exc:
        return {'ok': False, 'error_class': 'TLS_RESET', 'detail': str(exc), 'url': health}
    except OSError as exc:
        text = str(exc).lower()
        if 'reset' in text:
            return {'ok': False, 'error_class': 'TLS_RESET', 'detail': str(exc), 'url': health}
        return {'ok': False, 'error_class': 'unreachable', 'detail': str(exc), 'url': health}


class LoopbackHTTPSConnection(http.client.HTTPSConnection):
    """Connect to 127.0.0.1 while verifying TLS as the public host identity."""

    def connect(self):
        sock = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        context = getattr(self, '_context', None)
        if context is None:
            context = ssl.create_default_context()
        self.sock = context.wrap_socket(sock, server_hostname=self.host)


def https_loopback_get(public_host, port, path, ca_path, timeout=NETWORK_TIMEOUT):
    host = str(public_host or '').strip()
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    if not host:
        return {'ok': False, 'error_class': 'NO_HOST', 'detail': 'public host is missing'}
    path = str(path or '/')
    if not path.startswith('/'):
        path = '/' + path
    url = 'https://%s:%s%s' % (host, port, path)
    try:
        ctx = ssl.create_default_context(cafile=str(ca_path) if ca_path else None)
        if hasattr(ssl, 'TLSVersion'):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = LoopbackHTTPSConnection(host, int(port), timeout=timeout, context=ctx)
        try:
            conn.request('GET', path)
            resp = conn.getresponse()
            body = resp.read(65536)
            ctype = resp.getheader('Content-Type') or ''
            status = int(resp.status)
            result = {
                'ok': status == 200,
                'status_code': status,
                'body': body,
                'content_type': ctype,
                'error_class': None if status == 200 else 'HTTP_%s' % status,
                'detail': 'HTTP %s' % status,
                'url': url,
            }
            return result
        finally:
            conn.close()
    except ssl.CertificateError as exc:
        return {'ok': False, 'error_class': classify_ssl_error(exc), 'detail': str(exc), 'url': url}
    except ssl.SSLError as exc:
        return {'ok': False, 'error_class': classify_ssl_error(exc), 'detail': str(exc), 'url': url}
    except socket.timeout:
        return {'ok': False, 'error_class': 'timeout', 'detail': 'timeout', 'url': url}
    except socket.gaierror:
        return {'ok': False, 'error_class': 'dns', 'detail': 'DNS failure', 'url': url}
    except http.client.HTTPException as exc:
        return {'ok': False, 'error_class': 'HTTP_ERROR', 'detail': str(exc), 'url': url}
    except ConnectionResetError as exc:
        return {'ok': False, 'error_class': 'TLS_RESET', 'detail': str(exc), 'url': url}
    except OSError as exc:
        text = str(exc).lower()
        if 'timed out' in text:
            cls = 'timeout'
        elif 'refused' in text:
            cls = 'connection_refused'
        elif 'reset' in text:
            cls = 'TLS_RESET'
        else:
            cls = 'unreachable'
        return {'ok': False, 'error_class': cls, 'detail': str(exc), 'url': url}


def fingerprint_pem_bytes(pem):
    openssl = openssl_bin()
    if not openssl:
        return None, 'openssl is not installed'
    data = pem if isinstance(pem, (bytes, bytearray)) else str(pem).encode('utf-8')
    fd, tmp = tempfile.mkstemp(prefix='frp-doc-ca.', suffix='.crt')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data if data.endswith(b'\n') else data + b'\n')
        proc = run_cmd([openssl, 'x509', '-in', tmp, '-outform', 'DER'], timeout=10)
        if proc is None or proc.returncode != 0:
            return None, 'not a valid X.509 certificate'
        der = proc.stdout or b''
        if not der:
            return None, 'not a valid X.509 certificate'
        return hashlib.sha256(der).hexdigest(), None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def fingerprint_cert_file(path):
    try:
        pem = Path(path).read_bytes()
    except OSError as exc:
        return None, str(exc)
    return fingerprint_pem_bytes(pem)


def classify_frontend_ca_body(body, content_type, expected_fingerprint):
    if body is None:
        body = b''
    if isinstance(body, str):
        body = body.encode('utf-8', 'replace')
    if not body.strip():
        return {'ok': False, 'error_class': 'EMPTY', 'detail': 'empty body'}
    low = body.lower()
    if b'<html' in low or b'bad gateway' in low:
        return {
            'ok': False,
            'error_class': 'NOT_A_CA',
            'detail': 'HTML error body is not a CA certificate',
        }
    if b'-----BEGIN CERTIFICATE-----' not in body or b'-----END CERTIFICATE-----' not in body:
        return {'ok': False, 'error_class': 'NOT_A_CA', 'detail': 'body is not a PEM certificate'}
    fp, err = fingerprint_pem_bytes(body)
    if not fp:
        return {'ok': False, 'error_class': 'NOT_A_CA', 'detail': err or 'body is not a valid X.509 certificate'}
    wanted = str(expected_fingerprint or '').replace(':', '').strip().lower()
    if wanted and fp != wanted:
        return {'ok': False, 'error_class': 'FINGERPRINT_MISMATCH', 'detail': 'CA fingerprint mismatch'}
    ctype = str(content_type or '').lower()
    if 'application/x-pem-file' not in ctype:
        return {
            'ok': False,
            'error_class': 'CONTENT_TYPE',
            'detail': 'Content-Type %s is not application/x-pem-file' % (content_type or 'missing'),
            'fingerprint': fp,
        }
    return {'ok': True, 'fingerprint': fp, 'content_type': content_type, 'error_class': None}


def parse_frpc_proxies(text):
    proxies = []
    current = {}
    for raw in (text or '').splitlines():
        line = raw.strip()
        if line.startswith('['):
            if current.get('name') or current.get('remotePort'):
                proxies.append(current)
            current = {}
            continue
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"')
        if key in ('name', 'localIP', 'type'):
            current[key] = value
        elif key in ('remotePort', 'localPort', 'serverPort'):
            try:
                current[key] = int(value)
            except ValueError:
                current[key] = value
        elif key == 'serverAddr':
            current['serverAddr'] = value
    if current.get('name') or current.get('remotePort'):
        proxies.append(current)
    return proxies


def server_config_ports(cfg):
    public_host = str(cfg.get('public_ip') or cfg.get('public_host') or '')
    public_hostname = str(cfg.get('public_hostname') or '').strip()
    frp_pub = coerce_port(cfg.get('frp_control_public_port')) or coerce_port(cfg.get('control_port'))
    frp_listen = coerce_port(cfg.get('frp_control_listen_port')) or coerce_port(cfg.get('control_port'))
    alloc_pub = coerce_port(cfg.get('allocator_public_port'))
    alloc_listen = coerce_port(cfg.get('allocator_listen_port')) or coerce_port(cfg.get('listen_port'))
    port_start = coerce_port(cfg.get('port_start'))
    port_end = coerce_port(cfg.get('port_end'))
    listen_host = str(cfg.get('listen_host') or '0.0.0.0')
    bind_addr = str(cfg.get('frp_control_bind_addr') or listen_host or '0.0.0.0')
    mode = str(cfg.get('deployment_mode') or 'direct').strip().lower()
    compact = mode.replace('-', '').replace('_', '')
    if compact in ('single443', 'enterprise', 'enterprisesingle443'):
        mode = 'single443'
    else:
        mode = 'direct'
    transport = str(cfg.get('frp_transport') or '').strip().lower()
    if not transport:
        transport = 'wss' if mode == 'single443' else 'tcp'
    alloc_url = str(cfg.get('allocator_public_url') or '')
    return {
        'public_host': public_host,
        'public_ip': public_host,
        'public_hostname': public_hostname,
        'frp_public': frp_pub,
        'frp_listen': frp_listen,
        'alloc_public': alloc_pub,
        'alloc_listen': alloc_listen,
        'port_start': port_start,
        'port_end': port_end,
        'listen_host': listen_host,
        'frp_bind_addr': bind_addr,
        'deployment_mode': mode,
        'frp_transport': transport,
        'allocator_url': alloc_url,
    }


def validate_registry(state, cfg=None):
    issues = []
    infos = []
    if not isinstance(state, dict):
        return FAIL, 'registry is not a JSON object', issues
    version = state.get('schema_version')
    if version != 2:
        return FAIL, 'registry schema is not version 2', issues
    clients = state.get('clients') or {}
    if not isinstance(clients, dict):
        return FAIL, 'registry clients is not an object', issues
    reserved = state.get('reserved')
    if reserved is None:
        reserved = []
    if not isinstance(reserved, list):
        return FAIL, 'registry reserved list is invalid', issues
    groups = state.get('groups')
    if groups is None:
        groups = {}
    if not isinstance(groups, dict):
        return FAIL, 'registry groups is not an object', issues
    group_names = {}
    valid_group_ids = set()
    for gid, group in groups.items():
        if not isinstance(gid, str) or not re.fullmatch(r'grp_[0-9a-f]{8}', gid):
            issues.append('invalid group id %s' % gid)
            continue
        valid_group_ids.add(gid)
        if not isinstance(group, dict):
            issues.append('group %s record is not an object' % gid)
            continue
        name = group.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', name):
            issues.append('group %s has invalid name' % gid)
            continue
        if name.lower() in ('all', 'ungrouped'):
            issues.append('group %s uses reserved name %s' % (gid, name))
        if name in group_names:
            issues.append('duplicate group name %s' % name)
        group_names[name] = gid
        description = group.get('description')
        if description is not None and (
            not isinstance(description, str)
            or len(description) > 1024
            or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in description)
        ):
            issues.append('group %s has invalid description' % gid)
    port_start = port_end = None
    protected = set()
    if cfg:
        port_start = coerce_port(cfg.get('port_start'))
        port_end = coerce_port(cfg.get('port_end'))
        for key in ('allocator_listen_port', 'frp_control_listen_port', 'listen_port'):
            port = coerce_port(cfg.get(key))
            if port is not None:
                protected.add(port)
    seen_ports = {}
    outside = []
    revoked = 0
    disabled = 0
    reserved_ports = set()
    for item in reserved:
        port = coerce_port(item)
        if port is not None:
            reserved_ports.add(port)
            if port in seen_ports:
                issues.append('duplicate reserved port %s' % port)
            seen_ports[port] = ('reserved', None)
    for mid, client in clients.items():
        if not isinstance(client, dict):
            issues.append('client record is not an object')
            continue
        group_ids = client.get('group_ids')
        if group_ids is not None:
            if not isinstance(group_ids, list):
                issues.append('client %s group_ids must be a list' % str(mid)[:12])
            else:
                seen_group_ids = set()
                for gid in group_ids:
                    if not isinstance(gid, str) or not re.fullmatch(r'grp_[0-9a-f]{8}', gid):
                        issues.append('client %s has invalid group id' % str(mid)[:12])
                    elif gid in seen_group_ids:
                        issues.append('client %s has duplicate group id %s' % (str(mid)[:12], gid))
                    elif gid not in valid_group_ids:
                        issues.append('client %s references nonexistent group %s' % (str(mid)[:12], gid))
                    seen_group_ids.add(gid)
        if 'ssh_port' in client or 'https_port' in client:
            issues.append('legacy SSH/HTTPS fields are present')
            continue
        status = client.get('mgmt_status')
        if status is not None and status not in ('enrolled', 'legacy', 'revoked'):
            issues.append('invalid management identity status')
        if status == 'revoked':
            revoked += 1
            infos.append('revoked client %s is a valid lifecycle state' % (client.get('hostname') or mid[:12]))
        services = client.get('services') or {}
        if not isinstance(services, dict):
            issues.append('client services must be a map')
            continue
        seen_ids = set()
        for sid, svc in services.items():
            key = str(sid).strip().lower()
            if key in seen_ids:
                issues.append('duplicate service id %s' % key)
            seen_ids.add(key)
            if not isinstance(svc, dict):
                issues.append('service record is not an object')
                continue
            if svc.get('enabled', True) is False:
                disabled += 1
            port = coerce_port(svc.get('remote_port'))
            if port is None:
                continue
            if port in seen_ports and seen_ports[port][0] != 'reserved':
                issues.append('duplicate public port %s' % port)
            seen_ports[port] = (mid, key)
            if port_start is not None and port_end is not None:
                if port < port_start or port > port_end:
                    outside.append(port)
            if port in protected:
                issues.append('allocated port %s collides with a control port' % port)
    if issues:
        return FAIL, '; '.join(issues[:6]), issues
    extra = []
    if outside:
        extra.append('reservations outside current range: %s' % ','.join(str(p) for p in outside[:8]))
        return WARN, extra[0], extra
    msg = 'valid schema v2 (%s clients, %s reserved ports)' % (len(clients), len(seen_ports))
    if revoked:
        msg += ', %s revoked' % revoked
    if disabled:
        msg += ', %s disabled services' % disabled
    return PASS, msg, infos


def check_macos_support(report, facts):
    platform = facts.get('platform') or {}
    arch = str(platform.get('arch') or '').strip().lower()
    macos_ver = str(platform.get('macos_version') or '').strip()
    issues = []
    recs = []
    if arch and arch not in ('arm64', 'aarch64'):
        issues.append('architecture %s is not Apple Silicon' % arch)
        recs.append('The macOS client requires Apple Silicon (arm64); Intel Macs are not supported.')
    if macos_ver:
        major = macos_ver.split('.')[0]
        try:
            min_major = _macos_min_product_major()
            if int(major) < min_major:
                issues.append('macOS %s is older than the supported minimum (macOS %s)' % (macos_ver, min_major))
                recs.append('macOS %s or newer is required' % min_major)
        except ValueError:
            pass
    detail_bits = []
    if macos_ver:
        detail_bits.append('macos=%s' % macos_ver)
    if arch:
        detail_bits.append('arch=%s' % arch)
    detail = '; '.join(detail_bits)
    if issues:
        report.add(
            'macos_support', FAIL,
            '; '.join(issues),
            detail,
            recs[0] if recs else '',
            'host',
        )
        return
    report.add(
        'macos_support', PASS,
        'Apple Silicon macOS is a supported client platform',
        detail,
        '',
        'host',
    )


def check_host_facts(report, facts):
    platform = facts.get('platform') or {}
    os_name = platform.get('os') or 'unknown'
    os_id = str(platform.get('os_id') or '').strip()
    darwin = _facts_is_darwin(facts)
    if darwin:
        detail_bits = [
            'OS=%s' % os_name,
            'kernel=%s' % (platform.get('kernel') or 'unknown'),
            'arch=%s' % (platform.get('arch') or 'unknown'),
            'bash=%s' % (platform.get('bash') or 'unknown'),
            'python=%s' % (platform.get('python') or 'unknown'),
            'openssl=%s' % (platform.get('openssl') or 'unknown'),
            'service_manager=%s' % (platform.get('service_manager') or 'launchd'),
        ]
        if platform.get('macos_version'):
            detail_bits.append('macos=%s' % platform.get('macos_version'))
    else:
        detail_bits = [
            'OS=%s' % os_name,
            'kernel=%s' % (platform.get('kernel') or 'unknown'),
            'arch=%s' % (platform.get('arch') or 'unknown'),
            'bash=%s' % (platform.get('bash') or 'unknown'),
            'python=%s' % (platform.get('python') or 'unknown'),
            'openssl=%s' % (platform.get('openssl') or 'unknown'),
            'systemd=%s' % (platform.get('systemd') or 'unknown'),
        ]
    report.add('host_facts', INFO, 'support facts collected', '; '.join(detail_bits), '', 'host')
    if darwin:
        check_macos_support(report, facts)
    elif os_id and os_id not in SUPPORTED_DISTRO_IDS:
        report.add(
            'distro_support', WARN,
            'this distribution is not part of the automated container matrix',
            'os_id=%s' % os_id,
            'supported systemd Linux can still work; treat this as uncertified rather than broken',
            'host',
        )
    elif os_id:
        report.add('distro_support', INFO, 'distribution is in the automated container matrix', 'os_id=%s' % os_id, '', 'host')

    disk = facts.get('disk') or {}
    avail = disk.get('avail_mb')
    if isinstance(avail, (int, float)):
        if avail < DISK_WARN_MB:
            report.add(
                'disk_space', WARN,
                'low disk space on the FRP data filesystem',
                '%s MB available on %s' % (int(avail), disk.get('path') or ''),
                'free space before install or update operations',
                'host',
            )
        else:
            report.add('disk_space', PASS, 'disk space is adequate', '%s MB available' % int(avail), '', 'host')

    clock = facts.get('clock') or {}
    cstatus = clock.get('status')
    if cstatus == 'unsynchronized':
        report.add(
            'clock_sync', WARN,
            'system clock does not appear synchronized',
            clock.get('detail') or '',
            'management requests tolerate at most %s seconds of clock skew; synchronize time before signed operations' % MAX_CLOCK_SKEW,
            'host',
        )
    elif cstatus == 'synchronized':
        report.add('clock_sync', PASS, 'system clock appears synchronized', clock.get('detail') or '', '', 'host')
    elif cstatus:
        report.add('clock_sync', NOT_TESTED, 'clock synchronization was not verified', clock.get('detail') or '', '', 'host')


def check_versions(report, paths, facts):
    installed_proj = kv_file(paths, '/etc/frp-auto-deploy/version', 'PROJECT_VERSION')
    installed_frp = kv_file(paths, '/etc/frp-auto-deploy/version', 'FRP_VERSION')
    embedded = str(facts.get('embedded_version') or '')
    pinned = str(facts.get('pinned_frp') or PINNED_FRP_DEFAULT)
    report.project_version = installed_proj or 'legacy / unknown'
    report.frp_version = installed_frp or pinned
    report.release_channel = kv_file(paths, '/etc/frp-auto-deploy/version', 'RELEASE_CHANNEL') or 'unknown'
    report.source_ref = kv_file(paths, '/etc/frp-auto-deploy/version', 'SOURCE_REF') or 'unknown'
    report.bundle_sha256 = kv_file(paths, '/etc/frp-auto-deploy/version', 'BUNDLE_SHA256') or 'unknown'
    report.embedded_version = embedded
    report.pinned_frp = pinned

    if not installed_proj:
        if report.role in ('uninstalled',):
            report.add('project_version', NOT_APPLICABLE, 'no installed project version file', '', '', 'installation')
        else:
            report.add(
                'project_version', WARN,
                'installed project version file is missing',
                '',
                _recovery_for_role(report.role, 'project'),
                'installation',
            )
    elif embedded and installed_proj != embedded:
        report.add(
            'project_version', FAIL,
            'installed project version does not match this tool',
            'installed=%s tool=%s' % (installed_proj, embedded),
            _recovery_for_role(report.role, 'project'),
            'installation',
        )
    else:
        report.add('project_version', PASS, 'project version is %s' % installed_proj, '', '', 'installation')

    role = report.role
    bin_path = '/usr/local/bin/frps' if role in ('server', 'dual', 'partial_server') else '/usr/local/bin/frpc'
    if role == 'dual':
        for label, bpath in (('frps', '/usr/local/bin/frps'), ('frpc', '/usr/local/bin/frpc')):
            ver = parse_binary_version(paths, bpath)
            if ver == 'unknown' and not paths.is_file(bpath):
                report.add('frp_version_%s' % label, FAIL, '%s binary is missing' % label, bpath, 'sudo frpctl frp-update', 'installation')
            elif ver != pinned:
                report.add(
                    'frp_version_%s' % label, FAIL,
                    '%s version is not the pinned release' % label,
                    'installed=%s pinned=%s' % (ver, pinned),
                    'sudo frpctl frp-update',
                    'installation',
                )
            else:
                report.add('frp_version_%s' % label, PASS, '%s version is %s' % (label, ver), '', '', 'installation')
        report.add('frp_version', PASS if installed_frp in ('', pinned) else FAIL,
                   'pinned FRP version is %s' % pinned, 'version file=%s' % (installed_frp or 'absent'), '', 'installation')
        return

    if role in ('uninstalled',):
        report.add('frp_version', NOT_APPLICABLE, 'no FRP binary to version-check', '', '', 'installation')
        return
    ver = parse_binary_version(paths, bin_path)
    if not paths.is_file(bin_path):
        report.add('frp_version', FAIL, 'FRP binary is missing', bin_path, _recovery_for_role(role, 'frp'), 'installation')
    elif ver != pinned:
        report.add(
            'frp_version', FAIL,
            'installed FRP version is not the pinned release',
            'installed=%s pinned=%s' % (ver, pinned),
            _recovery_for_role(role, 'frp'),
            'installation',
        )
    else:
        report.add('frp_version', PASS, 'FRP version is %s' % ver, '', '', 'installation')


def check_pending(report, paths):
    markers = (
        ('/var/lib/frp-auto-deploy/server-update-pending.json', 'server', 'pending_server_transaction'),
        ('/var/lib/frp-auto-deploy/client-update-pending.json', 'client', 'pending_client_transaction'),
        ('/var/lib/frp-auto-deploy/update-pending.json', 'legacy', 'pending_transaction'),
    )
    apply_marker = '/etc/frp/apply-pending.json'
    found = False
    pending_display = []

    def _summary_for(kind, operation):
        op = str(operation or '').strip()
        if kind == 'client':
            if op in ('client-update', 'update', ''):
                return 'interrupted client update is pending'
            return 'interrupted client-role transaction is pending'
        if kind == 'server':
            if op == 'project-update':
                return 'interrupted project update is pending'
            if op in ('frp-update',):
                return 'interrupted FRP binary update is pending'
            if op == 'install':
                return 'interrupted install is pending'
            if op == 'restore':
                return 'interrupted restore is pending'
            return 'interrupted server-role transaction is pending'
        # legacy shared marker — classify by operation only; do not treat
        # client-update as a server project-update interruption.
        if op == 'project-update':
            return 'interrupted project update is pending (legacy marker)'
        if op in ('frp-update',):
            return 'interrupted FRP binary update is pending (legacy marker)'
        if op in ('client-update',):
            return 'interrupted client update is pending (legacy marker)'
        if op == 'install':
            return 'interrupted install is pending (legacy marker)'
        if op == 'restore':
            return 'interrupted restore is pending (legacy marker)'
        if op in ('update',):
            return 'interrupted lifecycle transaction is pending (legacy marker)'
        return 'interrupted lifecycle transaction is pending (legacy marker)'

    for update_marker, kind, check_id in markers:
        if not paths.is_file(update_marker):
            continue
        found = True
        data, err = load_json_path(paths, update_marker)
        if err:
            report.add(
                check_id, FAIL,
                '%s pending marker is unreadable' % kind,
                err,
                'inspect %s. %s' % (update_marker, MARKER_NOTE),
                'state',
            )
            continue
        phase = str((data or {}).get('phase') or 'unknown')
        operation = str((data or {}).get('operation') or '')
        failure = str((data or {}).get('failure_class') or (data or {}).get('FAILURE_CLASS') or '')
        recovery = _recovery_for_operation(operation, report.role)
        detail = 'marker=%s phase=%s operation=%s' % (update_marker, phase, operation)
        if failure:
            detail += ' failure_class=%s' % failure
        if phase in ('complete', 'cleanup', 'done'):
            report.add(
                check_id, WARN,
                '%s pending marker is still present after a completed-looking phase' % kind,
                detail,
                recovery,
                'state',
            )
        else:
            report.add(
                check_id, FAIL,
                _summary_for(kind, operation),
                detail,
                recovery,
                'state',
            )
        pending_display.append({
            'kind': kind,
            'path': update_marker,
            'phase': phase,
            'operation': operation,
            'failure_class': failure,
        })
    if pending_display:
        report.display['pending_update'] = pending_display[0]
        report.display['pending_updates'] = pending_display
    if paths.is_file(apply_marker):
        found = True
        data, err = load_json_path(paths, apply_marker)
        if err:
            report.add(
                'pending_apply', FAIL,
                'client Apply pending marker is unreadable',
                err,
                'inspect /etc/frp/apply-pending.json; run sudo frp-client manage and Apply after recovery. doctor does not clear it',
                'state',
            )
        else:
            phase = str((data or {}).get('phase') or 'unknown')
            failure = str((data or {}).get('failure_class') or '')
            detail = 'phase=%s' % phase
            if failure:
                detail += ' failure_class=%s' % failure
            status = FAIL if failure or phase not in ('complete',) else WARN
            report.add(
                'pending_apply', status,
                'pending client Apply transaction',
                detail,
                'sudo frp-client manage\n  Apply the current configuration\nDoctor does not clear the pending marker.',
                'state',
            )
            report.display['pending_apply'] = {'phase': phase, 'failure_class': failure}
    if not found:
        report.add('pending_transaction', PASS, 'no pending install/update/apply transaction', '', '', 'state')


def check_backups_and_locks(report, paths, role):
    keep = BACKUP_KEEP_DEFAULT
    dirs = []
    if role in ('server', 'dual', 'partial_server'):
        bdir = paths.p('/var/lib/frp-auto-deploy/backups')
        if bdir.is_dir():
            dirs.append(('/var/lib/frp-auto-deploy/backups', bdir))
    if role in ('client', 'dual', 'partial_client'):
        bdir = paths.p('/etc/frp/backups')
        if bdir.is_dir():
            dirs.append(('/etc/frp/backups', bdir))
        udir = paths.p('/var/lib/frp-auto-deploy/client-upgrade-backups')
        if not udir.is_dir():
            udir = paths.p('/var/lib/frp-auto-deploy/backups-client')
        if udir.is_dir():
            dirs.append((str(udir), udir))
    if not dirs:
        if role not in ('uninstalled',):
            report.add('backup_health', INFO, 'no backup directory present yet', '', '', 'state')
    for label, bdir in dirs:
        try:
            entries = sorted([p for p in bdir.iterdir() if p.is_dir()], key=lambda p: p.name)
        except OSError:
            continue
        n = len(entries)
        latest = entries[-1].name if entries else ''
        if n > keep + 2:
            report.add(
                'backup_health', WARN,
                'backup count exceeds expected retention',
                '%s has %s backups (retention %s), latest=%s' % (label, n, keep, latest),
                'do not delete backups from doctor; prune only through the existing update/install workflow',
                'state',
            )
        else:
            report.add(
                'backup_health', PASS if n else INFO,
                'backup directory present' if n else 'backup directory is empty',
                '%s count=%s latest=%s' % (label, n, latest or 'none'),
                '',
                'state',
            )

    lock = paths.p('/etc/frp/client-manage.lock')
    pid = None
    lock_exists = lock.exists()
    if lock.is_dir():
        pid_path = lock / 'pid'
        if pid_path.is_file():
            pid = pid_path.read_text(encoding='utf-8', errors='replace').strip()
    elif lock.is_file():
        pid_path = Path(str(lock) + '.pid')
        if pid_path.is_file():
            pid = pid_path.read_text(encoding='utf-8', errors='replace').strip()
    if lock_exists:
        alive = False
        if pid and pid.isdigit():
            try:
                os.kill(int(pid), 0)
                alive = True
            except OSError:
                alive = False
        if alive:
            report.add('stale_lock', INFO, 'client management lock is held by a live process', 'pid=%s' % pid, '', 'state')
        else:
            report.add(
                'stale_lock', WARN,
                'client management lock looks stale',
                'path=/etc/frp/client-manage.lock pid=%s' % (pid or 'none'),
                'do not remove the lock from doctor; retry sudo frp-client manage after confirming no other operator session is running',
                'state',
            )
    elif role in ('client', 'dual', 'partial_client'):
        report.add('stale_lock', PASS, 'no client management lock is present', '', '', 'state')

    for dpath, label in (
        ('/etc/frp', 'client config directory'),
        ('/etc/frp-auto-deploy', 'project config directory'),
        ('/var/lib/frp-auto-deploy', 'project state directory'),
    ):
        path = paths.p(dpath)
        if not path.exists():
            continue
        mode = paths.mode(dpath)
        if mode is None:
            continue
        writable_owner = bool(mode & stat.S_IWUSR)
        if not writable_owner:
            report.add(
                'dir_writability', WARN,
                '%s may not be writable for future lifecycle operations' % label,
                '%s mode %s' % (dpath, file_mode_oct(mode)),
                '',
                'state',
            )


def check_access_control(report, paths, facts, cfg, registry_state):
    """Validate Access Control Pack state, plugin wiring, and log path."""
    import importlib.util
    import sys as _sys

    acl = None
    candidates = []
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.append(Path(root) / 'usr/local/lib/frp-auto-deploy/frp_access_control.py')
    candidates.extend([
        Path(__file__).resolve().parent / 'frp_access_control.py',
        Path('/usr/local/lib/frp-auto-deploy/frp_access_control.py'),
    ])
    prev_bytecode = _sys.dont_write_bytecode
    _sys.dont_write_bytecode = True
    try:
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                spec = importlib.util.spec_from_file_location('frp_access_control', str(candidate))
                acl = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(acl)
                break
            except Exception as exc:
                report.add(
                    'ACCESS_CONFIG_ERROR', FAIL,
                    'ACCESS_CONFIG_ERROR: access control module failed to load',
                    str(exc),
                    're-run the server installer',
                    'state',
                )
                return
    finally:
        _sys.dont_write_bytecode = prev_bytecode
    if acl is None:
        report.add(
            'ACCESS_CONFIG_ERROR', FAIL,
            'ACCESS_CONFIG_ERROR: frp_access_control.py is missing',
            '',
            're-run the server installer',
            'installation',
        )
        return

    access_rel = '/var/lib/frp-auto-deploy/access-control.json'
    if isinstance(cfg, dict):
        configured = str(cfg.get('access_control_file') or '').strip()
        if configured.startswith('/'):
            access_rel = configured
    access_path = paths.p(access_rel)
    if not paths.is_file(access_rel):
        report.add(
            'ACCESS_CONFIG_ERROR', FAIL,
            'ACCESS_CONFIG_ERROR: access-control.json is missing',
            access_rel,
            're-run the server installer to create an empty access-control.json',
            'state',
        )
        access_state = None
    else:
        try:
            access_state = acl.load_access_state(path=access_path, cfg=cfg if isinstance(cfg, dict) else None)
            report.add(
                'ACCESS_CONFIG_ERROR', PASS,
                'access-control.json is readable and valid',
                access_rel, '', 'state',
            )
        except Exception as exc:
            report.add(
                'ACCESS_CONFIG_ERROR', FAIL,
                'ACCESS_CONFIG_ERROR: access-control.json is invalid',
                str(exc),
                'restore access-control.json from backup or recreate with frp-access',
                'state',
            )
            access_state = None

    if access_state is not None:
        registry = registry_state if isinstance(registry_state, dict) else {'clients': {}}
        for issue in acl.doctor_issues(access_state, registry):
            cls = str(issue.get('class') or 'ACCESS_CONFIG_ERROR')
            severity = str(issue.get('severity') or 'error').lower()
            status = FAIL if severity == 'error' else (WARN if severity == 'warn' else INFO)
            report.add(
                cls,
                status,
                '%s: %s' % (cls, issue.get('message') or 'issue'),
                '',
                'inspect Access Control with frpctl access; doctor does not rewrite ACL state',
                'state',
            )

    toml_rel = '/etc/frp/frps.toml'
    if paths.is_file(toml_rel):
        text = paths.read_text(toml_rel) or ''
        has_plugin = (
            '[[httpPlugins]]' in text
            and 'name = "frp-access"' in text
            and 'NewUserConn' in text
            and 'path = "/access-auth"' in text
        )
        if has_plugin:
            report.add(
                'ACCESS_PLUGIN_ERROR', PASS,
                'frps.toml wires NewUserConn httpPlugins to frp-access',
                '', '', 'installation',
            )
        else:
            report.add(
                'ACCESS_PLUGIN_ERROR', FAIL,
                'ACCESS_PLUGIN_ERROR: frps.toml is missing NewUserConn httpPlugins for frp-access',
                '',
                're-run the server installer to regenerate frps.toml',
                'installation',
            )
    else:
        report.add(
            'ACCESS_PLUGIN_ERROR', FAIL,
            'ACCESS_PLUGIN_ERROR: frps.toml is missing',
            toml_rel,
            're-run the server installer',
            'installation',
        )

    check_unit(report, facts, 'frp-access-plugin', 'access_plugin_service', 'frp-access-plugin.service')

    # Plugin readiness: when the unit is active, /healthz must be 200.
    units = facts.get('units') or {}
    access_unit = units.get('frp-access-plugin') or {}
    access_active = str(access_unit.get('active') or '') == 'active'
    skip_network = bool(os.environ.get('FRP_DOCTOR_SKIP_NETWORK')) or bool(
        os.environ.get('FRP_DEPLOY_TEST_ROOT')
    )
    if access_active and not skip_network:
        plugin_addr = '127.0.0.1:6101'
        if isinstance(cfg, dict):
            plugin_addr = str(cfg.get('access_plugin_addr') or plugin_addr).strip() or plugin_addr
        health_url = 'http://%s/healthz' % plugin_addr
        try:
            import urllib.request
            with urllib.request.urlopen(health_url, timeout=NETWORK_TIMEOUT) as resp:
                code = int(getattr(resp, 'status', 0) or resp.getcode())
            if code == 200:
                report.add(
                    'access_plugin_health', PASS,
                    'access plugin GET /healthz succeeded',
                    health_url, '', 'runtime',
                )
            else:
                report.add(
                    'access_plugin_health', FAIL,
                    'access plugin GET /healthz returned %s' % code,
                    health_url,
                    'inspect frp-access-plugin and authoritative Access/Registry state',
                    'runtime',
                )
        except Exception as exc:
            report.add(
                'access_plugin_health', FAIL,
                'access plugin GET /healthz failed',
                '%s (%s)' % (health_url, exc),
                'inspect frp-access-plugin and authoritative Access/Registry state',
                'runtime',
            )
    elif access_active and skip_network:
        report.add(
            'access_plugin_health', NOT_TESTED,
            'access plugin /healthz was not tested (network skipped)',
            '', '', 'runtime',
        )

    log_rel = '/var/log/frp-auto-deploy/access-conn.jsonl'
    if isinstance(cfg, dict):
        configured_log = str(cfg.get('access_conn_log_file') or '').strip()
        if configured_log.startswith('/'):
            log_rel = configured_log
    log_dir_rel = str(Path(log_rel).parent)
    log_dir = paths.p(log_dir_rel)
    if not log_dir.exists():
        report.add(
            'ACCESS_LOG_ERROR', FAIL,
            'ACCESS_LOG_ERROR: access connection log directory is missing',
            log_dir_rel,
            're-run the server installer so /var/log/frp-auto-deploy is created',
            'state',
        )
    elif not os.access(str(log_dir), os.W_OK):
        report.add(
            'ACCESS_LOG_ERROR', FAIL,
            'ACCESS_LOG_ERROR: access connection log directory is not writable',
            log_dir_rel,
            'ensure /var/log/frp-auto-deploy is writable by the access plugin',
            'state',
        )
    else:
        report.add(
            'ACCESS_LOG_ERROR', PASS,
            'access connection log directory is writable',
            log_dir_rel, '', 'state',
        )


def check_unit(report, facts, unit, check_id, label):
    systemd_usable = bool(facts.get('systemd_usable'))
    units = facts.get('units') or {}
    info = units.get(unit) or {}
    darwin_frpc = unit == 'frpc' and _facts_is_darwin(facts)
    if darwin_frpc:
        label = _frpc_runtime_label(facts)
    if not systemd_usable and not info:
        unavailable = 'launchd state unavailable' if darwin_frpc else 'systemd unavailable'
        report.add(check_id, NOT_TESTED, '%s was not tested (%s)' % (label, unavailable), '', '', 'runtime')
        return 'not_tested'
    active = str(info.get('active') or 'unknown')
    if active == 'active':
        report.add(check_id, PASS, '%s is active' % label, 'enabled=%s' % (info.get('enabled') or 'unknown'), '', 'runtime')
        return 'active'
    if active in ('inactive', 'failed'):
        journal = (facts.get('journal') or {}).get(unit) or ''
        detail = 'state=%s' % active
        if journal:
            detail += '\n' + redact(journal)
        recovery = _frpc_runtime_recovery(facts) if darwin_frpc else (
            'inspect the unit with systemctl status %s; doctor does not restart services' % unit
        )
        report.add(
            check_id, FAIL,
            '%s is not active' % label,
            detail,
            recovery,
            'runtime',
        )
        return active
    report.add(check_id, NOT_TESTED, '%s state is unknown' % label, 'state=%s' % active, '', 'runtime')
    return active


def check_port_collision(report, facts, listen_port, unit_state, check_id, label):
    if listen_port is None:
        return
    listeners = facts.get('listeners') or {}
    info = listeners.get(str(listen_port)) or listeners.get(listen_port) or {}
    listening = info.get('listening')
    if listening is None:
        report.add(check_id, NOT_TESTED, '%s listen port was not probed' % label, 'port=%s' % listen_port, '', 'runtime')
        return
    if unit_state in ('not_tested', 'unknown', None, ''):
        report.add(
            check_id, NOT_TESTED,
            '%s listen port was not validated without systemd' % label,
            'port=%s listening=%s' % (listen_port, listening),
            '',
            'runtime',
        )
        return
    if listening and unit_state == 'active':
        report.add(check_id, PASS, '%s is listening on the expected port' % label, 'port=%s' % listen_port, '', 'runtime')
    elif listening:
        report.add(
            check_id, FAIL,
            'a different process occupies the %s listen port' % label,
            'port=%s unit_state=%s' % (listen_port, unit_state),
            'identify the process on TCP/%s; doctor does not kill processes' % listen_port,
            'runtime',
        )
    elif unit_state == 'active':
        report.add(check_id, WARN, '%s is active but the listen port is not reachable locally' % label, 'port=%s' % listen_port, '', 'runtime')
    else:
        report.add(check_id, NOT_TESTED, '%s listen port is not in use' % label, 'port=%s unit_state=%s' % (listen_port, unit_state), '', 'runtime')



def check_service_profiles(report, paths, facts, cfg):
    """Validate Service Profiles store readability and schema."""
    import importlib.util
    import sys as _sys

    prof = None
    candidates = []
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.append(Path(root) / 'usr/local/lib/frp-auto-deploy/frp_service_profiles.py')
    candidates.extend([
        Path(__file__).resolve().parent / 'frp_service_profiles.py',
        Path('/usr/local/lib/frp-auto-deploy/frp_service_profiles.py'),
    ])
    prev_bytecode = _sys.dont_write_bytecode
    _sys.dont_write_bytecode = True
    try:
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                spec = importlib.util.spec_from_file_location('frp_service_profiles', str(candidate))
                prof = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(prof)
                break
            except Exception as exc:
                report.add(
                    'SERVICE_PROFILES_ERROR', FAIL,
                    'SERVICE_PROFILES_ERROR: service profiles module failed to load',
                    str(exc),
                    're-run the server installer',
                    'state',
                )
                return
    finally:
        _sys.dont_write_bytecode = prev_bytecode
    if prof is None:
        report.add(
            'SERVICE_PROFILES_ERROR', FAIL,
            'SERVICE_PROFILES_ERROR: frp_service_profiles.py is missing',
            '',
            're-run the server installer',
            'installation',
        )
        return

    profiles_rel = '/var/lib/frp-auto-deploy/service-profiles.json'
    if isinstance(cfg, dict):
        configured = str(cfg.get('service_profiles_file') or '').strip()
        if configured.startswith('/'):
            profiles_rel = configured
    if not paths.is_file(profiles_rel):
        report.add(
            'SERVICE_PROFILES_ERROR', FAIL,
            'SERVICE_PROFILES_ERROR: service-profiles.json is missing',
            profiles_rel,
            're-run the server installer to create an empty service-profiles.json',
            'state',
        )
        return
    try:
        profiles_path = paths.p(profiles_rel)
        state = prof.load_profiles_state(
            path=profiles_path,
            cfg=cfg if isinstance(cfg, dict) else None,
        )
        report.add(
            'SERVICE_PROFILES_ERROR', PASS,
            'service-profiles.json is readable and valid',
            profiles_rel, '', 'state',
        )
    except Exception as exc:
        report.add(
            'SERVICE_PROFILES_ERROR', FAIL,
            'SERVICE_PROFILES_ERROR: service-profiles.json is invalid',
            str(exc),
            'restore service-profiles.json from backup or recreate with frpctl create profile',
            'state',
        )
        return
    for issue in prof.doctor_issues(state):
        cls = str(issue.get('class') or 'SERVICE_PROFILES_ERROR')
        severity = str(issue.get('severity') or 'error').lower()
        status = FAIL if severity == 'error' else (WARN if severity == 'warn' else INFO)
        report.add(
            cls,
            status,
            '%s: %s' % (cls, issue.get('message') or 'issue'),
            '',
            'inspect Service Profiles with frpctl show profiles',
            'state',
        )



def check_egress_control(report, paths, facts, cfg):
    """Validate Controlled Egress policy, unit, and listen configuration (read-only)."""
    import importlib.util
    import sys as _sys

    eg = None
    candidates = []
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.append(Path(root) / 'usr/local/lib/frp-auto-deploy/frp_egress_control.py')
    candidates.extend([
        Path(__file__).resolve().parent / 'frp_egress_control.py',
        Path('/usr/local/lib/frp-auto-deploy/frp_egress_control.py'),
    ])
    prev_bytecode = _sys.dont_write_bytecode
    _sys.dont_write_bytecode = True
    try:
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                spec = importlib.util.spec_from_file_location('frp_egress_control', str(candidate))
                eg = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(eg)
                break
            except Exception as exc:
                report.add(
                    'EGRESS_CONFIG_ERROR', FAIL,
                    'EGRESS_CONFIG_ERROR: egress control module failed to load',
                    str(exc),
                    're-run the server installer',
                    'state',
                )
                return
    finally:
        _sys.dont_write_bytecode = prev_bytecode
    if eg is None:
        report.add(
            'EGRESS_CONFIG_ERROR', FAIL,
            'EGRESS_CONFIG_ERROR: frp_egress_control.py is missing',
            '',
            're-run the server installer',
            'installation',
        )
        return

    egress_rel = '/var/lib/frp-auto-deploy/egress-control.json'
    if isinstance(cfg, dict):
        configured = str(cfg.get('egress_control_file') or '').strip()
        if configured.startswith('/'):
            egress_rel = configured
    if not paths.is_file(egress_rel):
        report.add(
            'EGRESS_CONFIG_ERROR', FAIL,
            'EGRESS_CONFIG_ERROR: egress-control.json is missing',
            egress_rel,
            're-run the server installer to create an empty egress-control.json',
            'state',
        )
        return
    try:
        egress_path = paths.p(egress_rel)
        state = eg.load_egress_state(
            path=egress_path,
            cfg=cfg if isinstance(cfg, dict) else None,
        )
        report.add(
            'EGRESS_CONFIG_ERROR', PASS,
            'egress-control.json is readable and valid',
            egress_rel, '', 'state',
        )
    except Exception as exc:
        report.add(
            'EGRESS_CONFIG_ERROR', FAIL,
            'EGRESS_CONFIG_ERROR: egress-control.json is invalid (fail-closed)',
            str(exc),
            'restore egress-control.json from backup or recreate with frpctl create egress-profile',
            'state',
        )
        return

    try:
        host, port = eg.listen_bind(cfg if isinstance(cfg, dict) else None)
        report.add(
            'EGRESS_LISTEN', INFO,
            'Controlled Egress listen configured',
            '%s:%s' % (host, port),
            '',
            'runtime',
        )
    except Exception as exc:
        report.add(
            'EGRESS_CONFIG_ERROR', FAIL,
            'EGRESS_CONFIG_ERROR: invalid egress listen configuration',
            str(exc),
            'fix egress_listen_addr / egress_listen_port in config.json',
            'state',
        )

    try:
        import subprocess
        proc = subprocess.run(
            ['systemctl', 'is-active', 'frp-egress-gateway'],
            capture_output=True, text=True, timeout=5,
        )
        unit_state = (proc.stdout or '').strip() or 'unknown'
    except Exception:
        unit_state = 'unknown'
    if unit_state == 'active':
        report.add('EGRESS_UNIT', PASS, 'frp-egress-gateway is active', unit_state, '', 'runtime')
    elif unit_state == 'failed':
        report.add('EGRESS_UNIT', FAIL, 'frp-egress-gateway failed', unit_state, 'systemctl status frp-egress-gateway', 'runtime')
    else:
        report.add('EGRESS_UNIT', WARN, 'frp-egress-gateway is not active', unit_state, 'systemctl status frp-egress-gateway', 'runtime')

    for issue in eg.doctor_issues(state):
        cls = str(issue.get('class') or 'EGRESS_CONFIG_ERROR')
        severity = str(issue.get('severity') or 'error').lower()
        status = FAIL if severity == 'error' else (WARN if severity == 'warn' else INFO)
        report.add(
            cls,
            status,
            '%s: %s' % (cls, issue.get('message') or 'issue'),
            '',
            'inspect Controlled Egress with frpctl show egress-profiles',
            'state',
        )


def check_server(report, paths, facts, skip_network):
    expect_root = bool(facts.get('expect_root_owner'))
    cfg, err = load_json_path(paths, '/etc/frp-auto-deploy/config.json')
    if err:
        report.add(
            'server_config', FAIL,
            'server config.json is %s' % err,
            '',
            'restore /etc/frp-auto-deploy/config.json from backup or re-run the server installer',
            'installation',
        )
        cfg = {}
    else:
        if not isinstance(cfg, dict):
            report.add('server_config', FAIL, 'server config.json is not an object', '', 're-run the server installer', 'installation')
            cfg = {}
        else:
            ports = server_config_ports(cfg)
            missing = []
            for key in ('public_host', 'frp_public', 'frp_listen', 'alloc_listen', 'port_start', 'port_end', 'allocator_url'):
                if not ports.get(key) and key != 'public_host':
                    missing.append(key)
            if not ports.get('public_host'):
                missing.append('public_host')
            issues = []
            if ports['port_start'] and ports['port_end'] and ports['port_start'] > ports['port_end']:
                issues.append('port_start > port_end')
            if ports['frp_listen'] and ports['alloc_listen'] and ports['frp_listen'] == ports['alloc_listen']:
                issues.append('FRP listen port equals allocator listen port')
            url = ports.get('allocator_url') or ''
            if url and not url.lower().startswith('https://'):
                issues.append('allocator_public_url is not HTTPS')
            if missing or issues:
                report.add(
                    'server_config', FAIL,
                    'server config is incomplete or inconsistent',
                    '; '.join(missing + issues),
                    're-run the server installer with the intended public/listen values',
                    'installation',
                )
            else:
                report.add('server_config', PASS, 'server config structure is valid', '', '', 'installation')
            report.display['server_ports'] = ports
            # Optional public hostname DNS alias (access only; never FAIL product).
            alias = ports.get('public_hostname') or ''
            if not alias:
                report.add(
                    'public_hostname_dns', NOT_APPLICABLE,
                    'public hostname is not configured',
                    '',
                    '',
                    'network',
                )
            else:
                scfg = None
                try:
                    import importlib.util
                    here = Path(__file__).resolve().parent
                    candidates = [
                        here / 'frp_server_config.py',
                        Path('/usr/local/lib/frp-auto-deploy/frp_server_config.py'),
                    ]
                    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
                    if root:
                        candidates.insert(1, Path(root) / 'usr/local/lib/frp-auto-deploy/frp_server_config.py')
                    for path in candidates:
                        if path.is_file():
                            spec = importlib.util.spec_from_file_location('frp_server_config', str(path))
                            scfg = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(scfg)
                            break
                except Exception:
                    scfg = None
                if scfg is None:
                    report.add(
                        'public_hostname_dns', INFO,
                        'public hostname is configured; DNS helper unavailable',
                        alias,
                        '',
                        'network',
                    )
                else:
                    assessment = scfg.assess_dns(alias, ports.get('public_ip') or ports.get('public_host') or '')
                    status_map = {
                        'NOT_CONFIGURED': NOT_APPLICABLE,
                        'PENDING': WARN,
                        'READY': PASS,
                        'MISMATCH': WARN,
                    }
                    dns_status = status_map.get(assessment.get('status'), WARN)
                    detail_bits = [alias, assessment.get('status') or '']
                    addrs = assessment.get('addresses') or []
                    if addrs:
                        detail_bits.append('resolved=' + ','.join(addrs[:8]))
                    report.add(
                        'public_hostname_dns', dns_status,
                        assessment.get('message') or 'public hostname DNS check',
                        '; '.join(x for x in detail_bits if x),
                        'create or correct the external DNS record; FRP continues using the Public IP',
                        'network',
                    )
            # Public vs listen difference is intentional (P2.8). Never FAIL for that.
            if ports['frp_public'] and ports['frp_listen'] and ports['frp_public'] != ports['frp_listen']:
                report.add(
                    'public_listen_frp', PASS,
                    'FRP public and listen ports differ by design',
                    'public=%s listen=%s' % (ports['frp_public'], ports['frp_listen']),
                    '',
                    'network',
                )
            if ports['alloc_public'] and ports['alloc_listen'] and ports['alloc_public'] != ports['alloc_listen']:
                report.add(
                    'public_listen_allocator', PASS,
                    'allocator public and listen ports differ by design',
                    'public=%s listen=%s' % (ports['alloc_public'], ports['alloc_listen']),
                    '',
                    'network',
                )

    token_path = '/etc/frp/server_token'
    if cfg:
        token_path = str(cfg.get('token_file') or token_path)
        if token_path.startswith('/'):
            pass
        else:
            token_path = '/etc/frp/server_token'
    token_file = paths.p(token_path if token_path.startswith('/') else '/etc/frp/server_token')
    token_abs = token_path if token_path.startswith('/') else '/etc/frp/server_token'
    if not paths.is_file(token_abs):
        report.add('server_token', FAIL, 'FRP token is missing', token_abs, 're-run the server installer; doctor does not create a token', 'security')
    else:
        data = paths.read_bytes(token_abs) or b''
        if not data.strip():
            report.add('server_token', FAIL, 'FRP token is empty', '', 're-run the server installer', 'security')
        else:
            check_permissions(report, paths, token_abs, 'server_token', secret=True, expect_root=expect_root, section='security')
            # Rename message: the permission helper already added a check; if it PASSed, keep it.
            # Add a dedicated existence PASS only when permissions also passed.
            last = report.checks[-1] if report.checks else {}
            if last.get('id') == 'server_token' and last.get('status') == PASS:
                last['message'] = 'FRP token is present and permission-safe'

    registry_path = '/var/lib/frp-auto-deploy/registry.json'
    if cfg:
        registry_path = str(cfg.get('registry_file') or registry_path)
        if not registry_path.startswith('/'):
            registry_path = '/var/lib/frp-auto-deploy/registry.json'
    state, err = load_json_path(paths, registry_path)
    if err:
        report.add(
            'server_registry', FAIL,
            'registry.json is %s' % err,
            '',
            'restore the registry from backup; doctor does not rewrite it',
            'state',
        )
    else:
        status, message, extra = validate_registry(state, cfg if isinstance(cfg, dict) else None)
        rec = ''
        if status == FAIL:
            rec = 'restore registry.json from a known-good backup; doctor does not repair it'
        report.add('server_registry', status, message, '; '.join(extra[:4]) if extra and status != PASS else '', rec, 'state')
        check_permissions(report, paths, registry_path, 'server_registry_permissions', secret=True, expect_root=expect_root, section='security')

    pki_dir = '/etc/frp-auto-deploy/pki'
    if cfg:
        ca_cfg = str(cfg.get('tls_ca_cert') or '')
        if ca_cfg.endswith('/ca.crt'):
            pki_dir = ca_cfg[:-7] or pki_dir
    ca_crt = pki_dir + '/ca.crt'
    ca_key = pki_dir + '/ca.key'
    server_crt = pki_dir + '/server.crt'
    server_key = pki_dir + '/server.key'
    for abs_path, cid, secret, label in (
        (ca_key, 'allocator_ca_key', True, 'CA private key'),
        (ca_crt, 'allocator_ca', False, 'Allocator CA'),
        (server_key, 'allocator_server_key', True, 'allocator private key'),
        (server_crt, 'allocator_server_cert', False, 'Allocator cert'),
    ):
        if not paths.is_file(abs_path):
            report.add(cid, FAIL, '%s is missing' % label, abs_path, 're-run the server installer; do not rotate the CA unless it is actually missing', 'security')
            continue
        if secret:
            check_permissions(report, paths, abs_path, cid + '_permissions', secret=True, expect_root=expect_root, section='security')
            continue
        info = cert_info(paths.p(abs_path))
        if not info.get('ok'):
            report.add(cid, FAIL, '%s is not a valid X.509 certificate' % label, info.get('error') or '', 'restore the certificate from backup or re-run the server installer', 'security')
            continue
        rec = ''
        if cid == 'allocator_server_cert' and info.get('status') == FAIL and 'SAN' not in (info.get('message') or ''):
            rec = 're-run the server installer to reissue the allocator server certificate under the existing CA'
        elif info.get('status') == WARN:
            rec = 'plan a server-certificate reissue before expiry; doctor does not auto-renew'
        msg = '%s — %s' % (label, info.get('message'))
        detail = ''
        if facts.get('verbose'):
            detail = 'subject=%s SAN_DNS=%s SAN_IP=%s fingerprint=%s' % (
                info.get('subject'), ','.join(info.get('dns') or []), ','.join(info.get('ips') or []),
                (info.get('fingerprint') or '')[:16],
            )
        report.add(cid, info.get('status') or PASS, msg, detail, rec, 'security')

    if paths.is_file(ca_crt) and paths.is_file(server_crt):
        ok, err = verify_signed_by_ca(paths.p(ca_crt), paths.p(server_crt))
        if ok:
            report.add('allocator_cert_chain', PASS, 'allocator certificate is signed by the local CA', '', '', 'security')
        else:
            report.add(
                'allocator_cert_chain', FAIL,
                'allocator certificate is not signed by the local CA',
                err,
                're-run the server installer to reissue the allocator server certificate under the existing CA. Do not rotate the CA.',
                'security',
            )

    if cfg and paths.is_file(server_crt):
        ports = server_config_ports(cfg)
        host = ports.get('public_host') or ''
        want_dns = set()
        want_ips = set(['127.0.0.1'])
        if host:
            try:
                socket.inet_pton(socket.AF_INET, host)
                want_ips.add(host)
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, host)
                    want_ips.add(host)
                except OSError:
                    want_dns.add(host)
        want_dns.add('localhost')
        have_dns, have_ips = read_cert_sans(paths.p(server_crt))
        missing = []
        for name in sorted(want_dns):
            if name not in have_dns:
                missing.append('DNS:%s' % name)
        for addr in sorted(want_ips):
            if addr not in have_ips:
                missing.append('IP:%s' % addr)
        if missing:
            report.add(
                'allocator_san', FAIL,
                'allocator certificate SAN does not match configured public host',
                'missing %s' % ', '.join(missing),
                'Re-run the server installer. The existing CA should be preserved and only the server certificate reissued.',
                'security',
            )
        else:
            report.add('allocator_san', PASS, 'allocator certificate SAN covers the configured identities', '', '', 'security')

    if not paths.is_file('/usr/local/lib/frp-auto-deploy/frp-port-allocator.py'):
        report.add('allocator_python', FAIL, 'allocator Python is missing', '', 're-run the server installer', 'installation')
    else:
        report.add('allocator_python', PASS, 'allocator Python is present', '', '', 'installation')

    frps_state = check_unit(report, facts, 'frps', 'frps_service', 'frps.service')
    alloc_state = check_unit(report, facts, 'frp-port-allocator', 'allocator_service', 'frp-port-allocator.service')
    if cfg:
        ports = server_config_ports(cfg)
        check_port_collision(report, facts, ports.get('frp_listen'), frps_state, 'frps_listen_port', 'frps')
        check_port_collision(report, facts, ports.get('alloc_listen'), alloc_state, 'allocator_listen_port', 'allocator')
        if ports.get('deployment_mode') == 'single443':
            frontend_state = check_unit(report, facts, 'frp-frontend', 'frontend_service', 'frp-frontend.service')
            check_port_collision(report, facts, ports.get('frp_public'), frontend_state, 'frontend_listen_port', 'frontend')
            conf = paths.p('/etc/frp-auto-deploy/frontend.conf')
            if conf.is_file():
                text = conf.read_text(encoding='utf-8', errors='replace')
                missing = []
                if 'location = "/~!frp"' not in text:
                    missing.append('WSS path /~!frp')
                if 'proxy_ssl_verify on' not in text:
                    missing.append('proxy_ssl_verify')
                if 'proxy_ssl_name localhost;' not in text:
                    missing.append('proxy_ssl_name localhost')
                if 'proxy_ssl_server_name on' not in text:
                    missing.append('proxy_ssl_server_name')
                if 'listen' not in text or 'ssl' not in text:
                    missing.append('TLS listen')
                public_host = str(ports.get('public_host') or '').strip()
                if public_host and public_host != 'localhost' and ('proxy_ssl_name %s;' % public_host) in text:
                    missing.append('proxy_ssl_name must be localhost, not the public identity')
                if missing:
                    report.add(
                        'frontend_config', FAIL,
                        'single-443 frontend config is missing required directives',
                        ', '.join(missing),
                        're-run the server installer',
                        'installation',
                    )
                else:
                    report.add(
                        'frontend_config', PASS,
                        'single-443 frontend config routes HTTPS allocator and WSS control',
                        str(conf), '', 'installation',
                    )
            else:
                report.add('frontend_config', FAIL, 'single-443 frontend config is missing', '', 're-run the server installer', 'installation')
        else:
            report.add('frontend_service', INFO, 'Direct mode does not use the HTTPS/WSS frontend', '', '', 'installation')

    net = (facts.get('network') or {}).get('allocator_healthz')
    if net is None and not skip_network and cfg:
        ports = server_config_ports(cfg)
        listen = ports.get('alloc_listen') or 6099
        ca = paths.p(ca_crt)
        if ca.is_file():
            net = https_healthz('https://127.0.0.1:%s/healthz' % listen, ca)
    if net is None:
        report.add('allocator_health', NOT_TESTED, 'allocator HTTPS health was not tested', '', '', 'network')
    elif net.get('ok'):
        report.add('allocator_health', PASS, 'allocator GET /healthz succeeded', net.get('detail') or '', '', 'network')
    else:
        cls = net.get('error_class') or 'unreachable'
        status = FAIL if cls in ('UNKNOWN_CA', 'HOSTNAME_MISMATCH', 'EXPIRED_CERT', 'HTTP_500', 'HTTP_404') else WARN
        rec = 'inspect frp-port-allocator.service; doctor does not restart it'
        if cls in ('UNKNOWN_CA', 'HOSTNAME_MISMATCH', 'EXPIRED_CERT'):
            rec = 're-run the server installer to reissue the allocator certificate under the existing CA'
            status = FAIL
        elif cls == 'TLS_RESET':
            rec = (
                'TCP connected but TLS was reset. Some enterprise firewalls reset TLS on '
                'non-standard ports. Use Enterprise single-443 mode; do not downgrade to HTTP.'
            )
            status = FAIL
        report.add('allocator_health', status, 'allocator HTTPS health check failed (%s)' % cls, net.get('detail') or '', rec, 'network')

    if cfg and server_config_ports(cfg).get('deployment_mode') == 'single443':
        ports = server_config_ports(cfg)
        frontend_port = ports.get('frp_public') or 443
        public_host = str(ports.get('public_host') or '').strip()
        ca_path = paths.p(ca_crt)
        fe_net = (facts.get('network') or {}).get('frontend_healthz')
        fe_ca = (facts.get('network') or {}).get('frontend_ca')
        if fe_net is None and not skip_network and public_host and ca_path.is_file():
            fe_net = https_loopback_get(public_host, frontend_port, '/healthz', ca_path)
        if fe_ca is None and not skip_network and public_host and ca_path.is_file():
            fe_ca = https_loopback_get(public_host, frontend_port, '/ca.crt', ca_path)
        alloc_ok = bool(net and net.get('ok'))
        if fe_net is None:
            report.add('frontend_proxy_health', NOT_TESTED, 'frontend proxied /healthz was not tested', '', '', 'network')
        elif fe_net.get('ok'):
            report.add(
                'frontend_proxy_health', PASS,
                'frontend GET /healthz succeeded through verified HTTPS proxy',
                fe_net.get('detail') or '', '', 'network',
            )
        else:
            cls = fe_net.get('error_class') or 'unreachable'
            rec = 'inspect frp-frontend.service and frontend.conf; doctor does not restart it'
            if alloc_ok:
                rec = (
                    'allocator backend /healthz succeeded but the public frontend proxy failed. '
                    'Clients cannot use TCP/443. Re-run the server installer; do not disable proxy_ssl_verify.'
                )
            report.add(
                'frontend_proxy_health', FAIL,
                'frontend proxied /healthz failed (%s)' % cls,
                fe_net.get('detail') or '', rec, 'network',
            )
        expected_fp = ''
        if ca_path.is_file():
            expected_fp, _fp_err = fingerprint_cert_file(ca_path)
            expected_fp = expected_fp or ''
        if fe_ca is None:
            report.add('frontend_ca_endpoint', NOT_TESTED, 'frontend GET /ca.crt was not tested', '', '', 'network')
        else:
            rec = 'inspect frp-frontend.service; a 502 HTML body is not a CA'
            if alloc_ok:
                rec = (
                    'allocator backend is healthy but frontend GET /ca.crt failed. '
                    'A 502 HTML body must not be treated as the project CA. Re-run the server installer.'
                )
            body = fe_ca.get('body')
            if body is not None and body != '':
                verdict = classify_frontend_ca_body(
                    body,
                    fe_ca.get('content_type') or '',
                    expected_fp or fe_ca.get('expected_fingerprint') or '',
                )
                if verdict.get('ok'):
                    report.add(
                        'frontend_ca_endpoint', PASS,
                        'frontend GET /ca.crt returned the pinned project CA',
                        verdict.get('detail') or fe_ca.get('detail') or '', '', 'network',
                    )
                else:
                    report.add(
                        'frontend_ca_endpoint', FAIL,
                        'frontend GET /ca.crt failed (%s)' % (verdict.get('error_class') or 'NOT_A_CA'),
                        verdict.get('detail') or '', rec, 'network',
                    )
            elif fe_ca.get('ok'):
                report.add(
                    'frontend_ca_endpoint', PASS,
                    'frontend GET /ca.crt returned the pinned project CA',
                    fe_ca.get('detail') or '', '', 'network',
                )
            else:
                report.add(
                    'frontend_ca_endpoint', FAIL,
                    'frontend GET /ca.crt failed (%s)' % (fe_ca.get('error_class') or 'unreachable'),
                    fe_ca.get('detail') or '', rec, 'network',
                )

    check_access_control(report, paths, facts, cfg if isinstance(cfg, dict) else {}, state if isinstance(state, dict) else {})
    check_service_profiles(report, paths, facts, cfg if isinstance(cfg, dict) else {})
    check_egress_control(report, paths, facts, cfg if isinstance(cfg, dict) else {})

    bootstrap_abs = '/var/lib/frp-auto-deploy/bootstrap'
    enrollments_abs = '/var/lib/frp-auto-deploy/enrollments'
    retention_days = 30
    if cfg:
        configured = str(cfg.get('bootstrap_dir') or '').strip()
        enrollments = str(cfg.get('enrollments_dir') or '').strip()
        if configured.startswith('/'):
            bootstrap_abs = configured
        elif enrollments.startswith('/'):
            parent = enrollments.rsplit('/', 1)[0]
            if parent:
                bootstrap_abs = parent + '/bootstrap'
        if enrollments.startswith('/'):
            enrollments_abs = enrollments
    elc = None
    for candidate in (
        Path(__file__).resolve().parent / 'frp_enrollment_lifecycle.py',
        Path('/usr/local/lib/frp-auto-deploy/frp_enrollment_lifecycle.py'),
    ):
        if candidate.is_file():
            import importlib.util
            spec = importlib.util.spec_from_file_location('frp_enrollment_lifecycle', str(candidate))
            elc = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(elc)
            except Exception:
                elc = None
            break
    if elc is not None and cfg:
        try:
            retention_days = elc.retention_days_from_config(cfg)
        except Exception as exc:
            report.add(
                'enrollment_retention_config', WARN,
                'enrollment_retention_days is invalid; using default 30',
                str(exc),
                'set enrollment_retention_days to an integer between 1 and 3650',
                'config',
            )
            retention_days = 30
    if paths.is_dir(bootstrap_abs) or paths.is_dir(enrollments_abs):
        if elc is not None:
            findings, status = elc.doctor_scan_enrollment_lifecycle(
                enrollments_abs, bootstrap_abs, retention_days
            )
            report.add(
                'enrollment_retention', INFO,
                'enrollment retention policy: %s days' % status['retention_days'],
                'active=%s terminal=%s eligible=%s' % (
                    status['active'], status['terminal'], status['eligible'],
                ),
                '',
                'state',
            )
            severity = {
                'invalid_pairing': FAIL,
                'duplicate_pairing': FAIL,
                'orphan_bootstrap_ticket': WARN,
                'malformed_enrollment': WARN,
                'malformed_terminal_timestamp': WARN,
                'retention_overdue': WARN,
            }
            for kind, eid, detail in findings:
                report.add(
                    'enrollment_lifecycle_%s_%s' % (kind, eid),
                    severity.get(kind, WARN),
                    '%s: %s' % (kind.replace('_', ' '), detail),
                    'id=%s' % eid,
                    'doctor does not delete enrollment metadata',
                    'state',
                )
            if not findings:
                report.add(
                    'enrollment_lifecycle', PASS,
                    'enrollment lifecycle records are consistent',
                    'retention_days=%s active=%s terminal=%s' % (
                        retention_days, status['active'], status['terminal'],
                    ),
                    '',
                    'state',
                )
        else:
            # Fallback when lifecycle helper is unavailable: keep a quiet INFO.
            report.add(
                'bootstrap_tickets', INFO,
                'bootstrap ticket directory present',
                bootstrap_abs,
                '',
                'state',
            )
    else:
        report.add(
            'enrollment_retention', INFO,
            'enrollment retention policy: %s days' % retention_days,
            'active=0 terminal=0 eligible=0',
            '',
            'state',
        )

    if cfg:
        ports = server_config_ports(cfg)
        report.display['server_endpoints'] = {
            'deployment_mode': ports.get('deployment_mode') or 'direct',
            'frp_transport': ports.get('frp_transport') or 'tcp',
            'frp_public': '%s:%s' % (ports.get('public_host') or 'unknown', ports.get('frp_public') or '?'),
            'frp_listen': '%s:%s' % (ports.get('frp_bind_addr') or ports.get('listen_host') or '0.0.0.0', ports.get('frp_listen') or '?'),
            'allocator_public': ports.get('allocator_url') or '',
            'allocator_listen': '%s:%s' % (ports.get('listen_host') or '0.0.0.0', ports.get('alloc_listen') or '?'),
            'service_range': '%s-%s' % (ports.get('port_start') or '?', ports.get('port_end') or '?'),
        }


def check_client(report, paths, facts, skip_network):
    expect_root = bool(facts.get('expect_root_owner'))
    state, err = load_json_path(paths, '/etc/frp/client-state.json')
    if err == 'missing':
        report.add(
            'client_state', FAIL,
            'client-state.json is missing',
            '',
            'Restore /etc/frp/client-state.json from the latest valid backup.',
            'installation',
        )
        state = None
    elif err:
        report.add(
            'client_state', FAIL,
            'client-state.json is %s' % err,
            '',
            'Restore /etc/frp/client-state.json from the latest valid backup.',
            'state',
        )
        state = None
    else:
        if not isinstance(state, dict):
            report.add('client_state', FAIL, 'client-state.json is not an object', '', 'Restore /etc/frp/client-state.json from the latest valid backup.', 'state')
            state = None
        elif state.get('schema_version') != 1:
            report.add(
                'client_state', FAIL,
                'client-state.json schema is unsupported',
                'schema_version=%s' % state.get('schema_version'),
                'Restore a schema v1 client-state.json from backup, then run sudo frp-client manage and Apply.',
                'state',
            )
        elif 'services' not in state:
            report.add(
                'client_state', FAIL,
                "client-state.json is missing required 'services' data",
                '',
                'Restore /etc/frp/client-state.json from the latest valid backup.',
                'state',
            )
        else:
            services = state.get('services') or {}
            issues = []
            ids = set()
            if not isinstance(services, dict):
                issues.append('services is not an object')
                services = {}
            for sid, rec in services.items():
                if not isinstance(rec, dict):
                    issues.append('service %s is not an object' % sid)
                    continue
                key = str(rec.get('id') or sid)
                if key in ids:
                    issues.append('duplicate service id %s' % key)
                ids.add(key)
                lp = coerce_port(rec.get('local_port'))
                rp = coerce_port(rec.get('remote_port'))
                if rec.get('enabled', True) not in (True, False):
                    issues.append('service %s has invalid enabled flag' % key)
                if lp is None:
                    issues.append('service %s has invalid target port' % key)
                if rp is None:
                    issues.append('service %s has invalid public port' % key)
            url = str(state.get('allocator_url') or '')
            if url and not url.lower().startswith('https://'):
                issues.append('allocator URL is not HTTPS')
            if not state.get('machine_id') and not state.get('host_id'):
                issues.append('machine/client identity fields are missing')
            if issues:
                report.add('client_state', FAIL, 'client-state.json failed validation', '; '.join(issues[:8]), 'Restore /etc/frp/client-state.json from the latest valid backup.', 'state')
            else:
                enabled = sum(1 for s in services.values() if isinstance(s, dict) and s.get('enabled', True) is not False)
                disabled = max(0, len(services) - enabled)
                report.add('client_state', PASS, 'client-state.json is valid', '%s enabled / %s disabled' % (enabled, disabled), '', 'state')
                report.display['client_services'] = {'enabled': enabled, 'disabled': disabled, 'total': len(services)}
        check_permissions(report, paths, '/etc/frp/client-state.json', 'client_state_permissions', secret=True, expect_root=expect_root, section='security')

    key_p = '/etc/frp/client-identity.key'
    pub_p = '/etc/frp/client-identity.pub'
    mac_p = '/etc/frp/client-identity.mac'
    missing_ident = [p for p in (key_p, pub_p, mac_p) if not paths.is_file(p)]
    if len(missing_ident) == 3:
        report.add(
            'client_identity', INFO,
            'management identity is not established',
            '',
            'Create a short-lived Enrollment Code on the server with sudo frpctl enroll, then enroll this client.',
            'security',
        )
    elif missing_ident:
        report.add(
            'client_identity', FAIL,
            'management identity files are incomplete',
            'missing %s' % ', '.join(missing_ident),
            'Do not regenerate identity automatically. Create a new Enrollment Code with sudo frpctl enroll and re-enroll this client.',
            'security',
        )
    else:
        macval = (paths.read_text(mac_p) or '').strip()
        if not HEX64_RE.fullmatch(macval.lower()):
            report.add('client_identity', FAIL, 'management MAC file is not a valid 64-hex secret reference', 'length=%s' % len(macval), 're-enroll this client with a new Enrollment Code', 'security')
        else:
            derived, err = pubkey_from_private(paths.p(key_p))
            pub = paths.read_text(pub_p) or ''
            if err:
                report.add('client_identity', FAIL, 'management private key is unusable', err, 'Do not overwrite the damaged identity. Re-enroll with a new Enrollment Code.', 'security')
            else:
                if canonicalize_pub(derived) != canonicalize_pub(pub):
                    report.add(
                        'client_identity', FAIL,
                        'management public/private key pair does not match',
                        '',
                        'Do not overwrite the damaged identity. Re-enroll with a new Enrollment Code.',
                        'security',
                    )
                else:
                    fp = hashlib.sha256(canonicalize_pub(pub).encode('utf-8')).hexdigest()[:16]
                    report.add('client_identity', PASS, 'management identity files are present and consistent', 'pubkey_fingerprint=%s' % fp, '', 'security')
        check_permissions(report, paths, key_p, 'client_identity_permissions', secret=True, expect_root=expect_root, section='security')
        check_permissions(report, paths, mac_p, 'client_identity_mac_permissions', secret=True, expect_root=expect_root, section='security')

    ca_path = '/etc/frp-auto-deploy/allocator-ca.crt'
    if not paths.is_file(ca_path):
        report.add(
            'client_ca', FAIL,
            'allocator CA certificate is missing',
            '',
            're-run client enrollment with FRP_ALLOCATOR_CA_SHA256 from the server Enrollment Code output',
            'security',
        )
        ca_ok = False
    else:
        info = cert_info(paths.p(ca_path))
        if not info.get('ok'):
            report.add('client_ca', FAIL, 'allocator CA is not a valid X.509 certificate', info.get('error') or '', 'replace allocator-ca.crt from a trusted server copy', 'security')
            ca_ok = False
        else:
            report.add('client_ca', info.get('status') or PASS, 'Allocator CA — %s' % info.get('message'), '', '', 'security')
            ca_ok = info.get('status') != FAIL

    toml_path = '/etc/frp/frpc.toml'
    access_path = '/etc/frp/access-info.txt'
    if state and isinstance(state, dict) and isinstance(state.get('services'), dict):
        services = state.get('services') or {}
        enabled = []
        for sid, rec in services.items():
            if not isinstance(rec, dict):
                continue
            if rec.get('enabled', True) is False:
                continue
            enabled.append(str(rec.get('id') or sid))
        if not paths.is_file(toml_path):
            report.add(
                'frpc_config', FAIL,
                'client-state is valid but frpc.toml is missing',
                '',
                'sudo frp-client manage\n  Apply the current configuration',
                'state',
            )
        else:
            toml_text = paths.read_text(toml_path) or ''
            proxies = parse_frpc_proxies(toml_text)
            proxy_names = [str(p.get('name') or '') for p in proxies]
            missing_proxy = []
            port_mismatch = []
            extra_enabled = []
            for sid, rec in services.items():
                if not isinstance(rec, dict):
                    continue
                sid_s = str(rec.get('id') or sid)
                present = any(sid_s and sid_s in name for name in proxy_names)
                if rec.get('enabled', True) is False:
                    if present:
                        extra_enabled.append(sid_s)
                    continue
                if not present:
                    missing_proxy.append(sid_s)
                    continue
                want = coerce_port(rec.get('remote_port'))
                for proxy in proxies:
                    if sid_s in str(proxy.get('name') or ''):
                        if want is not None and coerce_port(proxy.get('remotePort')) not in (None, want):
                            port_mismatch.append(sid_s)
            if missing_proxy or port_mismatch:
                report.add(
                    'frpc_config', FAIL,
                    'frpc.toml has drifted from client-state.json',
                    'missing proxies=%s port mismatches=%s' % (','.join(missing_proxy) or 'none', ','.join(port_mismatch) or 'none'),
                    'sudo frp-client manage\n  Apply the current configuration',
                    'state',
                )
            elif extra_enabled:
                report.add(
                    'frpc_config', WARN,
                    'disabled services still appear in frpc.toml',
                    ','.join(extra_enabled),
                    'sudo frp-client manage\n  Apply the current configuration',
                    'state',
                )
            else:
                report.add('frpc_config', PASS, 'frpc.toml matches enabled client-state services', '', '', 'state')
            # Disabled reserved services are legitimate — no "unused port" error.
            disabled_n = sum(1 for rec in services.values() if isinstance(rec, dict) and rec.get('enabled', True) is False)
            if disabled_n:
                report.add('client_disabled_services', PASS, 'disabled reserved services are present and legitimate', 'count=%s' % disabled_n, '', 'state')

        if not paths.is_file(access_path):
            report.add(
                'access_info', WARN,
                'access-info.txt is missing',
                'display-only file; state/runtime can still be healthy',
                'sudo frp-client info regenerates connection text from local client-state when the file is absent',
                'state',
            )
        else:
            report.add('access_info', PASS, 'access-info.txt is present', '', '', 'state')
    elif not paths.is_file(toml_path) and report.role in ('client', 'dual', 'partial_client'):
        report.add('frpc_config', FAIL, 'frpc.toml is missing', '', 'sudo frp-client manage and Apply, or restore from backup', 'state')

    if state is not None and not client_has_enabled_services(state):
        info = (facts.get('units') or {}).get('frpc') or {}
        active = str(info.get('active') or 'unknown')
        if active in ('inactive', 'failed'):
            report.add(
                'frpc_service', PASS,
                'frpc is inactive because no enabled services are published',
                'state=%s' % active,
                '',
                'runtime',
            )
        elif active == 'active':
            report.add(
                'frpc_service', INFO,
                'frpc is running with no enabled services',
                'state=%s' % active,
                '',
                'runtime',
            )
        else:
            check_unit(report, facts, 'frpc', 'frpc_service', _frpc_runtime_label(facts))
    else:
        check_unit(report, facts, 'frpc', 'frpc_service', _frpc_runtime_label(facts))

    alloc_url = ''
    frp_host = ''
    frp_port = None
    if isinstance(state, dict):
        alloc_url = str(state.get('allocator_url') or '')
        frp_host = str(state.get('frp_server') or '')
        frp_port = coerce_port(state.get('frp_server_port'))
        report.display['client_endpoints'] = {
            'frp_public': '%s:%s' % (frp_host, frp_port or '?'),
            'allocator': alloc_url,
        }

    report.add(
        'mgmt_auth_ready',
        PASS if paths.is_file(key_p) and paths.is_file(mac_p) and paths.is_file(ca_path) and alloc_url.lower().startswith('https://') else WARN,
        'local prerequisites for management mutation',
        'identity/CA/HTTPS URL checked locally; no nonce was consumed',
        '',
        'security',
    )

    net = (facts.get('network') or {}).get('allocator_healthz')
    if net is None and not skip_network and alloc_url and ca_ok and paths.is_file(ca_path):
        net = https_healthz(alloc_url, paths.p(ca_path))
    if not alloc_url:
        report.add('allocator_health', NOT_APPLICABLE, 'no allocator URL configured', '', '', 'network')
    elif net is None:
        report.add('allocator_health', NOT_TESTED, 'allocator HTTPS was not tested', '', '', 'network')
    elif net.get('ok'):
        report.add('allocator_health', PASS, 'allocator GET /healthz succeeded with the trusted CA', net.get('detail') or '', '', 'network')
    else:
        cls = net.get('error_class') or 'unreachable'
        if cls in ('UNKNOWN_CA', 'HOSTNAME_MISMATCH', 'EXPIRED_CERT'):
            rec = {
                'UNKNOWN_CA': 'the local allocator-ca.crt does not match the server; re-enroll or copy the server CA fingerprint',
                'HOSTNAME_MISMATCH': 'allocator certificate hostname does not match the configured URL; re-run the server installer to reissue the server cert under the existing CA',
                'EXPIRED_CERT': 'allocator certificate is expired; re-run the server installer to reissue under the existing CA',
            }.get(cls, '')
            report.add('allocator_health', FAIL, 'allocator TLS validation failed (%s)' % cls, net.get('detail') or '', rec, 'network')
        elif cls in ('timeout', 'connection_refused', 'dns', 'unreachable'):
            report.add(
                'allocator_health', WARN,
                'allocator HTTPS is unreachable (%s)' % cls,
                net.get('detail') or '',
                'this is a network/reachability issue, not necessarily a corrupt client-state',
                'network',
            )
        else:
            report.add('allocator_health', WARN, 'allocator HTTPS check failed (%s)' % cls, net.get('detail') or '', '', 'network')

    tcp = (facts.get('network') or {}).get('frp_tcp')
    if tcp is None and not skip_network and frp_host and frp_port:
        ok, cls = tcp_reachable(frp_host, frp_port)
        tcp = {'ok': ok, 'error_class': None if ok else cls}
    if tcp is None:
        if frp_host:
            report.add('frp_control_reachability', NOT_TESTED, 'FRP control reachability was not tested', '', '', 'network')
    elif tcp.get('ok'):
        report.add('frp_control_reachability', PASS, 'FRP control public endpoint is reachable', '', '', 'network')
    else:
        report.add(
            'frp_control_reachability', WARN,
            'FRP control reachability %s' % (tcp.get('error_class') or 'failed'),
            '',
            'a firewall or dark-site network can cause this; it does not mean client-state is corrupt',
            'network',
        )


def render_human(report, quiet=False, verbose=False):
    counts = report.counts()
    overall = report.overall()
    overall_label = {
        'PASS': 'PASS',
        'PASS_WITH_WARNINGS': 'PASS WITH WARNINGS',
        'FAIL': 'FAIL',
        'ERROR': 'ERROR',
    }.get(overall, overall)
    lines = []
    if not quiet:
        lines.extend([
            'FRP Auto Deploy Doctor',
            '======================',
            '',
            'Host',
            '----',
            'Role            : %s' % report.role_label,
            'Confidence      : %s' % report.confidence,
            'Project version : %s' % (report.project_version or 'unknown'),
            'Release channel : %s' % (getattr(report, 'release_channel', None) or 'unknown'),
            'Source ref      : %s' % (getattr(report, 'source_ref', None) or 'unknown'),
            'FRP version     : %s' % (report.frp_version or report.pinned_frp),
            'Bundle SHA256   : %s' % (getattr(report, 'bundle_sha256', None) or 'unknown'),
            '',
        ])
        role_check = next((c for c in report.checks if c['id'] == 'host_role'), None)
        if role_check and role_check['status'] in (WARN, FAIL):
            lines.append('Status          : %s' % role_check['status'])
            lines.append('Reason          : %s' % role_check['message'])
            if role_check.get('detail'):
                lines.append('Detail          : %s' % role_check['detail'])
            lines.append('')

        endpoints = report.display.get('server_endpoints') or report.display.get('client_endpoints') or {}
        if report.display.get('server_endpoints'):
            ep = report.display['server_endpoints']
            lines.extend([
                'Installation / endpoints',
                '------------------------',
                'Deployment mode : %s' % (ep.get('deployment_mode') or 'direct'),
                'FRP control',
                '  Public endpoint : %s' % ep.get('frp_public'),
                '  Transport       : %s' % (ep.get('frp_transport') or 'tcp'),
                '  Local listener  : %s' % ep.get('frp_listen'),
                'Allocator',
                '  Public endpoint : %s' % ep.get('allocator_public'),
                '  Local listener  : %s' % ep.get('allocator_listen'),
                'Service range     : TCP/%s' % ep.get('service_range'),
                '',
            ])
        elif endpoints:
            lines.extend([
                'Installation / endpoints',
                '------------------------',
                'FRP server        : %s' % endpoints.get('frp_public'),
                'Allocator         : %s' % endpoints.get('allocator'),
                '',
            ])

        sections = [
            ('installation', 'Installation'),
            ('security', 'Security'),
            ('state', 'State'),
            ('runtime', 'Runtime'),
            ('network', 'Network'),
            ('host', 'Host facts'),
        ]
        for key, title in sections:
            items = [c for c in report.checks if c.get('section') == key]
            if not items:
                continue
            lines.append(title)
            lines.append('-' * len(title))
            for item in items:
                if not verbose and item['status'] in (PASS, INFO, NOT_APPLICABLE) and key == 'host':
                    if item['id'] in ('host_facts', 'distro_support', 'macos_support'):
                        lines.append('%-18s %s — %s' % (item['id'][:18], item['status'], item['message']))
                        continue
                if not verbose and item['status'] in (PASS, INFO) and key not in ('security', 'state', 'runtime', 'network', 'installation'):
                    continue
                msg = item['message']
                lines.append('%-18s %s — %s' % (item['id'][:18], item['status'], msg))
                if verbose and item.get('detail'):
                    for dline in str(item['detail']).splitlines():
                        lines.append('                     %s' % dline)
                if item['status'] in (FAIL, WARN) and item.get('recommendation') and not quiet:
                    rec = item['recommendation'].splitlines()[0]
                    lines.append('                     next: %s' % rec)
            lines.append('')

        pending = report.display.get('pending_apply') or report.display.get('pending_update')
        if pending:
            lines.extend([
                'Recovery',
                '--------',
                'Pending transaction  %s' % ('FAIL' if overall == 'FAIL' else 'WARN'),
                'Phase                %s' % pending.get('phase', 'unknown'),
            ])
            if pending.get('failure_class'):
                lines.append('Failure class        %s' % pending.get('failure_class'))
            lines.append('')

    lines.extend([
        'Summary',
        '-------',
        'PASS : %s' % counts[PASS],
        'WARN : %s' % counts[WARN],
        'FAIL : %s' % counts[FAIL],
        '',
        'Overall: %s' % overall_label,
        '',
    ])
    actions = report.recommended_actions()
    fail_actions = [c['recommendation'] for c in report.checks if c['status'] == FAIL and c.get('recommendation')]
    uniq = []
    seen = set()
    for rec in fail_actions:
        if rec in seen:
            continue
        seen.add(rec)
        uniq.append(rec)
    if uniq:
        lines.append('Recommended actions')
        lines.append('-------------------')
        for i, rec in enumerate(uniq[:8], 1):
            text = rec.replace('\n', '\n   ')
            lines.append('%s. %s' % (i, text))
        lines.append('')
    elif quiet and actions:
        lines.append('Recommended actions')
        lines.append('-------------------')
        for i, rec in enumerate(actions[:5], 1):
            lines.append('%s. %s' % (i, rec.replace('\n', '\n   ')))
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def render_json(report):
    counts = report.counts()
    payload = {
        'schema_version': REPORT_SCHEMA,
        'overall': report.overall(),
        'role': report.role,
        'role_label': report.role_label,
        'confidence': report.confidence,
        'project_version': report.project_version,
        'release_channel': getattr(report, 'release_channel', 'unknown'),
        'source_ref': getattr(report, 'source_ref', 'unknown'),
        'bundle_sha256': getattr(report, 'bundle_sha256', 'unknown'),
        'frp_version': report.frp_version,
        'summary': {
            'pass': counts[PASS],
            'warn': counts[WARN],
            'fail': counts[FAIL],
            'info': counts[INFO],
            'not_applicable': counts[NOT_APPLICABLE],
            'not_tested': counts[NOT_TESTED],
        },
        'checks': [
            {
                'id': c['id'],
                'status': c['status'],
                'message': c['message'],
                'detail': c.get('detail') or '',
                'recommendation': c.get('recommendation') or '',
            }
            for c in report.checks
        ],
        'recommended_actions': report.recommended_actions(),
    }
    if report.display.get('server_endpoints'):
        payload['endpoints'] = report.display['server_endpoints']
    if report.display.get('client_endpoints'):
        payload['endpoints'] = report.display['client_endpoints']
    return json.dumps(payload, indent=2, sort_keys=True) + '\n'


def run_doctor(root, facts, fmt='human', quiet=False, verbose=False, skip_network=False):
    paths = Paths(root)
    report = Report()
    report.facts = facts or {}
    facts = report.facts
    facts['verbose'] = verbose
    skip_network = skip_network or bool(facts.get('skip_network'))

    role_info = detect_role(paths)
    report.role = role_info['role']
    report.role_label = role_info['label']
    report.confidence = role_info['confidence']
    report.add(
        'host_role', role_info['status'],
        role_info['reason'],
        'server_signals=%s client_signals=%s' % (role_info['server_signals'], role_info['client_signals']),
        {
            'partial_client': 'complete the client install or run sudo frpctl update; do not re-enroll over a damaged identity',
            'partial_server': 're-run the server installer to complete missing components',
            'ambiguous': 'inspect leftover server and client files before taking further action',
            'uninstalled': 'install the server or client bootstrap first',
        }.get(report.role, ''),
        'host',
    )

    check_host_facts(report, facts)
    check_versions(report, paths, facts)
    check_pending(report, paths)
    check_backups_and_locks(report, paths, report.role)

    try:
        if report.role in ('server', 'dual', 'partial_server'):
            check_server(report, paths, facts, skip_network)
        if report.role in ('client', 'dual', 'partial_client'):
            check_client(report, paths, facts, skip_network)
    except Exception as exc:
        report.fatal = str(exc)
        report.add(
            'doctor_internal', FAIL,
            'doctor internal error',
            redact(traceback.format_exc() if verbose else str(exc)),
            '',
            'host',
        )

    if fmt == 'json':
        text = render_json(report)
    else:
        text = render_human(report, quiet=quiet, verbose=verbose)
    overall = report.overall()
    if overall == 'ERROR':
        code = 2
    elif overall == 'FAIL':
        code = 1
    else:
        code = 0
    return text, code, report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only FRP Auto Deploy doctor')
    parser.add_argument('--root', default='', help='test-root prefix; empty for live paths')
    parser.add_argument('--facts', default='', help='JSON facts from the shell wrapper')
    parser.add_argument('--format', choices=('human', 'json'), default='human')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--skip-network', action='store_true')
    parser.add_argument('--embedded-version', default='')
    parser.add_argument('--pinned-frp', default=PINNED_FRP_DEFAULT)
    args = parser.parse_args(argv)

    facts = {}
    if args.facts:
        if args.facts == '-':
            raw = sys.stdin.read()
            try:
                facts = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError as exc:
                sys.stderr.write('ERROR: doctor facts JSON is invalid: %s\n' % exc)
                return 2
        else:
            data, err = load_json_file(args.facts)
            if err:
                sys.stderr.write('ERROR: doctor facts file is %s\n' % err)
                return 2
            facts = data or {}
    if not isinstance(facts, dict):
        facts = {}
    if args.embedded_version:
        facts['embedded_version'] = args.embedded_version
    facts['pinned_frp'] = args.pinned_frp
    if args.skip_network:
        facts['skip_network'] = True
    try:
        text, code, _report = run_doctor(
            args.root, facts,
            fmt=args.format,
            quiet=args.quiet,
            verbose=args.verbose,
            skip_network=args.skip_network or bool(facts.get('skip_network')),
        )
    except Exception as exc:
        sys.stderr.write('ERROR: doctor internal error: %s\n' % redact(str(exc)))
        if args.verbose:
            traceback.print_exc()
        return 2
    sys.stdout.write(text)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
