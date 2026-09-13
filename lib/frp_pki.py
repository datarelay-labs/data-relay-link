#!/usr/bin/env python3
"""Lightweight persistent private CA for allocator HTTPS.

OpenSSL 1.0.2 compatible: SANs are written through a temporary openssl.cnf,
never via `openssl req -addext`.
"""
import sys
if sys.version_info < (3, 7):
    sys.stderr.write('ERROR: python 3.7 or newer is required\n')
    raise SystemExit(1)

import argparse
import hashlib
import ipaddress
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

CA_DAYS = 3650
SERVER_DAYS = 3650
RSA_BITS = 2048
HEX64_RE = re.compile(r'^[0-9a-f]{64}$')


class PkiError(Exception):
    pass


def _run(args, **kwargs):
    try:
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            universal_newlines=True,
            **kwargs,
        )
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or exc.stdout or '').strip()
        raise PkiError(err or 'openssl command failed') from exc
    except FileNotFoundError as exc:
        raise PkiError('openssl is required to manage allocator TLS certificates') from exc


def openssl_bin():
    path = shutil.which('openssl')
    if not path:
        raise PkiError('openssl is required to manage allocator TLS certificates')
    return path


def is_ip_address(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _run_bin(args):
    try:
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or exc.stdout or b'').decode('utf-8', 'replace').strip()
        raise PkiError(err or 'openssl command failed') from exc
    except FileNotFoundError as exc:
        raise PkiError('openssl is required to manage allocator TLS certificates') from exc


def validate_x509_cert(path, downloaded=False):
    openssl = openssl_bin()
    try:
        _run([openssl, 'x509', '-in', str(path), '-noout'])
    except PkiError as exc:
        if downloaded:
            raise PkiError('downloaded allocator CA is not a valid X.509 certificate') from exc
        raise PkiError('allocator CA is not a valid X.509 certificate') from exc


def der_from_cert_file(path, downloaded=False):
    validate_x509_cert(path, downloaded=downloaded)
    openssl = openssl_bin()
    try:
        proc = _run_bin([openssl, 'x509', '-in', str(path), '-outform', 'DER'])
    except PkiError as exc:
        if downloaded:
            raise PkiError('downloaded allocator CA is not a valid X.509 certificate') from exc
        raise PkiError('allocator CA is not a valid X.509 certificate') from exc
    if not proc.stdout:
        if downloaded:
            raise PkiError('downloaded allocator CA is not a valid X.509 certificate')
        raise PkiError('allocator CA is not a valid X.509 certificate')
    return proc.stdout


def fingerprint_from_der(der):
    return hashlib.sha256(der).hexdigest()


def fingerprint_from_cert_file(path, downloaded=False):
    return fingerprint_from_der(der_from_cert_file(path, downloaded=downloaded))


def normalize_fingerprint(value):
    text = str(value or '')
    # Strip separators without locale-sensitive case folding beyond ASCII hex.
    cleaned = []
    for ch in text:
        o = ord(ch)
        if 48 <= o <= 57:  # 0-9
            cleaned.append(ch)
        elif 65 <= o <= 70:  # A-F
            cleaned.append(chr(o + 32))
        elif 97 <= o <= 102:  # a-f
            cleaned.append(ch)
    hexstr = ''.join(cleaned)
    if not HEX64_RE.fullmatch(hexstr):
        raise PkiError('invalid CA fingerprint: expected 64 hexadecimal characters')
    return hexstr


def fingerprints_match(left, right):
    try:
        return normalize_fingerprint(left) == normalize_fingerprint(right)
    except PkiError:
        return False


def parse_https_url_host(url):
    text = str(url or '').strip()
    if not text.lower().startswith('https://'):
        raise PkiError('allocator public URL must be HTTPS')
    rest = text[8:]
    if '/' in rest:
        rest = rest.split('/', 1)[0]
    if rest.startswith('['):
        end = rest.find(']')
        if end < 0:
            raise PkiError('invalid allocator public URL host')
        return rest[1:end]
    if ':' in rest:
        host, _port = rest.rsplit(':', 1)
        return host
    return rest


def format_https_url(host, port, path='/enroll'):
    host = str(host).strip()
    port = int(port)
    if is_ip_address(host) and ':' in host:
        host = '[' + host + ']'
    if port == 443:
        return 'https://%s%s' % (host, path)
    return 'https://%s:%s%s' % (host, port, path)


def _write_mode(path, data, mode):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as handle:
            if isinstance(data, str):
                data = data.encode('utf-8')
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def pki_paths(pki_dir):
    root = Path(pki_dir)
    return {
        'dir': root,
        'ca_key': root / 'ca.key',
        'ca_crt': root / 'ca.crt',
        'server_key': root / 'server.key',
        'server_crt': root / 'server.crt',
        'serial': root / 'ca.srl',
    }


def _expected_files(paths):
    return (paths['ca_key'], paths['ca_crt'], paths['server_key'], paths['server_crt'])


def classify_pki_state(paths):
    present = [p.is_file() and p.stat().st_size > 0 for p in _expected_files(paths)]
    if all(present):
        return 'complete'
    if not any(present):
        return 'absent'
    return 'partial'


def apply_pki_permissions(paths):
    paths['dir'].mkdir(parents=True, exist_ok=True)
    os.chmod(str(paths['dir']), 0o700)
    if os.geteuid() == 0:
        os.chown(str(paths['dir']), 0, 0)
    mapping = (
        (paths['ca_key'], 0o600),
        (paths['ca_crt'], 0o644),
        (paths['server_key'], 0o600),
        (paths['server_crt'], 0o644),
    )
    for path, mode in mapping:
        if path.is_file():
            os.chmod(str(path), mode)
            if os.geteuid() == 0:
                os.chown(str(path), 0, 0)


def collect_identities(public_host, extra_hosts=None):
    hosts = []
    for item in [public_host] + list(extra_hosts or []):
        value = str(item or '').strip()
        if not value:
            continue
        if value not in hosts:
            hosts.append(value)
    for extra in ('localhost', '127.0.0.1'):
        if extra not in hosts:
            hosts.append(extra)
    # DNS:localhost is the internal trust identity used by the single-443
    # nginx frontend (proxy_ssl_name localhost). It is not a public option.
    dns = []
    ips = []
    for host in hosts:
        if is_ip_address(host):
            if host not in ips:
                ips.append(host)
        else:
            if host not in dns:
                dns.append(host)
    if not dns and not ips:
        raise PkiError('no identities available for the allocator certificate SAN')
    return dns, ips


def write_openssl_config(path, dns, ips, ca=False):
    lines = [
        '[req]',
        'distinguished_name = req_dn',
        'prompt = no',
        'x509_extensions = v3_ca' if ca else 'req_extensions = v3_server',
        '',
        '[req_dn]',
        'CN = Data Relay Link CA' if ca else 'CN = Data Relay Link allocator',
        '',
        '[v3_ca]',
        'basicConstraints = critical,CA:TRUE',
        'keyUsage = critical,keyCertSign,cRLSign',
        'subjectKeyIdentifier = hash',
        '',
        '[v3_server]',
        'basicConstraints = CA:FALSE',
        'keyUsage = critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage = serverAuth',
        'subjectAltName = @alt_names',
        '',
        '[alt_names]',
    ]
    for idx, name in enumerate(dns, start=1):
        lines.append('DNS.%s = %s' % (idx, name))
    for idx, addr in enumerate(ips, start=1):
        lines.append('IP.%s = %s' % (idx, addr))
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')


def read_cert_sans(cert_path):
    openssl = openssl_bin()
    proc = _run([openssl, 'x509', '-in', str(cert_path), '-noout', '-text'])
    text = proc.stdout
    dns = set()
    ips = set()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if 'Subject Alternative Name' not in line:
            continue
        blob = []
        for follow in lines[i + 1:]:
            stripped = follow.strip()
            if not stripped:
                continue
            # SAN values are on the immediately following indented line(s).
            # Stop at the next X.509 field rather than slurping the rest of -text.
            if stripped.startswith('X509') or stripped.startswith('Signature'):
                break
            if not follow.startswith(' '):
                break
            blob.append(stripped)
            # One SAN line is enough on OpenSSL 1.0.2 and 3.x.
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


def cert_covers_identities(cert_path, dns, ips):
    have_dns, have_ips = read_cert_sans(cert_path)
    return set(dns).issubset(have_dns) and set(ips).issubset(have_ips)


def verify_cert_signed_by_ca(ca_crt, server_crt):
    openssl = openssl_bin()
    try:
        _run([openssl, 'verify', '-CAfile', str(ca_crt), str(server_crt)])
    except PkiError as exc:
        raise PkiError('server certificate is not signed by the local CA') from exc


def _genrsa(path):
    openssl = openssl_bin()
    _run([openssl, 'genrsa', '-out', str(path), str(RSA_BITS)])
    os.chmod(str(path), 0o600)


def generate_ca(paths, workdir):
    openssl = openssl_bin()
    cfg = Path(workdir) / 'ca.cnf'
    write_openssl_config(cfg, ['Data Relay Link CA'], [], ca=True)
    _genrsa(paths['ca_key'])
    _run([
        openssl, 'req', '-new', '-x509',
        '-days', str(CA_DAYS),
        '-key', str(paths['ca_key']),
        '-out', str(paths['ca_crt']),
        '-config', str(cfg),
        '-extensions', 'v3_ca',
    ])
    os.chmod(str(paths['ca_crt']), 0o644)


def issue_server_cert(paths, dns, ips, workdir):
    openssl = openssl_bin()
    cfg = Path(workdir) / 'server.cnf'
    write_openssl_config(cfg, dns, ips, ca=False)
    if not paths['server_key'].is_file():
        _genrsa(paths['server_key'])
    csr = Path(workdir) / 'server.csr'
    _run([
        openssl, 'req', '-new',
        '-key', str(paths['server_key']),
        '-out', str(csr),
        '-config', str(cfg),
    ])
    cmd = [
        openssl, 'x509', '-req',
        '-in', str(csr),
        '-CA', str(paths['ca_crt']),
        '-CAkey', str(paths['ca_key']),
        '-out', str(paths['server_crt']),
        '-days', str(SERVER_DAYS),
        '-extfile', str(cfg),
        '-extensions', 'v3_server',
    ]
    if paths['serial'].is_file():
        cmd.extend(['-CAserial', str(paths['serial'])])
    else:
        cmd.append('-CAcreateserial')
        cmd.extend(['-CAserial', str(paths['serial'])])
    _run(cmd)
    os.chmod(str(paths['server_crt']), 0o644)
    os.chmod(str(paths['server_key']), 0o600)


def validate_existing_materials(paths):
    openssl = openssl_bin()
    try:
        _run([openssl, 'x509', '-in', str(paths['ca_crt']), '-noout'])
        _run([openssl, 'rsa', '-in', str(paths['ca_key']), '-check', '-noout'])
        _run([openssl, 'x509', '-in', str(paths['server_crt']), '-noout'])
        _run([openssl, 'rsa', '-in', str(paths['server_key']), '-check', '-noout'])
    except PkiError as exc:
        raise PkiError(
            'allocator PKI is incomplete or corrupted; refusing to replace the CA. '
            'Restore the existing files under %s or remove all of them to generate a new CA.'
            % paths['dir']
        ) from exc
    verify_cert_signed_by_ca(paths['ca_crt'], paths['server_crt'])


def ensure_pki(pki_dir, public_host, extra_hosts=None):
    paths = pki_paths(pki_dir)
    paths['dir'].mkdir(parents=True, exist_ok=True)
    os.chmod(str(paths['dir']), 0o700)
    state = classify_pki_state(paths)
    if state == 'partial':
        raise PkiError(
            'allocator PKI is incomplete or corrupted; refusing to replace the CA. '
            'Expected ca.key, ca.crt, server.key, and server.crt in %s.'
            % paths['dir']
        )
    dns, ips = collect_identities(public_host, extra_hosts)
    workdir = tempfile.mkdtemp(prefix='frp-pki.')
    try:
        if state == 'absent':
            generate_ca(paths, workdir)
            issue_server_cert(paths, dns, ips, workdir)
            action = 'generated'
        else:
            validate_existing_materials(paths)
            if cert_covers_identities(paths['server_crt'], dns, ips):
                action = 'reused'
            else:
                issue_server_cert(paths, dns, ips, workdir)
                action = 'reissued-server'
        apply_pki_permissions(paths)
        fingerprint = fingerprint_from_cert_file(paths['ca_crt'])
        return {
            'action': action,
            'fingerprint': fingerprint,
            'ca_crt': str(paths['ca_crt']),
            'ca_key': str(paths['ca_key']),
            'server_crt': str(paths['server_crt']),
            'server_key': str(paths['server_key']),
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def atomic_install_trusted_ca(src_pem_path, dest_path, expected_fingerprint=None, downloaded=False):
    dest = Path(dest_path)
    actual = fingerprint_from_cert_file(src_pem_path, downloaded=downloaded)
    if expected_fingerprint is not None:
        wanted = normalize_fingerprint(expected_fingerprint)
        if actual != wanted:
            raise PkiError('CA fingerprint mismatch')
    pem = Path(src_pem_path).read_bytes()
    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_mode(dest, pem if pem.endswith(b'\n') else pem + b'\n', 0o644)
    if os.geteuid() == 0:
        os.chown(str(dest), 0, 0)
        os.chmod(str(dest.parent), stat.S_IMODE(dest.parent.stat().st_mode))
    return actual


def main(argv=None):
    parser = argparse.ArgumentParser(description='Data Relay Link allocator PKI')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_ensure = sub.add_parser('ensure')
    p_ensure.add_argument('--pki-dir', required=True)
    p_ensure.add_argument('--public-host', required=True)
    p_ensure.add_argument('--url-host', default='')
    p_ensure.add_argument('--extra-host', action='append', default=[])

    p_fp = sub.add_parser('fingerprint')
    p_fp.add_argument('--cert', required=True)

    p_norm = sub.add_parser('normalize-fingerprint')
    p_norm.add_argument('value')

    args = parser.parse_args(argv)
    try:
        if args.cmd == 'ensure':
            extra = list(args.extra_host or [])
            if args.url_host:
                extra.append(args.url_host)
            result = ensure_pki(args.pki_dir, args.public_host, extra)
            sys.stdout.write('PKI_ACTION=%s\n' % result['action'])
            sys.stdout.write('CA_FINGERPRINT=%s\n' % result['fingerprint'])
            sys.stdout.write('TLS_CA_CERT=%s\n' % result['ca_crt'])
            sys.stdout.write('TLS_SERVER_CERT=%s\n' % result['server_crt'])
            sys.stdout.write('TLS_SERVER_KEY=%s\n' % result['server_key'])
            return 0
        if args.cmd == 'fingerprint':
            sys.stdout.write(fingerprint_from_cert_file(args.cert) + '\n')
            return 0
        if args.cmd == 'normalize-fingerprint':
            sys.stdout.write(normalize_fingerprint(args.value) + '\n')
            return 0
    except PkiError as exc:
        sys.stderr.write('ERROR: %s\n' % exc)
        return 1
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
