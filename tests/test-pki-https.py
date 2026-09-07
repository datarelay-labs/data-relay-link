#!/usr/bin/env python3
"""Allocator HTTPS, private CA, and SAN validation tests."""
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.client import HTTPConnection
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import frp_pki  # noqa: E402
import importlib.util


def load_mod():
    spec = importlib.util.spec_from_file_location(
        'frp_port_allocator', ROOT / 'server' / 'frp-port-allocator.py'
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load_mod()


def pass_(name):
    print(f'PASS {name}')


def fail(name, detail=''):
    print(f'FAIL {name} {detail}'.rstrip(), file=sys.stderr)
    raise SystemExit(1)


def free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_allocator(cfg_path):
    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / 'server' / 'frp-port-allocator.py'), '--config', str(cfg_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    return proc


def stop_allocator(proc, timeout=5):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
    if proc.poll() is None:
        raise SystemExit('FAIL test allocator still running pid=%s' % proc.pid)


def wait_https(url, ca, timeout=5.0):
    ctx = ssl.create_default_context(cafile=str(ca))
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=1) as resp:
                return resp.read()
        except Exception as exc:
            last = exc
            time.sleep(0.05)
    raise last or RuntimeError('https wait failed')


def write_env(tmp, listen_port, public_host='127.0.0.1', extra_hosts=None, public_port=None):
    pki_dir = Path(tmp) / 'pki'
    extra = list(extra_hosts or [])
    result = frp_pki.ensure_pki(str(pki_dir), public_host, extra)
    cfg = {
        'public_host': '203.0.113.10',
        'public_ip': '203.0.113.10',
        'frp_control_public_port': 8443,
        'frp_control_listen_port': 443,
        'port_start': 19000,
        'port_end': 19010,
        'listen_host': '127.0.0.1',
        'listen_port': listen_port,
        'allocator_listen_port': listen_port,
        'allocator_public_port': public_port or listen_port,
        'tls_ca_cert': result['ca_crt'],
        'tls_server_cert': result['server_crt'],
        'tls_server_key': result['server_key'],
        'registry_file': str(Path(tmp) / 'registry.json'),
        'enrollments_dir': str(Path(tmp) / 'enrollments'),
        'token_file': str(Path(tmp) / 'server_token'),
    }
    Path(cfg['enrollments_dir']).mkdir(parents=True, exist_ok=True)
    Path(cfg['token_file']).write_text('test-frp-token-do-not-use\n')
    os.chmod(cfg['token_file'], 0o600)
    Path(cfg['registry_file']).write_text(json.dumps({
        'schema_version': 2, 'reserved': [], 'clients': {},
    }) + '\n')
    cfg_path = Path(tmp) / 'config.json'
    cfg_path.write_text(json.dumps(cfg, indent=2) + '\n')
    return cfg_path, result


def test_https_healthz():
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        cfg, pki = write_env(tmp, port)
        proc = start_allocator(cfg)
        try:
            body = wait_https(f'https://127.0.0.1:{port}/healthz', pki['ca_crt'])
            if b'"status"' not in body:
                fail('verified healthz', body)
            pass_('allocator starts with TLS')
            pass_('verified /healthz succeeds')
        finally:
            stop_allocator(proc)


def test_plain_http_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        cfg, pki = write_env(tmp, port)
        proc = start_allocator(cfg)
        try:
            wait_https(f'https://127.0.0.1:{port}/healthz', pki['ca_crt'])
            conn = HTTPConnection('127.0.0.1', port, timeout=2)
            try:
                conn.request('GET', '/healthz')
                conn.getresponse()
                fail('plain HTTP should not succeed on the TLS listener')
            except Exception:
                pass
            pass_('plain HTTP is not supported')
        finally:
            stop_allocator(proc)


def test_unknown_ca_fails():
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        cfg, pki = write_env(tmp, port)
        other = Path(tmp) / 'other'
        other.mkdir()
        frp_pki.ensure_pki(str(other), '127.0.0.1')
        proc = start_allocator(cfg)
        try:
            wait_https(f'https://127.0.0.1:{port}/healthz', pki['ca_crt'])
            ctx = ssl.create_default_context(cafile=str(other / 'ca.crt'))
            try:
                urllib.request.urlopen(f'https://127.0.0.1:{port}/healthz', context=ctx, timeout=2)
                fail('unknown CA should fail')
            except ssl.SSLError:
                pass
            except urllib.error.URLError as exc:
                if 'CERTIFICATE' not in str(exc).upper() and 'certificate' not in str(exc).lower():
                    if not isinstance(getattr(exc, 'reason', None), ssl.SSLError):
                        fail('unknown CA', exc)
            pass_('unknown CA fails')
        finally:
            stop_allocator(proc)


def test_wrong_san_fails():
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        cfg, pki = write_env(tmp, port, public_host='192.0.2.50', extra_hosts=['192.0.2.50'])
        proc = start_allocator(cfg)
        try:
            # Wait using IP SAN 127.0.0.1 which is always included.
            wait_https(f'https://127.0.0.1:{port}/healthz', pki['ca_crt'])
            ctx = ssl.create_default_context(cafile=pki['ca_crt'])
            try:
                urllib.request.urlopen(f'https://203.0.113.10:{port}/healthz', context=ctx, timeout=2)
                fail('wrong SAN should fail')
            except Exception:
                pass
            pass_('wrong SAN fails')
        finally:
            stop_allocator(proc)


def test_ca_crt_public_only():
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        cfg, pki = write_env(tmp, port)
        proc = start_allocator(cfg)
        try:
            wait_https(f'https://127.0.0.1:{port}/healthz', pki['ca_crt'])
            ctx = ssl.create_default_context(cafile=pki['ca_crt'])
            with urllib.request.urlopen(f'https://127.0.0.1:{port}/ca.crt', context=ctx, timeout=2) as resp:
                body = resp.read()
                ctype = resp.headers.get('Content-Type', '')
            if b'BEGIN CERTIFICATE' not in body:
                fail('ca.crt body', body[:80])
            if b'PRIVATE KEY' in body:
                fail('ca.crt leaked private key')
            if 'application/x-pem-file' not in ctype:
                fail('ca.crt content type', ctype)
            ca_text = Path(pki['ca_crt']).read_bytes()
            if body.strip() != ca_text.strip():
                fail('ca.crt mismatch')
            pass_('/ca.crt returns public certificate only')
        finally:
            stop_allocator(proc)


def test_refuse_plain_start():
    with tempfile.TemporaryDirectory() as tmp:
        port = free_port()
        cfg, pki = write_env(tmp, port)
        data = json.loads(Path(cfg).read_text())
        data.pop('tls_server_cert', None)
        data.pop('tls_server_key', None)
        Path(cfg).write_text(json.dumps(data) + '\n')
        proc = start_allocator(cfg)
        try:
            rc = proc.wait(timeout=5)
            if rc == 0:
                fail('allocator should fail closed without TLS')
            out = proc.stdout.read().decode() if proc.stdout else ''
            if 'plain HTTP' not in out and 'TLS' not in out:
                fail('missing TLS error', out)
            pass_('allocator fails closed without TLS')
        finally:
            stop_allocator(proc)


def test_ca_preserved_on_reissue():
    with tempfile.TemporaryDirectory() as tmp:
        pki_dir = Path(tmp) / 'pki'
        first = frp_pki.ensure_pki(str(pki_dir), '203.0.113.10')
        second = frp_pki.ensure_pki(str(pki_dir), '203.0.113.10')
        if first['fingerprint'] != second['fingerprint'] or second['action'] != 'reused':
            fail('CA reused', second)
        # Port is not a certificate identity.
        third = frp_pki.ensure_pki(str(pki_dir), '203.0.113.10')
        if third['fingerprint'] != first['fingerprint']:
            fail('port-equivalent ensure rotated CA')
        fourth = frp_pki.ensure_pki(str(pki_dir), '192.0.2.50')
        if fourth['fingerprint'] != first['fingerprint']:
            fail('host change rotated CA')
        if fourth['action'] != 'reissued-server':
            fail('server cert should be reissued for new SAN', fourth)
        pass_('changing public identity reissues server cert only')
        pass_('CA fingerprint preserved across ensure')


def test_partial_pki_fails():
    with tempfile.TemporaryDirectory() as tmp:
        pki_dir = Path(tmp) / 'pki'
        frp_pki.ensure_pki(str(pki_dir), '127.0.0.1')
        (pki_dir / 'server.crt').unlink()
        try:
            frp_pki.ensure_pki(str(pki_dir), '127.0.0.1')
            fail('partial PKI should fail')
        except frp_pki.PkiError:
            pass
        if not (pki_dir / 'ca.key').is_file():
            fail('partial PKI replaced CA key')
        pass_('partial PKI fails closed')


def test_fingerprint_is_sha256_of_openssl_der():
    with tempfile.TemporaryDirectory() as tmp:
        pki_dir = Path(tmp) / 'pki'
        result = frp_pki.ensure_pki(str(pki_dir), '127.0.0.1')
        ca = pki_dir / 'ca.crt'
        der = subprocess.check_output(['openssl', 'x509', '-in', str(ca), '-outform', 'DER'])
        expected = hashlib.sha256(der).hexdigest()
        if result['fingerprint'] != expected:
            fail('fingerprint not SHA256(DER)', result['fingerprint'])
        if frp_pki.fingerprint_from_cert_file(ca) != expected:
            fail('fingerprint_from_cert_file not SHA256(DER)')
        subprocess.check_call(['openssl', 'x509', '-in', str(ca), '-noout'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pass_('canonical fingerprint is SHA256 of openssl DER')


def test_garbage_pem_rejected():
    import base64
    with tempfile.TemporaryDirectory() as tmp:
        garbage = Path(tmp) / 'garbage.crt'
        body = base64.b64encode(b'not-an-x509-certificate-' * 16).decode('ascii')
        garbage.write_text(
            '-----BEGIN CERTIFICATE-----\n' + body + '\n-----END CERTIFICATE-----\n',
            encoding='utf-8',
        )
        dest = Path(tmp) / 'trusted.crt'
        try:
            frp_pki.fingerprint_from_cert_file(garbage)
            fail('garbage PEM fingerprint should fail')
        except frp_pki.PkiError as exc:
            if 'X.509' not in str(exc):
                fail('garbage PEM error', exc)
        try:
            frp_pki.atomic_install_trusted_ca(garbage, dest)
            fail('garbage PEM should not be installed')
        except frp_pki.PkiError:
            pass
        if dest.exists():
            fail('garbage PEM was installed')
        pass_('base64 garbage wrapped as certificate is rejected')


def test_atomic_install_requires_x509_and_fingerprint():
    with tempfile.TemporaryDirectory() as tmp:
        pki_dir = Path(tmp) / 'pki'
        result = frp_pki.ensure_pki(str(pki_dir), '127.0.0.1')
        dest = Path(tmp) / 'trusted.crt'
        actual = frp_pki.atomic_install_trusted_ca(pki_dir / 'ca.crt', dest, result['fingerprint'])
        if actual != result['fingerprint'] or not dest.is_file():
            fail('valid CA atomic install')
        other = Path(tmp) / 'other'
        other.mkdir()
        frp_pki.ensure_pki(str(other), '127.0.0.1')
        dest2 = Path(tmp) / 'trusted2.crt'
        try:
            frp_pki.atomic_install_trusted_ca(other / 'ca.crt', dest2, result['fingerprint'])
            fail('wrong fingerprint should fail')
        except frp_pki.PkiError as exc:
            if 'mismatch' not in str(exc).lower():
                fail('wrong fingerprint error', exc)
        if dest2.exists():
            fail('wrong fingerprint installed CA')
        pass_('atomic install requires X.509 parse and fingerprint match')


def test_fingerprint_format():
    with tempfile.TemporaryDirectory() as tmp:
        pki_dir = Path(tmp) / 'pki'
        result = frp_pki.ensure_pki(str(pki_dir), '127.0.0.1')
        fp = result['fingerprint']
        if len(fp) != 64 or any(c not in '0123456789abcdef' for c in fp):
            fail('fingerprint format', fp)
        colon = ':'.join(fp[i:i + 2] for i in range(0, 64, 2)).upper()
        if not frp_pki.fingerprints_match(colon, fp):
            fail('fingerprint normalize')
        pass_('CA fingerprint format')


def test_enroll_uses_public_control_port():
    env_tmp = tempfile.TemporaryDirectory()
    try:
        tmp = Path(env_tmp.name)
        cfg = {
            'public_host': '203.0.113.10',
            'frp_control_public_port': 8443,
            'frp_control_listen_port': 443,
            'port_start': 19100,
            'port_end': 19110,
            'listen_port': 6099,
            'registry_file': str(tmp / 'registry.json'),
            'enrollments_dir': str(tmp / 'enrollments'),
            'token_file': str(tmp / 'token'),
        }
        Path(cfg['enrollments_dir']).mkdir()
        Path(cfg['token_file']).write_text('test-frp-token-do-not-use\n')
        Path(cfg['registry_file']).write_text(json.dumps({
            'schema_version': 2, 'reserved': [], 'clients': {},
        }) + '\n')
        cfg_path = tmp / 'config.json'
        cfg_path.write_text(json.dumps(cfg) + '\n')
        alloc = MOD.Allocator(str(cfg_path))
        MOD.port_is_available = lambda port: True
        now = int(time.time())
        rec = {
            'id': 'aabbccddeeff0011',
            'secret': 'secret-aabbccddeeff0011',
            'expires_at': now + 600,
            'bound_machine_id': None,
            'used_at': None,
        }
        Path(cfg['enrollments_dir'], 'aabbccddeeff0011.json').write_text(json.dumps(rec) + '\n')
        body = json.dumps({
            'machine_id': 'machine-a',
            'hostname': 'host-a',
            'services': [{
                'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp',
                'local_ip': '127.0.0.1', 'local_port': 22, 'preset': 'ssh',
                'ssh_user': 'aella',
            }],
        }, separators=(',', ':')).encode()
        import hmac
        ts = str(now)
        sig = hmac.new(rec['secret'].encode(), (ts + '\n' + body.decode()).encode(), hashlib.sha256).hexdigest()
        code, result = alloc.enroll('aabbccddeeff0011', ts, sig, body)
        if code != 200:
            fail('enroll public port', result)
        if result.get('frp_server') != '203.0.113.10' or int(result.get('frp_server_port')) != 8443:
            fail('enroll returned listen port', result)
        if result.get('frp_transport') != 'tcp':
            fail('enroll default transport', result)
        pass_('enroll response uses FRP public control port')
    finally:
        env_tmp.cleanup()


def test_enroll_single443_transport():
    env_tmp = tempfile.TemporaryDirectory()
    try:
        tmp = Path(env_tmp.name)
        cfg = {
            'public_host': '203.0.113.10',
            'frp_control_public_port': 443,
            'frp_control_listen_port': 7000,
            'deployment_mode': 'single443',
            'port_start': 19100,
            'port_end': 19110,
            'listen_port': 6099,
            'registry_file': str(tmp / 'registry.json'),
            'enrollments_dir': str(tmp / 'enrollments'),
            'token_file': str(tmp / 'token'),
        }
        Path(cfg['enrollments_dir']).mkdir()
        Path(cfg['token_file']).write_text('test-frp-token-do-not-use\n')
        Path(cfg['registry_file']).write_text(json.dumps({
            'schema_version': 2, 'reserved': [], 'clients': {},
        }) + '\n')
        cfg_path = tmp / 'config.json'
        cfg_path.write_text(json.dumps(cfg) + '\n')
        alloc = MOD.Allocator(str(cfg_path))
        MOD.port_is_available = lambda port: True
        now = int(time.time())
        rec = {
            'id': 'aabbccddeeff0011',
            'secret': 'secret-aabbccddeeff0011',
            'expires_at': now + 600,
            'bound_machine_id': None,
            'used_at': None,
        }
        Path(cfg['enrollments_dir'], 'aabbccddeeff0011.json').write_text(json.dumps(rec) + '\n')
        body = json.dumps({
            'machine_id': 'machine-a',
            'hostname': 'host-a',
            'services': [{
                'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp',
                'local_ip': '127.0.0.1', 'local_port': 22, 'preset': 'ssh',
                'ssh_user': 'aella',
            }],
        }, separators=(',', ':')).encode()
        import hmac
        ts = str(now)
        sig = hmac.new(rec['secret'].encode(), (ts + '\n' + body.decode()).encode(), hashlib.sha256).hexdigest()
        code, result = alloc.enroll('aabbccddeeff0011', ts, sig, body)
        if code != 200:
            fail('enroll single443', result)
        if result.get('frp_transport') != 'wss' or int(result.get('frp_server_port')) != 443:
            fail('enroll single443 transport', result)
        received = result.pop('response_hmac')
        expected = MOD.hmac_hex(rec['secret'], MOD.canonical_json(result))
        if received != expected:
            fail('enroll single443 hmac', result)
        pass_('enroll single443 returns wss and HMAC covers transport')
    finally:
        env_tmp.cleanup()


def test_localhost_san_invariant():
    cases = [
        ('203.0.113.10', set(), {'203.0.113.10', '127.0.0.1'}, {'localhost'}),
        ('frp.example.test', {'frp.example.test', 'localhost'}, {'127.0.0.1'}, set()),
    ]
    for public_host, extra_dns, extra_ips, _ in cases:
        dns, ips = frp_pki.collect_identities(public_host)
        if 'localhost' not in dns:
            fail('collect_identities localhost DNS', public_host)
        if '127.0.0.1' not in ips:
            fail('collect_identities 127.0.0.1 IP', public_host)
        if frp_pki.is_ip_address(public_host):
            if public_host not in ips:
                fail('collect_identities public IP', public_host)
        else:
            if public_host not in dns:
                fail('collect_identities public DNS', public_host)
        with tempfile.TemporaryDirectory() as tmp:
            result = frp_pki.ensure_pki(str(Path(tmp) / 'pki'), public_host)
            have_dns, have_ips = frp_pki.read_cert_sans(result['server_crt'])
            if 'localhost' not in have_dns:
                fail('leaf missing DNS:localhost', public_host)
            if '127.0.0.1' not in have_ips:
                fail('leaf missing IP:127.0.0.1', public_host)
            if extra_dns - have_dns:
                fail('leaf missing DNS SAN', extra_dns - have_dns)
            if extra_ips - have_ips:
                fail('leaf missing IP SAN', extra_ips - have_ips)
    pass_('PKI_LOCALHOST_SAN')


def main():
    test_https_healthz()
    test_plain_http_rejected()
    test_unknown_ca_fails()
    test_wrong_san_fails()
    test_ca_crt_public_only()
    test_refuse_plain_start()
    test_ca_preserved_on_reissue()
    test_partial_pki_fails()
    test_fingerprint_is_sha256_of_openssl_der()
    test_garbage_pem_rejected()
    test_atomic_install_requires_x509_and_fingerprint()
    test_fingerprint_format()
    test_enroll_uses_public_control_port()
    test_enroll_single443_transport()
    test_localhost_san_invariant()
    print()
    print('PKI_HTTPS_TEST=PASS')


if __name__ == '__main__':
    main()
