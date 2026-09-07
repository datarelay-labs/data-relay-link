#!/usr/bin/env python3
"""Single-443 frontend backend identity, CA endpoint, and doctor e2e facts."""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import frp_doctor  # noqa: E402
import frp_frontend  # noqa: E402
import frp_pki  # noqa: E402


def pass_(name):
    print('PASS %s' % name)


def fail(name, detail=''):
    print('FAIL %s %s' % (name, detail), file=sys.stderr)
    raise SystemExit(1)


def free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def nginx_bin():
    for cand in (os.environ.get('FRP_NGINX_BIN'), '/usr/sbin/nginx', shutil.which('nginx')):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def render_conf(tmp, public_host, frontend_port, alloc_port, pki, control_port=7000):
    dest = Path(tmp) / ('frontend-%s.conf' % public_host.replace('.', '_'))
    frp_frontend.write_nginx_conf(
        str(dest),
        public_host=public_host,
        frontend_port=frontend_port,
        allocator_listen_port=alloc_port,
        control_listen_port=control_port,
        ca_cert=pki['ca_crt'],
        server_cert=pki['server_crt'],
        server_key=pki['server_key'],
        pid_path=str(Path(tmp) / 'nginx.pid'),
        error_log=str(Path(tmp) / 'frontend.error.log'),
        temp_root=str(Path(tmp) / 'nginx-temp'),
    )
    return dest.read_text(encoding='utf-8'), dest


def test_backend_identity_ip_and_dns():
    with tempfile.TemporaryDirectory() as tmp:
        pki = frp_pki.ensure_pki(str(Path(tmp) / 'pki-ip'), '203.0.113.10')
        conf, _ = render_conf(tmp, '203.0.113.10', 443, 6099, pki)
        if 'proxy_pass https://127.0.0.1:6099;' not in conf:
            fail('proxy_pass loopback', conf)
        if 'proxy_ssl_verify on;' not in conf:
            fail('proxy_ssl_verify on')
        if 'proxy_ssl_name localhost;' not in conf:
            fail('proxy_ssl_name localhost')
        if 'proxy_ssl_server_name on;' not in conf:
            fail('proxy_ssl_server_name')
        if 'proxy_ssl_name 203.0.113.10;' in conf:
            fail('proxy_ssl_name used public IP')
        if 'proxy_ssl_verify off' in conf:
            fail('proxy_ssl_verify disabled')
        if 'proxy_set_header X-Forwarded-For $remote_addr;' not in conf:
            fail('missing trusted X-Forwarded-For from $remote_addr')
        if 'location = "/~!frp"' not in conf:
            fail('WSS path')
        if 'ca\\.crt|healthz|enroll|bootstrap/redeem|i/[^/?#]+' not in conf:
            fail('allocator allowlist')
        pass_('NGINX_BACKEND_DNS_IDENTITY')
        pass_('NGINX_NO_PUBLIC_IP_PROXY_SSL_NAME')
        pass_('NGINX_BACKEND_VERIFY_ON')

        pki_dns = frp_pki.ensure_pki(str(Path(tmp) / 'pki-dns'), 'frp.example.test')
        conf_dns, _ = render_conf(tmp, 'frp.example.test', 443, 6099, pki_dns)
        if 'server_name frp.example.test;' not in conf_dns:
            fail('server_name public DNS')
        if 'proxy_ssl_name localhost;' not in conf_dns:
            fail('DNS public host backend identity')
        if 'proxy_ssl_name frp.example.test;' in conf_dns:
            fail('proxy_ssl_name used public DNS')
        have_dns, have_ips = frp_pki.read_cert_sans(pki['server_crt'])
        if 'localhost' not in have_dns or '127.0.0.1' not in have_ips or '203.0.113.10' not in have_ips:
            fail('IP public host SAN', (have_dns, have_ips))
        have_dns, have_ips = frp_pki.read_cert_sans(pki_dns['server_crt'])
        if 'localhost' not in have_dns or 'frp.example.test' not in have_dns or '127.0.0.1' not in have_ips:
            fail('DNS public host SAN', (have_dns, have_ips))
        pass_('PKI_LOCALHOST_SAN')


def test_502_html_is_not_a_ca():
    html = b'<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>502 Bad Gateway</body>\r\n</html>\r\n'
    verdict = frp_doctor.classify_frontend_ca_body(html, 'text/html', 'a' * 64)
    if verdict.get('ok'):
        fail('502 HTML accepted as CA')
    if verdict.get('error_class') != 'NOT_A_CA':
        fail('502 HTML class', verdict)
    garbage = b'not-a-certificate'
    verdict = frp_doctor.classify_frontend_ca_body(garbage, 'application/x-pem-file', 'a' * 64)
    if verdict.get('ok'):
        fail('garbage accepted as CA')
    pass_('FRONTEND_CA_ENDPOINT')


def write_allocator_cfg(tmp, listen_port, pki, public_host='203.0.113.10'):
    cfg = {
        'public_host': public_host,
        'public_ip': public_host,
        'frp_control_public_port': 443,
        'frp_control_listen_port': 7000,
        'deployment_mode': 'single443',
        'port_start': 19000,
        'port_end': 19010,
        'listen_host': '127.0.0.1',
        'listen_port': listen_port,
        'allocator_listen_port': listen_port,
        'allocator_public_port': 443,
        'tls_ca_cert': pki['ca_crt'],
        'tls_server_cert': pki['server_crt'],
        'tls_server_key': pki['server_key'],
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
    return cfg_path


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


def test_live_frontend_proxy():
    bin_path = nginx_bin()
    with tempfile.TemporaryDirectory() as tmp:
        public_host = '203.0.113.10'
        alloc_port = free_port()
        frontend_port = free_port()
        pki = frp_pki.ensure_pki(str(Path(tmp) / 'pki'), public_host)
        cfg_path = write_allocator_cfg(tmp, alloc_port, pki, public_host)
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / 'server' / 'frp-port-allocator.py'), '--config', str(cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        nginx_proc = None
        try:
            wait_https('https://127.0.0.1:%s/healthz' % alloc_port, pki['ca_crt'])
            expected_fp = frp_pki.fingerprint_from_cert_file(pki['ca_crt'])
            if bin_path is None:
                pass_('FRONTEND_PROXY_HEALTH_CHECK')
                return
            temp_root = Path(tmp) / 'nginx-temp'
            for name in ('body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
                (temp_root / name).mkdir(parents=True, exist_ok=True)
            _conf, dest = render_conf(tmp, public_host, frontend_port, alloc_port, pki)
            nginx_proc = subprocess.Popen(
                [bin_path, '-c', str(dest)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            deadline = time.time() + 5
            last = None
            body = None
            while time.time() < deadline:
                result = frp_doctor.https_loopback_get(
                    public_host, frontend_port, '/healthz', pki['ca_crt'], timeout=1,
                )
                if result.get('ok'):
                    body = result.get('body') or b''
                    break
                last = result
                time.sleep(0.05)
            if body is None:
                err = b''
                if nginx_proc.poll() is not None:
                    err = nginx_proc.stdout.read() if nginx_proc.stdout else b''
                fail('live frontend /healthz', last or err)
            ca_result = frp_doctor.https_loopback_get(
                public_host, frontend_port, '/ca.crt', pki['ca_crt'], timeout=2,
            )
            if not ca_result.get('ok'):
                fail('live frontend /ca.crt', ca_result)
            verdict = frp_doctor.classify_frontend_ca_body(
                ca_result.get('body'), ca_result.get('content_type'), expected_fp,
            )
            if not verdict.get('ok'):
                fail('live frontend CA body', verdict)
            if verdict.get('fingerprint') != expected_fp:
                fail('live frontend CA fingerprint', verdict)
            pass_('FRONTEND_PROXY_HEALTH_CHECK')
        finally:
            if nginx_proc is not None and nginx_proc.poll() is None:
                nginx_proc.terminate()
                try:
                    nginx_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    nginx_proc.kill()
                    nginx_proc.wait(timeout=5)
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            if proc.poll() is None:
                raise SystemExit('FAIL test allocator still running pid=%s' % proc.pid)


def write_single443_tree(tree, pki_host='203.0.113.10'):
    tree = Path(tree)
    for rel in (
        'etc/frp', 'etc/frp-auto-deploy', 'var/lib/frp-auto-deploy',
        'usr/local/bin', 'usr/local/lib/frp-auto-deploy', 'etc/systemd/system',
    ):
        (tree / rel).mkdir(parents=True, exist_ok=True)
    (tree / 'etc/frp-auto-deploy/version').write_text('PROJECT_VERSION=2.1.0\nFRP_VERSION=0.71.0\n')
    frps = tree / 'usr/local/bin/frps'
    frps.write_text('#!/bin/sh\necho "frps version 0.71.0"\n')
    os.chmod(frps, 0o755)
    shutil.copy(str(ROOT / 'server' / 'frp-port-allocator.py'), str(tree / 'usr/local/lib/frp-auto-deploy/frp-port-allocator.py'))
    (tree / 'etc/systemd/system/frps.service').write_text('[Unit]\nDescription=fixture\n')
    (tree / 'etc/systemd/system/frp-port-allocator.service').write_text('[Unit]\nDescription=fixture\n')
    (tree / 'etc/systemd/system/frp-frontend.service').write_text('[Unit]\nDescription=fixture\n')
    (tree / 'etc/frp/server_token').write_text('test-frp-token-do-not-use\n')
    os.chmod(str(tree / 'etc/frp/server_token'), 0o600)
    (tree / 'etc/frp/frps.toml').write_text('bindAddr = "127.0.0.1"\nbindPort = 7000\n')
    os.chmod(str(tree / 'etc/frp/frps.toml'), 0o600)
    pki = frp_pki.ensure_pki(str(tree / 'etc/frp-auto-deploy/pki'), pki_host)
    conf, _ = render_conf(str(tree / 'etc/frp-auto-deploy'), pki_host, 443, 6099, {
        'ca_crt': '/etc/frp-auto-deploy/pki/ca.crt',
        'server_crt': '/etc/frp-auto-deploy/pki/server.crt',
        'server_key': '/etc/frp-auto-deploy/pki/server.key',
    })
    (tree / 'etc/frp-auto-deploy/frontend.conf').write_text(conf)
    os.chmod(str(tree / 'etc/frp-auto-deploy/frontend.conf'), 0o600)
    cfg = {
        'public_host': pki_host,
        'public_ip': pki_host,
        'frp_control_public_port': 443,
        'frp_control_listen_port': 7000,
        'port_start': 6000,
        'port_end': 6098,
        'listen_host': '127.0.0.1',
        'frp_control_bind_addr': '127.0.0.1',
        'frp_proxy_bind_addr': '0.0.0.0',
        'deployment_mode': 'single443',
        'frp_transport': 'wss',
        'allocator_public_port': 443,
        'allocator_listen_port': 6099,
        'listen_port': 6099,
        'allocator_public_url': 'https://%s/enroll' % pki_host,
        'registry_file': '/var/lib/frp-auto-deploy/registry.json',
        'token_file': '/etc/frp/server_token',
        'tls_ca_cert': '/etc/frp-auto-deploy/pki/ca.crt',
        'tls_server_cert': '/etc/frp-auto-deploy/pki/server.crt',
        'tls_server_key': '/etc/frp-auto-deploy/pki/server.key',
    }
    (tree / 'etc/frp-auto-deploy/config.json').write_text(json.dumps(cfg, indent=2, sort_keys=True) + '\n')
    os.chmod(str(tree / 'etc/frp-auto-deploy/config.json'), 0o600)
    (tree / 'var/lib/frp-auto-deploy/registry.json').write_text(json.dumps({
        'schema_version': 2, 'reserved': [], 'clients': {},
    }) + '\n')
    os.chmod(str(tree / 'var/lib/frp-auto-deploy/registry.json'), 0o600)
    return pki


def test_doctor_frontend_502_fails_overall():
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / 'server'
        write_single443_tree(tree)
        facts = {
            'expect_root_owner': False,
            'systemd_usable': False,
            'skip_network': True,
            'units': {},
            'network': {
                'allocator_healthz': {'ok': True, 'detail': 'HTTP 200', 'error_class': None},
                'frontend_healthz': {'ok': False, 'error_class': 'HTTP_502', 'detail': 'HTTP 502'},
                'frontend_ca': {
                    'ok': False,
                    'error_class': 'HTTP_502',
                    'detail': 'HTTP 502',
                    'body': '<html><body>502 Bad Gateway</body></html>',
                    'content_type': 'text/html',
                },
            },
            'platform': {},
            'disk': {},
            'clock': {'status': 'ok', 'detail': ''},
        }
        _text, code, report = frp_doctor.run_doctor(
            str(tree), facts, fmt='json', skip_network=True,
        )
        statuses = {c['id']: c['status'] for c in report.checks}
        if statuses.get('allocator_health') != 'PASS':
            fail('doctor allocator_health', statuses.get('allocator_health'))
        if statuses.get('frontend_proxy_health') != 'FAIL':
            fail('doctor frontend_proxy_health', statuses.get('frontend_proxy_health'))
        if statuses.get('frontend_ca_endpoint') != 'FAIL':
            fail('doctor frontend_ca_endpoint', statuses.get('frontend_ca_endpoint'))
        if statuses.get('frontend_config') != 'PASS':
            fail('doctor frontend_config', statuses.get('frontend_config'))
        if report.overall() != 'FAIL' or code != 1:
            fail('doctor overall with frontend 502', report.overall())
        pass_('FRONTEND_PROXY_HEALTH_CHECK')


def main():
    test_backend_identity_ip_and_dns()
    test_502_html_is_not_a_ca()
    test_doctor_frontend_502_fails_overall()
    test_live_frontend_proxy()
    print()
    print('FRONTEND_PROXY_TEST=PASS')


if __name__ == '__main__':
    main()
