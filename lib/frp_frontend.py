#!/usr/bin/env python3
"""Generate the isolated nginx config used in Enterprise single-443 mode.

FRP 0.71.0 WebSocket path is the compile-time constant FrpWebsocketPath
('/~!frp'). That path is not a server configuration key in v0.71.0.
"""
from __future__ import annotations

import sys
if sys.version_info < (3, 7):
    sys.stderr.write('ERROR: python 3.7 or newer is required\n')
    raise SystemExit(1)

import argparse
import os
import re
from pathlib import Path

# pkg/util/net/websocket.go in fatedier/frp v0.71.0
FRP_WEBSOCKET_PATH = '/~!frp'
DEFAULT_BACKEND_CONTROL_PORT = 7000
DEFAULT_ALLOCATOR_LISTEN_PORT = 6099
DEFAULT_FRONTEND_PORT = 443
# Internal TLS identity for the loopback allocator backend. nginx
# proxy_ssl_verify matches DNS names, not iPAddress SANs, so the frontend
# verifies DNS:localhost rather than the public IP/hostname. This is not a
# user-configurable public option.
ALLOCATOR_BACKEND_TLS_NAME = 'localhost'

_SAFE_HOST = re.compile(r'^[A-Za-z0-9._:\[\]-]+$')
_LISTEN_SSL_RE = re.compile(r'^(\s*)listen\s+\S+\s+ssl;', re.M)


def normalize_deployment_mode(value):
    text = str(value or 'direct').strip().lower().replace('-', '').replace('_', '')
    if text in ('single443', 'enterprise', 'enterprisesingle443'):
        return 'single443'
    if text in ('direct', ''):
        return 'direct'
    raise ValueError('deployment_mode must be direct or single443')


def normalize_transport(value, mode='direct'):
    text = str(value or '').strip().lower()
    if not text:
        return 'wss' if mode == 'single443' else 'tcp'
    if text == 'wss':
        return 'wss'
    if text == 'tcp':
        return 'tcp'
    raise ValueError('frp_transport must be tcp or wss')


def _require_host(value, name):
    host = str(value or '').strip()
    if not host or not _SAFE_HOST.fullmatch(host):
        raise ValueError('%s is invalid' % name)
    return host


def _require_port(value, name):
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('%s must be a TCP port' % name) from exc
    if not 1 <= port <= 65535:
        raise ValueError('%s must be a TCP port' % name)
    return port


def _require_abs_path(value, name):
    path = str(value or '').strip()
    if not path.startswith('/') or '..' in path.split('/'):
        raise ValueError('%s must be an absolute path' % name)
    return path


def _require_error_log(value):
    """Allow absolute paths or nginx special targets (stderr / syslog:...)."""
    text = str(value or '').strip()
    if text in ('stderr', '/dev/stderr', 'stdout', '/dev/stdout'):
        return text
    if text.startswith('syslog:'):
        if '..' in text or any(ch in text for ch in '\r\n\x00'):
            raise ValueError('error_log syslog target is invalid')
        return text
    return _require_abs_path(text, 'error_log')


def render_nginx_conf(
    public_host,
    frontend_port,
    allocator_listen_port,
    control_listen_port,
    ca_cert,
    server_cert,
    server_key,
    pid_path='/run/drlink/nginx.pid',
    error_log='stderr',
    temp_root='/var/lib/drlink/nginx',
    websocket_path=FRP_WEBSOCKET_PATH,
):
    host = _require_host(public_host, 'public_host')
    frontend_port = _require_port(frontend_port, 'frontend_port')
    allocator_listen_port = _require_port(allocator_listen_port, 'allocator_listen_port')
    control_listen_port = _require_port(control_listen_port, 'control_listen_port')
    ca_cert = _require_abs_path(ca_cert, 'ca_cert')
    server_cert = _require_abs_path(server_cert, 'server_cert')
    server_key = _require_abs_path(server_key, 'server_key')
    pid_path = _require_abs_path(pid_path, 'pid_path')
    error_log = _require_error_log(error_log)
    temp_root = _require_abs_path(temp_root, 'temp_root')
    if websocket_path != FRP_WEBSOCKET_PATH:
        raise ValueError('FRP 0.71.0 WebSocket path is fixed at %s' % FRP_WEBSOCKET_PATH)

    # Exact-match FRP WebSocket path. The '!' in /~!frp is not special in nginx
    # prefix/exact locations; quoting still keeps the config unambiguous.
    # Allocator endpoints are an anchored allowlist so arbitrary paths are not
    # proxied to localhost services. Exact '=' locations outrank this regex.
    return '''\
pid %s;
error_log %s warn;
worker_processes 1;
daemon off;

events {
    worker_connections 1024;
}

http {
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }

    client_body_temp_path %s/body;
    proxy_temp_path %s/proxy;
    fastcgi_temp_path %s/fastcgi;
    uwsgi_temp_path %s/uwsgi;
    scgi_temp_path %s/scgi;
    access_log off;
    server_tokens off;
    client_max_body_size 1m;

    server {
        listen %s ssl;
        server_name %s;

        ssl_certificate %s;
        ssl_certificate_key %s;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers off;

        location = "%s" {
            proxy_pass http://127.0.0.1:%s;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $host;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_connect_timeout 10s;
            proxy_buffering off;
            proxy_request_buffering off;
        }

        # Allocator backend is always loopback HTTPS. Verify DNS:localhost
        # (present on every project leaf) because nginx proxy_ssl_verify does
        # not reliably match iPAddress SANs such as the public IP.
        location ~ ^/(ca\\.crt|healthz|enroll|bootstrap/redeem|i/[^/?#]+)$ {
            proxy_pass https://127.0.0.1:%s;
            proxy_http_version 1.1;
            proxy_ssl_trusted_certificate %s;
            proxy_ssl_verify on;
            proxy_ssl_verify_depth 2;
            proxy_ssl_name %s;
            proxy_ssl_server_name on;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_read_timeout 60s;
            proxy_send_timeout 60s;
            proxy_connect_timeout 10s;
        }

        location / {
            return 404;
        }
    }
}
''' % (
        pid_path,
        error_log,
        temp_root,
        temp_root,
        temp_root,
        temp_root,
        temp_root,
        frontend_port,
        host,
        server_cert,
        server_key,
        websocket_path,
        control_listen_port,
        allocator_listen_port,
        ca_cert,
        ALLOCATOR_BACKEND_TLS_NAME,
    )


def rewrite_listen_for_syntax_check(text, listen_host='127.0.0.1', listen_port=49152):
    """Rewrite listen so nginx -t does not bind the production frontend port.

    nginx -t opens listen sockets. Using public TCP/443 fails in isolated tests
    (EACCES) and on live reinstall/migration (EADDRINUSE while frps or the
    running frontend still owns 443).
    """
    host = _require_host(listen_host, 'syntax_check_listen_host')
    port = _require_port(listen_port, 'syntax_check_listen_port')
    rewritten, count = _LISTEN_SSL_RE.subn(
        r'\1listen %s:%s ssl;' % (host, port),
        text,
        count=1,
    )
    if count != 1:
        raise ValueError('frontend config is missing a listen ... ssl directive')
    return rewritten


def write_syntax_check_conf(src, dest, listen_host='127.0.0.1', listen_port=49152):
    text = Path(src).read_text(encoding='utf-8')
    rewritten = rewrite_listen_for_syntax_check(text, listen_host, listen_port)
    path = Path(dest)
    tmp = path.with_name(path.name + '.tmp.%s' % os.getpid())
    tmp.write_text(rewritten, encoding='utf-8')
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return str(path)


def write_nginx_conf(dest, **kwargs):
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = render_nginx_conf(**kwargs)
    tmp = path.with_name(path.name + '.tmp.%s' % os.getpid())
    tmp.write_text(text, encoding='utf-8')
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return str(path)


def verify_frontend_proxy(public_host, frontend_port, ca_cert, expected_fingerprint, timeout=8):
    """Verified TLS GET /healthz and /ca.crt through the public frontend.

    Never disables certificate verification. Returns (ok, message).
    """
    # Local imports keep the config-writer usable without doctor on PATH.
    import frp_doctor  # noqa: WPS433

    host = str(public_host or '').strip()
    ca_path = str(ca_cert or '').strip()
    if not host:
        return False, 'public host is missing'
    if not ca_path or not Path(ca_path).is_file():
        return False, 'CA certificate is missing'
    try:
        port = int(frontend_port)
    except (TypeError, ValueError):
        return False, 'frontend port is invalid'
    expected = str(expected_fingerprint or '').replace(':', '').strip().lower()
    if not expected:
        try:
            expected = frp_doctor.fingerprint_cert_file(ca_path)[0] or ''
        except Exception:
            expected = ''
    if not expected:
        return False, 'expected CA fingerprint is missing'

    health = frp_doctor.https_loopback_get(host, port, '/healthz', ca_path, timeout=timeout)
    if not health.get('ok'):
        return False, 'frontend /healthz failed (%s)' % (
            health.get('error_class') or health.get('detail') or 'unreachable'
        )

    ca_resp = frp_doctor.https_loopback_get(host, port, '/ca.crt', ca_path, timeout=timeout)
    if not ca_resp.get('ok') and not ca_resp.get('body'):
        return False, 'frontend /ca.crt failed (%s)' % (
            ca_resp.get('error_class') or ca_resp.get('detail') or 'unreachable'
        )
    verdict = frp_doctor.classify_frontend_ca_body(
        ca_resp.get('body'),
        ca_resp.get('content_type') or '',
        expected,
    )
    if not verdict.get('ok'):
        return False, 'frontend /ca.crt invalid (%s)' % (
            verdict.get('error_class') or verdict.get('detail') or 'NOT_A_CA'
        )
    return True, 'frontend proxy health and CA fingerprint verified'


def main(argv=None):
    parser = argparse.ArgumentParser(description='Write the single-443 nginx frontend config')
    parser.add_argument('--dest', default='')
    parser.add_argument('--syntax-check-from', default='')
    parser.add_argument('--syntax-check-port', type=int, default=0)
    parser.add_argument('--verify-proxy', action='store_true')
    parser.add_argument('--public-host', default='')
    parser.add_argument('--frontend-port', type=int, default=DEFAULT_FRONTEND_PORT)
    parser.add_argument('--allocator-listen-port', type=int, default=0)
    parser.add_argument('--control-listen-port', type=int, default=0)
    parser.add_argument('--ca-cert', default='')
    parser.add_argument('--server-cert', default='')
    parser.add_argument('--server-key', default='')
    parser.add_argument('--expected-fingerprint', default='')
    parser.add_argument('--pid-path', default='/run/drlink/nginx.pid')
    parser.add_argument('--error-log', default='stderr')
    parser.add_argument('--temp-root', default='/var/lib/drlink/nginx')
    args = parser.parse_args(argv)
    if args.verify_proxy:
        ok, message = verify_frontend_proxy(
            args.public_host,
            args.frontend_port,
            args.ca_cert,
            args.expected_fingerprint,
        )
        if not ok:
            sys.stderr.write('ERROR: %s\n' % message)
            raise SystemExit(1)
        sys.stdout.write('%s\n' % message)
        return
    if args.syntax_check_from:
        if not args.dest:
            parser.error('--dest is required with --syntax-check-from')
        port = args.syntax_check_port or (49152 + (os.getpid() % 10000))
        write_syntax_check_conf(args.syntax_check_from, args.dest, listen_port=port)
        return
    if not args.dest:
        parser.error('--dest is required unless --verify-proxy is set')
    missing = [
        name for name, value in (
            ('--public-host', args.public_host),
            ('--allocator-listen-port', args.allocator_listen_port),
            ('--control-listen-port', args.control_listen_port),
            ('--ca-cert', args.ca_cert),
            ('--server-cert', args.server_cert),
            ('--server-key', args.server_key),
        ) if not value
    ]
    if missing:
        parser.error('missing required arguments: %s' % ', '.join(missing))
    write_nginx_conf(
        args.dest,
        public_host=args.public_host,
        frontend_port=args.frontend_port,
        allocator_listen_port=args.allocator_listen_port,
        control_listen_port=args.control_listen_port,
        ca_cert=args.ca_cert,
        server_cert=args.server_cert,
        server_key=args.server_key,
        pid_path=args.pid_path,
        error_log=args.error_log,
        temp_root=args.temp_root,
    )


if __name__ == '__main__':
    main()
